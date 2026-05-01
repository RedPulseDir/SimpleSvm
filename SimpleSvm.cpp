/*!
@file       SimpleSvm.cpp
@brief      Full refactored SVM hypervisor with proper synchronization
@author     Fox (based on Satoshi Tanda's work)
*/

#define POOL_NX_OPTIN 1

#include "SimpleSvm.hpp"
#include "process_manager.h"
#include "pte.h"

#include <intrin.h>
#include <ntifs.h>
#include <stdarg.h>

// ============================================================================
//                             CONSTANTS & MACROS
// ============================================================================

#define KUSER_SHARED_DATA_KERNELMODE 0xFFFFF78000000000ULL

#define EFER_SVME         (1ULL << 12)
#define EFER_LME          (1ULL << 8)
#define EFER_LMA          (1ULL << 10)
#define EFER_NXE          (1ULL << 11)
#define EFER_SCE          (1ULL << 0)

#define X86_FLAGS_TF      (1U << 8)
#define X86_FLAGS_IF      (1U << 9)
#define BRANCH_SINGLE_STEP (1U << 1)
#define SINGLE_STEP       (1U << 14)

#define SVM_INTERCEPT_EXCEPTION_DB (1UL << 1)
#define SVM_INTERCEPT_EXCEPTION_PF (1UL << 14)
#define SVM_INTERCEPT_EXCEPTION_AC (1UL << 17)
#define SVM_INTERCEPT_EXCEPTION_SS (1UL << 12)
#define SVM_INTERCEPT_MISC1_GDTR_READ (1UL << 7)
#define SVM_INTERCEPT_MISC1_RDTSC (1UL << 14)
#define SVM_INTERCEPT_MISC1_RDPMC (1UL << 15)
#define SVM_INTERCEPT_MISC2_VMMCALL (1UL << 1)

#define CPUID_HV_VENDOR_AND_MAX_FUNCTIONS  0x40000000
#define CPUID_HV_INTERFACE                 0x40000001
#define CPUID_UNLOAD_SIMPLE_SVM            0x41414141

#define SVM_MSR_VM_CR      0xC0010114
#define SVM_MSR_VM_HSAVE_PA 0xC0010117
#define SVM_MSR_EFER        0xC0000080
#define IA32_MSR_LSTAR      0xC0000082
#define IA32_MSR_DEBUGCTL   0x000001D9
#define IA32_MSR_PAT        0x00000277

#define SVM_VM_CR_SVMDIS    (1UL << 4)

// ============================================================================
//                             TYPE DEFINITIONS
// ============================================================================

#pragma pack(push, 1)

typedef struct _DESCRIPTOR_TABLE_REGISTER {
    UINT16 Limit;
    ULONG_PTR Base;
} DESCRIPTOR_TABLE_REGISTER;

typedef struct _SEGMENT_DESCRIPTOR {
    union {
        UINT64 AsUInt64;
        struct {
            UINT16 LimitLow;
            UINT16 BaseLow;
            UINT32 BaseMiddle : 8;
            UINT32 Type : 4;
            UINT32 System : 1;
            UINT32 Dpl : 2;
            UINT32 Present : 1;
            UINT32 LimitHigh : 4;
            UINT32 Avl : 1;
            UINT32 LongMode : 1;
            UINT32 DefaultBit : 1;
            UINT32 Granularity : 1;
            UINT32 BaseHigh : 8;
        } Fields;
    };
} SEGMENT_DESCRIPTOR;

typedef struct _SEGMENT_ATTRIBUTE {
    union {
        UINT16 AsUInt16;
        struct {
            UINT16 Type : 4;
            UINT16 System : 1;
            UINT16 Dpl : 2;
            UINT16 Present : 1;
            UINT16 Avl : 1;
            UINT16 LongMode : 1;
            UINT16 DefaultBit : 1;
            UINT16 Granularity : 1;
            UINT16 Reserved : 4;
        } Fields;
    };
} SEGMENT_ATTRIBUTE;

typedef struct _GUEST_REGISTERS {
    UINT64 R15, R14, R13, R12, R11, R10, R9, R8;
    UINT64 Rdi, Rsi, Rbp, Rsp, Rbx, Rdx, Rcx, Rax;
} GUEST_REGISTERS;

typedef struct _GUEST_CONTEXT {
    PGUEST_REGISTERS Regs;
    BOOLEAN ExitVm;
} GUEST_CONTEXT;

#pragma pack(pop)

// ============================================================================
//                             GLOBALS (MINIMAL)
// ============================================================================

static PVOID g_PowerCallbackRegistration = nullptr;
static ProcessManager* g_ProcessMgr = nullptr;
static KSPIN_LOCK g_VmcbLock;

// ============================================================================
//                             FORWARD DECLARATIONS
// ============================================================================

static VOID SvHandleCpuid(PVMCB Vmcb, PGUEST_CONTEXT GuestCtx);
static VOID SvHandleMsrAccess(PVMCB Vmcb, PGUEST_CONTEXT GuestCtx);
static VOID SvHandleVmrun(PVMCB Vmcb, PGUEST_CONTEXT GuestCtx);
static VOID SvHandleExceptionDb(PVMCB Vmcb, PGUEST_CONTEXT GuestCtx);
static VOID SvHandleExceptionPf(PVMCB Vmcb, PGUEST_CONTEXT GuestCtx);
static VOID SvHandleExceptionAc(PVMCB Vmcb, PGUEST_CONTEXT GuestCtx);
static VOID SvHandleExceptionSs(PVMCB Vmcb, PGUEST_CONTEXT GuestCtx);
static VOID SvHandleSgdt(PVMCB Vmcb, PGUEST_CONTEXT GuestCtx);
static VOID SvInjectEvent(PVMCB Vmcb, UINT8 Vector, UINT8 Type, BOOLEAN ErrorCodeValid, UINT32 ErrorCode);

// ============================================================================
//                             MEMORY MANAGEMENT
// ============================================================================

static PVOID SvAllocatePageAlignedMemory(SIZE_T Size) {
    NT_ASSERT(Size >= PAGE_SIZE);
    PVOID Memory = ExAllocatePool2(POOL_FLAG_NON_PAGED, Size, 'SVMS');
    if (Memory) {
        RtlZeroMemory(Memory, Size);
        NT_ASSERT(((UINT64)Memory & (PAGE_SIZE - 1)) == 0);
    }
    return Memory;
}

static VOID SvFreePageAlignedMemory(PVOID Memory) {
    if (Memory) ExFreePoolWithTag(Memory, 'SVMS');
}

static PVOID SvAllocateContiguousMemory(SIZE_T Size) {
    PHYSICAL_ADDRESS Low, High, Boundary;
    Low.QuadPart = 0;
    High.QuadPart = -1;
    Boundary.QuadPart = 0;
    
    PVOID Memory = MmAllocateContiguousNodeMemory(Size, Low, High, Boundary, 
                                                   PAGE_READWRITE, MM_ANY_NODE_OK);
    if (Memory) RtlZeroMemory(Memory, Size);
    return Memory;
}

static VOID SvFreeContiguousMemory(PVOID Memory) {
    if (Memory) MmFreeContiguousMemory(Memory);
}

// ============================================================================
//                             UTILITY FUNCTIONS
// ============================================================================

static UINT16 SvGetSegmentAccessRight(UINT16 Selector, ULONG_PTR GdtBase) {
    PSEGMENT_DESCRIPTOR Desc = (PSEGMENT_DESCRIPTOR)(GdtBase + (Selector & ~3));
    SEGMENT_ATTRIBUTE Attr;
    
    Attr.Fields.Type = Desc->Fields.Type;
    Attr.Fields.System = Desc->Fields.System;
    Attr.Fields.Dpl = Desc->Fields.Dpl;
    Attr.Fields.Present = Desc->Fields.Present;
    Attr.Fields.Avl = Desc->Fields.Avl;
    Attr.Fields.LongMode = Desc->Fields.LongMode;
    Attr.Fields.DefaultBit = Desc->Fields.DefaultBit;
    Attr.Fields.Granularity = Desc->Fields.Granularity;
    Attr.Fields.Reserved = 0;
    
    return Attr.AsUInt16;
}

static BOOLEAN SvIsSvmSupported(VOID) {
    int Regs[4];
    ULONG64 VmCr;
    
    // Check AMD vendor
    __cpuid(Regs, 0);
    if (Regs[1] != 'htuA' || Regs[3] != 'itne' || Regs[2] != 'DMAc')
        return FALSE;
    
    // Check SVM feature
    __cpuid(Regs, 0x80000001);
    if (!(Regs[2] & (1 << 2))) return FALSE;
    
    // Check Nested Paging
    __cpuid(Regs, 0x8000000A);
    if (!(Regs[3] & 1)) return FALSE;
    
    // Check SVM not disabled
    VmCr = __readmsr(SVM_MSR_VM_CR);
    if (VmCr & SVM_VM_CR_SVMDIS) return FALSE;
    
    return TRUE;
}

static BOOLEAN SvIsSimpleSvmInstalled(VOID) {
    int Regs[4];
    char VendorId[13];
    
    __cpuid(Regs, CPUID_HV_VENDOR_AND_MAX_FUNCTIONS);
    *(UINT32*)(VendorId + 0) = Regs[1];
    *(UINT32*)(VendorId + 4) = Regs[2];
    *(UINT32*)(VendorId + 8) = Regs[3];
    VendorId[12] = 0;
    
    return (strcmp(VendorId, "SimpleSvm   ") == 0);
}

static BOOLEAN SvIsKvaShadowDisabled(VOID) {
    // Simplified - return TRUE if KVAShadow is disabled
    return TRUE;
}

// ============================================================================
//                             EVENT INJECTION
// ============================================================================

static VOID SvInjectEvent(PVMCB Vmcb, UINT8 Vector, UINT8 Type, 
                          BOOLEAN ErrorCodeValid, UINT32 ErrorCode) {
    EVENTINJ Event = { 0 };
    Event.Fields.Vector = Vector;
    Event.Fields.Type = Type;
    Event.Fields.ErrorCodeValid = ErrorCodeValid ? 1 : 0;
    Event.Fields.Valid = 1;
    if (ErrorCodeValid) Event.Fields.ErrorCode = ErrorCode;
    Vmcb->ControlArea.EventInj = Event.AsUInt64;
}

static VOID SvInjectGp(PVMCB Vmcb) {
    SvInjectEvent(Vmcb, 13, 3, TRUE, 0);
}

static VOID SvInjectDb(PVMCB Vmcb) {
    SvInjectEvent(Vmcb, 1, 3, FALSE, 0);
}

static VOID SvInjectPf(PVMCB Vmcb, UINT32 ErrorCode) {
    SvInjectEvent(Vmcb, 14, 3, TRUE, ErrorCode);
}

static VOID SvInjectAc(PVMCB Vmcb) {
    SvInjectEvent(Vmcb, 17, 3, TRUE, 0);
}

static VOID SvInjectSs(PVMCB Vmcb, UINT32 ErrorCode) {
    SvInjectEvent(Vmcb, 12, 3, TRUE, ErrorCode);
}

// ============================================================================
//                             MSR PERMISSIONS MAP
// ============================================================================

static VOID SvBuildMsrPermissionsMap(PVOID Msrpm) {
    constexpr UINT32 BITS_PER_MSR = 2;
    constexpr UINT32 SECOND_MSR_RANGE_BASE = 0xC0000000;
    constexpr UINT32 SECOND_MSRPM_OFFSET = 0x800 * 8; // 0x800 bytes = bits
    RTL_BITMAP Bitmap;
    
    RtlInitializeBitMap(&Bitmap, (PULONG)Msrpm, SVM_MSR_PERMISSIONS_MAP_SIZE * 8);
    RtlClearAllBits(&Bitmap);
    
    // Intercept EFER write
    UINT32 OffsetFrom2nd = (IA32_MSR_EFER - SECOND_MSR_RANGE_BASE) * BITS_PER_MSR;
    UINT32 Offset = SECOND_MSRPM_OFFSET + OffsetFrom2nd;
    RtlSetBits(&Bitmap, Offset + 1, 1);  // Write intercept
    
    // Intercept LSTAR read/write
    OffsetFrom2nd = (IA32_MSR_LSTAR - SECOND_MSR_RANGE_BASE) * BITS_PER_MSR;
    Offset = SECOND_MSRPM_OFFSET + OffsetFrom2nd;
    RtlSetBits(&Bitmap, Offset, 2);  // Both read and write
}

// ============================================================================
//                             NESTED PAGE TABLES
// ============================================================================

typedef struct _PML4_ENTRY_2MB {
    union {
        UINT64 AsUInt64;
        struct {
            UINT64 Valid : 1;
            UINT64 Write : 1;
            UINT64 User : 1;
            UINT64 WriteThrough : 1;
            UINT64 CacheDisable : 1;
            UINT64 Accessed : 1;
            UINT64 Reserved1 : 3;
            UINT64 Avl : 3;
            UINT64 PageFrameNumber : 40;
            UINT64 Reserved2 : 11;
            UINT64 NoExecute : 1;
        } Fields;
    };
} PML4_ENTRY_2MB;

typedef struct _PD_ENTRY_2MB {
    union {
        UINT64 AsUInt64;
        struct {
            UINT64 Valid : 1;
            UINT64 Write : 1;
            UINT64 User : 1;
            UINT64 WriteThrough : 1;
            UINT64 CacheDisable : 1;
            UINT64 Accessed : 1;
            UINT64 Dirty : 1;
            UINT64 LargePage : 1;
            UINT64 Global : 1;
            UINT64 Avl : 3;
            UINT64 Pat : 1;
            UINT64 Reserved1 : 8;
            UINT64 PageFrameNumber : 31;
            UINT64 Reserved2 : 11;
            UINT64 NoExecute : 1;
        } Fields;
    };
} PD_ENTRY_2MB;

typedef struct _PML4E_TREE {
    DECLSPEC_ALIGN(PAGE_SIZE) PDPTE_64 PdptEntries[512];
    DECLSPEC_ALIGN(PAGE_SIZE) PD_ENTRY_2MB PdEntries[512][512];
} PML4E_TREE;

typedef struct _SHARED_VIRTUAL_PROCESSOR_DATA {
    PVOID MsrPermissionsMap;
    DECLSPEC_ALIGN(PAGE_SIZE) PML4_ENTRY_2MB Pml4Entries[512];
    DECLSPEC_ALIGN(PAGE_SIZE) PML4E_TREE Pml4eTrees[2];
} SHARED_VIRTUAL_PROCESSOR_DATA;

static VOID SvBuildNestedPageTables(PSHARED_VIRTUAL_PROCESSOR_DATA Shared) {
    for (UINT64 Pml4Idx = 0; Pml4Idx < 2; Pml4Idx++) {
        PPML4_ENTRY_2MB Pml4e = &Shared->Pml4Entries[Pml4Idx];
        PPML4E_TREE Tree = &Shared->Pml4eTrees[Pml4Idx];
        
        UINT64 PdptPa = MmGetPhysicalAddress(&Tree->PdptEntries).QuadPart;
        Pml4e->Fields.PageFrameNumber = PdptPa >> PAGE_SHIFT;
        Pml4e->Fields.Valid = 1;
        Pml4e->Fields.Write = 1;
        Pml4e->Fields.User = 1;
        
        for (UINT64 PdptIdx = 0; PdptIdx < 512; PdptIdx++) {
            UINT64 PdPa = MmGetPhysicalAddress(&Tree->PdEntries[PdptIdx][0]).QuadPart;
            Tree->PdptEntries[PdptIdx].Fields.PageFrameNumber = PdPa >> PAGE_SHIFT;
            Tree->PdptEntries[PdptIdx].Fields.Present = 1;
            Tree->PdptEntries[PdptIdx].Fields.Write = 1;
            Tree->PdptEntries[PdptIdx].Fields.Supervisor = 1;
            
            for (UINT64 PdIdx = 0; PdIdx < 512; PdIdx++) {
                UINT64 TranslationPa = (Pml4Idx * 512 * 512) + (PdptIdx * 512) + PdIdx;
                Tree->PdEntries[PdptIdx][PdIdx].Fields.PageFrameNumber = TranslationPa;
                Tree->PdEntries[PdptIdx][PdIdx].Fields.Valid = 1;
                Tree->PdEntries[PdptIdx][PdIdx].Fields.Write = 1;
                Tree->PdEntries[PdptIdx][PdIdx].Fields.User = 1;
                Tree->PdEntries[PdptIdx][PdIdx].Fields.LargePage = 1;
            }
        }
    }
}

// ============================================================================
//                             VIRTUAL PROCESSOR DATA
// ============================================================================

typedef struct _VIRTUAL_PROCESSOR_DATA {
    union {
        DECLSPEC_ALIGN(PAGE_SIZE) UINT8 HostStack[KERNEL_STACK_SIZE];
        struct {
            UINT8 Stack[KERNEL_STACK_SIZE - sizeof(KTRAP_FRAME) - sizeof(PVOID) * 8];
            KTRAP_FRAME TrapFrame;
            UINT64 GuestVmcbPa;
            UINT64 HostVmcbPa;
            struct _VIRTUAL_PROCESSOR_DATA* Self;
            PSHARED_VIRTUAL_PROCESSOR_DATA Shared;
            UINT64 Padding;
            UINT64 Magic;  // Must be MAXUINT64
        } Layout;
    };
    
    DECLSPEC_ALIGN(PAGE_SIZE) VMCB GuestVmcb;
    DECLSPEC_ALIGN(PAGE_SIZE) VMCB HostVmcb;
    DECLSPEC_ALIGN(PAGE_SIZE) UINT8 HostStateArea[PAGE_SIZE];
} VIRTUAL_PROCESSOR_DATA;

static_assert(sizeof(VIRTUAL_PROCESSOR_DATA) == KERNEL_STACK_SIZE + PAGE_SIZE * 3,
              "VIRTUAL_PROCESSOR_DATA size mismatch");

// ============================================================================
//                             VMEXIT HANDLERS
// ============================================================================

static VOID SvHandleCpuid(PVMCB Vmcb, PGUEST_CONTEXT GuestCtx) {
    int Regs[4];
    INT Leaf = (INT)GuestCtx->Regs->Rax;
    INT SubLeaf = (INT)GuestCtx->Regs->Rcx;
    SEGMENT_ATTRIBUTE Attr;
    
    // Check for backdoor requests (CPL=3, DR3 magic)
    if (Vmcb->StateSaveArea.Cpl == 3) {
        UINT64 Dr3 = __readdr(3);
        UINT64 Dr7 = Vmcb->StateSaveArea.Dr7;
        
        if (Dr3 == TARGET_DR3 && (Dr7 & 0xF0000040) == 0x40) {
            // Magic backdoor requests
            if (Leaf == 0x1) {
                // Spoof CPUID leaf 1
                GuestCtx->Regs->Rax = 0x00A20F12;
                GuestCtx->Regs->Rbx = 0x00100800;
                GuestCtx->Regs->Rcx = 0x7EF8320B & ~((1<<12)|(1<<25)|(1<<26)|(1<<27)|(1<<28)|(1<<29)|(1<<30));
                GuestCtx->Regs->Rdx = 0x178BFBFF;
                goto AdvanceRip;
            }
            
            if (Leaf == 0x1337 && ProcessManager::IsTrackingActive() == FALSE) {
                // Request process tracking
                HANDLE Pid = (HANDLE)GuestCtx->Regs->Rdx;
                NTSTATUS Status = ProcessManager::RequestTracking(Pid, GuestCtx->Regs->Rcx);
                GuestCtx->Regs->Rax = Status;
                goto AdvanceRip;
            }
            
            if (Leaf == 0x1338 && ProcessManager::IsTrackingActive()) {
                ProcessManager::StopTracking();
                GuestCtx->Regs->Rax = STATUS_SUCCESS;
                goto AdvanceRip;
            }
            
            if (Leaf == 0x336933) {
                // Set syscall handler
                ProcessManager::UpdateSyscallHandler(GuestCtx->Regs->Rcx);
                goto AdvanceRip;
            }
        }
    }
    
    // Normal CPUID execution
    __cpuidex(Regs, Leaf, SubLeaf);
    
    switch (Leaf) {
        case 1:
            Regs[2] |= (1 << 31);  // Hypervisor present
            break;
            
        case CPUID_HV_VENDOR_AND_MAX_FUNCTIONS:
            Regs[0] = CPUID_HV_INTERFACE;
            Regs[1] = 'pmiS';
            Regs[2] = 'vSel';
            Regs[3] = '   m';
            break;
            
        case CPUID_HV_INTERFACE:
            Regs[0] = '0#vH';  // Hv#0
            Regs[1] = 0;
            Regs[2] = 0;
            Regs[3] = 0;
            break;
            
        case CPUID_UNLOAD_SIMPLE_SVM:
            if (SubLeaf == CPUID_UNLOAD_SIMPLE_SVM) {
                Attr.AsUInt16 = Vmcb->StateSaveArea.SsAttrib;
                if (Attr.Fields.Dpl == 0) {  // Kernel mode request
                    GuestCtx->ExitVm = TRUE;
                }
            }
            break;
    }
    
    GuestCtx->Regs->Rax = (UINT32)Regs[0];
    GuestCtx->Regs->Rbx = (UINT32)Regs[1];
    GuestCtx->Regs->Rcx = (UINT32)Regs[2];
    GuestCtx->Regs->Rdx = (UINT32)Regs[3];
    
AdvanceRip:
    Vmcb->StateSaveArea.Rip = Vmcb->ControlArea.NRip;
    
    // Handle single-step trap
    if ((Vmcb->StateSaveArea.Rflags & X86_FLAGS_TF) && 
        !(__readmsr(IA32_MSR_DEBUGCTL) & BRANCH_SINGLE_STEP)) {
        Vmcb->StateSaveArea.Dr6 |= SINGLE_STEP;
        SvInjectDb(Vmcb);
    }
}

static VOID SvHandleMsrAccess(PVMCB Vmcb, PGUEST_CONTEXT GuestCtx) {
    ULARGE_INTEGER Value;
    UINT32 Msr = (UINT32)GuestCtx->Regs->Rcx;
    BOOLEAN Write = (Vmcb->ControlArea.ExitInfo1 != 0);
    
    if (Msr == IA32_MSR_LSTAR) {
        if (Write) {
            Value.LowPart = (UINT32)GuestCtx->Regs->Rax;
            Value.HighPart = (UINT32)GuestCtx->Regs->Rdx;
            Vmcb->StateSaveArea.LStar = Value.QuadPart;
        } else {
            Value.QuadPart = Vmcb->StateSaveArea.LStar;
            GuestCtx->Regs->Rax = Value.LowPart;
            GuestCtx->Regs->Rdx = Value.HighPart;
        }
        goto AdvanceRip;
    }
    
    if (Msr == IA32_MSR_EFER) {
        if (!Write) {
            Value.QuadPart = Vmcb->StateSaveArea.Efer;
            GuestCtx->Regs->Rax = Value.LowPart;
            GuestCtx->Regs->Rdx = Value.HighPart;
            goto AdvanceRip;
        }
        
        Value.LowPart = (UINT32)GuestCtx->Regs->Rax;
        Value.HighPart = (UINT32)GuestCtx->Regs->Rdx;
        
        // Protect SVME bit from being cleared
        if ((Value.QuadPart & EFER_SVME) == 0) {
            SvInjectGp(Vmcb);
            return;
        }
        
        // Validate EFER bits
        UINT64 Allowed = EFER_SCE | EFER_LME | EFER_LMA | EFER_NXE | EFER_SVME;
        if (Value.QuadPart & ~Allowed) {
            SvInjectGp(Vmcb);
            return;
        }
        
        Vmcb->StateSaveArea.Efer = Value.QuadPart;
        goto AdvanceRip;
    }
    
    // Pass-through other MSRs
    if (Write) {
        Value.LowPart = (UINT32)GuestCtx->Regs->Rax;
        Value.HighPart = (UINT32)GuestCtx->Regs->Rdx;
        __writemsr(Msr, Value.QuadPart);
    } else {
        Value.QuadPart = __readmsr(Msr);
        GuestCtx->Regs->Rax = Value.LowPart;
        GuestCtx->Regs->Rdx = Value.HighPart;
    }
    
AdvanceRip:
    Vmcb->StateSaveArea.Rip = Vmcb->ControlArea.NRip;
}

static VOID SvHandleVmrun(PVMCB Vmcb, PGUEST_CONTEXT GuestCtx) {
    UNREFERENCED_PARAMETER(GuestCtx);
    SvInjectGp(Vmcb);
}

static VOID SvHandleExceptionDb(PVMCB Vmcb, PGUEST_CONTEXT GuestCtx) {
    UNREFERENCED_PARAMETER(GuestCtx);
    
    // Re-enable intercepts that were temporarily disabled
    Vmcb->ControlArea.InterceptException |= SVM_INTERCEPT_EXCEPTION_PF;
    Vmcb->ControlArea.InterceptException |= SVM_INTERCEPT_EXCEPTION_AC;
    Vmcb->ControlArea.InterceptException |= SVM_INTERCEPT_EXCEPTION_SS;
    Vmcb->ControlArea.InterceptMisc1 |= SVM_INTERCEPT_MISC1_GDTR_READ;
    
    SvInjectDb(Vmcb);
}

static VOID SvHandleExceptionPf(PVMCB Vmcb, PGUEST_CONTEXT GuestCtx) {
    UNREFERENCED_PARAMETER(GuestCtx);
    
    // Restore IF and TF if needed
    if (Vmcb->ControlArea.InterceptMisc1 & SVM_INTERCEPT_MISC1_RDPMC) {
        Vmcb->StateSaveArea.Rflags |= X86_FLAGS_IF;
        Vmcb->ControlArea.InterceptMisc1 &= ~SVM_INTERCEPT_MISC1_RDPMC;
    }
    
    if (Vmcb->ControlArea.InterceptMisc2 & SVM_INTERCEPT_MISC2_VMMCALL) {
        UINT64 DebugCtl = __readmsr(IA32_MSR_DEBUGCTL);
        DebugCtl |= BRANCH_SINGLE_STEP;
        __writemsr(IA32_MSR_DEBUGCTL, DebugCtl);
        Vmcb->ControlArea.InterceptMisc2 &= ~SVM_INTERCEPT_MISC2_VMMCALL;
    }
    
    if (Vmcb->ControlArea.InterceptMisc1 & SVM_INTERCEPT_MISC1_RDTSC) {
        Vmcb->ControlArea.InterceptMisc1 &= ~SVM_INTERCEPT_MISC1_RDTSC;
    } else {
        Vmcb->StateSaveArea.Rflags &= ~X86_FLAGS_TF;
    }
    
    // Restore correct GDTR
    DESCRIPTOR_TABLE_REGISTER Gdtr;
    _sgdt(&Gdtr);
    Vmcb->StateSaveArea.GdtrLimit = Gdtr.Limit;
    
    Vmcb->StateSaveArea.Cr2 = Vmcb->ControlArea.ExitInfo2;
    SvInjectPf(Vmcb, (UINT32)Vmcb->ControlArea.ExitInfo1);
}

static VOID SvHandleExceptionAc(PVMCB Vmcb, PGUEST_CONTEXT GuestCtx) {
    UNREFERENCED_PARAMETER(GuestCtx);
    
    if (Vmcb->ControlArea.InterceptMisc1 & SVM_INTERCEPT_MISC1_RDPMC) {
        Vmcb->StateSaveArea.Rflags |= X86_FLAGS_IF;
        Vmcb->ControlArea.InterceptMisc1 &= ~SVM_INTERCEPT_MISC1_RDPMC;
    }
    
    if (Vmcb->ControlArea.InterceptMisc2 & SVM_INTERCEPT_MISC2_VMMCALL) {
        UINT64 DebugCtl = __readmsr(IA32_MSR_DEBUGCTL);
        DebugCtl |= BRANCH_SINGLE_STEP;
        __writemsr(IA32_MSR_DEBUGCTL, DebugCtl);
        Vmcb->ControlArea.InterceptMisc2 &= ~SVM_INTERCEPT_MISC2_VMMCALL;
    }
    
    if (Vmcb->ControlArea.InterceptMisc1 & SVM_INTERCEPT_MISC1_RDTSC) {
        Vmcb->ControlArea.InterceptMisc1 &= ~SVM_INTERCEPT_MISC1_RDTSC;
    } else {
        Vmcb->StateSaveArea.Rflags &= ~X86_FLAGS_TF;
    }
    
    DESCRIPTOR_TABLE_REGISTER Gdtr;
    _sgdt(&Gdtr);
    Vmcb->StateSaveArea.GdtrLimit = Gdtr.Limit;
    
    SvInjectAc(Vmcb);
}

static VOID SvHandleExceptionSs(PVMCB Vmcb, PGUEST_CONTEXT GuestCtx) {
    UNREFERENCED_PARAMETER(GuestCtx);
    
    if (Vmcb->ControlArea.InterceptMisc1 & SVM_INTERCEPT_MISC1_RDPMC) {
        Vmcb->StateSaveArea.Rflags |= X86_FLAGS_IF;
        Vmcb->ControlArea.InterceptMisc1 &= ~SVM_INTERCEPT_MISC1_RDPMC;
    }
    
    if (Vmcb->ControlArea.InterceptMisc2 & SVM_INTERCEPT_MISC2_VMMCALL) {
        UINT64 DebugCtl = __readmsr(IA32_MSR_DEBUGCTL);
        DebugCtl |= BRANCH_SINGLE_STEP;
        __writemsr(IA32_MSR_DEBUGCTL, DebugCtl);
        Vmcb->ControlArea.InterceptMisc2 &= ~SVM_INTERCEPT_MISC2_VMMCALL;
    }
    
    if (Vmcb->ControlArea.InterceptMisc1 & SVM_INTERCEPT_MISC1_RDTSC) {
        Vmcb->ControlArea.InterceptMisc1 &= ~SVM_INTERCEPT_MISC1_RDTSC;
    } else {
        Vmcb->StateSaveArea.Rflags &= ~X86_FLAGS_TF;
    }
    
    DESCRIPTOR_TABLE_REGISTER Gdtr;
    _sgdt(&Gdtr);
    Vmcb->StateSaveArea.GdtrLimit = Gdtr.Limit;
    
    SvInjectSs(Vmcb, (UINT32)Vmcb->ControlArea.ExitInfo1);
}

static VOID SvHandleSgdt(PVMCB Vmcb, PGUEST_CONTEXT GuestCtx) {
    UNREFERENCED_PARAMETER(GuestCtx);
    
    // Set up intercepts for next step
    if (Vmcb->StateSaveArea.Rflags & X86_FLAGS_TF) {
        Vmcb->ControlArea.InterceptMisc1 |= SVM_INTERCEPT_MISC1_RDTSC;
    }
    
    if (Vmcb->StateSaveArea.Rflags & X86_FLAGS_IF) {
        Vmcb->ControlArea.InterceptMisc1 |= SVM_INTERCEPT_MISC1_RDPMC;
        Vmcb->StateSaveArea.Rflags &= ~X86_FLAGS_IF;
    }
    
    UINT64 DebugCtl = __readmsr(IA32_MSR_DEBUGCTL);
    if (DebugCtl & BRANCH_SINGLE_STEP) {
        Vmcb->ControlArea.InterceptMisc2 |= SVM_INTERCEPT_MISC2_VMMCALL;
        DebugCtl &= ~BRANCH_SINGLE_STEP;
        __writemsr(IA32_MSR_DEBUGCTL, DebugCtl);
    }
    
    Vmcb->StateSaveArea.Rflags |= X86_FLAGS_TF;
    Vmcb->ControlArea.InterceptMisc1 &= ~SVM_INTERCEPT_MISC1_GDTR_READ;
    Vmcb->ControlArea.InterceptException |= SVM_INTERCEPT_EXCEPTION_PF;
    Vmcb->ControlArea.InterceptException |= SVM_INTERCEPT_EXCEPTION_AC;
    Vmcb->ControlArea.InterceptException |= SVM_INTERCEPT_EXCEPTION_SS;
    
    // Check if DR3 is set for spoofing
    UINT64 Dr3 = __readdr(3);
    UINT64 Dr7 = Vmcb->StateSaveArea.Dr7;
    if (Vmcb->StateSaveArea.Cpl == 3 && Dr3 == TARGET_DR3 && (Dr7 & 0xF0000040) == 0x40) {
        Vmcb->StateSaveArea.GdtrLimit = 0x7F;
    }
}

// ============================================================================
//                             VMCB INITIALIZATION
// ============================================================================

static VOID SvPrepareVirtualization(PVIRTUAL_PROCESSOR_DATA VpData,
                                     PSHARED_VIRTUAL_PROCESSOR_DATA Shared,
                                     PCONTEXT Context) {
    DESCRIPTOR_TABLE_REGISTER Gdtr, Idtr;
    _sgdt(&Gdtr);
    __sidt(&Idtr);
    
    PHYSICAL_ADDRESS GuestVmcbPa = MmGetPhysicalAddress(&VpData->GuestVmcb);
    PHYSICAL_ADDRESS HostVmcbPa = MmGetPhysicalAddress(&VpData->HostVmcb);
    PHYSICAL_ADDRESS HostStatePa = MmGetPhysicalAddress(&VpData->HostStateArea);
    PHYSICAL_ADDRESS Pml4Pa = MmGetPhysicalAddress(&Shared->Pml4Entries);
    PHYSICAL_ADDRESS MsrpmPa = MmGetPhysicalAddress(Shared->MsrPermissionsMap);
    
    // Configure intercepts
    VpData->GuestVmcb.ControlArea.InterceptMisc1 |= SVM_INTERCEPT_MISC1_CPUID;
    VpData->GuestVmcb.ControlArea.InterceptMisc2 |= SVM_INTERCEPT_MISC2_VMRUN;
    VpData->GuestVmcb.ControlArea.InterceptException |= SVM_INTERCEPT_EXCEPTION_DB;
    VpData->GuestVmcb.ControlArea.InterceptMisc1 |= SVM_INTERCEPT_MISC1_MSR_PROT;
    VpData->GuestVmcb.ControlArea.MsrpmBasePa = MsrpmPa.QuadPart;
    
    VpData->GuestVmcb.ControlArea.GuestAsid = 1;
    
    // Nested Page Tables (disabled by default, enable if needed)
    // VpData->GuestVmcb.ControlArea.NpEnable |= 1;
    // VpData->GuestVmcb.ControlArea.NCr3 = Pml4Pa.QuadPart;
    
    // Guest state
    VpData->GuestVmcb.StateSaveArea.GdtrBase = Gdtr.Base;
    VpData->GuestVmcb.StateSaveArea.GdtrLimit = Gdtr.Limit;
    VpData->GuestVmcb.StateSaveArea.IdtrBase = Idtr.Base;
    VpData->GuestVmcb.StateSaveArea.IdtrLimit = Idtr.Limit;
    
    VpData->GuestVmcb.StateSaveArea.CsSelector = Context->SegCs;
    VpData->GuestVmcb.StateSaveArea.DsSelector = Context->SegDs;
    VpData->GuestVmcb.StateSaveArea.EsSelector = Context->SegEs;
    VpData->GuestVmcb.StateSaveArea.SsSelector = Context->SegSs;
    
    VpData->GuestVmcb.StateSaveArea.CsAttrib = SvGetSegmentAccessRight(Context->SegCs, Gdtr.Base);
    VpData->GuestVmcb.StateSaveArea.DsAttrib = SvGetSegmentAccessRight(Context->SegDs, Gdtr.Base);
    VpData->GuestVmcb.StateSaveArea.EsAttrib = SvGetSegmentAccessRight(Context->SegEs, Gdtr.Base);
    VpData->GuestVmcb.StateSaveArea.SsAttrib = SvGetSegmentAccessRight(Context->SegSs, Gdtr.Base);
    
    VpData->GuestVmcb.StateSaveArea.Efer = __readmsr(IA32_MSR_EFER);
    VpData->GuestVmcb.StateSaveArea.Cr0 = __readcr0();
    VpData->GuestVmcb.StateSaveArea.Cr2 = __readcr2();
    VpData->GuestVmcb.StateSaveArea.Cr3 = __readcr3();
    VpData->GuestVmcb.StateSaveArea.Cr4 = __readcr4();
    VpData->GuestVmcb.StateSaveArea.Rflags = Context->EFlags;
    VpData->GuestVmcb.StateSaveArea.Rsp = Context->Rsp;
    VpData->GuestVmcb.StateSaveArea.Rip = Context->Rip;
    
    // Save host state to VMCB
    __svm_vmsave(GuestVmcbPa.QuadPart);
    
    // Setup LSTAR hook (will be replaced if tracking active)
    VpData->GuestVmcb.StateSaveArea.LStar = (UINT64)SystemCallHook;
    
    // Setup host stack layout
    VpData->Layout.Magic = MAXUINT64;
    VpData->Layout.Shared = Shared;
    VpData->Layout.Self = VpData;
    VpData->Layout.HostVmcbPa = HostVmcbPa.QuadPart;
    VpData->Layout.GuestVmcbPa = GuestVmcbPa.QuadPart;
    
    __writemsr(SVM_MSR_VM_HSAVE_PA, HostStatePa.QuadPart);
    __svm_vmsave(HostVmcbPa.QuadPart);
}

// ============================================================================
//                             PROCESSOR VIRTUALIZATION
// ============================================================================

static NTSTATUS SvVirtualizeProcessor(PVOID Context) {
    PSHARED_VIRTUAL_PROCESSOR_DATA Shared = (PSHARED_VIRTUAL_PROCESSOR_DATA)Context;
    CONTEXT HostContext;
    PVIRTUAL_PROCESSOR_DATA VpData = nullptr;
    NTSTATUS Status = STATUS_SUCCESS;
    
    VpData = (PVIRTUAL_PROCESSOR_DATA)SvAllocatePageAlignedMemory(sizeof(VIRTUAL_PROCESSOR_DATA));
    if (!VpData) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    
    if (!SvIsSimpleSvmInstalled()) {
        RtlCaptureContext(&HostContext);
        SvPrepareVirtualization(VpData, Shared, &HostContext);
        
        __writemsr(IA32_MSR_EFER, __readmsr(IA32_MSR_EFER) | EFER_SVME);
        
        // Enter VM loop - never returns normally
        LaunchVm(&VpData->Layout.GuestVmcbPa);
        
        // Should never reach here
        KeBugCheck(MANUALLY_INITIATED_CRASH);
    }
    
    SvFreePageAlignedMemory(VpData);
    return Status;
}

static NTSTATUS SvDevirtualizeProcessor(PVOID Context) {
    INT Regs[4];
    UINT64 High, Low;
    PVIRTUAL_PROCESSOR_DATA VpData = nullptr;
    PSHARED_VIRTUAL_PROCESSOR_DATA* SharedPtr = (PSHARED_VIRTUAL_PROCESSOR_DATA*)Context;
    
    __cpuidex(Regs, CPUID_UNLOAD_SIMPLE_SVM, CPUID_UNLOAD_SIMPLE_SVM);
    if (Regs[2] == 'SSVM') {
        High = Regs[3];
        Low = Regs[0];
        VpData = (PVIRTUAL_PROCESSOR_DATA)(High << 32 | Low);
        if (VpData && VpData->Layout.Magic == MAXUINT64 && SharedPtr) {
            *SharedPtr = VpData->Layout.Shared;
        }
        SvFreePageAlignedMemory(VpData);
    }
    
    return STATUS_SUCCESS;
}

static NTSTATUS SvExecuteOnEachProcessor(PFUNCTION Callback, PVOID Context, PULONG Completed) {
    NTSTATUS Status = STATUS_SUCCESS;
    ULONG Count = KeQueryActiveProcessorCountEx(ALL_PROCESSOR_GROUPS);
    ULONG i = 0;
    
    for (i = 0; i < Count; i++) {
        PROCESSOR_NUMBER ProcNum;
        Status = KeGetProcessorNumberFromIndex(i, &ProcNum);
        if (!NT_SUCCESS(Status)) goto Exit;
        
        GROUP_AFFINITY Affinity = { 0 };
        Affinity.Group = ProcNum.Group;
        Affinity.Mask = 1ULL << ProcNum.Number;
        
        GROUP_AFFINITY OldAffinity;
        KeSetSystemGroupAffinityThread(&Affinity, &OldAffinity);
        
        Status = Callback(Context);
        
        KeRevertToUserGroupAffinityThread(&OldAffinity);
        if (!NT_SUCCESS(Status)) goto Exit;
    }
    
Exit:
    if (Completed) *Completed = i;
    return Status;
}

static NTSTATUS SvVirtualizeAllProcessors(VOID) {
    NTSTATUS Status;
    PSHARED_VIRTUAL_PROCESSOR_DATA Shared = nullptr;
    ULONG Completed = 0;
    
    if (!SvIsSvmSupported()) {
        return STATUS_HV_FEATURE_UNAVAILABLE;
    }
    
    Shared = (PSHARED_VIRTUAL_PROCESSOR_DATA)SvAllocatePageAlignedMemory(sizeof(SHARED_VIRTUAL_PROCESSOR_DATA));
    if (!Shared) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    
    Shared->MsrPermissionsMap = SvAllocateContiguousMemory(SVM_MSR_PERMISSIONS_MAP_SIZE);
    if (!Shared->MsrPermissionsMap) {
        SvFreePageAlignedMemory(Shared);
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    
    SvBuildNestedPageTables(Shared);
    SvBuildMsrPermissionsMap(Shared->MsrPermissionsMap);
    
    Status = SvExecuteOnEachProcessor(SvVirtualizeProcessor, Shared, &Completed);
    
    if (!NT_SUCCESS(Status) && Completed) {
        SvDevirtualizeAllProcessors();
    }
    
    return Status;
}

static VOID SvDevirtualizeAllProcessors(VOID) {
    PSHARED_VIRTUAL_PROCESSOR_DATA Shared = nullptr;
    
    SvExecuteOnEachProcessor(SvDevirtualizeProcessor, &Shared, nullptr);
    
    if (Shared) {
        if (Shared->MsrPermissionsMap) {
            SvFreeContiguousMemory(Shared->MsrPermissionsMap);
        }
        SvFreePageAlignedMemory(Shared);
    }
}

// ============================================================================
//                             C ENTRY POINT
// ============================================================================

EXTERN_C BOOLEAN NTAPI HandleVmExit(PVIRTUAL_PROCESSOR_DATA VpData, PGUEST_REGISTERS GuestRegs) {
    GUEST_CONTEXT GuestCtx = { GuestRegs, FALSE };
    KIRQL OldIrql = KeGetCurrentIrql();
    
    __svm_vmload(VpData->Layout.HostVmcbPa);
    
    if (OldIrql < DISPATCH_LEVEL) KeRaiseIrqlToDpcLevel();
    
    VpData->Layout.TrapFrame.Rsp = VpData->GuestVmcb.StateSaveArea.Rsp;
    VpData->Layout.TrapFrame.Rip = VpData->GuestVmcb.ControlArea.NRip;
    
    GuestRegs->Rax = VpData->GuestVmcb.StateSaveArea.Rax;
    
    switch (VpData->GuestVmcb.ControlArea.ExitCode) {
        case VMEXIT_CPUID:        SvHandleCpuid(&VpData->GuestVmcb, &GuestCtx); break;
        case VMEXIT_MSR:          SvHandleMsrAccess(&VpData->GuestVmcb, &GuestCtx); break;
        case VMEXIT_GDTR_READ:    SvHandleSgdt(&VpData->GuestVmcb, &GuestCtx); break;
        case VMEXIT_EXCEPTION_DB: SvHandleExceptionDb(&VpData->GuestVmcb, &GuestCtx); break;
        case VMEXIT_EXCEPTION_PF: SvHandleExceptionPf(&VpData->GuestVmcb, &GuestCtx); break;
        case VMEXIT_EXCEPTION_AC: SvHandleExceptionAc(&VpData->GuestVmcb, &GuestCtx); break;
        case VMEXIT_EXCEPTION_SS: SvHandleExceptionSs(&VpData->GuestVmcb, &GuestCtx); break;
        case VMEXIT_VMRUN:        SvHandleVmrun(&VpData->GuestVmcb, &GuestCtx); break;
        default:
            DbgPrint("[SVM] Unknown VMEXIT: 0x%llX\n", VpData->GuestVmcb.ControlArea.ExitCode);
            KeBugCheckEx(MANUALLY_INITIATED_CRASH, 0xDEADBEEF, (ULONG_PTR)VpData, 0, 0);
    }
    
    if (OldIrql < DISPATCH_LEVEL) KeLowerIrql(OldIrql);
    
    if (GuestCtx.ExitVm) {
        if (g_OriginalLstar) {
            VpData->GuestVmcb.StateSaveArea.LStar = g_OriginalLstar;
        }
        
        GuestRegs->Rax = (UINT64)VpData & 0xFFFFFFFF;
        GuestRegs->Rbx = VpData->GuestVmcb.ControlArea.NRip;
        GuestRegs->Rcx = VpData->GuestVmcb.StateSaveArea.Rsp;
        GuestRegs->Rdx = (UINT64)VpData >> 32;
        
        __svm_vmload(MmGetPhysicalAddress(&VpData->GuestVmcb).QuadPart);
        _disable();
        __svm_stgi();
        __writemsr(IA32_MSR_EFER, __readmsr(IA32_MSR_EFER) & ~EFER_SVME);
        __writeeflags(VpData->GuestVmcb.StateSaveArea.Rflags);
        
        return TRUE;
    }
    
    VpData->GuestVmcb.StateSaveArea.Rax = GuestRegs->Rax;
    return FALSE;
}

// ============================================================================
//                             POWER CALLBACK
// ============================================================================

static VOID SvPowerCallback(PVOID Context, PVOID Arg1, PVOID Arg2) {
    UNREFERENCED_PARAMETER(Context);
    
    if (Arg1 != (PVOID)PO_CB_SYSTEM_STATE_LOCK) return;
    
    if (Arg2 != FALSE) {
        SvVirtualizeAllProcessors();
    } else {
        if (ProcessManager::IsTrackingActive()) {
            ProcessManager::StopTracking();
        }
        SvDevirtualizeAllProcessors();
    }
}

// ============================================================================
//                             DRIVER ENTRY/UNLOAD
// ============================================================================

static VOID SvDriverUnload(PDRIVER_OBJECT DriverObject) {
    UNREFERENCED_PARAMETER(DriverObject);
    
    DbgPrint("[SVM] Unloading driver...\n");
    
    if (ProcessManager::IsTrackingActive()) {
        ProcessManager::StopTracking();
    }
    
    if (g_ProcessMgr) {
        ProcessManager::Shutdown();
        delete g_ProcessMgr;
        g_ProcessMgr = nullptr;
    }
    
    if (g_PowerCallbackRegistration) {
        ExUnregisterCallback(g_PowerCallbackRegistration);
        g_PowerCallbackRegistration = nullptr;
    }
    
    SvDevirtualizeAllProcessors();
    
    DbgPrint("[SVM] Driver unloaded\n");
}

EXTERN_C NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {
    UNREFERENCED_PARAMETER(RegistryPath);
    
    NTSTATUS Status;
    UNICODE_STRING ObjName;
    OBJECT_ATTRIBUTES ObjAttr;
    PCALLBACK_OBJECT CallbackObj = nullptr;
    
    DbgPrint("[SVM] Loading driver...\n");
    
    DriverObject->DriverUnload = SvDriverUnload;
    ExInitializeDriverRuntime(DrvRtPoolNxOptIn);
    
    KeInitializeSpinLock(&g_VmcbLock);
    
    // Initialize process manager
    g_ProcessMgr = new ProcessManager();
    if (!g_ProcessMgr) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    
    Status = ProcessManager::Initialize();
    if (!NT_SUCCESS(Status)) {
        delete g_ProcessMgr;
        g_ProcessMgr = nullptr;
        return Status;
    }
    
    // Register power callback
    RtlInitUnicodeString(&ObjName, L"\\Callback\\PowerState");
    InitializeObjectAttributes(&ObjAttr, &ObjName, OBJ_CASE_INSENSITIVE, NULL, NULL);
    Status = ExCreateCallback(&CallbackObj, &ObjAttr, FALSE, TRUE);
    
    if (NT_SUCCESS(Status) && CallbackObj) {
        g_PowerCallbackRegistration = ExRegisterCallback(CallbackObj, SvPowerCallback, nullptr);
        ObDereferenceObject(CallbackObj);
    }
    
    // Virtualize all processors
    Status = SvVirtualizeAllProcessors();
    
    if (!NT_SUCCESS(Status)) {
        DbgPrint("[SVM] Virtualization failed: 0x%X\n", Status);
        ProcessManager::Shutdown();
        delete g_ProcessMgr;
        g_ProcessMgr = nullptr;
        if (g_PowerCallbackRegistration) {
            ExUnregisterCallback(g_PowerCallbackRegistration);
            g_PowerCallbackRegistration = nullptr;
        }
    } else {
        DbgPrint("[SVM] Virtualization successful\n");
    }
    
    return Status;
}