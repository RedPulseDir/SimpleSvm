#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <ntifs.h>
#include <intrin.h>

// ============================================================================
// Constants
// ============================================================================

#define KERNEL_STACK_SIZE           (PAGE_SIZE * 8)
#define SVM_MSR_PERMISSIONS_MAP_SIZE (PAGE_SIZE * 2)

#define SVM_MSR_VM_CR               0xC0010114
#define SVM_MSR_VM_HSAVE_PA         0xC0010117
#define IA32_MSR_EFER               0xC0000080
#define IA32_MSR_LSTAR              0xC0000082
#define IA32_MSR_DEBUGCTL           0x000001D9
#define IA32_MSR_PAT                0x00000277

#define EFER_SVME                   (1ULL << 12)
#define EFER_LME                    (1ULL << 8)
#define EFER_LMA                    (1ULL << 10)
#define EFER_NXE                    (1ULL << 11)

#define SVM_VM_CR_SVMDIS            (1UL << 4)

// Intercept bits
#define SVM_INTERCEPT_MISC1_CPUID   (1UL << 18)
#define SVM_INTERCEPT_MISC1_MSR_PROT (1UL << 28)
#define SVM_INTERCEPT_MISC2_VMRUN   (1UL << 0)
#define SVM_INTERCEPT_MISC1_GDTR_READ (1UL << 7)
#define SVM_INTERCEPT_MISC1_RDTSC   (1UL << 14)
#define SVM_INTERCEPT_MISC1_RDPMC   (1UL << 15)
#define SVM_INTERCEPT_MISC2_VMMCALL (1UL << 1)

#define SVM_INTERCEPT_EXCEPTION_DB  (1UL << 1)
#define SVM_INTERCEPT_EXCEPTION_PF  (1UL << 14)
#define SVM_INTERCEPT_EXCEPTION_AC  (1UL << 17)
#define SVM_INTERCEPT_EXCEPTION_SS  (1UL << 12)

// VMEXIT codes
#define VMEXIT_CPUID                0x0072
#define VMEXIT_MSR                  0x007C
#define VMEXIT_VMRUN                0x0080
#define VMEXIT_GDTR_READ            0x0067
#define VMEXIT_EXCEPTION_DB         0x0041
#define VMEXIT_EXCEPTION_PF         0x004E
#define VMEXIT_EXCEPTION_AC         0x0051
#define VMEXIT_EXCEPTION_SS         0x004C

// CPUID leaves
#define CPUID_HV_VENDOR_AND_MAX_FUNCTIONS  0x40000000
#define CPUID_HV_INTERFACE                 0x40000001
#define CPUID_UNLOAD_SIMPLE_SVM            0x41414141

// ============================================================================
// Structures
// ============================================================================

#pragma pack(push, 1)

typedef struct _EVENTINJ {
    union {
        UINT64 AsUInt64;
        struct {
            UINT64 Vector : 8;
            UINT64 Type : 3;
            UINT64 ErrorCodeValid : 1;
            UINT64 Reserved1 : 19;
            UINT64 Valid : 1;
            UINT64 ErrorCode : 32;
        } Fields;
    };
} EVENTINJ;

typedef struct _VMCB_CONTROL_AREA {
    UINT16 InterceptCrRead;
    UINT16 InterceptCrWrite;
    UINT16 InterceptDrRead;
    UINT16 InterceptDrWrite;
    UINT32 InterceptException;
    UINT32 InterceptMisc1;
    UINT32 InterceptMisc2;
    UINT8  Reserved1[0x03C - 0x014];
    UINT16 PauseFilterThreshold;
    UINT16 PauseFilterCount;
    UINT64 IopmBasePa;
    UINT64 MsrpmBasePa;
    UINT64 TscOffset;
    UINT32 GuestAsid;
    UINT32 TlbControl;
    UINT64 VIntr;
    UINT64 InterruptShadow;
    UINT64 ExitCode;
    UINT64 ExitInfo1;
    UINT64 ExitInfo2;
    UINT64 ExitIntInfo;
    UINT64 NpEnable;
    UINT64 AvicApicBar;
    UINT64 GuestPaOfGhcb;
    UINT64 EventInj;
    UINT64 NCr3;
    UINT64 LbrVirtualizationEnable;
    UINT64 VmcbClean;
    UINT64 NRip;
    UINT8  NumOfBytesFetched;
    UINT8  GuestInstructionBytes[15];
    UINT64 AvicApicBackingPagePointer;
    UINT64 Reserved2;
    UINT64 AvicLogicalTablePointer;
    UINT64 AvicPhysicalTablePointer;
    UINT64 Reserved3;
    UINT64 VmcbSaveStatePointer;
    UINT8  Reserved4[0x400 - 0x110];
} VMCB_CONTROL_AREA;

typedef struct _VMCB_STATE_SAVE_AREA {
    UINT16 EsSelector;
    UINT16 EsAttrib;
    UINT32 EsLimit;
    UINT64 EsBase;
    UINT16 CsSelector;
    UINT16 CsAttrib;
    UINT32 CsLimit;
    UINT64 CsBase;
    UINT16 SsSelector;
    UINT16 SsAttrib;
    UINT32 SsLimit;
    UINT64 SsBase;
    UINT16 DsSelector;
    UINT16 DsAttrib;
    UINT32 DsLimit;
    UINT64 DsBase;
    UINT16 FsSelector;
    UINT16 FsAttrib;
    UINT32 FsLimit;
    UINT64 FsBase;
    UINT16 GsSelector;
    UINT16 GsAttrib;
    UINT32 GsLimit;
    UINT64 GsBase;
    UINT16 GdtrSelector;
    UINT16 GdtrAttrib;
    UINT32 GdtrLimit;
    UINT64 GdtrBase;
    UINT16 LdtrSelector;
    UINT16 LdtrAttrib;
    UINT32 LdtrLimit;
    UINT64 LdtrBase;
    UINT16 IdtrSelector;
    UINT16 IdtrAttrib;
    UINT32 IdtrLimit;
    UINT64 IdtrBase;
    UINT16 TrSelector;
    UINT16 TrAttrib;
    UINT32 TrLimit;
    UINT64 TrBase;
    UINT8  Reserved1[0x0CB - 0x0A0];
    UINT8  Cpl;
    UINT32 Reserved2;
    UINT64 Efer;
    UINT8  Reserved3[0x148 - 0x0D8];
    UINT64 Cr4;
    UINT64 Cr3;
    UINT64 Cr0;
    UINT64 Dr7;
    UINT64 Dr6;
    UINT64 Rflags;
    UINT64 Rip;
    UINT8  Reserved4[0x1D8 - 0x180];
    UINT64 Rsp;
    UINT8  Reserved5[0x1F8 - 0x1E0];
    UINT64 Rax;
    UINT64 Star;
    UINT64 LStar;
    UINT64 CStar;
    UINT64 SfMask;
    UINT64 KernelGsBase;
    UINT64 SysenterCs;
    UINT64 SysenterEsp;
    UINT64 SysenterEip;
    UINT64 Cr2;
    UINT8  Reserved6[0x268 - 0x248];
    UINT64 GPat;
    UINT64 DbgCtl;
    UINT64 BrFrom;
    UINT64 BrTo;
    UINT64 LastExcepFrom;
    UINT64 LastExcepTo;
} VMCB_STATE_SAVE_AREA;

typedef struct _VMCB {
    VMCB_CONTROL_AREA ControlArea;
    VMCB_STATE_SAVE_AREA StateSaveArea;
    UINT8 Reserved[0x1000 - sizeof(VMCB_CONTROL_AREA) - sizeof(VMCB_STATE_SAVE_AREA)];
} VMCB, *PVMCB;

typedef struct _DESCRIPTOR_TABLE_REGISTER {
    UINT16 Limit;
    UINT64 Base;
} DESCRIPTOR_TABLE_REGISTER;

typedef struct _SEGMENT_ATTRIBUTE {
    union {
        UINT16 Value;
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
        } Bits;
    };
} SEGMENT_ATTRIBUTE;

typedef struct _GUEST_REGISTERS {
    UINT64 R15, R14, R13, R12, R11, R10, R9, R8;
    UINT64 Rdi, Rsi, Rbp, Rsp, Rbx, Rdx, Rcx, Rax;
} GUEST_REGISTERS, *PGUEST_REGISTERS;

#pragma pack(pop)

// ============================================================================
// Assembly functions
// ============================================================================

VOID LaunchVm(PVOID GuestVmcbPa);
VOID SyscallHook(VOID);
VOID InvalidatePage(PVOID Address);

// ============================================================================
// C handlers
// ============================================================================

BOOLEAN NTAPI SvHandleVmExit(PVOID VpData, PVOID GuestRegisters);
NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath);

// ============================================================================
// Global variables (exported to asm)
// ============================================================================

extern UINT64 OriginalLstar;
extern UINT64 SyscallHandler;
extern UINT64 TargetDR3;

#ifdef __cplusplus
}
#endif
