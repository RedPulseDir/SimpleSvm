/*!
    @file       SimpleSvm.cpp
    @brief      All C code.
 */
#define POOL_NX_OPTIN   1
#include "SimpleSvm.hpp"

#include <intrin.h>
#include <ntifs.h>
#include <stdarg.h>

// ============================================================================
// MISSING FUNCTION
// ============================================================================
static UINT32 GetSegmentLimit(UINT16 SegmentSelector)
{
    UNREFERENCED_PARAMETER(SegmentSelector);
    return 0xFFFFFFFF;
}

// ============================================================================
// GLOBALS
// ============================================================================
EXTERN_C UINT64 TargetSysHandler = 0x0;
EXTERN_C UINT64 OrigLstar = 0x0;
EXTERN_C const UINT64 TargetDR3 = 0x7FFE0FF0;
EXTERN_C const UINT64 SyscallBypassMagic = 0x1337133713371337;

PVOID NewKuserSharedData = nullptr;
HANDLE TrackedProcessId = NULL;
BOOLEAN StopCounterThread = FALSE;
BOOLEAN ProcessExitCleanup = FALSE;
BOOLEAN NotifyRoutineActive = FALSE;
PEPROCESS TargetProcess = nullptr;
HANDLE TargetProcessId = NULL;
HANDLE CounterThreadHandle = NULL;
PMDL KuserMDL = nullptr;

KSTART_ROUTINE CounterUpdater;

EXTERN_C VOID SyscallHook();
UINT64 LstarHook = (UINT64)SyscallHook;

typedef struct _NT_KPROCESS
{
    DISPATCHER_HEADER Header;
    LIST_ENTRY        ProfileListHead;
    ULONG_PTR         DirectoryTableBase;
    UCHAR             Data[1];
} NT_KPROCESS, * PNT_KPROCESS;

#define KUSER_SHARED_DATA_KERNELMODE 0xFFFFF78000000000

typedef enum _SYSTEM_INFORMATION_CLASS {
    SystemBasicInformation = 0,
    SystemPerformanceInformation = 2,
    SystemTimeOfDayInformation = 3,
    SystemProcessInformation = 5,
    SystemProcessorPerformanceInformation = 8,
    SystemInterruptInformation = 23,
    SystemExceptionInformation = 33,
    SystemRegistryQuotaInformation = 37,
    SystemLookasideInformation = 45,
    SystemCodeIntegrityInformation = 103,
    SystemPolicyInformation = 134,
} SYSTEM_INFORMATION_CLASS;

#define SystemKernelVaShadowInformation (SYSTEM_INFORMATION_CLASS)196

EXTERN_C __kernel_entry NTSTATUS NTAPI NtQuerySystemInformation(
    IN SYSTEM_INFORMATION_CLASS SystemInformationClass,
    OUT PVOID SystemInformation,
    IN ULONG SystemInformationLength,
    OUT PULONG ReturnLength OPTIONAL
);

typedef struct _SYSTEM_KERNEL_VA_SHADOW_INFORMATION
{
    struct
    {
        ULONG KvaShadowEnabled : 1;
        ULONG KvaShadowUserGlobal : 1;
        ULONG KvaShadowPcid : 1;
        ULONG KvaShadowInvpcid : 1;
        ULONG KvaShadowRequired : 1;
        ULONG KvaShadowRequiredAvailable : 1;
        ULONG InvalidPteBit : 6;
        ULONG L1DataCacheFlushSupported : 1;
        ULONG L1TerminalFaultMitigationPresent : 1;
        ULONG Reserved : 18;
    } KvaShadowFlags;
} SYSTEM_KERNEL_VA_SHADOW_INFORMATION, * PSYSTEM_KERNEL_VA_SHADOW_INFORMATION;

EXTERN_C DRIVER_INITIALIZE DriverEntry;
static DRIVER_UNLOAD SvDriverUnload;
static CALLBACK_FUNCTION SvPowerCallbackRoutine;

EXTERN_C VOID _sgdt(_Out_ PVOID Descriptor);

_IRQL_requires_max_(DISPATCH_LEVEL)
_IRQL_requires_min_(PASSIVE_LEVEL)
_IRQL_requires_same_
DECLSPEC_NORETURN
EXTERN_C
VOID NTAPI SvLaunchVm(_In_ PVOID HostRsp);

typedef struct _PML4_ENTRY_2MB
{
    union
    {
        UINT64 AsUInt64;
        struct
        {
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
} PML4_ENTRY_2MB, * PPML4_ENTRY_2MB,
PDPT_ENTRY_2MB, * PPDPT_ENTRY_2MB;

typedef struct _PD_ENTRY_2MB
{
    union
    {
        UINT64 AsUInt64;
        struct
        {
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
} PD_ENTRY_2MB, * PPD_ENTRY_2MB;

#include <pshpack1.h>
typedef struct _DESCRIPTOR_TABLE_REGISTER
{
    UINT16 Limit;
    ULONG_PTR Base;
} DESCRIPTOR_TABLE_REGISTER, * PDESCRIPTOR_TABLE_REGISTER;
#include <poppack.h>

typedef struct _SEGMENT_DESCRIPTOR
{
    union
    {
        UINT64 AsUInt64;
        struct
        {
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
} SEGMENT_DESCRIPTOR, * PSEGMENT_DESCRIPTOR;

typedef struct _SEGMENT_ATTRIBUTE
{
    union
    {
        UINT16 AsUInt16;
        struct
        {
            UINT16 Type : 4;
            UINT16 System : 1;
            UINT16 Dpl : 2;
            UINT16 Present : 1;
            UINT16 Avl : 1;
            UINT16 LongMode : 1;
            UINT16 DefaultBit : 1;
            UINT16 Granularity : 1;
            UINT16 Reserved1 : 4;
        } Fields;
    };
} SEGMENT_ATTRIBUTE, * PSEGMENT_ATTRIBUTE;

typedef struct _PML4E_TREE
{
    DECLSPEC_ALIGN(PAGE_SIZE) PDPT_ENTRY_2MB PdptEntries[512];
    DECLSPEC_ALIGN(PAGE_SIZE) PD_ENTRY_2MB PdEntries[512][512];
} PML4E_TREE, * PPML4E_TREE;

typedef struct _SHARED_VIRTUAL_PROCESSOR_DATA
{
    PVOID MsrPermissionsMap;
    DECLSPEC_ALIGN(PAGE_SIZE) PML4_ENTRY_2MB Pml4Entries[512];
    DECLSPEC_ALIGN(PAGE_SIZE) PML4E_TREE Pml4eTrees[2];
} SHARED_VIRTUAL_PROCESSOR_DATA, * PSHARED_VIRTUAL_PROCESSOR_DATA;

typedef struct _VIRTUAL_PROCESSOR_DATA
{
    union
    {
        DECLSPEC_ALIGN(PAGE_SIZE) UINT8 HostStackLimit[KERNEL_STACK_SIZE];
        struct
        {
            UINT8 StackContents[KERNEL_STACK_SIZE - (sizeof(PVOID) * 6) - sizeof(KTRAP_FRAME)];
            KTRAP_FRAME TrapFrame;
            UINT64 GuestVmcbPa;
            UINT64 HostVmcbPa;
            struct _VIRTUAL_PROCESSOR_DATA* Self;
            PSHARED_VIRTUAL_PROCESSOR_DATA SharedVpData;
            UINT64 Padding1;
            UINT64 Reserved1;
        } HostStackLayout;
    };
    DECLSPEC_ALIGN(PAGE_SIZE) VMCB GuestVmcb;
    DECLSPEC_ALIGN(PAGE_SIZE) VMCB HostVmcb;
    DECLSPEC_ALIGN(PAGE_SIZE) UINT8 HostStateArea[PAGE_SIZE];
} VIRTUAL_PROCESSOR_DATA, * PVIRTUAL_PROCESSOR_DATA;

typedef struct _GUEST_REGISTERS
{
    UINT64 R15, R14, R13, R12, R11, R10, R9, R8;
    UINT64 Rdi, Rsi, Rbp, Rsp, Rbx, Rdx, Rcx, Rax;
} GUEST_REGISTERS, * PGUEST_REGISTERS;

typedef struct _GUEST_CONTEXT
{
    PGUEST_REGISTERS VpRegs;
    BOOLEAN ExitVm;
} GUEST_CONTEXT, * PGUEST_CONTEXT;

#define IA32_MSR_PAT      0x00000277
#define IA32_MSR_EFER     0xc0000080
#define IA32_MSR_LSTAR    0xC0000082
#define IA32_MSR_DEBUGCTL 0x000001D9
#define EFER_SVME         (1UL << 12)
#define X86_FLAGS_TF      (1U<<8)
#define X86_FLAGS_IF      (1U<<9)
#define BranchSingleStep  (1U<<1)
#define SingleStep        (1U<<14)

#define SVM_InterceptException_DB       (1UL << 1)
#define SVM_INTERCEPT_MISC1_GDTR_READ   (1UL << 7)
#define UMIP                            (1UL << 11)
#define SVM_InterceptException_SS       (1UL << 12)
#define SVM_InterceptException_PF       (1UL << 14)
#define SVM_InterceptException_AC       (1UL << 17)
#define SVM_INTERCEPT_MISC2_VMMCALL     (1UL << 1)
#define SVM_INTERCEPT_MISC1_RDTSC       (1UL << 14)
#define SVM_INTERCEPT_MISC1_RDPMC       (1UL << 15)

#define RPL_MASK        3
#define DPL_SYSTEM      0

#define CPUID_FN8000_0001_ECX_SVM                   (1UL << 2)
#define CPUID_FN0000_0001_ECX_HYPERVISOR_PRESENT    (1UL << 31)
#define CPUID_FN8000_000A_EDX_NP                    (1UL << 0)

#define CPUID_MAX_STANDARD_FN_NUMBER_AND_VENDOR_STRING         0x00000000
#define CPUID_PROCESSOR_AND_PROCESSOR_FEATURE_IDENTIFIERS      0x00000001
#define CPUID_PROCESSOR_AND_PROCESSOR_FEATURE_IDENTIFIERS_EX   0x80000001
#define CPUID_SVM_FEATURES                                     0x8000000a
#define CPUID_HV_VENDOR_AND_MAX_FUNCTIONS                      0x40000000
#define CPUID_HV_INTERFACE                                     0x40000001
#define CPUID_UNLOAD_SIMPLE_SVM                                0x41414141
#define CPUID_HV_MAX                CPUID_HV_INTERFACE

static PVOID g_PowerCallbackRegistration;

static VOID SvDebugPrint(PCSTR Format, ...)
{
    va_list argList;
    va_start(argList, Format);
    vDbgPrintExWithPrefix("[SimpleSvm] ", DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, Format, argList);
    va_end(argList);
}

static PVOID SvAllocatePageAlingedPhysicalMemory(SIZE_T NumberOfBytes)
{
    PVOID memory = ExAllocatePool2(POOL_FLAG_NON_PAGED, NumberOfBytes, 'MVSS');
    if (memory != nullptr) RtlZeroMemory(memory, NumberOfBytes);
    return memory;
}

static VOID SvFreePageAlingedPhysicalMemory(PVOID BaseAddress)
{
    ExFreePoolWithTag(BaseAddress, 'MVSS');
}

static PVOID SvAllocateContiguousMemory(SIZE_T NumberOfBytes)
{
    PHYSICAL_ADDRESS boundary, lowest, highest;
    boundary.QuadPart = lowest.QuadPart = 0;
    highest.QuadPart = -1;
    return MmAllocateContiguousNodeMemory(NumberOfBytes, lowest, highest, boundary, PAGE_READWRITE, MM_ANY_NODE_OK);
}

static VOID SvFreeContiguousMemory(PVOID BaseAddress)
{
    MmFreeContiguousMemory(BaseAddress);
}

static VOID SvInjectGeneralProtectionException(PVIRTUAL_PROCESSOR_DATA VpData)
{
    EVENTINJ event = {0};
    event.Fields.Vector = 13;
    event.Fields.Type = 3;
    event.Fields.ErrorCodeValid = 1;
    event.Fields.Valid = 1;
    VpData->GuestVmcb.ControlArea.EventInj = event.AsUInt64;
}

static VOID SvInjectDbException(PVIRTUAL_PROCESSOR_DATA VpData)
{
    EVENTINJ event = {0};
    event.Fields.Vector = 1;
    event.Fields.Type = 3;
    event.Fields.Valid = 1;
    VpData->GuestVmcb.ControlArea.EventInj = event.AsUInt64;
}

static VOID SvInjectPFException(PVIRTUAL_PROCESSOR_DATA VpData)
{
    EVENTINJ event = {0};
    event.Fields.Vector = 14;
    event.Fields.Type = 3;
    event.Fields.ErrorCodeValid = 1;
    event.Fields.Valid = 1;
    event.Fields.ErrorCode = VpData->GuestVmcb.ControlArea.ExitInfo1;
    VpData->GuestVmcb.ControlArea.EventInj = event.AsUInt64;
}

static VOID SvInjectACException(PVIRTUAL_PROCESSOR_DATA VpData)
{
    EVENTINJ event = {0};
    event.Fields.Vector = 17;
    event.Fields.Type = 3;
    event.Fields.ErrorCodeValid = 1;
    event.Fields.Valid = 1;
    VpData->GuestVmcb.ControlArea.EventInj = event.AsUInt64;
}

static VOID SvInjectSsException(PVIRTUAL_PROCESSOR_DATA VpData)
{
    EVENTINJ event = {0};
    event.Fields.Vector = 12;
    event.Fields.Type = 3;
    event.Fields.ErrorCodeValid = 1;
    event.Fields.Valid = 1;
    event.Fields.ErrorCode = VpData->GuestVmcb.ControlArea.ExitInfo1;
    VpData->GuestVmcb.ControlArea.EventInj = event.AsUInt64;
}

UINT64 GetCr3ByProcessId(HANDLE ProcessId)
{
    PEPROCESS TargetEprocess = nullptr;
    UINT64 ProcessCr3 = 0x0;
    if (PsLookupProcessByProcessId(ProcessId, &TargetEprocess) != STATUS_SUCCESS) return ProcessCr3;
    NT_KPROCESS* CurrentProcess = (NT_KPROCESS*)(TargetEprocess);
    ProcessCr3 = CurrentProcess->DirectoryTableBase;
    ObDereferenceObject(TargetEprocess);
    return ProcessCr3;
}

EXTERN_C NTSTATUS NTAPI PsAcquireProcessExitSynchronization(PEPROCESS Process);
EXTERN_C VOID NTAPI PsReleaseProcessExitSynchronization(PEPROCESS Process);

PVOID PfnToVirtualAddr(uintptr_t pfn)
{
    PHYSICAL_ADDRESS pa = {0};
    pa.QuadPart = pfn << PAGE_SHIFT;
    return MmGetVirtualForPhysical(pa);
}

PT_ENTRY_64* GetPte(UINT64 virtual_address, uintptr_t pml4_base_pa)
{
    AddressTranslationHelper helper = {0};
    helper.as_int64 = (uintptr_t)virtual_address;
    PHYSICAL_ADDRESS pml4_physical = {0};
    pml4_physical.QuadPart = pml4_base_pa;
    PML4E_64* pml4 = (PML4E_64*)MmGetVirtualForPhysical(pml4_physical);
    if (pml4 == NULL) return NULL;
    PML4E_64* pml4e = &pml4[helper.AsIndex.pml4];
    if (pml4e->Fields.Present == FALSE) return NULL;
    PDPTE_64* pdpt = (PDPTE_64*)PfnToVirtualAddr(pml4e->Fields.PageFrameNumber);
    if (pdpt == NULL) return NULL;
    PDPTE_64* pdpte = &pdpt[helper.AsIndex.pdpt];
    if (pdpte->Fields.LargePage == TRUE) return (PT_ENTRY_64*)pdpte;
    if (pdpte->Fields.Present == FALSE) return NULL;
    PDE_64* pd = (PDE_64*)PfnToVirtualAddr(pdpte->Fields.PageFrameNumber);
    if (pd == NULL) return NULL;
    PDE_64* pde = &pd[helper.AsIndex.pd];
    if (pde->Fields.LargePage == TRUE) return (PT_ENTRY_64*)pde;
    if (pde->Fields.Present == FALSE) return NULL;
    PTE_64* pt = (PTE_64*)PfnToVirtualAddr(pde->Fields.PageFrameNumber);
    if (pt == NULL) return NULL;
    PTE_64* pte = &pt[helper.AsIndex.pt];
    return (PT_ENTRY_64*)pte;
}

VOID ProcessExitNotifyRoutine(HANDLE ParentId, HANDLE ProcessId, BOOLEAN Create)
{
    UNREFERENCED_PARAMETER(ParentId);
    if (Create == FALSE && ProcessId == TrackedProcessId) ProcessExitCleanup = TRUE;
}

VOID CleanupKuser()
{
    if (TrackedProcessId && ProcessExitCleanup)
    {
        if (NewKuserSharedData && KuserMDL)
        {
            MmUnmapLockedPages(NewKuserSharedData, KuserMDL);
            MmUnlockPages(KuserMDL);
            IoFreeMdl(KuserMDL);
            NewKuserSharedData = nullptr;
            KuserMDL = nullptr;
            PsReleaseProcessExitSynchronization(TargetProcess);
            ObDereferenceObject(TargetProcess);
            TargetSysHandler = NULL;
            TrackedProcessId = NULL;
            TargetProcess = nullptr;
            ProcessExitCleanup = FALSE;
        }
    }
}

VOID CounterUpdater(PVOID StartContext)
{
    UNREFERENCED_PARAMETER(StartContext);
    LARGE_INTEGER TimeToWait = {0};
    TimeToWait.QuadPart = -10000LL;
    while (StopCounterThread == FALSE)
    {
        if (TargetProcessId)
        {
            NTSTATUS status = PsLookupProcessByProcessId(TargetProcessId, &TargetProcess);
            if (NT_SUCCESS(status))
            {
                status = PsAcquireProcessExitSynchronization(TargetProcess);
                if (!NT_SUCCESS(status))
                {
                    ObDereferenceObject(TargetProcess);
                    TargetProcessId = NULL;
                    TargetSysHandler = NULL;
                    TargetProcess = nullptr;
                    SvDebugPrint("Failed to AcquireProcessExitSynchronization\n");
                    goto End;
                }
            }
            else
            {
                TargetSysHandler = NULL;
                TargetProcess = nullptr;
                TargetProcessId = NULL;
                SvDebugPrint("Failed to LookupProcessByProcessId\n");
                goto End;
            }
            TrackedProcessId = TargetProcessId;
            TargetProcessId = NULL;
            UINT64 TargetCr3 = GetCr3ByProcessId(TrackedProcessId);
            KAPC_STATE State = {0};
            KeStackAttachProcess(TargetProcess, &State);
            PT_ENTRY_64* TargetProcessKuserPte = GetPte(0x7FFE0000, TargetCr3);
            if (!NewKuserSharedData)
            {
                if (TargetProcessKuserPte)
                {
                    TargetProcessKuserPte->Fields.Ignored1 = 0b001;
                    KuserMDL = IoAllocateMdl((PVOID)0x7FFE0000, PAGE_SIZE, FALSE, FALSE, NULL);
                    MmProbeAndLockPages(KuserMDL, UserMode, IoWriteAccess);
                    KeUnstackDetachProcess(&State);
                    NewKuserSharedData = MmMapLockedPagesSpecifyCache(KuserMDL, KernelMode, MmCached, NULL, FALSE, HighPagePriority);
                }
                else KeUnstackDetachProcess(&State);
            }
            if (NewKuserSharedData)
            {
                UINT64 NewKusdAddress = (UINT64)NewKuserSharedData;
                *(UINT64*)(NewKusdAddress + 0x260) = 0x0100006658;
                *(UINT32*)(NewKusdAddress + 0x268) = 0x090001;
                *(UINT32*)(NewKusdAddress + 0x26C) = 0xA;
                *(UINT32*)(NewKusdAddress + 0x270) = 0x0;
                *(UINT32*)(NewKusdAddress + 0x274) = 0x01010000;
                *(UINT32*)(NewKusdAddress + 0x278) = 0x010000;
                *(UINT32*)(NewKusdAddress + 0x27C) = 0x010101;
                *(UINT32*)(NewKusdAddress + 0x280) = 0x010101;
                *(UINT32*)(NewKusdAddress + 0x284) = 0x0100;
                *(UINT32*)(NewKusdAddress + 0x288) = 0x01010101;
                *(UINT32*)(NewKusdAddress + 0x28C) = 0x0;
                *(UINT32*)(NewKusdAddress + 0x290) = 0x01;
                *(UINT32*)(NewKusdAddress + 0x294) = 0x01000101;
                *(UINT32*)(NewKusdAddress + 0x298) = 0x01010101;
                *(UINT32*)(NewKusdAddress + 0x29C) = 0x010001;
                *(UINT32*)(NewKusdAddress + 0x2A0) = 0x0;
                *(UINT32*)(NewKusdAddress + 0x2A4) = 0x0;
                *(UINT32*)(NewKusdAddress + 0x2A8) = 0x0;
                *(UINT32*)(NewKusdAddress + 0x2AC) = 0x0;
                *(UINT32*)(NewKusdAddress + 0x2B0) = 0x1;
                *(UINT8*)(NewKusdAddress + 0x290) = 0x0;
                *(UINT8*)(NewKusdAddress + 0x294) = 0x0;
                *(UINT8*)(NewKusdAddress + 0x295) = 0x0;
                *(UINT8*)(NewKusdAddress + 0x297) = 0x0;
                *(UINT8*)(NewKusdAddress + 0x285) = 0x0;
                *(UINT8*)(NewKusdAddress + 0x29B) = 0x0;
                *(UINT8*)(NewKusdAddress + 0x29C) = 0x0;
                *(UINT64*)(NewKusdAddress + 0x3D8) = 0x0;
                *(UINT64*)(NewKusdAddress + 0x3E0) = 0x0;
                *(UINT32*)(NewKusdAddress + 0x3EC) = 0x0;
                memset((void*)(NewKusdAddress + 0x3F0), 0x00, 0x200);
                *(UINT64*)(NewKusdAddress + 0x5F0) = 0x0;
                *(UINT64*)(NewKusdAddress + 0x5F8) = 0x0;
                memset((void*)(NewKusdAddress + 0x604), 0x00, 0x200);
                *(UINT64*)(NewKusdAddress + 0x808) = 0x0;
                *(UINT64*)(NewKusdAddress + 0x810) = 0x0;
                *(UINT64*)(NewKusdAddress + 0x2D0) = 0x320A0000000110;
                *(UINT64*)(NewKusdAddress + 0x2E8) = 0x0100007FB10B;
                *(UINT32*)(NewKusdAddress + 0x2F4) = 0x0;
                *(UINT64*)(NewKusdAddress + 0x36C) = 0x0;
                *(UINT64*)(NewKusdAddress + 0x374) = 0x0;
                *(UINT32*)(NewKusdAddress + 0x37C) = 0x1;
                *(UINT64*)(NewKusdAddress + 0x3C0) = 0x83000100000010;
                *(UINT32*)(NewKusdAddress + 0xFFC) = 0x13371337;
            }
            if (!NotifyRoutineActive) {
                if (NT_SUCCESS(PsSetCreateProcessNotifyRoutine(ProcessExitNotifyRoutine, FALSE))) NotifyRoutineActive = TRUE;
            }
        }
    End:
        KeDelayExecutionThread(KernelMode, FALSE, &TimeToWait);
        if (NewKuserSharedData)
        {
            PKUSER_SHARED_DATA TargetSpoofedKuserSharedData = (PKUSER_SHARED_DATA)NewKuserSharedData;
            PKUSER_SHARED_DATA KernelKuserSharedData = (PKUSER_SHARED_DATA)(KUSER_SHARED_DATA_KERNELMODE);
            *(ULONG64*)&TargetSpoofedKuserSharedData->InterruptTime = *(ULONG64*)&KernelKuserSharedData->InterruptTime.LowPart;
            TargetSpoofedKuserSharedData->InterruptTime.High2Time = TargetSpoofedKuserSharedData->InterruptTime.High1Time;
            *(ULONG64*)&TargetSpoofedKuserSharedData->SystemTime = *(ULONG64*)&KernelKuserSharedData->SystemTime.LowPart;
            TargetSpoofedKuserSharedData->SystemTime.High2Time = TargetSpoofedKuserSharedData->SystemTime.High1Time;
            TargetSpoofedKuserSharedData->LastSystemRITEventTickCount = KernelKuserSharedData->LastSystemRITEventTickCount;
            *(ULONG64*)&TargetSpoofedKuserSharedData->TickCount = *(ULONG64*)&KernelKuserSharedData->TickCount.LowPart;
            TargetSpoofedKuserSharedData->TickCount.High2Time = TargetSpoofedKuserSharedData->TickCount.High1Time;
            TargetSpoofedKuserSharedData->TimeUpdateLock = KernelKuserSharedData->TimeUpdateLock;
            TargetSpoofedKuserSharedData->BaselineSystemTimeQpc = KernelKuserSharedData->BaselineSystemTimeQpc;
            TargetSpoofedKuserSharedData->BaselineInterruptTimeQpc = TargetSpoofedKuserSharedData->BaselineSystemTimeQpc;
        }
        if (ProcessExitCleanup) CleanupKuser();
    }
    if (NotifyRoutineActive)
    {
        PsSetCreateProcessNotifyRoutine(ProcessExitNotifyRoutine, TRUE);
        NotifyRoutineActive = FALSE;
        CleanupKuser();
    }
    PsTerminateSystemThread(STATUS_SUCCESS);
}

static VOID SvHandleCpuid(PVIRTUAL_PROCESSOR_DATA VpData, PGUEST_CONTEXT GuestContext)
{
    int registers[4];
    int leaf = (int)GuestContext->VpRegs->Rax;
    int subLeaf = (int)GuestContext->VpRegs->Rcx;
    SEGMENT_ATTRIBUTE attribute;
    if (VpData->GuestVmcb.StateSaveArea.Cpl == 0x3)
    {
        UINT64 CurrentDR3 = __readdr(3);
        UINT64 CurrentDR7 = VpData->GuestVmcb.StateSaveArea.Dr7;
        if (CurrentDR3 == TargetDR3 && (CurrentDR7 & 0xF0000040) == 0x40)
        {
            if (leaf == 0x1)
            {
                GuestContext->VpRegs->Rax = 0x00A20F12;
                GuestContext->VpRegs->Rbx = 0x00100800;
                GuestContext->VpRegs->Rcx = 0x7EF8320B & ~((1<<12)|(1<<25)|(1<<26)|(1<<27)|(1<<28)|(1<<29)|(1<<30));
                GuestContext->VpRegs->Rdx = 0x178BFBFF;
                goto Exit;
            }
            if (GuestContext->VpRegs->Rax == 0x336933)
            {
                if (!TargetSysHandler) TargetSysHandler = GuestContext->VpRegs->Rcx;
                goto doCpuid;
            }
            if (GuestContext->VpRegs->Rax == 0x1337)
            {
                if (!TrackedProcessId) TargetProcessId = (HANDLE)GuestContext->VpRegs->Rdx;
                goto doCpuid;
            }
        }
    }
doCpuid:
    __cpuidex(registers, leaf, subLeaf);
    switch (leaf)
    {
    case CPUID_PROCESSOR_AND_PROCESSOR_FEATURE_IDENTIFIERS:
        registers[2] |= CPUID_FN0000_0001_ECX_HYPERVISOR_PRESENT;
        break;
    case CPUID_HV_VENDOR_AND_MAX_FUNCTIONS:
        registers[0] = CPUID_HV_MAX;
        registers[1] = 'pmiS';
        registers[2] = 'vSel';
        registers[3] = '   m';
        break;
    case CPUID_HV_INTERFACE:
        registers[0] = '0#vH';
        registers[1] = registers[2] = registers[3] = 0;
        break;
    case CPUID_UNLOAD_SIMPLE_SVM:
        if (subLeaf == CPUID_UNLOAD_SIMPLE_SVM)
        {
            attribute.AsUInt16 = VpData->GuestVmcb.StateSaveArea.SsAttrib;
            if (attribute.Fields.Dpl == DPL_SYSTEM) GuestContext->ExitVm = TRUE;
        }
        break;
    }
    GuestContext->VpRegs->Rax = (UINT32)registers[0];
    GuestContext->VpRegs->Rbx = (UINT32)registers[1];
    GuestContext->VpRegs->Rcx = (UINT32)registers[2];
    GuestContext->VpRegs->Rdx = (UINT32)registers[3];
Exit:
    VpData->GuestVmcb.StateSaveArea.Rip = VpData->GuestVmcb.ControlArea.NRip;
    if ((VpData->GuestVmcb.StateSaveArea.Rflags & X86_FLAGS_TF) != 0)
    {
        if ((__readmsr(IA32_MSR_DEBUGCTL) & BranchSingleStep) == 0)
        {
            VpData->GuestVmcb.StateSaveArea.Dr6 = (VpData->GuestVmcb.StateSaveArea.Dr6 |= SingleStep);
            SvInjectDbException(VpData);
        }
    }
}

static VOID SvHandleMsrAccess(PVIRTUAL_PROCESSOR_DATA VpData, PGUEST_CONTEXT GuestContext)
{
    ULARGE_INTEGER value;
    UINT32 msr = GuestContext->VpRegs->Rcx & 0xFFFFFFFF;
    BOOLEAN writeAccess = (VpData->GuestVmcb.ControlArea.ExitInfo1 != 0);
    if (msr == IA32_MSR_EFER)
    {
        NT_ASSERT(writeAccess != FALSE);
        value.LowPart = GuestContext->VpRegs->Rax & 0xFFFFFFFF;
        value.HighPart = GuestContext->VpRegs->Rdx & 0xFFFFFFFF;
        if ((value.QuadPart & EFER_SVME) == 0)
        {
            SvInjectGeneralProtectionException(VpData);
            return;
        }
        VpData->GuestVmcb.StateSaveArea.Efer = value.QuadPart;
    }
    else if (msr == IA32_MSR_LSTAR)
    {
        if (writeAccess)
        {
            value.LowPart = GuestContext->VpRegs->Rax & 0xFFFFFFFF;
            value.HighPart = GuestContext->VpRegs->Rdx & 0xFFFFFFFF;
            if (value.QuadPart != OrigLstar)
                VpData->GuestVmcb.StateSaveArea.LStar = value.QuadPart;
            else
                VpData->GuestVmcb.StateSaveArea.LStar = LstarHook;
        }
        else
        {
            value.QuadPart = (VpData->GuestVmcb.StateSaveArea.LStar != LstarHook) 
                ? VpData->GuestVmcb.StateSaveArea.LStar : OrigLstar;
            GuestContext->VpRegs->Rax = value.LowPart;
            GuestContext->VpRegs->Rdx = value.HighPart;
        }
    }
    else
    {
        if (writeAccess)
        {
            value.LowPart = GuestContext->VpRegs->Rax & 0xFFFFFFFF;
            value.HighPart = GuestContext->VpRegs->Rdx & 0xFFFFFFFF;
            __writemsr(msr, value.QuadPart);
        }
        else
        {
            value.QuadPart = __readmsr(msr);
            GuestContext->VpRegs->Rax = value.LowPart;
            GuestContext->VpRegs->Rdx = value.HighPart;
        }
    }
    VpData->GuestVmcb.StateSaveArea.Rip = VpData->GuestVmcb.ControlArea.NRip;
}

static VOID SvHandleVmrun(PVIRTUAL_PROCESSOR_DATA VpData, PGUEST_CONTEXT GuestContext)
{
    UNREFERENCED_PARAMETER(GuestContext);
    SvInjectGeneralProtectionException(VpData);
}

static VOID SvHandleDbException(PVIRTUAL_PROCESSOR_DATA VpData, PGUEST_CONTEXT GuestContext)
{
    UNREFERENCED_PARAMETER(GuestContext);
    if (VpData->GuestVmcb.StateSaveArea.Rip == LstarHook)
        VpData->GuestVmcb.StateSaveArea.Rip = OrigLstar;
    if ((VpData->GuestVmcb.ControlArea.InterceptException & SVM_InterceptException_AC) != 0)
    {
        VpData->GuestVmcb.ControlArea.InterceptMisc1 |= SVM_INTERCEPT_MISC1_GDTR_READ;
        VpData->GuestVmcb.ControlArea.InterceptException = (VpData->GuestVmcb.ControlArea.InterceptException & ~SVM_InterceptException_PF);
        VpData->GuestVmcb.ControlArea.InterceptException = (VpData->GuestVmcb.ControlArea.InterceptException & ~SVM_InterceptException_AC);
        VpData->GuestVmcb.ControlArea.InterceptException = (VpData->GuestVmcb.ControlArea.InterceptException & ~SVM_InterceptException_SS);
        DESCRIPTOR_TABLE_REGISTER CorrectGDTR = {0};
        _sgdt(&CorrectGDTR);
        VpData->GuestVmcb.StateSaveArea.GdtrLimit = CorrectGDTR.Limit;
        if ((VpData->GuestVmcb.ControlArea.InterceptMisc1 & SVM_INTERCEPT_MISC1_RDPMC) != 0)
        {
            VpData->GuestVmcb.StateSaveArea.Rflags = (VpData->GuestVmcb.StateSaveArea.Rflags |= X86_FLAGS_IF);
            VpData->GuestVmcb.ControlArea.InterceptMisc1 = (VpData->GuestVmcb.ControlArea.InterceptMisc1 & ~SVM_INTERCEPT_MISC1_RDPMC);
        }
        BOOLEAN IsDbPending = 0x0;
        if ((VpData->GuestVmcb.ControlArea.InterceptMisc1 & SVM_INTERCEPT_MISC1_RDTSC) != 0)
        {
            IsDbPending = 0x1;
            VpData->GuestVmcb.ControlArea.InterceptMisc1 = (VpData->GuestVmcb.ControlArea.InterceptMisc1 & ~SVM_INTERCEPT_MISC1_RDTSC);
        }
        else
        {
            VpData->GuestVmcb.StateSaveArea.Rflags = (VpData->GuestVmcb.StateSaveArea.Rflags & ~X86_FLAGS_TF);
        }
        if ((VpData->GuestVmcb.ControlArea.InterceptMisc2 & SVM_INTERCEPT_MISC2_VMMCALL) != 0)
        {
            IsDbPending = 0x0;
            UINT64 MSR_DEBUGCTL = __readmsr(IA32_MSR_DEBUGCTL);
            MSR_DEBUGCTL = (MSR_DEBUGCTL |= BranchSingleStep);
            __writemsr(IA32_MSR_DEBUGCTL, MSR_DEBUGCTL);
            VpData->GuestVmcb.ControlArea.InterceptMisc2 = (VpData->GuestVmcb.ControlArea.InterceptMisc2 & ~SVM_INTERCEPT_MISC2_VMMCALL);
        }
        if (!IsDbPending) return;
    }
    SvInjectDbException(VpData);
}

static VOID SvHandleSGDT(PVIRTUAL_PROCESSOR_DATA VpData, PGUEST_CONTEXT GuestContext)
{
    UNREFERENCED_PARAMETER(GuestContext);
    if ((VpData->GuestVmcb.StateSaveArea.Rflags & X86_FLAGS_TF) != 0)
        VpData->GuestVmcb.ControlArea.InterceptMisc1 |= SVM_INTERCEPT_MISC1_RDTSC;
    if ((VpData->GuestVmcb.StateSaveArea.Rflags & X86_FLAGS_IF) != 0)
    {
        VpData->GuestVmcb.ControlArea.InterceptMisc1 |= SVM_INTERCEPT_MISC1_RDPMC;
        VpData->GuestVmcb.StateSaveArea.Rflags = (VpData->GuestVmcb.StateSaveArea.Rflags & ~X86_FLAGS_IF);
    }
    UINT64 MSR_DEBUGCTL = __readmsr(IA32_MSR_DEBUGCTL);
    if ((MSR_DEBUGCTL & BranchSingleStep) != 0)
    {
        VpData->GuestVmcb.ControlArea.InterceptMisc2 |= SVM_INTERCEPT_MISC2_VMMCALL;
        MSR_DEBUGCTL = (MSR_DEBUGCTL & ~BranchSingleStep);
        __writemsr(IA32_MSR_DEBUGCTL, MSR_DEBUGCTL);
    }
    VpData->GuestVmcb.StateSaveArea.Rflags = (VpData->GuestVmcb.StateSaveArea.Rflags |= X86_FLAGS_TF);
    VpData->GuestVmcb.ControlArea.InterceptMisc1 = (VpData->GuestVmcb.ControlArea.InterceptMisc1 & ~SVM_INTERCEPT_MISC1_GDTR_READ);
    VpData->GuestVmcb.ControlArea.InterceptException |= SVM_InterceptException_PF;
    VpData->GuestVmcb.ControlArea.InterceptException |= SVM_InterceptException_AC;
    VpData->GuestVmcb.ControlArea.InterceptException |= SVM_InterceptException_SS;
    UINT64 CurrentDR3 = __readdr(3);
    UINT64 CurrentDR7 = VpData->GuestVmcb.StateSaveArea.Dr7;
    if (VpData->GuestVmcb.StateSaveArea.Cpl == 0x3 && CurrentDR3 == TargetDR3 && (CurrentDR7 & 0xF0000040) == 0x40)
        VpData->GuestVmcb.StateSaveArea.GdtrLimit = 0x7F;
}

static VOID SvHandlePFException(PVIRTUAL_PROCESSOR_DATA VpData, PGUEST_CONTEXT GuestContext)
{
    UNREFERENCED_PARAMETER(GuestContext);
    if ((VpData->GuestVmcb.ControlArea.InterceptMisc1 & SVM_INTERCEPT_MISC1_RDPMC) != 0)
    {
        VpData->GuestVmcb.StateSaveArea.Rflags = (VpData->GuestVmcb.StateSaveArea.Rflags |= X86_FLAGS_IF);
        VpData->GuestVmcb.ControlArea.InterceptMisc1 = (VpData->GuestVmcb.ControlArea.InterceptMisc1 & ~SVM_INTERCEPT_MISC1_RDPMC);
    }
    if ((VpData->GuestVmcb.ControlArea.InterceptMisc2 & SVM_INTERCEPT_MISC2_VMMCALL) != 0)
    {
        UINT64 MSR_DEBUGCTL = __readmsr(IA32_MSR_DEBUGCTL);
        MSR_DEBUGCTL = (MSR_DEBUGCTL |= BranchSingleStep);
        __writemsr(IA32_MSR_DEBUGCTL, MSR_DEBUGCTL);
        VpData->GuestVmcb.ControlArea.InterceptMisc2 = (VpData->GuestVmcb.ControlArea.InterceptMisc2 & ~SVM_INTERCEPT_MISC2_VMMCALL);
    }
    if ((VpData->GuestVmcb.ControlArea.InterceptMisc1 & SVM_INTERCEPT_MISC1_RDTSC) != 0)
        VpData->GuestVmcb.ControlArea.InterceptMisc1 = (VpData->GuestVmcb.ControlArea.InterceptMisc1 & ~SVM_INTERCEPT_MISC1_RDTSC);
    else
        VpData->GuestVmcb.StateSaveArea.Rflags = (VpData->GuestVmcb.StateSaveArea.Rflags & ~X86_FLAGS_TF);
    DESCRIPTOR_TABLE_REGISTER CorrectGDTR = {0};
    _sgdt(&CorrectGDTR);
    VpData->GuestVmcb.StateSaveArea.GdtrLimit = CorrectGDTR.Limit;
    VpData->GuestVmcb.ControlArea.InterceptException = (VpData->GuestVmcb.ControlArea.InterceptException & ~SVM_InterceptException_PF);
    VpData->GuestVmcb.ControlArea.InterceptException = (VpData->GuestVmcb.ControlArea.InterceptException & ~SVM_InterceptException_AC);
    VpData->GuestVmcb.ControlArea.InterceptException = (VpData->GuestVmcb.ControlArea.InterceptException & ~SVM_InterceptException_SS);
    VpData->GuestVmcb.ControlArea.InterceptMisc1 |= SVM_INTERCEPT_MISC1_GDTR_READ;
    VpData->GuestVmcb.StateSaveArea.Cr2 = VpData->GuestVmcb.ControlArea.ExitInfo2;
    SvInjectPFException(VpData);
}

static VOID SvHandleACException(PVIRTUAL_PROCESSOR_DATA VpData, PGUEST_CONTEXT GuestContext)
{
    UNREFERENCED_PARAMETER(GuestContext);
    if ((VpData->GuestVmcb.ControlArea.InterceptMisc1 & SVM_INTERCEPT_MISC1_RDPMC) != 0)
    {
        VpData->GuestVmcb.StateSaveArea.Rflags = (VpData->GuestVmcb.StateSaveArea.Rflags |= X86_FLAGS_IF);
        VpData->GuestVmcb.ControlArea.InterceptMisc1 = (VpData->GuestVmcb.ControlArea.InterceptMisc1 & ~SVM_INTERCEPT_MISC1_RDPMC);
    }
    if ((VpData->GuestVmcb.ControlArea.InterceptMisc2 & SVM_INTERCEPT_MISC2_VMMCALL) != 0)
    {
        UINT64 MSR_DEBUGCTL = __readmsr(IA32_MSR_DEBUGCTL);
        MSR_DEBUGCTL = (MSR_DEBUGCTL |= BranchSingleStep);
        __writemsr(IA32_MSR_DEBUGCTL, MSR_DEBUGCTL);
        VpData->GuestVmcb.ControlArea.InterceptMisc2 = (VpData->GuestVmcb.ControlArea.InterceptMisc2 & ~SVM_INTERCEPT_MISC2_VMMCALL);
    }
    if ((VpData->GuestVmcb.ControlArea.InterceptMisc1 & SVM_INTERCEPT_MISC1_RDTSC) != 0)
        VpData->GuestVmcb.ControlArea.InterceptMisc1 = (VpData->GuestVmcb.ControlArea.InterceptMisc1 & ~SVM_INTERCEPT_MISC1_RDTSC);
    else
        VpData->GuestVmcb.StateSaveArea.Rflags = (VpData->GuestVmcb.StateSaveArea.Rflags & ~X86_FLAGS_TF);
    DESCRIPTOR_TABLE_REGISTER CorrectGDTR = {0};
    _sgdt(&CorrectGDTR);
    VpData->GuestVmcb.StateSaveArea.GdtrLimit = CorrectGDTR.Limit;
    VpData->GuestVmcb.ControlArea.InterceptException = (VpData->GuestVmcb.ControlArea.InterceptException & ~SVM_InterceptException_PF);
    VpData->GuestVmcb.ControlArea.InterceptException = (VpData->GuestVmcb.ControlArea.InterceptException & ~SVM_InterceptException_AC);
    VpData->GuestVmcb.ControlArea.InterceptException = (VpData->GuestVmcb.ControlArea.InterceptException & ~SVM_InterceptException_SS);
    VpData->GuestVmcb.ControlArea.InterceptMisc1 |= SVM_INTERCEPT_MISC1_GDTR_READ;
    SvInjectACException(VpData);
}

static VOID SvHandleSsException(PVIRTUAL_PROCESSOR_DATA VpData, PGUEST_CONTEXT GuestContext)
{
    UNREFERENCED_PARAMETER(GuestContext);
    if ((VpData->GuestVmcb.ControlArea.InterceptMisc1 & SVM_INTERCEPT_MISC1_RDPMC) != 0)
    {
        VpData->GuestVmcb.StateSaveArea.Rflags = (VpData->GuestVmcb.StateSaveArea.Rflags |= X86_FLAGS_IF);
        VpData->GuestVmcb.ControlArea.InterceptMisc1 = (VpData->GuestVmcb.ControlArea.InterceptMisc1 & ~SVM_INTERCEPT_MISC1_RDPMC);
    }
    if ((VpData->GuestVmcb.ControlArea.InterceptMisc2 & SVM_INTERCEPT_MISC2_VMMCALL) != 0)
    {
        UINT64 MSR_DEBUGCTL = __readmsr(IA32_MSR_DEBUGCTL);
        MSR_DEBUGCTL = (MSR_DEBUGCTL |= BranchSingleStep);
        __writemsr(IA32_MSR_DEBUGCTL, MSR_DEBUGCTL);
        VpData->GuestVmcb.ControlArea.InterceptMisc2 = (VpData->GuestVmcb.ControlArea.InterceptMisc2 & ~SVM_INTERCEPT_MISC2_VMMCALL);
    }
    if ((VpData->GuestVmcb.ControlArea.InterceptMisc1 & SVM_INTERCEPT_MISC1_RDTSC) != 0)
        VpData->GuestVmcb.ControlArea.InterceptMisc1 = (VpData->GuestVmcb.ControlArea.InterceptMisc1 & ~SVM_INTERCEPT_MISC1_RDTSC);
    else
        VpData->GuestVmcb.StateSaveArea.Rflags = (VpData->GuestVmcb.StateSaveArea.Rflags & ~X86_FLAGS_TF);
    DESCRIPTOR_TABLE_REGISTER CorrectGDTR = {0};
    _sgdt(&CorrectGDTR);
    VpData->GuestVmcb.StateSaveArea.GdtrLimit = CorrectGDTR.Limit;
    VpData->GuestVmcb.ControlArea.InterceptException = (VpData->GuestVmcb.ControlArea.InterceptException & ~SVM_InterceptException_PF);
    VpData->GuestVmcb.ControlArea.InterceptException = (VpData->GuestVmcb.ControlArea.InterceptException & ~SVM_InterceptException_AC);
    VpData->GuestVmcb.ControlArea.InterceptException = (VpData->GuestVmcb.ControlArea.InterceptException & ~SVM_InterceptException_SS);
    VpData->GuestVmcb.ControlArea.InterceptMisc1 |= SVM_INTERCEPT_MISC1_GDTR_READ;
    SvInjectSsException(VpData);
}

EXTERN_C BOOLEAN NTAPI SvHandleVmExit(PVIRTUAL_PROCESSOR_DATA VpData, PGUEST_REGISTERS GuestRegisters)
{
    GUEST_CONTEXT guestContext;
    KIRQL oldIrql;
    guestContext.VpRegs = GuestRegisters;
    guestContext.ExitVm = FALSE;
    __svm_vmload(VpData->HostStackLayout.HostVmcbPa);
    oldIrql = KeGetCurrentIrql();
    if (oldIrql < DISPATCH_LEVEL) KeRaiseIrqlToDpcLevel();
    GuestRegisters->Rax = VpData->GuestVmcb.StateSaveArea.Rax;
    VpData->HostStackLayout.TrapFrame.Rsp = VpData->GuestVmcb.StateSaveArea.Rsp;
    VpData->HostStackLayout.TrapFrame.Rip = VpData->GuestVmcb.ControlArea.NRip;
    switch (VpData->GuestVmcb.ControlArea.ExitCode)
    {
    case VMEXIT_CPUID:        SvHandleCpuid(VpData, &guestContext); break;
    case VMEXIT_MSR:          SvHandleMsrAccess(VpData, &guestContext); break;
    case VMEXIT_GDTR_READ:    SvHandleSGDT(VpData, &guestContext); break;
    case VMEXIT_EXCEPTION_DB: SvHandleDbException(VpData, &guestContext); break;
    case VMEXIT_EXCEPTION_PF: SvHandlePFException(VpData, &guestContext); break;
    case VMEXIT_EXCEPTION_AC: SvHandleACException(VpData, &guestContext); break;
    case VMEXIT_EXCEPTION_SS: SvHandleSsException(VpData, &guestContext); break;
    case VMEXIT_VMRUN:        SvHandleVmrun(VpData, &guestContext); break;
    default:
        KeBugCheckEx(MANUALLY_INITIATED_CRASH, 0xDEADBEEF, (ULONG_PTR)VpData, 0, 0);
    }
    if (oldIrql < DISPATCH_LEVEL) KeLowerIrql(oldIrql);
    if (guestContext.ExitVm != FALSE)
    {
        if (OrigLstar) VpData->GuestVmcb.StateSaveArea.LStar = OrigLstar;
        guestContext.VpRegs->Rax = (UINT64)VpData & 0xFFFFFFFF;
        guestContext.VpRegs->Rbx = VpData->GuestVmcb.ControlArea.NRip;
        guestContext.VpRegs->Rcx = VpData->GuestVmcb.StateSaveArea.Rsp;
        guestContext.VpRegs->Rdx = (UINT64)VpData >> 32;
        __svm_vmload(MmGetPhysicalAddress(&VpData->GuestVmcb).QuadPart);
        _disable();
        __svm_stgi();
        __writemsr(IA32_MSR_EFER, __readmsr(IA32_MSR_EFER) & ~EFER_SVME);
        __writeeflags(VpData->GuestVmcb.StateSaveArea.Rflags);
        return TRUE;
    }
    VpData->GuestVmcb.StateSaveArea.Rax = guestContext.VpRegs->Rax;
    return FALSE;
}

static UINT16 SvGetSegmentAccessRight(UINT16 SegmentSelector, ULONG_PTR GdtBase)
{
    PSEGMENT_DESCRIPTOR descriptor = (PSEGMENT_DESCRIPTOR)(GdtBase + (SegmentSelector & ~RPL_MASK));
    SEGMENT_ATTRIBUTE attribute;
    attribute.Fields.Type = descriptor->Fields.Type;
    attribute.Fields.System = descriptor->Fields.System;
    attribute.Fields.Dpl = descriptor->Fields.Dpl;
    attribute.Fields.Present = descriptor->Fields.Present;
    attribute.Fields.Avl = descriptor->Fields.Avl;
    attribute.Fields.LongMode = descriptor->Fields.LongMode;
    attribute.Fields.DefaultBit = descriptor->Fields.DefaultBit;
    attribute.Fields.Granularity = descriptor->Fields.Granularity;
    attribute.Fields.Reserved1 = 0;
    return attribute.AsUInt16;
}

static BOOLEAN SvIsSimpleSvmHypervisorInstalled(VOID)
{
    int registers[4];
    char vendorId[13];
    __cpuid(registers, CPUID_HV_VENDOR_AND_MAX_FUNCTIONS);
    *(UINT32*)(vendorId + 0) = registers[1];
    *(UINT32*)(vendorId + 4) = registers[2];
    *(UINT32*)(vendorId + 8) = registers[3];
    vendorId[12] = 0;
    return (strcmp(vendorId, "SimpleSvm   ") == 0);
}

static VOID SvPrepareForVirtualization(PVIRTUAL_PROCESSOR_DATA VpData, PSHARED_VIRTUAL_PROCESSOR_DATA SharedVpData, const CONTEXT* ContextRecord)
{
    DESCRIPTOR_TABLE_REGISTER gdtr, idtr;
    PHYSICAL_ADDRESS guestVmcbPa, hostVmcbPa, hostStateAreaPa, pml4BasePa, msrpmPa;
    _sgdt(&gdtr);
    __sidt(&idtr);
    guestVmcbPa = MmGetPhysicalAddress(&VpData->GuestVmcb);
    hostVmcbPa = MmGetPhysicalAddress(&VpData->HostVmcb);
    hostStateAreaPa = MmGetPhysicalAddress(&VpData->HostStateArea);
    pml4BasePa = MmGetPhysicalAddress(&SharedVpData->Pml4Entries);
    msrpmPa = MmGetPhysicalAddress(SharedVpData->MsrPermissionsMap);
    VpData->GuestVmcb.ControlArea.InterceptMisc1 |= SVM_INTERCEPT_MISC1_CPUID;
    VpData->GuestVmcb.ControlArea.InterceptMisc2 |= SVM_INTERCEPT_MISC2_VMRUN;
    VpData->GuestVmcb.ControlArea.InterceptException |= SVM_InterceptException_DB;
    VpData->GuestVmcb.ControlArea.InterceptMisc1 |= SVM_INTERCEPT_MISC1_MSR_PROT;
    VpData->GuestVmcb.ControlArea.MsrpmBasePa = msrpmPa.QuadPart;
    VpData->GuestVmcb.ControlArea.GuestAsid = 1;
    VpData->GuestVmcb.StateSaveArea.GdtrBase = gdtr.Base;
    VpData->GuestVmcb.StateSaveArea.GdtrLimit = gdtr.Limit;
    VpData->GuestVmcb.StateSaveArea.IdtrBase = idtr.Base;
    VpData->GuestVmcb.StateSaveArea.IdtrLimit = idtr.Limit;
    VpData->GuestVmcb.StateSaveArea.CsLimit = GetSegmentLimit(ContextRecord->SegCs);
    VpData->GuestVmcb.StateSaveArea.DsLimit = GetSegmentLimit(ContextRecord->SegDs);
    VpData->GuestVmcb.StateSaveArea.EsLimit = GetSegmentLimit(ContextRecord->SegEs);
    VpData->GuestVmcb.StateSaveArea.SsLimit = GetSegmentLimit(ContextRecord->SegSs);
    VpData->GuestVmcb.StateSaveArea.CsSelector = ContextRecord->SegCs;
    VpData->GuestVmcb.StateSaveArea.DsSelector = ContextRecord->SegDs;
    VpData->GuestVmcb.StateSaveArea.EsSelector = ContextRecord->SegEs;
    VpData->GuestVmcb.StateSaveArea.SsSelector = ContextRecord->SegSs;
    VpData->GuestVmcb.StateSaveArea.CsAttrib = SvGetSegmentAccessRight(ContextRecord->SegCs, gdtr.Base);
    VpData->GuestVmcb.StateSaveArea.DsAttrib = SvGetSegmentAccessRight(ContextRecord->SegDs, gdtr.Base);
    VpData->GuestVmcb.StateSaveArea.EsAttrib = SvGetSegmentAccessRight(ContextRecord->SegEs, gdtr.Base);
    VpData->GuestVmcb.StateSaveArea.SsAttrib = SvGetSegmentAccessRight(ContextRecord->SegSs, gdtr.Base);
    VpData->GuestVmcb.StateSaveArea.Efer = __readmsr(IA32_MSR_EFER);
    VpData->GuestVmcb.StateSaveArea.Cr0 = __readcr0();
    VpData->GuestVmcb.StateSaveArea.Cr2 = __readcr2();
    VpData->GuestVmcb.StateSaveArea.Cr3 = __readcr3();
    VpData->GuestVmcb.StateSaveArea.Cr4 = __readcr4();
    VpData->GuestVmcb.StateSaveArea.Rflags = ContextRecord->EFlags;
    VpData->GuestVmcb.StateSaveArea.Rsp = ContextRecord->Rsp;
    VpData->GuestVmcb.StateSaveArea.Rip = ContextRecord->Rip;
    if ((VpData->GuestVmcb.StateSaveArea.Cr4 & UMIP) == 0)
    {
        if (gdtr.Limit < 0x7F) VpData->GuestVmcb.ControlArea.InterceptMisc1 |= SVM_INTERCEPT_MISC1_GDTR_READ;
    }
    __svm_vmsave(guestVmcbPa.QuadPart);
    VpData->GuestVmcb.StateSaveArea.LStar = LstarHook;
    VpData->HostStackLayout.Reserved1 = -1ULL;
    VpData->HostStackLayout.SharedVpData = SharedVpData;
    VpData->HostStackLayout.Self = VpData;
    VpData->HostStackLayout.HostVmcbPa = hostVmcbPa.QuadPart;
    VpData->HostStackLayout.GuestVmcbPa = guestVmcbPa.QuadPart;
    __writemsr(SVM_MSR_VM_HSAVE_PA, hostStateAreaPa.QuadPart);
    __svm_vmsave(hostVmcbPa.QuadPart);
}

static NTSTATUS SvVirtualizeProcessor(PVOID Context)
{
    NTSTATUS status;
    PSHARED_VIRTUAL_PROCESSOR_DATA sharedVpData;
    PVIRTUAL_PROCESSOR_DATA vpData;
    PCONTEXT contextRecord;
    vpData = nullptr;
    contextRecord = (PCONTEXT)ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(CONTEXT), 'MVSS');
    if (contextRecord == nullptr) return STATUS_INSUFFICIENT_RESOURCES;
    vpData = (PVIRTUAL_PROCESSOR_DATA)SvAllocatePageAlingedPhysicalMemory(sizeof(VIRTUAL_PROCESSOR_DATA));
    if (vpData == nullptr)
    {
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto Exit;
    }
    RtlCaptureContext(contextRecord);
    if (SvIsSimpleSvmHypervisorInstalled() == FALSE)
    {
        SvDebugPrint("Attempting to virtualize the processor.\n");
        sharedVpData = (PSHARED_VIRTUAL_PROCESSOR_DATA)Context;
        __writemsr(IA32_MSR_EFER, __readmsr(IA32_MSR_EFER) | EFER_SVME);
        SvPrepareForVirtualization(vpData, sharedVpData, contextRecord);
        SvLaunchVm(&vpData->HostStackLayout.GuestVmcbPa);
        KeBugCheck(MANUALLY_INITIATED_CRASH);
    }
    SvDebugPrint("The processor has been virtualized.\n");
    status = STATUS_SUCCESS;
Exit:
    if (contextRecord) ExFreePoolWithTag(contextRecord, 'MVSS');
    if ((!NT_SUCCESS(status)) && (vpData)) SvFreePageAlingedPhysicalMemory(vpData);
    return status;
}

static NTSTATUS SvExecuteOnEachProcessor(NTSTATUS(*Callback)(PVOID), PVOID Context, PULONG NumOfProcessorCompleted)
{
    NTSTATUS status = STATUS_SUCCESS;
    ULONG i, numOfProcessors = KeQueryActiveProcessorCountEx(ALL_PROCESSOR_GROUPS);
    for (i = 0; i < numOfProcessors; i++)
    {
        PROCESSOR_NUMBER processorNumber;
        status = KeGetProcessorNumberFromIndex(i, &processorNumber);
        if (!NT_SUCCESS(status)) goto Exit;
        GROUP_AFFINITY affinity, oldAffinity;
        affinity.Group = processorNumber.Group;
        affinity.Mask = 1ULL << processorNumber.Number;
        affinity.Reserved[0] = affinity.Reserved[1] = affinity.Reserved[2] = 0;
        KeSetSystemGroupAffinityThread(&affinity, &oldAffinity);
        status = Callback(Context);
        KeRevertToUserGroupAffinityThread(&oldAffinity);
        if (!NT_SUCCESS(status)) goto Exit;
    }
Exit:
    if (NumOfProcessorCompleted) *NumOfProcessorCompleted = i;
    return status;
}

static NTSTATUS SvDevirtualizeProcessor(PVOID Context)
{
    int registers[4];
    UINT64 high, low;
    PVIRTUAL_PROCESSOR_DATA vpData;
    PSHARED_VIRTUAL_PROCESSOR_DATA* sharedVpDataPtr;
    if (!ARGUMENT_PRESENT(Context)) return STATUS_SUCCESS;
    __cpuidex(registers, CPUID_UNLOAD_SIMPLE_SVM, CPUID_UNLOAD_SIMPLE_SVM);
    if (registers[2] != 'SSVM') return STATUS_SUCCESS;
    SvDebugPrint("The processor has been de-virtualized.\n");
    high = registers[3];
    low = registers[0] & 0xFFFFFFFF;
    vpData = (PVIRTUAL_PROCESSOR_DATA)(high << 32 | low);
    sharedVpDataPtr = (PSHARED_VIRTUAL_PROCESSOR_DATA*)Context;
    *sharedVpDataPtr = vpData->HostStackLayout.SharedVpData;
    SvFreePageAlingedPhysicalMemory(vpData);
    return STATUS_SUCCESS;
}

static VOID SvDevirtualizeAllProcessors(VOID)
{
    PSHARED_VIRTUAL_PROCESSOR_DATA sharedVpData = nullptr;
    SvExecuteOnEachProcessor(SvDevirtualizeProcessor, &sharedVpData, nullptr);
    if (sharedVpData)
    {
        SvFreeContiguousMemory(sharedVpData->MsrPermissionsMap);
        SvFreePageAlingedPhysicalMemory(sharedVpData);
    }
}

static VOID SvBuildMsrPermissionsMap(PVOID MsrPermissionsMap)
{
    const UINT32 BITS_PER_MSR = 2;
    const UINT32 SECOND_MSR_RANGE_BASE = 0xc0000000;
    const UINT32 SECOND_MSRPM_OFFSET = 0x800 * 8;
    RTL_BITMAP bitmapHeader;
    ULONG offsetFrom2ndBase, offset;
    RtlInitializeBitMap(&bitmapHeader, (PULONG)MsrPermissionsMap, SVM_MSR_PERMISSIONS_MAP_SIZE * 8);
    RtlClearAllBits(&bitmapHeader);
    offsetFrom2ndBase = (IA32_MSR_EFER - SECOND_MSR_RANGE_BASE) * BITS_PER_MSR;
    offset = SECOND_MSRPM_OFFSET + offsetFrom2ndBase;
    RtlSetBits(&bitmapHeader, offset + 1, 1);
    offsetFrom2ndBase = (IA32_MSR_LSTAR - SECOND_MSR_RANGE_BASE) * BITS_PER_MSR;
    offset = SECOND_MSRPM_OFFSET + offsetFrom2ndBase;
    RtlSetBits(&bitmapHeader, offset, 1);
    RtlSetBits(&bitmapHeader, offset + 1, 1);
}

static VOID SvBuildNestedPageTables(PSHARED_VIRTUAL_PROCESSOR_DATA SharedVpData)
{
    for (UINT64 pml4Index = 0; pml4Index < 2; pml4Index++)
    {
        PPML4_ENTRY_2MB pml4e = &SharedVpData->Pml4Entries[pml4Index];
        PPML4E_TREE pml4eTree = &SharedVpData->Pml4eTrees[pml4Index];
        UINT64 pdptBasePa = MmGetPhysicalAddress(&pml4eTree->PdptEntries).QuadPart;
        pml4e->Fields.PageFrameNumber = pdptBasePa >> PAGE_SHIFT;
        pml4e->Fields.Valid = 1;
        pml4e->Fields.Write = 1;
        pml4e->Fields.User = 1;
        for (UINT64 pdptIndex = 0; pdptIndex < 512; pdptIndex++)
        {
            UINT64 pdBasePa = MmGetPhysicalAddress(&pml4eTree->PdEntries[pdptIndex][0]).QuadPart;
            pml4eTree->PdptEntries[pdptIndex].Fields.PageFrameNumber = pdBasePa >> PAGE_SHIFT;
            pml4eTree->PdptEntries[pdptIndex].Fields.Valid = 1;
            pml4eTree->PdptEntries[pdptIndex].Fields.Write = 1;
            pml4eTree->PdptEntries[pdptIndex].Fields.User = 1;
            for (UINT64 pdIndex = 0; pdIndex < 512; pdIndex++)
            {
                UINT64 translationPa = (pml4Index * 512 * 512) + (pdptIndex * 512) + pdIndex;
                pml4eTree->PdEntries[pdptIndex][pdIndex].Fields.PageFrameNumber = translationPa;
                pml4eTree->PdEntries[pdptIndex][pdIndex].Fields.Valid = 1;
                pml4eTree->PdEntries[pdptIndex][pdIndex].Fields.Write = 1;
                pml4eTree->PdEntries[pdptIndex][pdIndex].Fields.User = 1;
                pml4eTree->PdEntries[pdptIndex][pdIndex].Fields.LargePage = 1;
            }
        }
    }
}

static BOOLEAN SvIsSvmSupported(VOID)
{
    int registers[4];
    __cpuid(registers, 0);
    if ((registers[1] != 'htuA') || (registers[3] != 'itne') || (registers[2] != 'DMAc')) return FALSE;
    __cpuid(registers, 0x80000001);
    if ((registers[2] & (1 << 2)) == 0) return FALSE;
    __cpuid(registers, 0x8000000A);
    if ((registers[3] & 1) == 0) return FALSE;
    UINT64 vmcr = __readmsr(SVM_MSR_VM_CR);
    if ((vmcr & SVM_VM_CR_SVMDIS) != 0) return FALSE;
    return TRUE;
}

static NTSTATUS SvVirtualizeAllProcessors(VOID)
{
    NTSTATUS status;
    PSHARED_VIRTUAL_PROCESSOR_DATA sharedVpData = nullptr;
    ULONG numOfProcessorsCompleted = 0;
    if (SvIsSvmSupported() == FALSE) return STATUS_HV_FEATURE_UNAVAILABLE;
    sharedVpData = (PSHARED_VIRTUAL_PROCESSOR_DATA)SvAllocatePageAlingedPhysicalMemory(sizeof(SHARED_VIRTUAL_PROCESSOR_DATA));
    if (sharedVpData == nullptr) return STATUS_INSUFFICIENT_RESOURCES;
    sharedVpData->MsrPermissionsMap = SvAllocateContiguousMemory(SVM_MSR_PERMISSIONS_MAP_SIZE);
    if (sharedVpData->MsrPermissionsMap == nullptr)
    {
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto Exit;
    }
    SvBuildNestedPageTables(sharedVpData);
    SvBuildMsrPermissionsMap(sharedVpData->MsrPermissionsMap);
    if (!OrigLstar) OrigLstar = __readmsr(IA32_MSR_LSTAR);
    status = SvExecuteOnEachProcessor(SvVirtualizeProcessor, sharedVpData, &numOfProcessorsCompleted);
Exit:
    if (!NT_SUCCESS(status))
    {
        if (numOfProcessorsCompleted != 0)
        {
            SvDevirtualizeAllProcessors();
        }
        else
        {
            if (sharedVpData)
            {
                if (sharedVpData->MsrPermissionsMap) SvFreeContiguousMemory(sharedVpData->MsrPermissionsMap);
                SvFreePageAlingedPhysicalMemory(sharedVpData);
            }
        }
    }
    return status;
}

static VOID SvPowerCallbackRoutine(PVOID CallbackContext, PVOID Argument1, PVOID Argument2)
{
    UNREFERENCED_PARAMETER(CallbackContext);
    if (Argument1 != (PVOID)PO_CB_SYSTEM_STATE_LOCK) return;
    if (Argument2 != FALSE)
        SvVirtualizeAllProcessors();
    else
        SvDevirtualizeAllProcessors();
}

static VOID SvDriverUnload(PDRIVER_OBJECT DriverObject)
{
    UNREFERENCED_PARAMETER(DriverObject);
    if (CounterThreadHandle)
    {
        PETHREAD CounterThread = NULL;
        ObReferenceObjectByHandle(CounterThreadHandle, 0, *PsThreadType, KernelMode, (PVOID*)&CounterThread, NULL);
        StopCounterThread = TRUE;
        if (NotifyRoutineActive) ProcessExitCleanup = TRUE;
        KeWaitForSingleObject(CounterThread, Executive, KernelMode, FALSE, NULL);
        ObDereferenceObject(CounterThread);
        ZwClose(CounterThreadHandle);
        CounterThreadHandle = NULL;
    }
    if (g_PowerCallbackRegistration) ExUnregisterCallback(g_PowerCallbackRegistration);
    SvDevirtualizeAllProcessors();
}

EXTERN_C NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
    NTSTATUS status;
    UNICODE_STRING objectName;
    OBJECT_ATTRIBUTES objectAttributes;
    PCALLBACK_OBJECT callbackObject;
    PVOID callbackRegistration = nullptr;
    UNREFERENCED_PARAMETER(RegistryPath);
    DriverObject->DriverUnload = SvDriverUnload;
    ExInitializeDriverRuntime(DrvRtPoolNxOptIn);
    objectName = RTL_CONSTANT_STRING(L"\\Callback\\PowerState");
    InitializeObjectAttributes(&objectAttributes, &objectName, OBJ_CASE_INSENSITIVE, NULL, NULL);
    status = ExCreateCallback(&callbackObject, &objectAttributes, FALSE, TRUE);
    if (!NT_SUCCESS(status))
    {
        SvDebugPrint("Failed to open power state callback object.\n");
        goto Exit;
    }
    callbackRegistration = ExRegisterCallback(callbackObject, SvPowerCallbackRoutine, nullptr);
    ObDereferenceObject(callbackObject);
    if (callbackRegistration == nullptr)
    {
        SvDebugPrint("Failed to register power state callback.\n");
        status = STATUS_UNSUCCESSFUL;
        goto Exit;
    }
    status = SvVirtualizeAllProcessors();
Exit:
    if (NT_SUCCESS(status))
    {
        NTSTATUS ThreadStatus = PsCreateSystemThread(&CounterThreadHandle, 0, NULL, NULL, NULL, CounterUpdater, NULL);
        if (NT_SUCCESS(ThreadStatus))
        {
            g_PowerCallbackRegistration = callbackRegistration;
        }
        else
        {
            status = STATUS_HV_FEATURE_UNAVAILABLE;
            SvDebugPrint("Failed to create CounterUpdater thread.\n");
            if (callbackRegistration) ExUnregisterCallback(callbackRegistration);
        }
    }
    else
    {
        if (callbackRegistration) ExUnregisterCallback(callbackRegistration);
    }
    return status;
}
