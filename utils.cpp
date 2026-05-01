#include "utils.h"
#include "pte.h"

namespace Utils
{
    void* PfnToVirtualAddr(uintptr_t pfn) {
        PHYSICAL_ADDRESS pa;
        pa.QuadPart = pfn << PAGE_SHIFT;
        return MmGetVirtualForPhysical(pa);
    }
    
    PFN_NUMBER VirtualAddrToPfn(uintptr_t va) {
        PHYSICAL_ADDRESS pa = MmGetPhysicalAddress((PVOID)va);
        return (PFN_NUMBER)(pa.QuadPart >> PAGE_SHIFT);
    }
    
    void* GetUserModule32(PEPROCESS Process, PUNICODE_STRING ModuleName) {
        KAPC_STATE ApcState;
        KeStackAttachProcess(Process, &ApcState);
        
        void* ModuleBase = nullptr;
        PPEB Peb = (PPEB)PsGetProcessPeb(Process);
        
        if (Peb && Peb->Ldr) {
            LIST_ENTRY* Head = &Peb->Ldr->InLoadOrderModuleList;
            LIST_ENTRY* Entry = Head->Flink;
            
            while (Entry != Head && !ModuleBase) {
                LDR_DATA_TABLE_ENTRY* LdrEntry = CONTAINING_RECORD(Entry, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
                
                if (LdrEntry->DllBase && LdrEntry->BaseDllName.Buffer) {
                    if (RtlCompareUnicodeString(ModuleName, &LdrEntry->BaseDllName, TRUE) == 0) {
                        ModuleBase = LdrEntry->DllBase;
                        break;
                    }
                }
                Entry = Entry->Flink;
            }
        }
        
        KeUnstackDetachProcess(&ApcState);
        return ModuleBase;
    }
    
    void* GetUserModule64(PEPROCESS Process, PUNICODE_STRING ModuleName) {
        return GetUserModule32(Process, ModuleName); // Same on x64
    }
    
    void* GetKernelModule(PUNICODE_STRING DriverName, PSIZE_T OutSize) {
        void* ModuleBase = nullptr;
        SIZE_T ModuleSize = 0;
        
        for (PLIST_ENTRY Entry = PsLoadedModuleList->Flink;
             Entry != PsLoadedModuleList;
             Entry = Entry->Flink) {
            
            LDR_DATA_TABLE_ENTRY* LdrEntry = CONTAINING_RECORD(Entry, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
            
            if (RtlCompareUnicodeString(DriverName, &LdrEntry->BaseDllName, TRUE) == 0) {
                ModuleBase = LdrEntry->DllBase;
                ModuleSize = (SIZE_T)LdrEntry->SizeOfImage;
                break;
            }
        }
        
        if (OutSize) *OutSize = ModuleSize;
        return ModuleBase;
    }
    
    uintptr_t GetModuleFromAddress32(PEPROCESS Process, uintptr_t Address, PUNICODE_STRING ModuleName) {
        KAPC_STATE ApcState;
        KeStackAttachProcess(Process, &ApcState);
        
        uintptr_t ModuleBase = 0;
        PPEB Peb = (PPEB)PsGetProcessPeb(Process);
        
        if (Peb && Peb->Ldr) {
            LIST_ENTRY* Head = &Peb->Ldr->InLoadOrderModuleList;
            LIST_ENTRY* Entry = Head->Flink;
            
            while (Entry != Head && !ModuleBase) {
                LDR_DATA_TABLE_ENTRY* LdrEntry = CONTAINING_RECORD(Entry, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
                
                if (LdrEntry->DllBase && Address >= (uintptr_t)LdrEntry->DllBase &&
                    Address < (uintptr_t)LdrEntry->DllBase + LdrEntry->SizeOfImage) {
                    if (ModuleName) RtlCopyUnicodeString(ModuleName, &LdrEntry->BaseDllName);
                    ModuleBase = (uintptr_t)LdrEntry->DllBase;
                    break;
                }
                Entry = Entry->Flink;
            }
        }
        
        KeUnstackDetachProcess(&ApcState);
        return ModuleBase;
    }
    
    uintptr_t FindPattern(uintptr_t RegionBase, size_t RegionSize, 
                          const char* Pattern, size_t PatternSize, char Wildcard) {
        for (size_t i = 0; i < RegionSize - PatternSize; i++) {
            bool Found = true;
            for (size_t j = 0; j < PatternSize; j++) {
                char Byte = ((char*)RegionBase)[i + j];
                if (Pattern[j] != Wildcard && Pattern[j] != Byte) {
                    Found = false;
                    break;
                }
            }
            if (Found) return RegionBase + i;
        }
        return 0;
    }
    
    uintptr_t FindPatternRelative(uintptr_t RegionBase, size_t RegionSize,
                                  const char* Pattern, size_t PatternSize,
                                  int Offset, char Wildcard) {
        uintptr_t Match = FindPattern(RegionBase, RegionSize, Pattern, PatternSize, Wildcard);
        if (Match) Match += Offset;
        return Match;
    }
    
    PMDL LockPages(void* VirtualAddress, LOCK_OPERATION Operation, 
                   KPROCESSOR_MODE AccessMode, int Size) {
        PMDL Mdl = IoAllocateMdl(VirtualAddress, Size, FALSE, FALSE, nullptr);
        if (!Mdl) return nullptr;
        
        __try {
            MmProbeAndLockPages(Mdl, AccessMode, Operation);
        } __except(EXCEPTION_EXECUTE_HANDLER) {
            IoFreeMdl(Mdl);
            return nullptr;
        }
        
        return Mdl;
    }
    
    NTSTATUS UnlockPages(PMDL Mdl) {
        if (!Mdl) return STATUS_INVALID_PARAMETER;
        
        MmUnlockPages(Mdl);
        IoFreeMdl(Mdl);
        return STATUS_SUCCESS;
    }
    
    PT_ENTRY_64* GetPte(void* VirtualAddress, uintptr_t Pml4BasePa,
                        int (*Callback)(PT_ENTRY_64*, void*), void* CallbackData) {
        AddressTranslationHelper Helper;
        Helper.as_int64 = (uintptr_t)VirtualAddress;
        
        PHYSICAL_ADDRESS Pml4Physical;
        Pml4Physical.QuadPart = Pml4BasePa;
        
        PML4E_64* Pml4 = (PML4E_64*)MmGetVirtualForPhysical(Pml4Physical);
        if (!Pml4) return nullptr;
        
        PML4E_64* Pml4e = &Pml4[Helper.AsIndex.pml4];
        if (Callback) Callback((PT_ENTRY_64*)Pml4e, CallbackData);
        if (!Pml4e->Fields.Present) return nullptr;
        
        PDPTE_64* Pdpt = (PDPTE_64*)PfnToVirtualAddr(Pml4e->Fields.PageFrameNumber);
        if (!Pdpt) return nullptr;
        
        PDPTE_64* Pdpte = &Pdpt[Helper.AsIndex.pdpt];
        if (Callback) Callback((PT_ENTRY_64*)Pdpte, CallbackData);
        if (Pdpte->Fields.LargePage) return (PT_ENTRY_64*)Pdpte;
        if (!Pdpte->Fields.Present) return nullptr;
        
        PDE_64* Pd = (PDE_64*)PfnToVirtualAddr(Pdpte->Fields.PageFrameNumber);
        if (!Pd) return nullptr;
        
        PDE_64* Pde = &Pd[Helper.AsIndex.pd];
        if (Callback) Callback((PT_ENTRY_64*)Pde, CallbackData);
        if (Pde->Fields.LargePage) return (PT_ENTRY_64*)Pde;
        if (!Pde->Fields.Present) return nullptr;
        
        PTE_64* Pt = (PTE_64*)PfnToVirtualAddr(Pde->Fields.PageFrameNumber);
        if (!Pt) return nullptr;
        
        PTE_64* Pte = &Pt[Helper.AsIndex.pt];
        if (Callback) Callback((PT_ENTRY_64*)Pte, CallbackData);
        if (!Pte->Fields.Present) return nullptr;
        
        return (PT_ENTRY_64*)Pte;
    }
    
    int Exponent(int Base, int Power) {
        int Result = 1;
        for (int i = 0; i < Power; i++) Result *= Base;
        return Result;
    }
    
    void Cpuid(int CpuInfo[4], int FunctionId, int SubFunctionId) {
        __cpuidex(CpuInfo, FunctionId, SubFunctionId);
    }
    
    BOOLEAN IsAmdCpu() {
        int Regs[4];
        Cpuid(Regs, 0);
        return (Regs[1] == 'htuA' && Regs[3] == 'itne' && Regs[2] == 'DMAc');
    }
    
    BOOLEAN IsIntelCpu() {
        int Regs[4];
        Cpuid(Regs, 0);
        return (Regs[1] == 'tneI' && Regs[3] == 'erae' && Regs[2] == 'lAeu');
    }
    
    UINT64 ReadMsrSafe(UINT32 Msr, PBOOLEAN Success) {
        BOOLEAN LocalSuccess = FALSE;
        UINT64 Value = 0;
        
        __try {
            Value = __readmsr(Msr);
            LocalSuccess = TRUE;
        } __except(EXCEPTION_EXECUTE_HANDLER) {
            LocalSuccess = FALSE;
        }
        
        if (Success) *Success = LocalSuccess;
        return Value;
    }
    
    BOOLEAN WriteMsrSafe(UINT32 Msr, UINT64 Value) {
        __try {
            __writemsr(Msr, Value);
            return TRUE;
        } __except(EXCEPTION_EXECUTE_HANDLER) {
            return FALSE;
        }
    }
    
    BOOLEAN IsInsideExceptionHandler() {
        // Check if we're in VEH context
        return FALSE; // Simplified
    }
    
    VOID InstallVectoredExceptionHandler() {
        // Not implemented in this version
    }
    
    VOID RemoveVectoredExceptionHandler() {
        // Not implemented in this version
    }
}
