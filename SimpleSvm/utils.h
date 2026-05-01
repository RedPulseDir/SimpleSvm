#pragma once
#include "amd.h"
#include "global.h"

#define RELATIVE_ADDR(insn, operand_offset, size) \
    (UINT64)(*(int*)((BYTE*)insn + operand_offset) + (BYTE*)insn + (int)size)

namespace Utils
{
    // Physical memory helpers
    void* PfnToVirtualAddr(uintptr_t pfn);
    PFN_NUMBER VirtualAddrToPfn(uintptr_t va);
    
    // Module enumeration
    void* GetUserModule32(PEPROCESS Process, PUNICODE_STRING ModuleName);
    void* GetUserModule64(PEPROCESS Process, PUNICODE_STRING ModuleName);
    void* GetKernelModule(PUNICODE_STRING DriverName, PSIZE_T OutSize = nullptr);
    uintptr_t GetModuleFromAddress32(PEPROCESS Process, uintptr_t Address, PUNICODE_STRING ModuleName);
    
    // Pattern scanning
    uintptr_t FindPattern(uintptr_t RegionBase, size_t RegionSize, 
                          const char* Pattern, size_t PatternSize, char Wildcard = '?');
    uintptr_t FindPatternRelative(uintptr_t RegionBase, size_t RegionSize,
                                  const char* Pattern, size_t PatternSize,
                                  int Offset, char Wildcard = '?');
    
    // Memory locking/unlocking
    PMDL LockPages(void* VirtualAddress, LOCK_OPERATION Operation, 
                   KPROCESSOR_MODE AccessMode, int Size = PAGE_SIZE);
    NTSTATUS UnlockPages(PMDL Mdl);
    
    // Page table operations
    PT_ENTRY_64* GetPte(void* VirtualAddress, uintptr_t Pml4BasePa,
                        int (*Callback)(PT_ENTRY_64*, void*) = nullptr, 
                        void* CallbackData = nullptr);
    
    // Thread local storage
    template <typename T>
    T** GetTlsPtr(uintptr_t GsBase, uint32_t TlsIndex)
    {
        // gs_base == NtCurrentTeb()
        if (TlsIndex < 64) {
            return (T**)(GsBase + 8 * TlsIndex + 0x1480);
        } else {
            uintptr_t TlsExpansionSlots = *(uintptr_t*)(GsBase + 0x1780);
            return (T**)(TlsExpansionSlots + 8 * (TlsIndex - 64));
        }
    }
    
    // Utility functions
    int Exponent(int Base, int Power);
    template <typename T> uint32_t Diff(T A, T B) {
        return (A > B) ? (uint32_t)(A - B) : (uint32_t)(B - A);
    }
    
    // CPUID helpers
    void Cpuid(int CpuInfo[4], int FunctionId, int SubFunctionId = 0);
    BOOLEAN IsAmdCpu();
    BOOLEAN IsIntelCpu();
    
    // MSR helpers
    UINT64 ReadMsrSafe(UINT32 Msr, PBOOLEAN Success = nullptr);
    BOOLEAN WriteMsrSafe(UINT32 Msr, UINT64 Value);
    
    // Exception handling
    BOOLEAN IsInsideExceptionHandler();
    VOID InstallVectoredExceptionHandler();
    VOID RemoveVectoredExceptionHandler();
}
