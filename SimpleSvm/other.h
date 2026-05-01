#ifndef _OTHER_H
#define _OTHER_H

#include "global.h"

namespace other {
    // Process enumeration
    PEPROCESS GetProcessByName(const wchar_t* ProcessName);
    PEPROCESS GetProcessById(HANDLE ProcessId);
    HANDLE GetProcessIdByName(const wchar_t* ProcessName);
    
    // Module enumeration
    PVOID GetModuleBase(PEPROCESS Process, const wchar_t* ModuleName);
    SIZE_T GetModuleSize(PEPROCESS Process, PVOID ModuleBase);
    PVOID GetModuleExport(PEPROCESS Process, PVOID ModuleBase, const char* ExportName);
    
    // Pattern scanning
    UINT64 FindPattern(PEPROCESS Process, PVOID Start, SIZE_T Size, 
                       const char* Pattern, SIZE_T PatternSize, char Wildcard = '?');
    UINT64 FindPatternInModule(PEPROCESS Process, const wchar_t* ModuleName,
                               const char* Pattern, SIZE_T PatternSize, char Wildcard = '?');
    
    // Memory operations
    BOOLEAN ReadProcessMemory(PEPROCESS Process, PVOID Address, PVOID Buffer, SIZE_T Size);
    BOOLEAN WriteProcessMemory(PEPROCESS Process, PVOID Address, PVOID Buffer, SIZE_T Size);
    BOOLEAN ProtectProcessMemory(PEPROCESS Process, PVOID Address, SIZE_T Size, ULONG NewProtect, PULONG OldProtect);
    
    // Thread operations
    HANDLE CreateRemoteThread(PEPROCESS Process, PVOID StartAddress, PVOID Parameter = nullptr);
    NTSTATUS SuspendAllThreads(PEPROCESS Process, BOOLEAN Suspend);
    
    // Handle operations
    HANDLE DuplicateHandleFromProcess(PEPROCESS SourceProcess, HANDLE SourceHandle, 
                                      PEPROCESS TargetProcess, ACCESS_MASK DesiredAccess);
}

#endif
