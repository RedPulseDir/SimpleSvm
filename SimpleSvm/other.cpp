#include "other.h"
#include "pte.h"

namespace other {

PEPROCESS GetProcessByName(const wchar_t* ProcessName) {
    PEPROCESS Process = nullptr;
    ULONG_PTR HandleTable = 0;
    
    for (ULONG i = 4; i < 0x10000; i += 4) {
        HANDLE Pid = (HANDLE)i;
        if (PsLookupProcessByProcessId(Pid, &Process) == STATUS_SUCCESS) {
            UNICODE_STRING ImageName = { 0 };
            PVOID ImageNamePtr = nullptr;
            
            // Получаем имя процесса через SeLocateProcessImageName
            NTSTATUS Status = SeLocateProcessImageName(Process, &ImageNamePtr);
            if (NT_SUCCESS(Status) && ImageNamePtr) {
                RtlInitUnicodeString(&ImageName, (PCWSTR)ImageNamePtr);
                
                // Извлекаем имя файла из полного пути
                wchar_t Buffer[260] = { 0 };
                if (ImageName.Length < sizeof(Buffer)) {
                    RtlCopyMemory(Buffer, ImageName.Buffer, ImageName.Length);
                    
                    // Ищем последний бэкслэш
                    for (int j = wcslen(Buffer) - 1; j >= 0; j--) {
                        if (Buffer[j] == L'\\') {
                            if (_wcsicmp(Buffer + j + 1, ProcessName) == 0) {
                                ObDereferenceObject(Process);
                                return Process;
                            }
                            break;
                        }
                    }
                }
                ObfDereferenceObject(ImageNamePtr);
            }
            ObDereferenceObject(Process);
        }
    }
    return nullptr;
}

PEPROCESS GetProcessById(HANDLE ProcessId) {
    PEPROCESS Process = nullptr;
    if (PsLookupProcessByProcessId(ProcessId, &Process) == STATUS_SUCCESS) {
        return Process;
    }
    return nullptr;
}

HANDLE GetProcessIdByName(const wchar_t* ProcessName) {
    PEPROCESS Process = GetProcessByName(ProcessName);
    if (Process) {
        HANDLE Pid = PsGetProcessId(Process);
        ObDereferenceObject(Process);
        return Pid;
    }
    return nullptr;
}

PVOID GetModuleBase(PEPROCESS Process, const wchar_t* ModuleName) {
    if (!Process) return nullptr;
    
    KAPC_STATE ApcState;
    KeStackAttachProcess(Process, &ApcState);
    
    PVOID ModuleBase = nullptr;
    PPEB Peb = (PPEB)PsGetProcessPeb(Process);
    
    if (Peb && Peb->Ldr) {
        LIST_ENTRY* Head = &Peb->Ldr->InMemoryOrderModuleList;
        LIST_ENTRY* Entry = Head->Flink;
        
        while (Entry != Head) {
            LDR_DATA_TABLE_ENTRY* LdrEntry = CONTAINING_RECORD(Entry, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
            
            if (LdrEntry->DllBase && LdrEntry->BaseDllName.Buffer) {
                if (_wcsicmp(LdrEntry->BaseDllName.Buffer, ModuleName) == 0) {
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

SIZE_T GetModuleSize(PEPROCESS Process, PVOID ModuleBase) {
    if (!Process || !ModuleBase) return 0;
    
    KAPC_STATE ApcState;
    KeStackAttachProcess(Process, &ApcState);
    
    SIZE_T ModuleSize = 0;
    PPEB Peb = (PPEB)PsGetProcessPeb(Process);
    
    if (Peb && Peb->Ldr) {
        LIST_ENTRY* Head = &Peb->Ldr->InMemoryOrderModuleList;
        LIST_ENTRY* Entry = Head->Flink;
        
        while (Entry != Head) {
            LDR_DATA_TABLE_ENTRY* LdrEntry = CONTAINING_RECORD(Entry, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
            
            if (LdrEntry->DllBase == ModuleBase) {
                ModuleSize = (SIZE_T)LdrEntry->SizeOfImage;
                break;
            }
            Entry = Entry->Flink;
        }
    }
    
    KeUnstackDetachProcess(&ApcState);
    return ModuleSize;
}

PVOID GetModuleExport(PEPROCESS Process, PVOID ModuleBase, const char* ExportName) {
    if (!Process || !ModuleBase || !ExportName) return nullptr;
    
    KAPC_STATE ApcState;
    KeStackAttachProcess(Process, &ApcState);
    
    PVOID ExportAddress = nullptr;
    __try {
        PIMAGE_DOS_HEADER Dos = (PIMAGE_DOS_HEADER)ModuleBase;
        if (Dos->e_magic != IMAGE_DOS_SIGNATURE) __leave;
        
        PIMAGE_NT_HEADERS Nt = (PIMAGE_NT_HEADERS)((BYTE*)ModuleBase + Dos->e_lfanew);
        if (Nt->Signature != IMAGE_NT_SIGNATURE) __leave;
        
        DWORD Rva = Nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
        if (!Rva) __leave;
        
        PIMAGE_EXPORT_DIRECTORY Export = (PIMAGE_EXPORT_DIRECTORY)((BYTE*)ModuleBase + Rva);
        
        DWORD* Names = (DWORD*)((BYTE*)ModuleBase + Export->AddressOfNames);
        WORD* Ordinals = (WORD*)((BYTE*)ModuleBase + Export->AddressOfNameOrdinals);
        DWORD* Functions = (DWORD*)((BYTE*)ModuleBase + Export->AddressOfFunctions);
        
        for (DWORD i = 0; i < Export->NumberOfNames; i++) {
            const char* Name = (const char*)ModuleBase + Names[i];
            if (strcmp(Name, ExportName) == 0) {
                ExportAddress = (BYTE*)ModuleBase + Functions[Ordinals[i]];
                break;
            }
        }
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        ExportAddress = nullptr;
    }
    
    KeUnstackDetachProcess(&ApcState);
    return ExportAddress;
}

UINT64 FindPattern(PEPROCESS Process, PVOID Start, SIZE_T Size, 
                   const char* Pattern, SIZE_T PatternSize, char Wildcard) {
    if (!Process || !Start || !Size || !Pattern || !PatternSize) return 0;
    
    UINT64 Result = 0;
    KAPC_STATE ApcState;
    KeStackAttachProcess(Process, &ApcState);
    
    BYTE* Buffer = (BYTE*)ExAllocatePool2(POOL_FLAG_NON_PAGED, Size, 'PTRN');
    if (Buffer) {
        pte* PteManager = pte::GetInstance();
        PteManager->SetProcess(Process);
        
        if (PteManager->ReadVirtual((UINT64)Start, Buffer, Size)) {
            for (SIZE_T i = 0; i <= Size - PatternSize; i++) {
                BOOLEAN Found = TRUE;
                for (SIZE_T j = 0; j < PatternSize; j++) {
                    char PatternChar = Pattern[j];
                    BYTE Byte = Buffer[i + j];
                    if (PatternChar != Wildcard && (BYTE)PatternChar != Byte) {
                        Found = FALSE;
                        break;
                    }
                }
                if (Found) {
                    Result = (UINT64)Start + i;
                    break;
                }
            }
        }
        ExFreePoolWithTag(Buffer, 'PTRN');
    }
    
    KeUnstackDetachProcess(&ApcState);
    return Result;
}

UINT64 FindPatternInModule(PEPROCESS Process, const wchar_t* ModuleName,
                           const char* Pattern, SIZE_T PatternSize, char Wildcard) {
    PVOID ModuleBase = GetModuleBase(Process, ModuleName);
    if (!ModuleBase) return 0;
    
    SIZE_T ModuleSize = GetModuleSize(Process, ModuleBase);
    if (!ModuleSize) return 0;
    
    return FindPattern(Process, ModuleBase, ModuleSize, Pattern, PatternSize, Wildcard);
}

BOOLEAN ReadProcessMemory(PEPROCESS Process, PVOID Address, PVOID Buffer, SIZE_T Size) {
    if (!Process || !Address || !Buffer || !Size) return FALSE;
    
    pte* PteManager = pte::GetInstance();
    PteManager->SetProcess(Process);
    return PteManager->ReadVirtual((UINT64)Address, Buffer, Size);
}

BOOLEAN WriteProcessMemory(PEPROCESS Process, PVOID Address, PVOID Buffer, SIZE_T Size) {
    if (!Process || !Address || !Buffer || !Size) return FALSE;
    
    pte* PteManager = pte::GetInstance();
    PteManager->SetProcess(Process);
    return PteManager->WriteVirtual((UINT64)Address, Buffer, Size);
}

BOOLEAN ProtectProcessMemory(PEPROCESS Process, PVOID Address, SIZE_T Size, 
                             ULONG NewProtect, PULONG OldProtect) {
    if (!Process || !Address || !Size) return FALSE;
    
    KAPC_STATE ApcState;
    KeStackAttachProcess(Process, &ApcState);
    
    BOOLEAN Result = FALSE;
    PMDL Mdl = IoAllocateMdl(Address, (ULONG)Size, FALSE, FALSE, nullptr);
    if (Mdl) {
        __try {
            MmProbeAndLockPages(Mdl, KernelMode, IoReadAccess);
            Result = NT_SUCCESS(MmProtectMdlSystemAddress(Mdl, NewProtect, OldProtect));
            MmUnlockPages(Mdl);
        } __except(EXCEPTION_EXECUTE_HANDLER) {
            Result = FALSE;
        }
        IoFreeMdl(Mdl);
    }
    
    KeUnstackDetachProcess(&ApcState);
    return Result;
}

HANDLE CreateRemoteThread(PEPROCESS Process, PVOID StartAddress, PVOID Parameter) {
    if (!Process || !StartAddress) return nullptr;
    
    HANDLE ThreadHandle = nullptr;
    KAPC_STATE ApcState;
    KeStackAttachProcess(Process, &ApcState);
    
    // Аллокация памяти в целевом процессе
    SIZE_T ShellcodeSize = 32;
    PVOID RemoteCode = nullptr;
    NTSTATUS Status = ZwAllocateVirtualMemory(NtCurrentProcess(), &RemoteCode, 0, 
                                               &ShellcodeSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    
    if (NT_SUCCESS(Status) && RemoteCode) {
        // Шеллкод для вызова функции
        BYTE Code[] = {
            0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // mov rax, func
            0x48, 0x89, 0xE1,                                            // mov rcx, rsp
            0x48, 0x83, 0xEC, 0x20,                                      // sub rsp, 0x20
            0xFF, 0xD0,                                                   // call rax
            0x48, 0x83, 0xC4, 0x20,                                      // add rsp, 0x20
            0xC3                                                          // ret
        };
        *(UINT64*)(Code + 2) = (UINT64)StartAddress;
        
        pte* PteManager = pte::GetInstance();
        PteManager->SetProcess(Process);
        
        if (PteManager->WriteVirtual((UINT64)RemoteCode, Code, ShellcodeSize)) {
            // Создаём поток напрямую через KeStartThread
            PETHREAD Thread = nullptr;
            Status = PsCreateSystemThread(&ThreadHandle, THREAD_ALL_ACCESS, nullptr, nullptr, nullptr,
                                          (PKSTART_ROUTINE)RemoteCode, Parameter);
        }
        
        ZwFreeVirtualMemory(NtCurrentProcess(), &RemoteCode, &ShellcodeSize, MEM_RELEASE);
    }
    
    KeUnstackDetachProcess(&ApcState);
    return ThreadHandle;
}

NTSTATUS SuspendAllThreads(PEPROCESS Process, BOOLEAN Suspend) {
    if (!Process) return STATUS_INVALID_PARAMETER;
    
    NTSTATUS Status = STATUS_SUCCESS;
    KAPC_STATE ApcState;
    KeStackAttachProcess(Process, &ApcState);
    
    // Получаем список потоков через системный вызов
    ULONG BufferSize = 0x10000;
    PSYSTEM_PROCESS_INFORMATION Spi = (PSYSTEM_PROCESS_INFORMATION)ExAllocatePool2(POOL_FLAG_NON_PAGED, BufferSize, 'THRD');
    if (Spi) {
        if (NT_SUCCESS(ZwQuerySystemInformation(SystemProcessInformation, Spi, BufferSize, nullptr))) {
            PSYSTEM_PROCESS_INFORMATION Current = Spi;
            while (Current) {
                if (Current->UniqueProcessId == PsGetProcessId(Process)) {
                    for (ULONG i = 0; i < Current->NumberOfThreads; i++) {
                        PETHREAD Thread = nullptr;
                        HANDLE Tid = (HANDLE)Current->Threads[i].ClientId.UniqueThread;
                        if (NT_SUCCESS(PsLookupThreadByThreadId(Tid, &Thread))) {
                            if (Suspend) {
                                KeSuspendThread(Thread);
                            } else {
                                KeResumeThread(Thread);
                            }
                            ObDereferenceObject(Thread);
                        }
                    }
                    break;
                }
                Current = (PSYSTEM_PROCESS_INFORMATION)((BYTE*)Current + Current->NextEntryOffset);
                if (!Current->NextEntryOffset) break;
            }
        }
        ExFreePoolWithTag(Spi, 'THRD');
    }
    
    KeUnstackDetachProcess(&ApcState);
    return Status;
}

HANDLE DuplicateHandleFromProcess(PEPROCESS SourceProcess, HANDLE SourceHandle,
                                   PEPROCESS TargetProcess, ACCESS_MASK DesiredAccess) {
    if (!SourceProcess || !SourceHandle) return nullptr;
    
    HANDLE TargetHandle = nullptr;
    HANDLE SourceProcessHandle = nullptr;
    
    // Получаем HANDLE для процесса-источника
    NTSTATUS Status = ObOpenObjectByPointer(SourceProcess, OBJ_KERNEL_HANDLE, nullptr, 
                                             PROCESS_DUP_HANDLE, *PsProcessType, KernelMode, 
                                             &SourceProcessHandle);
    
    if (NT_SUCCESS(Status) && SourceProcessHandle) {
        // Определяем целевой процесс (текущий по умолчанию)
        HANDLE TargetProcessHandle = nullptr;
        PEPROCESS TargetProc = TargetProcess ? TargetProcess : PsGetCurrentProcess();
        
        Status = ObOpenObjectByPointer(TargetProc, OBJ_KERNEL_HANDLE, nullptr,
                                        PROCESS_DUP_HANDLE, *PsProcessType, KernelMode,
                                        &TargetProcessHandle);
        
        if (NT_SUCCESS(Status) && TargetProcessHandle) {
            // Дублируем хендл
            Status = ZwDuplicateObject(SourceProcessHandle, SourceHandle, TargetProcessHandle,
                                        &TargetHandle, DesiredAccess, 0, DUPLICATE_SAME_ACCESS);
            ZwClose(TargetProcessHandle);
        }
        ZwClose(SourceProcessHandle);
    }
    
    return TargetHandle;
}

} // namespace other
