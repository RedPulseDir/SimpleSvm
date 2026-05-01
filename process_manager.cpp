#include "process_manager.h"
#include "pte.h"

// Статические члены
TRACKED_PROCESS_INFO ProcessManager::g_TrackedProcess = { 0 };
PKTHREAD ProcessManager::g_WorkerThread = nullptr;
HANDLE ProcessManager::g_WorkerThreadHandle = nullptr;
volatile LONG ProcessManager::g_StopWorker = FALSE;
KEVENT ProcessManager::g_WorkerWakeupEvent;

// Оригинальный LSTAR глобально - защищён
static volatile UINT64 g_OriginalLstar = 0;
static KSPIN_LOCK g_LstarLock;

// Сюда будем писать при регистрации
static UINT64 g_TargetSyscallHandler = 0;
static KSPIN_LOCK g_HandlerLock;

// Callback для уведомлений о процессе
static PVOID g_RegistrationHandle = nullptr;

NTSTATUS ProcessManager::Initialize() {
    KeInitializeSpinLock(&g_LstarLock);
    KeInitializeSpinLock(&g_HandlerLock);
    KeInitializeEvent(&g_WorkerWakeupEvent, NotificationEvent, FALSE);
    KeInitializeEvent(&g_TrackedProcess.RequestEvent, NotificationEvent, FALSE);
    KeInitializeEvent(&g_TrackedProcess.CleanupEvent, NotificationEvent, FALSE);
    KeInitializeSpinLock(&g_TrackedProcess.Lock);
    
    g_TrackedProcess.State = TRACKING_IDLE;
    g_TrackedProcess.ProcessId = NULL;
    g_TrackedProcess.ProcessObject = nullptr;
    g_TrackedProcess.Cr3 = 0;
    g_TrackedProcess.KuserSharedData = nullptr;
    g_TrackedProcess.KuserMdl = nullptr;
    g_TrackedProcess.NotifyRegistered = FALSE;
    g_StopWorker = FALSE;
    
    // Сохраняем оригинальный LSTAR
    KeAcquireSpinLockAtDpcLevel(&g_LstarLock);
    g_OriginalLstar = __readmsr(IA32_MSR_LSTAR);
    KeReleaseSpinLockFromDpcLevel(&g_LstarLock);
    
    // Создаём рабочий поток
    NTSTATUS status = PsCreateSystemThread(
        &g_WorkerThreadHandle,
        THREAD_ALL_ACCESS,
        nullptr,
        nullptr,
        nullptr,
        WorkerThread,
        nullptr
    );
    
    if (!NT_SUCCESS(status)) {
        DbgPrint("[ProcessManager] Failed to create worker thread: 0x%X\n", status);
        return status;
    }
    
    // Получаем объект потока
    status = ObReferenceObjectByHandle(
        g_WorkerThreadHandle,
        THREAD_ALL_ACCESS,
        nullptr,
        KernelMode,
        (PVOID*)&g_WorkerThread,
        nullptr
    );
    
    if (!NT_SUCCESS(status)) {
        ZwClose(g_WorkerThreadHandle);
        g_WorkerThreadHandle = nullptr;
        return status;
    }
    
    DbgPrint("[ProcessManager] Initialized successfully\n");
    return STATUS_SUCCESS;
}

VOID ProcessManager::Shutdown() {
    // Останавливаем поток
    InterlockedExchange(&g_StopWorker, TRUE);
    KeSetEvent(&g_WorkerWakeupEvent, IO_NO_INCREMENT, FALSE);
    
    if (g_WorkerThread) {
        KeWaitForSingleObject(g_WorkerThread, Executive, KernelMode, FALSE, nullptr);
        ObDereferenceObject(g_WorkerThread);
        g_WorkerThread = nullptr;
    }
    
    if (g_WorkerThreadHandle) {
        ZwClose(g_WorkerThreadHandle);
        g_WorkerThreadHandle = nullptr;
    }
    
    // Убираем уведомления если были
    if (g_TrackedProcess.NotifyRegistered) {
        PsSetCreateProcessNotifyRoutineEx(ProcessExitNotify, TRUE);
        g_TrackedProcess.NotifyRegistered = FALSE;
    }
    
    // Чистим KUSER
    CleanupKuserSpoofing();
    
    // Восстанавливаем LSTAR если надо
    if (g_OriginalLstar) {
        KeAcquireSpinLockAtDpcLevel(&g_LstarLock);
        __writemsr(IA32_MSR_LSTAR, g_OriginalLstar);
        KeReleaseSpinLockFromDpcLevel(&g_LstarLock);
    }
    
    DbgPrint("[ProcessManager] Shutdown complete\n");
}

NTSTATUS ProcessManager::RequestTracking(HANDLE ProcessId, UINT64 SyscallHandler) {
    if (!ProcessId || !SyscallHandler) {
        return STATUS_INVALID_PARAMETER;
    }
    
    // Проверяем текущее состояние
    LONG oldState = InterlockedCompareExchange(&g_TrackedProcess.State, 
                                                TRACKING_REQUESTED, 
                                                TRACKING_IDLE);
    if (oldState != TRACKING_IDLE) {
        DbgPrint("[ProcessManager] Already tracking or cleanup pending\n");
        return STATUS_DEVICE_BUSY;
    }
    
    // Сохраняем параметры
    KeAcquireSpinLockAtDpcLevel(&g_HandlerLock);
    g_TargetSyscallHandler = SyscallHandler;
    KeReleaseSpinLockFromDpcLevel(&g_HandlerLock);
    
    g_TrackedProcess.ProcessId = ProcessId;
    g_TrackedProcess.ProcessObject = nullptr;
    g_TrackedProcess.Cr3 = 0;
    
    // Регистрируем callback для exit если ещё не зарегистрирован
    if (!g_TrackedProcess.NotifyRegistered) {
        NTSTATUS status = PsSetCreateProcessNotifyRoutineEx(ProcessExitNotify, FALSE);
        if (!NT_SUCCESS(status)) {
            InterlockedExchange(&g_TrackedProcess.State, TRACKING_IDLE);
            DbgPrint("[ProcessManager] Failed to register notify routine: 0x%X\n", status);
            return status;
        }
        g_TrackedProcess.NotifyRegistered = TRUE;
    }
    
    // Будим воркер
    KeSetEvent(&g_WorkerWakeupEvent, IO_NO_INCREMENT, FALSE);
    
    // Ждём completion или timeout (5 секунд)
    LARGE_INTEGER timeout;
    timeout.QuadPart = -50000000LL; // 5 секунд
    
    NTSTATUS status = KeWaitForSingleObject(&g_TrackedProcess.RequestEvent, 
                                            Executive, 
                                            KernelMode, 
                                            FALSE, 
                                            &timeout);
    
    if (status == STATUS_TIMEOUT) {
        DbgPrint("[ProcessManager] Tracking request timeout\n");
        InterlockedExchange(&g_TrackedProcess.State, TRACKING_IDLE);
        return STATUS_TIMEOUT;
    }
    
    // Проверяем результат
    if (g_TrackedProcess.State == TRACKING_ACTIVE) {
        DbgPrint("[ProcessManager] Successfully tracking process %p\n", ProcessId);
        return STATUS_SUCCESS;
    }
    
    return STATUS_UNSUCCESSFUL;
}

VOID ProcessManager::StopTracking() {
    LONG oldState = InterlockedCompareExchange(&g_TrackedProcess.State, 
                                                TRACKING_CLEANUP_PENDING, 
                                                TRACKING_ACTIVE);
    
    if (oldState == TRACKING_ACTIVE) {
        DbgPrint("[ProcessManager] Stopping tracking\n");
        
        // Будим воркер для очистки
        KeSetEvent(&g_WorkerWakeupEvent, IO_NO_INCREMENT, FALSE);
        
        // Ждём очистки
        KeWaitForSingleObject(&g_TrackedProcess.CleanupEvent, 
                              Executive, 
                              KernelMode, 
                              FALSE, 
                              nullptr);
        
        // Принудительная очистка если воркер не справился
        if (g_TrackedProcess.State != TRACKING_IDLE) {
            CleanupKuserSpoofing();
            
            if (g_TrackedProcess.ProcessObject) {
                PsReleaseProcessExitSynchronization(g_TrackedProcess.ProcessObject);
                ObDereferenceObject(g_TrackedProcess.ProcessObject);
                g_TrackedProcess.ProcessObject = nullptr;
            }
            
            KeAcquireSpinLockAtDpcLevel(&g_TrackedProcess.Lock);
            g_TrackedProcess.ProcessId = NULL;
            g_TrackedProcess.Cr3 = 0;
            g_TrackedProcess.OriginalLstar = 0;
            KeReleaseSpinLockFromDpcLevel(&g_TrackedProcess.Lock);
            
            InterlockedExchange(&g_TrackedProcess.State, TRACKING_IDLE);
        }
    }
}

BOOLEAN ProcessManager::IsTrackingActive() {
    return (g_TrackedProcess.State == TRACKING_ACTIVE);
}

NTSTATUS ProcessManager::UpdateSyscallHandler(UINT64 NewHandler) {
    if (!NewHandler) return STATUS_INVALID_PARAMETER;
    
    KeAcquireSpinLockAtDpcLevel(&g_HandlerLock);
    UINT64 oldHandler = g_TargetSyscallHandler;
    g_TargetSyscallHandler = NewHandler;
    KeReleaseSpinLockFromDpcLevel(&g_HandlerLock);
    
    // TODO: Update VMCB LSTAR if already tracking
    if (IsTrackingActive()) {
        // Signal worker to update
        KeSetEvent(&g_WorkerWakeupEvent, IO_NO_INCREMENT, FALSE);
    }
    
    return STATUS_SUCCESS;
}

NTSTATUS ProcessManager::WorkerThread(PVOID Context) {
    UNREFERENCED_PARAMETER(Context);
    
    LARGE_INTEGER sleepInterval;
    sleepInterval.QuadPart = -10000000LL; // 1ms
    
    DbgPrint("[ProcessManager] Worker thread started\n");
    
    while (!g_StopWorker) {
        // Ждём событие или таймаут для обновления времени
        NTSTATUS waitStatus = KeWaitForSingleObject(&g_WorkerWakeupEvent,
                                                     Executive,
                                                     KernelMode,
                                                     FALSE,
                                                     &sleepInterval);
        
        // Проверяем состояние
        LONG currentState = g_TrackedProcess.State;
        
        switch (currentState) {
            case TRACKING_REQUESTED:
                AttachToProcess(nullptr);
                break;
                
            case TRACKING_ACTIVE:
                // Обновляем время в KUSER_SHARED_DATA
                UpdateKuserTime();
                
                // Проверяем жив ли процесс
                if (!IsProcessAlive(g_TrackedProcess.ProcessId)) {
                    DbgPrint("[ProcessManager] Process died, cleaning up\n");
                    InterlockedExchange(&g_TrackedProcess.State, TRACKING_CLEANUP_PENDING);
                    CleanupKuserSpoofing();
                    InterlockedExchange(&g_TrackedProcess.State, TRACKING_IDLE);
                    KeSetEvent(&g_TrackedProcess.CleanupEvent, IO_NO_INCREMENT, FALSE);
                }
                break;
                
            case TRACKING_CLEANUP_PENDING:
                CleanupKuserSpoofing();
                InterlockedExchange(&g_TrackedProcess.State, TRACKING_IDLE);
                KeSetEvent(&g_TrackedProcess.CleanupEvent, IO_NO_INCREMENT, FALSE);
                break;
        }
        
        // Сбрасываем событие если не останов
        if (!g_StopWorker && waitStatus == STATUS_SUCCESS) {
            KeResetEvent(&g_WorkerWakeupEvent);
        }
    }
    
    DbgPrint("[ProcessManager] Worker thread exiting\n");
    return STATUS_SUCCESS;
}

BOOLEAN ProcessManager::AttachToProcess(PEPROCESS Process) {
    NTSTATUS status;
    PEPROCESS targetProcess = Process;
    
    if (!targetProcess) {
        // Lookup by PID
        status = PsLookupProcessByProcessId(g_TrackedProcess.ProcessId, &targetProcess);
        if (!NT_SUCCESS(status)) {
            DbgPrint("[ProcessManager] Failed to lookup process: 0x%X\n", status);
            InterlockedExchange(&g_TrackedProcess.State, TRACKING_IDLE);
            KeSetEvent(&g_TrackedProcess.RequestEvent, IO_NO_INCREMENT, FALSE);
            return FALSE;
        }
    }
    
    // Acquire exit synchronization to prevent race with process termination
    status = PsAcquireProcessExitSynchronization(targetProcess);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[ProcessManager] Failed to acquire exit sync: 0x%X\n", status);
        ObDereferenceObject(targetProcess);
        InterlockedExchange(&g_TrackedProcess.State, TRACKING_IDLE);
        KeSetEvent(&g_TrackedProcess.RequestEvent, IO_NO_INCREMENT, FALSE);
        return FALSE;
    }
    
    // Get CR3
    UINT64 cr3 = 0;
    __try {
        cr3 = *(UINT64*)((PUCHAR)targetProcess + 0x28);
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        PsReleaseProcessExitSynchronization(targetProcess);
        ObDereferenceObject(targetProcess);
        InterlockedExchange(&g_TrackedProcess.State, TRACKING_IDLE);
        KeSetEvent(&g_TrackedProcess.RequestEvent, IO_NO_INCREMENT, FALSE);
        return FALSE;
    }
    
    // Setup KUSER spoofing
    if (!SetupKuserSpoofing()) {
        PsReleaseProcessExitSynchronization(targetProcess);
        ObDereferenceObject(targetProcess);
        InterlockedExchange(&g_TrackedProcess.State, TRACKING_IDLE);
        KeSetEvent(&g_TrackedProcess.RequestEvent, IO_NO_INCREMENT, FALSE);
        return FALSE;
    }
    
    // Store info
    KeAcquireSpinLockAtDpcLevel(&g_TrackedProcess.Lock);
    g_TrackedProcess.ProcessObject = targetProcess;
    g_TrackedProcess.Cr3 = cr3;
    KeReleaseSpinLockFromDpcLevel(&g_TrackedProcess.Lock);
    
    // Update LSTAR in guest VMCB
    KeAcquireSpinLockAtDpcLevel(&g_HandlerLock);
    UINT64 handler = g_TargetSyscallHandler;
    KeReleaseSpinLockFromDpcLevel(&g_HandlerLock);
    
    // TODO: Update VMCB LSTAR for all VPs
    
    // Success
    InterlockedExchange(&g_TrackedProcess.State, TRACKING_ACTIVE);
    KeSetEvent(&g_TrackedProcess.RequestEvent, IO_NO_INCREMENT, FALSE);
    
    return TRUE;
}

VOID ProcessManager::DetachFromProcess() {
    // Called from cleanup
    if (g_TrackedProcess.ProcessObject) {
        PsReleaseProcessExitSynchronization(g_TrackedProcess.ProcessObject);
        ObDereferenceObject(g_TrackedProcess.ProcessObject);
        g_TrackedProcess.ProcessObject = nullptr;
    }
    
    KeAcquireSpinLockAtDpcLevel(&g_TrackedProcess.Lock);
    g_TrackedProcess.ProcessId = NULL;
    g_TrackedProcess.Cr3 = 0;
    g_TrackedProcess.OriginalLstar = 0;
    KeReleaseSpinLockFromDpcLevel(&g_TrackedProcess.Lock);
}

BOOLEAN ProcessManager::SetupKuserSpoofing() {
    if (!g_TrackedProcess.ProcessObject || !g_TrackedProcess.Cr3) {
        return FALSE;
    }
    
    // Get current PTE for KUSER_SHARED_DATA
    pte* pteManager = pte::GetInstance();
    pteManager->SetProcess(g_TrackedProcess.ProcessObject);
    
    PT_ENTRY_64* kuserPte = pteManager->GetPte(0x7FFE0000);
    if (!kuserPte || !kuserPte->Present) {
        DbgPrint("[ProcessManager] KUSER PTE not present\n");
        return FALSE;
    }
    
    // Mark as copy-on-write
    if (!pteManager->ProtectPage(0x7FFE0000, kuserPte->Flags | 0x200)) { // Set COW bit
        DbgPrint("[ProcessManager] Failed to set COW on KUSER page\n");
        return FALSE;
    }
    
    // Allocate MDL
    PMDL mdl = IoAllocateMdl((PVOID)0x7FFE0000, PAGE_SIZE, FALSE, FALSE, nullptr);
    if (!mdl) return FALSE;
    
    __try {
        MmProbeAndLockPages(mdl, UserMode, IoWriteAccess);
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        IoFreeMdl(mdl);
        return FALSE;
    }
    
    // Map in kernel space
    PVOID mappedKuser = MmMapLockedPagesSpecifyCache(mdl, 
                                                      KernelMode, 
                                                      MmCached, 
                                                      nullptr, 
                                                      FALSE, 
                                                      NormalPagePriority);
    if (!mappedKuser) {
        MmUnlockPages(mdl);
        IoFreeMdl(mdl);
        return FALSE;
    }
    
    // Spoof CPU features
    __try {
        // Disable RDTSCP, RDPID, etc.
        *(UINT8*)((PUCHAR)mappedKuser + 0x294) = 0x00; // RDTSCP disabled
        *(UINT8*)((PUCHAR)mappedKuser + 0x295) = 0x00; // RDPID disabled
        *(UINT8*)((PUCHAR)mappedKuser + 0x297) = 0x00; // RDRAND disabled
        
        // Disable XSAVE/AVX
        *(UINT8*)((PUCHAR)mappedKuser + 0x285) = 0x00; // XSAVE disabled
        *(UINT8*)((PUCHAR)mappedKuser + 0x29B) = 0x00; // AVX disabled
        *(UINT8*)((PUCHAR)mappedKuser + 0x29C) = 0x00; // AVX2 disabled
        
        // Mark as spoofed
        *(UINT32*)((PUCHAR)mappedKuser + 0xFFC) = 0x13371337;
        
        g_TrackedProcess.KuserSharedData = mappedKuser;
        g_TrackedProcess.KuserMdl = mdl;
        
        DbgPrint("[ProcessManager] KUSER spoofing setup for process\n");
        return TRUE;
        
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        MmUnmapLockedPages(mappedKuser, mdl);
        MmUnlockPages(mdl);
        IoFreeMdl(mdl);
        return FALSE;
    }
}

VOID ProcessManager::CleanupKuserSpoofing() {
    if (!g_TrackedProcess.KuserSharedData || !g_TrackedProcess.KuserMdl) {
        return;
    }
    
    __try {
        // Unmap
        MmUnmapLockedPages(g_TrackedProcess.KuserSharedData, g_TrackedProcess.KuserMdl);
        MmUnlockPages(g_TrackedProcess.KuserMdl);
        IoFreeMdl(g_TrackedProcess.KuserMdl);
        
        g_TrackedProcess.KuserSharedData = nullptr;
        g_TrackedProcess.KuserMdl = nullptr;
        
        DbgPrint("[ProcessManager] KUSER cleanup complete\n");
        
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        DbgPrint("[ProcessManager] Exception in KUSER cleanup\n");
    }
}

VOID ProcessManager::UpdateKuserTime() {
    if (!g_TrackedProcess.KuserSharedData) return;
    
    PKUSER_SHARED_DATA kernelKuser = (PKUSER_SHARED_DATA)0xFFFFF78000000000;
    PKUSER_SHARED_DATA spoofedKuser = (PKUSER_SHARED_DATA)g_TrackedProcess.KuserSharedData;
    
    __try {
        // Update time fields
        *(ULONG64*)&spoofedKuser->InterruptTime = *(ULONG64*)&kernelKuser->InterruptTime.LowPart;
        spoofedKuser->InterruptTime.High2Time = spoofedKuser->InterruptTime.High1Time;
        
        *(ULONG64*)&spoofedKuser->SystemTime = *(ULONG64*)&kernelKuser->SystemTime.LowPart;
        spoofedKuser->SystemTime.High2Time = spoofedKuser->SystemTime.High1Time;
        
        *(ULONG64*)&spoofedKuser->TickCount = *(ULONG64*)&kernelKuser->TickCount.LowPart;
        spoofedKuser->TickCount.High2Time = spoofedKuser->TickCount.High1Time;
        
        spoofedKuser->TimeUpdateLock = kernelKuser->TimeUpdateLock;
        spoofedKuser->BaselineSystemTimeQpc = kernelKuser->BaselineSystemTimeQpc;
        
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        DbgPrint("[ProcessManager] Exception updating KUSER time\n");
    }
}

BOOLEAN ProcessManager::IsProcessAlive(HANDLE ProcessId) {
    PEPROCESS process;
    NTSTATUS status = PsLookupProcessByProcessId(ProcessId, &process);
    
    if (NT_SUCCESS(status)) {
        ObDereferenceObject(process);
        return TRUE;
    }
    
    return FALSE;
}

VOID ProcessManager::ProcessExitNotify(PEPROCESS Process, 
                                        HANDLE ProcessId, 
                                        PEPROCESS ParentProcess) {
    UNREFERENCED_PARAMETER(ParentProcess);
    
    if (ProcessId == g_TrackedProcess.ProcessId && 
        g_TrackedProcess.State == TRACKING_ACTIVE) {
        DbgPrint("[ProcessManager] Process exit detected, signaling cleanup\n");
        InterlockedExchange(&g_TrackedProcess.State, TRACKING_CLEANUP_PENDING);
        KeSetEvent(&g_WorkerWakeupEvent, IO_NO_INCREMENT, FALSE);
    }
}