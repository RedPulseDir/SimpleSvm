#ifndef _PROCESS_MANAGER_H
#define _PROCESS_MANAGER_H

#include "global.h"

// Состояния процесса
enum PROCESS_TRACKING_STATE {
    TRACKING_IDLE = 0,
    TRACKING_REQUESTED,
    TRACKING_ACTIVE,
    TRACKING_CLEANUP_PENDING,
    TRACKING_CLEANUP_DONE
};

// Структура для безопасного трекинга
struct TRACKED_PROCESS_INFO {
    volatile LONG State;
    HANDLE ProcessId;
    PEPROCESS ProcessObject;
    UINT64 Cr3;
    UINT64 OriginalLstar;
    PVOID KuserSharedData;
    PMDL KuserMdl;
    BOOLEAN NotifyRegistered;
    KEVENT RequestEvent;
    KEVENT CleanupEvent;
    KSPIN_LOCK Lock;
};

class ProcessManager {
private:
    static TRACKED_PROCESS_INFO g_TrackedProcess;
    static PKTHREAD g_WorkerThread;
    static HANDLE g_WorkerThreadHandle;
    static volatile LONG g_StopWorker;
    static KEVENT g_WorkerWakeupEvent;
    
private:
    static NTSTATUS WorkerThread(PVOID Context);
    static VOID ProcessExitNotify(PEPROCESS Process, HANDLE ProcessId, PEPROCESS ParentProcess);
    static BOOLEAN AttachToProcess(PEPROCESS Process);
    static VOID DetachFromProcess();
    static BOOLEAN SetupKuserSpoofing();
    static VOID CleanupKuserSpoofing();
    static VOID UpdateKuserTime();
    static BOOLEAN IsProcessAlive(HANDLE ProcessId);
    
public:
    static NTSTATUS Initialize();
    static VOID Shutdown();
    static NTSTATUS RequestTracking(HANDLE ProcessId, UINT64 SyscallHandler);
    static VOID StopTracking();
    static BOOLEAN IsTrackingActive();
    static NTSTATUS UpdateSyscallHandler(UINT64 NewHandler);
};

#endif