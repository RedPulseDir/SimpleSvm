#ifndef _PTE_H
#define _PTE_H

#include "global.h"
#include "ia32.h"

// Кэш для PTE с LRU
#define PTE_CACHE_SIZE 64

struct PTE_CACHE_ENTRY {
    UINT64 VirtualAddress;
    UINT64 Cr3;
    PT_ENTRY_64 Pte;
    UINT64 LastAccess;
    BOOLEAN IsValid;
};

class pte {
private:
    CR3 m_Cr3;
    PEPROCESS m_Process;
    PTE_CACHE_ENTRY m_Cache[PTE_CACHE_SIZE];
    UINT64 m_CacheCounter;
    KSPIN_LOCK m_CacheLock;
    KSPIN_LOCK m_ProcessLock;
    
private:
    PT_ENTRY_64* WalkPageTables(UINT64 virtualAddress, UINT64 cr3, PEPROCESS process = nullptr);
    UINT64 GetCr3ForProcess(PEPROCESS process);
    PT_ENTRY_64* GetFromCache(UINT64 virtualAddress, UINT64 cr3);
    void AddToCache(UINT64 virtualAddress, UINT64 cr3, PT_ENTRY_64* pte);
    void InvalidateCacheForProcess(UINT64 cr3);
    BOOLEAN IsAddressValid(UINT64 virtualAddress, UINT64 cr3);
    
public:
    pte();
    ~pte();
    
    static pte* GetInstance() {
        static pte instance;
        return &instance;
    }
    
    void SetProcess(PEPROCESS process) {
        KeAcquireSpinLockAtDpcLevel(&m_ProcessLock);
        m_Process = process;
        if (process) {
            m_Cr3.value = GetCr3ForProcess(process);
        } else {
            m_Cr3.value = 0;
        }
        KeReleaseSpinLockFromDpcLevel(&m_ProcessLock);
    }
    
    PEPROCESS GetProcess() {
        PEPROCESS process;
        KeAcquireSpinLockAtDpcLevel(&m_ProcessLock);
        process = m_Process;
        KeReleaseSpinLockFromDpcLevel(&m_ProcessLock);
        return process;
    }
    
    // Основные операции
    BOOLEAN ReadPhysical(UINT64 physicalAddress, PVOID buffer, SIZE_T size);
    BOOLEAN WritePhysical(UINT64 physicalAddress, PVOID buffer, SIZE_T size);
    BOOLEAN ReadVirtual(UINT64 virtualAddress, PVOID buffer, SIZE_T size);
    BOOLEAN WriteVirtual(UINT64 virtualAddress, PVOID buffer, SIZE_T size);
    
    // Работа со страницами
    PT_ENTRY_64* GetPte(UINT64 virtualAddress);
    BOOLEAN MapPage(UINT64 virtualAddress, UINT64 physicalAddress, UINT64 flags);
    BOOLEAN UnmapPage(UINT64 virtualAddress);
    BOOLEAN ProtectPage(UINT64 virtualAddress, UINT64 newFlags);
    
    // Спуфинг
    BOOLEAN SpoofRange(UINT64 startVa, SIZE_T sizeVa);
    BOOLEAN ClonePageTable(UINT64 sourceCr3, UINT64 targetCr3, UINT64 startVa, SIZE_T size);
    BOOLEAN InstallHook(UINT64 targetVa, PVOID hookFunction, PUINT64 originalBytes, SIZE_T hookSize);
};

#endif