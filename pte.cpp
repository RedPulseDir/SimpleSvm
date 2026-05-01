#include "pte.h"

// Helper для работы с физической памятью
static PVOID MapPhysicalMemory(UINT64 physicalAddress, SIZE_T size) {
    PHYSICAL_ADDRESS pa;
    pa.QuadPart = physicalAddress;
    
    // Выровнять по странице
    UINT64 alignedPa = physicalAddress & ~(PAGE_SIZE - 1);
    SIZE_T alignedSize = size + (physicalAddress - alignedPa);
    alignedSize = (alignedSize + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1);
    
    PMDL mdl = IoAllocateMdl(NULL, (ULONG)alignedSize, FALSE, FALSE, NULL);
    if (!mdl) return nullptr;
    
    MmBuildMdlForNonPagedPool(mdl);
    mdl->MappedSystemVa = MmMapLockedPagesSpecifyCache(mdl, KernelMode, MmCached, NULL, FALSE, NormalPagePriority);
    if (!mdl->MappedSystemVa) {
        IoFreeMdl(mdl);
        return nullptr;
    }
    
    return (PVOID)((UINT64)mdl->MappedSystemVa + (physicalAddress - alignedPa));
}

static VOID UnmapPhysicalMemory(PVOID mappedAddress) {
    if (!mappedAddress) return;
    
    PMDL mdl = MmGetMdlForAddress(mappedAddress);
    if (mdl) {
        MmUnmapLockedPages(mappedAddress, mdl);
        IoFreeMdl(mdl);
    }
}

pte::pte() {
    m_Cr3.value = 0;
    m_Process = nullptr;
    m_CacheCounter = 0;
    KeInitializeSpinLock(&m_CacheLock);
    KeInitializeSpinLock(&m_ProcessLock);
    RtlZeroMemory(m_Cache, sizeof(m_Cache));
}

pte::~pte() {
    // Nothing to clean up
}

UINT64 pte::GetCr3ForProcess(PEPROCESS process) {
    if (!process) return __readcr3();
    
    // Безопасное чтение DirectoryTableBase
    __try {
        return *(UINT64*)((PUCHAR)process + 0x28); // Windows 10/11 offset
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        return 0;
    }
}

PT_ENTRY_64* pte::GetFromCache(UINT64 virtualAddress, UINT64 cr3) {
    KeAcquireSpinLockAtDpcLevel(&m_CacheLock);
    
    for (int i = 0; i < PTE_CACHE_SIZE; i++) {
        if (m_Cache[i].IsValid && 
            m_Cache[i].VirtualAddress == virtualAddress && 
            m_Cache[i].Cr3 == cr3) {
            m_Cache[i].LastAccess = ++m_CacheCounter;
            KeReleaseSpinLockFromDpcLevel(&m_CacheLock);
            return &m_Cache[i].Pte;
        }
    }
    
    KeReleaseSpinLockFromDpcLevel(&m_CacheLock);
    return nullptr;
}

void pte::AddToCache(UINT64 virtualAddress, UINT64 cr3, PT_ENTRY_64* pte) {
    if (!pte) return;
    
    KeAcquireSpinLockAtDpcLevel(&m_CacheLock);
    
    // Найти старый или самый старый entry
    int oldestIndex = 0;
    UINT64 oldestAccess = m_Cache[0].LastAccess;
    
    for (int i = 0; i < PTE_CACHE_SIZE; i++) {
        if (!m_Cache[i].IsValid) {
            oldestIndex = i;
            break;
        }
        if (m_Cache[i].LastAccess < oldestAccess) {
            oldestAccess = m_Cache[i].LastAccess;
            oldestIndex = i;
        }
    }
    
    m_Cache[oldestIndex].VirtualAddress = virtualAddress;
    m_Cache[oldestIndex].Cr3 = cr3;
    m_Cache[oldestIndex].Pte = *pte;
    m_Cache[oldestIndex].LastAccess = ++m_CacheCounter;
    m_Cache[oldestIndex].IsValid = TRUE;
    
    KeReleaseSpinLockFromDpcLevel(&m_CacheLock);
}

void pte::InvalidateCacheForProcess(UINT64 cr3) {
    KeAcquireSpinLockAtDpcLevel(&m_CacheLock);
    
    for (int i = 0; i < PTE_CACHE_SIZE; i++) {
        if (m_Cache[i].IsValid && m_Cache[i].Cr3 == cr3) {
            m_Cache[i].IsValid = FALSE;
        }
    }
    
    KeReleaseSpinLockFromDpcLevel(&m_CacheLock);
}

PT_ENTRY_64* pte::WalkPageTables(UINT64 virtualAddress, UINT64 cr3, PEPROCESS process) {
    AddressTranslationHelper helper;
    helper.as_int64 = virtualAddress;
    
    // Проверка кэша
    PT_ENTRY_64* cached = GetFromCache(virtualAddress, cr3);
    if (cached) return cached;
    
    KAPC_STATE apcState;
    BOOLEAN attached = FALSE;
    
    if (process && process != PsGetCurrentProcess()) {
        KeStackAttachProcess(process, &apcState);
        attached = TRUE;
        cr3 = __readcr3(); // Обновить CR3 после аттача
    }
    
    // Маппим PML4
    PML4E_64* pml4 = (PML4E_64*)MapPhysicalMemory(cr3 & ~0xFFF, PAGE_SIZE);
    if (!pml4) {
        if (attached) KeUnstackDetachProcess(&apcState);
        return nullptr;
    }
    
    PML4E_64* pml4e = &pml4[helper.AsIndex.pml4];
    if (!pml4e->Present) {
        UnmapPhysicalMemory(pml4);
        if (attached) KeUnstackDetachProcess(&apcState);
        return nullptr;
    }
    
    // PDPT
    PDPTE_64* pdpt = (PDPTE_64*)MapPhysicalMemory(pml4e->PageFrameNumber << PAGE_SHIFT, PAGE_SIZE);
    if (!pdpt) {
        UnmapPhysicalMemory(pml4);
        if (attached) KeUnstackDetachProcess(&apcState);
        return nullptr;
    }
    
    PDPTE_64* pdpte = &pdpt[helper.AsIndex.pdpt];
    if (!pdpte->Present) {
        UnmapPhysicalMemory(pdpt);
        UnmapPhysicalMemory(pml4);
        if (attached) KeUnstackDetachProcess(&apcState);
        return nullptr;
    }
    
    // Check for 1GB page
    if (pdpte->LargePage) {
        UnmapPhysicalMemory(pdpt);
        UnmapPhysicalMemory(pml4);
        if (attached) KeUnstackDetachProcess(&apcState);
        
        AddToCache(virtualAddress, cr3, (PT_ENTRY_64*)pdpte);
        return (PT_ENTRY_64*)pdpte;
    }
    
    // PD
    PDE_64* pd = (PDE_64*)MapPhysicalMemory(pdpte->PageFrameNumber << PAGE_SHIFT, PAGE_SIZE);
    if (!pd) {
        UnmapPhysicalMemory(pdpt);
        UnmapPhysicalMemory(pml4);
        if (attached) KeUnstackDetachProcess(&apcState);
        return nullptr;
    }
    
    PDE_64* pde = &pd[helper.AsIndex.pd];
    if (!pde->Present) {
        UnmapPhysicalMemory(pd);
        UnmapPhysicalMemory(pdpt);
        UnmapPhysicalMemory(pml4);
        if (attached) KeUnstackDetachProcess(&apcState);
        return nullptr;
    }
    
    // Check for 2MB page
    if (pde->LargePage) {
        UnmapPhysicalMemory(pd);
        UnmapPhysicalMemory(pdpt);
        UnmapPhysicalMemory(pml4);
        if (attached) KeUnstackDetachProcess(&apcState);
        
        AddToCache(virtualAddress, cr3, (PT_ENTRY_64*)pde);
        return (PT_ENTRY_64*)pde;
    }
    
    // PT
    PTE_64* pt = (PTE_64*)MapPhysicalMemory(pde->PageFrameNumber << PAGE_SHIFT, PAGE_SIZE);
    if (!pt) {
        UnmapPhysicalMemory(pd);
        UnmapPhysicalMemory(pdpt);
        UnmapPhysicalMemory(pml4);
        if (attached) KeUnstackDetachProcess(&apcState);
        return nullptr;
    }
    
    PTE_64* pte = &pt[helper.AsIndex.pt];
    
    // Сохраняем результат
    static PT_ENTRY_64 result;
    result.Flags = pte->Flags;
    
    UnmapPhysicalMemory(pt);
    UnmapPhysicalMemory(pd);
    UnmapPhysicalMemory(pdpt);
    UnmapPhysicalMemory(pml4);
    
    if (attached) KeUnstackDetachProcess(&apcState);
    
    if (pte->Present) {
        AddToCache(virtualAddress, cr3, &result);
        return &result;
    }
    
    return nullptr;
}

PT_ENTRY_64* pte::GetPte(UINT64 virtualAddress) {
    KeAcquireSpinLockAtDpcLevel(&m_ProcessLock);
    UINT64 cr3 = m_Cr3.value;
    PEPROCESS process = m_Process;
    KeReleaseSpinLockFromDpcLevel(&m_ProcessLock);
    
    if (!cr3) return nullptr;
    
    return WalkPageTables(virtualAddress, cr3, process);
}

BOOLEAN pte::ReadPhysical(UINT64 physicalAddress, PVOID buffer, SIZE_T size) {
    if (!buffer || size == 0) return FALSE;
    
    PVOID mapped = MapPhysicalMemory(physicalAddress, size);
    if (!mapped) return FALSE;
    
    __try {
        RtlCopyMemory(buffer, mapped, size);
        UnmapPhysicalMemory(mapped);
        return TRUE;
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        UnmapPhysicalMemory(mapped);
        return FALSE;
    }
}

BOOLEAN pte::WritePhysical(UINT64 physicalAddress, PVOID buffer, SIZE_T size) {
    if (!buffer || size == 0) return FALSE;
    
    PVOID mapped = MapPhysicalMemory(physicalAddress, size);
    if (!mapped) return FALSE;
    
    __try {
        RtlCopyMemory(mapped, buffer, size);
        UnmapPhysicalMemory(mapped);
        return TRUE;
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        UnmapPhysicalMemory(mapped);
        return FALSE;
    }
}

BOOLEAN pte::ReadVirtual(UINT64 virtualAddress, PVOID buffer, SIZE_T size) {
    PT_ENTRY_64* pte = GetPte(virtualAddress);
    if (!pte || !pte->Present) return FALSE;
    
    UINT64 physicalBase = (pte->PageFrameNumber << PAGE_SHIFT);
    UINT64 offset = virtualAddress & (PAGE_SIZE - 1);
    
    if (offset + size > PAGE_SIZE) {
        // Split across page boundary
        SIZE_T firstPart = PAGE_SIZE - offset;
        if (!ReadPhysical(physicalBase + offset, buffer, firstPart)) return FALSE;
        return ReadVirtual(virtualAddress + firstPart, (PUCHAR)buffer + firstPart, size - firstPart);
    }
    
    return ReadPhysical(physicalBase + offset, buffer, size);
}

BOOLEAN pte::WriteVirtual(UINT64 virtualAddress, PVOID buffer, SIZE_T size) {
    PT_ENTRY_64* pte = GetPte(virtualAddress);
    if (!pte || !pte->Present) return FALSE;
    
    // Check write permission
    if (!pte->Write && (KeGetCurrentIrql() < DISPATCH_LEVEL)) {
        // Try to temporarily enable write
        PT_ENTRY_64 oldPte = *pte;
        pte->Write = 1;
        
        BOOLEAN result = WriteVirtual(virtualAddress, buffer, size);
        
        // Restore
        WritePhysical((pte->PageFrameNumber << PAGE_SHIFT) + (virtualAddress & ~(PAGE_SIZE - 1)), 
                      &oldPte, sizeof(PT_ENTRY_64));
        
        return result;
    }
    
    UINT64 physicalBase = (pte->PageFrameNumber << PAGE_SHIFT);
    UINT64 offset = virtualAddress & (PAGE_SIZE - 1);
    
    if (offset + size > PAGE_SIZE) {
        SIZE_T firstPart = PAGE_SIZE - offset;
        if (!WritePhysical(physicalBase + offset, buffer, firstPart)) return FALSE;
        return WriteVirtual(virtualAddress + firstPart, (PUCHAR)buffer + firstPart, size - firstPart);
    }
    
    return WritePhysical(physicalBase + offset, buffer, size);
}

BOOLEAN pte::MapPage(UINT64 virtualAddress, UINT64 physicalAddress, UINT64 flags) {
    PT_ENTRY_64* pte = GetPte(virtualAddress);
    if (!pte) return FALSE;
    
    PT_ENTRY_64 newPte;
    newPte.Flags = flags;
    newPte.Present = 1;
    newPte.PageFrameNumber = physicalAddress >> PAGE_SHIFT;
    
    UINT64 ptePhysical = (pte->PageFrameNumber << PAGE_SHIFT) + 
                         (virtualAddress & (PAGE_SIZE - 1));
    
    if (!WritePhysical(ptePhysical, &newPte, sizeof(PT_ENTRY_64))) return FALSE;
    
    // Flush TLB
    __invlpg((PVOID)virtualAddress);
    
    // Invalidate cache for this address
    KeAcquireSpinLockAtDpcLevel(&m_CacheLock);
    for (int i = 0; i < PTE_CACHE_SIZE; i++) {
        if (m_Cache[i].IsValid && m_Cache[i].VirtualAddress == virtualAddress) {
            m_Cache[i].IsValid = FALSE;
            break;
        }
    }
    KeReleaseSpinLockFromDpcLevel(&m_CacheLock);
    
    return TRUE;
}

BOOLEAN pte::UnmapPage(UINT64 virtualAddress) {
    return MapPage(virtualAddress, 0, 0);
}

BOOLEAN pte::ProtectPage(UINT64 virtualAddress, UINT64 newFlags) {
    PT_ENTRY_64* pte = GetPte(virtualAddress);
    if (!pte || !pte->Present) return FALSE;
    
    UINT64 ptePhysical = (pte->PageFrameNumber << PAGE_SHIFT) + 
                         (virtualAddress & (PAGE_SIZE - 1));
    
    PT_ENTRY_64 newPte = *pte;
    newPte.Flags = (newPte.Flags & ~0xFFF) | (newFlags & 0xFFF);
    
    if (!WritePhysical(ptePhysical, &newPte, sizeof(PT_ENTRY_64))) return FALSE;
    
    __invlpg((PVOID)virtualAddress);
    InvalidateCacheForProcess(m_Cr3.value);
    
    return TRUE;
}

BOOLEAN pte::SpoofRange(UINT64 startVa, SIZE_T sizeVa) {
    if (sizeVa == 0) return TRUE;
    
    UINT64 currentVa = startVa;
    while (currentVa < startVa + sizeVa) {
        PT_ENTRY_64* pte = GetPte(currentVa);
        if (pte && pte->Present) {
            // Mark as copy-on-write by setting ignored bits
            PT_ENTRY_64 newPte = *pte;
            newPte.Ignored1 = 0b001; // Mark as special
            
            UINT64 ptePhysical = (pte->PageFrameNumber << PAGE_SHIFT) + 
                                 (currentVa & (PAGE_SIZE - 1));
            WritePhysical(ptePhysical, &newPte, sizeof(PT_ENTRY_64));
        }
        currentVa += PAGE_SIZE;
    }
    
    // Flush TLB for the entire range
    __invlpg((PVOID)startVa);
    InvalidateCacheForProcess(m_Cr3.value);
    
    return TRUE;
}

BOOLEAN pte::ClonePageTable(UINT64 sourceCr3, UINT64 targetCr3, UINT64 startVa, SIZE_T size) {
    // Map source and target PML4
    PML4E_64* srcPml4 = (PML4E_64*)MapPhysicalMemory(sourceCr3 & ~0xFFF, PAGE_SIZE);
    PML4E_64* dstPml4 = (PML4E_64*)MapPhysicalMemory(targetCr3 & ~0xFFF, PAGE_SIZE);
    
    if (!srcPml4 || !dstPml4) {
        if (srcPml4) UnmapPhysicalMemory(srcPml4);
        if (dstPml4) UnmapPhysicalMemory(dstPml4);
        return FALSE;
    }
    
    AddressTranslationHelper helper;
    helper.as_int64 = startVa;
    
    // Clone PML4E
    for (int i = helper.AsIndex.pml4; i < 512; i++) {
        if (srcPml4[i].Present) {
            dstPml4[i] = srcPml4[i];
        }
    }
    
    UnmapPhysicalMemory(srcPml4);
    UnmapPhysicalMemory(dstPml4);
    
    InvalidateCacheForProcess(targetCr3);
    
    return TRUE;
}

BOOLEAN pte::InstallHook(UINT64 targetVa, PVOID hookFunction, PUINT64 originalBytes, SIZE_T hookSize) {
    if (!hookFunction || hookSize > PAGE_SIZE || hookSize < 12) return FALSE;
    
    // Read original bytes
    if (originalBytes && !ReadVirtual(targetVa, originalBytes, hookSize)) return FALSE;
    
    // Calculate relative jump (jmp qword ptr [rip+offset])
    // mov rax, hookFunction
    // jmp rax
    UINT8 shellCode[] = {
        0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov rax, addr
        0xFF, 0xE0                                                  // jmp rax
    };
    
    *(UINT64*)&shellCode[2] = (UINT64)hookFunction;
    
    // Write hook
    if (!WriteVirtual(targetVa, shellCode, hookSize)) return FALSE;
    
    // Flush cache
    __invlpg((PVOID)targetVa);
    InvalidateCacheForProcess(m_Cr3.value);
    
    return TRUE;
}