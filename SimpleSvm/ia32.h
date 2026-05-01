#ifndef _IA32_H
#define _IA32_H

#pragma once

// ============================================================================
//                             CR4 REGISTER
// ============================================================================

typedef union _CR4_REGISTER {
    struct {
        UINT64 VirtualModeExtensions : 1;                    // bit 0
        UINT64 ProtectedModeVirtualInterrupts : 1;           // bit 1
        UINT64 TimestampDisable : 1;                         // bit 2
        UINT64 DebuggingExtensions : 1;                      // bit 3
        UINT64 PageSizeExtensions : 1;                       // bit 4
        UINT64 PhysicalAddressExtension : 1;                 // bit 5
        UINT64 MachineCheckEnable : 1;                       // bit 6
        UINT64 PageGlobalEnable : 1;                         // bit 7
        UINT64 PerformanceMonitoringCounterEnable : 1;       // bit 8
        UINT64 OsFxsaveFxrstorSupport : 1;                   // bit 9
        UINT64 OsXmmExceptionSupport : 1;                    // bit 10
        UINT64 UsermodeInstructionPrevention : 1;            // bit 11
        UINT64 LinearAddresses57Bit : 1;                     // bit 12
        UINT64 VmxEnable : 1;                                // bit 13
        UINT64 SmxEnable : 1;                                // bit 14
        UINT64 Reserved1 : 1;                                // bit 15
        UINT64 FsgsbaseEnable : 1;                           // bit 16
        UINT64 PcidEnable : 1;                               // bit 17
        UINT64 OsXsave : 1;                                  // bit 18
        UINT64 KeyLockerEnable : 1;                          // bit 19
        UINT64 SmepEnable : 1;                               // bit 20
        UINT64 SmapEnable : 1;                               // bit 21
        UINT64 ProtectionKeyEnable : 1;                      // bit 22
        UINT64 ControlFlowEnforcementEnable : 1;             // bit 23
        UINT64 ProtectionKeyForSupervisorModeEnable : 1;     // bit 24
        UINT64 Reserved2 : 39;                               // bits 25-63
    } Bits;
    UINT64 Value;
} CR4_REGISTER, *PCR4_REGISTER;

// CR4 bit definitions
#define CR4_VME_BIT         0
#define CR4_VME_FLAG        (1ULL << CR4_VME_BIT)
#define CR4_PVI_BIT         1
#define CR4_PVI_FLAG        (1ULL << CR4_PVI_BIT)
#define CR4_TSD_BIT         2
#define CR4_TSD_FLAG        (1ULL << CR4_TSD_BIT)
#define CR4_DE_BIT          3
#define CR4_DE_FLAG         (1ULL << CR4_DE_BIT)
#define CR4_PSE_BIT         4
#define CR4_PSE_FLAG        (1ULL << CR4_PSE_BIT)
#define CR4_PAE_BIT         5
#define CR4_PAE_FLAG        (1ULL << CR4_PAE_BIT)
#define CR4_MCE_BIT         6
#define CR4_MCE_FLAG        (1ULL << CR4_MCE_BIT)
#define CR4_PGE_BIT         7
#define CR4_PGE_FLAG        (1ULL << CR4_PGE_BIT)
#define CR4_PCE_BIT         8
#define CR4_PCE_FLAG        (1ULL << CR4_PCE_BIT)
#define CR4_OSFXSR_BIT      9
#define CR4_OSFXSR_FLAG     (1ULL << CR4_OSFXSR_BIT)
#define CR4_OSXMMEXCPT_BIT  10
#define CR4_OSXMMEXCPT_FLAG (1ULL << CR4_OSXMMEXCPT_BIT)
#define CR4_UMIP_BIT        11
#define CR4_UMIP_FLAG       (1ULL << CR4_UMIP_BIT)
#define CR4_LA57_BIT        12
#define CR4_LA57_FLAG       (1ULL << CR4_LA57_BIT)
#define CR4_VMXE_BIT        13
#define CR4_VMXE_FLAG       (1ULL << CR4_VMXE_BIT)
#define CR4_SMXE_BIT        14
#define CR4_SMXE_FLAG       (1ULL << CR4_SMXE_BIT)
#define CR4_FSGSBASE_BIT    16
#define CR4_FSGSBASE_FLAG   (1ULL << CR4_FSGSBASE_BIT)
#define CR4_PCIDE_BIT       17
#define CR4_PCIDE_FLAG      (1ULL << CR4_PCIDE_BIT)
#define CR4_OSXSAVE_BIT     18
#define CR4_OSXSAVE_FLAG    (1ULL << CR4_OSXSAVE_BIT)
#define CR4_KEYLOCKER_BIT   19
#define CR4_KEYLOCKER_FLAG  (1ULL << CR4_KEYLOCKER_BIT)
#define CR4_SMEP_BIT        20
#define CR4_SMEP_FLAG       (1ULL << CR4_SMEP_BIT)
#define CR4_SMAP_BIT        21
#define CR4_SMAP_FLAG       (1ULL << CR4_SMAP_BIT)
#define CR4_PKE_BIT         22
#define CR4_PKE_FLAG        (1ULL << CR4_PKE_BIT)
#define CR4_CET_BIT         23
#define CR4_CET_FLAG        (1ULL << CR4_CET_BIT)
#define CR4_PKS_BIT         24
#define CR4_PKS_FLAG        (1ULL << CR4_PKS_BIT)

// ============================================================================
//                             CR3 REGISTER
// ============================================================================

typedef union _CR3_REGISTER {
    struct {
        UINT64 Reserved1 : 3;                              // bits 0-2
        UINT64 PageLevelWriteThrough : 1;                  // bit 3
        UINT64 PageLevelCacheDisable : 1;                  // bit 4
        UINT64 Reserved2 : 7;                              // bits 5-11
        UINT64 AddressOfPageDirectory : 36;                // bits 12-47
        UINT64 Reserved3 : 16;                             // bits 48-63
    } Bits;
    UINT64 Value;
} CR3_REGISTER, *PCR3_REGISTER;

#define CR3_PWT_BIT         3
#define CR3_PWT_FLAG        (1ULL << CR3_PWT_BIT)
#define CR3_PCD_BIT         4
#define CR3_PCD_FLAG        (1ULL << CR3_PCD_BIT)
#define CR3_ADDR_MASK       0xFFFFFFFFF000ULL
#define CR3_ADDR_SHIFT      12

// ============================================================================
//                             PML4 ENTRY
// ============================================================================

typedef union _PML4_ENTRY_64 {
    struct {
        UINT64 Present : 1;                                // bit 0
        UINT64 Write : 1;                                  // bit 1
        UINT64 Supervisor : 1;                             // bit 2
        UINT64 PageLevelWriteThrough : 1;                  // bit 3
        UINT64 PageLevelCacheDisable : 1;                  // bit 4
        UINT64 Accessed : 1;                               // bit 5
        UINT64 Reserved1 : 1;                              // bit 6
        UINT64 MustBeZero : 1;                             // bit 7
        UINT64 Ignored1 : 4;                               // bits 8-11
        UINT64 PageFrameNumber : 36;                       // bits 12-47
        UINT64 Reserved2 : 4;                              // bits 48-51
        UINT64 Ignored2 : 11;                              // bits 52-62
        UINT64 ExecuteDisable : 1;                         // bit 63
    } Bits;
    UINT64 Value;
} PML4_ENTRY_64, *PPML4_ENTRY_64;

#define PML4E_PRESENT_BIT       0
#define PML4E_PRESENT_FLAG      (1ULL << PML4E_PRESENT_BIT)
#define PML4E_WRITE_BIT         1
#define PML4E_WRITE_FLAG        (1ULL << PML4E_WRITE_BIT)
#define PML4E_USER_BIT          2
#define PML4E_USER_FLAG         (1ULL << PML4E_USER_BIT)
#define PML4E_PWT_BIT           3
#define PML4E_PWT_FLAG          (1ULL << PML4E_PWT_BIT)
#define PML4E_PCD_BIT           4
#define PML4E_PCD_FLAG          (1ULL << PML4E_PCD_BIT)
#define PML4E_ACCESSED_BIT      5
#define PML4E_ACCESSED_FLAG     (1ULL << PML4E_ACCESSED_BIT)
#define PML4E_MUST_BE_ZERO_BIT  7
#define PML4E_MUST_BE_ZERO_FLAG (1ULL << PML4E_MUST_BE_ZERO_BIT)
#define PML4E_PFN_MASK          0xFFFFFFFFF000ULL
#define PML4E_PFN_SHIFT         12
#define PML4E_XD_BIT            63
#define PML4E_XD_FLAG           (1ULL << PML4E_XD_BIT)

// ============================================================================
//                             PDPT ENTRY
// ============================================================================

typedef union _PDPT_ENTRY_64 {
    struct {
        UINT64 Present : 1;                                // bit 0
        UINT64 Write : 1;                                  // bit 1
        UINT64 Supervisor : 1;                             // bit 2
        UINT64 PageLevelWriteThrough : 1;                  // bit 3
        UINT64 PageLevelCacheDisable : 1;                  // bit 4
        UINT64 Accessed : 1;                               // bit 5
        UINT64 Reserved1 : 1;                              // bit 6
        UINT64 LargePage : 1;                              // bit 7
        UINT64 Ignored1 : 4;                               // bits 8-11
        UINT64 PageFrameNumber : 36;                       // bits 12-47
        UINT64 Reserved2 : 4;                              // bits 48-51
        UINT64 Ignored2 : 11;                              // bits 52-62
        UINT64 ExecuteDisable : 1;                         // bit 63
    } Bits;
    UINT64 Value;
} PDPT_ENTRY_64, *PPDPT_ENTRY_64;

#define PDPTE_PRESENT_BIT       0
#define PDPTE_PRESENT_FLAG      (1ULL << PDPTE_PRESENT_BIT)
#define PDPTE_WRITE_BIT         1
#define PDPTE_WRITE_FLAG        (1ULL << PDPTE_WRITE_BIT)
#define PDPTE_USER_BIT          2
#define PDPTE_USER_FLAG         (1ULL << PDPTE_USER_BIT)
#define PDPTE_PWT_BIT           3
#define PDPTE_PWT_FLAG          (1ULL << PDPTE_PWT_BIT)
#define PDPTE_PCD_BIT           4
#define PDPTE_PCD_FLAG          (1ULL << PDPTE_PCD_BIT)
#define PDPTE_ACCESSED_BIT      5
#define PDPTE_ACCESSED_FLAG     (1ULL << PDPTE_ACCESSED_BIT)
#define PDPTE_LARGE_PAGE_BIT    7
#define PDPTE_LARGE_PAGE_FLAG   (1ULL << PDPTE_LARGE_PAGE_BIT)
#define PDPTE_PFN_MASK          0xFFFFFFFFF000ULL
#define PDPTE_PFN_SHIFT         12
#define PDPTE_XD_BIT            63
#define PDPTE_XD_FLAG           (1ULL << PDPTE_XD_BIT)

// 1GB Page specific (when LargePage = 1)
#define PDPTE_PFN_1GB_MASK      0xFFFFFFFFFF000000ULL
#define PDPTE_PFN_1GB_SHIFT     30

// ============================================================================
//                             PDE ENTRY
// ============================================================================

typedef union _PDE_ENTRY_64 {
    struct {
        UINT64 Present : 1;                                // bit 0
        UINT64 Write : 1;                                  // bit 1
        UINT64 Supervisor : 1;                             // bit 2
        UINT64 PageLevelWriteThrough : 1;                  // bit 3
        UINT64 PageLevelCacheDisable : 1;                  // bit 4
        UINT64 Accessed : 1;                               // bit 5
        UINT64 Reserved1 : 1;                              // bit 6
        UINT64 LargePage : 1;                              // bit 7
        UINT64 Global : 1;                                 // bit 8
        UINT64 Ignored1 : 3;                               // bits 9-11
        UINT64 Pat : 1;                                    // bit 12
        UINT64 Reserved2 : 8;                              // bits 13-20
        UINT64 PageFrameNumber : 40;                       // bits 21-60
        UINT64 Reserved3 : 2;                              // bits 61-62
        UINT64 ExecuteDisable : 1;                         // bit 63
    } Bits;
    UINT64 Value;
} PDE_ENTRY_64, *PPDE_ENTRY_64;

#define PDE_PRESENT_BIT         0
#define PDE_PRESENT_FLAG        (1ULL << PDE_PRESENT_BIT)
#define PDE_WRITE_BIT           1
#define PDE_WRITE_FLAG          (1ULL << PDE_WRITE_BIT)
#define PDE_USER_BIT            2
#define PDE_USER_FLAG           (1ULL << PDE_USER_BIT)
#define PDE_PWT_BIT             3
#define PDE_PWT_FLAG            (1ULL << PDE_PWT_BIT)
#define PDE_PCD_BIT             4
#define PDE_PCD_FLAG            (1ULL << PDE_PCD_BIT)
#define PDE_ACCESSED_BIT        5
#define PDE_ACCESSED_FLAG       (1ULL << PDE_ACCESSED_BIT)
#define PDE_LARGE_PAGE_BIT      7
#define PDE_LARGE_PAGE_FLAG     (1ULL << PDE_LARGE_PAGE_BIT)
#define PDE_GLOBAL_BIT          8
#define PDE_GLOBAL_FLAG         (1ULL << PDE_GLOBAL_BIT)
#define PDE_PAT_BIT             12
#define PDE_PAT_FLAG            (1ULL << PDE_PAT_BIT)
#define PDE_PFN_MASK            0xFFFFFFFFFFF00000ULL
#define PDE_PFN_SHIFT           21
#define PDE_XD_BIT              63
#define PDE_XD_FLAG             (1ULL << PDE_XD_BIT)

// ============================================================================
//                             PTE ENTRY
// ============================================================================

typedef union _PTE_ENTRY_64 {
    struct {
        UINT64 Present : 1;                                // bit 0
        UINT64 Write : 1;                                  // bit 1
        UINT64 Supervisor : 1;                             // bit 2
        UINT64 PageLevelWriteThrough : 1;                  // bit 3
        UINT64 PageLevelCacheDisable : 1;                  // bit 4
        UINT64 Accessed : 1;                               // bit 5
        UINT64 Dirty : 1;                                  // bit 6
        UINT64 Pat : 1;                                    // bit 7
        UINT64 Global : 1;                                 // bit 8
        UINT64 CopyOnWrite : 1;                            // bit 9
        UINT64 Unused : 1;                                 // bit 10
        UINT64 Write1 : 1;                                 // bit 11
        UINT64 PageFrameNumber : 36;                       // bits 12-47
        UINT64 Reserved1 : 4;                              // bits 48-51
        UINT64 Ignored2 : 7;                               // bits 52-58
        UINT64 ProtectionKey : 4;                          // bits 59-62
        UINT64 ExecuteDisable : 1;                         // bit 63
    } Bits;
    UINT64 Value;
} PTE_ENTRY_64, *PPTE_ENTRY_64;

#define PTE_PRESENT_BIT         0
#define PTE_PRESENT_FLAG        (1ULL << PTE_PRESENT_BIT)
#define PTE_WRITE_BIT           1
#define PTE_WRITE_FLAG          (1ULL << PTE_WRITE_BIT)
#define PTE_USER_BIT            2
#define PTE_USER_FLAG           (1ULL << PTE_USER_BIT)
#define PTE_PWT_BIT             3
#define PTE_PWT_FLAG            (1ULL << PTE_PWT_BIT)
#define PTE_PCD_BIT             4
#define PTE_PCD_FLAG            (1ULL << PTE_PCD_BIT)
#define PTE_ACCESSED_BIT        5
#define PTE_ACCESSED_FLAG       (1ULL << PTE_ACCESSED_BIT)
#define PTE_DIRTY_BIT           6
#define PTE_DIRTY_FLAG          (1ULL << PTE_DIRTY_BIT)
#define PTE_PAT_BIT             7
#define PTE_PAT_FLAG            (1ULL << PTE_PAT_BIT)
#define PTE_GLOBAL_BIT          8
#define PTE_GLOBAL_FLAG         (1ULL << PTE_GLOBAL_BIT)
#define PTE_COPY_ON_WRITE_BIT   9
#define PTE_COPY_ON_WRITE_FLAG  (1ULL << PTE_COPY_ON_WRITE_BIT)
#define PTE_PFN_MASK            0xFFFFFFFFF000ULL
#define PTE_PFN_SHIFT           12
#define PTE_XD_BIT              63
#define PTE_XD_FLAG             (1ULL << PTE_XD_BIT)

// ============================================================================
//                             PT ENTRY (generic)
// ============================================================================

typedef union _PT_ENTRY {
    struct {
        UINT64 Present : 1;                                // bit 0
        UINT64 Write : 1;                                  // bit 1
        UINT64 Supervisor : 1;                             // bit 2
        UINT64 PageLevelWriteThrough : 1;                  // bit 3
        UINT64 PageLevelCacheDisable : 1;                  // bit 4
        UINT64 Accessed : 1;                               // bit 5
        UINT64 Dirty : 1;                                  // bit 6
        UINT64 LargePage : 1;                              // bit 7
        UINT64 Global : 1;                                 // bit 8
        UINT64 Ignored1 : 3;                               // bits 9-11
        UINT64 PageFrameNumber : 36;                       // bits 12-47
        UINT64 Reserved1 : 4;                              // bits 48-51
        UINT64 Ignored2 : 7;                               // bits 52-58
        UINT64 ProtectionKey : 4;                          // bits 59-62
        UINT64 ExecuteDisable : 1;                         // bit 63
    } Bits;
    UINT64 Value;
} PT_ENTRY, *PPT_ENTRY;

// ============================================================================
//                             ADDRESS TRANSLATION
// ============================================================================

typedef union _ADDRESS_TRANSLATION_HELPER {
    struct {
        UINT64 PageOffset : 12;                            // bits 0-11
        UINT64 PtIndex : 9;                                // bits 12-20
        UINT64 PdIndex : 9;                                // bits 21-29
        UINT64 PdptIndex : 9;                              // bits 30-38
        UINT64 Pml4Index : 9;                              // bits 39-47
        UINT64 Reserved : 16;                              // bits 48-63
    } AsIndex;
    struct {
        UINT64 Offset4Kb : 12;                             // bits 0-11
        UINT64 Offset2Mb : 21;                             // bits 0-20
        UINT64 Offset1Gb : 30;                             // bits 0-29
    } AsPageOffset;
    UINT64 Value;
} ADDRESS_TRANSLATION_HELPER, *PADDRESS_TRANSLATION_HELPER;

// Page size constants
#define PAGE_SHIFT          12
#define PAGE_SIZE           (1ULL << PAGE_SHIFT)
#define PAGE_MASK           (PAGE_SIZE - 1)

#define PAGE_2MB_SHIFT      21
#define PAGE_2MB_SIZE       (1ULL << PAGE_2MB_SHIFT)
#define PAGE_2MB_MASK       (PAGE_2MB_SIZE - 1)

#define PAGE_1GB_SHIFT      30
#define PAGE_1GB_SIZE       (1ULL << PAGE_1GB_SHIFT)
#define PAGE_1GB_MASK       (PAGE_1GB_SIZE - 1)

// ============================================================================
//                             DESCRIPTOR TABLES
// ============================================================================

#include <pshpack1.h>

typedef struct _DESCRIPTOR_TABLE_REGISTER {
    UINT16 Limit;
    UINT64 Base;
} DESCRIPTOR_TABLE_REGISTER, *PDESCRIPTOR_TABLE_REGISTER;

static_assert(sizeof(DESCRIPTOR_TABLE_REGISTER) == 10, "DESCRIPTOR_TABLE_REGISTER size mismatch");

typedef struct _SEGMENT_DESCRIPTOR {
    union {
        UINT64 Value;
        struct {
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
        } Bits;
    };
} SEGMENT_DESCRIPTOR, *PSEGMENT_DESCRIPTOR;

static_assert(sizeof(SEGMENT_DESCRIPTOR) == 8, "SEGMENT_DESCRIPTOR size mismatch");

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
} SEGMENT_ATTRIBUTE, *PSEGMENT_ATTRIBUTE;

static_assert(sizeof(SEGMENT_ATTRIBUTE) == 2, "SEGMENT_ATTRIBUTE size mismatch");

#include <poppack.h>

// ============================================================================
//                             HELPER MACROS
// ============================================================================

#define VA_2_PA(x)          ((x) & ~((1ULL << 48) - 1))
#define PA_2_VA(x)          ((x) | 0xFFFF000000000000ULL)

#define PFN_2_PA(x)         ((UINT64)(x) << PAGE_SHIFT)
#define PA_2_PFN(x)         ((x) >> PAGE_SHIFT)

#define ALIGN_UP(x, a)      (((x) + (a) - 1) & ~((a) - 1))
#define ALIGN_DOWN(x, a)    ((x) & ~((a) - 1))
#define IS_ALIGNED(x, a)    (((x) & ((a) - 1)) == 0)

#define PAGE_ALIGN_UP(x)    ALIGN_UP(x, PAGE_SIZE)
#define PAGE_ALIGN_DOWN(x)  ALIGN_DOWN(x, PAGE_SIZE)
#define IS_PAGE_ALIGNED(x)  IS_ALIGNED(x, PAGE_SIZE)

#endif // _IA32_H
