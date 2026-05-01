#pragma once
#include "includes.h"

/*  enum for cpuid codes    */
enum CPUID : UINT32
{
    vendor_and_max_standard_fn_number = 0x0,
    feature_identifier = 0x80000001,
    ext_perfmon_and_debug = 0x80000022,
    svm_features = 0x8000000A,
};

/*  enum for some model specific register numbers    */
enum MSR : UINT64
{
    pat = 0x277,
    apic_bar = 0x1b,
    vm_cr = 0xC0010114,
    efer = 0xC0000080,
    vm_hsave_pa = 0xC0010117,
    lstar = 0xC0000082,
    debugctl = 0x1D9,
    sysenter_cs = 0x174,
    sysenter_eip = 0x176,
    sysenter_esp = 0x175,
    star = 0xC0000081,
    cstar = 0xC0000083,
    sf_mask = 0xC0000084,
    fs_base = 0xC0000100,
    gs_base = 0xC0000101,
    kernel_gs_base = 0xC0000102,
    tsc = 0x10,
    aperf = 0xE8,
    mperf = 0xE9,
};

/*  enum for cpuid leaves for hypervisor interface */
enum HYPERVISOR_CPUID : UINT32
{
    hv_vendor_and_max_functions = 0x40000000,
    hv_interface = 0x40000001,
    unload_simple_svm = 0x41414141,
};

/*  struct for segment descriptor */
struct SegmentDescriptor
{
    union
    {
        UINT64 value;
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
        } fields;
    };
};
static_assert(sizeof(SegmentDescriptor) == 8, "SegmentDescriptor Size Mismatch");

/*  Core::X86::MSR::efer  */
union EFER_MSR
{
    struct 
    {
        UINT64 syscall : 1;
        UINT64 reserved1 : 7;
        UINT64 long_mode_enable : 1;
        UINT64 reserved2 : 1;
        UINT64 long_mode_active : 1;
        UINT64 nx_page : 1;
        UINT64 svme : 1;
        UINT64 lmsle : 1;
        UINT64 ffxse : 1;
        UINT64 reserved3 : 1;
        UINT64 reserved4 : 47;
    };
    UINT64 value;
};
static_assert(sizeof(EFER_MSR) == 8, "EFER MSR Size Mismatch");

/*  Core::X86::Msr::APIC_BAR  */
struct APIC_BAR_MSR
{
    union
    {
        UINT64 value;
        struct
        {
            UINT64 reserved1 : 8;
            UINT64 bootstrap_processor : 1;
            UINT64 reserved2 : 1;
            UINT64 x2apic_mode : 1;
            UINT64 xapic_global : 1;
            UINT64 apic_base : 24;
            UINT64 reserved3 : 28;
        } fields;
    };
};
static_assert(sizeof(APIC_BAR_MSR) == 8, "APIC_BAR_MSR Size Mismatch");

/*  Core::X86::MSR::vm_cr  */
union VM_CR_MSR
{
    struct 
    {
        UINT32 reserved1 : 1;
        UINT32 intercept_init : 1;
        UINT32 reserved2 : 1;
        UINT32 svm_lock : 1;
        UINT32 svme_disable : 1;
        UINT32 reserved3 : 27;
        UINT32 reserved4 : 32;
    };
    UINT64 value;
};
static_assert(sizeof(VM_CR_MSR) == 8, "VM_CR_MSR Size Mismatch");

/*  Intercept vector for misc2  */
union InterceptVector4
{
    struct 
    {
        UINT32 vmrun_intercept : 1;
        UINT32 vmmcall_intercept : 1;
        UINT32 vmload_intercept : 1;
        UINT32 vmsave_intercept : 1;
        UINT32 stgi_intercept : 1;
        UINT32 clgi_intercept : 1;
        UINT32 skinit_intercept : 1;
        UINT32 rdtscp_intercept : 1;
        UINT32 icebp_intercept : 1;
        UINT32 wbinvd_intercept : 1;
        UINT32 monitor_intercept : 1;
        UINT32 mwait_intercept_unconditional : 1;
        UINT32 mwait_intercept_armed : 1;
        UINT32 xsetbv_intercept : 1;
        UINT32 rdpru_intercept : 1;
        UINT32 efer_write_intercept : 1;
        UINT32 cr_write_intercept : 16;
    } fields;
    UINT32 value;
};
static_assert(sizeof(InterceptVector4) == 0x4, "InterceptVector4 Size Mismatch");

/*  packed structures for GDTR/IDTR  */
#include <pshpack1.h>
struct DescriptorTableRegister
{
    UINT16 limit;
    UINT64 base;
};
static_assert(sizeof(DescriptorTableRegister) == 0xA, "DESCRIPTOR_TABLE_REGISTER Size Mismatch");
#include <poppack.h>

/*  segment attribute structure  */
struct SegmentAttribute
{
    union
    {
        UINT16 value;
        struct
        {
            UINT16 type : 4;
            UINT16 system : 1;
            UINT16 dpl : 2;
            UINT16 present : 1;
            UINT16 avl : 1;
            UINT16 long_mode : 1;
            UINT16 default_bit : 1;
            UINT16 granularity : 1;
            UINT16 reserved1 : 4;
        } fields;
    };
};
static_assert(sizeof(SegmentAttribute) == 2, "SegmentAttribute Size Mismatch");

/*  address translation helper for paging  */
union AddressTranslationHelper
{
    struct
    {
        UINT64 page_offset : 12;
        UINT64 pt : 9;
        UINT64 pd : 9;
        UINT64 pdpt : 9;
        UINT64 pml4 : 9;
        UINT64 reserved : 16;
    } AsIndex;
    
    struct
    {
        UINT64 offset_4kb : 12;
        UINT64 offset_2mb : 21;
        UINT64 offset_1gb : 30;
    } AsPageOffset;
    
    UINT64 as_int64;
};

/*  extern declarations  */
extern "C" void _sgdt(void* Descriptor);
extern "C" void _sidt(void* Descriptor);
extern "C" UINT64 _readdr(UINT32 Dr);
extern "C" void _writedr(UINT32 Dr, UINT64 Value);
