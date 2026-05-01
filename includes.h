#pragma once

// Windows kernel headers
#include <ntifs.h>
#include <ntstrsafe.h>
#include <intrin.h>
#include <ntdef.h>
#include <windef.h>
#include <wdm.h>
#include <ntimage.h>

// Standard C++ headers (minimal)
#include <cstdint>
#include <cstring>
#include <new>

// Disable specific warnings
#pragma warning(disable: 4100)  // unreferenced formal parameter
#pragma warning(disable: 4201)  // nameless struct/union
#pragma warning(disable: 4706)  // assignment within conditional

// SAL annotations for static analysis
#define _IRQL_requires_max_(x)
#define _IRQL_requires_min_(x)
#define _IRQL_requires_same_
#define _Check_return_
#define _Must_inspect_result_
#define _Pre_notnull_
#define _Post_writable_byte_size_(x)
#define _Post_maybenull_
#define _In_opt_
#define _Out_opt_
#define _In_
#define _Out_
#define _Inout_
#define _In_z_
#define _Printf_format_string_

// Type aliases
typedef unsigned __int64 SIZE_T;
typedef __int64 SSIZE_T;
