#ifndef _GLOBAL_H
#define _GLOBAL_H

#include <ntifs.h>
#include <ntimage.h>
#include <intrin.h>
#include <ntstrsafe.h>
#include <windef.h>
#include <wdm.h>
#include <stdarg.h>
#include <string.h>

#define KERNEL_STACK_SIZE (PAGE_SIZE * 8)
#define TARGET_DR3 0x7FFE0FF0ULL
#define SYSCALL_BYPASS_MAGIC 0x1337133713371337ULL

// Forward declarations
extern "C" UINT64 g_OriginalLstar;
extern "C" UINT64 g_TargetSysHandler;

// Logging macro
#define LOG_ERROR 0
#define LOG_WARN  1
#define LOG_INFO  2
#define LOG_DEBUG 3

extern LONG g_LogLevel;

void log_message(const char* format, ...);
#define LOG(level, ...) if (level <= g_LogLevel) log_message(__VA_ARGS__)

#endif
