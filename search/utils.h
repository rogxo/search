#pragma once
#include <ntifs.h>
#include "import.h"

#define STACK_CAPTURE_SIZE 32

PKLDR_DATA_TABLE_ENTRY GetKernelModuleForAddress(PVOID Address);

PVOID GetThreadStartAddress(PETHREAD Thread);

VOID StackWalk();

VOID Sleep(ULONG Milliseconds);

ULONG_PTR FindPattern(PVOID Base, SIZE_T Size, PCHAR Pattern);

PVOID GetVirtualForPhysical(ULONG_PTR PhysicalAddress);

PVOID GetProcAddressW(PCWSTR SourceString);
