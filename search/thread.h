#pragma once
#include <ntifs.h>

NTSTATUS CheckThreadCallstackByApc(PETHREAD Thread);

NTSTATUS CheckThreadCallstackByDpcApc(PETHREAD Thread);

NTSTATUS CheckThreadRip(PETHREAD Thread);

NTSTATUS CheckAllThread();
