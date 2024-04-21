#include "utils.h"
#include "import.h"

#define InRange(x, a, b) (x >= a && x <= b) 
#define GetBits(x) (InRange(x, '0', '9') ? (x - '0') : ((x - 'A') + 0xA))
#define GetByte(x) ((UCHAR)(GetBits(x[0]) << 4 | GetBits(x[1])))

PKLDR_DATA_TABLE_ENTRY GetKernelModuleForAddress(PVOID Address)
{
    for (PLIST_ENTRY Entry = PsLoadedModuleList; Entry != PsLoadedModuleList->Blink; Entry = Entry->Flink)
    {
        PLDR_DATA_TABLE_ENTRY DataTableEntry = CONTAINING_RECORD(Entry, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
        if ((ULONG_PTR)Address > (ULONG_PTR)DataTableEntry->DllBase && 
			(ULONG_PTR)Address < (ULONG_PTR)DataTableEntry->DllBase + DataTableEntry->SizeOfImage)
        {
            return DataTableEntry;
        }
    }
    return NULL;
}

PVOID GetThreadStartAddress(PETHREAD Thread)
{
	NTSTATUS status;
	HANDLE ThreadHandle;
	PVOID StartAddress;
	ULONG ReturnLength;

	StartAddress = NULL;

	status = ObOpenObjectByPointer(Thread, OBJ_KERNEL_HANDLE, NULL, GENERIC_READ, *PsThreadType, KernelMode, &ThreadHandle);
	if (!NT_SUCCESS(status))
	{
		return NULL;
	}
	status = ZwQueryInformationThread(ThreadHandle, ThreadQuerySetWin32StartAddress, &StartAddress, sizeof(StartAddress), &ReturnLength);
	if (!NT_SUCCESS(status))
	{
		NtClose(ThreadHandle);
		return NULL;
	}
	NtClose(ThreadHandle);
	return StartAddress;
}

VOID StackWalk()
{
    PVOID StackFrames[STACK_CAPTURE_SIZE];

	ULONG FramesCaptured = RtlWalkFrameChain(StackFrames, STACK_CAPTURE_SIZE - 1, 0);
    for (ULONG i = 0; i < FramesCaptured; ++i)
    {
        PVOID Address = StackFrames[i];
        PKLDR_DATA_TABLE_ENTRY Module = GetKernelModuleForAddress(Address);     // 获取地址所在的内核模块
        if (Module == NULL)     // 获取不到内核模块，说明是shellcode
        {
			DbgPrint("[+] Thread:%p  Cpu:%d  StackFrame %d: 0x%p  %ws\n", 
				PsGetCurrentThread(), KeGetCurrentProcessorNumber(), i, Address, L" <------ Shellcode!");
        }
    }
}

VOID Sleep(ULONG Milliseconds)
{
	LARGE_INTEGER Timeout;
	Timeout.QuadPart = -10000LL * (LONGLONG)Milliseconds;
	KeDelayExecutionThread(KernelMode, FALSE, &Timeout);
}

ULONG_PTR FindPattern(PVOID Base, SIZE_T Size, PCHAR Pattern)
{
    BOOLEAN Skip;
    PUCHAR Start = (PUCHAR)Base;
    PUCHAR End = (PUCHAR)(Start + Size);
    PUCHAR FirstMatch = NULL;
    PCHAR CurPatt = Pattern;

    for (; Start < End; ++Start)
    {
        Skip = (*CurPatt == '\?');
        if (Skip || *Start == GetByte(CurPatt)) {
            if (!FirstMatch) FirstMatch = Start;
            if (Skip) CurPatt += 2; else CurPatt += 3;
            if (CurPatt[-1] == 0) return (ULONG_PTR)FirstMatch;
        }
        else if (FirstMatch) {
            Start = FirstMatch;
            FirstMatch = NULL;
            CurPatt = Pattern;
        }
    }
    return 0;
}

PVOID GetVirtualForPhysical(ULONG_PTR PhysicalAddress)
{
    PHYSICAL_ADDRESS Pa;
    Pa.QuadPart = PhysicalAddress;
    return MmGetVirtualForPhysical(Pa);     // 将物理地址转换到虚拟地址的映射
}

PVOID GetProcAddressW(PCWSTR SourceString)
{
    UNICODE_STRING DestinationString; // [rsp+20h] [rbp-18h] BYREF

    RtlInitUnicodeString(&DestinationString, SourceString);
    return MmGetSystemRoutineAddress(&DestinationString);
}
