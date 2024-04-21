#include "nmi.h"
#include "utils.h"

PVOID ShellcodeAddress;

BOOLEAN NmiCallbackForCheck(PVOID Context, BOOLEAN Handled)
{
	UNREFERENCED_PARAMETER(Context);
	UNREFERENCED_PARAMETER(Handled);

	//DbgPrint("[*] Running at %s\n", __FUNCTION__);	// Cannot use print in NMI context or BSOD

	PVOID StackFrames[STACK_CAPTURE_SIZE];
	ULONG FramesCaptured = RtlWalkFrameChain(StackFrames, STACK_CAPTURE_SIZE - 1, 0);
	for (ULONG i = 0; i < FramesCaptured; ++i)
	{
		PVOID Address = StackFrames[i];
		PKLDR_DATA_TABLE_ENTRY Module = GetKernelModuleForAddress(Address);
		if (Module == NULL)
		{
			ShellcodeAddress = Address;
			break;
		}
	}
	return TRUE;
}

NTSTATUS CheckByNmi()
{
	NTSTATUS status;
	PVOID NmiCallbackHandle;
	ULONG ProcessorCount;
	KAFFINITY_EX NmiAffinity;

	// 获取CPU逻辑核心数量
	ProcessorCount = KeQueryActiveProcessorCountEx(ALL_PROCESSOR_GROUPS);
	// 注册NMI回调函数
	NmiCallbackHandle = KeRegisterNmiCallback(NmiCallbackForCheck, NULL);
	if (!NmiCallbackHandle)
	{
		return STATUS_UNSUCCESSFUL;
	}
	for (CCHAR i = 0u; i < (CCHAR)ProcessorCount; ++i)
	{
		ShellcodeAddress = NULL;
		KeInitializeAffinityEx(&NmiAffinity);	// 初始化KAFFINITY_EX结构体
		KeAddProcessorAffinityEx(&NmiAffinity, i);	// 绑定指定CPU核心到KAFFINITY_EX上
		HalSendNMI(&NmiAffinity);	// 向执行核心发送NMI
		Sleep(100);
		if (ShellcodeAddress)
		{
			DbgPrint("Shellcode detected at cpu:%d  VirtualAddress:%p    %ws\n",
				i, ShellcodeAddress, L" <------ Shellcode!");
		}
	}
	status = KeDeregisterNmiCallback(NmiCallbackHandle);
	return status;
}
