#include "search.h"
#include "utils.h"
#include "thread.h"
#include "dpc.h"
#include "nmi.h"
#include "ipi.h"
#include "pool.h"
#include "page.h"
#include "phys.h"
#include "timer.h"

KEVENT SearchSyncEvent;
PETHREAD SearchThread = NULL;

VOID SearchThreadProc(_In_ PVOID StartContext)
{
	UNREFERENCED_PARAMETER(StartContext);
	NTSTATUS status;
	LARGE_INTEGER Interval;

	while (TRUE)
	{
		// 通过向全部核心插入异步执行的DPC例程打断执行中的代码并检查调用堆栈
		CheckByAsynchronousDpc();
		
		// 让全部核心同步执行DPC例程打断执行中的代码并检查调用堆栈
		CheckBySynchronousDpc();
		
		// 通过注册NMI回调函数并向全部核心发送NMI打断执行中的代码并检查调用堆栈
		CheckByNmi();		// Sometime BSOD	// 貌似在NMI回调里没法DbgPrint
		
		// 通过向全部核心发送IPI（处理器间中断）的方式打断执行中的代码并检查调用堆栈
		CheckByIpi();
		
		// 遍历内核Pool内存寻找shellcode特征以定位shellcode
		ScanBigPool();
		
		// 遍历系统进程页表，对比内存定位shellcode
		ScanPageTable();
		
		// 遍历系统所有物理内存，对比内存定位shellcode
		ScanPhysicalMemory();

		// 通过在定时器回调栈回溯查找shellcode
		CheckByTimer();

		Interval.QuadPart = -10000LL * 100;		// 设置等待同步事件的超时时间为100ms
		status = KeWaitForSingleObject(&SearchSyncEvent, Executive, KernelMode, FALSE, &Interval);
		if (status == STATUS_SUCCESS) 
		{
			PsTerminateSystemThread(STATUS_SUCCESS);
		}
	}
}

NTSTATUS StartSearch()
{
	NTSTATUS status;
	HANDLE Handle;

	if (SearchThread) {
		return STATUS_ALREADY_COMPLETE;
	}
	KeInitializeEvent(&SearchSyncEvent, NotificationEvent, FALSE);
	status = PsCreateSystemThread(&Handle, THREAD_ALL_ACCESS, NULL, NtCurrentProcess(), NULL, SearchThreadProc, NULL);
	if (!NT_SUCCESS(status)) {
		return status;
	}
	DbgPrint("[Search] Search started!\n");
	status = ObReferenceObjectByHandle(Handle, THREAD_ALL_ACCESS, NULL, KernelMode, (PVOID*)&SearchThread, NULL);
	if (!NT_SUCCESS(status)) {
		return status;
	}
	status = ZwClose(Handle);
	if (!NT_SUCCESS(status)) {
		return status;
	}
	return status;
}

NTSTATUS StopSearch()
{
	NTSTATUS status = STATUS_SUCCESS;
	if (SearchThread)
	{
		KeSetEvent(&SearchSyncEvent, 0, FALSE);		// 设置同步事件的状态
		status = KeWaitForSingleObject(SearchThread, Executive, KernelMode, FALSE, NULL);	// 等待线程结束
		ObDereferenceObject(SearchThread);
		SearchThread = NULL;
		DbgPrint("[Search] Search stoped!\n");
		return status;
	}
	return status;
}
