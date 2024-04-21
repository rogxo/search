#include "timer.h"
#include "utils.h"

KTIMER Timer;
KDPC TimerDpc;
LONG TimerLock;

VOID TimerDpcRoutine(IN PKDPC Dpc, IN PVOID DeferredContext, IN PVOID SystemArgument1, IN PVOID SystemArgument2)
{
    UNREFERENCED_PARAMETER(Dpc);
    UNREFERENCED_PARAMETER(DeferredContext);
    UNREFERENCED_PARAMETER(SystemArgument1);
    UNREFERENCED_PARAMETER(SystemArgument2);

    InterlockedIncrement(&TimerLock);
    DbgPrint("[*] Running at %s\n", __FUNCTION__);
    StackWalk();    // 对当前核心上正在执行的线程进行调用堆栈回溯
    InterlockedDecrement(&TimerLock);
}

NTSTATUS StartTimerCheck()
{
    LARGE_INTEGER DueTime;
    BOOLEAN Result;

    KeInitializeDpc(&TimerDpc, TimerDpcRoutine, NULL);  // 初始化 DPC 对象
    KeInitializeTimer(&Timer);  // 初始化定时器
    DueTime.QuadPart = -10000 * 1;  // 设置定时器1ms后执行
    Result = KeSetTimer(&Timer, DueTime, &TimerDpc);
    Sleep(10);
    return Result ? STATUS_ALREADY_COMPLETE : STATUS_SUCCESS;
}

NTSTATUS StopTimerCheck()
{
    BOOLEAN Result;
    
    Result = KeCancelTimer(&Timer);
    while (TimerLock) KeStallExecutionProcessor(10);
    return STATUS_SUCCESS;
}

NTSTATUS CheckByTimer()
{
    NTSTATUS status;

    status = StartTimerCheck();		// 启动定时器
    if (!NT_SUCCESS(status)) {
        return status;
    }
    status = StopTimerCheck();		// 停止定时器
    if (!NT_SUCCESS(status)) {
        return status;
    }
    return STATUS_SUCCESS;
}
