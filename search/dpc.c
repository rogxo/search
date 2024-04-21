#include "dpc.h"
#include "utils.h"

VOID AsynchronousDpcRoutine(IN PKDPC Dpc, IN PVOID DeferredContext, IN PVOID SystemArgument1, IN PVOID SystemArgument2)
{
    UNREFERENCED_PARAMETER(Dpc);
    UNREFERENCED_PARAMETER(DeferredContext);
    UNREFERENCED_PARAMETER(SystemArgument1);
    UNREFERENCED_PARAMETER(SystemArgument2);

    DbgPrint("[*] Running at %s\n", __FUNCTION__);
    StackWalk();    // 对当前核心上正在执行的线程进行调用堆栈回溯
}

NTSTATUS CheckByAsynchronousDpc()
{
    KDPC Dpc;
    ULONG ProcessorCount;

    ProcessorCount = KeQueryActiveProcessorCountEx(ALL_PROCESSOR_GROUPS);
    for (CCHAR i = 0; i < (CCHAR)ProcessorCount; i++)
    {
        KeInitializeDpc(&Dpc, AsynchronousDpcRoutine, NULL);    // 初始化KDPC结构体
        KeSetTargetProcessorDpc(&Dpc, i);      // 绑定DPC执行的CPU核心
        if (!KeInsertQueueDpc(&Dpc, NULL, NULL))    // 将DPC插入到CPU核心的DPC队列中
        {
            DbgPrint("[-] Failed to insert DPC!\n");
            return STATUS_UNSUCCESSFUL;
        }
        KeFlushQueuedDpcs();    // 使在所有核心DPC队列上的DPC立即交付执行
    }
    return STATUS_SUCCESS;
}

VOID SynchronousDpcRoutine(IN PKDPC Dpc, IN PVOID DeferredContext, IN PVOID SystemArgument1, IN PVOID SystemArgument2)
{
    UNREFERENCED_PARAMETER(Dpc);
    UNREFERENCED_PARAMETER(DeferredContext);
    UNREFERENCED_PARAMETER(SystemArgument1);
    UNREFERENCED_PARAMETER(SystemArgument2);

    DbgPrint("[*] Running at %s\n", __FUNCTION__);
    StackWalk();    // 对当前核心上正在执行的线程进行调用堆栈回溯
    KeSignalCallDpcDone(SystemArgument1);   // 通知DPC调度系统该核心上的DPC例程执行结束
}

NTSTATUS CheckBySynchronousDpc()
{
    // 使所有核心同时立即执行指定的DPC例程
    KeGenericCallDpc(SynchronousDpcRoutine, NULL);
    return STATUS_SUCCESS;
}