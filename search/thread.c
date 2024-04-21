#include "thread.h"
#include "import.h"
#include "utils.h"
#pragma warning(disable:6387)

#define MAX_STACK_DEPTH 256

VOID NormalAPC(_In_opt_ PVOID NormalContext, _In_opt_ PVOID SystemArgument1, _In_opt_ PVOID SystemArgument2)
{
    UNREFERENCED_PARAMETER(NormalContext);
    UNREFERENCED_PARAMETER(SystemArgument1);
    UNREFERENCED_PARAMETER(SystemArgument2);
}

VOID RundownAPC(_In_ PRKAPC Apc)
{
    ExFreePool(Apc);
}

VOID CaptureStackAPC(IN PKAPC Apc, IN OUT PKNORMAL_ROUTINE* NormalRoutine, IN OUT PVOID* NormalContext, IN OUT PVOID* SystemArgument1, IN OUT PVOID* SystemArgument2)
{
    UNREFERENCED_PARAMETER(Apc);
    UNREFERENCED_PARAMETER(NormalRoutine);
    UNREFERENCED_PARAMETER(NormalContext);
    UNREFERENCED_PARAMETER(SystemArgument1);
    UNREFERENCED_PARAMETER(SystemArgument2);

    DbgPrint("[*] Running at %s\n", __FUNCTION__);
    StackWalk();
}

NTSTATUS CheckThreadCallstackByApc(PETHREAD Thread)
{
    NTSTATUS status;
    PKAPC Apc;
    
    Apc = (PKAPC)ExAllocatePool(NonPagedPool, sizeof(KAPC));
    if (!Apc) return STATUS_INSUFFICIENT_RESOURCES;

    KeInitializeApc(Apc, Thread, OriginalApcEnvironment, CaptureStackAPC, RundownAPC, NormalAPC, KernelMode, NULL);
    status = KeInsertQueueApc(Apc, NULL, NULL, IO_NO_INCREMENT);
    if (!NT_SUCCESS(status))
    {
        DbgPrint("[-] KeInsertQueueApc failed\n");
        ExFreePool(Apc);
    }
    return status;
}

VOID DpcRoutineForApc(IN PKDPC Dpc, IN PVOID DeferredContext, IN PVOID SystemArgument1, IN PVOID SystemArgument2)
{
    UNREFERENCED_PARAMETER(Dpc);
    UNREFERENCED_PARAMETER(DeferredContext);
    UNREFERENCED_PARAMETER(SystemArgument2);

    CheckThreadCallstackByApc((PETHREAD)SystemArgument1);
}

NTSTATUS CheckThreadCallstackByDpcApc(PETHREAD Thread)
{
    KDPC Dpc;

    KeInitializeDpc(&Dpc, DpcRoutineForApc, NULL);
    if (!KeInsertQueueDpc(&Dpc, Thread, NULL))
    {
        DbgPrint("[-] Failed to insert DPC!\n");
        return STATUS_UNSUCCESSFUL;
    }
    KeFlushQueuedDpcs();
    return STATUS_SUCCESS;
}

NTSTATUS CheckAllThread()
{
    NTSTATUS status;
    PETHREAD Thread;

    for (ULONG tid = 8; tid < 0x13880; tid += 4)
    {
        status = PsLookupThreadByThreadId((HANDLE)tid, &Thread);
        if (NT_SUCCESS(status))
        {
            if (!PsIsThreadTerminating(Thread) && Thread != KeGetCurrentThread())
            {
                if (PsIsSystemThread(Thread))
                {
                    //DbgPrint("[*] Thread:%p  StartAddress:%p\n", Thread, StartAddress);
                    
                    //status = CheckThreadCallstackByApc(Thread);

                    // 从DPC中插入APC的方式只能查到PatchGuard
                    status = CheckThreadCallstackByDpcApc(Thread);

                    // APC会阻塞
                    status = CheckThreadRip(Thread);
                }
            }
            ObDereferenceObject(Thread);
        }
    }
    return status;
}

NTSTATUS(__fastcall* g_PspGetContextThreadInternal)(PETHREAD, PCONTEXT, KPROCESSOR_MODE, KPROCESSOR_MODE, KPROCESSOR_MODE);
NTSTATUS PspGetContextThreadInternal(PETHREAD Thread, PCONTEXT Context, KPROCESSOR_MODE Mode, KPROCESSOR_MODE Mode2, KPROCESSOR_MODE Mode3)
{
    PUCHAR pPsGetContextThread; // rax

    if (!g_PspGetContextThreadInternal)
    {
        pPsGetContextThread = GetProcAddressW(L"PsGetContextThread");
        for (ULONG i = 0; i < 0x20; i++)
        {
            if (pPsGetContextThread[i] == 0xE8)
            {
                g_PspGetContextThreadInternal = 
                    (NTSTATUS(__fastcall*)(PETHREAD, PCONTEXT, KPROCESSOR_MODE, KPROCESSOR_MODE, KPROCESSOR_MODE))
                    ((ULONG_PTR)&pPsGetContextThread[i] + *(LONG*)&pPsGetContextThread[i + 1] + 5);
                break;
            }
        }
    }
    if (g_PspGetContextThreadInternal)
    {
        return g_PspGetContextThreadInternal(Thread, Context, Mode, Mode2, Mode3);
    }
    return STATUS_NOT_FOUND;
}

NTSTATUS CheckThreadRip(PETHREAD Thread)
{
    NTSTATUS status;
    CONTEXT Context = { 0 };

    Context.ContextFlags = CONTEXT_ALL;
    status = PspGetContextThreadInternal(Thread, &Context, KernelMode, KernelMode, KernelMode);
    if (!NT_SUCCESS(status))
    {
        return STATUS_UNSUCCESSFUL;
    }
    PKLDR_DATA_TABLE_ENTRY Module = GetKernelModuleForAddress((PVOID)Context.Rip);     // 获取地址所在的内核模块
    if (Module == NULL)     // 获取不到内核模块，说明是shellcode
    {
        DbgPrint("[+] Thread:%p  Context.Rip:%llX  %ws\n", Thread, Context.Rip, L" <------ Shellcode!");
    }
    return STATUS_SUCCESS;
}