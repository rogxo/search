#include "ipi.h"
#include "utils.h"

ULONG_PTR IpiBroadcastFunction(_In_ ULONG_PTR Argument)
{
    UNREFERENCED_PARAMETER(Argument);

    DbgPrint("[*] Running at %s\n", __FUNCTION__);
    StackWalk();    // 栈回溯
    return 0;
}

NTSTATUS CheckByIpi()
{
    // 发起处理器间中断，打断所有核心让其执行IpiBroadcastFunction
    KeIpiGenericCall(IpiBroadcastFunction, 0);
    return STATUS_SUCCESS;
}
