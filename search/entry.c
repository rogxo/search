#include <ntifs.h>
#include "search.h"

VOID DriverUnload(PDRIVER_OBJECT DriverObject)
{
	UNREFERENCED_PARAMETER(DriverObject);
	StopSearch();	// 结束搜索线程
}

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
	UNREFERENCED_PARAMETER(RegistryPath);
	NTSTATUS status;
	
	DriverObject->DriverUnload = DriverUnload;
	status = StartSearch();		// 启动搜索线程
	return status;
}
