#include "pool.h"
#include "import.h"
#include "utils.h"

#pragma warning(disable: 6011)
#pragma warning(disable: 6387)

// 检查Pool内存的Tag、特征码
VOID CheckPoolMemory(PVOID VirtualAddress, SIZE_T RegionSize, ULONG Tag)
{
	NTSTATUS status;
	PVOID Buffer;
	ULONG_PTR Result;
	ULONG_PTR BaseAddress;
	SIZE_T SizeCopied;
	MM_COPY_ADDRESS MmCopyAddress;

	if (Tag == 'ace0')
	{
		BaseAddress = (ULONG_PTR)VirtualAddress & ~1ull;		// 池内存实际的起始地址
		Buffer = ExAllocatePool(NonPagedPoolNx, RegionSize);	// 申请内存缓冲区
		if (!Buffer)
			return;
		// 拷贝目标池内存，用于后续读取
		MmCopyAddress.VirtualAddress = (PVOID)BaseAddress;
		status = MmCopyMemory(Buffer, MmCopyAddress, RegionSize, MM_COPY_MEMORY_VIRTUAL, &SizeCopied);
		if (NT_SUCCESS(status))
		{
			// 遍历池内存，寻找Shellcode特征
			Result = FindPattern((PVOID)Buffer, RegionSize, "41 B8 CE 0A 00 00");	// mov  r8d, 0ACEh
			if (Result)
			{
				DbgPrint("[+] Shellcode mapped at:%llX  Size:%llX    <------ Shellcode!\n", BaseAddress, RegionSize);
			}
			ExFreePool(Buffer);
		}
	}
}

// 遍历系统中所有Pool内存
NTSTATUS ScanBigPool()
{
	NTSTATUS status;
	PSYSTEM_BIGPOOL_INFORMATION SystemBigPoolInfo;
	PSYSTEM_BIGPOOL_ENTRY Allocation;
	ULONG Length;

	// 获取输出缓冲区长度
	status = ZwQuerySystemInformation(SystemBigPoolInformation, &Length, 0, &Length);
	if (!NT_SUCCESS(status) && status != STATUS_INFO_LENGTH_MISMATCH)
	{
		return status;
	}
	SystemBigPoolInfo = NULL;
	while (status == STATUS_INFO_LENGTH_MISMATCH)
	{
		if (SystemBigPoolInfo)
		{
			ExFreePool(SystemBigPoolInfo);
		}
		SystemBigPoolInfo = (PSYSTEM_BIGPOOL_INFORMATION)ExAllocatePool(NonPagedPoolNx, Length);
		if (!SystemBigPoolInfo)
		{
			return STATUS_INSUFFICIENT_RESOURCES;
		}
		// 获取Pool内存信息
		status = ZwQuerySystemInformation(SystemBigPoolInformation, SystemBigPoolInfo, Length, &Length);
	}
	if (NT_SUCCESS(status))
	{
		for (ULONG i = 0; i < SystemBigPoolInfo->Count; i++)
		{
			Allocation = &SystemBigPoolInfo->AllocatedInfo[i];
			// 检查内存特征是否为目标
			CheckPoolMemory(Allocation->VirtualAddress, Allocation->SizeInBytes, Allocation->TagUlong);
		}
	}
	ExFreePool(SystemBigPoolInfo);
	return status;
}
