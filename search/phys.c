#include "phys.h"
#include "utils.h"

#pragma warning(disable:6385)

extern PCHAR PageSignature;

NTSTATUS ScanPhysicalMemory()
{
	NTSTATUS status;
	UNICODE_STRING usPhysicalMemory;
	OBJECT_ATTRIBUTES ObjectAttributes;
	HANDLE PhysicalMemoryHandle;
	PPHYSICAL_MEMORY_RANGE PhysicalMemoryRanges;
	PVOID BaseAddress;
	SIZE_T PhysicalMemorySize;
	LARGE_INTEGER SectionOffset;
	ULONG_PTR MappedAddress;
	ULONG_PTR CurrentAddress;
	ULONG_PTR PhysicalAddress;

	RtlInitUnicodeString(&usPhysicalMemory, L"\\Device\\PhysicalMemory");
	InitializeObjectAttributes(&ObjectAttributes, &usPhysicalMemory, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
	status = ZwOpenSection(&PhysicalMemoryHandle, SECTION_ALL_ACCESS, &ObjectAttributes);	// 打开物理内存节区对象
	if (!NT_SUCCESS(status)) 
	{
		return status;
	}
	// 获取系统物理内存区域数据并遍历每个区域
	PhysicalMemoryRanges = MmGetPhysicalMemoryRanges();
	while (PhysicalMemoryRanges->NumberOfBytes.QuadPart)
	{
		BaseAddress = NULL;
		SectionOffset = PhysicalMemoryRanges->BaseAddress;
		PhysicalMemorySize = PhysicalMemoryRanges->NumberOfBytes.QuadPart;
		// 映射物理内存到虚拟地址
		status = ZwMapViewOfSection(
			PhysicalMemoryHandle, 
			ZwCurrentProcess(), 
			&BaseAddress, 
			0, 
			0,
			&SectionOffset,
			&PhysicalMemorySize, 
			ViewShare,
			0, 
			PAGE_READWRITE
		);
		if (!NT_SUCCESS(status)) {
			ZwClose(PhysicalMemoryHandle);
			return status;
		}
		MappedAddress = (ULONG_PTR)BaseAddress;		// 映射的物理内存的起始虚拟地址
		// 按4K对齐的方式遍历映射过来的物理内存
		for (LONG_PTR i = 0; i < PhysicalMemoryRanges->NumberOfBytes.QuadPart; i+= PAGE_SIZE)
		{
			CurrentAddress = MappedAddress + i;		// 判断物理地址中是否包含shellcode特征
			if (!memcmp((PVOID)CurrentAddress, PageSignature, 19))
			{
				PhysicalAddress = SectionOffset.QuadPart + i;
				DbgPrint("[+] Shellcode mapped at PhysicalAddress:%llX -> VA:%p    <------ Shellcode!\n", 
					PhysicalAddress, GetVirtualForPhysical(PhysicalAddress));
			}
		}
		status = ZwUnmapViewOfSection(ZwCurrentProcess(), BaseAddress);		// 解除物理内存映射
		if (!NT_SUCCESS(status)) {
			ZwClose(PhysicalMemoryHandle);
			return status;
		}
		PhysicalMemoryRanges++;
	}
	return ZwClose(PhysicalMemoryHandle);
}
