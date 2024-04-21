#include "page.h"
#include <intrin.h>
#include "ia32.h"
#include "utils.h"

PCHAR PageSignature = "\x55\x56\x48\x83\xEC\x38\x48\x8D\x6C\x24\x30\x48\x83\xE4\xF0\xC7\x44\x24\x2C";

VOID CheckPage(ULONG_PTR Pfn, ULONG PageSize)
{
	PVOID VirtualAddress;

	if (PageSize < sizeof(PageSignature)) 
		return;

	VirtualAddress = GetVirtualForPhysical(Pfn << 12);	//获取物理页面所在的虚拟地址
	if (!MmIsAddressValid(VirtualAddress)) 
		return;

	__try {
		// 对比页面内存是否包含shellcode特征
		if (!memcmp(VirtualAddress, PageSignature, 19))
		{
			DbgPrint("[+] Shellcode page pfn:%llX -> VA:%p    <------ Shellcode!\n", Pfn, VirtualAddress);
		}
	}
	__except (1) {
	}
}

NTSTATUS ScanPageTable()
{
	CR3 Cr3;

	Cr3.AsUInt = __readcr3();	// 拿到本进程（System）的Cr3
	PML4E_64* Pml4 = (PML4E_64*)GetVirtualForPhysical(Cr3.AddressOfPageDirectory << 12);	// 获取PML4表的基址对应的虚拟地址
	if (!Pml4)	return STATUS_ACCESS_VIOLATION;
	// 遍历四级页表，判断页面可执行属性并测试物理页面是存在特定内存
	for (ULONG Pxi = 0; Pxi < 512; Pxi++)
	{
		PML4E_64 Pxe = Pml4[Pxi];
		if (!Pxe.Present) continue;
		//KdPrint(("[PteWalk] Pml4[%X]:%016llX -> Pxe.Pfn:%llX\n", Pxi, Pxe.AsUInt, Pxe.PageFrameNumber));

		PDPTE_64* Pdpt = (PDPTE_64*)GetVirtualForPhysical(Pxe.PageFrameNumber << 12);
		if (!MmIsAddressValid(Pdpt)) continue;

		for (ULONG Ppi = 0; Ppi < 512; Ppi++)
		{
			PDPTE_64 Ppe = Pdpt[Ppi];
			if (!Ppe.Present) continue;

			if (Ppe.LargePage) {
				PDPTE_1GB_64 Ppe_1G;	// 1GB large page
				Ppe_1G.AsUInt = Ppe.AsUInt;
				//KdPrint(("[PteWalk] Pdpt[%X]:%016llX -> PpeLarge.Pfn:%llX\n", Ppi, Ppe_1G.AsUInt, Ppe_1G.PageFrameNumber));
				if (!Ppe_1G.ExecuteDisable) {
					CheckPage(Ppe_1G.PageFrameNumber, 0x40000000);
				}
				continue;
			}

			PDE_64* Pd = (PDE_64*)GetVirtualForPhysical(Ppe.PageFrameNumber << 12);
			if (!MmIsAddressValid(Pd)) continue;

			for (ULONG Pdi = 0; Pdi < 512; Pdi++)
			{
				PDE_64 Pde = Pd[Pdi];
				if (!Pde.Present) continue;

				if (Pde.LargePage) {
					PDE_2MB_64 Pde_2M;	// 2MB large page
					Pde_2M.AsUInt = Pde.AsUInt;
					//KdPrint(("[PteWalk] Pd[%X]:%016llX -> PdeLarge.Pfn:%llX\n", Pdi, Pde_2M.AsUInt, Pde_2M.PageFrameNumber));
					if (!Pde_2M.ExecuteDisable) {
						CheckPage(Pde_2M.PageFrameNumber, 0x200000);
					}
					continue;
				}

				PTE_64* Pt = (PTE_64*)GetVirtualForPhysical(Pde.PageFrameNumber << 12);
				if (!MmIsAddressValid(Pt)) continue;
				for (ULONG Pti = 0; Pti < 512; Pti++)
				{
					PTE_64 Pte = Pt[Pti];
					if (!Pte.Present) continue;
					if (!Pte.ExecuteDisable) {
						CheckPage(Pte.PageFrameNumber, 0x1000);
					}
				}
			}
		}
	}
	return STATUS_SUCCESS;
}
