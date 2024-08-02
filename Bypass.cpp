#include "Bypass.h"

namespace Bypass
{
	bool Init()
	{
		SeValidateImageDataOffset	= KernelUtils::GetSeValidateImageDataOffset();
		SeValidateImageHeaderOffset = KernelUtils::GetSeValidateImageHeaderOffset();
		RetOffset					= KernelUtils::GetReturnOffset();
		NtoskrnlBaseAddress			= KernelUtils::GetNtoskrnlBase();
		PatchgaurdValueOffset		= KernelUtils::GetPatchGaurdValueOffset();
		PatchgaurdOffset			= KernelUtils::GetPatchGaurdOffset();

		if (SeValidateImageDataOffset == 0 || SeValidateImageHeaderOffset == 0 || RetOffset == 0 || NtoskrnlBaseAddress == 0)
			return false;

		return true;
	}

	bool DisableDSE()
	{
		ULONG64 ReturnAddressOffset = NtoskrnlBaseAddress + RetOffset;

		BOOL Status = Vuln::WriteVirtualMemory(VulnurableDriverHandle, NtoskrnlBaseAddress + SeValidateImageHeaderOffset, &ReturnAddressOffset, sizeof(ReturnAddressOffset));
		if (!Status)
			return false;

		Status = Vuln::WriteVirtualMemory(VulnurableDriverHandle, NtoskrnlBaseAddress + SeValidateImageDataOffset, &ReturnAddressOffset, sizeof(ReturnAddressOffset));
		if (!Status)
			return false;

		return Status;
	}

	bool DisablePG() 
	{
		ULONG64 ReturnAddressOffset			= NtoskrnlBaseAddress + RetOffset;
		ULONG64 PatchGaurdValueAddress		= NtoskrnlBaseAddress + PatchgaurdValueOffset;

		BOOL Status = Vuln::WriteVirtualMemory(VulnurableDriverHandle, NtoskrnlBaseAddress + PatchgaurdOffset, &PatchGaurdValueAddress, 8);
		return Status;
	}

	bool LoadVulnurableDriver(std::string PdFwKrnlPath, std::string PdFwKrnlServiceName)
	{
		std::string DrvPath = PdFwKrnlPath;
		bool Status = driver::load(DrvPath, "PdFwKrnl");
		if (!Status)
			return Status;

		VulnurableDriverHandle = CreateFileA(E("\\\\.\\PdFwKrnl"), GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
		if (VulnurableDriverHandle == INVALID_HANDLE_VALUE || !VulnurableDriverHandle)
			return false;

		return true;
	}

	BypassStatus LoadCheatDriver(std::string DriverPath, std::string DriverServiceName, std::string PdFwKrnlPath, std::string PdFwKrnlServiceName)
	{
		bool Status = LoadVulnurableDriver(PdFwKrnlPath, PdFwKrnlServiceName);
		if (!Status)
			return FAILED_LOADINGVULN;

		Status = DisablePG();
		if (!Status)
			return FAILED_DISABLEPG;
		
		Status = DisableDSE();
		if (!Status)
			return FAILED_DISABLEDSE;
		
		std::string DrvPath = DriverPath;
		Status = driver::load(DrvPath, DriverServiceName);
		if (Status == 0xC000010E)
			driver::unload(DriverServiceName);

		Status = driver::load(DrvPath, DriverServiceName);
		if (!Status)
			return FAILED_LOADINGCHEATDRV;

		driver::unload(PdFwKrnlServiceName);
		return SUCCESS;
	}

	std::string BypassStatusToString(BypassStatus Status)
	{
		std::string StatusString;

		switch (Status)
		{
			case FAILED_LOADINGVULN:
			{
				StatusString = "Failed loading Vulnurable Driver";
				break;
			}

			case FAILED_DISABLEPG:
			{
				StatusString = "Failed Disabling Patchgaurd";
				break;
			}

			case FAILED_DISABLEDSE:
			{
				StatusString = "Failed Disabling DSE";
				break;
			}

			case FAILED_LOADINGCHEATDRV:
			{
				StatusString = "Failed Loading Main Driver";
				break;
			}

			case SUCCESS:
			{
				StatusString = "Success";
				break;
			}

			defualt:
			{
				StatusString = "Unkown Status, assuming success";
				break;
			}
		}

		return StatusString;
	}
}

