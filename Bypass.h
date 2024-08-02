#pragma once
#include "Signature/Scanner.h"
#include "Utils/Utils.h"
#include "Loadup/Loadup.h"
#include "Vuln/Vuln.h"

namespace Bypass
{
	enum BypassStatus : int {
		FAILED_LOADINGVULN,
		FAILED_DISABLEPG,
		FAILED_DISABLEDSE,
		FAILED_LOADINGCHEATDRV,
		SUCCESS,
	};

	static char SeValidateImageDataOG[8]	= { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 }; // Not Needed unless its VGK.
	static char SeValidateImageHeaderOG[8]  = { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 }; // Not Needed unless its VGK.

	static ULONG64 SeValidateImageDataOffset;
	static ULONG64 SeValidateImageHeaderOffset;
	static ULONG64 RetOffset;
	static ULONG64 NtoskrnlBaseAddress;
	static ULONG64 PatchgaurdValueOffset;
	static ULONG64 PatchgaurdOffset;
	static HANDLE  VulnurableDriverHandle;

	bool Init();

	bool DisableDSE();
	bool DisablePG();

	bool LoadVulnurableDriver(std::string PdFwKrnlPath, std::string PdFwKrnlServiceName);

	BypassStatus LoadCheatDriver(std::string DriverPath, std::string DriverServiceName, std::string PdFwKrnlPath, std::string PdFwKrnlServiceName);
	std::string BypassStatusToString(BypassStatus Status);
}