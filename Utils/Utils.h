#pragma once
#include "../Bypass.h"

namespace KernelUtils
{
	ULONG64 GetNtoskrnlBase();
	ULONG64 GetSeValidateImageHeaderOffset();
	ULONG64 GetSeValidateImageDataOffset();
	ULONG64 GetReturnOffset();
	ULONG64 GetPatchGaurdOffset();
	ULONG64 GetPatchGaurdValueOffset();
}