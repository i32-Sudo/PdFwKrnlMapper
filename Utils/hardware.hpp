#include <windows.h>
#include <tlhelp32.h>
#include <string>
#include <iostream>
#include "vector.h"
#include <tuple>
#include <cmath>

std::string GetDiskVolumeSerialNumber()
{
    char volumeName[MAX_PATH + 1] = { 0 };
    char fileSystemName[MAX_PATH + 1] = { 0 };
    DWORD serialNumber = 0;
    DWORD maxComponentLength = 0;
    DWORD fileSystemFlags = 0;

    if (GetVolumeInformationA("C:\\", volumeName, ARRAYSIZE(volumeName),
        &serialNumber, &maxComponentLength, &fileSystemFlags,
        fileSystemName, ARRAYSIZE(fileSystemName)))
    {
        // Convert serial number to a string
        std::string serialNumberStr = std::to_string(serialNumber);

        return serialNumberStr;
    }
    else
    {
        // Handle error
        DWORD error = GetLastError();
        std::cerr << "Failed to get volume information. Error code: " << error << std::endl;
        return "";
    }
}