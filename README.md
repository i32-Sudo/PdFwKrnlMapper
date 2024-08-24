# PdFwKrnlMapper
An Unsigned Driver Mapper for Windows 10 22H2 -> Windows 11 23H2 that uses PdFwKrnl to exploit the Read/Write IOCTL Calls to disable DSE &amp; PG to map the unsigned driver.
# Main Entry
```cpp
#include <iostream>
#include <windows.h>
#include "Bypass.h"

int main() {
	std::cout << " Initializing Offsets...\n";
	Bypass::Init(); // Initialize Offsets & Cache Them
	std::cout << " Initializing Exploit and Loading Cheat Driver using PdFwKrnl...\n";
	Bypass::BypassStatus Status = Bypass::LoadCheatDriver("C:\\Driver.sys", "Driver Service Name", "C:\\Windows\\System32\\PdFwKrnl.sys", "Vuln Service Name"); // Load Cheat Driver & PdFwKrnl
	std::cout << " Status: " << Bypass::BypassStatusToString(Status) << std::endl;
	Sleep(5000);
	driver::unload("Driver Service Name"); // Unload Cheat Driver
	return 0;
}
```
# Contact
If you want to contact me in regards of my work or projects my discord is -> `_ambitza`, Please do not message me for Issues or Learning/Studying I am not a teacher.
