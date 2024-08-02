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