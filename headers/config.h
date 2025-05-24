#pragma once
#include <windows.h>

namespace injector {
	int WriteConfig(wchar_t* absPath, wchar_t* selectedFilePath, wchar_t* selectedProcess);
	void ReadConfig(wchar_t* absPath, wchar_t* procName, wchar_t* dllPath, size_t pNLength, size_t dPLength);
}