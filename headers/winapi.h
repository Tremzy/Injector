#pragma once
#include <windows.h>
#include "map"
#include <string>

namespace injector {
	DWORD FetchProcesses(std::map<size_t, std::tuple<const char*, int>>& processes);
	LRESULT CALLBACK KeyboardHook(int nCode, WPARAM wParam, LPARAM lParam);
	void CreateConsole();
	void FindProcInList(wchar_t* w_procName, HWND hComboBox, HWND p_hwnd);
	void FindLastDLL(wchar_t* w_dllPath, wchar_t* selectedFilePath, HWND pathEdit, wchar_t* dllFileName);
	void Inject(HWND hComboBox, wchar_t* selectedProcess, wchar_t* appDataPath, wchar_t* selectedFilePath, bool (*injectFunc)(DWORD processID, const std::string& dllPath), HWND p_hwnd);
	void SelectDLL(HWND hwnd, wchar_t* selectedFilePath, wchar_t* appDataPath, wchar_t* selectedProcess, HWND pathEdit);
	bool InjectDLL(DWORD processID, const std::string& dllPath);
}
