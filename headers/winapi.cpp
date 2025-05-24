#include "winapi.h"
#include "config.h"
#include <iostream>
#include <Windows.h>
#include <tlhelp32.h>
#include <filesystem>
#include <map>

namespace injector {
    bool consoleSwitch = false;

    // Allocate a console since windows requires this if you want to make a window application
    void CreateConsole() {
        AllocConsole();
        FILE* fp;
        freopen_s(&fp, "CONOUT$", "w", stdout);
        freopen_s(&fp, "CONOUT$", "w", stderr);
        freopen_s(&fp, "CONIN$", "r", stdin);

        std::ios::sync_with_stdio();
        std::cout.clear(); std::clog.clear(); std::cerr.clear();
        std::cin.clear();
    }

    // Hook on keyboard thread to detect keypress for switching the console on and off
    LRESULT CALLBACK KeyboardHook(int nCode, WPARAM wParam, LPARAM lParam) {
        if (wParam == WM_KEYDOWN) {
            KBDLLHOOKSTRUCT* keyPtr = reinterpret_cast<KBDLLHOOKSTRUCT*>(lParam);
            DWORD vkCode = keyPtr->vkCode;
            if (vkCode == VK_INSERT) {
                consoleSwitch ? ShowWindow(GetConsoleWindow(), SW_HIDE) : ShowWindow(GetConsoleWindow(), SW_SHOW);
                consoleSwitch = !consoleSwitch;
            }
        }
        return CallNextHookEx(NULL, nCode, wParam, lParam);
    }

    // Fetch process from WinAPI processlist and save it in a map object
    DWORD FetchProcesses(std::map<size_t, std::tuple<const char*, int>>& processes) {
        HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snapshot == INVALID_HANDLE_VALUE) return 0;

        PROCESSENTRY32 processEntry;
        memset(&processEntry, 0, sizeof(PROCESSENTRY32));
        processEntry.dwSize = sizeof(PROCESSENTRY32);

        if (Process32First(snapshot, &processEntry)) {
            do {
                //std::wcout << processEntry.szExeFile << L" - " << processEntry.th32ProcessID << std::endl;
                int procId = processEntry.th32ProcessID;
                wchar_t* w_fname = processEntry.szExeFile;

                size_t len = wcslen(w_fname) + 1;
                char* procName = new char[len];
                size_t convChars = 0;
                wcstombs_s(&convChars, procName, len, w_fname, _TRUNCATE);


                std::cout << procName << " - " << procId << std::endl;

                processes[processes.size()] = std::make_tuple(static_cast<const char*>(procName), procId);
            } while (Process32Next(snapshot, &processEntry));
        }

        CloseHandle(snapshot);
        return 0;
    }

    // Find the saved process name in the current process list and set it to selected, report if not found
    void FindProcInList(wchar_t* w_procName, HWND hComboBox, HWND p_hwnd) {
        if (wcslen(w_procName) > 1) {
            int count = (int)SendMessage(hComboBox, CB_GETCOUNT, 0, 0);
            bool foundProc = false;
            for (int i = 0; i < count; i++) {
                wchar_t itemTextBuffer[MAX_PATH];
                memset(itemTextBuffer, 0, sizeof(wchar_t) * MAX_PATH);
                SendMessage(hComboBox, CB_GETLBTEXT, i, (LPARAM)itemTextBuffer);
                bool mismatchFound = false;
                for (size_t i = 0; i < wcslen(w_procName); i++) {
                    if (w_procName[i] != itemTextBuffer[i]) {
                        mismatchFound = true;
                        break;
                    }
                }

                if (!mismatchFound) {
                    foundProc = true;
                    std::wcout << "Found " << itemTextBuffer << " as matching with " << w_procName << std::endl;
                    SendMessage(hComboBox, CB_SETCURSEL, i, 0);
                    break;
                }
            }
            if (!foundProc) MessageBox(p_hwnd, L"Couldnt find previously used application in current process list. You may reselect it after you've opened it.", L"Process not found", MB_ICONINFORMATION);
        }
    }
    
    // Sets the selected DLL to the one that is saved in config
    void FindLastDLL(wchar_t* w_dllPath, wchar_t* selectedFilePath, HWND pathEdit, wchar_t* dllFileName) {
        if (wcslen(w_dllPath) > 1 && std::filesystem::exists(w_dllPath)) {
            std::cout << "valid dllpath" << std::endl;
            wchar_t* lastSlash = wcsrchr(w_dllPath, L'\\');
            if (lastSlash) {
                wcscpy_s(dllFileName, MAX_PATH + 1, lastSlash + 1);
                std::wcout << "lastFileName: " << dllFileName << std::endl;
                wcscpy_s(selectedFilePath, MAX_PATH + 1, w_dllPath);
                SetWindowTextW(pathEdit, dllFileName);
            }
        }
    }

    // Injects the selected DLL into the selected process on button press
    void Inject(HWND hComboBox, wchar_t* selectedProcess, wchar_t* appDataPath, wchar_t* selectedFilePath, bool (*injectFunc)(DWORD processID, const std::string& dllPath), HWND p_hwnd) {
        LRESULT index = SendMessage(hComboBox, CB_GETCURSEL, 0, 0);
        if (index != CB_ERR) {
            wchar_t processData[260];
            memset(processData, 0, sizeof(wchar_t) * 260);
            SendMessage(hComboBox, CB_GETLBTEXT, index, (LPARAM)processData);
            std::wcout << processData << std::endl;
            wchar_t procDataCopy[MAX_PATH + 1];
            wcscpy_s(procDataCopy, MAX_PATH + 1, processData);
            wchar_t* paren = wcsrchr(procDataCopy, L'(');
            if (paren != nullptr) {
                *paren = L'\0';
            }
            wcscpy_s(selectedProcess, MAX_PATH + 1, procDataCopy);

            injector::WriteConfig(appDataPath, selectedFilePath, selectedProcess);

            const wchar_t* openParen = wcsrchr(processData, L'(');
            if (openParen) {
                int procID = _wtoi(openParen + 1);
                std::cout << procID << std::endl;

                size_t len = wcslen(selectedFilePath) + 1;
                char* ch_path = new char[len];
                size_t convChars = 0;
                wcstombs_s(&convChars, ch_path, len, selectedFilePath, _TRUNCATE);
                if (!injectFunc((DWORD)procID, ch_path)) {
                    MessageBox(p_hwnd, L"Failed to inject", L"Error", MB_ICONERROR);
                }
                else {
                    MessageBox(p_hwnd, L"Successfully injected!", L"Success", MB_OK);
                }
            }
        }
    }

    // Select DLL in a file explorer opened by the injector
    void SelectDLL(HWND hwnd, wchar_t* selectedFilePath, wchar_t* appDataPath, wchar_t* selectedProcess, HWND pathEdit) {
        OPENFILENAME ofn;
        ZeroMemory(&ofn, sizeof(ofn));
        ofn.lStructSize = sizeof(ofn);
        ofn.hwndOwner = hwnd;
        ofn.lpstrFile = selectedFilePath;
        ofn.lpstrFile[0] = '\0';
        ofn.nMaxFile = MAX_PATH;
        ofn.lpstrFilter = L"DLL Files (.dll)\0*.dll\0All Files\0*.*\0";
        ofn.nFilterIndex = 1;
        ofn.Flags = OFN_PATHMUSTEXIST | OFN_FILEMUSTEXIST | OFN_NOCHANGEDIR;

        if (GetOpenFileName(&ofn) == TRUE) {
            std::wcout << selectedFilePath << std::endl;

            injector::WriteConfig(appDataPath, selectedFilePath, selectedProcess);

            wchar_t basename[260] = { 0 };
            size_t pathLen = wcslen(selectedFilePath);

            for (size_t i = pathLen; i > 0; i--) {
                if (selectedFilePath[i] == L'\\' || selectedFilePath[i] == L'/') {
                    if (i != wcslen(selectedFilePath)) {
                        wcsncpy_s(basename, &selectedFilePath[i + 1], _TRUNCATE);
                        break;
                    }
                }
            }
            SendMessage(pathEdit, EM_SETSEL, 0, -1);
            SendMessage(pathEdit, EM_REPLACESEL, FALSE, (LPARAM)basename);
        }
    }

    // Allocate memory remotely and inject using LoadLibraryA module
    bool InjectDLL(DWORD processID, const std::string& dllPath) {
        HANDLE process = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processID);
        if (!process) return false;

        size_t pathLen = dllPath.length() + 1;
        void* allocMem = VirtualAllocEx(process, NULL, pathLen, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (!allocMem) {
            CloseHandle(process);
            return false;
        }

        if (!WriteProcessMemory(process, allocMem, dllPath.c_str(), pathLen, NULL)) {
            VirtualFreeEx(process, allocMem, 0, MEM_RELEASE);
            CloseHandle(process);
            return false;
        }

        HANDLE thread = CreateRemoteThread(process, NULL, 0, (LPTHREAD_START_ROUTINE)LoadLibraryA, allocMem, 0, NULL);
        if (!thread) {
            VirtualFreeEx(process, allocMem, 0, MEM_RELEASE);
            CloseHandle(process);
            return false;
        }

        WaitForSingleObject(thread, INFINITE);
        VirtualFreeEx(process, allocMem, 0, MEM_RELEASE);
        CloseHandle(thread);
        CloseHandle(process);
        return true;
    }
}