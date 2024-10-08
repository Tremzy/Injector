#include <windows.h>
#include <tlhelp32.h>
#include <iostream>
#include <string>

DWORD GetProcessID(const wchar_t* processName) {
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) return 0;

    PROCESSENTRY32 processEntry;
    processEntry.dwSize = sizeof(PROCESSENTRY32);

    if (Process32First(snapshot, &processEntry)) {
        do {
            if (_wcsicmp(processEntry.szExeFile, processName) == 0) {
                CloseHandle(snapshot);
                return processEntry.th32ProcessID;
            }
        } while (Process32Next(snapshot, &processEntry));
    }

    CloseHandle(snapshot);
    return 0;
}

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

int main() {
    std::wstring inputProcessName;
    std::cout << "Input the target process (e.g., main.exe): " << std::endl;
    std::wcin >> inputProcessName;

    std::string inputDllPath;
    std::cout << "Input the DLL to inject (e.g., C:\\programs\\...\\file.dll): " << std::endl;
    std::cin >> inputDllPath;

    DWORD processID = GetProcessID(inputProcessName.c_str());
    if (processID) {
        if (InjectDLL(processID, inputDllPath)) {
            std::cout << "DLL injected successfully." << std::endl;
        }
        else {
            std::cerr << "DLL injection failed." << std::endl;
        }
    }
    else {
        std::cerr << "Target process not found." << std::endl;
    }

    return 0;
}
