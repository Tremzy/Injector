#include <windows.h>
#include <tlhelp32.h>
#include <iostream>
#include <string>
#include <map>
#include <cstring>
#include <cwchar> 
#include <tuple>
#include <thread>

HWND p_hwnd;
std::map<int, std::tuple<const char*, int>> processes;

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

DWORD FetchProcesses() {
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) return 0;

    PROCESSENTRY32 processEntry;
    processEntry.dwSize = sizeof(PROCESSENTRY32);

    if (Process32First(snapshot, &processEntry)) {
        do {
            //if (_wcsicmp(processEntry.szExeFile, processName) == 0) {
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

LRESULT CALLBACK WindowProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam) {
    HWND hComboBox;
    HFONT hfont = CreateFont(16, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE, DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, DEFAULT_QUALITY, DEFAULT_PITCH, L"Arial");
    switch (uMsg)
    {
    case WM_CREATE:{
        HDC hdc = GetDC(hwnd);

        RECT rect;
        GetWindowRect(hwnd, &rect);

        hComboBox = CreateWindowEx(
            0, L"COMBOBOX", NULL,
            CBS_DROPDOWN | WS_CHILD | WS_VISIBLE | WS_VSCROLL,
            (rect.right - rect.left) / 2 - 100, 40, 200, 300,
            hwnd, NULL, GetModuleHandle(NULL), NULL
        );

        SendMessage(hComboBox, WM_SETFONT, (WPARAM)hfont, TRUE);
        
        for (auto& process : processes) {
            //extracting info from current entry
            std::tuple<const char*, int> processData = process.second;
            const char* procName = std::get<0>(processData);
            int procId = std::get<1>(processData);

            //building the text
            char option[260];
            std::snprintf(option, sizeof(option), "%s (%d)", procName, procId);

            //converting to useable format
            wchar_t woption[300];
            size_t converted = 0;
            mbstowcs_s(&converted, woption, option, _TRUNCATE);

            //appending to options
            SendMessage(hComboBox, CB_ADDSTRING, 0, (LPARAM)woption);
        }
        return 0;
    }
    case WM_PAINT:
    {
        PAINTSTRUCT ps; 
        HDC hdc = BeginPaint(hwnd, &ps);
        RECT rect;
        GetClientRect(hwnd, &rect);
        SelectObject(hdc, hfont);

        RECT procListLabelRect = {
            50,
            20,
            50 + 200,
            20 + 20
        };

        DrawTextA(hdc, "Process list:", -1, &procListLabelRect, DT_SINGLELINE | DT_LEFT | DT_VCENTER);

        EndPaint(hwnd, &ps);
        return 0;
    }
    case WM_DESTROY: {
        PostQuitMessage(0);
        return 0;
    }
    default:
        return DefWindowProc(hwnd, uMsg, wParam, lParam);
    }
}

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE, LPSTR, int nCmdShow) {
    WNDCLASS wc = {};
    wc.lpfnWndProc = WindowProc;
    wc.hInstance = hInstance;
    wc.lpszClassName = L"InjectorWindowClass";
    wc.hCursor = LoadCursor(nullptr, IDC_ARROW);
    wc.hbrBackground = (HBRUSH)GetStockObject(WHITE_BRUSH);
    RegisterClass(&wc);
    CreateConsole();
    FetchProcesses();
    HWND hwnd = CreateWindowEx(0, L"InjectorWindowClass", L"Injector", WS_SYSMENU | WS_VISIBLE, GetSystemMetrics(SM_CXSCREEN) / 2, GetSystemMetrics(SM_CYSCREEN) / 2, 300, 400, nullptr, nullptr, hInstance, nullptr);
    if (!hwnd) return 1;
    ShowWindow(hwnd, nCmdShow);
    
    p_hwnd = hwnd;

    MSG msg = {};
    while (GetMessage(&msg, nullptr, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }
    return 0;
}