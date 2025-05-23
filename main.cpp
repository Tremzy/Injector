//
//
//
//               BEFORE YOU CRY
// 
//     I WILL DOCUMENT THIS IN THE FUTURE!!!
//
//
//
//
//
//
#include <windows.h>
#include <tlhelp32.h>
#include <iostream>
#include <string>
#include <map>
#include <cstring>
#include <cwchar> 
#include <tuple>
#include <thread>
#include <commdlg.h>
#include <filesystem>
#include <fstream>
#include <lmcons.h>

#define SELECT_DLL_BUTTON 1
#define INJECT_BUTTON 2

#pragma warning(disable: 28251)


static wchar_t appDataPath[MAX_PATH + 1];
HWND p_hwnd;
std::map<size_t, std::tuple<const char*, int>> processes;
static wchar_t selectedFilePath[MAX_PATH + 1] = { 0 };
static wchar_t selectedProcess[MAX_PATH + 1] = { 0 };
static wchar_t dllFileName[MAX_PATH + 1] = {};
HFONT hfont = CreateFontW(16, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE, DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, DEFAULT_QUALITY, DEFAULT_PITCH, L"Segoe UI Variable");
HFONT b_hfont = CreateFontW(20, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE, DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, DEFAULT_QUALITY, DEFAULT_PITCH, L"Segoe UI Variable");

HWND pathEdit;
WNDPROC originalEditProc = nullptr;
HHOOK g_hHook = NULL;
bool consoleSwitch = false;
HWND hComboBox = nullptr;

int WriteConfig(wchar_t* absPath) {
    if (wcslen(absPath) < 1 || wcslen(selectedFilePath) < 1) {
        return 1;
    }

    wchar_t* folderPath = new wchar_t[wcslen(absPath) + 1];
    wcscpy_s(folderPath, wcslen(absPath) + 1, absPath);
    wchar_t* lastSlash = wcsrchr(folderPath, L'\\');
    if (lastSlash != nullptr) {
        *lastSlash = L'\0';
    }

    if (!std::filesystem::exists(folderPath)) {
        std::filesystem::create_directories(folderPath);
    }
    delete[] folderPath;

    size_t len = wcslen(selectedProcess);
    for (size_t i = 0; i < len; i++) {
        if (iswspace(selectedProcess[i])) {
            selectedProcess[i] = L'\0';
        }
    }

    char utf8Proc[MAX_PATH + 1] = { 0 };
    char utf8Dll[MAX_PATH + 1] = { 0 };
    wcstombs_s(nullptr, utf8Proc, selectedProcess, MAX_PATH);
    wcstombs_s(nullptr, utf8Dll, selectedFilePath, MAX_PATH);

    std::ofstream f(absPath, std::ios::trunc);
    if (!f.is_open()) {
        return 2;
    }

    f << "{\n";
    f << "\t\"lastProcessName\": \"" << utf8Proc << "\",\n";
    f << "\t\"lastDLLPath\": \"" << utf8Dll << "\"\n";
    f << "}";
    f.close();

    return 0;
}


void ReadConfig(wchar_t* absPath, wchar_t* procName, wchar_t* dllPath, size_t pNLength, size_t dPLength) {
    wchar_t* folderPath = new wchar_t[wcslen(absPath) + 1];
    wcscpy_s(folderPath, wcslen(absPath) + 1, absPath);
    wchar_t* lastSlash = wcsrchr(folderPath, L'\\');
    if (lastSlash != nullptr) {
        *lastSlash = L'\0';
    }
    std::wcout << folderPath << std::endl;
    std::wcout << absPath << std::endl;

    if (!std::filesystem::exists(folderPath)) {
        std::filesystem::create_directories(folderPath);
    }

    delete[] folderPath;

    if (!std::filesystem::exists(absPath)) {
        std::ofstream f(absPath);
        f << "{\n\t\"lastProcessName\": \"\",\n\t\"lastDLLPath\": \"\"\n}";
    }

    if (std::filesystem::exists(absPath)) {
        std::tuple<wchar_t*, wchar_t*> data;
        std::ifstream f(absPath);
        std::string s_output;
        memset(procName, 0, pNLength * sizeof(wchar_t));
        memset(dllPath, 0, dPLength * sizeof(wchar_t));

        if (f.is_open()) {
            std::string tempOut;
            while (std::getline(f, tempOut)) {
                size_t len = tempOut.length() + 1;
                wchar_t* w_output = new wchar_t[len];

                size_t converted = 0;
                mbstowcs_s(&converted, w_output, len, tempOut.c_str(), _TRUNCATE);
                const wchar_t* lpn = wcsstr(w_output, L"lastProcessName");
                if (lpn) {
                    const wchar_t* colon = wcschr(lpn, L':');
                    if (colon) {
                        bool start = false;
                        size_t counter = 0;
                        for (size_t i = 0; i < wcslen(colon); i++) {
                            if (counter > pNLength) break;
                            if (start && colon[i] == L'"') break;
                            if (!start && colon[i] == L'"') start = true;
                            if (start && colon[i] != L'"') {
                                procName[counter++] = colon[i];
                            }
                        }
                        procName[counter] = L'\0';

                    }
                    std::cout << std::endl;
                }
                const wchar_t* ldp = wcsstr(w_output, L"lastDLLPath");
                if (ldp) {
                    const wchar_t* colon = wcschr(ldp, L':');
                    if (colon) {
                        bool start = false;
                        size_t counter = 0;
                        for (size_t i = 0; i < wcslen(colon); i++) {
                            if (counter > dPLength) break;
                            if (start && colon[i] == L'"') break;
                            if (!start && colon[i] == L'"') start = true;
                            if (start && colon[i] != L'"') {
                                dllPath[counter++] = colon[i];
                            }
                        }
                        dllPath[counter] = L'\0';
                    }
                }
                delete[] w_output;
            }
        }
    }
}

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

LRESULT CALLBACK KeyboardHook(int nCode, WPARAM wParam, LPARAM lParam) {
    if (wParam == WM_KEYDOWN) {
        KBDLLHOOKSTRUCT* keyPtr = reinterpret_cast<KBDLLHOOKSTRUCT*>(lParam);
        DWORD vkCode = keyPtr->vkCode;
        if (vkCode == VK_INSERT) {
            consoleSwitch ? ShowWindow(GetConsoleWindow(), SW_HIDE) : ShowWindow(GetConsoleWindow(), SW_SHOW);
            consoleSwitch = !consoleSwitch;
        }
    }
    return CallNextHookEx(g_hHook, nCode, wParam, lParam);
}

DWORD FetchProcesses() {
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

LRESULT CALLBACK EditBoxProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
    case WM_LBUTTONDOWN:
    case WM_LBUTTONDBLCLK:
    case WM_RBUTTONDOWN:
    case WM_RBUTTONDBLCLK:
    case WM_MBUTTONDOWN:
    case WM_SETFOCUS:
    case WM_MOUSEACTIVATE:
    case WM_KEYDOWN:
    case WM_CHAR:
    case WM_PASTE:
        return 0;
    }
    return CallWindowProc(originalEditProc, hwnd, msg, wParam, lParam);
}

LRESULT CALLBACK WindowProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam) {

    switch (uMsg)
    {
    case WM_CREATE:{
        HDC hdc = GetDC(hwnd);

        RECT rect;
        GetWindowRect(hwnd, &rect);
        HWND hButton = CreateWindow(L"BUTTON", L"Select DLL", WS_VISIBLE | WS_CHILD, (rect.right - rect.left) / 2 - 100, 100, 100, 30, hwnd, (HMENU)SELECT_DLL_BUTTON, GetModuleHandle(NULL), NULL);
        HWND injectButton = CreateWindow(L"BUTTON", L"Inject", WS_VISIBLE | WS_CHILD, (rect.right - rect.left) / 2 - 100, 300, 200, 30, hwnd, (HMENU)INJECT_BUTTON, GetModuleHandle(NULL), NULL);
        pathEdit = CreateWindow(L"EDIT", L"", WS_VISIBLE | WS_CHILD | WS_BORDER, (rect.right - rect.left) / 2 - 100, 160, 200, 25, hwnd, NULL, GetModuleHandle(NULL), NULL);
        hComboBox = CreateWindowEx(0, L"COMBOBOX", NULL, CBS_DROPDOWNLIST | WS_CHILD | WS_VISIBLE | WS_VSCROLL, (rect.right - rect.left) / 2 - 100, 40, 200, 300, hwnd, NULL, GetModuleHandle(NULL), NULL);

        originalEditProc = (WNDPROC)SetWindowLongPtr(pathEdit, GWLP_WNDPROC, (LONG_PTR)EditBoxProc);
        SendMessage(hComboBox, WM_SETFONT, (WPARAM)hfont, TRUE);
        SendMessage(hButton, WM_SETFONT, (WPARAM)hfont, TRUE);
        SendMessage(pathEdit, WM_SETFONT, (WPARAM)hfont, TRUE);
        SendMessage(injectButton, WM_SETFONT, (WPARAM)b_hfont, TRUE);
        
        for (auto& process : processes) {
            std::tuple<const char*, int> processData = process.second;
            const char* procName = std::get<0>(processData);
            int procId = std::get<1>(processData);

            char option[260];
            std::snprintf(option, sizeof(option), "%s (%d)", procName, procId);
            wchar_t woption[300];
            size_t converted = 0;
            mbstowcs_s(&converted, woption, option, _TRUNCATE);

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

        RECT dllPathLabel = {
            (rect.right - rect.left) / 2 - 90,
            260,
            50 + 200,
            20 + 20
        };

        DrawTextA(hdc, "Current DLL basename:", -1, &dllPathLabel, DT_SINGLELINE | DT_LEFT | DT_VCENTER);

        EndPaint(hwnd, &ps);
        return 0;
    }
    case WM_COMMAND:
        if (LOWORD(wParam) == 1) {
            OPENFILENAME ofn;
            ZeroMemory(&ofn, sizeof(ofn));
            ofn.lStructSize = sizeof(ofn);
            ofn.hwndOwner = hwnd;
            ofn.lpstrFile = selectedFilePath;
            ofn.lpstrFile[0] = '\0';
            ofn.nMaxFile = sizeof(selectedFilePath) / sizeof(wchar_t);
            ofn.lpstrFilter = L"DLL Files (.dll)\0*.dll\0All Files\0*.*\0";
            ofn.nFilterIndex = 1;
            ofn.Flags = OFN_PATHMUSTEXIST | OFN_FILEMUSTEXIST | OFN_NOCHANGEDIR;

            if (GetOpenFileName(&ofn) == TRUE) {
                std::wcout << selectedFilePath << std::endl;

                WriteConfig(appDataPath);

                wchar_t basename[260] = {0};
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
        else if (LOWORD(wParam) == 2) {
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

                WriteConfig(appDataPath);

                const wchar_t* openParen = wcsrchr(processData, L'(');
                if (openParen) {
                    int procID = _wtoi(openParen + 1);
                    std::cout << procID << std::endl;

                    size_t len = wcslen(selectedFilePath) + 1;
                    char* ch_path = new char[len];
                    size_t convChars = 0;
                    wcstombs_s(&convChars, ch_path, len, selectedFilePath, _TRUNCATE);
                    if (!InjectDLL((DWORD)procID, ch_path)) {
                        MessageBox(p_hwnd, L"Failed to inject", L"Error", MB_ICONERROR);
                    }
                    else {
                        MessageBox(p_hwnd, L"Successfully injected!", L"Success", MB_OK);
                    }
                }
            }
        }
        return 0;
    case WM_DESTROY: {
        if (g_hHook) UnhookWindowsHookEx(g_hHook);
        g_hHook = nullptr;
        if (b_hfont) DeleteObject(b_hfont);
        if (hfont) DeleteObject(hfont);
        FreeConsole();

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
    ShowWindow(GetConsoleWindow(), SW_HIDE);

    memset(dllFileName, 0, (MAX_PATH + 1) * sizeof(wchar_t));

    wchar_t username[UNLEN + 1];
    DWORD size = UNLEN + 1;
    GetUserNameW(username, &size);
    std::wcout << username << std::endl;
    const wchar_t* prePath = L"C:\\Users\\";
    const wchar_t* trailPath = L"\\AppData\\Roaming\\Injector\\config.json";
    wcscpy_s(appDataPath, MAX_PATH + 1, prePath);
    wcscat_s(appDataPath, MAX_PATH + 1, username);
    wcscat_s(appDataPath, MAX_PATH + 1, trailPath);

    wchar_t w_procName[MAX_PATH + 1];
    wchar_t w_dllPath[MAX_PATH + 1];
    ReadConfig(appDataPath, w_procName, w_dllPath, MAX_PATH + 1, MAX_PATH + 1);

    std::wcout << "procname: " << w_procName << std::endl;
    std::wcout << "dllpath: " << w_dllPath << std::endl;

    g_hHook = SetWindowsHookExW(WH_KEYBOARD_LL, KeyboardHook, NULL, 0);
    if (!g_hHook) MessageBox(p_hwnd, L"Failed to install keyboard hook!\nBinds wont work", L"Error", MB_ICONERROR);

    HWND hwnd = CreateWindowEx(0, L"InjectorWindowClass", L"Injector", WS_SYSMENU | WS_VISIBLE, GetSystemMetrics(SM_CXSCREEN) / 2, GetSystemMetrics(SM_CYSCREEN) / 2, 300, 400, nullptr, nullptr, hInstance, nullptr);
    if (!hwnd) { MessageBox(p_hwnd, L"Failed to create window!\nSomething may be blocking it!", L"Error", MB_ICONERROR);  return 1; }
    ShowWindow(hwnd, nCmdShow);

    p_hwnd = hwnd;

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

    for (auto& p : processes) {
        char* procNamePtr = const_cast<char*>(std::get<0>(p.second));
        delete[] procNamePtr;
    }
    processes.clear();

    MSG msg = {};
    while (GetMessage(&msg, nullptr, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }
    return 0;
}