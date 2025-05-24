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
#include "headers/injector.h"

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
HWND hComboBox = nullptr;

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
            injector::SelectDLL(hwnd, selectedFilePath, appDataPath, selectedProcess, pathEdit);
        }
        else if (LOWORD(wParam) == 2) {
            injector::Inject(hComboBox, selectedProcess, appDataPath, selectedFilePath, injector::InjectDLL, p_hwnd);
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
    injector::CreateConsole();
    injector::FetchProcesses(processes);
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
    injector::ReadConfig(appDataPath, w_procName, w_dllPath, MAX_PATH + 1, MAX_PATH + 1);

    std::wcout << "procname: " << w_procName << std::endl;
    std::wcout << "dllpath: " << w_dllPath << std::endl;

    g_hHook = SetWindowsHookExW(WH_KEYBOARD_LL, injector::KeyboardHook, NULL, 0);
    if (!g_hHook) MessageBox(p_hwnd, L"Failed to install keyboard hook!\nBinds wont work", L"Error", MB_ICONERROR);

    HWND hwnd = CreateWindowEx(0, L"InjectorWindowClass", L"Injector", WS_SYSMENU | WS_VISIBLE, GetSystemMetrics(SM_CXSCREEN) / 2, GetSystemMetrics(SM_CYSCREEN) / 2, 300, 400, nullptr, nullptr, hInstance, nullptr);
    if (!hwnd) { MessageBox(p_hwnd, L"Failed to create window!\nSomething may be blocking it!", L"Error", MB_ICONERROR);  return 1; }
    ShowWindow(hwnd, nCmdShow);

    p_hwnd = hwnd;

    injector::FindLastDLL(w_dllPath, selectedFilePath, pathEdit, dllFileName);
    injector::FindProcInList(w_procName, hComboBox, p_hwnd);

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