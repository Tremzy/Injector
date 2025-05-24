#include "config.h"
#include <windows.h>
#include <iostream>
#include <string>
#include <filesystem>
#include <fstream>

namespace injector {
    int WriteConfig(wchar_t* absPath, wchar_t* selectedFilePath, wchar_t* selectedProcess) {
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
}