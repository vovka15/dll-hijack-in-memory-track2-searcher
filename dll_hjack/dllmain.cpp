// dllmain.cpp : Defines the entry point for the DLL application.
#include "pch.h"
#include <iostream>
#include <fstream>
#include <regex>
#include <Windows.h>
#include <TlHelp32.h>
#include <psapi.h>
#include <tchar.h>
#include <thread>



std::string currentDateTime() {
    std::string current_time;
    SYSTEMTIME st;
    GetSystemTime(&st);
    char buffer[256];

    sprintf_s(buffer, sizeof(buffer),
        "%d-%02d-%02d %02d:%02d:%02d.%03d",
        st.wYear,
        st.wMonth,
        st.wDay,
        st.wHour,
        st.wMinute,
        st.wSecond,
        st.wMilliseconds);

    current_time = buffer;
    return current_time;
}

int writeFile(std::string str)
{
    std::string logFile;
    logFile = "test.log";

    std::ofstream myfile;
    myfile.open(logFile, std::ofstream::app);
    myfile << currentDateTime() << " - " << str << "\r\n";
    myfile.close();
    return 0;
}

HMODULE GetModule(DWORD processID, HANDLE hProcess)
{
    HMODULE hMods[1024];
    DWORD cbNeeded;
    unsigned int i;
    TCHAR pN[] = _T("C:\\PATH\\TO\\FILE");

    // Get a list of all the modules in this process.

    if (EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded))
    {
        for (i = 0; i < (cbNeeded / sizeof(HMODULE)); i++)
        {
            TCHAR szModName[MAX_PATH];

            // Get the full path to the module's file.

            if (GetModuleFileNameEx(hProcess, hMods[i], szModName,
                sizeof(szModName) / sizeof(TCHAR)))
            {
                if (_tcscmp(pN, szModName) == 0)
                {
                    // Print the module name and handle value.
                    return hMods[i];
                }
            }
        }
    }
    writeFile("module not found");
    return nullptr;
}

bool isProcessExist(HANDLE pHandle)
{
    DWORD exitCode = 0;
    bool check_process = GetExitCodeProcess(pHandle, &exitCode);
    if (check_process) {
        if (exitCode != STILL_ACTIVE) {
            return false;
        }
        return true;
    }
    return false;
}

bool find_data() 
{  
    // wait process to load
    Sleep(15000);
    DWORD procId = GetCurrentProcessId();
    HANDLE processHandle = OpenProcess(PROCESS_ALL_ACCESS, TRUE, procId);

    if (processHandle == NULL)
    {
        int error = GetLastError();
        writeFile("open proces error. System error - " + std::to_string(error));
        return false;
    }

    writeFile("got Handle");

    while (!GetModule(procId, processHandle)) {
        writeFile("no baseaddr found. Waiting 1 min and searching again");
        Sleep(60000);
    }
    HMODULE Module = GetModule(procId, processHandle);
    DWORD BaseAddr = (DWORD)Module;
    
    
    writeFile("got base address");

    char buffer[256];
    std::string current_track2 = "0000000000000000D23092011365879200000";
    std::string found_track2;
    bool found_flag = 0;

    while (isProcessExist(processHandle)) {
        writeFile("starting to search");
        int last_error = 0;
        int* start = (int*)BaseAddr;
        int* end = start + (0xAF000 / sizeof(int));
        while (start < end) {
            int res = ReadProcessMemory(processHandle, (LPVOID)start, &buffer, sizeof(buffer), 0);
            if (res == 0)
            {
                if (last_error != GetLastError())
                {
                    last_error = GetLastError();
                }
            }
            else {
                std::regex track2("[0-9]{16}D[0-9]{20}");
                std::string tmp_str;
                std::smatch match;

                tmp_str = buffer;


                if (regex_search(tmp_str, match, track2)) {
                    found_track2 = match.str(0);
                    if (current_track2.compare(found_track2) != 0)
                    {
                        current_track2 = found_track2;
                        found_flag = 1;
                    }
                    else {
                        continue;
                    }
                    writeFile(current_track2);
                }
            }
            start += 64;
        }
        if (last_error)
        {
            writeFile("read memory error. System error - " + std::to_string(last_error));
            last_error = 0;
        }
        if (found_flag == 0) {
            writeFile("nothing found");
        }
        found_flag = 0;
        // sleeping
        Sleep(15000);
    }
    CloseHandle(processHandle);
    return true;
}

extern "C" BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
    {
        writeFile("injected");
        std::thread t1(find_data);
        t1.detach();
    }
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}
