#include <iostream>
#include <string>
#include <Windows.h>
#include <TlHelp32.h>
#include "color.hpp"
#include <thread>
DWORD GetProcessIDFromProcessName(const std::wstring& processName) {
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        return 0; // Return 0 if unable to get the snapshot
    }

    PROCESSENTRY32 processEntry;
    processEntry.dwSize = sizeof(PROCESSENTRY32);

    if (Process32First(snapshot, &processEntry)) {
        do {
            if (_wcsicmp(processEntry.szExeFile, processName.c_str()) == 0) {
                CloseHandle(snapshot);
                return processEntry.th32ProcessID;
            }
        } while (Process32Next(snapshot, &processEntry));
    }

    CloseHandle(snapshot);
    return 0; // Return 0 if the process name was not found
}

int main() {
    const char* dllPath = "C:\\Users\\janko\\source\\repos\\Injector\\x64\\Debug\\dll.dll";
    std::wstring processName = L"RobloxPlayerBeta.exe";
    std::cout << "Looking for Roblox\n";
    std::this_thread::sleep_for(std::chrono::milliseconds(800));
    DWORD pid = GetProcessIDFromProcessName(processName);
    if (pid)
    {
        std::cout << dye::green("Found RobloxPlayerBeta.exe") << std::endl;
    }
    else
    {
        std::cout << dye::red("Couldn't found RobloxPlayerBeta.exe") << std::endl;
        std::cout << "Trying again in 5 seconds.\n";
        std::this_thread::sleep_for(std::chrono::seconds(5));
        main();
    }
    std::cout << "Obtaining PID\n";
    std::this_thread::sleep_for(std::chrono::milliseconds(800));
    if (pid)
    {
        std::cout << dye::green("Success! PID: ") << dye::green(pid) << "\n";

    }
    else
    {
        std::cout << dye::red("Error obtainging PID!\n");
    }
    
    HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, NULL, pid);
    if (hProc && hProc != INVALID_HANDLE_VALUE)
    {
        std::cout << dye::green("Success! Roblox Handled.\n");
        std::cout << "Trying to allocate memory\n";
        std::this_thread::sleep_for(std::chrono::milliseconds(800));
        void* alloc = VirtualAllocEx(hProc, 0, MAX_PATH, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
        if (alloc)
        {
            std::cout << dye::green("Success! Memory Allocated.\n");
            WriteProcessMemory(hProc, alloc, dllPath, strlen(dllPath + 1), 0);
        }
        else
        {
            std::cout << dye::red("Error allocating memory\n");
        }
        
        HANDLE hThread = CreateRemoteThread(hProc, NULL, NULL, (LPTHREAD_START_ROUTINE)LoadLibraryA, alloc, NULL, NULL);
        if (hThread)
        {
            std::cout << dye::green("Success! Injected!\n");
            std::this_thread::sleep_for(std::chrono::milliseconds(800));
            CloseHandle(hThread);
        }
        else
        {
            std::cout << dye::red("Error injecting\n");
            main();
        }
        if (hProc)
        {
            VirtualFreeEx(hProc, 0, MAX_PATH, MEM_RELEASE | MEM_FREE);
            CloseHandle(hProc);
            
        }

    }
    else
    {
        std::cout << dye::red("Error handling Roblox!\n");
        return 1;
    }


    return 0;
}
