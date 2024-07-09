//Hi thanks for using simpleshell
//As you may notice ive makred some functions that may be dtc on some anticheats
//please note that the shellcode is in shellcode.h and you need to replace it with your shellcode and change the target if you want to do something
//compile x64/x86 (deppends on target and shellcode) release
#include <Windows.h>
#include <TlHelp32.h>
#include <iostream>
#include <string>
#include "shellcode.h"

int main() {
    std::wstring target = L"notepad.exe";
    DWORD pid = 0;
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32 pe32;
        pe32.dwSize = sizeof(PROCESSENTRY32);
        if (Process32First(hSnapshot, &pe32)) {
            do {
                if (target.compare(pe32.szExeFile) == 0) {
                    pid = pe32.th32ProcessID;
                    break;
                }
            } while (Process32Next(hSnapshot, &pe32));
        }
        CloseHandle(hSnapshot);
    }

    if (pid == 0) {
        std::cout << "Failed to get proc please oppen target or change the target!";
        return 1;
    }
    // ud ?
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (hProcess == NULL) {
        std::cerr << "Failed to open proc Error : " << GetLastError() << std::endl;
        return 1;
    }
    int size = sizeof(simga::Shellcode);
    //this prob wont work on good ac games
    LPVOID remote_buffer = VirtualAllocEx(hProcess, NULL, size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (remote_buffer == NULL) {
        std::cerr << "Failed to alloc memory Error : " << GetLastError() << std::endl;
        CloseHandle(hProcess);
        return 1;
    }
    //if your game has a ac pls replace this
    if (!WriteProcessMemory(hProcess, remote_buffer, simga::Shellcode, size, NULL)) {
        std::cerr << "Failed to write shellcode Error : " << GetLastError() << std::endl;
        VirtualFreeEx(hProcess, remote_buffer, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return 1;
    }
    //if your game has a mid ac pls replace
    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)remote_buffer, NULL, 0, NULL);
    if (hThread == NULL) {
        std::cerr << "Failed to create remote thread. Error code: " << GetLastError() << std::endl;
        VirtualFreeEx(hProcess, remote_buffer, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return 1;
    }

    WaitForSingleObject(hThread, INFINITE);

    CloseHandle(hThread);
    VirtualFreeEx(hProcess, remote_buffer, 0, MEM_RELEASE);
    CloseHandle(hProcess);

    return 0;
}
