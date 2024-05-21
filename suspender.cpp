#include <Windows.h>
#include <TlHelp32.h>
#include <iostream>
#include <string>

// Function to enable SE_DEBUG_NAME privilege
BOOL EnableDebugPrivilege() {
    HANDLE hToken;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
        std::cerr << "Error: OpenProcessToken failed." << std::endl;
        return FALSE;
    }

    TOKEN_PRIVILEGES tp;
    tp.PrivilegeCount = 1;
    if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &tp.Privileges[0].Luid)) {
        std::cerr << "Error: LookupPrivilegeValue failed." << std::endl;
        CloseHandle(hToken);
        return FALSE;
    }

    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), NULL, NULL)) {
        std::cerr << "Error: AdjustTokenPrivileges failed." << std::endl;
        CloseHandle(hToken);
        return FALSE;
    }

    CloseHandle(hToken);
    return TRUE;
}

// Function to suspend all threads in a process by its name
void SuspendProcessThreads(const std::wstring& processName) {
    HANDLE hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hProcessSnap == INVALID_HANDLE_VALUE) {
        std::cerr << "Error: CreateToolhelp32Snapshot failed." << std::endl;
        return;
    }

    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);

    if (!Process32First(hProcessSnap, &pe32)) {
        std::cerr << "Error: Process32First failed." << std::endl;
        CloseHandle(hProcessSnap);
        return;
    }

    do {
        if (_wcsicmp(pe32.szExeFile, processName.c_str()) == 0) {
            HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pe32.th32ProcessID);
            if (hProcess != NULL) {
                HANDLE hThreadSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
                if (hThreadSnap != INVALID_HANDLE_VALUE) {
                    THREADENTRY32 te32;
                    te32.dwSize = sizeof(THREADENTRY32);

                    if (Thread32First(hThreadSnap, &te32)) {
                        do {
                            if (te32.th32OwnerProcessID == pe32.th32ProcessID) {
                                HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, te32.th32ThreadID);
                                if (hThread != NULL) {
                                    SuspendThread(hThread);
                                    CloseHandle(hThread);
                                }
                            }
                        } while (Thread32Next(hThreadSnap, &te32));
                    }

                    CloseHandle(hThreadSnap);
                }

                CloseHandle(hProcess);
            }
        }
    } while (Process32Next(hProcessSnap, &pe32));

    CloseHandle(hProcessSnap);
}

int main() {
    if (!EnableDebugPrivilege()) {
        std::cerr << "Failed to enable debug privilege." << std::endl;
        return 1;
    }

    std::wstring processName = L"suspend_program.exe";  // Change the program name here to suspend.
    SuspendProcessThreads(processName);
    std::cout << "All threads in ", processName, " have been suspended.";
    return 0;
}
