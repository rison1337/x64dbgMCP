#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <wchar.h>

int wmain(int argc, wchar_t **argv)
{
    if (argc == 3 && wcscmp(argv[1], L"--ready-handle") == 0) {
        ULONG_PTR raw = (ULONG_PTR)_wcstoui64(argv[2], NULL, 0);
        HANDLE ready = (HANDLE)raw;
        if (ready == NULL || !SetEvent(ready)) {
            return 71;
        }
        printf("HOLLOW_HOST_READY pid=%lu loaderInitialized=1\n", GetCurrentProcessId());
        fflush(stdout);
        Sleep(30000);
        return 72;
    }
    printf("HOLLOW_HOST_OK pid=%lu imageExecuted=1\n", GetCurrentProcessId());
    fflush(stdout);
    return 0;
}
