#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>

typedef int (WINAPI *GetSystemMetricsFn)(int);

static HMODULE g_user32;

__declspec(dllexport) int dynamic_api_prepare(void)
{
    g_user32 = LoadLibraryW(L"user32.dll");
    if (g_user32 == NULL) {
        fprintf(stderr, "DYNAMIC_API_FAIL phase=LoadLibraryW error=%lu\n",
                GetLastError());
        return 71;
    }
    return 0;
}

__declspec(dllexport) int dynamic_api_target(void)
{
    FARPROC resolved;
    int width;
    resolved = GetProcAddress(g_user32, "GetSystemMetrics");
    if (resolved == NULL) {
        fprintf(stderr, "DYNAMIC_API_FAIL phase=GetProcAddress error=%lu\n",
                GetLastError());
        FreeLibrary(g_user32);
        return 72;
    }
    width = ((GetSystemMetricsFn)resolved)(SM_CXSCREEN);
    printf(
        "DYNAMIC_API_OK module=1 resolver=1 call=1 widthPositive=%d\n",
        width > 0 ? 1 : 0);
    fflush(stdout);
    FreeLibrary(g_user32);
    g_user32 = NULL;
    return width > 0 ? 0 : 73;
}

int wmain(void)
{
    if (dynamic_api_prepare() != 0) {
        return 71;
    }
    return dynamic_api_target();
}
