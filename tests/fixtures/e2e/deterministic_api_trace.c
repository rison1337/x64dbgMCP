#define UNICODE
#define _UNICODE
#include <windows.h>
#include <stdio.h>
#include <wchar.h>

__declspec(dllexport) __declspec(noinline)
DWORD fixture_api_roundtrip(void)
{
    wchar_t environment[64] = {0};
    HANDLE event_handle = NULL;
    DWORD initial_wait = WAIT_FAILED;
    DWORD signaled_wait = WAIT_FAILED;
    DWORD environment_length = 0;

    event_handle = CreateEventW(NULL, TRUE, FALSE, NULL);
    printf("API_EVENT seq=1 api=CreateEventW success=%d handle=%p\n", event_handle != NULL, event_handle);
    if (event_handle == NULL) {
        return 10;
    }

    initial_wait = WaitForSingleObject(event_handle, 0);
    printf("API_EVENT seq=2 api=WaitForSingleObject timeout=0 return=0x%08lX\n", initial_wait);
    if (initial_wait != WAIT_TIMEOUT) {
        CloseHandle(event_handle);
        return 11;
    }

    if (!SetEvent(event_handle)) {
        CloseHandle(event_handle);
        return 12;
    }
    printf("API_EVENT seq=3 api=SetEvent return=1\n");

    signaled_wait = WaitForSingleObject(event_handle, 0);
    printf("API_EVENT seq=4 api=WaitForSingleObject timeout=0 return=0x%08lX\n", signaled_wait);
    if (signaled_wait != WAIT_OBJECT_0) {
        CloseHandle(event_handle);
        return 13;
    }

    environment_length = GetEnvironmentVariableW(
        L"X64DBG_MCP_E2E_API",
        environment,
        (DWORD)(sizeof(environment) / sizeof(environment[0])));
    printf("API_EVENT seq=5 api=GetEnvironmentVariableW return=%lu\n", environment_length);
    if (environment_length != 10 || wcscmp(environment, L"trace-ok-7") != 0) {
        CloseHandle(event_handle);
        return 14;
    }

    if (!CloseHandle(event_handle)) {
        return 15;
    }
    printf("API_EVENT seq=6 api=CloseHandle return=1\n");
    fflush(stdout);
    return 0;
}

int wmain(void)
{
    DWORD result = fixture_api_roundtrip();
    if (result == 0) {
        printf("API_TRACE_OK calls=6 result=0\n");
        fflush(stdout);
    }
    return (int)result;
}
