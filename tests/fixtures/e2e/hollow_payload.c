#define WIN32_LEAN_AND_MEAN
#include <windows.h>

typedef LONG NTSTATUS;
__declspec(dllimport) NTSTATUS NTAPI NtTerminateProcess(HANDLE, NTSTATUS);

static DWORD parse_hold_ms(void)
{
    WCHAR value[32];
    DWORD length = GetEnvironmentVariableW(
        L"X64DBG_MCP_E2E_HOLLOW_HOLD_MS", value,
        (DWORD)(sizeof(value) / sizeof(value[0]))
    );
    DWORD result = 50;
    DWORD index;
    if (length == 0 || length >= (DWORD)(sizeof(value) / sizeof(value[0]))) {
        return result;
    }
    result = 0;
    for (index = 0; index < length; ++index) {
        if (value[index] < L'0' || value[index] > L'9') {
            return 50;
        }
        if (result > 30000 / 10) {
            return 30000;
        }
        result = result * 10 + (DWORD)(value[index] - L'0');
    }
    if (result > 30000) result = 30000;
    return result;
}

void WINAPI payload_entry(void)
{
    static const char marker[] =
        "HOLLOW_PAYLOAD_OK identity=payload imageExecuted=1 exit=42\r\n";
    HANDLE output = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD written = 0;
    if (output != NULL && output != INVALID_HANDLE_VALUE) {
        (void)WriteFile(output, marker, (DWORD)(sizeof(marker) - 1), &written, NULL);
    }
    {
        WCHAR break_value[4];
        DWORD break_length = GetEnvironmentVariableW(
            L"X64DBG_MCP_E2E_HOLLOW_BREAK", break_value,
            (DWORD)(sizeof(break_value) / sizeof(break_value[0]))
        );
        if (break_length == 1 && break_value[0] == L'1') {
            DebugBreak();
        }
    }
    Sleep(parse_hold_ms());
    (void)NtTerminateProcess((HANDLE)(LONG_PTR)-1, (NTSTATUS)42);
    for (;;) {
        /* NtTerminateProcess does not return on success. */
    }
}
