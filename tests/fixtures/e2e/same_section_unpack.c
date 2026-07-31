#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <intrin.h>

#pragma code_seg(push, ".packed$a")

static void write_marker(const char *text, DWORD length) {
    DWORD written = 0;
    HANDLE output = GetStdHandle(STD_OUTPUT_HANDLE);
    if (output != NULL && output != INVALID_HANDLE_VALUE) {
        WriteFile(output, text, length, &written, NULL);
    }
}

__declspec(noinline)
static int payload_placeholder(void) {
    volatile LONG value = 7;
    value = (value * 9) ^ 0x1357;
    value = (value + 0x2468) ^ 0x1357;
    return (int)(value & 0x7FFFFFFF);
}

#if defined(_WIN64)
static const unsigned char restored_payload[32] = {
    0x55, 0x48, 0x89, 0xE5, 0xB8, 0x2A, 0x00, 0x00,
    0x00, 0x5D, 0xC3, 0x90, 0x90, 0x90, 0x90, 0x90,
    0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
    0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90
};
#else
static const unsigned char restored_payload[32] = {
    0x55, 0x8B, 0xEC, 0xB8, 0x2A, 0x00, 0x00, 0x00,
    0x5D, 0xC3, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
    0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
    0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90
};
#endif

void WINAPI packer_entry(void) {
    DWORD old_protect = 0;
    DWORD index;
    WCHAR break_value[4];
    DWORD break_length;
    int result;
    static const char marker[] =
        "SAME_SECTION_OK result=42 runtimeMutation=1\n";
    static const char failure[] =
        "SAME_SECTION_FAIL resultMismatch=1\n";

    if (!VirtualProtect(
            (void *)(ULONG_PTR)payload_placeholder,
            sizeof(restored_payload),
            PAGE_EXECUTE_READWRITE,
            &old_protect)) {
        ExitProcess(91);
    }
    for (index = 0; index < sizeof(restored_payload); ++index) {
        ((volatile unsigned char *)(ULONG_PTR)payload_placeholder)[index] =
            restored_payload[index];
    }
    FlushInstructionCache(
        GetCurrentProcess(),
        (const void *)(ULONG_PTR)payload_placeholder,
        sizeof(restored_payload)
    );

    break_length = GetEnvironmentVariableW(
        L"X64DBG_MCP_E2E_SAME_SECTION_BREAK",
        break_value,
        (DWORD)(sizeof(break_value) / sizeof(break_value[0]))
    );
    if (break_length == 1 && break_value[0] == L'1') {
        __debugbreak();
    }

    result = payload_placeholder();
    if (result == 42) {
        write_marker(marker, (DWORD)(sizeof(marker) - 1));
        ExitProcess(0);
    }
    write_marker(failure, (DWORD)(sizeof(failure) - 1));
    ExitProcess(92);
}

#pragma code_seg(pop)
