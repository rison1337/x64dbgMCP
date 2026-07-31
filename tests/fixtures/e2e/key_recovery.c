#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <wchar.h>

static int run_direct(const wchar_t *input)
{
    char narrow[128];
    const char expected[] = "polished-key-42";
    int converted = WideCharToMultiByte(
        CP_UTF8, 0, input, -1, narrow, (int)sizeof(narrow), NULL, NULL);
    if (converted <= 0) {
        return 2;
    }
    int result = lstrcmpA(narrow, expected);
    printf("KEY_RECOVERY_RESULT mode=direct equal=%d\n", result == 0);
    if (result == 0) {
        printf("KEY_RECOVERY_OK mode=direct\n");
        return 0;
    }
    return 1;
}

static int run_xor(const wchar_t *input)
{
    enum { KEY = 0x23, EXPECTED_LENGTH = 9 };
    static const unsigned char encoded_expected[EXPECTED_LENGTH + 1] = {
        0x7B, 0x4C, 0x51, 0x68, 0x46, 0x5A, 0x0E, 0x14, 0x02, 0x00
    };
    char narrow[128];
    unsigned char encoded_input[128];
    int converted = WideCharToMultiByte(
        CP_UTF8, 0, input, -1, narrow, (int)sizeof(narrow), NULL, NULL);
    if (converted <= 0) {
        return 2;
    }
    size_t length = strlen(narrow);
    if (length >= sizeof(encoded_input)) {
        return 2;
    }
    for (size_t index = 0; index < length; ++index) {
        encoded_input[index] = (unsigned char)narrow[index] ^ KEY;
    }
    encoded_input[length] = 0;
    int result = lstrcmpA(
        (const char *)encoded_input,
        (const char *)encoded_expected);
    printf("KEY_RECOVERY_RESULT mode=xor equal=%d length=%zu\n",
           result == 0, length);
    if (result == 0) {
        printf("KEY_RECOVERY_OK mode=xor\n");
        return 0;
    }
    return 1;
}

static int run_wide(const wchar_t *input)
{
    const wchar_t expected[] = L"wide-key-42";
    int result = lstrcmpW(input, expected);
    printf("KEY_RECOVERY_RESULT mode=wide equal=%d\n", result == 0);
    if (result == 0) {
        printf("KEY_RECOVERY_OK mode=wide\n");
        return 0;
    }
    return 1;
}

int wmain(int argc, wchar_t **argv)
{
    if (argc != 3) {
        fprintf(stderr, "usage: key_recovery.exe direct|xor|wide candidate\n");
        return 2;
    }
    if (wcscmp(argv[1], L"direct") == 0) {
        return run_direct(argv[2]);
    }
    if (wcscmp(argv[1], L"xor") == 0) {
        return run_xor(argv[2]);
    }
    if (wcscmp(argv[1], L"wide") == 0) {
        return run_wide(argv[2]);
    }
    fprintf(stderr, "unknown mode\n");
    return 2;
}
