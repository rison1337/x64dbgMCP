#define UNICODE
#define _UNICODE
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>

#define ARRAY_COUNT(value) (sizeof(value) / sizeof((value)[0]))
#define STREAM_INPUT_LIMIT (64ui64 * 1024ui64 * 1024ui64)
#define BURST_CHUNK_SIZE 8192u
#define BURST_CHUNK_COUNT 256u
#define FNV1A64_OFFSET 14695981039346656037ui64
#define FNV1A64_PRIME 1099511628211ui64

typedef enum environment_state {
    ENVIRONMENT_INVALID = 0,
    ENVIRONMENT_ABSENT,
    ENVIRONMENT_EMPTY,
    ENVIRONMENT_VALUE
} environment_state;

static int fail_contract(const char *reason, int code)
{
    DWORD win32_error = GetLastError();

    fprintf(
        stderr,
        "LAUNCH_CONTRACT_FAIL reason=%s code=%d win32=%lu\n",
        reason,
        code,
        win32_error);
    fflush(stderr);
    return code;
}

static BOOL write_all(HANDLE handle, const void *buffer, DWORD size)
{
    const unsigned char *cursor = (const unsigned char *)buffer;
    DWORD remaining = size;

    if (handle == NULL || handle == INVALID_HANDLE_VALUE) {
        SetLastError(ERROR_INVALID_HANDLE);
        return FALSE;
    }
    while (remaining != 0) {
        DWORD written = 0;

        if (!WriteFile(handle, cursor, remaining, &written, NULL) || written == 0) {
            return FALSE;
        }
        cursor += written;
        remaining -= written;
    }
    return TRUE;
}

static unsigned __int64 fnv1a64_update(
    unsigned __int64 hash,
    const unsigned char *data,
    DWORD size)
{
    DWORD index = 0;

    for (index = 0; index < size; ++index) {
        hash ^= data[index];
        hash *= FNV1A64_PRIME;
    }
    return hash;
}

static unsigned long crc32_update(
    unsigned long crc,
    const unsigned char *data,
    DWORD size)
{
    DWORD index = 0;

    while (index < size) {
        unsigned int bit = 0;

        crc ^= data[index++];
        for (bit = 0; bit < 8; ++bit) {
            const unsigned long mask = (unsigned long)-(long)(crc & 1u);

            crc = (crc >> 1) ^ (0xEDB88320ul & mask);
        }
    }
    return crc;
}

static environment_state read_environment_value(
    const wchar_t *name,
    wchar_t *value,
    DWORD capacity,
    DWORD *length)
{
    DWORD result = 0;
    DWORD error = ERROR_SUCCESS;

    if (name == NULL || *name == L'\0' || value == NULL || capacity == 0 || length == NULL) {
        SetLastError(ERROR_INVALID_PARAMETER);
        return ENVIRONMENT_INVALID;
    }
    value[0] = L'\0';
    SetLastError(ERROR_SUCCESS);
    result = GetEnvironmentVariableW(name, value, capacity);
    error = GetLastError();
    *length = result;
    if (result >= capacity) {
        SetLastError(ERROR_INSUFFICIENT_BUFFER);
        return ENVIRONMENT_INVALID;
    }
    if (result != 0) {
        return ENVIRONMENT_VALUE;
    }
    if (error == ERROR_ENVVAR_NOT_FOUND) {
        return ENVIRONMENT_ABSENT;
    }
    if (error == ERROR_SUCCESS) {
        return ENVIRONMENT_EMPTY;
    }
    SetLastError(error);
    return ENVIRONMENT_INVALID;
}

static BOOL check_environment_exact(const wchar_t *name, const wchar_t *expected)
{
    wchar_t value[512] = {0};
    DWORD length = 0;
    environment_state state = read_environment_value(
        name,
        value,
        (DWORD)ARRAY_COUNT(value),
        &length);

    (void)length;
    return state == ENVIRONMENT_VALUE && wcscmp(value, expected) == 0;
}

static BOOL check_environment_state(
    const wchar_t *name,
    environment_state expected)
{
    wchar_t value[512] = {0};
    DWORD length = 0;
    environment_state state = read_environment_value(
        name,
        value,
        (DWORD)ARRAY_COUNT(value),
        &length);

    (void)length;
    return state == expected;
}

static BOOL check_working_directory(void)
{
    wchar_t current_directory[32768] = {0};
    const wchar_t *leaf = NULL;
    HANDLE marker = INVALID_HANDLE_VALUE;

    if (GetCurrentDirectoryW((DWORD)ARRAY_COUNT(current_directory), current_directory) == 0) {
        return FALSE;
    }
    leaf = wcsrchr(current_directory, L'\\');
    leaf = leaf == NULL ? current_directory : leaf + 1;
    if (wcscmp(leaf, L"launch_тест") != 0) {
        SetLastError(ERROR_BAD_PATHNAME);
        return FALSE;
    }
    marker = CreateFileW(
        L"cwd_marker.txt",
        GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL);
    if (marker == INVALID_HANDLE_VALUE) {
        return FALSE;
    }
    CloseHandle(marker);
    return TRUE;
}

static int run_quick(void)
{
    printf("LAUNCH_QUICK_OK pid=%lu\n", GetCurrentProcessId());
    fflush(stdout);
    return 0;
}

/*
 * Keep the original corpus invocation stable:
 *   --message Привет-世界-🙂 --exit 37
 */
static int run_legacy_manifest(int argc, wchar_t **argv)
{
    wchar_t *end = NULL;
    unsigned long exit_code = 0;

    if (argc != 5 ||
        wcscmp(argv[1], L"--message") != 0 ||
        wcscmp(argv[2], L"Привет-世界-🙂") != 0 ||
        wcscmp(argv[3], L"--exit") != 0) {
        return fail_contract("legacy-arguments", 81);
    }
    exit_code = wcstoul(argv[4], &end, 10);
    if (end == argv[4] || *end != L'\0' || exit_code != 37ul) {
        return fail_contract("legacy-exit", 82);
    }
    if (!check_environment_exact(L"X64DBG_MCP_E2E_ENV", L"значение-世界")) {
        return fail_contract("legacy-environment", 83);
    }
    if (!check_working_directory()) {
        return fail_contract("legacy-cwd", 84);
    }
    printf(
        "LAUNCH_CONTRACT_OK unicodeArgs=1 unicodeEnv=1 unicodeCwd=1 exit=%lu\n",
        exit_code);
    fflush(stdout);
    return (int)exit_code;
}

/*
 * New typed-launch argv oracle.  The strings intentionally exercise every
 * corner of the CommandLineToArgvW/CRT quoting contract without involving a
 * command shell.
 */
static int run_case_argv_env_cwd(int argc, wchar_t **argv)
{
    static const wchar_t *expected[] = {
        L"",
        L"plain",
        L"two words",
        L"quote\"inside",
        L"slashes\\\\before\"quote",
        L"trailing\\",
        L"punctuation !@#$%^&*()[]{};,.?",
        L"Привет 世界 🙂"
    };
    size_t index = 0;

    if (argc != 3 + (int)ARRAY_COUNT(expected)) {
        return fail_contract("case-argv-count", 91);
    }
    for (index = 0; index < ARRAY_COUNT(expected); ++index) {
        if (wcscmp(argv[index + 3], expected[index]) != 0) {
            SetLastError(ERROR_INVALID_DATA);
            return fail_contract("case-argv-value", 92);
        }
    }
    if (!check_environment_exact(
            L"X64DBG_MCP_E2E_ENV_SET",
            L"значение-世界")) {
        return fail_contract("case-environment-set", 93);
    }
    if (!check_environment_state(
            L"X64DBG_MCP_E2E_ENV_EMPTY",
            ENVIRONMENT_EMPTY)) {
        return fail_contract("case-environment-empty", 94);
    }
    if (!check_environment_state(
            L"X64DBG_MCP_E2E_ENV_DELETE",
            ENVIRONMENT_ABSENT)) {
        return fail_contract("case-environment-deleted", 95);
    }
    if (!check_environment_state(
            L"X64DBG_MCP_E2E_ENV_ABSENT",
            ENVIRONMENT_ABSENT)) {
        return fail_contract("case-environment-absent", 96);
    }
    if (!check_working_directory()) {
        return fail_contract("case-cwd", 97);
    }

    printf(
        "ARGV_ENV_CWD_OK argCount=%u empty=1 plain=1 spaces=1 quote=1 "
        "backslashes=1 trailingSlash=1 punctuation=1 unicodeArgs=1 "
        "envSet=1 envEmpty=1 envDeleted=1 envAbsent=1 unicodeCwd=1 exit=37\n",
        (unsigned int)ARRAY_COUNT(expected));
    fflush(stdout);
    return 37;
}

/* Preserve the direct argv-env-cwd mode from the initial launch work. */
static int run_legacy_argv_env_cwd(int argc, wchar_t **argv)
{
    static const wchar_t *expected[] = {
        L"",
        L"two words",
        L"quote\"inside",
        L"trailing\\",
        L"slashes\\\\before\"quote",
        L"Привет 世界 🙂"
    };
    size_t index = 0;

    if (argc != 2 + (int)ARRAY_COUNT(expected)) {
        return fail_contract("argv-count", 101);
    }
    for (index = 0; index < ARRAY_COUNT(expected); ++index) {
        if (wcscmp(argv[index + 2], expected[index]) != 0) {
            SetLastError(ERROR_INVALID_DATA);
            return fail_contract("argv-value", 102);
        }
    }
    if (!check_environment_exact(L"X64DBG_MCP_E2E_ENV", L"значение-世界")) {
        return fail_contract("unicode-environment", 103);
    }
    if (!check_working_directory()) {
        return fail_contract("unicode-cwd", 104);
    }
    printf(
        "ARGV_ENV_CWD_OK argc=%d empty=1 spaces=1 quotes=1 backslashes=1 "
        "unicodeArgs=1 unicodeEnv=1 unicodeCwd=1 exit=37\n",
        argc);
    fflush(stdout);
    return 37;
}

/* Preserve the flexible environment-only oracle used by early 1B tests. */
static int run_legacy_environment(int argc, wchar_t **argv)
{
    int index = 0;

    if (argc < 3) {
        return fail_contract("environment-oracles", 111);
    }
    for (index = 2; index < argc; ++index) {
        const wchar_t *spec = argv[index];
        const wchar_t *name = NULL;
        const wchar_t *expected = NULL;
        const wchar_t *equals = NULL;
        const char *state_name = NULL;
        wchar_t name_buffer[128] = {0};
        wchar_t value_buffer[512] = {0};
        DWORD length = 0;
        environment_state state = ENVIRONMENT_INVALID;
        BOOL matches = FALSE;

        if (wcsncmp(spec, L"value:", 6) == 0) {
            state_name = "value";
            name = spec + 6;
            equals = wcschr(name, L'=');
            if (equals == NULL || equals == name ||
                (size_t)(equals - name) >= ARRAY_COUNT(name_buffer)) {
                return fail_contract("environment-value-spec", 112);
            }
            wmemcpy(name_buffer, name, (size_t)(equals - name));
            name_buffer[equals - name] = L'\0';
            name = name_buffer;
            expected = equals + 1;
        } else if (wcsncmp(spec, L"present:", 8) == 0) {
            state_name = "present";
            name = spec + 8;
        } else if (wcsncmp(spec, L"empty:", 6) == 0) {
            state_name = "empty";
            name = spec + 6;
        } else if (wcsncmp(spec, L"absent:", 7) == 0) {
            state_name = "absent";
            name = spec + 7;
        } else {
            return fail_contract("environment-spec-kind", 113);
        }

        state = read_environment_value(
            name,
            value_buffer,
            (DWORD)ARRAY_COUNT(value_buffer),
            &length);
        if (state == ENVIRONMENT_INVALID) {
            return fail_contract("environment-read", 114);
        }
        if (strcmp(state_name, "value") == 0) {
            matches = state == ENVIRONMENT_VALUE && expected != NULL &&
                wcscmp(value_buffer, expected) == 0;
        } else if (strcmp(state_name, "present") == 0) {
            matches = state == ENVIRONMENT_VALUE || state == ENVIRONMENT_EMPTY;
        } else if (strcmp(state_name, "empty") == 0) {
            matches = state == ENVIRONMENT_EMPTY && length == 0;
        } else {
            matches = state == ENVIRONMENT_ABSENT;
        }
        if (!matches) {
            SetLastError(ERROR_INVALID_ENVIRONMENT);
            return fail_contract("environment-mismatch", 115);
        }
        printf("ENV_CHECK index=%d state=%s ok=1\n", index - 1, state_name);
    }
    printf("ENVIRONMENT_OK checks=%d\n", argc - 2);
    fflush(stdout);
    return 0;
}

static int emit_stream_result(
    unsigned __int64 total,
    unsigned __int64 hash,
    unsigned __int64 nul_count,
    unsigned __int64 ff_count)
{
    static const unsigned char stdout_marker[] = {
        'S', 'T', 'R', 'E', 'A', 'M', '_', 'S', 'T', 'D', 'O', 'U', 'T',
        0x00, 0xFF, '\n'
    };
    static const unsigned char stderr_marker[] = {
        'S', 'T', 'R', 'E', 'A', 'M', '_', 'S', 'T', 'D', 'E', 'R', 'R',
        0x00, 0xFE, '\n'
    };
    HANDLE output = GetStdHandle(STD_OUTPUT_HANDLE);
    HANDLE error = GetStdHandle(STD_ERROR_HANDLE);
    char line[256] = {0};
    int length = 0;

    if (!write_all(output, stdout_marker, (DWORD)sizeof(stdout_marker))) {
        return fail_contract("stream-stdout-marker", 121);
    }
    length = _snprintf_s(
        line,
        sizeof(line),
        _TRUNCATE,
        "STREAM_STDOUT count=%I64u fnv1a64=%016I64X nul=%I64u ff=%I64u channel=stdout\n",
        total,
        hash,
        nul_count,
        ff_count);
    if (length < 0 || !write_all(output, line, (DWORD)length)) {
        return fail_contract("stream-stdout-result", 122);
    }

    if (!write_all(error, stderr_marker, (DWORD)sizeof(stderr_marker))) {
        return fail_contract("stream-stderr-marker", 123);
    }
    length = _snprintf_s(
        line,
        sizeof(line),
        _TRUNCATE,
        "STREAM_STDERR count=%I64u fnv1a64=%016I64X nul=%I64u ff=%I64u channel=stderr\n",
        total,
        hash,
        nul_count,
        ff_count);
    if (length < 0 || !write_all(error, line, (DWORD)length)) {
        return fail_contract("stream-stderr-result", 124);
    }
    return 0;
}

static int read_stream(
    unsigned __int64 *total,
    unsigned __int64 *hash,
    unsigned __int64 *nul_count,
    unsigned __int64 *ff_count,
    unsigned long *crc32)
{
    unsigned char buffer[16384] = {0};
    HANDLE input = GetStdHandle(STD_INPUT_HANDLE);

    *total = 0;
    *hash = FNV1A64_OFFSET;
    *nul_count = 0;
    *ff_count = 0;
    *crc32 = 0xFFFFFFFFul;
    for (;;) {
        DWORD size = 0;
        DWORD index = 0;

        if (!ReadFile(input, buffer, (DWORD)sizeof(buffer), &size, NULL)) {
            DWORD error = GetLastError();

            if (error == ERROR_BROKEN_PIPE || error == ERROR_HANDLE_EOF) {
                break;
            }
            SetLastError(error);
            return fail_contract("stream-read", 125);
        }
        if (size == 0) {
            break;
        }
        if (*total > STREAM_INPUT_LIMIT - size) {
            SetLastError(ERROR_FILE_TOO_LARGE);
            return fail_contract("stream-input-limit", 126);
        }
        *hash = fnv1a64_update(*hash, buffer, size);
        *crc32 = crc32_update(*crc32, buffer, size);
        *total += size;
        for (index = 0; index < size; ++index) {
            if (buffer[index] == 0x00) {
                ++*nul_count;
            }
            if (buffer[index] == 0xFF) {
                ++*ff_count;
            }
        }
    }
    *crc32 = ~*crc32;
    return 0;
}

static int run_case_stream(void)
{
    unsigned __int64 total = 0;
    unsigned __int64 hash = 0;
    unsigned __int64 nul_count = 0;
    unsigned __int64 ff_count = 0;
    unsigned long crc32 = 0;
    int result = read_stream(&total, &hash, &nul_count, &ff_count, &crc32);

    (void)crc32;
    if (result != 0) {
        return result;
    }
    return emit_stream_result(total, hash, nul_count, ff_count);
}

static int emit_legacy_stream_result(
    unsigned long total,
    unsigned long crc32)
{
    static const unsigned char stdout_prefix[] = {
        'S', 'T', 'D', 'O', 'U', 'T', '_', 'B', 'I', 'N',
        0x00, 0xFF, 0x7F, '\n'
    };
    static const unsigned char stderr_prefix[] = {
        'S', 'T', 'D', 'E', 'R', 'R', '_', 'B', 'I', 'N',
        0x00, 0xFE, 0x80, '\n'
    };
    HANDLE output = GetStdHandle(STD_OUTPUT_HANDLE);
    HANDLE error = GetStdHandle(STD_ERROR_HANDLE);
    char line[160] = {0};
    int length = 0;

    if (!write_all(output, stdout_prefix, (DWORD)sizeof(stdout_prefix))) {
        return fail_contract("legacy-stream-stdout-prefix", 127);
    }
    length = _snprintf_s(
        line,
        sizeof(line),
        _TRUNCATE,
        "STREAM_STDOUT bytes=%lu crc32=%08lX channel=stdout\n",
        total,
        crc32);
    if (length < 0 || !write_all(output, line, (DWORD)length)) {
        return fail_contract("legacy-stream-stdout-result", 128);
    }
    if (!write_all(error, stderr_prefix, (DWORD)sizeof(stderr_prefix))) {
        return fail_contract("legacy-stream-stderr-prefix", 129);
    }
    length = _snprintf_s(
        line,
        sizeof(line),
        _TRUNCATE,
        "STREAM_STDERR bytes=%lu crc32=%08lX channel=stderr\n",
        total,
        crc32);
    if (length < 0 || !write_all(error, line, (DWORD)length)) {
        return fail_contract("legacy-stream-stderr-result", 130);
    }
    return 0;
}

/* Preserve the older size+CRC validating stream mode. */
static int run_legacy_stream_binary(int argc, wchar_t **argv)
{
    unsigned __int64 total = 0;
    unsigned __int64 hash = 0;
    unsigned __int64 nul_count = 0;
    unsigned __int64 ff_count = 0;
    unsigned long crc32 = 0;
    unsigned long expected_size = 0;
    unsigned long expected_crc = 0;
    wchar_t *end = NULL;
    int result = 0;

    if (argc != 4) {
        return fail_contract("stream-arguments", 131);
    }
    expected_size = wcstoul(argv[2], &end, 10);
    if (end == argv[2] || *end != L'\0') {
        return fail_contract("stream-size", 132);
    }
    expected_crc = wcstoul(argv[3], &end, 16);
    if (end == argv[3] || *end != L'\0') {
        return fail_contract("stream-crc", 133);
    }
    result = read_stream(&total, &hash, &nul_count, &ff_count, &crc32);
    if (result != 0) {
        return result;
    }
    if (total != expected_size || crc32 != expected_crc) {
        SetLastError(ERROR_CRC);
        return fail_contract("stream-oracle", 134);
    }
    return emit_legacy_stream_result((unsigned long)total, crc32);
}

static int run_legacy_burst(void)
{
    unsigned char stdout_chunk[BURST_CHUNK_SIZE];
    unsigned char stderr_chunk[BURST_CHUNK_SIZE];
    HANDLE output = GetStdHandle(STD_OUTPUT_HANDLE);
    HANDLE error = GetStdHandle(STD_ERROR_HANDLE);
    unsigned int chunk = 0;
    unsigned int index = 0;

    for (chunk = 0; chunk < BURST_CHUNK_COUNT; ++chunk) {
        for (index = 0; index < BURST_CHUNK_SIZE; ++index) {
            stdout_chunk[index] =
                (unsigned char)((chunk * 17u + index * 31u) & 0xFFu);
            stderr_chunk[index] =
                (unsigned char)((chunk * 29u + index * 13u + 7u) & 0xFFu);
        }
        if (!write_all(output, stdout_chunk, BURST_CHUNK_SIZE)) {
            return fail_contract("legacy-burst-stdout", 135);
        }
        if (!write_all(error, stderr_chunk, BURST_CHUNK_SIZE)) {
            return fail_contract("legacy-burst-stderr", 136);
        }
    }
    return 0;
}

static int run_case_burst(void)
{
    unsigned char stdout_chunk[BURST_CHUNK_SIZE];
    unsigned char stderr_chunk[BURST_CHUNK_SIZE];
    HANDLE output = GetStdHandle(STD_OUTPUT_HANDLE);
    HANDLE error = GetStdHandle(STD_ERROR_HANDLE);
    unsigned __int64 stdout_hash = FNV1A64_OFFSET;
    unsigned __int64 stderr_hash = FNV1A64_OFFSET;
    unsigned __int64 payload_size =
        (unsigned __int64)BURST_CHUNK_SIZE * BURST_CHUNK_COUNT;
    unsigned int chunk = 0;
    unsigned int index = 0;
    char marker[192] = {0};
    int marker_length = 0;

    marker_length = _snprintf_s(
        marker,
        sizeof(marker),
        _TRUNCATE,
        "BURST_STDOUT_BEGIN bytes=%I64u chunks=%u chunkSize=%u\n",
        payload_size,
        BURST_CHUNK_COUNT,
        BURST_CHUNK_SIZE);
    if (marker_length < 0 || !write_all(output, marker, (DWORD)marker_length)) {
        return fail_contract("burst-stdout-begin", 141);
    }
    marker_length = _snprintf_s(
        marker,
        sizeof(marker),
        _TRUNCATE,
        "BURST_STDERR_BEGIN bytes=%I64u chunks=%u chunkSize=%u\n",
        payload_size,
        BURST_CHUNK_COUNT,
        BURST_CHUNK_SIZE);
    if (marker_length < 0 || !write_all(error, marker, (DWORD)marker_length)) {
        return fail_contract("burst-stderr-begin", 142);
    }

    for (chunk = 0; chunk < BURST_CHUNK_COUNT; ++chunk) {
        for (index = 0; index < BURST_CHUNK_SIZE; ++index) {
            stdout_chunk[index] =
                (unsigned char)((chunk * 17u + index * 31u + 3u) & 0xFFu);
            stderr_chunk[index] =
                (unsigned char)((chunk * 29u + index * 13u + 7u) & 0xFFu);
        }
        stdout_hash = fnv1a64_update(stdout_hash, stdout_chunk, BURST_CHUNK_SIZE);
        stderr_hash = fnv1a64_update(stderr_hash, stderr_chunk, BURST_CHUNK_SIZE);
        if (!write_all(output, stdout_chunk, BURST_CHUNK_SIZE)) {
            return fail_contract("burst-stdout-payload", 143);
        }
        if (!write_all(error, stderr_chunk, BURST_CHUNK_SIZE)) {
            return fail_contract("burst-stderr-payload", 144);
        }
    }

    marker_length = _snprintf_s(
        marker,
        sizeof(marker),
        _TRUNCATE,
        "\nBURST_STDOUT_END bytes=%I64u fnv1a64=%016I64X channel=stdout\n",
        payload_size,
        stdout_hash);
    if (marker_length < 0 || !write_all(output, marker, (DWORD)marker_length)) {
        return fail_contract("burst-stdout-end", 145);
    }
    marker_length = _snprintf_s(
        marker,
        sizeof(marker),
        _TRUNCATE,
        "\nBURST_STDERR_END bytes=%I64u fnv1a64=%016I64X channel=stderr\n",
        payload_size,
        stderr_hash);
    if (marker_length < 0 || !write_all(error, marker, (DWORD)marker_length)) {
        return fail_contract("burst-stderr-end", 146);
    }
    return 0;
}

int wmain(int argc, wchar_t **argv)
{
    if (argc == 1 || (argc == 2 && wcscmp(argv[1], L"quick") == 0)) {
        return run_quick();
    }
    if (argc >= 2 && wcscmp(argv[1], L"--message") == 0) {
        return run_legacy_manifest(argc, argv);
    }
    if (argc >= 2 && wcscmp(argv[1], L"argv-env-cwd") == 0) {
        return run_legacy_argv_env_cwd(argc, argv);
    }
    if (argc >= 2 && wcscmp(argv[1], L"environment") == 0) {
        return run_legacy_environment(argc, argv);
    }
    if (argc >= 2 && wcscmp(argv[1], L"stream-binary") == 0) {
        return run_legacy_stream_binary(argc, argv);
    }
    if (argc == 2 && wcscmp(argv[1], L"burst") == 0) {
        return run_legacy_burst();
    }

    if (argc >= 3 && wcscmp(argv[1], L"--case") == 0) {
        if (wcscmp(argv[2], L"quick") == 0 && argc == 3) {
            return run_quick();
        }
        if (wcscmp(argv[2], L"argv-env-cwd") == 0) {
            return run_case_argv_env_cwd(argc, argv);
        }
        if (wcscmp(argv[2], L"stream") == 0 && argc == 3) {
            return run_case_stream();
        }
        if (wcscmp(argv[2], L"burst") == 0 && argc == 3) {
            return run_case_burst();
        }
    }
    SetLastError(ERROR_INVALID_PARAMETER);
    return fail_contract("unknown-mode", 90);
}
