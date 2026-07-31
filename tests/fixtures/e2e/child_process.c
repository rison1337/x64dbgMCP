#define UNICODE
#define _UNICODE
#include <windows.h>
#include <stdio.h>
#include <wchar.h>

static int run_child(DWORD hold_ms)
{
    printf("CHILD_EVENT role=child pid=%lu holdMs=%lu token=child-ok\n", GetCurrentProcessId(), hold_ms);
    fflush(stdout);
    Sleep(hold_ms);
    return 23;
}

static int spawn_graph_child(
    const wchar_t *image_path,
    const wchar_t *command_line,
    DWORD *child_pid,
    DWORD *child_exit)
{
    STARTUPINFOW startup = {0};
    PROCESS_INFORMATION process = {0};
    SECURITY_ATTRIBUTES inherit_attributes = {0};
    HANDLE inherited_output = NULL;
    HANDLE inherited_input = INVALID_HANDLE_VALUE;
    HANDLE current_output = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD wait_result = WAIT_FAILED;
    if (child_pid != NULL) *child_pid = 0;
    if (child_exit != NULL) *child_exit = 0;
    if (current_output == NULL || current_output == INVALID_HANDLE_VALUE ||
        !DuplicateHandle(
            GetCurrentProcess(), current_output, GetCurrentProcess(),
            &inherited_output, 0, TRUE, DUPLICATE_SAME_ACCESS)) {
        return 67;
    }
    inherit_attributes.nLength = sizeof(inherit_attributes);
    inherit_attributes.bInheritHandle = TRUE;
    inherited_input = CreateFileW(
        L"NUL", GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        &inherit_attributes, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (inherited_input == INVALID_HANDLE_VALUE) {
        CloseHandle(inherited_output);
        return 67;
    }
    startup.cb = sizeof(startup);
    startup.dwFlags = STARTF_USESTDHANDLES;
    startup.hStdInput = inherited_input;
    startup.hStdOutput = inherited_output;
    startup.hStdError = inherited_output;
    if (!CreateProcessW(
            image_path, (LPWSTR)command_line, NULL, NULL, TRUE,
            CREATE_NO_WINDOW, NULL, NULL, &startup, &process)) {
        DWORD error = GetLastError();
        fprintf(stderr, "GRAPH_FAIL phase=CreateProcessW error=%lu\n", error);
        CloseHandle(inherited_input);
        CloseHandle(inherited_output);
        return 67;
    }
    CloseHandle(inherited_input);
    CloseHandle(inherited_output);
    if (child_pid != NULL) *child_pid = process.dwProcessId;
    wait_result = WaitForSingleObject(process.hProcess, 30000);
    if (wait_result != WAIT_OBJECT_0 ||
        !GetExitCodeProcess(process.hProcess, child_exit)) {
        TerminateProcess(process.hProcess, 68);
        CloseHandle(process.hThread);
        CloseHandle(process.hProcess);
        return 68;
    }
    CloseHandle(process.hThread);
    CloseHandle(process.hProcess);
    return 0;
}

static int run_graph_node(
    const wchar_t *image_path,
    int depth,
    int fanout,
    DWORD hold_ms,
    const wchar_t *node_id,
    const wchar_t *child_image)
{
    int index;
    (void)image_path;
    printf("GRAPH_EVENT node=%ls pid=%lu depth=%d fanout=%d\n",
           node_id, GetCurrentProcessId(), depth, fanout);
    fflush(stdout);
    if (depth > 0) {
        for (index = 0; index < fanout; ++index) {
            wchar_t child_id[256] = {0};
            wchar_t command_line[32768] = {0};
            DWORD child_pid = 0;
            DWORD child_exit = 0;
            if (swprintf_s(child_id, sizeof(child_id) / sizeof(child_id[0]),
                           L"%ls.%d", node_id, index) < 0 ||
                swprintf_s(command_line, sizeof(command_line) / sizeof(command_line[0]),
                           L"\"%ls\" --graph-node %d %d %lu %ls \"%ls\"",
                           child_image, depth - 1, fanout, hold_ms,
                           child_id, child_image) < 0) {
                return 66;
            }
            if (spawn_graph_child(child_image, command_line,
                                  &child_pid, &child_exit) != 0 || child_exit != 0) {
                fprintf(stderr,
                        "GRAPH_FAIL node=%ls child=%ls childPid=%lu exit=%lu\n",
                        node_id, child_id, child_pid, child_exit);
                return 69;
            }
            printf("GRAPH_EVENT parent=%ls child=%ls childPid=%lu exit=%lu\n",
                   node_id, child_id, child_pid, child_exit);
            fflush(stdout);
        }
    }
    Sleep(hold_ms);
    printf("GRAPH_EVENT done=%ls pid=%lu\n", node_id, GetCurrentProcessId());
    fflush(stdout);
    return 0;
}

int wmain(int argc, wchar_t **argv)
{
    wchar_t image_path[MAX_PATH] = {0};
    wchar_t command_line[MAX_PATH + 128] = {0};
    STARTUPINFOW startup = {0};
    PROCESS_INFORMATION process = {0};
    SECURITY_ATTRIBUTES inherit_attributes = {0};
    HANDLE inherited_output = NULL;
    HANDLE inherited_input = INVALID_HANDLE_VALUE;
    HANDLE current_output = NULL;
    DWORD child_exit = 0;
    DWORD wait_result = WAIT_FAILED;

    if (argc >= 6 && wcscmp(argv[1], L"--graph-root") == 0) {
        int depth = (int)wcstol(argv[2], NULL, 10);
        int fanout = (int)wcstol(argv[3], NULL, 10);
        DWORD hold_ms = wcstoul(argv[4], NULL, 10);
        wchar_t self_path[32768] = {0};
        const wchar_t *child_image = argv[5];
        if (GetModuleFileNameW(NULL, self_path,
                               (DWORD)(sizeof(self_path) / sizeof(self_path[0]))) == 0)
            return 65;
        if (child_image == NULL || child_image[0] == L'\0') child_image = self_path;
        return run_graph_node(self_path, depth, fanout, hold_ms,
                              L"root", child_image);
    }
    if (argc >= 7 && wcscmp(argv[1], L"--graph-node") == 0) {
        int depth = (int)wcstol(argv[2], NULL, 10);
        int fanout = (int)wcstol(argv[3], NULL, 10);
        DWORD hold_ms = wcstoul(argv[4], NULL, 10);
        return run_graph_node(argv[0], depth, fanout, hold_ms,
                              argv[5], argv[6]);
    }

    if (argc >= 2 && wcscmp(argv[1], L"--child") == 0) {
        DWORD hold_ms = argc >= 3 ? wcstoul(argv[2], NULL, 10) : 500;
        return run_child(hold_ms);
    }
    if (argc != 1) {
        return 64;
    }
    if (GetModuleFileNameW(NULL, image_path, (DWORD)(sizeof(image_path) / sizeof(image_path[0]))) == 0) {
        return 65;
    }
    if (swprintf_s(
            command_line,
            sizeof(command_line) / sizeof(command_line[0]),
            L"\"%ls\" --child 750",
            image_path) < 0) {
        return 66;
    }

    startup.cb = sizeof(startup);
    inherit_attributes.nLength = sizeof(inherit_attributes);
    inherit_attributes.bInheritHandle = TRUE;
    current_output = GetStdHandle(STD_OUTPUT_HANDLE);
    if (current_output == NULL || current_output == INVALID_HANDLE_VALUE ||
        !DuplicateHandle(
            GetCurrentProcess(),
            current_output,
            GetCurrentProcess(),
            &inherited_output,
            0,
            TRUE,
            DUPLICATE_SAME_ACCESS)) {
        return 67;
    }
    inherited_input = CreateFileW(
        L"NUL",
        GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        &inherit_attributes,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL);
    if (inherited_input == INVALID_HANDLE_VALUE) {
        CloseHandle(inherited_output);
        return 67;
    }
    startup.dwFlags = STARTF_USESTDHANDLES;
    startup.hStdInput = inherited_input;
    startup.hStdOutput = inherited_output;
    startup.hStdError = inherited_output;
    if (!CreateProcessW(
            image_path,
            command_line,
            NULL,
            NULL,
            TRUE,
            CREATE_NO_WINDOW,
            NULL,
            NULL,
            &startup,
            &process)) {
        fprintf(stderr, "CHILD_FAIL phase=CreateProcessW error=%lu\n", GetLastError());
        CloseHandle(inherited_input);
        CloseHandle(inherited_output);
        return 67;
    }
    CloseHandle(inherited_input);
    CloseHandle(inherited_output);

    printf(
        "CHILD_EVENT role=parent phase=spawn parentPid=%lu childPid=%lu\n",
        GetCurrentProcessId(),
        process.dwProcessId);
    fflush(stdout);

    // A child debugger is intentionally spawned by the broker during this
    // wait.  Cold-starting a second x32/x64dbg (especially after Defender or
    // Explorer validation) can exceed ten seconds; keep the fixture oracle
    // bounded but long enough to distinguish broker startup from a hang.
    wait_result = WaitForSingleObject(process.hProcess, 30000);
    if (wait_result != WAIT_OBJECT_0 || !GetExitCodeProcess(process.hProcess, &child_exit)) {
        TerminateProcess(process.hProcess, 68);
        CloseHandle(process.hThread);
        CloseHandle(process.hProcess);
        return 68;
    }
    CloseHandle(process.hThread);
    CloseHandle(process.hProcess);

    printf("CHILD_OK childExit=%lu observed=1\n", child_exit);
    fflush(stdout);
    return child_exit == 23 ? 0 : 69;
}
