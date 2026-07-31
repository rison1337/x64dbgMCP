#define UNICODE
#define _UNICODE
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>

#define EXPORT __declspec(dllexport) __declspec(noinline)

EXPORT void *fixture_heap_alloc(SIZE_T size, unsigned char fill)
{
    void *allocation = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, size);
    if (allocation != NULL) {
        memset(allocation, fill, size);
    }
    return allocation;
}

EXPORT void *fixture_heap_realloc(void *allocation, SIZE_T size)
{
    return HeapReAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, allocation, size);
}

EXPORT BOOL fixture_heap_free(void *allocation)
{
    return HeapFree(GetProcessHeap(), 0, allocation);
}

typedef LPVOID (WINAPI *PFN_COTASKMEMALLOC)(SIZE_T);
typedef LPVOID (WINAPI *PFN_COTASKMEMREALLOC)(LPVOID, SIZE_T);
typedef void (WINAPI *PFN_COTASKMEMFREE)(LPVOID);

static HMODULE g_ole32 = NULL;
static PFN_COTASKMEMALLOC g_cotask_alloc = NULL;
static PFN_COTASKMEMREALLOC g_cotask_realloc = NULL;
static PFN_COTASKMEMFREE g_cotask_free = NULL;
static HANDLE g_cross_release = NULL;
static HANDLE g_cross_worker = NULL;
static void *g_cross_virtual = NULL;

static DWORD WINAPI fixture_cross_thread_proc(void *context)
{
    (void)context;
    // Debugger entry/return hooks suspend the whole process and those pauses
    // still consume Win32 wait time. Keep this comfortably above the live
    // trace budget so the worker cannot time out before the primary thread
    // reaches SetEvent.
    if (WaitForSingleObject(g_cross_release, 120000) != WAIT_OBJECT_0) {
        return 1;
    }
    const DWORD result = VirtualFree(g_cross_virtual, 0, MEM_RELEASE) ? 0 : 2;
    // Keep the debuggee alive briefly after the secondary-thread release.
    // This gives a debugger enough time to consume the breakpoint event
    // before the primary thread joins and exits the process.
    Sleep(1000);
    return result;
}

EXPORT int fixture_resource_matrix(void)
{
    void *virtual_memory = NULL;
    void *cross_virtual = NULL;
    HLOCAL local_memory = NULL;
    HGLOBAL global_memory = NULL;
    void *crt_memory = NULL;
    void *com_memory = NULL;
    if (g_ole32 == NULL || g_cotask_alloc == NULL
        || g_cotask_realloc == NULL || g_cotask_free == NULL) {
        return 80;
    }

    g_cross_release = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (g_cross_release == NULL) {
        return 82;
    }
    g_cross_worker = CreateThread(NULL, 0, fixture_cross_thread_proc, NULL, 0, NULL);
    if (g_cross_worker == NULL) {
        return 83;
    }

    virtual_memory = VirtualAlloc(NULL, 128, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    cross_virtual = VirtualAlloc(NULL, 160, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    local_memory = LocalAlloc(LMEM_MOVEABLE | LMEM_ZEROINIT, 24);
    global_memory = GlobalAlloc(GMEM_MOVEABLE | GMEM_ZEROINIT, 48);
    crt_memory = malloc(56);
    com_memory = g_cotask_alloc(80);
    if (virtual_memory == NULL || cross_virtual == NULL
        || local_memory == NULL || global_memory == NULL
        || crt_memory == NULL || com_memory == NULL) {
        return 84;
    }

    local_memory = LocalReAlloc(local_memory, 40, LMEM_MOVEABLE | LMEM_ZEROINIT);
    global_memory = GlobalReAlloc(global_memory, 64, GMEM_MOVEABLE | GMEM_ZEROINIT);
    crt_memory = realloc(crt_memory, 72);
    com_memory = g_cotask_realloc(com_memory, 96);
    if (local_memory == NULL || global_memory == NULL || crt_memory == NULL
        || com_memory == NULL) {
        return 85;
    }

    if (!VirtualFree(virtual_memory, 0, MEM_RELEASE)) {
        return 86;
    }
    if (LocalFree(local_memory) != NULL) {
        return 87;
    }
    local_memory = NULL;
    // Deliberately free a second VirtualAlloc resource from the worker
    // thread to exercise cross-thread ownership evidence on a stable API.
    g_cross_virtual = cross_virtual;
    cross_virtual = NULL;
    if (GlobalFree(global_memory) != NULL) {
        return 88;
    }
    free(crt_memory);
    g_cotask_free(com_memory);

    SetEvent(g_cross_release);
    if (WaitForSingleObject(g_cross_worker, 120000) != WAIT_OBJECT_0) {
        return 89;
    }
    DWORD worker_code = 1;
    GetExitCodeThread(g_cross_worker, &worker_code);
    CloseHandle(g_cross_worker);
    CloseHandle(g_cross_release);
    g_cross_worker = NULL;
    g_cross_release = NULL;
    g_cross_virtual = NULL;
    FreeLibrary(g_ole32);
    g_ole32 = NULL;
    g_cotask_alloc = NULL;
    g_cotask_realloc = NULL;
    g_cotask_free = NULL;
    return worker_code == 0 ? 0 : 90;
}

int wmain(int argc, wchar_t **argv)
{
    DWORD hold_ms = 100;
    void *first = NULL;
    void *second = NULL;
    void *third = NULL;
    BOOL resource_matrix = FALSE;

    if (argc == 3 && wcscmp(argv[1], L"--hold-ms") == 0) {
        hold_ms = wcstoul(argv[2], NULL, 10);
        if (hold_ms > 5000) {
            return 64;
        }
    } else if (argc == 2 && wcscmp(argv[1], L"--resource-matrix") == 0) {
        resource_matrix = TRUE;
    } else if (argc != 1) {
        return 64;
    }

    if (resource_matrix) {
        g_ole32 = LoadLibraryW(L"ole32.dll");
        if (g_ole32 != NULL) {
            g_cotask_alloc = (PFN_COTASKMEMALLOC)GetProcAddress(g_ole32, "CoTaskMemAlloc");
            g_cotask_realloc = (PFN_COTASKMEMREALLOC)GetProcAddress(g_ole32, "CoTaskMemRealloc");
            g_cotask_free = (PFN_COTASKMEMFREE)GetProcAddress(g_ole32, "CoTaskMemFree");
        }
        // Keep the process alive long enough for the debugger to arm the
        // symbolic anchor without tracing loader-initialization allocations.
        // Five seconds covers a cold x64dbg launch while keeping corpus
        // verification fast and deterministic.
        Sleep(5000);
        int result = fixture_resource_matrix();
        printf("HEAP_FAMILIES_OK result=%d\n", result);
        fflush(stdout);
        return result;
    }

    first = fixture_heap_alloc(32, 0x11);
    second = fixture_heap_alloc(64, 0x22);
    third = fixture_heap_alloc(96, 0x33);
    if (first == NULL || second == NULL || third == NULL) {
        return 70;
    }
    printf("HEAP_EVENT seq=1 op=alloc id=first size=32 ptr=%p\n", first);
    printf("HEAP_EVENT seq=2 op=alloc id=second size=64 ptr=%p\n", second);
    printf("HEAP_EVENT seq=3 op=alloc id=third size=96 ptr=%p\n", third);

    if (!fixture_heap_free(second)) {
        return 71;
    }
    printf("HEAP_EVENT seq=4 op=free id=second ptr=%p\n", second);
    second = NULL;

    first = fixture_heap_realloc(first, 80);
    if (first == NULL) {
        return 72;
    }
    printf("HEAP_EVENT seq=5 op=realloc id=first size=80 ptr=%p\n", first);
    printf("HEAP_CHECKPOINT live=2 freed=1 allocations=3 reallocations=1\n");
    fflush(stdout);
    Sleep(hold_ms);

    if (!fixture_heap_free(first) || !fixture_heap_free(third)) {
        return 73;
    }
    printf("HEAP_EVENT seq=6 op=free id=first ptr=%p\n", first);
    printf("HEAP_EVENT seq=7 op=free id=third ptr=%p\n", third);
    printf("HEAP_OK live=0 alloc=3 realloc=1 free=3\n");
    fflush(stdout);
    return 0;
}
