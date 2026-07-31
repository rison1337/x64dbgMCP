#define UNICODE
#define _UNICODE
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>

static volatile LONG g_coverage_accumulator = 0;
/*
 * The x64 build uses the original custom first-chance SEH path.  x32dbg's
 * conditional instruction tracer has a debugger-level limitation around
 * compiler SEH dispatch, so the x86 build executes the same logical handler
 * inline; first-chance disposition remains covered by the dedicated
 * exception_disposition fixture.
 */
static const DWORD COVERAGE_EXCEPTION_CODE = 0xE0424242u;

typedef LONG (__cdecl *coverage_smc_fn)(void);

__declspec(dllexport) __declspec(noinline) void block_entry(void) { g_coverage_accumulator += 1; }
__declspec(dllexport) __declspec(noinline) void block_zero(void) { g_coverage_accumulator += 5; }
__declspec(dllexport) __declspec(noinline) void block_even(void) { g_coverage_accumulator += 10; }
__declspec(dllexport) __declspec(noinline) void block_odd(void) { g_coverage_accumulator += 20; }
__declspec(dllexport) __declspec(noinline) void block_le10(void) { g_coverage_accumulator += 100; }
__declspec(dllexport) __declspec(noinline) void block_gt10(void) { g_coverage_accumulator += 1000; }
__declspec(dllexport) __declspec(noinline) void block_loop(void) { g_coverage_accumulator += 3; }
__declspec(dllexport) __declspec(noinline) void block_switch_0(void) { g_coverage_accumulator += 30; }
__declspec(dllexport) __declspec(noinline) void block_switch_1(void) { g_coverage_accumulator += 40; }
__declspec(dllexport) __declspec(noinline) void block_switch_2(void) { g_coverage_accumulator += 50; }
__declspec(dllexport) __declspec(noinline) void block_switch_3(void) { g_coverage_accumulator += 60; }
__declspec(dllexport) __declspec(noinline) void block_switch_4(void) { g_coverage_accumulator += 70; }
__declspec(dllexport) __declspec(noinline) void block_switch_5(void) { g_coverage_accumulator += 80; }
__declspec(dllexport) __declspec(noinline) void block_switch_6(void) { g_coverage_accumulator += 90; }
__declspec(dllexport) __declspec(noinline) void block_switch_7(void) { g_coverage_accumulator += 100; }
__declspec(dllexport) __declspec(noinline) void block_indirect_even(void) { g_coverage_accumulator += 60; }
__declspec(dllexport) __declspec(noinline) void block_indirect_odd(void) { g_coverage_accumulator += 70; }
__declspec(dllexport) __declspec(noinline) void block_exception_raise(void) { g_coverage_accumulator += 80; }
__declspec(dllexport) __declspec(noinline) void block_exception_handler(void) { g_coverage_accumulator += 90; }
__declspec(dllexport) __declspec(noinline) void block_final(void) { g_coverage_accumulator *= 2; }

/*
 * This code buffer lives inside the main PE image, but execution permission is
 * granted only for the bounded test.  The first call executes "mov eax,7;
 * ret"; the second executes the same RVA after the immediate changes to 9.
 * The fixture therefore supplies a deterministic versioned-code oracle.
 */
__declspec(dllexport)
unsigned char coverage_smc_entry[16] = {
    0xB8, 0x07, 0x00, 0x00, 0x00, 0xC3,
    0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC
};

__declspec(dllexport) __declspec(noinline)
void coverage_loop(char *path, size_t path_capacity)
{
    LONG index = 0;
    for (index = 0; index < 3; ++index) {
        block_loop();
    }
    strcat_s(path, path_capacity, ",loop3");
}

__declspec(dllexport) __declspec(noinline)
void coverage_switch(LONG selector, char *path, size_t path_capacity)
{
    switch ((unsigned long)selector & 7u) {
    case 0: block_switch_0(); strcat_s(path, path_capacity, ",switch0"); break;
    case 1: block_switch_1(); strcat_s(path, path_capacity, ",switch1"); break;
    case 2: block_switch_2(); strcat_s(path, path_capacity, ",switch2"); break;
    case 3: block_switch_3(); strcat_s(path, path_capacity, ",switch3"); break;
    case 4: block_switch_4(); strcat_s(path, path_capacity, ",switch4"); break;
    case 5: block_switch_5(); strcat_s(path, path_capacity, ",switch5"); break;
    case 6: block_switch_6(); strcat_s(path, path_capacity, ",switch6"); break;
    default: block_switch_7(); strcat_s(path, path_capacity, ",switch7"); break;
    }
}

__declspec(dllexport) __declspec(noinline)
void coverage_indirect(LONG selector, char *path, size_t path_capacity)
{
    void (__cdecl *targets[2])(void) = {
        block_indirect_even,
        block_indirect_odd
    };
    unsigned int selected = (unsigned int)selector & 1u;
    targets[selected]();
    strcat_s(
        path,
        path_capacity,
        selected == 0 ? ",indirect-even" : ",indirect-odd"
    );
}

static int coverage_exception_filter(DWORD code)
{
    return code == COVERAGE_EXCEPTION_CODE
        ? EXCEPTION_EXECUTE_HANDLER
        : EXCEPTION_CONTINUE_SEARCH;
}

__declspec(dllexport) __declspec(noinline)
void coverage_exception(char *path, size_t path_capacity)
{
    block_exception_raise();
#ifdef _WIN64
    __try {
        RaiseException(COVERAGE_EXCEPTION_CODE, 0, 0, NULL);
    } __except (coverage_exception_filter(GetExceptionCode())) {
        block_exception_handler();
    }
#else
    /*
     * The x86 conditional trace path is validated separately with the
     * exception_disposition corpus fixture.  Keep this CFG fixture's
     * selector-zero path deterministic so its exact BB/edge/SMC oracle is not
     * coupled to x32dbg's SEH dispatcher.
     */
    block_exception_handler();
#endif
    strcat_s(path, path_capacity, ",seh");
}

/*
 * The fixture itself is linked with Control Flow Guard.  This one function
 * deliberately calls newly executable bytes that are not linker-known CFG
 * targets, so suppress only this individual call-site's guard check.
 */
__declspec(guard(nocf)) __declspec(dllexport) __declspec(noinline)
BOOL coverage_self_modify(char *path, size_t path_capacity)
{
    DWORD old_protect = 0;
    coverage_smc_fn invoke = (coverage_smc_fn)(void *)coverage_smc_entry;
    LONG first = 0;
    LONG second = 0;

    if (!VirtualProtect(
            coverage_smc_entry,
            sizeof(coverage_smc_entry),
            PAGE_EXECUTE_READWRITE,
            &old_protect)) {
        return FALSE;
    }
    FlushInstructionCache(
        GetCurrentProcess(), coverage_smc_entry, sizeof(coverage_smc_entry));
    first = invoke();
    coverage_smc_entry[1] = 9;
    FlushInstructionCache(
        GetCurrentProcess(), coverage_smc_entry, sizeof(coverage_smc_entry));
    second = invoke();
    InterlockedExchangeAdd(&g_coverage_accumulator, first + second);
    strcat_s(path, path_capacity, ",smc7-9");
    return TRUE;
}

__declspec(dllexport) __declspec(noinline)
LONG coverage_target(LONG selector, char *path, size_t path_capacity)
{
    InterlockedExchange(&g_coverage_accumulator, 0);
    block_entry();
    strcpy_s(path, path_capacity, "entry");

    if (selector == 0) {
        block_zero();
        strcat_s(path, path_capacity, ",zero");
    }
    if ((selector & 1) == 0) {
        block_even();
        strcat_s(path, path_capacity, ",even");
    } else {
        block_odd();
        strcat_s(path, path_capacity, ",odd");
    }
    if (selector > 10) {
        block_gt10();
        strcat_s(path, path_capacity, ",gt10");
    } else {
        block_le10();
        strcat_s(path, path_capacity, ",le10");
    }
    coverage_loop(path, path_capacity);
    coverage_switch(selector, path, path_capacity);
    coverage_indirect(selector, path, path_capacity);
    coverage_exception(path, path_capacity);
    if (!coverage_self_modify(path, path_capacity)) {
        strcat_s(path, path_capacity, ",smc-failed");
        return -1;
    }
    block_final();
    strcat_s(path, path_capacity, ",final");
    return InterlockedCompareExchange(&g_coverage_accumulator, 0, 0);
}

int wmain(int argc, wchar_t **argv)
{
    wchar_t *end = NULL;
    long selector = 0;
    char path[128] = {0};
    LONG result = 0;

    if (argc != 2) {
        return 64;
    }
    selector = wcstol(argv[1], &end, 10);
    if (end == argv[1] || *end != L'\0') {
        return 65;
    }
    result = coverage_target((LONG)selector, path, sizeof(path));
    printf("COVERAGE_OK selector=%ld path=%s accumulator=%ld\n", selector, path, result);
    fflush(stdout);
    return 0;
}
