#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>

#define FIXTURE_TLS_EXCEPTION ((DWORD)0xE0425E11u)

static volatile LONG g_tls_entered = 0;
static volatile LONG g_seh_handled = 0;

static LONG fixture_exception_filter(unsigned int code)
{
    return code == FIXTURE_TLS_EXCEPTION
        ? EXCEPTION_EXECUTE_HANDLER
        : EXCEPTION_CONTINUE_SEARCH;
}

static void NTAPI fixture_tls_callback(PVOID module, DWORD reason, PVOID reserved)
{
    (void)module;
    (void)reserved;
    if(reason != DLL_PROCESS_ATTACH)
        return;

    InterlockedExchange(&g_tls_entered, 1);
    __try
    {
        RaiseException(FIXTURE_TLS_EXCEPTION, 0, 0, NULL);
    }
    __except(fixture_exception_filter(GetExceptionCode()))
    {
        InterlockedExchange(&g_seh_handled, 1);
    }
}

#pragma section(".CRT$XLB", long, read)
__declspec(allocate(".CRT$XLB"))
PIMAGE_TLS_CALLBACK fixture_tls_callback_ptr = fixture_tls_callback;

#ifdef _WIN64
#pragma comment(linker, "/INCLUDE:_tls_used")
#pragma comment(linker, "/INCLUDE:fixture_tls_callback_ptr")
#else
#pragma comment(linker, "/INCLUDE:__tls_used")
#pragma comment(linker, "/INCLUDE:_fixture_tls_callback_ptr")
#endif

int main(void)
{
    LONG tls_entered = InterlockedCompareExchange(&g_tls_entered, 0, 0);
    LONG seh_handled = InterlockedCompareExchange(&g_seh_handled, 0, 0);
    printf(
        "TLS_SEH_OK tlsEntered=%ld firstChance=1 sehHandled=%ld code=0x%08lX\n",
        tls_entered,
        seh_handled,
        (unsigned long)FIXTURE_TLS_EXCEPTION);
    return (tls_entered == 1 && seh_handled == 1) ? 0 : 91;
}
