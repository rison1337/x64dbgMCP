#define UNICODE
#define _UNICODE
#include <windows.h>
#include <stdio.h>
#include <wchar.h>

#define FIXTURE_EXCEPTION ((DWORD)0xE0424242u)
#define FIXTURE_MASKED_EXCEPTION ((DWORD)0xE0429999u)
#define FIXTURE_WILDCARD_EXCEPTION ((DWORD)0xA1234567u)

static volatile LONG g_first_chance_count = 0;
static volatile LONG g_continue_from_veh = 0;

static LONG CALLBACK fixture_vectored_handler(PEXCEPTION_POINTERS pointers)
{
    if (pointers != NULL &&
        pointers->ExceptionRecord != NULL &&
        pointers->ExceptionRecord->ExceptionCode == FIXTURE_EXCEPTION) {
        InterlockedIncrement(&g_first_chance_count);
        if (InterlockedCompareExchange(&g_continue_from_veh, 0, 0) != 0) {
            return EXCEPTION_CONTINUE_EXECUTION;
        }
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

static int fixture_exception_filter(unsigned int code)
{
    return code == FIXTURE_EXCEPTION ? EXCEPTION_EXECUTE_HANDLER : EXCEPTION_CONTINUE_SEARCH;
}

static int fixture_sequence_filter(unsigned int code)
{
    return code == FIXTURE_EXCEPTION ||
                   code == FIXTURE_MASKED_EXCEPTION ||
                   code == FIXTURE_WILDCARD_EXCEPTION
               ? EXCEPTION_EXECUTE_HANDLER
               : EXCEPTION_CONTINUE_SEARCH;
}

static int raise_and_catch_sequence_exception(DWORD code, const char *selector)
{
    LONG caught = 0;
    __try {
        RaiseException(code, 0, 0, NULL);
    }
    __except (fixture_sequence_filter(GetExceptionCode())) {
        caught = 1;
    }
    printf(
        "EXCEPTION_SEQUENCE selector=%s code=0x%08lX caught=%ld\n",
        selector,
        code,
        caught);
    fflush(stdout);
    return caught ? 0 : 1;
}

int wmain(int argc, wchar_t **argv)
{
    PVOID handler = NULL;

    if (argc != 2) {
        fprintf(stderr, "usage: exception_disposition handled|first-chance|unhandled|policy-sequence\n");
        return 64;
    }

    SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX);
    handler = AddVectoredExceptionHandler(1, fixture_vectored_handler);
    if (handler == NULL) {
        return 65;
    }

    if (_wcsicmp(argv[1], L"handled") == 0) {
        LONG seh_handled = 0;
        __try {
            RaiseException(FIXTURE_EXCEPTION, 0, 0, NULL);
        }
        __except (fixture_exception_filter(GetExceptionCode())) {
            seh_handled = 1;
            printf(
                "EXCEPTION_OK mode=handled firstChance=%ld sehHandled=1\n",
                InterlockedCompareExchange(&g_first_chance_count, 0, 0));
            fflush(stdout);
        }
        RemoveVectoredExceptionHandler(handler);
        // Distinguish normal/pass delivery from a debugger swallowing the
        // exception: both paths are process-safe, but only pass reaches SEH.
        return seh_handled ? 0 : 68;
    }

    if (_wcsicmp(argv[1], L"first-chance") == 0) {
        LONG veh_count = 0;
        InterlockedExchange(&g_continue_from_veh, 1);
        RaiseException(FIXTURE_EXCEPTION, 0, 0, NULL);
        veh_count = InterlockedCompareExchange(&g_first_chance_count, 0, 0);
        printf(
            "EXCEPTION_OK mode=first-chance firstChance=%ld vehContinued=1\n",
            veh_count);
        fflush(stdout);
        RemoveVectoredExceptionHandler(handler);
        // A debugger-side swallow also returns from RaiseException, so the
        // handler count is the deterministic oracle that not-handled delivery
        // actually reached the process VEH.
        return veh_count == 1 ? 0 : 70;
    }

    if (_wcsicmp(argv[1], L"managed") == 0) {
        ULONG_PTR parameters[2];
        LONG caught = 0;
        parameters[0] = (ULONG_PTR)0x80131500u; /* System.Exception HRESULT */
        parameters[1] = (ULONG_PTR)&g_first_chance_count; /* deterministic object token */
        __try {
            RaiseException(
                (DWORD)0xE0434352u, /* CLR managed exception dispatch code */
                0,
                2,
                parameters);
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            caught = 1;
        }
        printf(
            "MANAGED_EXCEPTION_OK code=0xE0434352 hresult=0x80131500 caught=%ld\n",
            caught);
        fflush(stdout);
        RemoveVectoredExceptionHandler(handler);
        return caught == 1 ? 0 : 74;
    }

    if (_wcsicmp(argv[1], L"unhandled") == 0) {
        printf("EXCEPTION_EVENT mode=unhandled phase=raising code=0x%08lX\n", FIXTURE_EXCEPTION);
        fflush(stdout);
        RaiseException(FIXTURE_EXCEPTION, EXCEPTION_NONCONTINUABLE, 0, NULL);
        return 99;
    }

    if (_wcsicmp(argv[1], L"policy-sequence") == 0) {
        int failures = 0;
        failures += raise_and_catch_sequence_exception(FIXTURE_EXCEPTION, "exact");
        failures += raise_and_catch_sequence_exception(FIXTURE_MASKED_EXCEPTION, "masked");
        failures += raise_and_catch_sequence_exception(FIXTURE_WILDCARD_EXCEPTION, "wildcard");
        printf(
            "EXCEPTION_POLICY_OK exact=1 masked=1 wildcard=1 caught=%d\n",
            3 - failures);
        fflush(stdout);
        RemoveVectoredExceptionHandler(handler);
        return failures == 0 ? 0 : 69;
    }

    RemoveVectoredExceptionHandler(handler);
    fprintf(stderr, "unknown exception mode\n");
    return 66;
}
