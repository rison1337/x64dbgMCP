#define FIXTURE_MODULE_EXPORTS
#include "module_api.h"
#include <wchar.h>

BOOL WINAPI DllMain(HINSTANCE instance, DWORD reason, LPVOID reserved)
{
    (void)instance;
    (void)reason;
    (void)reserved;
    return TRUE;
}

int __cdecl FixtureAdd(int left, int right)
{
    return left + right;
}

DWORD __cdecl FixtureFill(wchar_t *buffer, DWORD capacity)
{
    static const wchar_t value[] = L"module-import-ok";
    DWORD required = (DWORD)(sizeof(value) / sizeof(value[0]));
    if (buffer == NULL || capacity < required) {
        return required;
    }
    wcscpy_s(buffer, capacity, value);
    return required - 1;
}

const wchar_t *__cdecl FixtureName(void)
{
    return L"fixture_module";
}
