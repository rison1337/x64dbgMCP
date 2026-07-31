#include "module_api.h"
#include <stdio.h>
#include <wchar.h>

int wmain(void)
{
    wchar_t buffer[64] = {0};
    HMODULE module = GetModuleHandleW(L"fixture_module.dll");
    int sum = FixtureAdd(19, 23);
    DWORD length = FixtureFill(buffer, (DWORD)(sizeof(buffer) / sizeof(buffer[0])));
    const wchar_t *name = FixtureName();

    if (module == NULL || sum != 42 || length != 16 ||
        wcscmp(buffer, L"module-import-ok") != 0 ||
        wcscmp(name, L"fixture_module") != 0) {
        fprintf(
            stderr,
            "MODULE_IMPORT_FAIL loaded=%d sum=%d length=%lu\n",
            module != NULL,
            sum,
            length);
        return 70;
    }

    printf(
        "MODULE_IMPORT_OK loaded=1 directImports=3 sum=%d textLength=%lu module=%p\n",
        sum,
        length,
        module);
    fflush(stdout);
    return 0;
}
