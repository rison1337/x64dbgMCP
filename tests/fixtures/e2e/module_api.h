#ifndef X64DBG_MCP_E2E_MODULE_API_H
#define X64DBG_MCP_E2E_MODULE_API_H

#define UNICODE
#define _UNICODE
#include <windows.h>

#ifdef FIXTURE_MODULE_EXPORTS
#define FIXTURE_API __declspec(dllexport)
#else
#define FIXTURE_API __declspec(dllimport)
#endif

#ifdef __cplusplus
extern "C" {
#endif

FIXTURE_API int __cdecl FixtureAdd(int left, int right);
FIXTURE_API DWORD __cdecl FixtureFill(wchar_t *buffer, DWORD capacity);
FIXTURE_API const wchar_t *__cdecl FixtureName(void);

#ifdef __cplusplus
}
#endif

#endif
