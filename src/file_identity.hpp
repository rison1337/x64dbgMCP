#pragma once

#include <array>
#include <cstdint>
#include <string>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#endif

namespace mcplaunch
{
#ifdef _WIN32
    struct FileIdentityResult
    {
        bool ok = false;
        std::wstring finalPath;
        std::string sha256;
        uint64_t size = 0;
        uint64_t volumeSerialNumber = 0;
        std::array<uint8_t, 16> fileId{};
        DWORD win32Error = ERROR_SUCCESS;
        std::string errorCode;
        std::string error;
    };

    // Both functions hash an independently opened file object.  They never
    // change the caller's file pointer, which is required for x64dbg's
    // CREATE_PROCESS_DEBUG_INFO::hFile ownership contract.
    FileIdentityResult identifyFileByPath(const std::wstring& path) noexcept;
    FileIdentityResult identifyFileByHandle(HANDLE handle) noexcept;
#endif
}
