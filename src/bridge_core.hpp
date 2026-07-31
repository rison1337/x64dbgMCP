#pragma once

#include <cstddef>
#include <cstdint>
#include <functional>
#include <string>
#include <string_view>
#include <vector>

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <winsock2.h>

namespace mcpbridge
{
    struct HexParseResult
    {
        bool ok = false;
        std::vector<unsigned char> bytes;
        std::string error;
        size_t errorOffset = 0;
    };

    // Parse a canonical, contiguous hexadecimal byte string. The function is
    // deliberately all-or-nothing: bytes is empty on every failure path.
    HexParseResult parseHexExact(std::string_view text, size_t maxBytes);

    bool parseUnsignedDecimalExact(std::string_view text, uint64_t& value);

    // Parse one TCP port using the exact environment/configuration contract:
    // ASCII decimal digits only, with no sign or whitespace, in [1, 65535].
    // port is reset to zero on every failure path.
    bool parseTcpPortExact(std::string_view text, uint16_t& port);

    // Parse a listener configuration value. The explicit value 0 requests an
    // OS-assigned ephemeral loopback port; every other accepted value is in
    // [1, 65535]. This is separate from parseTcpPortExact because zero is never
    // a valid advertised/bound peer port. configuredPort becomes -1 on error.
    bool parseListenPortExact(std::string_view text, int& configuredPort);

    // Compare secrets without data-dependent early exits. requiredLength=0
    // accepts any equal non-empty length; otherwise both inputs must match it.
    bool constantTimeEqual(std::string_view left,
                           std::string_view right,
                           size_t requiredLength = 0) noexcept;

    struct CommandTokenResult
    {
        bool ok = false;
        std::string encoded;
        std::string error;
        size_t errorOffset = 0;
    };

    // Encode one x64dbg command-parser token. Some byte sequences are not
    // losslessly representable by the upstream parser; those fail closed.
    CommandTokenResult encodeX64dbgCommandToken(std::string_view value,
                                                bool finalToken);

    using SendOperation = std::function<int(const char* data, int length, int& error)>;

    // Testable core for sendAllSocket. sendOperation must return a positive byte
    // count, 0 for an orderly close, or SOCKET_ERROR and populate error.
    bool sendAllUsing(const char* data,
                      size_t size,
                      const SendOperation& sendOperation,
                      int* finalError = nullptr);

    bool sendAllSocket(SOCKET socket,
                       const char* data,
                       size_t size,
                       int* finalError = nullptr);

    std::string createGuidString();
}
