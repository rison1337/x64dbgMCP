#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include "bridge_core.hpp"

#include <Windows.h>
#include <objbase.h>

#include <algorithm>
#include <climits>
#include <limits>
#include <sstream>

namespace mcpbridge
{
    static int hexNibble(unsigned char ch)
    {
        if(ch >= '0' && ch <= '9')
            return ch - '0';
        if(ch >= 'a' && ch <= 'f')
            return ch - 'a' + 10;
        if(ch >= 'A' && ch <= 'F')
            return ch - 'A' + 10;
        return -1;
    }

    HexParseResult parseHexExact(std::string_view text, size_t maxBytes)
    {
        HexParseResult result;
        if(text.empty())
        {
            result.error = "hex payload is empty";
            return result;
        }
        if((text.size() & 1u) != 0)
        {
            result.error = "hex payload must contain an even number of characters";
            result.errorOffset = text.size() - 1;
            return result;
        }
        const size_t byteCount = text.size() / 2u;
        if(byteCount > maxBytes)
        {
            result.error = "hex payload exceeds the configured byte limit";
            result.errorOffset = maxBytes * 2u;
            return result;
        }

        std::vector<unsigned char> parsed;
        parsed.resize(byteCount);
        for(size_t i = 0; i < text.size(); i += 2u)
        {
            const int high = hexNibble(static_cast<unsigned char>(text[i]));
            if(high < 0)
            {
                result.error = "hex payload contains a non-hexadecimal character";
                result.errorOffset = i;
                return result;
            }
            const int low = hexNibble(static_cast<unsigned char>(text[i + 1u]));
            if(low < 0)
            {
                result.error = "hex payload contains a non-hexadecimal character";
                result.errorOffset = i + 1u;
                return result;
            }
            parsed[i / 2u] = static_cast<unsigned char>((high << 4) | low);
        }

        result.ok = true;
        result.bytes = std::move(parsed);
        return result;
    }

    bool parseUnsignedDecimalExact(std::string_view text, uint64_t& value)
    {
        value = 0;
        if(text.empty())
            return false;
        uint64_t parsed = 0;
        for(const unsigned char ch : text)
        {
            if(ch < '0' || ch > '9')
                return false;
            const uint64_t digit = ch - '0';
            if(parsed > (std::numeric_limits<uint64_t>::max() - digit) / 10u)
                return false;
            parsed = parsed * 10u + digit;
        }
        value = parsed;
        return true;
    }

    bool parseTcpPortExact(std::string_view text, uint16_t& port)
    {
        port = 0;
        uint64_t parsed = 0;
        if(!parseUnsignedDecimalExact(text, parsed)
            || parsed == 0
            || parsed > std::numeric_limits<uint16_t>::max())
        {
            return false;
        }
        port = static_cast<uint16_t>(parsed);
        return true;
    }

    bool parseListenPortExact(std::string_view text, int& configuredPort)
    {
        configuredPort = -1;
        uint64_t parsed = 0;
        if(!parseUnsignedDecimalExact(text, parsed)
            || parsed > std::numeric_limits<uint16_t>::max())
        {
            return false;
        }
        configuredPort = static_cast<int>(parsed);
        return true;
    }

    bool constantTimeEqual(std::string_view left,
                           std::string_view right,
                           size_t requiredLength) noexcept
    {
        const size_t compareLength = std::max(left.size(), right.size());
        volatile unsigned int difference =
            static_cast<unsigned int>(left.size() ^ right.size());
        if(requiredLength != 0)
            difference |= static_cast<unsigned int>(left.size() ^ requiredLength)
                | static_cast<unsigned int>(right.size() ^ requiredLength);
        if(compareLength == 0)
            difference |= 1u;
        for(size_t index = 0; index < compareLength; ++index)
        {
            const unsigned char leftByte = index < left.size()
                ? static_cast<unsigned char>(left[index]) : 0;
            const unsigned char rightByte = index < right.size()
                ? static_cast<unsigned char>(right[index]) : 0;
            difference |= static_cast<unsigned int>(leftByte ^ rightByte);
        }
        return difference == 0;
    }

    CommandTokenResult encodeX64dbgCommandToken(std::string_view value,
                                                bool finalToken)
    {
        CommandTokenResult result;
        for(size_t i = 0; i < value.size(); ++i)
        {
            const unsigned char ch = static_cast<unsigned char>(value[i]);
            if(ch == 0 || ch == '\r' || ch == '\n')
            {
                result.error = "command token contains a forbidden control character";
                result.errorOffset = i;
                return result;
            }
            if(ch == '{' || ch == '}')
            {
                result.error = "command token contains braces that invoke x64dbg string formatting";
                result.errorOffset = i;
                return result;
            }
            if(ch == '\\' && i + 1u < value.size()
                && (value[i + 1u] == '"' || value[i + 1u] == '{'))
            {
                result.error = "command token contains an upstream parser-ambiguous escape sequence";
                result.errorOffset = i;
                return result;
            }
        }
        const bool trailingBackslash = !value.empty() && value.back() == '\\';
        if(trailingBackslash && !finalToken)
        {
            result.error = "a non-final x64dbg command token cannot end in a backslash";
            result.errorOffset = value.size() - 1u;
            return result;
        }

        result.encoded.push_back('"');
        const size_t quotedSize = trailingBackslash ? value.size() - 1u : value.size();
        for(size_t i = 0; i < quotedSize; ++i)
        {
            if(value[i] == '"')
                result.encoded.push_back('\\');
            result.encoded.push_back(value[i]);
        }
        result.encoded.push_back('"');
        if(trailingBackslash)
            result.encoded.push_back('\\');
        result.ok = true;
        return result;
    }

    bool sendAllUsing(const char* data,
                      size_t size,
                      const SendOperation& sendOperation,
                      int* finalError)
    {
        if(finalError)
            *finalError = 0;
        if((!data && size != 0) || !sendOperation)
        {
            if(finalError)
                *finalError = WSAEINVAL;
            return false;
        }

        size_t offset = 0;
        while(offset < size)
        {
            const size_t remaining = size - offset;
            const int chunk = static_cast<int>(std::min<size_t>(remaining, INT_MAX));
            int error = 0;
            const int sent = sendOperation(data + offset, chunk, error);
            if(sent == SOCKET_ERROR)
            {
                if(error == WSAEINTR)
                    continue;
                if(finalError)
                    *finalError = error;
                return false;
            }
            if(sent <= 0 || sent > chunk)
            {
                if(finalError)
                    *finalError = sent > chunk ? WSAEINVAL : WSAECONNRESET;
                return false;
            }
            offset += static_cast<size_t>(sent);
        }
        return true;
    }

    bool sendAllSocket(SOCKET socket, const char* data, size_t size, int* finalError)
    {
        return sendAllUsing(
            data,
            size,
            [socket](const char* current, int length, int& error) {
                const int sent = send(socket, current, length, 0);
                error = sent == SOCKET_ERROR ? WSAGetLastError() : 0;
                return sent;
            },
            finalError);
    }

    std::string createGuidString()
    {
        GUID guid = {};
        if(FAILED(CoCreateGuid(&guid)))
            return {};
        char text[40] = {};
        const int written = snprintf(
            text,
            sizeof(text),
            "%08lx-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x",
            static_cast<unsigned long>(guid.Data1),
            static_cast<unsigned int>(guid.Data2),
            static_cast<unsigned int>(guid.Data3),
            static_cast<unsigned int>(guid.Data4[0]),
            static_cast<unsigned int>(guid.Data4[1]),
            static_cast<unsigned int>(guid.Data4[2]),
            static_cast<unsigned int>(guid.Data4[3]),
            static_cast<unsigned int>(guid.Data4[4]),
            static_cast<unsigned int>(guid.Data4[5]),
            static_cast<unsigned int>(guid.Data4[6]),
            static_cast<unsigned int>(guid.Data4[7]));
        return written > 0 ? std::string(text, static_cast<size_t>(written)) : std::string();
    }
}
