#include "http_parser_core.hpp"

#include <algorithm>
#include <cctype>
#include <limits>

namespace mcphttp {
namespace {

void fail(HeaderResult& result, int status, const char* code, const char* message)
{
    result.ok = false;
    result.status = status;
    result.errorCode = code ? code : "malformed_request";
    result.errorMessage = message ? message : "Malformed HTTP request";
}

void fail(RequestResult& result, int status, const char* code, const char* message)
{
    result.ok = false;
    result.status = status;
    result.errorCode = code ? code : "malformed_request";
    result.errorMessage = message ? message : "Malformed HTTP request";
}

bool isTokenChar(unsigned char ch)
{
    if(std::isalnum(ch)) return true;
    switch(ch)
    {
    case '!': case '#': case '$': case '%': case '&': case '\'':
    case '*': case '+': case '-': case '.': case '^': case '_':
    case '`': case '|': case '~':
        return true;
    default:
        return false;
    }
}

bool hasControl(std::string_view value)
{
    for(unsigned char ch : value)
    {
        if(ch == '\t') continue;
        if(ch < 0x20u || ch == 0x7Fu) return true;
    }
    return false;
}

std::string trimOws(std::string_view value)
{
    std::size_t first = 0;
    while(first < value.size() && (value[first] == ' ' || value[first] == '\t')) ++first;
    std::size_t last = value.size();
    while(last > first && (value[last - 1] == ' ' || value[last - 1] == '\t')) --last;
    return std::string(value.substr(first, last - first));
}

bool equalsInsensitive(std::string_view left, std::string_view right)
{
    if(left.size() != right.size()) return false;
    for(std::size_t i = 0; i < left.size(); ++i)
    {
        if(std::tolower(static_cast<unsigned char>(left[i]))
            != std::tolower(static_cast<unsigned char>(right[i]))) return false;
    }
    return true;
}

bool parseUnsignedDecimal(std::string_view text, std::uint64_t& value)
{
    if(text.empty()) return false;
    std::uint64_t parsed = 0;
    for(unsigned char ch : text)
    {
        if(ch < '0' || ch > '9') return false;
        const std::uint64_t digit = static_cast<std::uint64_t>(ch - '0');
        if(parsed > (std::numeric_limits<std::uint64_t>::max() - digit) / 10u) return false;
        parsed = parsed * 10u + digit;
    }
    value = parsed;
    return true;
}

bool parseRequestLine(std::string_view line, std::string& method,
                      std::string& target)
{
    const std::size_t firstSpace = line.find(' ');
    if(firstSpace == std::string_view::npos || firstSpace == 0) return false;
    const std::size_t secondSpace = line.find(' ', firstSpace + 1);
    if(secondSpace == std::string_view::npos || secondSpace == firstSpace + 1) return false;
    if(line.find(' ', secondSpace + 1) != std::string_view::npos) return false;
    const std::string_view version = line.substr(secondSpace + 1);
    if(version != "HTTP/1.0" && version != "HTTP/1.1") return false;
    const std::string_view methodView = line.substr(0, firstSpace);
    for(unsigned char ch : methodView)
    {
        if(!isTokenChar(ch) || std::islower(ch)) return false;
    }
    const std::string_view targetView = line.substr(firstSpace + 1, secondSpace - firstSpace - 1);
    if(targetView.empty() || targetView.front() != '/' || hasControl(targetView)) return false;
    if(targetView.find('\0') != std::string_view::npos) return false;
    method.assign(methodView);
    target.assign(targetView);
    return true;
}

} // namespace

HeaderResult parseHeaders(std::string_view headerBlock,
                          std::size_t maxHeaderBytes,
                          std::size_t maxRequestBytes)
{
    HeaderResult result;
    const std::size_t marker = headerBlock.find("\r\n\r\n");
    if(marker == std::string_view::npos)
    {
        fail(result, 400, "headers_incomplete", "HTTP headers are incomplete");
        return result;
    }
    result.headerBytes = marker + 4u;
    if(result.headerBytes > maxHeaderBytes)
    {
        fail(result, 431, "headers_too_large", "HTTP headers exceed the configured limit");
        return result;
    }
    if(result.headerBytes > maxRequestBytes)
    {
        fail(result, 413, "request_too_large", "HTTP request exceeds the configured limit");
        return result;
    }
    // Include the CRLF terminating the final header line; the second CRLF is
    // the empty-line marker and is intentionally excluded from the scan.
    const std::string_view head = headerBlock.substr(0, marker + 2u);
    const std::size_t firstEnd = head.find("\r\n");
    if(firstEnd == std::string_view::npos)
    {
        fail(result, 400, "request_line_missing", "HTTP request line is missing");
        return result;
    }
    std::string method;
    std::string target;
    if(!parseRequestLine(head.substr(0, firstEnd), method, target))
    {
        fail(result, 400, "malformed_request_line", "Malformed HTTP request line");
        return result;
    }
    std::size_t lineStart = firstEnd + 2u;
    while(lineStart < head.size())
    {
        const std::size_t lineEnd = head.find("\r\n", lineStart);
        if(lineEnd == std::string_view::npos || lineEnd == lineStart)
        {
            fail(result, 400, "malformed_header_line", "Malformed HTTP header line");
            return result;
        }
        const std::string_view line = head.substr(lineStart, lineEnd - lineStart);
        const std::size_t colon = line.find(':');
        if(colon == std::string_view::npos || colon == 0)
        {
            fail(result, 400, "malformed_header_line", "Malformed HTTP header line");
            return result;
        }
        const std::string_view name = line.substr(0, colon);
        for(unsigned char ch : name)
        {
            if(!isTokenChar(ch))
            {
                fail(result, 400, "invalid_header_name", "HTTP header name contains an invalid character");
                return result;
            }
        }
        const std::string value = trimOws(line.substr(colon + 1));
        if(hasControl(value))
        {
            fail(result, 400, "invalid_header_value", "HTTP header value contains a control character");
            return result;
        }
        if(equalsInsensitive(name, "transfer-encoding"))
        {
            fail(result, 400, "transfer_encoding_unsupported",
                 "Transfer-Encoding is unsupported; use Content-Length");
            return result;
        }
        if(equalsInsensitive(name, "content-length"))
        {
            if(result.hasContentLength)
            {
                fail(result, 400, "duplicate_content_length", "duplicate Content-Length header");
                return result;
            }
            if(!parseUnsignedDecimal(value, result.contentLength))
            {
                fail(result, 400, "invalid_content_length",
                     "Content-Length must be an unsigned decimal integer");
                return result;
            }
            result.hasContentLength = true;
        }
        lineStart = lineEnd + 2u;
    }
    result.ok = true;
    result.status = 200;
    return result;
}

RequestResult parseRequest(std::string_view request,
                           std::size_t maxHeaderBytes,
                           std::size_t maxRequestBytes)
{
    RequestResult result;
    if(request.size() > maxRequestBytes)
    {
        fail(result, 413, "request_too_large", "HTTP request exceeds the configured limit");
        return result;
    }
    const std::size_t marker = request.find("\r\n\r\n");
    if(marker == std::string_view::npos)
    {
        fail(result, 400, "headers_incomplete", "HTTP headers are incomplete");
        return result;
    }
    result.headers = parseHeaders(request.substr(0, marker + 4u), maxHeaderBytes, maxRequestBytes);
    if(!result.headers.ok)
    {
        fail(result, result.headers.status, result.headers.errorCode.c_str(),
             result.headers.errorMessage.c_str());
        return result;
    }
    const std::string_view head = request.substr(0, marker + 2u);
    const std::size_t firstEnd = head.find("\r\n");
    std::string target;
    if(!parseRequestLine(head.substr(0, firstEnd), result.method, target))
    {
        fail(result, 400, "malformed_request_line", "Malformed HTTP request line");
        return result;
    }
    const std::size_t queryStart = target.find('?');
    if(queryStart == std::string::npos)
        result.path = target;
    else
    {
        result.path = target.substr(0, queryStart);
        result.query = target.substr(queryStart + 1);
    }
    const std::size_t bodyStart = marker + 4u;
    if(!result.headers.hasContentLength)
    {
        if(request.size() != bodyStart)
        {
            fail(result, 400, "body_length_required", "request body requires Content-Length");
            return result;
        }
    }
    else
    {
        if(result.headers.contentLength > maxRequestBytes
            || bodyStart > maxRequestBytes
            || result.headers.contentLength > maxRequestBytes - bodyStart)
        {
            fail(result, 413, "request_too_large", "HTTP request body exceeds the configured limit");
            return result;
        }
        const std::size_t expected = bodyStart + static_cast<std::size_t>(result.headers.contentLength);
        if(request.size() < expected)
        {
            fail(result, 400, "body_incomplete", "connection ended before Content-Length bytes arrived");
            return result;
        }
        if(request.size() > expected)
        {
            fail(result, 400, "trailing_bytes", "unexpected bytes after the declared HTTP request body");
            return result;
        }
    }
    result.body.assign(request.substr(bodyStart));
    result.ok = true;
    result.status = 200;
    return result;
}

} // namespace mcphttp
