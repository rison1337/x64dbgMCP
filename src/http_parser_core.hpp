#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>

namespace mcphttp {

constexpr std::size_t kDefaultMaxHeaderBytes = 64u * 1024u;
constexpr std::size_t kDefaultMaxRequestBytes = 16u * 1024u * 1024u;

struct HeaderResult {
    bool ok = false;
    int status = 400;
    std::string errorCode;
    std::string errorMessage;
    std::size_t headerBytes = 0;
    std::uint64_t contentLength = 0;
    bool hasContentLength = false;
};

struct RequestResult {
    bool ok = false;
    int status = 400;
    std::string errorCode;
    std::string errorMessage;
    std::string method;
    std::string path;
    std::string query;
    std::string body;
    HeaderResult headers;
};

// Validate and inspect a complete header block.  The input must end at (or
// immediately after) CRLFCRLF; body bytes are intentionally ignored here.
HeaderResult parseHeaders(std::string_view headerBlock,
                          std::size_t maxHeaderBytes = kDefaultMaxHeaderBytes,
                          std::size_t maxRequestBytes = kDefaultMaxRequestBytes);

// Parse a complete request, including exact Content-Length/body framing and a
// strict HTTP/1.0 or HTTP/1.1 request line.  No allocation is performed for
// query/body fields until the header and framing checks have passed.
RequestResult parseRequest(std::string_view request,
                           std::size_t maxHeaderBytes = kDefaultMaxHeaderBytes,
                           std::size_t maxRequestBytes = kDefaultMaxRequestBytes);

} // namespace mcphttp
