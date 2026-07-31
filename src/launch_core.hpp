#pragma once

#include <cstddef>
#include <cstdint>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

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
    // CreateProcessW accepts at most 32,767 UTF-16 code units including the
    // terminating NUL.  Keeping the limit here makes the pure builder and the
    // eventual process-launch path share exactly the same boundary.
    constexpr size_t kMaxCreateProcessCommandLineCodeUnits = 32767;
    constexpr size_t kMaxUnicodeEnvironmentBlockCodeUnits = 32767;

    struct CommandLineBuildResult
    {
        bool ok = false;
        std::wstring commandLine;
        size_t codeUnitsIncludingNul = 0;
        size_t argumentIndex = 0;
        std::string errorCode;
        std::string error;
    };

    using CommandLineResult = CommandLineBuildResult;

    struct QuoteWindowsArgumentResult
    {
        bool ok = false;
        std::wstring quoted;
        std::string errorCode;
        std::string error;
    };

    // Apply the quoting rules used by the Microsoft C/C++ runtime argv parser.
    // The caller must reject embedded NULs before passing the result to Win32;
    // buildWindowsCommandLine performs that validation transactionally.
    std::wstring quoteWindowsCrtArgument(std::wstring_view argument);
    QuoteWindowsArgumentResult quoteWindowsArgument(std::wstring_view argument);

    // arguments excludes argv[0]; executable is emitted as argv[0].
    CommandLineBuildResult buildWindowsCommandLine(
        std::wstring_view executable,
        const std::vector<std::wstring>& arguments);

    // Preserve an already-tokenized/raw command-line tail verbatim.  The one
    // separator between argv[0] and rawTail is supplied by this function.
    CommandLineBuildResult buildWindowsCommandLine(
        std::wstring_view executable,
        std::wstring_view rawTail);

    // JSON-neutral environment mutation model.  A value means set/replace;
    // nullopt means delete.  It deliberately has no dependency on a JSON type
    // so every transport can validate into the same representation first.
    struct EnvironmentEntry
    {
        std::wstring name;
        std::optional<std::wstring> value;

        static EnvironmentEntry set(std::wstring name, std::wstring value);
        static EnvironmentEntry erase(std::wstring name);
    };

    struct EnvironmentBlockBuildResult
    {
        bool ok = false;
        std::vector<EnvironmentEntry> entries;
        std::vector<wchar_t> block;
        size_t codeUnitsIncludingFinalNuls = 0;
        size_t entryIndex = 0;
        bool overrideEntry = false;
        std::string errorCode;
        std::string error;
    };

    using EnvironmentBuildResult = EnvironmentBlockBuildResult;

    // inheritedSnapshot must contain only set entries.  overrides may set or
    // delete names.  Names are matched case-insensitively, including hidden
    // pseudo variables (=C:, =ExitCode).  Duplicate names in either input are rejected
    // rather than resolved by input order.  The result is sorted and always
    // double-NUL terminated, including an empty environment.
    EnvironmentBlockBuildResult buildUnicodeEnvironmentBlock(
        const std::vector<EnvironmentEntry>& inheritedSnapshot,
        const std::vector<EnvironmentEntry>& overrides);

    struct Base64DecodeResult
    {
        bool ok = false;
        std::vector<uint8_t> bytes;
        size_t errorOffset = 0;
        std::string errorCode;
        std::string error;
    };

    // RFC 4648 standard alphabet, no whitespace and canonical padding/bits.
    // maxDecodedBytes is checked before allocation as well as after decoding.
    Base64DecodeResult decodeBase64Strict(
        std::string_view encoded,
        size_t maxDecodedBytes);
    std::string encodeBase64(const void* data, size_t size);
    inline std::string encodeBase64(const std::vector<uint8_t>& bytes)
    {
        return encodeBase64(bytes.data(), bytes.size());
    }

    struct ByteRingReadResult
    {
        std::vector<uint8_t> bytes;
        uint64_t requestedCursor = 0;
        uint64_t effectiveCursor = 0;
        uint64_t nextCursor = 0;
        uint64_t oldestCursor = 0;
        uint64_t newestCursor = 0;
        uint64_t totalDroppedBytes = 0;
        uint64_t droppedBeforeCursor = 0;
        size_t availableBytes = 0;
        bool cursorTruncated = false;
        bool cursorAhead = false;
        bool limited = false;
        bool truncated = false;
        bool closed = false;
        bool eof = false;
    };

    // Thread-safe bounded capture storage.  A cursor is the absolute offset of
    // the next byte to read.  append() is all-or-nothing and rejects writes
    // after close or cursor overflow.  Old bytes are overwritten by design and
    // reported explicitly to readers.
    class BoundedByteRing
    {
    public:
        explicit BoundedByteRing(size_t capacity);

        BoundedByteRing(const BoundedByteRing&) = delete;
        BoundedByteRing& operator=(const BoundedByteRing&) = delete;

        bool append(const void* data, size_t size);
        bool append(std::string_view bytes);
        void close();
        void markEof() { close(); }

        ByteRingReadResult read(uint64_t cursor, size_t maxBytes) const;
        ByteRingReadResult snapshot(size_t maxBytes =
            static_cast<size_t>(-1)) const;
        size_t capacity() const noexcept;
        size_t retainedSize() const;
        uint64_t oldestCursor() const;
        uint64_t newestCursor() const;
        bool isClosed() const;

    private:
        mutable std::mutex mutex_;
        std::vector<uint8_t> storage_;
        size_t head_ = 0;
        size_t size_ = 0;
        uint64_t oldestCursor_ = 0;
        uint64_t newestCursor_ = 0;
        bool closed_ = false;
    };

#ifdef _WIN32
    inline bool isValidHandle(HANDLE handle) noexcept
    {
        return handle != nullptr && handle != INVALID_HANDLE_VALUE;
    }

    class UniqueHandle
    {
    public:
        UniqueHandle() noexcept = default;
        explicit UniqueHandle(HANDLE handle) noexcept : handle_(handle) {}
        ~UniqueHandle() noexcept;

        UniqueHandle(const UniqueHandle&) = delete;
        UniqueHandle& operator=(const UniqueHandle&) = delete;

        UniqueHandle(UniqueHandle&& other) noexcept;
        UniqueHandle& operator=(UniqueHandle&& other) noexcept;

        HANDLE get() const noexcept { return handle_; }
        explicit operator bool() const noexcept { return isValidHandle(handle_); }
        HANDLE release() noexcept;
        void reset(HANDLE replacement = nullptr) noexcept;
        void swap(UniqueHandle& other) noexcept;

    private:
        HANDLE handle_ = nullptr;
    };

    struct HandleInheritanceValidation
    {
        bool ok = false;
        std::vector<HANDLE> handles;
        size_t failingIndex = 0;
        DWORD win32Error = ERROR_SUCCESS;
        std::string errorCode;
        std::string error;
    };

    bool setHandleInheritable(HANDLE handle,
                              bool inheritable,
                              DWORD* win32Error = nullptr) noexcept;

    // PROC_THREAD_ATTRIBUTE_HANDLE_LIST requires valid, distinct handles.  If
    // requireInheritable is true, every handle must already carry
    // HANDLE_FLAG_INHERIT; this prevents an accidental broad/failing launch.
    HandleInheritanceValidation validateExplicitInheritanceList(
        const std::vector<HANDLE>& handles,
        bool requireInheritable = true);
#endif
}
