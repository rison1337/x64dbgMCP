#include "launch_core.hpp"

#include <algorithm>
#include <cstring>
#include <cwctype>
#include <limits>
#include <utility>

namespace mcplaunch
{
    namespace
    {
        bool containsNul(std::wstring_view value)
        {
            return value.find(L'\0') != std::wstring_view::npos;
        }

        bool isHiddenEnvironmentName(std::wstring_view name)
        {
            // Windows commonly emits =X: drive-current-directory entries,
            // but cmd/CMake can also publish pseudo variables such as
            // =ExitCode.  They are valid only in an explicit environment
            // block and must be preserved even though SetEnvironmentVariable
            // cannot create them.
            return name.size() > 1 && name[0] == L'=' &&
                   name.find(L'=', 1) == std::wstring_view::npos;
        }

        int compareOrdinal(std::wstring_view left,
                           std::wstring_view right,
                           bool ignoreCase)
        {
#ifdef _WIN32
            const int result = CompareStringOrdinal(
                left.data(), static_cast<int>(left.size()),
                right.data(), static_cast<int>(right.size()),
                ignoreCase ? TRUE : FALSE);
            if(result == CSTR_LESS_THAN)
                return -1;
            if(result == CSTR_GREATER_THAN)
                return 1;
            return 0;
#else
            const size_t common = std::min(left.size(), right.size());
            for(size_t index = 0; index < common; ++index)
            {
                wchar_t l = left[index];
                wchar_t r = right[index];
                if(ignoreCase)
                {
                    l = static_cast<wchar_t>(std::towupper(l));
                    r = static_cast<wchar_t>(std::towupper(r));
                }
                if(l < r)
                    return -1;
                if(l > r)
                    return 1;
            }
            if(left.size() < right.size())
                return -1;
            if(left.size() > right.size())
                return 1;
            return 0;
#endif
        }

        bool equalEnvironmentName(std::wstring_view left,
                                  std::wstring_view right)
        {
            return compareOrdinal(left, right, true) == 0;
        }

        bool validateEnvironmentEntry(const EnvironmentEntry& entry,
                                      bool allowDelete,
                                      std::string& errorCode,
                                      std::string& error)
        {
            if(entry.name.empty())
            {
                errorCode = "environment_name_empty";
                error = "environment variable name must not be empty";
                return false;
            }
            if(containsNul(entry.name))
            {
                errorCode = "environment_name_nul";
                error = "environment variable name contains NUL";
                return false;
            }
            if(entry.name.front() == L'=')
            {
                if(!isHiddenEnvironmentName(entry.name))
                {
                    errorCode = "environment_hidden_name_invalid";
                    error = "hidden environment name contains a second '=' or has no name";
                    return false;
                }
            }
            else if(entry.name.find(L'=') != std::wstring::npos)
            {
                errorCode = "environment_name_equals";
                error = "environment variable name contains '='";
                return false;
            }
            if(!entry.value)
            {
                if(!allowDelete)
                {
                    errorCode = "environment_snapshot_delete";
                    error = "inherited environment entries must have values";
                    return false;
                }
                return true;
            }
            if(containsNul(*entry.value))
            {
                errorCode = "environment_value_nul";
                error = "environment variable value contains NUL";
                return false;
            }
            return true;
        }

        bool findDuplicateName(const std::vector<EnvironmentEntry>& entries,
                               size_t current,
                               size_t& duplicate)
        {
            for(size_t index = 0; index < current; ++index)
            {
                if(equalEnvironmentName(entries[index].name,
                                        entries[current].name))
                {
                    duplicate = index;
                    return true;
                }
            }
            return false;
        }

        int base64Value(unsigned char value)
        {
            if(value >= 'A' && value <= 'Z')
                return value - 'A';
            if(value >= 'a' && value <= 'z')
                return 26 + value - 'a';
            if(value >= '0' && value <= '9')
                return 52 + value - '0';
            if(value == '+')
                return 62;
            if(value == '/')
                return 63;
            return -1;
        }
    }

    std::wstring quoteWindowsCrtArgument(std::wstring_view argument)
    {
        const bool quote = argument.empty() ||
            argument.find_first_of(L" \t\"") != std::wstring_view::npos;
        if(!quote)
            return std::wstring(argument);

        std::wstring result;
        result.reserve(argument.size() + 2);
        result.push_back(L'"');
        size_t backslashes = 0;
        for(const wchar_t value : argument)
        {
            if(value == L'\\')
            {
                ++backslashes;
                continue;
            }
            if(value == L'"')
            {
                result.append(backslashes * 2 + 1, L'\\');
                result.push_back(L'"');
                backslashes = 0;
                continue;
            }
            result.append(backslashes, L'\\');
            backslashes = 0;
            result.push_back(value);
        }
        // Backslashes immediately before the closing quote must be doubled so
        // the closing quote cannot be consumed as a literal quote.
        result.append(backslashes * 2, L'\\');
        result.push_back(L'"');
        return result;
    }

    QuoteWindowsArgumentResult quoteWindowsArgument(std::wstring_view argument)
    {
        QuoteWindowsArgumentResult result;
        if(containsNul(argument))
        {
            result.errorCode = "argument_nul";
            result.error = "command-line argument contains NUL";
            return result;
        }
        result.quoted = quoteWindowsCrtArgument(argument);
        result.ok = true;
        return result;
    }

    CommandLineBuildResult buildWindowsCommandLine(
        std::wstring_view executable,
        const std::vector<std::wstring>& arguments)
    {
        CommandLineBuildResult result;
        if(executable.empty())
        {
            result.errorCode = "executable_empty";
            result.error = "executable must not be empty";
            return result;
        }
        if(containsNul(executable))
        {
            result.errorCode = "argument_nul";
            result.error = "argv[0] contains NUL";
            return result;
        }

        result.commandLine = quoteWindowsCrtArgument(executable);
        for(size_t index = 0; index < arguments.size(); ++index)
        {
            result.argumentIndex = index + 1;
            if(containsNul(arguments[index]))
            {
                result.commandLine.clear();
                result.errorCode = "argument_nul";
                result.error = "command-line argument contains NUL";
                return result;
            }
            std::wstring encoded = quoteWindowsCrtArgument(arguments[index]);
            if(result.commandLine.size() >
               kMaxCreateProcessCommandLineCodeUnits - 1 - 1 ||
               encoded.size() > kMaxCreateProcessCommandLineCodeUnits - 1 -
                                    result.commandLine.size() - 1)
            {
                result.commandLine.clear();
                result.errorCode = "command_line_too_long";
                result.error = "CreateProcess command line exceeds 32767 UTF-16 code units";
                return result;
            }
            result.commandLine.push_back(L' ');
            result.commandLine += encoded;
        }

        result.codeUnitsIncludingNul = result.commandLine.size() + 1;
        if(result.codeUnitsIncludingNul >
           kMaxCreateProcessCommandLineCodeUnits)
        {
            result.commandLine.clear();
            result.codeUnitsIncludingNul = 0;
            result.argumentIndex = 0;
            result.errorCode = "command_line_too_long";
            result.error = "CreateProcess command line exceeds 32767 UTF-16 code units";
            return result;
        }
        result.ok = true;
        result.argumentIndex = 0;
        return result;
    }

    CommandLineBuildResult buildWindowsCommandLine(
        std::wstring_view executable,
        std::wstring_view rawTail)
    {
        CommandLineBuildResult result;
        if(executable.empty())
        {
            result.errorCode = "executable_empty";
            result.error = "executable must not be empty";
            return result;
        }
        if(containsNul(executable) || containsNul(rawTail))
        {
            result.errorCode = "argument_nul";
            result.error = "raw command line contains NUL";
            return result;
        }
        result.commandLine = quoteWindowsCrtArgument(executable);
        if(!rawTail.empty())
        {
            const size_t visibleLimit =
                kMaxCreateProcessCommandLineCodeUnits - 1;
            if(result.commandLine.size() >= visibleLimit ||
               rawTail.size() > visibleLimit - result.commandLine.size() - 1)
            {
                result.commandLine.clear();
                result.errorCode = "command_line_too_long";
                result.error = "CreateProcess command line exceeds 32767 UTF-16 code units";
                return result;
            }
            result.commandLine.push_back(L' ');
            result.commandLine.append(rawTail);
        }
        result.codeUnitsIncludingNul = result.commandLine.size() + 1;
        if(result.codeUnitsIncludingNul >
           kMaxCreateProcessCommandLineCodeUnits)
        {
            result.commandLine.clear();
            result.codeUnitsIncludingNul = 0;
            result.errorCode = "command_line_too_long";
            result.error = "CreateProcess command line exceeds 32767 UTF-16 code units";
            return result;
        }
        result.ok = true;
        return result;
    }

    EnvironmentEntry EnvironmentEntry::set(std::wstring name,
                                           std::wstring value)
    {
        return {std::move(name), std::move(value)};
    }

    EnvironmentEntry EnvironmentEntry::erase(std::wstring name)
    {
        return {std::move(name), std::nullopt};
    }

    EnvironmentBlockBuildResult buildUnicodeEnvironmentBlock(
        const std::vector<EnvironmentEntry>& inheritedSnapshot,
        const std::vector<EnvironmentEntry>& overrides)
    {
        EnvironmentBlockBuildResult result;
        for(size_t index = 0; index < inheritedSnapshot.size(); ++index)
        {
            result.entryIndex = index;
            std::string code;
            std::string error;
            if(!validateEnvironmentEntry(inheritedSnapshot[index], false,
                                         code, error))
            {
                result.errorCode = std::move(code);
                result.error = std::move(error);
                return result;
            }
            size_t duplicate = 0;
            if(findDuplicateName(inheritedSnapshot, index, duplicate))
            {
                result.errorCode = "environment_snapshot_duplicate";
                result.error = "inherited environment contains a case-insensitive duplicate name";
                return result;
            }
        }
        for(size_t index = 0; index < overrides.size(); ++index)
        {
            result.overrideEntry = true;
            result.entryIndex = index;
            std::string code;
            std::string error;
            if(!validateEnvironmentEntry(overrides[index], true, code, error))
            {
                result.errorCode = std::move(code);
                result.error = std::move(error);
                return result;
            }
            size_t duplicate = 0;
            if(findDuplicateName(overrides, index, duplicate))
            {
                result.errorCode = "environment_override_duplicate";
                result.error = "environment overrides contain a case-insensitive duplicate name";
                return result;
            }
        }

        result.entries = inheritedSnapshot;
        for(const auto& mutation : overrides)
        {
            const auto found = std::find_if(
                result.entries.begin(), result.entries.end(),
                [&](const EnvironmentEntry& existing) {
                    return equalEnvironmentName(existing.name, mutation.name);
                });
            if(!mutation.value)
            {
                if(found != result.entries.end())
                    result.entries.erase(found);
            }
            else if(found == result.entries.end())
                result.entries.push_back(mutation);
            else
                *found = mutation;
        }

        std::sort(result.entries.begin(), result.entries.end(),
                  [](const EnvironmentEntry& left,
                     const EnvironmentEntry& right) {
                      const int folded = compareOrdinal(left.name, right.name, true);
                      if(folded != 0)
                          return folded < 0;
                      return compareOrdinal(left.name, right.name, false) < 0;
                  });

        size_t required = result.entries.empty() ? 2 : 1;
        for(const auto& entry : result.entries)
        {
            const size_t valueSize = entry.value ? entry.value->size() : 0;
            if(entry.name.size() >
                   kMaxUnicodeEnvironmentBlockCodeUnits - required ||
               valueSize > kMaxUnicodeEnvironmentBlockCodeUnits - required -
                               entry.name.size() ||
               2 > kMaxUnicodeEnvironmentBlockCodeUnits - required -
                       entry.name.size() - valueSize)
            {
                result.entries.clear();
                result.errorCode = "environment_block_too_large";
                result.error = "Unicode environment block exceeds 32767 UTF-16 code units";
                return result;
            }
            // name + '=' + value + per-entry NUL.  required already contains
            // the final extra NUL for a non-empty block.
            required += entry.name.size() + 1 + valueSize + 1;
        }

        result.block.reserve(required);
        for(const auto& entry : result.entries)
        {
            result.block.insert(result.block.end(), entry.name.begin(),
                                entry.name.end());
            result.block.push_back(L'=');
            result.block.insert(result.block.end(), entry.value->begin(),
                                entry.value->end());
            result.block.push_back(L'\0');
        }
        if(result.entries.empty())
            result.block.push_back(L'\0');
        result.block.push_back(L'\0');
        result.codeUnitsIncludingFinalNuls = result.block.size();
        result.ok = true;
        result.entryIndex = 0;
        result.overrideEntry = false;
        return result;
    }

    Base64DecodeResult decodeBase64Strict(std::string_view encoded,
                                          size_t maxDecodedBytes)
    {
        Base64DecodeResult result;
        if(encoded.empty())
        {
            result.ok = true;
            return result;
        }
        if((encoded.size() & 3u) != 0)
        {
            result.errorOffset = encoded.size();
            result.errorCode = "base64_length_invalid";
            result.error = "base64 length must be a multiple of four";
            return result;
        }
        size_t padding = 0;
        if(encoded.back() == '=')
            ++padding;
        if(encoded.size() >= 2 && encoded[encoded.size() - 2] == '=')
            ++padding;
        const size_t groups = encoded.size() / 4;
        if(groups > (std::numeric_limits<size_t>::max() / 3))
        {
            result.errorCode = "base64_too_large";
            result.error = "decoded base64 length overflows size_t";
            return result;
        }
        const size_t decodedSize = groups * 3 - padding;
        if(decodedSize > maxDecodedBytes)
        {
            result.errorCode = "base64_too_large";
            result.error = "decoded base64 exceeds the configured limit";
            return result;
        }
        result.bytes.reserve(decodedSize);
        for(size_t offset = 0; offset < encoded.size(); offset += 4)
        {
            const bool finalGroup = offset + 4 == encoded.size();
            int values[4] = {};
            for(size_t index = 0; index < 4; ++index)
            {
                const unsigned char ch =
                    static_cast<unsigned char>(encoded[offset + index]);
                if(ch == '=')
                {
                    if(!finalGroup || index < 2 ||
                       (index == 2 && encoded[offset + 3] != '='))
                    {
                        result.bytes.clear();
                        result.errorOffset = offset + index;
                        result.errorCode = "base64_padding_invalid";
                        result.error = "base64 padding is not canonical";
                        return result;
                    }
                    values[index] = 0;
                    continue;
                }
                values[index] = base64Value(ch);
                if(values[index] < 0)
                {
                    result.bytes.clear();
                    result.errorOffset = offset + index;
                    result.errorCode = "base64_character_invalid";
                    result.error = "base64 contains a non-alphabet character";
                    return result;
                }
                if(finalGroup && padding != 0 &&
                   index >= 4 - padding)
                {
                    result.bytes.clear();
                    result.errorOffset = offset + index;
                    result.errorCode = "base64_padding_invalid";
                    result.error = "base64 data appears after padding";
                    return result;
                }
            }
            // Unused low bits must be zero for a unique/canonical encoding.
            if(finalGroup && padding == 2 && (values[1] & 0x0F) != 0)
            {
                result.bytes.clear();
                result.errorOffset = offset + 1;
                result.errorCode = "base64_noncanonical_bits";
                result.error = "base64 has non-zero unused bits";
                return result;
            }
            if(finalGroup && padding == 1 && (values[2] & 0x03) != 0)
            {
                result.bytes.clear();
                result.errorOffset = offset + 2;
                result.errorCode = "base64_noncanonical_bits";
                result.error = "base64 has non-zero unused bits";
                return result;
            }
            const uint32_t packed =
                (static_cast<uint32_t>(values[0]) << 18) |
                (static_cast<uint32_t>(values[1]) << 12) |
                (static_cast<uint32_t>(values[2]) << 6) |
                static_cast<uint32_t>(values[3]);
            result.bytes.push_back(static_cast<uint8_t>(packed >> 16));
            if(!finalGroup || padding < 2)
                result.bytes.push_back(static_cast<uint8_t>(packed >> 8));
            if(!finalGroup || padding == 0)
                result.bytes.push_back(static_cast<uint8_t>(packed));
        }
        result.ok = true;
        return result;
    }

    std::string encodeBase64(const void* data, size_t size)
    {
        static constexpr char alphabet[] =
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        if(size != 0 && data == nullptr)
            return {};
        const auto* bytes = static_cast<const uint8_t*>(data);
        std::string encoded;
        if(size <= (std::numeric_limits<size_t>::max() - 2) / 3)
            encoded.reserve(((size + 2) / 3) * 4);
        for(size_t offset = 0; offset < size; offset += 3)
        {
            const size_t remaining = size - offset;
            const uint32_t packed =
                (static_cast<uint32_t>(bytes[offset]) << 16) |
                (remaining > 1 ? static_cast<uint32_t>(bytes[offset + 1]) << 8 : 0) |
                (remaining > 2 ? static_cast<uint32_t>(bytes[offset + 2]) : 0);
            encoded.push_back(alphabet[(packed >> 18) & 0x3F]);
            encoded.push_back(alphabet[(packed >> 12) & 0x3F]);
            encoded.push_back(remaining > 1 ? alphabet[(packed >> 6) & 0x3F] : '=');
            encoded.push_back(remaining > 2 ? alphabet[packed & 0x3F] : '=');
        }
        return encoded;
    }

    BoundedByteRing::BoundedByteRing(size_t capacity) : storage_(capacity) {}

    bool BoundedByteRing::append(const void* data, size_t length)
    {
        if(length != 0 && data == nullptr)
            return false;
        std::lock_guard<std::mutex> lock(mutex_);
        if(closed_ || length >
              std::numeric_limits<uint64_t>::max() - newestCursor_)
            return false;
        if(length == 0)
            return true;

        const auto* input = static_cast<const uint8_t*>(data);
        const uint64_t newEnd = newestCursor_ + static_cast<uint64_t>(length);
        if(storage_.empty())
        {
            newestCursor_ = newEnd;
            oldestCursor_ = newEnd;
            head_ = 0;
            size_ = 0;
            return true;
        }

        const size_t capacityValue = storage_.size();
        if(length >= capacityValue)
        {
            std::memcpy(storage_.data(), input + (length - capacityValue),
                        capacityValue);
            head_ = 0;
            size_ = capacityValue;
            newestCursor_ = newEnd;
            oldestCursor_ = newEnd - capacityValue;
            return true;
        }

        if(size_ + length > capacityValue)
        {
            const size_t remove = size_ + length - capacityValue;
            head_ = (head_ + remove) % capacityValue;
            size_ -= remove;
            oldestCursor_ += remove;
        }
        size_t destination = (head_ + size_) % capacityValue;
        const size_t first = std::min(length, capacityValue - destination);
        std::memcpy(storage_.data() + destination, input, first);
        if(first < length)
            std::memcpy(storage_.data(), input + first, length - first);
        size_ += length;
        newestCursor_ = newEnd;
        oldestCursor_ = newestCursor_ - size_;
        return true;
    }

    bool BoundedByteRing::append(std::string_view bytes)
    {
        return append(bytes.data(), bytes.size());
    }

    void BoundedByteRing::close()
    {
        std::lock_guard<std::mutex> lock(mutex_);
        closed_ = true;
    }

    ByteRingReadResult BoundedByteRing::read(uint64_t cursor,
                                             size_t maxBytes) const
    {
        std::lock_guard<std::mutex> lock(mutex_);
        ByteRingReadResult result;
        result.requestedCursor = cursor;
        result.oldestCursor = oldestCursor_;
        result.newestCursor = newestCursor_;
        result.totalDroppedBytes = oldestCursor_;
        result.closed = closed_;

        if(cursor < oldestCursor_)
        {
            result.cursorTruncated = true;
            result.droppedBeforeCursor = oldestCursor_ - cursor;
            result.effectiveCursor = oldestCursor_;
        }
        else if(cursor > newestCursor_)
        {
            result.cursorAhead = true;
            result.effectiveCursor = newestCursor_;
        }
        else
            result.effectiveCursor = cursor;

        const uint64_t available64 = newestCursor_ - result.effectiveCursor;
        result.availableBytes = static_cast<size_t>(available64);
        const size_t take = std::min(maxBytes, result.availableBytes);
        result.bytes.resize(take);
        if(take != 0)
        {
            const size_t offset = static_cast<size_t>(
                result.effectiveCursor - oldestCursor_);
            const size_t source = (head_ + offset) % storage_.size();
            const size_t first = std::min(take, storage_.size() - source);
            std::memcpy(result.bytes.data(), storage_.data() + source, first);
            if(first < take)
                std::memcpy(result.bytes.data() + first, storage_.data(),
                            take - first);
        }
        result.nextCursor = result.effectiveCursor + take;
        result.limited = take < result.availableBytes;
        result.truncated = result.cursorTruncated || result.limited;
        result.eof = closed_ && result.nextCursor == newestCursor_;
        return result;
    }

    ByteRingReadResult BoundedByteRing::snapshot(size_t maxBytes) const
    {
        return read(0, maxBytes);
    }

    size_t BoundedByteRing::capacity() const noexcept
    {
        return storage_.size();
    }

    size_t BoundedByteRing::retainedSize() const
    {
        std::lock_guard<std::mutex> lock(mutex_);
        return size_;
    }

    uint64_t BoundedByteRing::oldestCursor() const
    {
        std::lock_guard<std::mutex> lock(mutex_);
        return oldestCursor_;
    }

    uint64_t BoundedByteRing::newestCursor() const
    {
        std::lock_guard<std::mutex> lock(mutex_);
        return newestCursor_;
    }

    bool BoundedByteRing::isClosed() const
    {
        std::lock_guard<std::mutex> lock(mutex_);
        return closed_;
    }

#ifdef _WIN32
    UniqueHandle::~UniqueHandle() noexcept
    {
        reset();
    }

    UniqueHandle::UniqueHandle(UniqueHandle&& other) noexcept
        : handle_(other.release())
    {
    }

    UniqueHandle& UniqueHandle::operator=(UniqueHandle&& other) noexcept
    {
        if(this != &other)
            reset(other.release());
        return *this;
    }

    HANDLE UniqueHandle::release() noexcept
    {
        HANDLE released = handle_;
        handle_ = nullptr;
        return released;
    }

    void UniqueHandle::reset(HANDLE replacement) noexcept
    {
        if(handle_ == replacement)
            return;
        if(isValidHandle(handle_))
            CloseHandle(handle_);
        handle_ = replacement;
    }

    void UniqueHandle::swap(UniqueHandle& other) noexcept
    {
        std::swap(handle_, other.handle_);
    }

    bool setHandleInheritable(HANDLE handle,
                              bool inheritable,
                              DWORD* win32Error) noexcept
    {
        if(win32Error)
            *win32Error = ERROR_SUCCESS;
        if(!isValidHandle(handle))
        {
            if(win32Error)
                *win32Error = ERROR_INVALID_HANDLE;
            return false;
        }
        if(SetHandleInformation(handle, HANDLE_FLAG_INHERIT,
                                inheritable ? HANDLE_FLAG_INHERIT : 0))
            return true;
        if(win32Error)
            *win32Error = GetLastError();
        return false;
    }

    HandleInheritanceValidation validateExplicitInheritanceList(
        const std::vector<HANDLE>& handles,
        bool requireInheritable)
    {
        HandleInheritanceValidation result;
        result.handles.reserve(handles.size());
        for(size_t index = 0; index < handles.size(); ++index)
        {
            result.failingIndex = index;
            if(!isValidHandle(handles[index]))
            {
                result.win32Error = ERROR_INVALID_HANDLE;
                result.errorCode = "inheritance_handle_invalid";
                result.error = "explicit inheritance list contains an invalid handle";
                return result;
            }
            if(std::find(result.handles.begin(), result.handles.end(),
                         handles[index]) != result.handles.end())
            {
                result.win32Error = ERROR_INVALID_PARAMETER;
                result.errorCode = "inheritance_handle_duplicate";
                result.error = "explicit inheritance list contains a duplicate handle";
                return result;
            }
            DWORD flags = 0;
            if(!GetHandleInformation(handles[index], &flags))
            {
                result.win32Error = GetLastError();
                result.errorCode = "inheritance_handle_query_failed";
                result.error = "GetHandleInformation failed for an explicit inherited handle";
                return result;
            }
            if(requireInheritable && !(flags & HANDLE_FLAG_INHERIT))
            {
                result.win32Error = ERROR_INVALID_PARAMETER;
                result.errorCode = "inheritance_handle_not_inheritable";
                result.error = "explicit inherited handle does not have HANDLE_FLAG_INHERIT";
                return result;
            }
            result.handles.push_back(handles[index]);
        }
        result.ok = true;
        result.failingIndex = 0;
        result.win32Error = ERROR_SUCCESS;
        return result;
    }
#endif
}
