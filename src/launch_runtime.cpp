#include "launch_runtime.hpp"

#ifdef _WIN32

#include <algorithm>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cerrno>
#include <cstring>
#include <cwchar>
#include <deque>
#include <iomanip>
#include <limits>
#include <mutex>
#include <new>
#include <process.h>
#include <sstream>
#include <utility>

namespace mcplaunch
{
    namespace
    {
        static_assert(alignof(std::max_align_t) >= alignof(void*),
                      "process attribute storage must be pointer-aligned");

        constexpr DWORD kOwnedProcessExitCode = 0xC000013Au;
        constexpr size_t kPipeTransferSize = 64u * 1024u;
        constexpr DWORD kDefaultTeardownTimeoutMs = 5000u;

        DWORD boundedTeardownTimeout(DWORD timeoutMs) noexcept
        {
            return timeoutMs == INFINITE
                ? kDefaultTeardownTimeoutMs : timeoutMs;
        }

        bool containsNul(const std::wstring& value)
        {
            return value.find(L'\0') != std::wstring::npos;
        }

        std::string utf8FromWide(const std::wstring& value)
        {
            if(value.empty())
                return {};
            const int required = WideCharToMultiByte(
                CP_UTF8, WC_ERR_INVALID_CHARS, value.data(),
                static_cast<int>(value.size()), nullptr, 0, nullptr, nullptr);
            if(required <= 0)
                return {};
            std::string result(static_cast<size_t>(required), '\0');
            if(WideCharToMultiByte(
                   CP_UTF8, WC_ERR_INVALID_CHARS, value.data(),
                   static_cast<int>(value.size()), result.data(), required,
                   nullptr, nullptr) != required)
                return {};
            return result;
        }

        std::string describeWin32Error(DWORD error)
        {
            if(error == ERROR_SUCCESS)
                return {};
            wchar_t* allocated = nullptr;
            const DWORD flags = FORMAT_MESSAGE_ALLOCATE_BUFFER |
                                FORMAT_MESSAGE_FROM_SYSTEM |
                                FORMAT_MESSAGE_IGNORE_INSERTS;
            const DWORD length = FormatMessageW(
                flags, nullptr, error,
                MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
                reinterpret_cast<wchar_t*>(&allocated), 0, nullptr);
            std::wstring message;
            if(length && allocated)
            {
                message.assign(allocated, allocated + length);
                while(!message.empty() &&
                      (message.back() == L'\r' || message.back() == L'\n' ||
                       message.back() == L' ' || message.back() == L'\t'))
                    message.pop_back();
            }
            if(allocated)
                LocalFree(allocated);
            std::string converted = utf8FromWide(message);
            if(!converted.empty())
                return converted;
            return "Win32 error " + std::to_string(error);
        }

        RuntimeError runtimeError(std::string code,
                                  std::string message,
                                  DWORD win32Error = ERROR_SUCCESS,
                                  StandardStream stream = StandardStream::None,
                                  bool retryable = false)
        {
            RuntimeError result;
            result.code = std::move(code);
            result.message = std::move(message);
            result.win32Error = win32Error;
            result.stream = stream;
            result.retryable = retryable;
            if(win32Error != ERROR_SUCCESS)
            {
                const std::string detail = describeWin32Error(win32Error);
                if(!detail.empty())
                {
                    if(!result.message.empty())
                        result.message += ": ";
                    result.message += detail;
                }
            }
            return result;
        }

        RuntimeError allocationError()
        {
            return runtimeError("allocation_failed",
                                "memory allocation failed while preparing the launch");
        }

        uint64_t fileTimeValue(const FILETIME& value) noexcept
        {
            ULARGE_INTEGER combined{};
            combined.LowPart = value.dwLowDateTime;
            combined.HighPart = value.dwHighDateTime;
            return combined.QuadPart;
        }

        std::string makeLaunchId(DWORD processId, uint64_t creationTime)
        {
            static std::atomic<uint64_t> counter{0};
            LARGE_INTEGER ticks{};
            QueryPerformanceCounter(&ticks);
            const uint64_t sequence = counter.fetch_add(1,
                std::memory_order_relaxed) + 1;
            std::ostringstream stream;
            stream << std::hex << std::uppercase << std::setfill('0')
                   << std::setw(16) << creationTime << '-'
                   << std::setw(8) << processId << '-'
                   << std::setw(16) << sequence << '-'
                   << std::setw(16)
                   << static_cast<uint64_t>(ticks.QuadPart);
            return stream.str();
        }

        bool captureCurrentEnvironment(
            std::vector<EnvironmentEntry>& snapshot,
            RuntimeError& error)
        {
            LPWCH block = GetEnvironmentStringsW();
            if(!block)
            {
                const DWORD code = GetLastError();
                error = runtimeError("environment_snapshot_failed",
                    "GetEnvironmentStringsW failed", code);
                return false;
            }

            struct EnvironmentGuard
            {
                LPWCH value;
                ~EnvironmentGuard() { FreeEnvironmentStringsW(value); }
            } guard{block};

            for(const wchar_t* current = block; *current != L'\0';)
            {
                const size_t length = std::wcslen(current);
                const std::wstring entry(current, length);
                const size_t separator = entry.empty()
                    ? std::wstring::npos
                    : entry.find(L'=', entry.front() == L'=' ? 1u : 0u);
                if(separator == std::wstring::npos || separator == 0)
                {
                    error = runtimeError("environment_snapshot_malformed",
                        "the process environment contains a malformed entry");
                    return false;
                }
                snapshot.push_back(EnvironmentEntry::set(
                    entry.substr(0, separator), entry.substr(separator + 1)));
                current += length + 1;
            }
            return true;
        }

        bool validateInputSpec(const InputSpec& spec, RuntimeError& error)
        {
            if(spec.mode == StdioMode::File)
            {
                if(spec.filePath.empty())
                {
                    error = runtimeError("stdin_file_path_empty",
                        "stdin file mode requires a non-empty path",
                        ERROR_SUCCESS, StandardStream::Stdin);
                    return false;
                }
                if(containsNul(spec.filePath))
                {
                    error = runtimeError("stdin_file_path_nul",
                        "stdin file path contains NUL", ERROR_SUCCESS,
                        StandardStream::Stdin);
                    return false;
                }
            }
            else if(!spec.filePath.empty())
            {
                error = runtimeError("stdin_file_path_unexpected",
                    "stdin filePath is valid only in file mode",
                    ERROR_SUCCESS, StandardStream::Stdin);
                return false;
            }

            if(spec.mode != StdioMode::Bytes && !spec.initialBytes.empty())
            {
                error = runtimeError("stdin_bytes_unexpected",
                    "stdin initialBytes is valid only in bytes mode",
                    ERROR_SUCCESS, StandardStream::Stdin);
                return false;
            }
            return true;
        }

        bool validateOutputSpec(const OutputSpec& spec,
                                StandardStream stream,
                                RuntimeError& error)
        {
            if(spec.mode == StdioMode::Bytes)
            {
                error = runtimeError("output_bytes_mode_invalid",
                    "bytes mode is valid only for stdin", ERROR_SUCCESS,
                    stream);
                return false;
            }
            if(spec.mode == StdioMode::File)
            {
                if(spec.filePath.empty())
                {
                    error = runtimeError("output_file_path_empty",
                        "output file mode requires a non-empty path",
                        ERROR_SUCCESS, stream);
                    return false;
                }
                if(containsNul(spec.filePath))
                {
                    error = runtimeError("output_file_path_nul",
                        "output file path contains NUL", ERROR_SUCCESS,
                        stream);
                    return false;
                }
            }
            else if(!spec.filePath.empty())
            {
                error = runtimeError("output_file_path_unexpected",
                    "output filePath is valid only in file mode",
                    ERROR_SUCCESS, stream);
                return false;
            }
            return true;
        }

        bool normalizedFullPath(const std::wstring& path,
                                std::wstring& normalized,
                                RuntimeError& error)
        {
            DWORD required = GetFullPathNameW(path.c_str(), 0, nullptr,
                                              nullptr);
            if(required == 0)
            {
                const DWORD code = GetLastError();
                error = runtimeError("output_path_normalize_failed",
                    "GetFullPathNameW failed for an output path", code);
                return false;
            }
            std::vector<wchar_t> buffer(static_cast<size_t>(required));
            const DWORD written = GetFullPathNameW(path.c_str(), required,
                                                   buffer.data(), nullptr);
            if(written == 0 || written >= required)
            {
                const DWORD code = written == 0 ? GetLastError()
                                                : ERROR_INSUFFICIENT_BUFFER;
                error = runtimeError("output_path_normalize_failed",
                    "GetFullPathNameW failed for an output path", code);
                return false;
            }
            normalized.assign(buffer.data(), written);
            std::replace(normalized.begin(), normalized.end(), L'/', L'\\');
            return true;
        }

        bool equalPathInsensitive(const std::wstring& left,
                                  const std::wstring& right)
        {
            return CompareStringOrdinal(
                       left.data(), static_cast<int>(left.size()),
                       right.data(), static_cast<int>(right.size()), TRUE) ==
                   CSTR_EQUAL;
        }

        bool validateSpec(const LaunchSpec& spec, RuntimeError& error)
        {
            if(spec.executable.empty())
            {
                error = runtimeError("executable_empty",
                    "executable must not be empty");
                return false;
            }
            if(containsNul(spec.executable))
            {
                error = runtimeError("executable_nul",
                    "executable contains NUL");
                return false;
            }
            if(spec.rawCommandLineTail && !spec.arguments.empty())
            {
                error = runtimeError("command_line_mode_conflict",
                    "arguments and rawCommandLineTail are mutually exclusive");
                return false;
            }
            if(spec.workingDirectory)
            {
                if(spec.workingDirectory->empty())
                {
                    error = runtimeError("working_directory_empty",
                        "workingDirectory must be absent or non-empty");
                    return false;
                }
                if(containsNul(*spec.workingDirectory))
                {
                    error = runtimeError("working_directory_nul",
                        "workingDirectory contains NUL");
                    return false;
                }
            }
            if(!spec.inheritEnvironment &&
               spec.inheritedEnvironmentSnapshot)
            {
                error = runtimeError("environment_source_conflict",
                    "an inherited environment snapshot requires inheritEnvironment=true");
                return false;
            }
            if(!validateInputSpec(spec.stdinSpec, error) ||
               !validateOutputSpec(spec.stdoutSpec, StandardStream::Stdout,
                                   error) ||
               !validateOutputSpec(spec.stderrSpec, StandardStream::Stderr,
                                   error))
                return false;

            if(spec.stdoutSpec.mode == StdioMode::File &&
               spec.stderrSpec.mode == StdioMode::File)
            {
                std::wstring stdoutPath;
                std::wstring stderrPath;
                if(!normalizedFullPath(spec.stdoutSpec.filePath, stdoutPath,
                                       error) ||
                   !normalizedFullPath(spec.stderrSpec.filePath, stderrPath,
                                       error))
                    return false;
                if(equalPathInsensitive(stdoutPath, stderrPath))
                {
                    error = runtimeError("output_file_collision",
                        "stdout and stderr file modes must use different normalized paths");
                    return false;
                }
            }

            const bool stdinConsole =
                spec.stdinSpec.mode == StdioMode::Console;
            const bool stdoutConsole =
                spec.stdoutSpec.mode == StdioMode::Console;
            const bool stderrConsole =
                spec.stderrSpec.mode == StdioMode::Console;
            const bool anyConsole = stdinConsole || stdoutConsole ||
                                    stderrConsole;
            const bool allConsole = stdinConsole && stdoutConsole &&
                                    stderrConsole;
            if(anyConsole && !allConsole)
            {
                error = runtimeError("console_mode_mixed",
                    "console mode is valid only when stdin, stdout and stderr all use console");
                return false;
            }

            if((spec.stdinSpec.mode == StdioMode::Pipe ||
                spec.stdinSpec.mode == StdioMode::Bytes) &&
               spec.stdinQueueCapacity == 0)
            {
                error = runtimeError("stdin_queue_capacity_zero",
                    "pipe and bytes stdin require a positive queue capacity",
                    ERROR_SUCCESS, StandardStream::Stdin);
                return false;
            }
            if(spec.stdinSpec.mode == StdioMode::Bytes &&
               spec.stdinSpec.initialBytes.size() >
                   spec.stdinQueueCapacity)
            {
                error = runtimeError("stdin_initial_bytes_too_large",
                    "initial stdin bytes exceed stdinQueueCapacity",
                    ERROR_SUCCESS, StandardStream::Stdin);
                return false;
            }
            return true;
        }

        bool duplicateInheritableHandle(HANDLE requested,
                                        DWORD standardHandle,
                                        StandardStream stream,
                                        UniqueHandle& duplicated,
                                        RuntimeError& error)
        {
            HANDLE source = requested;
            if(source == nullptr)
                source = GetStdHandle(standardHandle);
            if(!isValidHandle(source))
            {
                const DWORD code = source == INVALID_HANDLE_VALUE
                    ? GetLastError() : ERROR_INVALID_HANDLE;
                error = runtimeError("inherited_handle_invalid",
                    "the requested inherited standard handle is invalid",
                    code, stream);
                return false;
            }
            DWORD flags = 0;
            if(!GetHandleInformation(source, &flags))
            {
                const DWORD code = GetLastError();
                error = runtimeError("inherited_handle_query_failed",
                    "GetHandleInformation failed for an inherited standard handle",
                    code, stream);
                return false;
            }
            HANDLE copy = nullptr;
            if(!DuplicateHandle(GetCurrentProcess(), source,
                                GetCurrentProcess(), &copy, 0, TRUE,
                                DUPLICATE_SAME_ACCESS))
            {
                const DWORD code = GetLastError();
                error = runtimeError("inherited_handle_duplicate_failed",
                    "DuplicateHandle failed for an inherited standard handle",
                    code, stream);
                return false;
            }
            duplicated.reset(copy);
            return true;
        }

        bool openNullInput(UniqueHandle& handle, RuntimeError& error)
        {
            SECURITY_ATTRIBUTES security{sizeof(SECURITY_ATTRIBUTES),
                                         nullptr, TRUE};
            HANDLE raw = CreateFileW(L"NUL", GENERIC_READ,
                FILE_SHARE_READ | FILE_SHARE_WRITE, &security,
                OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
            if(!isValidHandle(raw))
            {
                const DWORD code = GetLastError();
                error = runtimeError("stdin_null_open_failed",
                    "opening NUL for stdin failed", code,
                    StandardStream::Stdin);
                return false;
            }
            handle.reset(raw);
            return true;
        }

        bool openNullOutput(StandardStream stream,
                            UniqueHandle& handle,
                            RuntimeError& error)
        {
            SECURITY_ATTRIBUTES security{sizeof(SECURITY_ATTRIBUTES),
                                         nullptr, TRUE};
            HANDLE raw = CreateFileW(L"NUL", GENERIC_WRITE,
                FILE_SHARE_READ | FILE_SHARE_WRITE, &security,
                OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
            if(!isValidHandle(raw))
            {
                const DWORD code = GetLastError();
                error = runtimeError("output_null_open_failed",
                    "opening NUL for output failed", code, stream);
                return false;
            }
            handle.reset(raw);
            return true;
        }

        bool openInputFile(const std::wstring& path,
                           UniqueHandle& handle,
                           RuntimeError& error)
        {
            SECURITY_ATTRIBUTES security{sizeof(SECURITY_ATTRIBUTES),
                                         nullptr, TRUE};
            HANDLE raw = CreateFileW(path.c_str(), GENERIC_READ,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                &security, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
            if(!isValidHandle(raw))
            {
                const DWORD code = GetLastError();
                error = runtimeError("stdin_file_open_failed",
                    "opening the stdin file failed", code,
                    StandardStream::Stdin);
                return false;
            }
            handle.reset(raw);
            return true;
        }

        bool openOutputFile(const OutputSpec& spec,
                            StandardStream stream,
                            UniqueHandle& handle,
                            RuntimeError& error)
        {
            SECURITY_ATTRIBUTES security{sizeof(SECURITY_ATTRIBUTES),
                                         nullptr, TRUE};
            const bool append = spec.writeMode == FileWriteMode::Append;
            const DWORD access = append ? FILE_APPEND_DATA : GENERIC_WRITE;
            const DWORD disposition = append ? OPEN_ALWAYS : CREATE_ALWAYS;
            HANDLE raw = CreateFileW(spec.filePath.c_str(), access,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                &security, disposition, FILE_ATTRIBUTE_NORMAL, nullptr);
            if(!isValidHandle(raw))
            {
                const DWORD code = GetLastError();
                error = runtimeError("output_file_open_failed",
                    "opening the output file failed", code, stream);
                return false;
            }
            handle.reset(raw);
            return true;
        }

        bool makeInputPipe(UniqueHandle& childRead,
                           UniqueHandle& parentWrite,
                           RuntimeError& error)
        {
            SECURITY_ATTRIBUTES security{sizeof(SECURITY_ATTRIBUTES),
                                         nullptr, TRUE};
            HANDLE readRaw = nullptr;
            HANDLE writeRaw = nullptr;
            if(!CreatePipe(&readRaw, &writeRaw, &security, 0))
            {
                const DWORD code = GetLastError();
                error = runtimeError("stdin_pipe_create_failed",
                    "CreatePipe failed for stdin", code,
                    StandardStream::Stdin);
                return false;
            }
            childRead.reset(readRaw);
            parentWrite.reset(writeRaw);
            DWORD code = ERROR_SUCCESS;
            if(!setHandleInheritable(parentWrite.get(), false, &code))
            {
                error = runtimeError("stdin_parent_handle_protect_failed",
                    "clearing HANDLE_FLAG_INHERIT on the parent stdin pipe failed",
                    code, StandardStream::Stdin);
                return false;
            }
            return true;
        }

        bool makeOutputPipe(StandardStream stream,
                            UniqueHandle& parentRead,
                            UniqueHandle& childWrite,
                            RuntimeError& error)
        {
            SECURITY_ATTRIBUTES security{sizeof(SECURITY_ATTRIBUTES),
                                         nullptr, TRUE};
            HANDLE readRaw = nullptr;
            HANDLE writeRaw = nullptr;
            if(!CreatePipe(&readRaw, &writeRaw, &security, 0))
            {
                const DWORD code = GetLastError();
                error = runtimeError("output_pipe_create_failed",
                    "CreatePipe failed for output", code, stream);
                return false;
            }
            parentRead.reset(readRaw);
            childWrite.reset(writeRaw);
            DWORD code = ERROR_SUCCESS;
            if(!setHandleInheritable(parentRead.get(), false, &code))
            {
                error = runtimeError("output_parent_handle_protect_failed",
                    "clearing HANDLE_FLAG_INHERIT on the parent output pipe failed",
                    code, stream);
                return false;
            }
            return true;
        }

        StreamDescriptor describeInput(const InputSpec& spec)
        {
            StreamDescriptor result;
            result.mode = spec.mode;
            result.path = spec.filePath;
            result.redirected = spec.mode != StdioMode::Console;
            result.captured = false;
            result.writable = spec.mode == StdioMode::Pipe;
            return result;
        }

        StreamDescriptor describeOutput(const OutputSpec& spec)
        {
            StreamDescriptor result;
            result.mode = spec.mode;
            result.path = spec.filePath;
            result.redirected = spec.mode != StdioMode::Console;
            result.captured = spec.mode == StdioMode::Pipe;
            result.writable = false;
            return result;
        }

        struct PreparedStreams
        {
            STARTUPINFOEXW startup{};
            std::vector<std::max_align_t> attributeStorage;
            bool attributeInitialized = false;
            bool console = false;

            UniqueHandle childStdin;
            UniqueHandle childStdout;
            UniqueHandle childStderr;
            UniqueHandle parentStdinWrite;
            UniqueHandle parentStdoutRead;
            UniqueHandle parentStderrRead;

            ~PreparedStreams()
            {
                if(attributeInitialized && startup.lpAttributeList)
                    DeleteProcThreadAttributeList(startup.lpAttributeList);
            }

            PreparedStreams()
            {
                std::memset(&startup, 0, sizeof(startup));
            }

            PreparedStreams(const PreparedStreams&) = delete;
            PreparedStreams& operator=(const PreparedStreams&) = delete;
        };

        bool prepareInput(const InputSpec& spec,
                          PreparedStreams& prepared,
                          RuntimeError& error)
        {
            switch(spec.mode)
            {
            case StdioMode::Inherit:
                return duplicateInheritableHandle(spec.inheritHandle,
                    STD_INPUT_HANDLE, StandardStream::Stdin,
                    prepared.childStdin, error);
            case StdioMode::Null:
                return openNullInput(prepared.childStdin, error);
            case StdioMode::File:
                return openInputFile(spec.filePath, prepared.childStdin,
                                     error);
            case StdioMode::Bytes:
            case StdioMode::Pipe:
                return makeInputPipe(prepared.childStdin,
                    prepared.parentStdinWrite, error);
            case StdioMode::Console:
                break;
            }
            error = runtimeError("stdin_mode_invalid",
                "invalid stdin mode", ERROR_INVALID_PARAMETER,
                StandardStream::Stdin);
            return false;
        }

        bool prepareOutput(const OutputSpec& spec,
                           StandardStream stream,
                           DWORD standardHandle,
                           UniqueHandle& child,
                           UniqueHandle& parentRead,
                           RuntimeError& error)
        {
            switch(spec.mode)
            {
            case StdioMode::Inherit:
                return duplicateInheritableHandle(spec.inheritHandle,
                    standardHandle, stream, child, error);
            case StdioMode::Null:
                return openNullOutput(stream, child, error);
            case StdioMode::File:
                return openOutputFile(spec, stream, child, error);
            case StdioMode::Pipe:
                return makeOutputPipe(stream, parentRead, child, error);
            case StdioMode::Console:
            case StdioMode::Bytes:
                break;
            }
            error = runtimeError("output_mode_invalid",
                "invalid output mode", ERROR_INVALID_PARAMETER, stream);
            return false;
        }

        bool prepareStreams(const LaunchSpec& spec,
                            PreparedStreams& prepared,
                            RuntimeError& error)
        {
            prepared.console =
                spec.stdinSpec.mode == StdioMode::Console;
            if(prepared.console)
            {
                prepared.startup.StartupInfo.cb = sizeof(STARTUPINFOW);
                return true;
            }

            prepared.startup.StartupInfo.cb = sizeof(STARTUPINFOEXW);
            prepared.startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
            if(!prepareInput(spec.stdinSpec, prepared, error) ||
               !prepareOutput(spec.stdoutSpec, StandardStream::Stdout,
                              STD_OUTPUT_HANDLE, prepared.childStdout,
                              prepared.parentStdoutRead, error) ||
               !prepareOutput(spec.stderrSpec, StandardStream::Stderr,
                              STD_ERROR_HANDLE, prepared.childStderr,
                              prepared.parentStderrRead, error))
                return false;

            prepared.startup.StartupInfo.hStdInput =
                prepared.childStdin.get();
            prepared.startup.StartupInfo.hStdOutput =
                prepared.childStdout.get();
            prepared.startup.StartupInfo.hStdError =
                prepared.childStderr.get();

            std::vector<HANDLE> handles{
                prepared.childStdin.get(), prepared.childStdout.get(),
                prepared.childStderr.get()};
            const HandleInheritanceValidation validation =
                validateExplicitInheritanceList(handles, true);
            if(!validation.ok)
            {
                error = runtimeError(validation.errorCode,
                    validation.error, validation.win32Error,
                    validation.failingIndex == 0 ? StandardStream::Stdin :
                    validation.failingIndex == 1 ? StandardStream::Stdout :
                                                   StandardStream::Stderr);
                return false;
            }

            SIZE_T bytes = 0;
            InitializeProcThreadAttributeList(nullptr, 1, 0, &bytes);
            if(bytes == 0)
            {
                const DWORD code = GetLastError();
                error = runtimeError("attribute_list_size_failed",
                    "InitializeProcThreadAttributeList did not report a size",
                    code);
                return false;
            }
            if(bytes > std::numeric_limits<size_t>::max() -
                           (sizeof(std::max_align_t) - 1))
            {
                error = runtimeError("attribute_list_size_overflow",
                    "the process attribute list size cannot be represented");
                return false;
            }
            const size_t alignedElements =
                (static_cast<size_t>(bytes) + sizeof(std::max_align_t) - 1) /
                sizeof(std::max_align_t);
            prepared.attributeStorage.resize(alignedElements);
            prepared.startup.lpAttributeList =
                reinterpret_cast<LPPROC_THREAD_ATTRIBUTE_LIST>(
                    prepared.attributeStorage.data());
            if(!InitializeProcThreadAttributeList(
                   prepared.startup.lpAttributeList, 1, 0, &bytes))
            {
                const DWORD code = GetLastError();
                error = runtimeError("attribute_list_init_failed",
                    "InitializeProcThreadAttributeList failed", code);
                prepared.startup.lpAttributeList = nullptr;
                return false;
            }
            prepared.attributeInitialized = true;
            if(!UpdateProcThreadAttribute(
                   prepared.startup.lpAttributeList, 0,
                   PROC_THREAD_ATTRIBUTE_HANDLE_LIST, handles.data(),
                   handles.size() * sizeof(HANDLE), nullptr, nullptr))
            {
                const DWORD code = GetLastError();
                error = runtimeError("attribute_handle_list_failed",
                    "UpdateProcThreadAttribute failed for the standard-handle allowlist",
                    code);
                return false;
            }
            return true;
        }

        OperationResult terminateProcessBounded(
            HANDLE process, UINT exitCode, DWORD timeoutMs)
        {
            OperationResult result;
            try
            {
                if(!isValidHandle(process))
                {
                    result.error = runtimeError(
                        "process_handle_invalid",
                        "the process handle is not valid",
                        ERROR_INVALID_HANDLE);
                    return result;
                }
                const DWORD state = WaitForSingleObject(process, 0);
                if(state == WAIT_OBJECT_0)
                {
                    result.ok = true;
                    return result;
                }
                if(state == WAIT_FAILED)
                {
                    const DWORD code = GetLastError();
                    result.error = runtimeError(
                        "process_state_query_failed",
                        "WaitForSingleObject failed before termination",
                        code);
                    return result;
                }
                if(!TerminateProcess(process, exitCode))
                {
                    const DWORD code = GetLastError();
                    if(WaitForSingleObject(process, 0) != WAIT_OBJECT_0)
                    {
                        result.error = runtimeError(
                            "terminate_process_failed",
                            "TerminateProcess failed",
                            code);
                        return result;
                    }
                }
                const DWORD waited = WaitForSingleObject(
                    process, boundedTeardownTimeout(timeoutMs));
                if(waited == WAIT_TIMEOUT)
                {
                    result.error = runtimeError(
                        "terminate_wait_timeout",
                        "the terminated process did not signal before the teardown deadline",
                        WAIT_TIMEOUT, StandardStream::None, true);
                    return result;
                }
                if(waited != WAIT_OBJECT_0)
                {
                    const DWORD code = GetLastError();
                    result.error = runtimeError(
                        "terminate_wait_failed",
                        "waiting for the terminated process failed",
                        code, StandardStream::None, true);
                    return result;
                }
                result.ok = true;
                return result;
            }
            catch(const std::exception& exception)
            {
                result.error = runtimeError(
                    "terminate_exception", exception.what(),
                    ERROR_SUCCESS, StandardStream::None, true);
            }
            catch(...)
            {
                result.error = runtimeError(
                    "terminate_exception",
                    "an unknown exception occurred while terminating the process",
                    ERROR_SUCCESS, StandardStream::None, true);
            }
            return result;
        }

        void terminateCreatedProcess(HANDLE process) noexcept
        {
            if(isValidHandle(process))
            {
                try
                {
                    (void)terminateProcessBounded(
                        process, kOwnedProcessExitCode,
                        kDefaultTeardownTimeoutMs);
                }
                catch(...)
                {
                }
            }
        }

        // Covers the narrow but important interval after CreateProcessW has
        // succeeded and before LaunchRuntime has assumed ownership.  Any C++
        // allocation/copy failure in that interval must not leak a suspended
        // orphan.
        struct CreatedProcessGuard
        {
            UniqueHandle process;
            UniqueHandle thread;
            bool armed = true;

            ~CreatedProcessGuard() noexcept
            {
                if(armed)
                    terminateCreatedProcess(process.get());
            }

            CreatedProcessGuard(HANDLE processHandle, HANDLE threadHandle)
                : process(processHandle), thread(threadHandle)
            {
            }

            CreatedProcessGuard(const CreatedProcessGuard&) = delete;
            CreatedProcessGuard& operator=(const CreatedProcessGuard&) = delete;
        };
    }

    struct LaunchRuntime::Impl
    {
        struct IoState
        {
            explicit IoState(size_t captureCapacity)
                : stdoutCapture(captureCapacity),
                  stderrCapture(captureCapacity)
            {
            }

            mutable std::mutex handleMutex;
            UniqueHandle stdinWrite;
            UniqueHandle stdoutRead;
            UniqueHandle stderrRead;
            std::atomic<bool> stopping{false};

            mutable std::mutex inputMutex;
            std::condition_variable inputReady;
            std::condition_variable inputSpace;
            std::deque<std::vector<uint8_t>> inputQueue;
            size_t inputQueuedBytes = 0;
            size_t inputCapacity = 0;
            bool inputPiped = false;
            bool inputInteractive = false;
            bool inputCloseRequested = false;
            bool inputOpen = false;
            RuntimeError stdinWorkerError;

            BoundedByteRing stdoutCapture;
            BoundedByteRing stderrCapture;
            bool stdoutCaptured = false;
            bool stderrCaptured = false;
            mutable std::mutex workerErrorMutex;
            RuntimeError stdoutWorkerError;
            RuntimeError stderrWorkerError;

            void setOutputError(StandardStream stream, RuntimeError error)
            {
                std::lock_guard<std::mutex> lock(workerErrorMutex);
                if(stream == StandardStream::Stdout)
                    stdoutWorkerError = std::move(error);
                else
                    stderrWorkerError = std::move(error);
            }

            HANDLE parentHandle(StandardStream stream) const noexcept
            {
                std::lock_guard<std::mutex> lock(handleMutex);
                if(stream == StandardStream::Stdin)
                    return stdinWrite.get();
                if(stream == StandardStream::Stdout)
                    return stdoutRead.get();
                return stderrRead.get();
            }

            void closeParentHandle(StandardStream stream) noexcept
            {
                std::lock_guard<std::mutex> lock(handleMutex);
                if(stream == StandardStream::Stdin)
                    stdinWrite.reset();
                else if(stream == StandardStream::Stdout)
                    stdoutRead.reset();
                else
                    stderrRead.reset();
            }

            void outputLoop(StandardStream stream)
            {
                BoundedByteRing& capture = stream == StandardStream::Stdout
                    ? stdoutCapture : stderrCapture;
                const HANDLE pipe = parentHandle(stream);
                std::vector<uint8_t> buffer;
                try
                {
                    buffer.resize(kPipeTransferSize);
                }
                catch(...)
                {
                    setOutputError(stream, runtimeError(
                        "capture_buffer_allocation_failed",
                        "allocating the output drain buffer failed",
                        ERROR_SUCCESS, stream));
                    capture.close();
                    closeParentHandle(stream);
                    return;
                }

                for(;;)
                {
                    if(stopping.load(std::memory_order_acquire))
                        break;
                    DWORD read = 0;
                    const BOOL ok = ReadFile(pipe, buffer.data(),
                        static_cast<DWORD>(buffer.size()), &read, nullptr);
                    if(ok)
                    {
                        if(read == 0)
                            break;
                        if(!capture.append(buffer.data(), read))
                        {
                            if(!stopping.load(std::memory_order_acquire))
                                setOutputError(stream, runtimeError(
                                    "capture_append_failed",
                                    "the bounded capture ring rejected output",
                                    ERROR_SUCCESS, stream));
                            break;
                        }
                        continue;
                    }

                    const DWORD code = GetLastError();
                    if(code != ERROR_BROKEN_PIPE &&
                       code != ERROR_HANDLE_EOF &&
                       !(code == ERROR_OPERATION_ABORTED &&
                         stopping.load(std::memory_order_acquire)))
                        setOutputError(stream, runtimeError(
                            "output_read_failed",
                            "ReadFile failed while draining output",
                            code, stream));
                    break;
                }
                capture.close();
                closeParentHandle(stream);
            }

            void inputLoop()
            {
                const HANDLE pipe = parentHandle(StandardStream::Stdin);
                for(;;)
                {
                    std::vector<uint8_t> chunk;
                    {
                        std::unique_lock<std::mutex> lock(inputMutex);
                        inputReady.wait(lock, [&] {
                            return stopping.load(std::memory_order_acquire) ||
                                   !inputQueue.empty() || inputCloseRequested;
                        });
                        if(stopping.load(std::memory_order_acquire))
                            break;
                        if(inputQueue.empty())
                        {
                            if(inputCloseRequested)
                                break;
                            continue;
                        }
                        chunk = std::move(inputQueue.front());
                        inputQueue.pop_front();
                    }

                    bool writtenSuccessfully = true;
                    size_t offset = 0;
                    while(offset < chunk.size())
                    {
                        if(stopping.load(std::memory_order_acquire))
                        {
                            writtenSuccessfully = false;
                            break;
                        }
                        const size_t remaining = chunk.size() - offset;
                        const DWORD request = static_cast<DWORD>(
                            std::min<size_t>(
                                remaining,
                                std::numeric_limits<DWORD>::max()));
                        DWORD written = 0;
                        const BOOL writeOk = WriteFile(
                            pipe, chunk.data() + offset, request, &written,
                            nullptr);
                        if(!writeOk || written == 0)
                        {
                            const DWORD code = writeOk
                                ? ERROR_WRITE_FAULT : GetLastError();
                            if(!(code == ERROR_OPERATION_ABORTED &&
                                 stopping.load(std::memory_order_acquire)))
                            {
                                std::lock_guard<std::mutex> lock(inputMutex);
                                stdinWorkerError = runtimeError(
                                    code == ERROR_BROKEN_PIPE
                                        ? "stdin_closed_by_child"
                                        : "stdin_write_failed",
                                    "WriteFile failed while delivering stdin",
                                    code, StandardStream::Stdin);
                            }
                            writtenSuccessfully = false;
                            break;
                        }
                        offset += written;
                    }

                    {
                        std::lock_guard<std::mutex> lock(inputMutex);
                        inputQueuedBytes = chunk.size() > inputQueuedBytes
                            ? 0 : inputQueuedBytes - chunk.size();
                        if(!writtenSuccessfully)
                        {
                            inputQueue.clear();
                            inputQueuedBytes = 0;
                            inputCloseRequested = true;
                        }
                    }
                    inputSpace.notify_all();
                    if(!writtenSuccessfully)
                        break;
                }

                closeParentHandle(StandardStream::Stdin);
                {
                    std::lock_guard<std::mutex> lock(inputMutex);
                    inputOpen = false;
                    if(stopping.load(std::memory_order_acquire))
                    {
                        inputQueue.clear();
                        inputQueuedBytes = 0;
                    }
                }
                inputSpace.notify_all();
            }
        };

        struct WorkerContext
        {
            std::shared_ptr<IoState> io;
            StandardStream stream = StandardStream::None;
        };

        explicit Impl(size_t captureCapacity)
            : io(std::make_shared<IoState>(captureCapacity))
        {
        }

        LaunchInfo launchInfo;
        UniqueHandle process;
        UniqueHandle primaryThread;

        mutable std::mutex lifecycleMutex;
        bool suspended = true;
        bool resumeSubmitted = false;
        bool abortOnDestruction = true;

        std::shared_ptr<IoState> io;
        UniqueHandle stdinThread;
        UniqueHandle stdoutThread;
        UniqueHandle stderrThread;
        mutable std::mutex teardownMutex;
        TeardownStatus teardownStatus;
        bool resourcesClosed = false;

        static unsigned __stdcall workerEntry(void* opaque) noexcept
        {
            std::unique_ptr<WorkerContext> context(
                static_cast<WorkerContext*>(opaque));
            if(!context || !context->io)
                return 1u;
            try
            {
                if(context->stream == StandardStream::Stdin)
                    context->io->inputLoop();
                else
                    context->io->outputLoop(context->stream);
            }
            catch(const std::exception& exception)
            {
                try
                {
                    const RuntimeError error = runtimeError(
                        "worker_exception", exception.what(),
                        ERROR_SUCCESS, context->stream, true);
                    if(context->stream == StandardStream::Stdin)
                    {
                        std::lock_guard<std::mutex> lock(
                            context->io->inputMutex);
                        context->io->stdinWorkerError = error;
                    }
                    else
                        context->io->setOutputError(
                            context->stream, error);
                }
                catch(...)
                {
                }
            }
            catch(...)
            {
                try
                {
                    const RuntimeError error = runtimeError(
                        "worker_exception",
                        "an unknown exception escaped a launch I/O worker",
                        ERROR_SUCCESS, context->stream, true);
                    if(context->stream == StandardStream::Stdin)
                    {
                        std::lock_guard<std::mutex> lock(
                            context->io->inputMutex);
                        context->io->stdinWorkerError = error;
                    }
                    else
                        context->io->setOutputError(
                            context->stream, error);
                }
                catch(...)
                {
                }
            }
            return 0u;
        }

        OperationResult startWorker(
            UniqueHandle& destination, StandardStream stream)
        {
            OperationResult result;
            auto context = std::make_unique<WorkerContext>();
            context->io = io;
            context->stream = stream;
            errno = 0;
            const uintptr_t raw = _beginthreadex(
                nullptr, 0, &Impl::workerEntry, context.get(), 0, nullptr);
            if(raw == 0)
            {
                DWORD code = GetLastError();
                if(code == ERROR_SUCCESS)
                    code = static_cast<DWORD>(errno);
                result.error = runtimeError(
                    "worker_thread_start_failed",
                    "_beginthreadex failed for a launch I/O worker",
                    code, stream);
                return result;
            }
            destination.reset(reinterpret_cast<HANDLE>(raw));
            context.release();
            result.ok = true;
            return result;
        }

        OperationResult startWorkers()
        {
            OperationResult result;
            if(io->stdoutCaptured)
            {
                result = startWorker(stdoutThread, StandardStream::Stdout);
                if(!result.ok)
                    return result;
            }
            else
                io->stdoutCapture.close();

            if(io->stderrCaptured)
            {
                result = startWorker(stderrThread, StandardStream::Stderr);
                if(!result.ok)
                    return result;
            }
            else
                io->stderrCapture.close();

            if(io->inputPiped)
            {
                result = startWorker(stdinThread, StandardStream::Stdin);
                if(!result.ok)
                    return result;
            }
            result.ok = true;
            return result;
        }

        static DWORD remainingMilliseconds(
            const std::chrono::steady_clock::time_point& deadline) noexcept
        {
            const auto now = std::chrono::steady_clock::now();
            if(now >= deadline)
                return 0;
            const auto remaining = deadline - now;
            const auto milliseconds =
                std::chrono::duration_cast<std::chrono::milliseconds>(
                    remaining).count();
            const uint64_t rounded = static_cast<uint64_t>(
                milliseconds) + 1u;
            return static_cast<DWORD>(std::min<uint64_t>(
                rounded, std::numeric_limits<DWORD>::max()));
        }

        static bool queryThreadHandle(
            HANDLE thread, RuntimeError& error)
        {
            if(!isValidHandle(thread))
            {
                error = runtimeError(
                    "worker_thread_handle_invalid",
                    "a launch I/O worker has no valid thread handle",
                    ERROR_INVALID_HANDLE, StandardStream::None, false);
                return false;
            }
            DWORD flags = 0;
            if(!GetHandleInformation(thread, &flags))
            {
                const DWORD code = GetLastError();
                error = runtimeError(
                    "worker_thread_handle_invalid",
                    "GetHandleInformation failed for a launch I/O worker",
                    code, StandardStream::None, false);
                return false;
            }
            return true;
        }

        void requestWorkerCancellation(
            UniqueHandle& worker,
            TeardownStatus& status,
            RuntimeError& hardError,
            RuntimeError& cancellationError)
        {
            if(!worker)
                return;
            ++status.workerCount;
            RuntimeError handleError;
            if(!queryThreadHandle(worker.get(), handleError))
            {
                if(!hardError)
                    hardError = std::move(handleError);
                return;
            }
            const DWORD state = WaitForSingleObject(worker.get(), 0);
            if(state == WAIT_OBJECT_0)
                return;
            if(state == WAIT_FAILED)
            {
                const DWORD code = GetLastError();
                if(!hardError)
                    hardError = runtimeError(
                        "worker_thread_wait_failed",
                        "WaitForSingleObject failed for a launch I/O worker",
                        code, StandardStream::None, true);
                return;
            }

            ++status.cancellationAttempts;
            if(!CancelSynchronousIo(worker.get()))
            {
                const DWORD code = GetLastError();
                if(code != ERROR_NOT_FOUND)
                {
                    ++status.cancellationFailures;
                    if(!cancellationError)
                        cancellationError = runtimeError(
                            "worker_io_cancel_failed",
                            "CancelSynchronousIo failed for a launch I/O worker",
                            code, StandardStream::None, true);
                }
            }
        }

        void waitForWorker(
            UniqueHandle& worker,
            const std::chrono::steady_clock::time_point& deadline,
            TeardownStatus& status,
            RuntimeError& hardError)
        {
            if(!worker)
                return;
            RuntimeError handleError;
            if(!queryThreadHandle(worker.get(), handleError))
            {
                if(!hardError)
                    hardError = std::move(handleError);
                return;
            }
            const DWORD waited = WaitForSingleObject(
                worker.get(), remainingMilliseconds(deadline));
            if(waited == WAIT_OBJECT_0)
            {
                ++status.workersStopped;
                worker.reset();
                return;
            }
            if(waited == WAIT_TIMEOUT)
            {
                status.timedOut = true;
                return;
            }
            const DWORD code = GetLastError();
            if(!hardError)
                hardError = runtimeError(
                    "worker_thread_wait_failed",
                    "WaitForSingleObject failed for a launch I/O worker",
                    code, StandardStream::None, true);
        }

        OperationResult shutdown(DWORD timeoutMs) noexcept
        {
            OperationResult result;
            try
            {
                std::lock_guard<std::mutex> closeLock(teardownMutex);
                if(resourcesClosed)
                {
                    result.ok = true;
                    return result;
                }

                const DWORD boundedTimeout =
                    boundedTeardownTimeout(timeoutMs);
                teardownStatus = TeardownStatus{};
                teardownStatus.requested = true;
                teardownStatus.timeoutMs = boundedTimeout;
                const auto deadline = std::chrono::steady_clock::now() +
                    std::chrono::milliseconds(boundedTimeout);

                bool abortProcess = true;
                {
                    std::lock_guard<std::mutex> lock(lifecycleMutex);
                    abortProcess = abortOnDestruction;
                }

                RuntimeError hardError;
                RuntimeError cancellationError;
                if(abortProcess && isValidHandle(process.get()))
                {
                    const DWORD processState =
                        WaitForSingleObject(process.get(), 0);
                    if(processState == WAIT_OBJECT_0)
                        teardownStatus.processExited = true;
                    else if(processState == WAIT_TIMEOUT)
                    {
                        teardownStatus.processTerminationRequested = true;
                        if(!TerminateProcess(
                               process.get(), kOwnedProcessExitCode))
                        {
                            const DWORD code = GetLastError();
                            if(WaitForSingleObject(process.get(), 0) ==
                               WAIT_OBJECT_0)
                                teardownStatus.processExited = true;
                            else
                                hardError = runtimeError(
                                    "terminate_process_failed",
                                    "TerminateProcess failed during launch teardown",
                                    code);
                        }
                    }
                    else
                    {
                        const DWORD code = GetLastError();
                        hardError = runtimeError(
                            "process_state_query_failed",
                            "WaitForSingleObject failed during launch teardown",
                            code);
                    }
                }

                io->stopping.store(true, std::memory_order_release);
                io->inputReady.notify_all();
                io->inputSpace.notify_all();
                requestWorkerCancellation(
                    stdinThread, teardownStatus,
                    hardError, cancellationError);
                requestWorkerCancellation(
                    stdoutThread, teardownStatus,
                    hardError, cancellationError);
                requestWorkerCancellation(
                    stderrThread, teardownStatus,
                    hardError, cancellationError);

                waitForWorker(
                    stdinThread, deadline, teardownStatus, hardError);
                waitForWorker(
                    stdoutThread, deadline, teardownStatus, hardError);
                waitForWorker(
                    stderrThread, deadline, teardownStatus, hardError);

                const bool workersStopped =
                    teardownStatus.workersStopped ==
                    teardownStatus.workerCount;
                if(workersStopped)
                {
                    std::lock_guard<std::mutex> lock(io->handleMutex);
                    io->stdinWrite.reset();
                    io->stdoutRead.reset();
                    io->stderrRead.reset();
                }
                io->stdoutCapture.close();
                io->stderrCapture.close();

                if(abortProcess && isValidHandle(process.get()) &&
                   !teardownStatus.processExited)
                {
                    const DWORD waited = WaitForSingleObject(
                        process.get(), remainingMilliseconds(deadline));
                    if(waited == WAIT_OBJECT_0)
                        teardownStatus.processExited = true;
                    else if(waited == WAIT_TIMEOUT)
                        teardownStatus.timedOut = true;
                    else if(!hardError)
                    {
                        const DWORD code = GetLastError();
                        hardError = runtimeError(
                            "terminate_wait_failed",
                            "waiting for the terminated process failed during launch teardown",
                            code, StandardStream::None, true);
                    }
                }
                else if(!abortProcess && isValidHandle(process.get()))
                {
                    teardownStatus.processExited =
                        WaitForSingleObject(process.get(), 0) ==
                        WAIT_OBJECT_0;
                }

                const bool processReady =
                    !abortProcess || teardownStatus.processExited;
                if(!hardError && workersStopped && processReady)
                {
                    primaryThread.reset();
                    process.reset();
                    resourcesClosed = true;
                    teardownStatus.complete = true;
                    teardownStatus.error = RuntimeError{};
                    result.ok = true;
                    return result;
                }

                if(hardError)
                    teardownStatus.error = std::move(hardError);
                else if(cancellationError && !workersStopped)
                    teardownStatus.error = std::move(cancellationError);
                else
                {
                    teardownStatus.timedOut = true;
                    teardownStatus.error = runtimeError(
                        "launch_teardown_timeout",
                        "launch resources did not become quiescent before the bounded teardown deadline",
                        WAIT_TIMEOUT, StandardStream::None, true);
                }
                result.error = teardownStatus.error;
                return result;
            }
            catch(const std::exception& exception)
            {
                result.error = runtimeError(
                    "launch_teardown_exception", exception.what(),
                    ERROR_SUCCESS, StandardStream::None, true);
            }
            catch(...)
            {
                result.error = runtimeError(
                    "launch_teardown_exception",
                    "an unknown exception occurred during bounded launch teardown",
                    ERROR_SUCCESS, StandardStream::None, true);
            }
            try
            {
                std::lock_guard<std::mutex> lock(teardownMutex);
                teardownStatus.requested = true;
                teardownStatus.error = result.error;
            }
            catch(...)
            {
            }
            return result;
        }
    };

    LaunchRuntime::LaunchRuntime(std::unique_ptr<Impl> impl) noexcept
        : impl_(std::move(impl))
    {
    }

    LaunchRuntime::~LaunchRuntime() noexcept
    {
        if(impl_)
            (void)impl_->shutdown(kDefaultTeardownTimeoutMs);
    }

    LaunchResult LaunchRuntime::createSuspended(
        const LaunchSpec& spec) noexcept
    {
        LaunchResult outcome;
        try
        {
            RuntimeError error;
            if(!validateSpec(spec, error))
            {
                outcome.error = std::move(error);
                return outcome;
            }

            CommandLineBuildResult commandLine = spec.rawCommandLineTail
                ? buildWindowsCommandLine(spec.executable,
                    std::wstring_view(*spec.rawCommandLineTail))
                : buildWindowsCommandLine(spec.executable, spec.arguments);
            if(!commandLine.ok)
            {
                outcome.error = runtimeError(commandLine.errorCode,
                                              commandLine.error);
                return outcome;
            }

            std::vector<EnvironmentEntry> inherited;
            if(spec.inheritEnvironment)
            {
                if(spec.inheritedEnvironmentSnapshot)
                    inherited = *spec.inheritedEnvironmentSnapshot;
                else if(!captureCurrentEnvironment(inherited, error))
                {
                    outcome.error = std::move(error);
                    return outcome;
                }
            }
            EnvironmentBlockBuildResult environment =
                buildUnicodeEnvironmentBlock(inherited,
                                              spec.environmentOverrides);
            if(!environment.ok)
            {
                outcome.error = runtimeError(environment.errorCode,
                                             environment.error);
                return outcome;
            }

            PreparedStreams streams;
            if(!prepareStreams(spec, streams, error))
            {
                outcome.error = std::move(error);
                return outcome;
            }

            std::vector<wchar_t> mutableCommandLine(
                commandLine.commandLine.begin(), commandLine.commandLine.end());
            mutableCommandLine.push_back(L'\0');
            PROCESS_INFORMATION processInfo{};
            DWORD creationFlags = CREATE_SUSPENDED |
                                  CREATE_UNICODE_ENVIRONMENT;
            if(!streams.console)
                creationFlags |= EXTENDED_STARTUPINFO_PRESENT;
            else
                creationFlags |= CREATE_NEW_CONSOLE;

            const BOOL created = CreateProcessW(
                spec.executable.c_str(), mutableCommandLine.data(), nullptr,
                nullptr, streams.console ? FALSE : TRUE, creationFlags,
                environment.block.data(),
                spec.workingDirectory ? spec.workingDirectory->c_str()
                                      : nullptr,
                &streams.startup.StartupInfo, &processInfo);
            if(!created)
            {
                const DWORD code = GetLastError();
                outcome.error = runtimeError("create_process_failed",
                    "CreateProcessW failed", code);
                return outcome;
            }

            CreatedProcessGuard createdProcess(processInfo.hProcess,
                                               processInfo.hThread);

            // The child-side ends must disappear from the parent before any
            // worker starts, otherwise EOF/backpressure semantics are wrong.
            streams.childStdin.reset();
            streams.childStdout.reset();
            streams.childStderr.reset();

            FILETIME creation{};
            FILETIME exit{};
            FILETIME kernel{};
            FILETIME user{};
            if(!GetProcessTimes(createdProcess.process.get(), &creation,
                                &exit, &kernel,
                                &user))
            {
                const DWORD code = GetLastError();
                outcome.error = runtimeError("process_time_query_failed",
                    "GetProcessTimes failed for the created process", code);
                return outcome;
            }

            auto implementation = std::make_unique<Impl>(
                spec.captureCapacity);
            implementation->process = std::move(createdProcess.process);
            implementation->primaryThread = std::move(createdProcess.thread);
            createdProcess.armed = false;
            auto& io = *implementation->io;
            io.stdinWrite =
                std::move(streams.parentStdinWrite);
            io.stdoutRead =
                std::move(streams.parentStdoutRead);
            io.stderrRead =
                std::move(streams.parentStderrRead);
            io.inputCapacity = spec.stdinQueueCapacity;
            io.inputPiped =
                spec.stdinSpec.mode == StdioMode::Pipe ||
                spec.stdinSpec.mode == StdioMode::Bytes;
            io.inputInteractive =
                spec.stdinSpec.mode == StdioMode::Pipe;
            io.inputOpen = io.inputPiped;
            io.stdoutCaptured =
                spec.stdoutSpec.mode == StdioMode::Pipe;
            io.stderrCaptured =
                spec.stderrSpec.mode == StdioMode::Pipe;

            if(spec.stdinSpec.mode == StdioMode::Bytes)
            {
                if(!spec.stdinSpec.initialBytes.empty())
                {
                    io.inputQueue.push_back(
                        spec.stdinSpec.initialBytes);
                    io.inputQueuedBytes =
                        spec.stdinSpec.initialBytes.size();
                }
                io.inputCloseRequested = true;
            }

            implementation->launchInfo.processId =
                processInfo.dwProcessId;
            implementation->launchInfo.primaryThreadId =
                processInfo.dwThreadId;
            implementation->launchInfo.creationTime100ns =
                fileTimeValue(creation);
            implementation->launchInfo.launchId = makeLaunchId(
                processInfo.dwProcessId,
                implementation->launchInfo.creationTime100ns);
            implementation->launchInfo.createdSuspended = true;
            implementation->launchInfo.stdinStream =
                describeInput(spec.stdinSpec);
            implementation->launchInfo.stdoutStream =
                describeOutput(spec.stdoutSpec);
            implementation->launchInfo.stderrStream =
                describeOutput(spec.stderrSpec);

            std::unique_ptr<LaunchRuntime> runtime(
                new LaunchRuntime(std::move(implementation)));
            const OperationResult workers =
                runtime->impl_->startWorkers();
            if(!workers.ok)
            {
                RuntimeError threadError = workers.error;
                runtime.reset();
                outcome.error = std::move(threadError);
                return outcome;
            }

            outcome.info = runtime->impl_->launchInfo;
            outcome.runtime = std::move(runtime);
            outcome.ok = true;
            return outcome;
        }
        catch(const std::bad_alloc&)
        {
            outcome.error = allocationError();
            return outcome;
        }
        catch(const std::exception& exception)
        {
            outcome.error = runtimeError("launch_runtime_exception",
                                          exception.what());
            return outcome;
        }
        catch(...)
        {
            outcome.error = runtimeError("launch_runtime_exception",
                "an unknown exception escaped launch preparation");
            return outcome;
        }
    }

    LaunchInfo LaunchRuntime::info() const
    {
        return impl_ ? impl_->launchInfo : LaunchInfo{};
    }

    HANDLE LaunchRuntime::nativeProcessHandle() const noexcept
    {
        return impl_ ? impl_->process.get() : nullptr;
    }

    HANDLE LaunchRuntime::nativePrimaryThreadHandle() const noexcept
    {
        return impl_ ? impl_->primaryThread.get() : nullptr;
    }

    ProcessState LaunchRuntime::state() const noexcept
    {
        ProcessState result;
        if(!impl_)
            return result;
        try
        {
            result.processId = impl_->launchInfo.processId;
            result.primaryThreadId = impl_->launchInfo.primaryThreadId;
            {
                std::lock_guard<std::mutex> lock(impl_->teardownMutex);
                result.teardown = impl_->teardownStatus;
            }
            {
                std::lock_guard<std::mutex> lock(impl_->lifecycleMutex);
                result.suspended = impl_->suspended;
                result.resumeSubmitted = impl_->resumeSubmitted;
            }

            if(isValidHandle(impl_->process.get()))
            {
                const DWORD waitResult = WaitForSingleObject(
                    impl_->process.get(), 0);
                if(waitResult == WAIT_OBJECT_0)
                {
                    result.exited = true;
                    DWORD exitCode = STILL_ACTIVE;
                    if(GetExitCodeProcess(impl_->process.get(), &exitCode))
                    {
                        result.exitCodeKnown = true;
                        result.exitCode = exitCode;
                    }
                }
                else if(waitResult == WAIT_TIMEOUT)
                    result.running = true;
            }
            else if(result.teardown.processExited)
                result.exited = true;

            const auto& io = *impl_->io;
            {
                std::lock_guard<std::mutex> lock(io.inputMutex);
                result.stdinOpen = io.inputOpen;
                result.stdinQueuedBytes = io.inputQueuedBytes;
                result.stdinError = io.stdinWorkerError;
            }
            result.stdoutEof = io.stdoutCaptured &&
                               io.stdoutCapture.isClosed();
            result.stderrEof = io.stderrCaptured &&
                               io.stderrCapture.isClosed();
            {
                std::lock_guard<std::mutex> lock(io.workerErrorMutex);
                result.stdoutError = io.stdoutWorkerError;
                result.stderrError = io.stderrWorkerError;
            }
        }
        catch(...)
        {
        }
        return result;
    }

    ResumeResult LaunchRuntime::resumeAfterValidation() noexcept
    {
        ResumeResult result;
        if(!impl_)
        {
            result.error = runtimeError("runtime_invalid",
                "the launch runtime is not initialized");
            return result;
        }
        try
        {
            {
                std::lock_guard<std::mutex> stateLock(
                    impl_->teardownMutex);
                if(impl_->resourcesClosed ||
                   impl_->teardownStatus.requested)
                {
                    result.error = runtimeError(
                        "runtime_resources_closed",
                        "the launch runtime is closing or has already been closed",
                        ERROR_INVALID_STATE, StandardStream::None, true);
                    return result;
                }
            }
            std::lock_guard<std::mutex> lock(impl_->lifecycleMutex);
            if(impl_->resumeSubmitted)
            {
                result.error = runtimeError("resume_already_submitted",
                    "resumeAfterValidation may be submitted only once");
                return result;
            }
            const DWORD previous = ResumeThread(impl_->primaryThread.get());
            if(previous == static_cast<DWORD>(-1))
            {
                const DWORD code = GetLastError();
                result.error = runtimeError("resume_thread_failed",
                    "ResumeThread failed for the primary thread", code);
                return result;
            }
            impl_->resumeSubmitted = true;
            // This runtime contributed exactly one CREATE_SUSPENDED count.
            // Remove exactly that count and never drain counts owned by x64dbg
            // (or another controller). A previous value above one therefore
            // means the process remains externally suspended, not that our
            // creation suspension is still held.
            impl_->suspended = false;
            result.previousSuspendCount = previous;
            result.remainsSuspended = previous > 1;
            result.ok = true;
            return result;
        }
        catch(const std::exception& exception)
        {
            result.error = runtimeError("resume_exception", exception.what());
            return result;
        }
        catch(...)
        {
            result.error = runtimeError("resume_exception",
                "an unknown exception occurred while resuming the process");
            return result;
        }
    }

    OperationResult
    LaunchRuntime::commitExternalDebuggerOwnership() noexcept
    {
        OperationResult result;
        if(!impl_)
        {
            result.error = runtimeError("runtime_invalid",
                "the launch runtime is not initialized");
            return result;
        }
        try
        {
            {
                std::lock_guard<std::mutex> stateLock(
                    impl_->teardownMutex);
                if(impl_->resourcesClosed ||
                   impl_->teardownStatus.requested)
                {
                    result.error = runtimeError(
                        "runtime_resources_closed",
                        "the launch runtime is closing or has already been closed",
                        ERROR_INVALID_STATE, StandardStream::None, true);
                    return result;
                }
            }
            std::lock_guard<std::mutex> lock(impl_->lifecycleMutex);
            if(!impl_->abortOnDestruction)
            {
                result.ok = true;
                return result;
            }
            if(!impl_->resumeSubmitted)
            {
                result.error = runtimeError(
                    "ownership_commit_before_resume",
                    "external ownership cannot be committed before resumeAfterValidation succeeds");
                return result;
            }
            if(impl_->suspended)
            {
                result.error = runtimeError(
                    "ownership_commit_while_suspended",
                    "external ownership cannot be committed while the primary thread remains suspended");
                return result;
            }
            impl_->abortOnDestruction = false;
            result.ok = true;
            return result;
        }
        catch(const std::exception& exception)
        {
            result.error = runtimeError("ownership_commit_exception",
                                         exception.what());
            return result;
        }
        catch(...)
        {
            result.error = runtimeError("ownership_commit_exception",
                "an unknown exception occurred while committing external ownership");
            return result;
        }
    }

    WriteInputResult LaunchRuntime::writeInput(const void* bytes,
                                                size_t size,
                                                DWORD timeoutMs) noexcept
    {
        WriteInputResult result;
        if(!impl_)
        {
            result.error = runtimeError("runtime_invalid",
                "the launch runtime is not initialized");
            return result;
        }
        auto& io = *impl_->io;
        {
            std::lock_guard<std::mutex> lock(impl_->teardownMutex);
            if(impl_->resourcesClosed || impl_->teardownStatus.requested)
            {
                result.error = runtimeError(
                    "runtime_resources_closed",
                    "launch resources are closing or have already been closed",
                    ERROR_INVALID_STATE, StandardStream::Stdin, true);
                return result;
            }
        }
        result.queueCapacity = io.inputCapacity;
        try
        {
            if(!io.inputInteractive)
            {
                result.error = runtimeError("stdin_not_writable",
                    "writeInput requires stdin pipe mode", ERROR_SUCCESS,
                    StandardStream::Stdin);
                return result;
            }
            if(size != 0 && bytes == nullptr)
            {
                result.error = runtimeError("stdin_bytes_null",
                    "a non-empty stdin write requires a non-null buffer",
                    ERROR_INVALID_PARAMETER, StandardStream::Stdin);
                return result;
            }
            if(size > io.inputCapacity)
            {
                result.wouldBlock = true;
                result.error = runtimeError("stdin_write_exceeds_capacity",
                    "the stdin write is larger than the entire queue capacity",
                    ERROR_SUCCESS, StandardStream::Stdin, false);
                return result;
            }

            std::unique_lock<std::mutex> lock(io.inputMutex);
            const auto ready = [&] {
                return io.stopping.load(std::memory_order_acquire) ||
                       !io.inputOpen || io.inputCloseRequested ||
                       static_cast<bool>(io.stdinWorkerError) ||
                       io.inputQueuedBytes <=
                           io.inputCapacity - size;
            };
            bool hasSpace = ready();
            if(!hasSpace)
            {
                if(timeoutMs == INFINITE)
                {
                    io.inputSpace.wait(lock, ready);
                    hasSpace = true;
                }
                else if(timeoutMs != 0)
                    hasSpace = io.inputSpace.wait_for(lock,
                        std::chrono::milliseconds(timeoutMs), ready);
            }
            if(!hasSpace)
            {
                result.wouldBlock = true;
                result.queuedBytes = io.inputQueuedBytes;
                result.error = runtimeError("stdin_backpressure",
                    "the bounded stdin queue has insufficient space",
                    ERROR_SUCCESS, StandardStream::Stdin, true);
                return result;
            }
            if(io.stopping.load(std::memory_order_acquire) ||
               !io.inputOpen || io.inputCloseRequested)
            {
                result.closed = true;
                result.queuedBytes = io.inputQueuedBytes;
                result.error = runtimeError("stdin_closed",
                    "stdin is closed", ERROR_BROKEN_PIPE,
                    StandardStream::Stdin);
                return result;
            }
            if(io.stdinWorkerError)
            {
                result.closed = true;
                result.queuedBytes = io.inputQueuedBytes;
                result.error = io.stdinWorkerError;
                return result;
            }
            if(size != 0)
            {
                const auto* begin = static_cast<const uint8_t*>(bytes);
                io.inputQueue.emplace_back(begin, begin + size);
                io.inputQueuedBytes += size;
            }
            result.acceptedBytes = size;
            result.queuedBytes = io.inputQueuedBytes;
            result.ok = true;
            lock.unlock();
            io.inputReady.notify_one();
            return result;
        }
        catch(const std::bad_alloc&)
        {
            result.error = allocationError();
            result.error.stream = StandardStream::Stdin;
            return result;
        }
        catch(const std::exception& exception)
        {
            result.error = runtimeError("stdin_write_exception",
                exception.what(), ERROR_SUCCESS, StandardStream::Stdin);
            return result;
        }
        catch(...)
        {
            result.error = runtimeError("stdin_write_exception",
                "an unknown exception occurred while queuing stdin",
                ERROR_SUCCESS, StandardStream::Stdin);
            return result;
        }
    }

    WriteInputResult LaunchRuntime::writeInput(
        const std::vector<uint8_t>& bytes, DWORD timeoutMs) noexcept
    {
        return writeInput(bytes.data(), bytes.size(), timeoutMs);
    }

    OperationResult LaunchRuntime::closeInput() noexcept
    {
        OperationResult result;
        if(!impl_)
        {
            result.error = runtimeError("runtime_invalid",
                "the launch runtime is not initialized");
            return result;
        }
        try
        {
            auto& io = *impl_->io;
            {
                std::lock_guard<std::mutex> stateLock(impl_->teardownMutex);
                if(impl_->resourcesClosed || impl_->teardownStatus.requested)
                {
                    result.error = runtimeError(
                        "runtime_resources_closed",
                        "launch resources are closing or have already been closed",
                        ERROR_INVALID_STATE, StandardStream::Stdin, true);
                    return result;
                }
            }
            if(!io.inputPiped)
            {
                result.error = runtimeError("stdin_not_closable",
                    "closeInput requires stdin pipe or bytes mode",
                    ERROR_SUCCESS, StandardStream::Stdin);
                return result;
            }
            {
                std::lock_guard<std::mutex> lock(io.inputMutex);
                io.inputCloseRequested = true;
            }
            io.inputReady.notify_all();
            result.ok = true;
            return result;
        }
        catch(const std::exception& exception)
        {
            result.error = runtimeError("stdin_close_exception",
                exception.what(), ERROR_SUCCESS, StandardStream::Stdin);
            return result;
        }
        catch(...)
        {
            result.error = runtimeError("stdin_close_exception",
                "an unknown exception occurred while closing stdin",
                ERROR_SUCCESS, StandardStream::Stdin);
            return result;
        }
    }

    CaptureReadResult LaunchRuntime::readStdout(uint64_t cursor,
                                                 size_t maxBytes) const noexcept
    {
        CaptureReadResult result;
        if(!impl_ || !impl_->io || !impl_->io->stdoutCaptured)
        {
            result.error = runtimeError("stdout_not_captured",
                "readStdout requires stdout pipe mode", ERROR_SUCCESS,
                StandardStream::Stdout);
            return result;
        }
        try
        {
            result.capture = impl_->io->stdoutCapture.read(cursor, maxBytes);
            result.ok = true;
        }
        catch(const std::bad_alloc&)
        {
            result.error = allocationError();
            result.error.stream = StandardStream::Stdout;
        }
        catch(const std::exception& exception)
        {
            result.error = runtimeError("stdout_read_exception",
                exception.what(), ERROR_SUCCESS, StandardStream::Stdout);
        }
        catch(...)
        {
            result.error = runtimeError("stdout_read_exception",
                "an unknown exception occurred while reading stdout capture",
                ERROR_SUCCESS, StandardStream::Stdout);
        }
        return result;
    }

    CaptureReadResult LaunchRuntime::readStderr(uint64_t cursor,
                                                 size_t maxBytes) const noexcept
    {
        CaptureReadResult result;
        if(!impl_ || !impl_->io || !impl_->io->stderrCaptured)
        {
            result.error = runtimeError("stderr_not_captured",
                "readStderr requires stderr pipe mode", ERROR_SUCCESS,
                StandardStream::Stderr);
            return result;
        }
        try
        {
            result.capture = impl_->io->stderrCapture.read(cursor, maxBytes);
            result.ok = true;
        }
        catch(const std::bad_alloc&)
        {
            result.error = allocationError();
            result.error.stream = StandardStream::Stderr;
        }
        catch(const std::exception& exception)
        {
            result.error = runtimeError("stderr_read_exception",
                exception.what(), ERROR_SUCCESS, StandardStream::Stderr);
        }
        catch(...)
        {
            result.error = runtimeError("stderr_read_exception",
                "an unknown exception occurred while reading stderr capture",
                ERROR_SUCCESS, StandardStream::Stderr);
        }
        return result;
    }

    WaitResult LaunchRuntime::wait(DWORD timeoutMs) noexcept
    {
        WaitResult result;
        if(!impl_)
        {
            result.error = runtimeError("runtime_invalid",
                "the launch runtime is not initialized");
            return result;
        }
        if(!isValidHandle(impl_->process.get()))
        {
            result.error = runtimeError(
                "runtime_resources_closed",
                "the child process handle is no longer owned by this runtime",
                ERROR_INVALID_HANDLE);
            return result;
        }
        const DWORD waited = WaitForSingleObject(impl_->process.get(),
                                                  timeoutMs);
        if(waited == WAIT_TIMEOUT)
        {
            result.ok = true;
            result.timedOut = true;
            return result;
        }
        if(waited != WAIT_OBJECT_0)
        {
            const DWORD code = GetLastError();
            result.error = runtimeError("process_wait_failed",
                "WaitForSingleObject failed for the child process", code,
                StandardStream::None, true);
            return result;
        }
        DWORD exitCode = STILL_ACTIVE;
        if(!GetExitCodeProcess(impl_->process.get(), &exitCode))
        {
            const DWORD code = GetLastError();
            result.error = runtimeError("exit_code_query_failed",
                "GetExitCodeProcess failed", code);
            return result;
        }
        result.ok = true;
        result.exited = true;
        result.exitCode = exitCode;
        return result;
    }

    OperationResult LaunchRuntime::terminate(
        UINT exitCode, DWORD timeoutMs) noexcept
    {
        OperationResult result;
        if(!impl_)
        {
            result.error = runtimeError("runtime_invalid",
                "the launch runtime is not initialized");
            return result;
        }
        try
        {
            return terminateProcessBounded(
                impl_->process.get(), exitCode, timeoutMs);
        }
        catch(const std::exception& exception)
        {
            result.error = runtimeError(
                "terminate_exception", exception.what(),
                ERROR_SUCCESS, StandardStream::None, true);
        }
        catch(...)
        {
            result.error = runtimeError(
                "terminate_exception",
                "an unknown exception occurred while terminating the process",
                ERROR_SUCCESS, StandardStream::None, true);
        }
        return result;
    }

    OperationResult LaunchRuntime::closeResources(DWORD timeoutMs) noexcept
    {
        OperationResult result;
        if(!impl_)
        {
            result.error = runtimeError("runtime_invalid",
                "the launch runtime is not initialized");
            return result;
        }
        return impl_->shutdown(timeoutMs);
    }
}

#endif
