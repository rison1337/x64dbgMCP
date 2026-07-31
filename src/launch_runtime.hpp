#pragma once

#include "launch_core.hpp"

#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace mcplaunch
{
#ifdef _WIN32
    enum class StandardStream
    {
        None,
        Stdin,
        Stdout,
        Stderr,
    };

    // Console deliberately means "let CreateProcess initialize all standard
    // handles from the attached console".  It is therefore valid only when
    // all three streams use Console.  Inherit is an explicit, duplicated and
    // allow-listed handle and may be mixed with the redirected modes.
    enum class StdioMode
    {
        Console,
        Inherit,
        Null,
        File,
        Bytes,
        Pipe,
    };

    enum class FileWriteMode
    {
        Truncate,
        Append,
    };

    struct InputSpec
    {
        StdioMode mode = StdioMode::Inherit;
        std::wstring filePath;
        HANDLE inheritHandle = nullptr; // nullptr selects GetStdHandle.
        std::vector<uint8_t> initialBytes;
    };

    struct OutputSpec
    {
        StdioMode mode = StdioMode::Inherit;
        std::wstring filePath;
        HANDLE inheritHandle = nullptr; // nullptr selects GetStdHandle.
        FileWriteMode writeMode = FileWriteMode::Truncate;
    };

    struct LaunchSpec
    {
        std::wstring executable;
        std::vector<std::wstring> arguments;
        // When present, the tail is preserved byte-for-code-unit after the
        // quoted argv[0].  It is mutually exclusive with arguments.
        std::optional<std::wstring> rawCommandLineTail;
        std::optional<std::wstring> workingDirectory;

        // If inheritEnvironment is true and inheritedEnvironmentSnapshot is
        // absent, createSuspended snapshots the current process environment.
        // Supplying a snapshot makes creation reproducible and avoids reading
        // mutable process state.  Overrides are then applied transactionally.
        bool inheritEnvironment = true;
        std::optional<std::vector<EnvironmentEntry>>
            inheritedEnvironmentSnapshot;
        std::vector<EnvironmentEntry> environmentOverrides;

        InputSpec stdinSpec;
        OutputSpec stdoutSpec;
        OutputSpec stderrSpec;

        size_t captureCapacity = 4u * 1024u * 1024u;
        size_t stdinQueueCapacity = 1u * 1024u * 1024u;
    };

    struct RuntimeError
    {
        std::string code;
        std::string message;
        DWORD win32Error = ERROR_SUCCESS;
        StandardStream stream = StandardStream::None;
        bool retryable = false;

        explicit operator bool() const noexcept { return !code.empty(); }
    };

    struct StreamDescriptor
    {
        StdioMode mode = StdioMode::Console;
        std::wstring path;
        bool redirected = false;
        bool captured = false;
        bool writable = false;
    };

    struct LaunchInfo
    {
        std::string launchId;
        DWORD processId = 0;
        DWORD primaryThreadId = 0;
        uint64_t creationTime100ns = 0;
        bool createdSuspended = false;
        StreamDescriptor stdinStream;
        StreamDescriptor stdoutStream;
        StreamDescriptor stderrStream;
    };

    struct OperationResult
    {
        bool ok = false;
        RuntimeError error;
    };

    struct ResumeResult
    {
        bool ok = false;
        DWORD previousSuspendCount = 0;
        bool remainsSuspended = false;
        RuntimeError error;
    };

    struct WriteInputResult
    {
        bool ok = false;
        size_t acceptedBytes = 0;
        size_t queuedBytes = 0;
        size_t queueCapacity = 0;
        bool closed = false;
        bool wouldBlock = false;
        RuntimeError error;
    };

    struct CaptureReadResult
    {
        bool ok = false;
        ByteRingReadResult capture;
        RuntimeError error;
    };

    struct WaitResult
    {
        bool ok = false;
        bool exited = false;
        bool timedOut = false;
        DWORD exitCode = STILL_ACTIVE;
        RuntimeError error;
    };

    struct TeardownStatus
    {
        bool requested = false;
        bool complete = false;
        bool timedOut = false;
        bool processTerminationRequested = false;
        bool processExited = false;
        DWORD timeoutMs = 0;
        size_t workerCount = 0;
        size_t workersStopped = 0;
        size_t cancellationAttempts = 0;
        size_t cancellationFailures = 0;
        RuntimeError error;
    };

    struct ProcessState
    {
        DWORD processId = 0;
        DWORD primaryThreadId = 0;
        bool suspended = false;
        bool resumeSubmitted = false;
        bool running = false;
        bool exited = false;
        bool exitCodeKnown = false;
        DWORD exitCode = STILL_ACTIVE;
        bool stdinOpen = false;
        bool stdoutEof = false;
        bool stderrEof = false;
        size_t stdinQueuedBytes = 0;
        RuntimeError stdinError;
        RuntimeError stdoutError;
        RuntimeError stderrError;
        TeardownStatus teardown;
    };

    class LaunchRuntime;

    struct LaunchResult
    {
        bool ok = false;
        std::unique_ptr<LaunchRuntime> runtime;
        LaunchInfo info;
        RuntimeError error;
    };

    // Owns the child process and all parent-side redirected handles.  Until
    // commitExternalDebuggerOwnership succeeds, destruction terminates a
    // still-live child.  A committed runtime instead cancels/closes its local
    // I/O and handles without terminating the externally owned debuggee.
    // Both paths stop every worker against a bounded deadline.  A failed
    // close keeps the runtime intact so its owner can inspect the explicit
    // teardown status and retry without racing live I/O.
    class LaunchRuntime
    {
    public:
        static LaunchResult createSuspended(const LaunchSpec& spec) noexcept;

        ~LaunchRuntime() noexcept;
        LaunchRuntime(const LaunchRuntime&) = delete;
        LaunchRuntime& operator=(const LaunchRuntime&) = delete;
        LaunchRuntime(LaunchRuntime&&) = delete;
        LaunchRuntime& operator=(LaunchRuntime&&) = delete;

        LaunchInfo info() const;
        ProcessState state() const noexcept;

        // Returned handles are borrowed and remain owned by this object.
        HANDLE nativeProcessHandle() const noexcept;
        HANDLE nativePrimaryThreadHandle() const noexcept;

        ResumeResult resumeAfterValidation() noexcept;
        // Call only after an external debugger has verified attachment and
        // resumeAfterValidation has fully removed this runtime's suspension.
        // On success, destruction no longer terminates the process.
        OperationResult commitExternalDebuggerOwnership() noexcept;
        WriteInputResult writeInput(const void* bytes,
                                    size_t size,
                                    DWORD timeoutMs = 0) noexcept;
        WriteInputResult writeInput(const std::vector<uint8_t>& bytes,
                                    DWORD timeoutMs = 0) noexcept;
        OperationResult closeInput() noexcept;

        CaptureReadResult readStdout(uint64_t cursor,
                                     size_t maxBytes) const noexcept;
        CaptureReadResult readStderr(uint64_t cursor,
                                     size_t maxBytes) const noexcept;

        WaitResult wait(DWORD timeoutMs = INFINITE) noexcept;
        OperationResult terminate(UINT exitCode = 1,
                                  DWORD timeoutMs = 5000) noexcept;
        OperationResult closeResources(DWORD timeoutMs = 5000) noexcept;

    private:
        struct Impl;
        explicit LaunchRuntime(std::unique_ptr<Impl> impl) noexcept;
        std::unique_ptr<Impl> impl_;
    };
#endif
}
