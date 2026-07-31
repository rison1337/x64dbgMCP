#include "file_identity.hpp"
#include "launch_runtime.hpp"

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

#ifdef _WIN32
#include <windows.h>
#endif

static int failures = 0;

#define CHECK(expr)                                                                 \
    do                                                                              \
    {                                                                               \
        if(!(expr))                                                                 \
        {                                                                           \
            std::cerr << __FILE__ << ':' << __LINE__ << ": CHECK failed: " #expr \
                      << '\n';                                                       \
            ++failures;                                                             \
        }                                                                           \
    } while(false)

#ifdef _WIN32
namespace
{
    std::wstring executableDirectory()
    {
        std::vector<wchar_t> buffer(32768, L'\0');
        const DWORD length = GetModuleFileNameW(
            nullptr, buffer.data(), static_cast<DWORD>(buffer.size()));
        if(length == 0 || length >= buffer.size())
            return {};
        std::wstring path(buffer.data(), length);
        const size_t slash = path.find_last_of(L"\\/");
        return slash == std::wstring::npos ? std::wstring() :
                                             path.substr(0, slash);
    }

    std::wstring joinPath(const std::wstring& directory,
                          const std::wstring& leaf)
    {
        if(directory.empty())
            return leaf;
        return directory + (directory.back() == L'\\' ? L"" : L"\\") + leaf;
    }

    std::wstring fixturePath()
    {
        return joinPath(executableDirectory(), L"launch_runtime_fixture.exe");
    }

    std::wstring makeWorkingDirectory()
    {
        wchar_t root[MAX_PATH] = {};
        if(GetTempPathW(_countof(root), root) == 0)
            return {};
        const std::wstring parent = joinPath(
            root, L"x64dbgMCP-launch-runtime-" +
                      std::to_wstring(GetCurrentProcessId()));
        CreateDirectoryW(parent.c_str(), nullptr);
        const std::wstring directory = joinPath(parent, L"launch_тест");
        if(!CreateDirectoryW(directory.c_str(), nullptr) &&
           GetLastError() != ERROR_ALREADY_EXISTS)
            return {};
        const std::wstring marker = joinPath(directory, L"cwd_marker.txt");
        HANDLE file = CreateFileW(marker.c_str(), GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
        if(file == INVALID_HANDLE_VALUE)
            return {};
        const char contents[] = "marker";
        DWORD written = 0;
        const BOOL wrote = WriteFile(file, contents,
                                     static_cast<DWORD>(sizeof(contents) - 1),
                                     &written, nullptr);
        CloseHandle(file);
        return wrote ? directory : std::wstring();
    }

    void removeWorkingDirectory(const std::wstring& directory)
    {
        if(directory.empty())
            return;
        DeleteFileW(joinPath(directory, L"cwd_marker.txt").c_str());
        RemoveDirectoryW(directory.c_str());
        const size_t slash = directory.find_last_of(L"\\/");
        if(slash != std::wstring::npos)
            RemoveDirectoryW(directory.substr(0, slash).c_str());
    }

    mcplaunch::LaunchSpec redirectedSpec()
    {
        mcplaunch::LaunchSpec spec;
        spec.executable = fixturePath();
        spec.stdinSpec.mode = mcplaunch::StdioMode::Null;
        spec.stdoutSpec.mode = mcplaunch::StdioMode::Pipe;
        spec.stderrSpec.mode = mcplaunch::StdioMode::Pipe;
        spec.captureCapacity = 1u << 20;
        spec.stdinQueueCapacity = 1u << 20;
        return spec;
    }

    void reportLaunchFailure(const mcplaunch::LaunchResult& result,
                             const char* context)
    {
        if(result.ok)
            return;
        std::cerr << context << ": code=" << result.error.code
                  << " win32=" << result.error.win32Error
                  << " message=" << result.error.message << '\n';
    }

    bool waitForCaptureEof(mcplaunch::LaunchRuntime& runtime,
                           DWORD timeoutMs)
    {
        const auto deadline = std::chrono::steady_clock::now() +
                              std::chrono::milliseconds(timeoutMs);
        while(std::chrono::steady_clock::now() < deadline)
        {
            const auto state = runtime.state();
            if(state.stdoutEof && state.stderrEof)
                return true;
            std::this_thread::sleep_for(std::chrono::milliseconds(2));
        }
        return false;
    }

    bool containsBytes(const std::vector<uint8_t>& haystack,
                       const std::string& needle)
    {
        return std::search(haystack.begin(), haystack.end(),
            needle.begin(), needle.end()) != haystack.end();
    }

    uint64_t fnv1a64(const std::vector<uint8_t>& bytes)
    {
        uint64_t value = 14695981039346656037ull;
        for(const uint8_t byte : bytes)
        {
            value ^= byte;
            value *= 1099511628211ull;
        }
        return value;
    }

    bool runToExit(mcplaunch::LaunchRuntime& runtime,
                   DWORD expectedExit,
                   DWORD timeoutMs = 10000)
    {
        const auto resumed = runtime.resumeAfterValidation();
        CHECK(resumed.ok && !resumed.remainsSuspended);
        if(!resumed.ok || resumed.remainsSuspended)
            return false;
        const auto committed = runtime.commitExternalDebuggerOwnership();
        CHECK(committed.ok);
        if(!committed.ok)
            return false;
        const auto waited = runtime.wait(timeoutMs);
        CHECK(waited.ok && waited.exited && !waited.timedOut);
        CHECK(waited.exitCode == expectedExit);
        if(!waited.ok || !waited.exited)
            runtime.terminate(0xE001u);
        return waited.ok && waited.exited && waited.exitCode == expectedExit;
    }

    void testTypedArgvEnvironmentCwd()
    {
        const std::wstring workingDirectory = makeWorkingDirectory();
        CHECK(!workingDirectory.empty());
        auto spec = redirectedSpec();
        spec.arguments = {
            L"--case", L"argv-env-cwd", L"", L"plain", L"two words",
            L"quote\"inside", L"slashes\\\\before\"quote", L"trailing\\",
            L"punctuation !@#$%^&*()[]{};,.?", L"Привет 世界 🙂"
        };
        spec.workingDirectory = workingDirectory;
        spec.inheritEnvironment = false;
        spec.environmentOverrides = {
            mcplaunch::EnvironmentEntry::set(
                L"X64DBG_MCP_E2E_ENV_SET", L"значение-世界"),
            mcplaunch::EnvironmentEntry::set(
                L"X64DBG_MCP_E2E_ENV_EMPTY", L""),
            mcplaunch::EnvironmentEntry::erase(
                L"X64DBG_MCP_E2E_ENV_DELETE"),
            mcplaunch::EnvironmentEntry::erase(
                L"X64DBG_MCP_E2E_ENV_ABSENT"),
        };
        auto created = mcplaunch::LaunchRuntime::createSuspended(spec);
        reportLaunchFailure(created, "typed argv/env/cwd");
        CHECK(created.ok && created.runtime);
        if(created.ok && created.runtime)
        {
            CHECK(created.info.processId != 0);
            CHECK(created.info.primaryThreadId != 0);
            CHECK(created.info.createdSuspended);
            CHECK(!created.info.launchId.empty());
            CHECK(runToExit(*created.runtime, 37));
            CHECK(waitForCaptureEof(*created.runtime, 5000));
            const auto output = created.runtime->readStdout(0, 1u << 20);
            const auto error = created.runtime->readStderr(0, 1u << 20);
            CHECK(output.ok && output.capture.eof);
            CHECK(error.ok && error.capture.eof);
            CHECK(containsBytes(output.capture.bytes, "ARGV_ENV_CWD_OK"));
            CHECK(error.capture.bytes.empty());
        }
        removeWorkingDirectory(workingDirectory);
    }

    void testBinaryStreams()
    {
        auto spec = redirectedSpec();
        spec.arguments = {L"--case", L"stream"};
        spec.stdinSpec.mode = mcplaunch::StdioMode::Bytes;
        spec.stdinSpec.initialBytes.resize(257);
        for(size_t index = 0; index < spec.stdinSpec.initialBytes.size(); ++index)
            spec.stdinSpec.initialBytes[index] =
                static_cast<uint8_t>((index * 37u + 11u) & 0xffu);
        spec.stdinSpec.initialBytes[0] = 0;
        spec.stdinSpec.initialBytes[1] = 0xff;

        const uint64_t digest = fnv1a64(spec.stdinSpec.initialBytes);
        const size_t nulCount = static_cast<size_t>(std::count(
            spec.stdinSpec.initialBytes.begin(),
            spec.stdinSpec.initialBytes.end(), uint8_t{0}));
        const size_t ffCount = static_cast<size_t>(std::count(
            spec.stdinSpec.initialBytes.begin(),
            spec.stdinSpec.initialBytes.end(), uint8_t{0xff}));
        std::ostringstream stdoutLine;
        stdoutLine << "STREAM_STDOUT count=257 fnv1a64=" << std::uppercase
                   << std::hex << std::setw(16) << std::setfill('0') << digest
                   << std::dec << " nul=" << nulCount << " ff=" << ffCount
                   << " channel=stdout";
        std::ostringstream stderrLine;
        stderrLine << "STREAM_STDERR count=257 fnv1a64=" << std::uppercase
                   << std::hex << std::setw(16) << std::setfill('0') << digest
                   << std::dec << " nul=" << nulCount << " ff=" << ffCount
                   << " channel=stderr";

        auto created = mcplaunch::LaunchRuntime::createSuspended(spec);
        reportLaunchFailure(created, "binary streams");
        CHECK(created.ok && created.runtime);
        if(created.ok && created.runtime)
        {
            CHECK(runToExit(*created.runtime, 0));
            CHECK(waitForCaptureEof(*created.runtime, 5000));
            const auto output = created.runtime->readStdout(0, 1u << 20);
            const auto error = created.runtime->readStderr(0, 1u << 20);
            CHECK(output.ok && output.capture.eof &&
                  output.capture.totalDroppedBytes == 0);
            CHECK(error.ok && error.capture.eof &&
                  error.capture.totalDroppedBytes == 0);
            CHECK(containsBytes(output.capture.bytes, stdoutLine.str()));
            CHECK(containsBytes(error.capture.bytes, stderrLine.str()));
            const std::vector<uint8_t> binaryMarker = {
                'S', 'T', 'R', 'E', 'A', 'M', '_', 'S', 'T', 'D', 'O',
                'U', 'T', 0x00, 0xff, '\n'
            };
            CHECK(std::search(output.capture.bytes.begin(),
                              output.capture.bytes.end(),
                              binaryMarker.begin(), binaryMarker.end()) !=
                  output.capture.bytes.end());
        }
    }

    void testBurstDrainAndBoundedRetention()
    {
        auto spec = redirectedSpec();
        spec.arguments = {L"--case", L"burst"};
        spec.captureCapacity = 64u * 1024u;
        auto created = mcplaunch::LaunchRuntime::createSuspended(spec);
        reportLaunchFailure(created, "burst");
        CHECK(created.ok && created.runtime);
        if(created.ok && created.runtime)
        {
            CHECK(runToExit(*created.runtime, 0, 30000));
            CHECK(waitForCaptureEof(*created.runtime, 5000));
            const auto output = created.runtime->readStdout(0, 1u << 20);
            const auto error = created.runtime->readStderr(0, 1u << 20);
            CHECK(output.ok && output.capture.eof);
            CHECK(error.ok && error.capture.eof);
            CHECK(output.capture.newestCursor > 2u * 1024u * 1024u);
            CHECK(error.capture.newestCursor > 2u * 1024u * 1024u);
            CHECK(output.capture.cursorTruncated &&
                  output.capture.totalDroppedBytes != 0);
            CHECK(error.capture.cursorTruncated &&
                  error.capture.totalDroppedBytes != 0);
            CHECK(containsBytes(output.capture.bytes, "BURST_STDOUT_END"));
            CHECK(containsBytes(error.capture.bytes, "BURST_STDERR_END"));
        }
    }

    void testValidationAndFailureCleanup()
    {
        auto missing = redirectedSpec();
        missing.executable = L"C:\\definitely-missing\\fixture.exe";
        auto result = mcplaunch::LaunchRuntime::createSuspended(missing);
        CHECK(!result.ok && result.error.code == "create_process_failed");

        auto mixed = redirectedSpec();
        mixed.stdinSpec.mode = mcplaunch::StdioMode::Console;
        result = mcplaunch::LaunchRuntime::createSuspended(mixed);
        CHECK(!result.ok && result.error.code == "console_mode_mixed");

        auto invalidInherit = redirectedSpec();
        invalidInherit.stdinSpec.mode = mcplaunch::StdioMode::Inherit;
        invalidInherit.stdinSpec.inheritHandle = INVALID_HANDLE_VALUE;
        result = mcplaunch::LaunchRuntime::createSuspended(invalidInherit);
        CHECK(!result.ok && result.error.stream ==
                               mcplaunch::StandardStream::Stdin);

        wchar_t root[MAX_PATH] = {};
        CHECK(GetTempPathW(_countof(root), root) != 0);
        const std::wstring collision = joinPath(root, L"mcp-launch-collision.tmp");
        auto sameFile = redirectedSpec();
        sameFile.stdinSpec.mode = mcplaunch::StdioMode::Null;
        sameFile.stdoutSpec.mode = mcplaunch::StdioMode::File;
        sameFile.stderrSpec.mode = mcplaunch::StdioMode::File;
        sameFile.stdoutSpec.filePath = collision;
        sameFile.stderrSpec.filePath = collision;
        result = mcplaunch::LaunchRuntime::createSuspended(sameFile);
        CHECK(!result.ok && result.error.code == "output_file_collision");
        DeleteFileW(collision.c_str());

        auto conflict = redirectedSpec();
        conflict.arguments = {L"x"};
        conflict.rawCommandLineTail = L"raw";
        result = mcplaunch::LaunchRuntime::createSuspended(conflict);
        CHECK(!result.ok &&
              result.error.code == "command_line_mode_conflict");

        // The first formatted Win32 failure can lazily load system MUI data.
        // Take the leak baseline after every error family has been warmed, then
        // prove repeated transactional failures do not retain owned handles.
        DWORD before = 0;
        CHECK(GetProcessHandleCount(GetCurrentProcess(), &before));
        for(size_t iteration = 0; iteration < 100; ++iteration)
        {
            result = mcplaunch::LaunchRuntime::createSuspended(missing);
            CHECK(!result.ok && result.error.code == "create_process_failed");
            result = mcplaunch::LaunchRuntime::createSuspended(invalidInherit);
            CHECK(!result.ok && result.error.stream ==
                                   mcplaunch::StandardStream::Stdin);
            result = mcplaunch::LaunchRuntime::createSuspended(sameFile);
            CHECK(!result.ok && result.error.code == "output_file_collision");
        }
        DWORD after = 0;
        CHECK(GetProcessHandleCount(GetCurrentProcess(), &after));
        if(after > before + 1)
            std::cerr << "failure-cleanup handle baseline=" << before
                      << " final=" << after << '\n';
        CHECK(after <= before + 1);
    }

    void testExternalSuspendCountOwnership()
    {
        auto spec = redirectedSpec();
        spec.arguments = {L"--case", L"quick"};
        spec.stdinSpec.mode = mcplaunch::StdioMode::Null;
        spec.stdoutSpec.mode = mcplaunch::StdioMode::Null;
        spec.stderrSpec.mode = mcplaunch::StdioMode::Null;
        auto created = mcplaunch::LaunchRuntime::createSuspended(spec);
        reportLaunchFailure(created, "external suspend ownership");
        CHECK(created.ok && created.runtime);
        if(!created.ok || !created.runtime)
            return;

        // Simulate x64dbg contributing one independent suspend count after it
        // attaches. The runtime must remove exactly its CREATE_SUSPENDED count,
        // preserve the debugger-owned count, and still permit ownership commit.
        const DWORD beforeExternalSuspend =
            SuspendThread(created.runtime->nativePrimaryThreadHandle());
        CHECK(beforeExternalSuspend == 1);
        const auto resumed = created.runtime->resumeAfterValidation();
        CHECK(resumed.ok);
        CHECK(resumed.previousSuspendCount == 2);
        CHECK(resumed.remainsSuspended);
        CHECK(!created.runtime->state().suspended);
        const auto committed =
            created.runtime->commitExternalDebuggerOwnership();
        CHECK(committed.ok);
        const DWORD beforeExternalResume =
            ResumeThread(created.runtime->nativePrimaryThreadHandle());
        CHECK(beforeExternalResume == 1);
        const auto waited = created.runtime->wait(10000);
        CHECK(waited.ok && waited.exited && waited.exitCode == 0);
        if(!waited.ok || !waited.exited)
            created.runtime->terminate(0xE002u);
    }

    void testOneHundredQuickLaunches()
    {
        auto spec = redirectedSpec();
        spec.arguments = {L"--case", L"quick"};
        spec.stdinSpec.mode = mcplaunch::StdioMode::Null;
        spec.stdoutSpec.mode = mcplaunch::StdioMode::Null;
        spec.stderrSpec.mode = mcplaunch::StdioMode::Null;

        // Warm up loader/runtime allocations before taking the handle baseline.
        {
            auto warmup = mcplaunch::LaunchRuntime::createSuspended(spec);
            reportLaunchFailure(warmup, "quick warmup");
            CHECK(warmup.ok && warmup.runtime);
            if(warmup.ok && warmup.runtime)
                CHECK(runToExit(*warmup.runtime, 0));
        }
        DWORD before = 0;
        CHECK(GetProcessHandleCount(GetCurrentProcess(), &before));
        for(size_t iteration = 0; iteration < 100; ++iteration)
        {
            auto created = mcplaunch::LaunchRuntime::createSuspended(spec);
            reportLaunchFailure(created, "quick cycle");
            CHECK(created.ok && created.runtime);
            if(!created.ok || !created.runtime)
                break;
            const DWORD pid = created.info.processId;
            const uint64_t creation = created.info.creationTime100ns;
            CHECK(runToExit(*created.runtime, 0));
            CHECK(created.runtime->state().exited);
            CHECK(created.info.processId == pid &&
                  created.info.creationTime100ns == creation);
        }
        DWORD after = 0;
        CHECK(GetProcessHandleCount(GetCurrentProcess(), &after));
        CHECK(after <= before + 2);
    }

    void testBoundedCloseUnderBlockedIo()
    {
        auto spec = redirectedSpec();
        spec.arguments = {L"--case", L"quick"};
        spec.stdinSpec.mode = mcplaunch::StdioMode::Pipe;
        spec.stdoutSpec.mode = mcplaunch::StdioMode::Null;
        spec.stderrSpec.mode = mcplaunch::StdioMode::Null;
        spec.stdinQueueCapacity = 2u * 1024u * 1024u;

        auto created = mcplaunch::LaunchRuntime::createSuspended(spec);
        reportLaunchFailure(created, "bounded close");
        CHECK(created.ok && created.runtime);
        if(!created.ok || !created.runtime)
            return;

        HANDLE cleanupProcess = nullptr;
        CHECK(DuplicateHandle(
            GetCurrentProcess(), created.runtime->nativeProcessHandle(),
            GetCurrentProcess(), &cleanupProcess, 0, FALSE,
            DUPLICATE_SAME_ACCESS) != FALSE);

        // Keep the child suspended after the runtime releases its own
        // CREATE_SUSPENDED count.  The stdin worker must then remain in a
        // synchronous WriteFile once the anonymous pipe fills.
        const DWORD externalSuspend =
            SuspendThread(created.runtime->nativePrimaryThreadHandle());
        CHECK(externalSuspend == 1);
        const auto resumed = created.runtime->resumeAfterValidation();
        CHECK(resumed.ok && resumed.remainsSuspended);
        const auto committed =
            created.runtime->commitExternalDebuggerOwnership();
        CHECK(committed.ok);

        std::vector<uint8_t> payload(2u * 1024u * 1024u, 0xA5u);
        const auto queued = created.runtime->writeInput(payload, 0);
        CHECK(queued.ok && queued.acceptedBytes == payload.size());
        std::this_thread::sleep_for(std::chrono::milliseconds(50));

        const auto firstClose = created.runtime->closeResources(0);
        if(!firstClose.ok)
        {
            const auto timedState = created.runtime->state();
            CHECK(timedState.teardown.requested);
            CHECK(timedState.teardown.timedOut ||
                  firstClose.error.retryable);
        }

        const auto started = std::chrono::steady_clock::now();
        const auto closed = firstClose.ok
            ? firstClose
            : created.runtime->closeResources(3000);
        const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - started).count();
        CHECK(closed.ok);
        CHECK(elapsed < 3500);
        const auto finalState = created.runtime->state();
        CHECK(finalState.teardown.complete);
        CHECK(finalState.teardown.workerCount >= 1);
        CHECK(finalState.teardown.workersStopped ==
              finalState.teardown.workerCount);
        CHECK(created.runtime->closeResources(0).ok);
        const auto resumeAfterClose =
            created.runtime->resumeAfterValidation();
        CHECK(!resumeAfterClose.ok &&
              resumeAfterClose.error.code == "runtime_resources_closed");
        const auto commitAfterClose =
            created.runtime->commitExternalDebuggerOwnership();
        CHECK(!commitAfterClose.ok &&
              commitAfterClose.error.code == "runtime_resources_closed");

        CHECK(cleanupProcess != nullptr);
        if(cleanupProcess)
        {
            TerminateProcess(cleanupProcess, 0xE100u);
            CHECK(WaitForSingleObject(cleanupProcess, 3000) == WAIT_OBJECT_0);
            CloseHandle(cleanupProcess);
        }

        const auto rejected = created.runtime->writeInput(
            std::vector<uint8_t>{0x01u}, 0);
        CHECK(!rejected.ok &&
              rejected.error.code == "runtime_resources_closed");
    }

    void testBoundedCloseStress()
    {
        auto spec = redirectedSpec();
        spec.arguments = {L"--case", L"quick"};
        spec.stdinSpec.mode = mcplaunch::StdioMode::Null;
        spec.stdoutSpec.mode = mcplaunch::StdioMode::Null;
        spec.stderrSpec.mode = mcplaunch::StdioMode::Null;
        DWORD before = 0;
        CHECK(GetProcessHandleCount(GetCurrentProcess(), &before));
        for(size_t iteration = 0; iteration < 50; ++iteration)
        {
            auto created = mcplaunch::LaunchRuntime::createSuspended(spec);
            reportLaunchFailure(created, "bounded close stress");
            CHECK(created.ok && created.runtime);
            if(!created.ok || !created.runtime)
                break;
            const auto closed = created.runtime->closeResources(3000);
            CHECK(closed.ok);
            CHECK(created.runtime->state().teardown.complete);
        }
        DWORD after = 0;
        CHECK(GetProcessHandleCount(GetCurrentProcess(), &after));
        CHECK(after <= before + 2);
    }
}

int wmain()
{
    const auto fixture = mcplaunch::identifyFileByPath(fixturePath());
    CHECK(fixture.ok && fixture.size != 0 && fixture.sha256.size() == 64);
    testTypedArgvEnvironmentCwd();
    testBinaryStreams();
    testBurstDrainAndBoundedRetention();
    testValidationAndFailureCleanup();
    testExternalSuspendCountOwnership();
    testOneHundredQuickLaunches();
    testBoundedCloseUnderBlockedIo();
    testBoundedCloseStress();
    if(failures)
    {
        std::cerr << failures << " native launch-runtime test(s) failed\n";
        return 1;
    }
    std::cout << "native launch-runtime tests passed\n";
    return 0;
}
#else
int main() { return 0; }
#endif
