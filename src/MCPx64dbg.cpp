#define _WINSOCK_DEPRECATED_NO_WARNINGS
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX

#include <Windows.h>
#include <DbgHelp.h>
#include <bcrypt.h>
#include <sddl.h>
#include <shlobj.h>
#include "bridge_core.hpp"
#include "exception_policy_core.hpp"
#include "file_identity.hpp"
#include "launch_core.hpp"
#include "launch_runtime.hpp"
#include "child_broker_core.hpp"
#include "http_parser_core.hpp"
#include "request_dispatcher_core.hpp"
#include "mutation_transaction_core.hpp"
#include "bridgemain.h"
#include "_plugins.h"
#include "_scriptapi_module.h"
#include "_scriptapi_memory.h"
#include "_scriptapi_register.h"
#include "_scriptapi_debug.h"
#include "_scriptapi_assembler.h"
#include "_scriptapi_comment.h"
#include "_scriptapi_label.h"
#include "_scriptapi_bookmark.h"
#include "_scriptapi_function.h"
#include "_scriptapi_argument.h"
#include "_scriptapi_symbol.h"
#include "_scriptapi_stack.h"
#include "_scriptapi_pattern.h"
#include "_scriptapi_flag.h"
#include "_scriptapi_gui.h"
#include "_scriptapi_misc.h"
#include <iomanip>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <string>
#include <string_view>
#include <vector>
#include <unordered_map>
#include <unordered_set>
#include <sstream>
#include <mutex>
#include <condition_variable>
#include <thread>
#include <deque>
#include <algorithm>
#include <cctype>
#include <cstdio>
#include <cstring>
#include <cerrno>
#include <cstdlib>
#include <chrono>
#include <stdexcept>
#include <atomic>
#include <limits>
#include <cwctype>
#include <eh.h>
#include <memory>
#include <fstream>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "dbghelp.lib")
#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "ole32.lib")

#ifdef _WIN64
#define FMT_DUINT_HEX "0x%llx"
#define FMT_DUINT_DEC "%llu"
#define DUINT_CAST_PRINTF(v) (unsigned long long)(v)
#define DUSIZE_CAST_PRINTF(v) (unsigned long long)(v)
#define REG_IP Script::Register::RIP
#else
#define FMT_DUINT_HEX "0x%08X"
#define FMT_DUINT_DEC "%u"
#define DUINT_CAST_PRINTF(v) (unsigned int)(v)
#define DUSIZE_CAST_PRINTF(v) (unsigned int)(v)
#define REG_IP Script::Register::EIP
#endif

#define PLUGIN_NAME "x64dbg HTTP Server"
#define PLUGIN_VERSION 3
#define DEFAULT_PORT 8888
#define MAX_REQUEST_SIZE 8192
constexpr unsigned int MAX_SERVER_WAIT_SLICE_MS = 750;
constexpr size_t MAX_HTTP_CONCURRENT_WORKERS = 8;
constexpr size_t MAX_HTTP_ADMITTED_CLIENTS = 32;
constexpr unsigned int MAX_HTTP_QUEUE_WAIT_MS = 5000;
constexpr unsigned int MAX_SERIALIZED_ROUTE_WAIT_MS = 5000;
std::mutex g_serializedRouteMutex;
std::condition_variable g_serializedRouteCv;
mcpdispatcher::FairAdmissionQueue g_serializedRouteQueue(
    1, MAX_HTTP_ADMITTED_CLIENTS);

// A debugger instance normally uses the historical 8888 port.  Multi-instance
// child debugging starts isolated x32/x64dbg processes with an explicit
// X64DBG_MCP_PORT environment value, so each plugin can publish its own
// authenticated descriptor without racing the primary bridge.  Invalid or
// out-of-range values fail closed to the default rather than binding an
// unintended interface/port.
static int configuredPortFromEnvironment()
{
    char buffer[32] = {};
    const DWORD length = GetEnvironmentVariableA(
        "X64DBG_MCP_PORT", buffer, static_cast<DWORD>(sizeof(buffer)));
    if(length == 0 || length >= sizeof(buffer))
        return DEFAULT_PORT;
    int parsed = -1;
    if(!mcpbridge::parseListenPortExact(
        std::string_view(buffer, static_cast<size_t>(length)), parsed))
    {
        return DEFAULT_PORT;
    }
    return parsed;
}

#ifndef MCP_BRIDGE_BUILD_ID
#define MCP_BRIDGE_BUILD_ID "unknown"
#endif
#ifndef MCP_BRIDGE_SOURCE_ID
#define MCP_BRIDGE_SOURCE_ID "unknown"
#endif
#ifndef MCP_ROUTE_POLICY_ID
#define MCP_ROUTE_POLICY_ID "unknown"
#endif

int g_pluginHandle;
std::string g_bridgeInstanceId;
ULONGLONG g_debuggerProcessStartTime100ns = 0;
std::string g_bridgeAuthToken;
std::wstring g_bridgeAuthFilePath;

enum class HttpLifecycleState
{
    Stopped,
    Starting,
    Running,
    Stopping,
    Failed,
};

struct HttpServerControl
{
    std::mutex mutex;
    std::condition_variable cv;
    HANDLE thread = NULL;
    SOCKET listenSocket = INVALID_SOCKET;
    std::unordered_set<SOCKET> activeClientSockets;
    mcpdispatcher::FairAdmissionQueue dispatcher{
        MAX_HTTP_CONCURRENT_WORKERS, MAX_HTTP_ADMITTED_CLIENTS};
    // Counts thread lifetime, including the short response/cleanup tail after a
    // queue cancellation.  The server thread waits for zero before unload.
    size_t liveWorkerCount = 0;
    std::atomic<bool> stopRequested{false};
    HttpLifecycleState state = HttpLifecycleState::Stopped;
    int configuredPort = DEFAULT_PORT;
    int boundPort = 0;
    DWORD threadExitCode = 0;
    std::string lastError;
};

HttpServerControl g_httpServer;
thread_local bool g_insideHttpRequestWorker = false;

class HttpRequestWorkerScope
{
public:
    HttpRequestWorkerScope() noexcept
        : previous_(g_insideHttpRequestWorker)
    {
        g_insideHttpRequestWorker = true;
    }

    ~HttpRequestWorkerScope() noexcept
    {
        g_insideHttpRequestWorker = previous_;
    }

    HttpRequestWorkerScope(const HttpRequestWorkerScope&) = delete;
    HttpRequestWorkerScope& operator=(const HttpRequestWorkerScope&) = delete;

private:
    bool previous_ = false;
};

// RAII: guarantees an accepted client socket is closed on every exit path from
// the request loop body -- the many early `continue` branches, an exception, or
// the normal fall-through. Previously only the fall-through path closed the
// socket, so every validation/error branch leaked a Windows handle.
struct ClientSocketGuard {
    SOCKET sock;
    explicit ClientSocketGuard(SOCKET s) : sock(s) {}
    ~ClientSocketGuard() {
        if (sock == INVALID_SOCKET) return;
        bool closeOwned = false;
        {
            std::lock_guard<std::mutex> lock(g_httpServer.mutex);
            const auto erased = g_httpServer.activeClientSockets.erase(sock);
            if (erased != 0) {
                closeOwned = true;
            }
        }
        if (closeOwned) closesocket(sock);
    }
    ClientSocketGuard(const ClientSocketGuard&) = delete;
    ClientSocketGuard& operator=(const ClientSocketGuard&) = delete;
};

struct SessionEventRecord
{
    uint64_t seq = 0;
    uint64_t sessionGeneration = 0;
    ULONGLONG tickMs = 0;
    std::string sessionId;
    std::string type;
    std::string state;
    std::string stopReason;
    DWORD processId = 0;
    DWORD threadId = 0;
    duint ip = 0;
    duint address = 0;
    DWORD exceptionCode = 0;
    bool firstChance = false;
    DWORD exitCode = 0;
    std::string imagePath;
    std::string breakpointName;
    std::string breakpointModule;
    std::string note;
};

struct ScopedWinHandle
{
    HANDLE value = nullptr;

    ScopedWinHandle() = default;
    explicit ScopedWinHandle(HANDLE handle) : value(handle) {}
    ~ScopedWinHandle() noexcept
    {
        if(value && value != INVALID_HANDLE_VALUE)
            CloseHandle(value);
    }
    ScopedWinHandle(const ScopedWinHandle&) = delete;
    ScopedWinHandle& operator=(const ScopedWinHandle&) = delete;
    ScopedWinHandle(ScopedWinHandle&& other) noexcept
        : value(other.value)
    {
        other.value = nullptr;
    }
    ScopedWinHandle& operator=(ScopedWinHandle&& other) noexcept
    {
        if(this == &other)
            return *this;
        if(value && value != INVALID_HANDLE_VALUE)
            CloseHandle(value);
        value = other.value;
        other.value = nullptr;
        return *this;
    }
};

enum class SerializedRouteAcquireResult
{
    Acquired,
    ServerStopping,
    QueueFull,
    TimedOut,
};

struct SerializedRouteLease
{
    uint64_t ticket = 0;
    bool owned = false;

    ~SerializedRouteLease()
    {
        if(!owned)
            return;
        {
            std::lock_guard<std::mutex> lock(g_serializedRouteMutex);
            g_serializedRouteQueue.finish(ticket);
        }
        g_serializedRouteCv.notify_all();
    }
    SerializedRouteLease() = default;
    SerializedRouteLease(const SerializedRouteLease&) = delete;
    SerializedRouteLease& operator=(const SerializedRouteLease&) = delete;
};

static SerializedRouteAcquireResult acquireSerializedRouteLease(
        SerializedRouteLease& lease)
{
    std::unique_lock<std::mutex> lock(g_serializedRouteMutex);
    uint64_t ticket = 0;
    if(!g_serializedRouteQueue.tryAdmit(ticket))
        return SerializedRouteAcquireResult::QueueFull;

    const auto deadline = std::chrono::steady_clock::now()
        + std::chrono::milliseconds(MAX_SERIALIZED_ROUTE_WAIT_MS);
    while(!g_httpServer.stopRequested.load(std::memory_order_acquire)
        && !g_serializedRouteQueue.canStart(ticket))
    {
        if(g_serializedRouteCv.wait_until(lock, deadline) == std::cv_status::timeout
            && !g_serializedRouteQueue.canStart(ticket))
        {
            g_serializedRouteQueue.cancel(ticket);
            lock.unlock();
            g_serializedRouteCv.notify_all();
            return SerializedRouteAcquireResult::TimedOut;
        }
    }
    if(g_httpServer.stopRequested.load(std::memory_order_acquire))
    {
        g_serializedRouteQueue.cancel(ticket);
        lock.unlock();
        g_serializedRouteCv.notify_all();
        return SerializedRouteAcquireResult::ServerStopping;
    }
    if(g_serializedRouteQueue.tryStart(ticket)
        != mcpdispatcher::StartDecision::Started)
    {
        g_serializedRouteQueue.cancel(ticket);
        lock.unlock();
        g_serializedRouteCv.notify_all();
        return SerializedRouteAcquireResult::TimedOut;
    }
    lease.ticket = ticket;
    lease.owned = true;
    return SerializedRouteAcquireResult::Acquired;
}

using ExceptionPolicyChance = mcpexception::Chance;
using ExceptionPolicyAction = mcpexception::Action;
using ExceptionSelectorKind = mcpexception::SelectorKind;
using ExceptionCodeSelector = mcpexception::Selector;
using ExceptionPolicyRule = mcpexception::Rule;
using ExceptionPolicyState = mcpexception::Policy;

struct ExceptionHistoryRecord
{
    uint64_t seq = 0;
    uint64_t eventSeq = 0;
    uint64_t sessionGeneration = 0;
    uint64_t policyVersion = 0;
    ULONGLONG tickMs = 0;
    ULONGLONG lastUpdateMs = 0;
    ULONGLONG timestamp100ns = 0;
    ULONGLONG lastUpdateTimestamp100ns = 0;
    std::string bridgeInstanceId;
    std::string sessionId;
    DWORD processId = 0;
    DWORD threadId = 0;
    DWORD exceptionCode = 0;
    bool firstChance = false;
    duint address = 0;
    duint ip = 0;
    std::string action = "pause";
    std::string source = "default";
    std::string ruleId;
    std::string matchedSelector;
    mcpexception::Continuation continuation;
};

struct PendingExceptionAutoContinuation
{
    bool requested = false;
    std::string command;
    std::string action;
    uint64_t historySeq = 0;
    uint64_t eventSeq = 0;
    uint64_t sessionGeneration = 0;
    std::string sessionId;
};

struct DebugSessionState
{
    std::mutex mutex;
    std::condition_variable cv;
    uint64_t eventSeq = 0;
    uint64_t generation = 0;
    ULONGLONG lastUpdateMs = 0;
    ULONGLONG sessionStartTickMs = 0;
    std::string sessionId;
    bool initialized = false;
    bool debugging = false;
    bool running = false;
    bool paused = false;
    bool stopping = false;
    bool exited = false;
    DWORD processId = 0;
    DWORD threadId = 0;
    DWORD exitCode = 0;
    DWORD exceptionCode = 0;
    bool exceptionFirstChance = false;
    bool exceptionPending = false;
    bool exceptionContinuationClaimed = false;
    uint64_t exceptionEventSeq = 0;
    std::string exceptionDisposition = "default";
    duint lastIp = 0;
    duint lastAddress = 0;
    std::string imagePath;
    std::string imageSha256;
    uint64_t imageSize = 0;
    uint64_t imageVolumeSerialNumber = 0;
    std::string imageFileId;
    std::string lastEventType = "idle";
    std::string state = "not_debugging";
    std::string stopReason;
    std::string breakpointName;
    std::string breakpointModule;
    std::string note;
    std::deque<SessionEventRecord> history;
    ExceptionPolicyState exceptionPolicy;
    uint64_t exceptionHistoryNextSeq = 1;
    uint64_t exceptionHistoryDropped = 0;
    std::deque<ExceptionHistoryRecord> exceptionHistory;
};

struct CaptureRangeSpec
{
    std::string label;
    std::string expression;
    duint size = 0;
    std::string format = "hex";
};

struct ManagedLaunch
{
    std::mutex mutex;
    std::condition_variable cv;
    std::unique_ptr<mcplaunch::LaunchRuntime> runtime;
    mcplaunch::LaunchInfo info;
    mcplaunch::FileIdentityResult expectedIdentity;
    mcplaunch::FileIdentityResult actualIdentity;
    std::string childPolicy = "none";
    std::string commandLineMode = "arguments";
    bool inheritEnvironment = true;
    size_t environmentOverrideCount = 0;
    size_t captureLimitBytes = 0;
    std::string phase = "created_suspended";
    bool attachSubmitted = false;
    bool createProcessObserved = false;
    bool identityVerified = false;
    bool resumed = false;
    bool ownershipCommitted = false;
    DWORD resumePreviousSuspendCount = 0;
    bool debuggerSuspensionObserved = false;
    std::string sessionId;
    uint64_t sessionGeneration = 0;
    uint64_t sessionEventSeq = 0;
    DWORD observedProcessId = 0;
    std::string errorCode;
    std::string errorMessage;
    size_t activeOperations = 0;
    bool closeRequested = false;
    bool closeInProgress = false;
    bool resourcesClosed = false;
    mcplaunch::RuntimeError teardownError;
};

// A registry lookup only keeps the shared object alive; it does not prevent a
// concurrent Resources/Close from tearing down the runtime.  Every route that
// touches a live LaunchRuntime therefore holds one of these pins.  Close is
// allowed to proceed only after the count reaches zero.
class ManagedLaunchOperationPin
{
public:
    explicit ManagedLaunchOperationPin(
        const std::shared_ptr<ManagedLaunch>& launch,
        bool allowClosingDiagnostics = false) noexcept
        : launch_(launch)
        , allowClosingDiagnostics_(allowClosingDiagnostics)
    {
        acquire();
    }

    ManagedLaunchOperationPin(const ManagedLaunchOperationPin&) = delete;
    ManagedLaunchOperationPin& operator=(
        const ManagedLaunchOperationPin&) = delete;

    ~ManagedLaunchOperationPin() noexcept
    {
        release();
    }

    bool acquired() const noexcept { return acquired_; }

    void release() noexcept
    {
        if(!acquired_ || !launch_)
            return;
        try
        {
            {
                std::lock_guard<std::mutex> lock(launch_->mutex);
                if(launch_->activeOperations != 0)
                    --launch_->activeOperations;
            }
            launch_->cv.notify_all();
        }
        catch(...)
        {
        }
        acquired_ = false;
    }

private:
    void acquire() noexcept
    {
        if(!launch_)
            return;
        try
        {
            std::lock_guard<std::mutex> lock(launch_->mutex);
            if(launch_->resourcesClosed || !launch_->runtime ||
               launch_->closeInProgress ||
               (!allowClosingDiagnostics_ && launch_->closeRequested))
                return;
            ++launch_->activeOperations;
            acquired_ = true;
        }
        catch(...)
        {
        }
    }

    std::shared_ptr<ManagedLaunch> launch_;
    bool allowClosingDiagnostics_ = false;
    bool acquired_ = false;
};

// Child-process interception is deliberately kept outside ManagedLaunch's
// stream/resource lifetime. A debugger instance may outlive the root typed
// launch while a descendant is being handed to another debugger instance.
struct ChildBrokerInterception
{
    bool active = false;
    bool directChild = true;
    DWORD threadId = 0;
    duint entryAddress = 0;
    duint entryStack = 0;
    duint threadFlagsAddress = 0;
    duint returnAddress = 0;
    duint processHandleOut = 0;
    duint threadHandleOut = 0;
    duint originalThreadFlags = 0;
    uint64_t token = 0;
};

struct ChildBrokerChild
{
    std::mutex mutex;
    std::string childId;
    std::string parentLaunchId;
    DWORD pid = 0;
    DWORD tid = 0;
    DWORD parentPid = 0;
    ULONGLONG creationTime100ns = 0;
    std::string imagePath;
    std::string architecture;
    std::string phase = "created_suspended";
    std::string errorCode;
    std::string errorMessage;
    bool identityVerified = false;
    bool debuggerSpawned = false;
    bool debuggerAttached = false;
    bool preEntryPaused = false;
    bool autoResumeAttempted = false;
    bool autoResumeSucceeded = false;
    bool brokerOwnedSuspension = true;
    bool parentBarrierArmed = false;
    bool parentBarrierReached = false;
    duint parentHandoffAddress = 0;
    bool parentHandoffBreakpointOwned = false;
    bool brokerSuspendIncremented = false;
    DWORD brokerSuspendPreviousCount = 0;
    // A quota reservation belongs to exactly one child record.  The worker,
    // parent callback, and shutdown path can all observe a failed handoff;
    // keep the reservation state on the record so rollback is exactly once.
    bool directChild = true;
    bool quotaReservationActive = true;
    bool resumeAttempted = false;
    bool resumeSucceeded = false;
    DWORD resumePreviousSuspendCount = 0;
    DWORD resumeReleaseCalls = 0;
    DWORD preservedSuspensionCount = 0;
    bool suspensionRestoreAttempted = false;
    bool suspensionRestoreSucceeded = false;
    DWORD suspensionRestorePreviousCount = 0;
    uint32_t preEntryPolls = 0;
    uint32_t preEntryResumeAttempts = 0;
    int preEntryLastHttpStatus = 0;
    std::string preEntryLastObservation;
    HANDLE processHandle = nullptr;
    HANDLE threadHandle = nullptr;
    HANDLE debuggerProcessHandle = nullptr;
    DWORD debuggerPid = 0;
};

struct ChildBrokerPendingHandoff
{
    uint64_t token = 0;
    DWORD threadId = 0;
    duint address = 0;
    bool ownsBreakpoint = false;
    std::shared_ptr<ChildBrokerChild> child;
};

struct ChildBrokerState
{
    std::mutex mutex;
    mcpchild::Policy policy = mcpchild::Policy::None;
    std::string policyName = "none";
    std::string brokerId;
    std::string rootLaunchId;
    DWORD rootPid = 0;
    DWORD parentPid = 0;
    bool configured = false;
    bool entryBreakpointInstalled = false;
    duint entryBreakpointAddress = 0;
    // A debugger spawned by the broker uses the same plugin, but has no
    // parent-side child policy.  Keep its one-shot child-entry rendezvous
    // state separate from the parent's NtCreateUserProcess hook so retries
    // across CREATEPROCESS/PAUSEDEBUG/LOADDLL callbacks are idempotent.
    bool autoEntryBreakpointInstalled = false;
    duint autoEntryBreakpointAddress = 0;
    uint32_t autoEntryResolveAttempts = 0;
    uint32_t autoEntryInstallAttempts = 0;
    std::string autoEntryLastError;
    uint64_t nextInterceptionToken = 1;
    mcpchild::ChildQuota quota;
    std::unordered_map<DWORD, ChildBrokerInterception> interceptions;
    std::unordered_map<uint64_t, ChildBrokerPendingHandoff> pendingHandoffs;
    std::vector<std::shared_ptr<ChildBrokerChild>> children;
    std::vector<std::thread> workerThreads;
    std::atomic<bool> stopping{false};
};

DebugSessionState g_debugSession;
std::mutex g_launchRegistryMutex;
std::unordered_map<std::string, std::shared_ptr<ManagedLaunch>> g_launchRegistry;
ChildBrokerState g_childBroker;

static ULONGLONG nowTickMs();
static std::string httpHeaderValue(const std::string& request,
                                   const std::string& name,
                                   bool* duplicate);

// A mutation lease spans a multi-request workflow (for example RestoreState).
// It is deliberately bridge-local, bound to the current session identity and
// client instance, and expires even if the MCP process disappears.  Ordinary
// single mutations remain compatible when no lease is active; while a lease is
// held, every other guarded mutation fails closed until release/expiry.
struct MutationLeaseState
{
    std::mutex mutex;
    std::string token;
    std::string ownerClientId;
    std::string bridgeInstanceId;
    std::string sessionId;
    uint64_t generation = 0;
    DWORD processId = 0;
    ULONGLONG expiresAtTickMs = 0;
    uint64_t revision = 0;
};

MutationLeaseState g_mutationLease;
std::mutex g_mutationCoordinatorMutex;
std::shared_ptr<mcpmutation::MutationCoordinator> g_mutationCoordinator;

static void clearMutationLeaseUnlocked(MutationLeaseState& lease)
{
    lease.token.clear();
    lease.ownerClientId.clear();
    lease.bridgeInstanceId.clear();
    lease.sessionId.clear();
    lease.generation = 0;
    lease.processId = 0;
    lease.expiresAtTickMs = 0;
    ++lease.revision;
}

static void expireMutationLeaseUnlocked(MutationLeaseState& lease)
{
    if(!lease.token.empty() && nowTickMs() >= lease.expiresAtTickMs)
        clearMutationLeaseUnlocked(lease);
}

static void clearMutationLease()
{
    std::lock_guard<std::mutex> lock(g_mutationLease.mutex);
    clearMutationLeaseUnlocked(g_mutationLease);
}

struct MutationLeaseSnapshot
{
    bool active = false;
    std::string ownerClientId;
    std::string sessionId;
    uint64_t generation = 0;
    DWORD processId = 0;
    ULONGLONG expiresAtTickMs = 0;
    uint64_t revision = 0;
};

static MutationLeaseSnapshot snapshotMutationLease()
{
    std::lock_guard<std::mutex> lock(g_mutationLease.mutex);
    expireMutationLeaseUnlocked(g_mutationLease);
    MutationLeaseSnapshot result;
    result.active = !g_mutationLease.token.empty();
    result.ownerClientId = g_mutationLease.ownerClientId;
    result.sessionId = g_mutationLease.sessionId;
    result.generation = g_mutationLease.generation;
    result.processId = g_mutationLease.processId;
    result.expiresAtTickMs = g_mutationLease.expiresAtTickMs;
    result.revision = g_mutationLease.revision;
    return result;
}

static mcpmutation::SessionIdentity currentMutationSessionIdentity()
{
    mcpmutation::SessionIdentity identity;
    identity.bridgeInstanceId = g_bridgeInstanceId;
    std::lock_guard<std::mutex> lock(g_debugSession.mutex);
    identity.sessionId = g_debugSession.sessionId;
    identity.generation = g_debugSession.generation;
    identity.processId = g_debugSession.processId;
    identity.targetSha256 = g_debugSession.imageSha256;
    return identity;
}

// Keep one coordinator per bridge process and move it forward only when the
// debugger publishes a newer session generation.  The pure coordinator owns
// all lease/permit counters; this adapter deliberately never calls into it
// while holding g_debugSession.mutex, avoiding the lifecycle lock inversion
// that caused the original shutdown races.
static std::shared_ptr<mcpmutation::MutationCoordinator>
syncMutationCoordinator()
{
    const mcpmutation::SessionIdentity identity =
        currentMutationSessionIdentity();
    if(!identity.valid())
        return {};

    std::lock_guard<std::mutex> lock(g_mutationCoordinatorMutex);
    if(!g_mutationCoordinator)
    {
        try
        {
            g_mutationCoordinator =
                std::make_shared<mcpmutation::MutationCoordinator>(
                    identity, []() -> mcpmutation::Tick {
                        return static_cast<mcpmutation::Tick>(nowTickMs());
                    });
        }
        catch(...)
        {
            return {};
        }
    }
    else
    {
        const mcpmutation::SnapshotResult current =
            g_mutationCoordinator->snapshot();
        if(current.ok() && current.snapshot.session != identity)
        {
            const mcpmutation::OperationResult replaced =
                g_mutationCoordinator->replaceSession(identity);
            if(!replaced.ok())
                return {};
        }
    }
    return g_mutationCoordinator;
}

static std::string mutationHeaderValue(
    const std::string& request,
    const char* name)
{
    return httpHeaderValue(request, name, nullptr);
}

struct NativeMutationPermitScope
{
    std::shared_ptr<mcpmutation::MutationCoordinator> coordinator;
    mcpmutation::MutationPermit permit;

    NativeMutationPermitScope() = default;
    NativeMutationPermitScope(const NativeMutationPermitScope&) = delete;
    NativeMutationPermitScope& operator=(const NativeMutationPermitScope&) = delete;
    NativeMutationPermitScope(NativeMutationPermitScope&&) noexcept = default;
    NativeMutationPermitScope& operator=(NativeMutationPermitScope&&) noexcept = default;

    ~NativeMutationPermitScope() noexcept
    {
        // A route that has not explicitly committed is abandoned fail-closed.
        // This still releases the in-flight pin on every early-return path.
    }

    bool active() const noexcept { return permit.active(); }
};

// Roll back a child reservation at most once.  Do not hold the child mutex
// while acquiring the broker mutex: worker failure and shutdown use the
// opposite order for parts of their cleanup, and keeping the two acquisitions
// separate avoids a lock-order cycle during forced teardown.
static void childBrokerRollbackReservation(
    const std::shared_ptr<ChildBrokerChild>& child) noexcept
{
    if(!child)
        return;
    bool shouldRollback = false;
    bool directChild = true;
    {
        std::lock_guard<std::mutex> childLock(child->mutex);
        if(child->quotaReservationActive)
        {
            child->quotaReservationActive = false;
            shouldRollback = true;
            directChild = child->directChild;
        }
    }
    if(!shouldRollback)
        return;
    std::lock_guard<std::mutex> brokerLock(g_childBroker.mutex);
    mcpchild::rollbackChildReservation(g_childBroker.quota, directChild);
}

struct NativeTraceEvent
{
    uint64_t seq = 0;
    ULONGLONG tickMs = 0;
    DWORD threadId = 0;
    duint ip = 0;
    std::string module;
    duint moduleBase = 0;
    duint rva = 0;
    std::string bytesHex;
    std::string instruction;
    int instructionSize = 0;
    bool branch = false;
    bool call = false;
    bool isReturn = false;
    duint branchTarget = 0;
    bool exceptionTransition = false;
    DWORD exceptionCode = 0;
    bool exceptionFirstChance = false;
    duint exceptionAddress = 0;
};

struct NativeTracePendingException
{
    DWORD code = 0;
    bool firstChance = false;
    duint address = 0;
};

struct NativeTraceHitUpdate
{
    uint64_t revision = 0;
    duint ip = 0;
    uint64_t hits = 0;
};

struct NativeTraceState
{
    std::mutex mutex;
    std::condition_variable cv;
    std::string traceId;
    std::string sessionId;
    uint64_t sessionGeneration = 0;
    DWORD processId = 0;
    std::string mode = "both";
    bool active = false;
    bool completed = false;
    bool captureEvents = true;
    bool stopOnLimit = true;
    bool autoResumeExceptions = false;
    bool exceptionResumeQueued = false;
    bool hasRange = false;
    duint rangeStart = 0;
    duint rangeSize = 0;
    uint64_t maxSteps = 100000;
    size_t maxEvents = 100000;
    size_t maxUnique = 100000;
    bool enrichEvents = false;
    uint64_t totalSteps = 0;
    uint64_t matchedSteps = 0;
    uint64_t droppedEvents = 0;
    uint64_t droppedUnique = 0;
    uint64_t hitRevision = 0;
    uint64_t droppedHitUpdates = 0;
    static constexpr size_t kMaxHitUpdates = 4096;
    ULONGLONG createdTickMs = 0;
    ULONGLONG lastTickMs = 0;
    std::string stopReason;
    // Bounded event ring.  When stopOnLimit=false the newest evidence wins
    // while droppedEvents/oldestEventSeq make cursor loss explicit.
    std::deque<NativeTraceEvent> events;
    std::unordered_map<duint, uint64_t> hits;
    // A separate bounded update stream gives each reader an independent
    // revision cursor without changing the legacy sorted hit snapshot.
    std::deque<NativeTraceHitUpdate> hitUpdates;
    // CB_EXCEPTION is delivered before the first resumed instruction in the
    // handler.  Retain one marker per thread and attach it to that next
    // in-range instruction so the Python CFG core can type the discontinuity
    // as an exception edge instead of an unexplained jump.
    std::unordered_map<DWORD, NativeTracePendingException> pendingExceptions;
};

NativeTraceState g_nativeTrace;

struct NativeApiTraceEvent
{
    uint64_t seq = 0;
    uint64_t callId = 0;
    uint64_t entrySeq = 0;
    ULONGLONG tickMs = 0;
    ULONGLONG durationMs = 0;
    DWORD threadId = 0;
    duint ip = 0;
    duint breakpointAddress = 0;
    duint apiAddress = 0;
    duint stackPointer = 0;
    duint returnAddress = 0;
    duint returnValue = 0;
    bool matchedReturn = false;
    size_t unwoundFrames = 0;
    DWORD exceptionCode = 0;
    bool exceptionFirstChance = false;
    bool managedException = false;
    std::string managedRuntime;
    DWORD managedHResult = 0;
    duint managedObject = 0;
    std::vector<duint> exceptionParameters;
    std::string traceId;
    std::string kind;
    std::string name;
    std::string module;
    std::string callerModule;
    duint callerModuleBase = 0;
    duint callerRva = 0;
    std::vector<duint> arguments;
};

struct NativeApiPendingCall
{
    uint64_t callId = 0;
    uint64_t entrySeq = 0;
    ULONGLONG entryTickMs = 0;
    duint apiAddress = 0;
    duint returnAddress = 0;
    std::string module;
    std::vector<duint> arguments;
};

struct NativeApiTraceConfig
{
    bool nativeReturnHooks = false;
    std::unordered_set<duint> registeredEntryBreakpoints;
    std::unordered_set<duint> ownedReturnBreakpoints;
    std::unordered_set<duint> preexistingReturnBreakpoints;
    uint64_t returnHooksInstalled = 0;
    uint64_t returnHooksRemoved = 0;
    uint64_t returnHookFailures = 0;
    std::string lastReturnHookError;
};

struct NativeApiTraceState
{
    std::mutex mutex;
    uint64_t nextSeq = 1;
    uint64_t nextCallId = 1;
    uint64_t droppedEvents = 0;
    static constexpr size_t kMaxEvents = 8192;
    std::deque<NativeApiTraceEvent> events;
    std::unordered_map<
        std::string,
        std::unordered_map<DWORD, std::vector<NativeApiPendingCall>>> pending;
    std::unordered_map<std::string, size_t> finalizedPending;
    std::unordered_map<std::string, size_t> exceptionUnwoundPending;
    std::unordered_map<std::string, NativeApiTraceConfig> configs;
};

NativeApiTraceState g_nativeApiTrace;

static std::string hexEncodeLower(const unsigned char* bytes, size_t count);

static void enrichNativeTraceEvent(NativeTraceEvent& event) noexcept
{
    try
    {
        const DBGFUNCTIONS* functions = DbgFunctions();
        char moduleName[MAX_MODULE_SIZE] = {};
        if(functions && functions->ModNameFromAddr
            && functions->ModNameFromAddr(event.ip, moduleName, true))
            event.module = moduleName;
        if(functions && functions->ModBaseFromAddr)
        {
            event.moduleBase = functions->ModBaseFromAddr(event.ip);
            if(event.moduleBase && event.ip >= event.moduleBase)
                event.rva = event.ip - event.moduleBase;
        }
        unsigned char bytes[16] = {};
        if(DbgMemRead(event.ip, bytes, sizeof(bytes)))
            event.bytesHex = hexEncodeLower(bytes, sizeof(bytes));
        BASIC_INSTRUCTION_INFO basic = {};
        if(functions && functions->DisasmFast)
        {
            if(functions->DisasmFast(bytes, event.ip, &basic))
            {
                event.instructionSize = basic.size;
                event.branch = basic.branch;
                event.call = basic.call;
                event.instruction = basic.instruction;
            }
        }
        if(event.instructionSize <= 0)
        {
            DbgDisasmFastAt(event.ip, &basic);
            event.instructionSize = basic.size;
            event.branch = basic.branch;
            event.call = basic.call;
            event.instruction = basic.instruction;
        }
        if(event.branch || event.call)
            event.branchTarget = DbgGetBranchDestination(event.ip);
        std::string loweredInstruction = event.instruction;
        std::transform(
            loweredInstruction.begin(), loweredInstruction.end(),
            loweredInstruction.begin(),
            [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
        event.isReturn = loweredInstruction.rfind("ret", 0) == 0
            || loweredInstruction.rfind("iret", 0) == 0;
        if(!event.bytesHex.empty() && event.instructionSize > 0
            && event.instructionSize < 16)
            event.bytesHex.resize(static_cast<size_t>(event.instructionSize) * 2);
    }
    catch(...)
    {
        // Enrichment is diagnostic evidence. A transient unreadable page or
        // decoder failure must never abort the trace callback itself.
    }
}

bool startHttpServer();
bool stopHttpServer();
DWORD WINAPI HttpServerThread(LPVOID lpParam);
std::string readHttpRequest(SOCKET clientSocket, int& errorStatus,
                            std::string& errorCode, std::string& errorText);
bool sendHttpResponse(SOCKET clientSocket, int statusCode, const std::string& contentType, const std::string& responseBody);
bool parseHttpRequest(const std::string& request, std::string& method, std::string& path, std::string& query, std::string& body);
std::unordered_map<std::string, std::string> parseQueryParams(const std::string& query);
std::string urlDecode(const std::string& str);
std::string escapeJsonString(const char* str);
void debugSessionCallback(CBTYPE cbType, void* callbackInfo);
void childBrokerConfigureFromEnvironment();
bool childBrokerConfigureForLaunch(const std::string& policy,
                                   const std::string& rootLaunchId,
                                   DWORD rootPid,
                                   std::string& errorCode,
                                   std::string& errorMessage);
void childBrokerObserveSessionReady();
void childBrokerHandleBreakpoint(PLUG_CB_BREAKPOINT* info);
void childBrokerHandleStepped();
void childBrokerStop(bool terminateOwnedDebuggers);
void registerCallbacks();
void unregisterCallbacks();
std::string buildDebugSessionJson(bool includeHistory = true, size_t historyLimit = 16);
std::string waitForSessionJson(const std::string& mode, unsigned int timeoutMs, uint64_t sinceSeq, duint requestedAddr, bool hasRequestedAddr, const std::string& requestedName, bool& timedOut);
std::string waitForSessionDetailedJson(const std::string& mode, unsigned int timeoutMs, uint64_t sinceSeq, duint requestedAddr, bool hasRequestedAddr, const std::string& requestedName, bool& timedOut);
std::string buildNativeTraceJson(size_t eventOffset = 0, size_t eventLimit = 0,
                                 size_t hitOffset = 0, size_t hitLimit = 0,
                                 uint64_t eventAfterSeq = 0,
                                 uint64_t hitAfterRevision = 0);
std::string buildNativeApiTraceJson(const std::string& traceId,
                                    uint64_t afterSeq = 0,
                                    size_t limit = 100);
void finishNativeTrace(const char* reason);
std::unordered_map<std::string, std::string> mergeRequestParams(const std::string& query, const std::string& body);
static bool breakpointMatchesRequestedUnlocked(const DebugSessionState& state, duint requestedAddr, bool hasRequestedAddr, const std::string& requestedName);
static std::string httpHeaderValue(const std::string& request, const std::string& name,
                                   bool* duplicate = nullptr);
static bool rotateBridgeAuthToken();
static void clearBridgeAuthToken();
static bool isBridgeAuthenticationValid(const std::string& request);

// Translate Windows structured exceptions (e.g. an access violation from a bad
// guest pointer) into C++ exceptions so per-request try/catch blocks turn them
// into HTTP 500 instead of crashing all of x64dbg. Requires compiling with /EHa
// and is installed per-thread (see installSehTranslator calls below).
static void __cdecl sehToCppTranslator(unsigned int code, EXCEPTION_POINTERS*) {
    char msg[64];
    _snprintf_s(msg, sizeof(msg), _TRUNCATE, "structured exception 0x%08X", code);
    throw std::runtime_error(msg);
}

static void installSehTranslator() {
    _set_se_translator(sehToCppTranslator);
}

static std::string hexEncodeLower(const unsigned char* bytes, size_t count) {
    static constexpr char digits[] = "0123456789abcdef";
    std::string output;
    output.resize(count * 2);
    for (size_t i = 0; i < count; ++i) {
        output[i * 2] = digits[(bytes[i] >> 4) & 0x0F];
        output[i * 2 + 1] = digits[bytes[i] & 0x0F];
    }
    return output;
}

static void clearBridgeAuthToken() {
    if (!g_bridgeAuthFilePath.empty()) {
        DeleteFileW(g_bridgeAuthFilePath.c_str());
        g_bridgeAuthFilePath.clear();
    }
    if (!g_bridgeAuthToken.empty()) {
        SecureZeroMemory(g_bridgeAuthToken.data(), g_bridgeAuthToken.size());
        g_bridgeAuthToken.clear();
    }
}

static bool rotateBridgeAuthToken() {
    clearBridgeAuthToken();
    unsigned char randomBytes[32] = {};
    const NTSTATUS randomStatus = BCryptGenRandom(
        nullptr, randomBytes, static_cast<ULONG>(sizeof(randomBytes)),
        BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    if (randomStatus < 0) {
        _plugin_logprintf("[MCP] BCryptGenRandom failed: 0x%08X\n",
            static_cast<unsigned int>(randomStatus));
        return false;
    }
    g_bridgeAuthToken = hexEncodeLower(randomBytes, sizeof(randomBytes));
    SecureZeroMemory(randomBytes, sizeof(randomBytes));

    PWSTR localAppDataRaw = nullptr;
    const HRESULT knownFolderResult = SHGetKnownFolderPath(
        FOLDERID_LocalAppData, KF_FLAG_CREATE, nullptr, &localAppDataRaw);
    if (FAILED(knownFolderResult) || !localAppDataRaw || !*localAppDataRaw) {
        if (localAppDataRaw) CoTaskMemFree(localAppDataRaw);
        clearBridgeAuthToken();
        _plugin_logprintf("[MCP] LocalAppData is unavailable for the bridge token file: 0x%08X\n",
            static_cast<unsigned int>(knownFolderResult));
        return false;
    }
    std::wstring directory(localAppDataRaw);
    CoTaskMemFree(localAppDataRaw);
    if (!directory.empty() && directory.back() != L'\\') directory.push_back(L'\\');
    directory += L"x64dbgMCP";
    if (!CreateDirectoryW(directory.c_str(), nullptr)
        && GetLastError() != ERROR_ALREADY_EXISTS) {
        clearBridgeAuthToken();
        _plugin_logprintf("[MCP] Failed to create token directory: %lu\n", GetLastError());
        return false;
    }
    const std::wstring finalPath = directory + L"\\bridge-"
        + std::to_wstring(GetCurrentProcessId()) + L".token";
    const std::wstring temporaryPath = finalPath + L".tmp-"
        + std::to_wstring(GetCurrentThreadId());

    PSECURITY_DESCRIPTOR securityDescriptor = nullptr;
    // Protected DACL: current object owner, LocalSystem and Administrators only.
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
            L"D:P(A;;GA;;;OW)(A;;GA;;;SY)(A;;GA;;;BA)",
            SDDL_REVISION_1, &securityDescriptor, nullptr)) {
        clearBridgeAuthToken();
        _plugin_logprintf("[MCP] Failed to create token-file security descriptor: %lu\n", GetLastError());
        return false;
    }
    SECURITY_ATTRIBUTES securityAttributes = {};
    securityAttributes.nLength = sizeof(securityAttributes);
    securityAttributes.lpSecurityDescriptor = securityDescriptor;
    HANDLE file = CreateFileW(
        temporaryPath.c_str(), GENERIC_WRITE, 0, &securityAttributes,
        CREATE_ALWAYS, FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_TEMPORARY, nullptr);
    LocalFree(securityDescriptor);
    if (file == INVALID_HANDLE_VALUE) {
        const DWORD error = GetLastError();
        clearBridgeAuthToken();
        _plugin_logprintf("[MCP] Failed to create protected token file: %lu\n", error);
        return false;
    }
    std::stringstream content;
    int configuredPort = DEFAULT_PORT;
    int boundPort = 0;
    {
        std::lock_guard<std::mutex> lock(g_httpServer.mutex);
        configuredPort = g_httpServer.configuredPort;
        boundPort = g_httpServer.boundPort;
    }
    // A configured port of zero means the kernel selected an ephemeral port.
    // Never publish zero in the descriptor: clients authenticate against the
    // actual bound endpoint, not against a pre-bind request.
    if(boundPort <= 0)
        boundPort = configuredPort;
    content << "version=1\n"
            << "pid=" << GetCurrentProcessId() << "\n"
            << "processStartTime100ns=" << g_debuggerProcessStartTime100ns << "\n"
            << "bridgeInstanceId=" << g_bridgeInstanceId << "\n"
            << "port=" << boundPort << "\n"
#ifdef _WIN64
            << "arch=x64\n"
#else
            << "arch=x86\n"
#endif
            << "token=" << g_bridgeAuthToken << "\n";
    const std::string serialized = content.str();
    DWORD written = 0;
    const bool wrote = WriteFile(
        file, serialized.data(), static_cast<DWORD>(serialized.size()), &written, nullptr)
        && written == serialized.size()
        && FlushFileBuffers(file);
    CloseHandle(file);
    if (!wrote) {
        const DWORD error = GetLastError();
        DeleteFileW(temporaryPath.c_str());
        clearBridgeAuthToken();
        _plugin_logprintf("[MCP] Failed to publish protected token file: %lu\n", error);
        return false;
    }
    if (!MoveFileExW(temporaryPath.c_str(), finalPath.c_str(),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
        const DWORD error = GetLastError();
        DeleteFileW(temporaryPath.c_str());
        clearBridgeAuthToken();
        _plugin_logprintf("[MCP] Failed to atomically publish token descriptor: %lu\n", error);
        return false;
    }
    g_bridgeAuthFilePath = finalPath;
    return true;
}

static bool isBridgeAuthenticationValid(const std::string& request) {
    bool duplicate = false;
    const std::string supplied = httpHeaderValue(
        request, "x-mcp-auth-token", &duplicate);
    if (duplicate) return false;
    return mcpbridge::constantTimeEqual(g_bridgeAuthToken, supplied, 64);
}

bool cbEnableHttpServer(int argc, char* argv[]);
bool cbSetHttpPort(int argc, char* argv[]);
void registerCommands();
void unregisterCommands();

bool pluginInit(PLUG_INITSTRUCT* initStruct) {
    initStruct->pluginVersion = PLUGIN_VERSION;
    initStruct->sdkVersion = PLUG_SDKVERSION;
    strncpy_s(initStruct->pluginName, PLUGIN_NAME, _TRUNCATE);
    g_pluginHandle = initStruct->pluginHandle;
    g_bridgeInstanceId = mcpbridge::createGuidString();
    if (g_bridgeInstanceId.empty()) {
        _plugin_logputs("Failed to create an immutable bridge instance ID");
        return false;
    }
    FILETIME creation = {}, exitTime = {}, kernel = {}, user = {};
    if (!GetProcessTimes(GetCurrentProcess(), &creation, &exitTime, &kernel, &user)) {
        _plugin_logprintf("Failed to read debugger process creation time: %lu\n", GetLastError());
        return false;
    }
    ULARGE_INTEGER value = {};
    value.LowPart = creation.dwLowDateTime;
    value.HighPart = creation.dwHighDateTime;
    g_debuggerProcessStartTime100ns = value.QuadPart;

    childBrokerConfigureFromEnvironment();

    _plugin_logputs("x64dbg HTTP Server plugin loading...");
    {
        std::lock_guard<std::mutex> lock(g_httpServer.mutex);
        g_httpServer.configuredPort = configuredPortFromEnvironment();
    }
    registerCommands();
    registerCallbacks();
    if (startHttpServer()) {
        int boundPort = 0;
        {
            std::lock_guard<std::mutex> lock(g_httpServer.mutex);
            boundPort = g_httpServer.boundPort;
        }
        _plugin_logprintf("x64dbg HTTP Server started on port %d\n", boundPort);
    } else {
        _plugin_logputs("Failed to start HTTP server!");
        // A loaded plugin without its authenticated bridge is not usable and
        // makes clients wait for a timeout.  Undo the partial registration and
        // fail plugin loading explicitly.
        unregisterCallbacks();
        unregisterCommands();
        childBrokerStop(true);
        return false;
    }

    _plugin_logputs("x64dbg HTTP Server plugin loaded!");
    return true;
}

bool pluginStop() {
    // DbgCmdExecDirect runs raw commands on the calling request worker.  A
    // nested script or any present/future plugunload alias can therefore reach
    // plugstop() while that worker still executes this DLL.  Refuse the
    // re-entrant unload before changing lifecycle state.  External GUI/loader
    // unloads run on another thread and retain the bounded stop-and-join path.
    if(g_insideHttpRequestWorker) {
        _plugin_logputs(
            "Refusing re-entrant plugin unload from an HTTP request worker");
        return false;
    }
    _plugin_logputs("Stopping x64dbg HTTP Server...");
    clearMutationLease();
    // Stop and join request workers first.  Otherwise an in-flight Launch route
    // can reconfigure/restart the child broker after childBrokerStop returned.
    // No request may create plugin-owned work once child shutdown begins.
    bool safeToUnload = stopHttpServer();
    if (!safeToUnload) {
        _plugin_logputs("HTTP server thread did not stop; keeping plugin loaded");
        return false;
    }
    childBrokerStop(true);
    unregisterCallbacks();
    // Stop every retained launch before allowing the plugin DLL to unload.
    // LaunchRuntime workers execute code in this module; destroying the last
    // shared_ptr while a bounded teardown is still pending would leave a live
    // thread executing from an unloaded image. Keep the registry intact and
    // return false on any failure so plugstop() can be retried safely.
    std::vector<std::shared_ptr<ManagedLaunch>> launches;
    {
        std::lock_guard<std::mutex> lock(g_launchRegistryMutex);
        launches.reserve(g_launchRegistry.size());
        for(const auto& entry : g_launchRegistry)
            if(entry.second)
                launches.push_back(entry.second);
    }
    bool launchesClosed = true;
    for(const auto& launch : launches)
    {
        mcplaunch::LaunchRuntime* runtime = nullptr;
        bool busy = false;
        {
            std::lock_guard<std::mutex> lock(launch->mutex);
            busy = launch->activeOperations != 0
                || launch->closeInProgress;
            runtime = launch->runtime.get();
        }
        if(busy || !runtime)
        {
            launchesClosed = false;
            _plugin_logprintf(
                "Launch %s is still busy during plugin shutdown\n",
                launch->info.launchId.c_str());
            continue;
        }
        const mcplaunch::OperationResult closed =
            runtime->closeResources(5000);
        if(!closed.ok)
        {
            launchesClosed = false;
            _plugin_logprintf(
                "Launch %s resource teardown failed: %s\n",
                launch->info.launchId.c_str(),
                closed.error.message.c_str());
            continue;
        }
        {
            std::lock_guard<std::mutex> lock(launch->mutex);
            launch->resourcesClosed = true;
            launch->closeRequested = true;
            launch->phase = "resources_closed";
        }
    }
    if(!launchesClosed)
    {
        _plugin_logputs(
            "Launch resources did not quiesce; keeping plugin loaded for retry");
        return false;
    }
    {
        std::lock_guard<std::mutex> lock(g_launchRegistryMutex);
        g_launchRegistry.clear();
    }
    launches.clear();
    unregisterCommands();
    _plugin_logputs("x64dbg HTTP Server stopped.");
    // Propagated to plugstop() -> the loader only calls FreeLibrary when true.
    return safeToUnload;
}

bool pluginSetup() {
    return true;
}

extern "C" __declspec(dllexport) bool pluginit(PLUG_INITSTRUCT* initStruct) {
    return pluginInit(initStruct);
}

extern "C" __declspec(dllexport) bool plugstop() {
    return pluginStop();
}

extern "C" __declspec(dllexport) void plugsetup(PLUG_SETUPSTRUCT* setupStruct) {
    pluginSetup();
}

bool startHttpServer() {
    if (!stopHttpServer()) {
        return false;
    }

    {
        std::lock_guard<std::mutex> routeLock(g_serializedRouteMutex);
        g_serializedRouteQueue.reset();
    }

    std::unique_lock<std::mutex> lock(g_httpServer.mutex);
    g_httpServer.stopRequested.store(false, std::memory_order_release);
    g_httpServer.state = HttpLifecycleState::Starting;
    g_httpServer.boundPort = 0;
    g_httpServer.activeClientSockets.clear();
    g_httpServer.dispatcher.reset();
    g_httpServer.liveWorkerCount = 0;
    g_httpServer.threadExitCode = STILL_ACTIVE;
    g_httpServer.lastError.clear();
    g_httpServer.thread = CreateThread(NULL, 0, HttpServerThread, NULL, 0, NULL);
    if (g_httpServer.thread == NULL) {
        g_httpServer.state = HttpLifecycleState::Failed;
        g_httpServer.lastError = "CreateThread failed: " + std::to_string(GetLastError());
        clearBridgeAuthToken();
        _plugin_logputs("Failed to create HTTP server thread");
        return false;
    }

    const bool signaled = g_httpServer.cv.wait_for(
        lock,
        std::chrono::seconds(5),
        []() { return g_httpServer.state != HttpLifecycleState::Starting; });
    const bool running = signaled && g_httpServer.state == HttpLifecycleState::Running;
    lock.unlock();
    if (!running) {
        stopHttpServer();
    }
    return running;
}

bool stopHttpServer() {
    HANDLE thread = NULL;
    std::vector<SOCKET> activeClientSockets;
    {
        std::lock_guard<std::mutex> lock(g_httpServer.mutex);
        thread = g_httpServer.thread;
        if (!thread) {
            g_httpServer.state = HttpLifecycleState::Stopped;
            g_httpServer.boundPort = 0;
            g_httpServer.listenSocket = INVALID_SOCKET;
            clearBridgeAuthToken();
            return true;
        }
        g_httpServer.stopRequested.store(true, std::memory_order_release);
        g_httpServer.state = HttpLifecycleState::Stopping;
        activeClientSockets.assign(
            g_httpServer.activeClientSockets.begin(),
            g_httpServer.activeClientSockets.end());
    }

    // Socket handles are closed only by their owning server/worker threads.
    // Concurrent closesocket can race descriptor reuse.  shutdown is enough to
    // interrupt blocking recv/send; the non-blocking accept loop observes the
    // stop flag within its bounded polling interval and closes the listener.
    for(const SOCKET activeClientSocket : activeClientSockets) {
        if(activeClientSocket == INVALID_SOCKET) continue;
        shutdown(activeClientSocket, SD_BOTH);
    }
    g_httpServer.cv.notify_all();
    g_serializedRouteCv.notify_all();
    g_debugSession.cv.notify_all();

    const DWORD waitResult = WaitForSingleObject(thread, 12000);
    if (waitResult != WAIT_OBJECT_0) {
        return false;
    }

    DWORD exitCode = 0;
    GetExitCodeThread(thread, &exitCode);
    CloseHandle(thread);
    {
        std::lock_guard<std::mutex> lock(g_httpServer.mutex);
        if (g_httpServer.thread == thread) {
            g_httpServer.thread = NULL;
        }
        g_httpServer.threadExitCode = exitCode;
        g_httpServer.state = HttpLifecycleState::Stopped;
        g_httpServer.boundPort = 0;
        g_httpServer.listenSocket = INVALID_SOCKET;
        g_httpServer.activeClientSockets.clear();
        g_httpServer.dispatcher.reset();
        g_httpServer.liveWorkerCount = 0;
    }
    g_httpServer.cv.notify_all();
    clearBridgeAuthToken();
    return true;
}

std::string urlDecode(const std::string& str) {
    std::string decoded;
    for (size_t i = 0; i < str.length(); ++i) {
        if (str[i] == '%' && i + 2 < str.length()) {
            int value;
            std::istringstream is(str.substr(i + 1, 2));
            if (is >> std::hex >> value) {
                decoded += static_cast<char>(value);
                i += 2;
            } else {
                decoded += str[i];
            }
        } else if (str[i] == '+') {
            decoded += ' ';
        } else {
            decoded += str[i];
        }
    }
    return decoded;
}

static void trimParam(std::string& s) {
    const char* ws = " \t\r\n\v\f";
    const auto first = s.find_first_not_of(ws);
    if (first == std::string::npos) {
        s.clear();
        return;
    }
    const auto last = s.find_last_not_of(ws);
    s = s.substr(first, last - first + 1u);
}

static std::string safeString(const char* value);

std::string escapeJsonString(const char* str) {
    std::string result;
    if (!str) return result;
    const std::string normalized = safeString(str);
    for (char ch : normalized) {
        switch (ch) {
            case '\\': result += "\\\\"; break;
            case '"':  result += "\\\""; break;
            case '\b': result += "\\b"; break;
            case '\f': result += "\\f"; break;
            case '\n': result += "\\n"; break;
            case '\r': result += "\\r"; break;
            case '\t': result += "\\t"; break;
            default:
                if (static_cast<unsigned char>(ch) < 0x20) {
                    char buf[8];
                    snprintf(buf, sizeof(buf), "\\u%04x", static_cast<unsigned char>(ch));
                    result += buf;
                } else {
                    result += ch;
                }
                break;
        }
    }
    return result;
}

static ULONGLONG nowTickMs() {
    return GetTickCount64();
}

static ULONGLONG nowTimestamp100ns() {
    FILETIME value = {};
    GetSystemTimeAsFileTime(&value);
    ULARGE_INTEGER combined = {};
    combined.LowPart = value.dwLowDateTime;
    combined.HighPart = value.dwHighDateTime;
    return combined.QuadPart;
}

static bool isValidUtf8(const char* value) {
    if (!value) {
        return false;
    }
    const unsigned char* bytes = reinterpret_cast<const unsigned char*>(value);
    while (*bytes) {
        if (*bytes <= 0x7F) {
            ++bytes;
            continue;
        }
        int remaining = 0;
        if ((*bytes & 0xE0) == 0xC0) remaining = 1;
        else if ((*bytes & 0xF0) == 0xE0) remaining = 2;
        else if ((*bytes & 0xF8) == 0xF0) remaining = 3;
        else return false;

        ++bytes;
        for (int i = 0; i < remaining; ++i, ++bytes) {
            if ((*bytes & 0xC0) != 0x80) {
                return false;
            }
        }
    }
    return true;
}

static std::wstring utf8ToWide(const std::string& value) {
    if (value.empty()) {
        return {};
    }
    int wideCount = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, value.c_str(), -1, nullptr, 0);
    if (wideCount <= 0) {
        return {};
    }
    std::wstring wide((size_t)wideCount, L'\0');
    if (MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, value.c_str(), -1, wide.data(), wideCount) <= 0) {
        return {};
    }
    if (!wide.empty() && wide.back() == L'\0') {
        wide.pop_back();
    }
    return wide;
}

static std::string wideToUtf8(const std::wstring& value) {
    if (value.empty()) {
        return {};
    }
    int utf8Count = WideCharToMultiByte(CP_UTF8, 0, value.c_str(), -1, nullptr, 0, nullptr, nullptr);
    if (utf8Count <= 0) {
        return {};
    }
    std::string utf8((size_t)utf8Count, '\0');
    if (WideCharToMultiByte(CP_UTF8, 0, value.c_str(), -1, utf8.data(), utf8Count, nullptr, nullptr) <= 0) {
        return {};
    }
    if (!utf8.empty() && utf8.back() == '\0') {
        utf8.pop_back();
    }
    return utf8;
}

static std::string wideToAnsiBytes(const std::wstring& value) {
    if (value.empty()) {
        return {};
    }
    int byteCount = WideCharToMultiByte(CP_ACP, 0, value.c_str(), -1, nullptr, 0, nullptr, nullptr);
    if (byteCount <= 0) {
        return {};
    }
    std::string bytes((size_t)byteCount, '\0');
    if (WideCharToMultiByte(CP_ACP, 0, value.c_str(), -1, bytes.data(), byteCount, nullptr, nullptr) <= 0) {
        return {};
    }
    if (!bytes.empty() && bytes.back() == '\0') {
        bytes.pop_back();
    }
    return bytes;
}

static bool looksLikeUtf8Mojibake(const std::wstring& value) {
    if (value.size() < 4) {
        return false;
    }
    size_t suspicious = 0;
    for (wchar_t ch : value) {
        if (ch == L'Р' || ch == L'С' || ch == L'Ð' || ch == L'Ñ') {
            ++suspicious;
        }
    }
    return suspicious >= 2 && suspicious * 3 >= value.size();
}

static std::string repairUtf8Mojibake(const std::string& utf8) {
    std::wstring mojibakeWide = utf8ToWide(utf8);
    if (mojibakeWide.empty() || !looksLikeUtf8Mojibake(mojibakeWide)) {
        return utf8;
    }
    std::string ansiBytes = wideToAnsiBytes(mojibakeWide);
    if (ansiBytes.empty() || !isValidUtf8(ansiBytes.c_str())) {
        return utf8;
    }
    std::wstring repairedWide = utf8ToWide(ansiBytes);
    std::string repairedUtf8 = wideToUtf8(repairedWide);
    return repairedUtf8.empty() ? utf8 : repairedUtf8;
}

static std::string ansiToUtf8(const char* value) {
    if (!value || !*value) {
        return {};
    }
    int wideCount = MultiByteToWideChar(CP_ACP, 0, value, -1, nullptr, 0);
    if (wideCount <= 0) {
        return std::string(value);
    }
    std::wstring wide((size_t)wideCount, L'\0');
    if (MultiByteToWideChar(CP_ACP, 0, value, -1, wide.data(), wideCount) <= 0) {
        return std::string(value);
    }
    int utf8Count = WideCharToMultiByte(CP_UTF8, 0, wide.c_str(), -1, nullptr, 0, nullptr, nullptr);
    if (utf8Count <= 0) {
        return std::string(value);
    }
    std::string utf8((size_t)utf8Count, '\0');
    if (WideCharToMultiByte(CP_UTF8, 0, wide.c_str(), -1, utf8.data(), utf8Count, nullptr, nullptr) <= 0) {
        return std::string(value);
    }
    if (!utf8.empty() && utf8.back() == '\0') {
        utf8.pop_back();
    }
    return utf8;
}

static std::string safeString(const char* value) {
    if (!value) {
        return {};
    }
    if (isValidUtf8(value)) {
        return repairUtf8Mojibake(std::string(value));
    }
    return ansiToUtf8(value);
}

static duint tryCaptureCurrentIp() {
    if (!DbgIsDebugging() || DbgIsRunning()) {
        return 0;
    }
    return Script::Register::Get(REG_IP);
}

static bool readNativeApiWord(duint address, duint& value) noexcept
{
    value = 0;
    try
    {
        return address != 0 && DbgMemRead(address, &value, sizeof(value));
    }
    catch(...)
    {
        value = 0;
        return false;
    }
}

static std::vector<duint> captureNativeApiArguments(
    duint stackPointer,
    size_t argumentCount = 8) noexcept
{
    std::vector<duint> arguments;
    try
    {
        argumentCount = std::min<size_t>(argumentCount, 16);
        arguments.reserve(argumentCount);
#ifdef _WIN64
        const Script::Register::RegisterEnum registerArguments[] = {
            Script::Register::RCX,
            Script::Register::RDX,
            Script::Register::R8,
            Script::Register::R9,
        };
        for(size_t index = 0;
            index < argumentCount && index < _countof(registerArguments);
            ++index)
            arguments.push_back(Script::Register::Get(registerArguments[index]));
        for(size_t index = arguments.size(); index < argumentCount; ++index)
        {
            duint value = 0;
            const duint offset = static_cast<duint>(
                0x28 + (index - 4) * sizeof(duint));
            readNativeApiWord(stackPointer + offset, value);
            arguments.push_back(value);
        }
#else
        for(size_t index = 0; index < argumentCount; ++index)
        {
            duint value = 0;
            const duint offset = static_cast<duint>(
                sizeof(duint) + index * sizeof(duint));
            readNativeApiWord(stackPointer + offset, value);
            arguments.push_back(value);
        }
#endif
    }
    catch(...)
    {
        // Keep a partial ABI snapshot if a register or stack read failed.
    }
    return arguments;
}

static void enrichNativeApiCaller(NativeApiTraceEvent& event) noexcept
{
    try
    {
        if(!event.returnAddress)
            return;
        const DBGFUNCTIONS* functions = DbgFunctions();
        if(!functions)
            return;
        char moduleName[MAX_MODULE_SIZE] = {};
        if(functions->ModNameFromAddr
            && functions->ModNameFromAddr(
                event.returnAddress, moduleName, true))
            event.callerModule = moduleName;
        if(functions->ModBaseFromAddr)
        {
            event.callerModuleBase =
                functions->ModBaseFromAddr(event.returnAddress);
            if(event.callerModuleBase
                && event.returnAddress >= event.callerModuleBase)
                event.callerRva =
                    event.returnAddress - event.callerModuleBase;
        }
    }
    catch(...)
    {
        // Caller enrichment is evidence-only.
    }
}

static bool nativeApiFindSoftwareBreakpoint(
    duint address,
    BRIDGEBP* found = nullptr) noexcept
{
    try
    {
        BPMAP map = {};
        const int count = DbgGetBpList(bp_normal, &map);
        bool result = false;
        if(count > 0 && map.bp)
        {
            for(int index = 0; index < count; ++index)
            {
                if(map.bp[index].addr != address)
                    continue;
                result = true;
                if(found)
                    *found = map.bp[index];
                break;
            }
        }
        if(map.bp)
            BridgeFree(map.bp);
        return result;
    }
    catch(...)
    {
        return false;
    }
}

static bool nativeApiClassifyAddressUnlocked(
    duint address,
    std::string& traceId,
    std::string& kind)
{
    if(!address)
        return false;
    for(const auto& item : g_nativeApiTrace.configs)
    {
        if(item.second.registeredEntryBreakpoints.count(address))
        {
            traceId = item.first;
            kind = "entry";
            return true;
        }
        if(item.second.ownedReturnBreakpoints.count(address))
        {
            traceId = item.first;
            kind = "return";
            return true;
        }
    }
    return false;
}

static bool nativeApiPendingReturnExistsUnlocked(
    const std::string& traceId,
    duint returnAddress)
{
    const auto traceIt = g_nativeApiTrace.pending.find(traceId);
    if(traceIt == g_nativeApiTrace.pending.end())
        return false;
    for(const auto& threadPending : traceIt->second)
    {
        for(const auto& pending : threadPending.second)
        {
            if(pending.returnAddress == returnAddress)
                return true;
        }
    }
    return false;
}

static bool nativeApiScheduleReturnHook(
    const std::string& traceId,
    duint returnAddress) noexcept
{
    if(traceId.empty() || !returnAddress)
        return false;
    {
        std::lock_guard<std::mutex> lock(g_nativeApiTrace.mutex);
        const auto configIt = g_nativeApiTrace.configs.find(traceId);
        if(configIt == g_nativeApiTrace.configs.end()
            || !configIt->second.nativeReturnHooks)
            return false;
        if(configIt->second.ownedReturnBreakpoints.count(returnAddress)
            || configIt->second.preexistingReturnBreakpoints.count(returnAddress))
            return true;
    }

    BRIDGEBP existing = {};
    if(nativeApiFindSoftwareBreakpoint(returnAddress, &existing))
    {
        std::lock_guard<std::mutex> lock(g_nativeApiTrace.mutex);
        auto& config = g_nativeApiTrace.configs[traceId];
        config.preexistingReturnBreakpoints.insert(returnAddress);
        return true;
    }

    char command[512] = {};
    _snprintf_s(
        command, sizeof(command), _TRUNCATE,
        "bp 0x%llx",
        static_cast<unsigned long long>(returnAddress));
    bool installed = DbgCmdExecDirect(command);
    if(installed)
    {
        const std::string name =
            std::string("mcp_api_trace:") + traceId + ":return";
        _snprintf_s(
            command, sizeof(command), _TRUNCATE,
            "SetBreakpointName 0x%llx,\"%s\"",
            static_cast<unsigned long long>(returnAddress),
            name.c_str());
        installed = DbgCmdExecDirect(command);
    }
    BRIDGEBP verified = {};
    installed = installed
        && nativeApiFindSoftwareBreakpoint(returnAddress, &verified)
        && verified.enabled && verified.active;
    if(!installed)
    {
        _snprintf_s(
            command, sizeof(command), _TRUNCATE,
            "bc 0x%llx",
            static_cast<unsigned long long>(returnAddress));
        DbgCmdExecDirect(command);
    }
    {
        std::lock_guard<std::mutex> lock(g_nativeApiTrace.mutex);
        auto& config = g_nativeApiTrace.configs[traceId];
        if(installed)
        {
            config.ownedReturnBreakpoints.insert(returnAddress);
            config.returnHooksInstalled++;
            config.lastReturnHookError.clear();
        }
        else
        {
            config.returnHookFailures++;
            config.lastReturnHookError =
                "x64dbg rejected or failed to verify the native return hook";
        }
    }
    return installed;
}

static bool nativeApiRemoveOwnedReturnHook(
    const std::string& traceId,
    duint returnAddress) noexcept
{
    if(traceId.empty() || !returnAddress)
        return false;
    {
        std::lock_guard<std::mutex> lock(g_nativeApiTrace.mutex);
        const auto configIt = g_nativeApiTrace.configs.find(traceId);
        if(configIt == g_nativeApiTrace.configs.end()
            || !configIt->second.ownedReturnBreakpoints.count(returnAddress))
            return true;
    }
    char command[128] = {};
    _snprintf_s(
        command, sizeof(command), _TRUNCATE,
        "bc 0x%llx",
        static_cast<unsigned long long>(returnAddress));
    const bool removed = DbgCmdExecDirect(command)
        && !nativeApiFindSoftwareBreakpoint(returnAddress);
    {
        std::lock_guard<std::mutex> lock(g_nativeApiTrace.mutex);
        auto& config = g_nativeApiTrace.configs[traceId];
        if(removed)
        {
            config.ownedReturnBreakpoints.erase(returnAddress);
            config.returnHooksRemoved++;
            config.lastReturnHookError.clear();
        }
        else
        {
            config.returnHookFailures++;
            config.lastReturnHookError =
                "x64dbg rejected or failed to verify native return-hook removal";
        }
    }
    return removed;
}

static void appendNativeApiEventUnlocked(NativeApiTraceEvent&& event) noexcept
{
    if(g_nativeApiTrace.events.size() >= NativeApiTraceState::kMaxEvents)
    {
        g_nativeApiTrace.events.pop_front();
        g_nativeApiTrace.droppedEvents++;
    }
    g_nativeApiTrace.events.push_back(std::move(event));
}

static void recordNativeApiBreakpoint(const PLUG_CB_BREAKPOINT* info) noexcept
{
    try
    {
        if(!info || !info->breakpoint)
            return;
        const std::string name = safeString(info->breakpoint->name);
        static constexpr const char* prefix = "mcp_api_trace:";
        std::string classifiedTraceId;
        std::string classifiedKind;
        if(name.rfind(prefix, 0) == 0)
        {
            const std::string remainder = name.substr(std::strlen(prefix));
            const size_t separator = remainder.rfind(':');
            if(separator != std::string::npos && separator != 0
                && separator + 1 < remainder.size())
            {
                classifiedTraceId = remainder.substr(0, separator);
                classifiedKind = remainder.substr(separator + 1);
            }
        }
        if(classifiedTraceId.empty())
        {
            std::lock_guard<std::mutex> lock(g_nativeApiTrace.mutex);
            if(!nativeApiClassifyAddressUnlocked(
                    info->breakpoint->addr,
                    classifiedTraceId,
                    classifiedKind))
                return;
        }
        if(classifiedKind != "entry" && classifiedKind != "return")
            return;
        NativeApiTraceEvent event;
        event.traceId = classifiedTraceId;
        event.kind = classifiedKind;
        event.name = name.empty()
            ? std::string(prefix) + classifiedTraceId + ":" + classifiedKind
            : name;
        event.module = safeString(info->breakpoint->mod);
        event.tickMs = nowTickMs();
        event.threadId = DbgGetThreadId();
        event.breakpointAddress = info->breakpoint->addr;
        event.ip = tryCaptureCurrentIp();
        if(!event.ip)
            event.ip = info->breakpoint->addr;
        event.stackPointer =
            Script::Register::Get(Script::Register::CSP);
        if(event.kind == "entry")
        {
            event.apiAddress = event.breakpointAddress;
            readNativeApiWord(event.stackPointer, event.returnAddress);
            event.arguments =
                captureNativeApiArguments(event.stackPointer, 8);
            enrichNativeApiCaller(event);
        }
        else if(event.kind == "return")
        {
            event.returnAddress = event.breakpointAddress;
            event.returnValue =
                Script::Register::Get(Script::Register::CAX);
        }
        const std::string eventTraceId = event.traceId;
        const std::string eventKind = event.kind;
        const duint entryReturnAddress = event.returnAddress;
        duint cleanupReturnAddress = 0;
        {
            std::lock_guard<std::mutex> lock(g_nativeApiTrace.mutex);
            event.seq = g_nativeApiTrace.nextSeq++;
            if(event.kind == "entry")
            {
                event.callId = g_nativeApiTrace.nextCallId++;
                event.entrySeq = event.seq;
                NativeApiPendingCall pending;
                pending.callId = event.callId;
                pending.entrySeq = event.entrySeq;
                pending.entryTickMs = event.tickMs;
                pending.apiAddress = event.apiAddress;
                pending.returnAddress = event.returnAddress;
                pending.module = event.module;
                pending.arguments = event.arguments;
                g_nativeApiTrace.pending[event.traceId][event.threadId]
                    .push_back(std::move(pending));
            }
            else if(event.kind == "return")
            {
                const auto traceIt =
                    g_nativeApiTrace.pending.find(event.traceId);
                if(traceIt != g_nativeApiTrace.pending.end())
                {
                    const auto threadIt =
                        traceIt->second.find(event.threadId);
                    if(threadIt != traceIt->second.end())
                    {
                        auto& stack = threadIt->second;
                        size_t matchedIndex = stack.size();
                        for(size_t index = stack.size(); index > 0; --index)
                        {
                            const auto& candidate = stack[index - 1];
                            if(candidate.returnAddress
                                == event.breakpointAddress)
                            {
                                matchedIndex = index - 1;
                                break;
                            }
                        }
                        if(matchedIndex < stack.size())
                        {
                            const NativeApiPendingCall matched =
                                stack[matchedIndex];
                            event.matchedReturn = true;
                            event.callId = matched.callId;
                            event.entrySeq = matched.entrySeq;
                            event.apiAddress = matched.apiAddress;
                            event.module = matched.module;
                            event.arguments = matched.arguments;
                            event.unwoundFrames =
                                stack.size() - matchedIndex - 1;
                            event.durationMs = event.tickMs >= matched.entryTickMs
                                ? event.tickMs - matched.entryTickMs : 0;
                            stack.erase(
                                stack.begin()
                                    + static_cast<std::ptrdiff_t>(matchedIndex),
                                stack.end());
                        }
                        if(stack.empty())
                            traceIt->second.erase(threadIt);
                    }
                    if(traceIt->second.empty())
                        g_nativeApiTrace.pending.erase(traceIt);
                }
                const auto configIt =
                    g_nativeApiTrace.configs.find(event.traceId);
                if(configIt != g_nativeApiTrace.configs.end()
                    && configIt->second.ownedReturnBreakpoints.count(
                        event.breakpointAddress)
                    && !nativeApiPendingReturnExistsUnlocked(
                        event.traceId, event.breakpointAddress))
                    cleanupReturnAddress = event.breakpointAddress;
            }
            appendNativeApiEventUnlocked(std::move(event));
        }
        if(eventKind == "entry" && entryReturnAddress)
            nativeApiScheduleReturnHook(eventTraceId, entryReturnAddress);
        else if(eventKind == "return" && cleanupReturnAddress)
            nativeApiRemoveOwnedReturnHook(
                eventTraceId, cleanupReturnAddress);
    }
    catch(...)
    {
        // Native API evidence is best-effort and must never escape the x64dbg
        // breakpoint callback.
    }
}

static bool recordNativeApiEntryRoute(
    const std::string& traceId,
    duint apiAddress,
    const std::string& module,
    uint64_t& outSeq,
    uint64_t& outCallId,
    bool& outDuplicate) noexcept
{
    outSeq = 0;
    outCallId = 0;
    outDuplicate = false;
    try
    {
        if(traceId.empty() || !apiAddress)
            return false;
        const DWORD threadId = DbgGetThreadId();
        if(!threadId)
            return false;
        NativeApiTraceEvent event;
        event.traceId = traceId;
        event.kind = "entry";
        event.name =
            std::string("mcp_api_trace:") + traceId + ":entry";
        event.module = module;
        event.tickMs = nowTickMs();
        event.threadId = threadId;
        event.apiAddress = apiAddress;
        event.breakpointAddress = apiAddress;
        event.ip = tryCaptureCurrentIp();
        event.stackPointer =
            Script::Register::Get(Script::Register::CSP);
        readNativeApiWord(event.stackPointer, event.returnAddress);
        event.arguments =
            captureNativeApiArguments(event.stackPointer, 8);
        enrichNativeApiCaller(event);
        if(!event.returnAddress)
            return false;
        const duint routeReturnAddress = event.returnAddress;
        {
            std::lock_guard<std::mutex> lock(g_nativeApiTrace.mutex);
            const auto configIt = g_nativeApiTrace.configs.find(traceId);
            if(configIt == g_nativeApiTrace.configs.end()
                || !configIt->second.nativeReturnHooks)
                return false;
            auto& stack = g_nativeApiTrace.pending[traceId][threadId];
            for(const auto& pending : stack)
            {
                if(pending.returnAddress == event.returnAddress
                    && pending.apiAddress == event.apiAddress)
                {
                    outSeq = pending.entrySeq;
                    outCallId = pending.callId;
                    outDuplicate = true;
                    return true;
                }
            }
            event.seq = g_nativeApiTrace.nextSeq++;
            event.callId = g_nativeApiTrace.nextCallId++;
            event.entrySeq = event.seq;
            NativeApiPendingCall pending;
            pending.callId = event.callId;
            pending.entrySeq = event.entrySeq;
            pending.entryTickMs = event.tickMs;
            pending.apiAddress = event.apiAddress;
            pending.returnAddress = event.returnAddress;
            pending.module = event.module;
            pending.arguments = event.arguments;
            stack.push_back(std::move(pending));
            outSeq = event.seq;
            outCallId = event.callId;
            appendNativeApiEventUnlocked(std::move(event));
        }
        nativeApiScheduleReturnHook(traceId, routeReturnAddress);
        return true;
    }
    catch(...)
    {
        return false;
    }
}

static bool nativeIsManagedExceptionCode(DWORD code) noexcept
{
    return code == 0xE0434352u || code == 0xE0434F4Du
        || code == 0xE0434353u;
}

static std::string nativeDetectManagedRuntime() noexcept
{
    try
    {
        ListInfo moduleList = {};
        if(!Script::Module::GetList(&moduleList) || !moduleList.data)
            return {};
        std::string runtime;
        auto* modules =
            reinterpret_cast<Script::Module::ModuleInfo*>(moduleList.data);
        for(size_t index = 0; index < moduleList.count; ++index)
        {
            std::string name = modules[index].name;
            std::transform(
                name.begin(),
                name.end(),
                name.begin(),
                [](unsigned char value) {
                    return static_cast<char>(std::tolower(value));
                });
            if(name.find("coreclr") != std::string::npos)
            {
                runtime = "coreclr";
                break;
            }
            if(name == "clr.dll" || name.find("mscoree") != std::string::npos)
                runtime = "clr";
        }
        BridgeFree(moduleList.data);
        return runtime;
    }
    catch(...)
    {
        return {};
    }
}

static void recordNativeApiException(const PLUG_CB_EXCEPTION* info) noexcept
{
    try
    {
        if(!info || !info->Exception)
            return;
        const DWORD threadId = DbgGetThreadId();
        if(!threadId)
            return;
        const DWORD exceptionCode =
            info->Exception->ExceptionRecord.ExceptionCode;
        const bool firstChance = info->Exception->dwFirstChance != 0;
        const duint exceptionAddress =
            reinterpret_cast<duint>(
                info->Exception->ExceptionRecord.ExceptionAddress);
        const duint stackPointer =
            Script::Register::Get(Script::Register::CSP);
        const bool managedException =
            nativeIsManagedExceptionCode(exceptionCode);
        std::string managedRuntime =
            managedException ? nativeDetectManagedRuntime() : std::string();
        if(managedException && managedRuntime.empty())
            managedRuntime = "unknown";
        const DWORD managedHResult =
            managedException
            && info->Exception->ExceptionRecord.NumberParameters > 0
            ? static_cast<DWORD>(
                info->Exception->ExceptionRecord.ExceptionInformation[0])
            : 0;
        const duint managedObject =
            managedException
            && info->Exception->ExceptionRecord.NumberParameters > 1
            ? static_cast<duint>(
                info->Exception->ExceptionRecord.ExceptionInformation[1])
            : 0;
        std::vector<duint> exceptionParameters;
        if(managedException)
        {
            const ULONG parameterCount = std::min<ULONG>(
                info->Exception->ExceptionRecord.NumberParameters,
                8);
            exceptionParameters.reserve(parameterCount);
            for(ULONG index = 0; index < parameterCount; ++index)
                exceptionParameters.push_back(static_cast<duint>(
                    info->Exception->ExceptionRecord.ExceptionInformation[index]));
        }
        std::vector<std::pair<std::string, duint>> cleanupReturnHooks;
        {
            std::lock_guard<std::mutex> lock(g_nativeApiTrace.mutex);
            std::unordered_set<std::string> affectedTraceIds;
            for(auto traceIt = g_nativeApiTrace.pending.begin();
                traceIt != g_nativeApiTrace.pending.end();)
            {
                auto threadIt = traceIt->second.find(threadId);
                if(threadIt == traceIt->second.end()
                    || threadIt->second.empty())
                {
                    ++traceIt;
                    continue;
                }
                auto& stack = threadIt->second;
                if(firstChance)
                {
                    const auto& pending = stack.back();
                    NativeApiTraceEvent event;
                    event.seq = g_nativeApiTrace.nextSeq++;
                    event.callId = pending.callId;
                    event.entrySeq = pending.entrySeq;
                    event.tickMs = nowTickMs();
                    event.threadId = threadId;
                    event.ip = exceptionAddress;
                    event.stackPointer = stackPointer;
                    event.apiAddress = pending.apiAddress;
                    event.returnAddress = pending.returnAddress;
                    event.unwoundFrames = stack.size();
                    event.exceptionCode = exceptionCode;
                    event.exceptionFirstChance = true;
                    event.managedException = managedException;
                    event.managedRuntime = managedRuntime;
                    event.managedHResult = managedHResult;
                    event.managedObject = managedObject;
                    event.exceptionParameters = exceptionParameters;
                    event.traceId = traceIt->first;
                    event.kind = "exception";
                    event.name = "exception";
                    event.module = pending.module;
                    event.arguments = pending.arguments;
                    appendNativeApiEventUnlocked(std::move(event));
                    ++traceIt;
                    continue;
                }
                const std::string traceId = traceIt->first;
                size_t unwound = 0;
                while(!stack.empty())
                {
                    const auto pending = stack.back();
                    stack.pop_back();
                    NativeApiTraceEvent event;
                    event.seq = g_nativeApiTrace.nextSeq++;
                    event.callId = pending.callId;
                    event.entrySeq = pending.entrySeq;
                    event.tickMs = nowTickMs();
                    event.threadId = threadId;
                    event.ip = exceptionAddress;
                    event.stackPointer = stackPointer;
                    event.apiAddress = pending.apiAddress;
                    event.returnAddress = pending.returnAddress;
                    event.unwoundFrames = unwound++;
                    event.exceptionCode = exceptionCode;
                    event.exceptionFirstChance = false;
                    event.managedException = managedException;
                    event.managedRuntime = managedRuntime;
                    event.managedHResult = managedHResult;
                    event.managedObject = managedObject;
                    event.exceptionParameters = exceptionParameters;
                    event.traceId = traceId;
                    event.kind = "exception_unwind";
                    event.name = "exception_unwind";
                    event.module = pending.module;
                    event.arguments = pending.arguments;
                    appendNativeApiEventUnlocked(std::move(event));
                }
                g_nativeApiTrace.exceptionUnwoundPending[traceId] += unwound;
                affectedTraceIds.insert(traceId);
                traceIt->second.erase(threadIt);
                if(traceIt->second.empty())
                    traceIt = g_nativeApiTrace.pending.erase(traceIt);
                else
                    ++traceIt;
            }
            for(const auto& traceId : affectedTraceIds)
            {
                const auto configIt = g_nativeApiTrace.configs.find(traceId);
                if(configIt == g_nativeApiTrace.configs.end())
                    continue;
                for(const duint address :
                    configIt->second.ownedReturnBreakpoints)
                {
                    if(!nativeApiPendingReturnExistsUnlocked(traceId, address))
                        cleanupReturnHooks.emplace_back(traceId, address);
                }
            }
        }
        for(const auto& cleanup : cleanupReturnHooks)
            nativeApiRemoveOwnedReturnHook(cleanup.first, cleanup.second);
    }
    catch(...)
    {
        // Exception evidence must never escape the debugger callback.
    }
}

static std::string toLowerCopy(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(), [](unsigned char c) {
        return (char)std::tolower(c);
    });
    return value;
}

static std::string baseNameCopy(const std::string& value) {
    size_t pos = value.find_last_of("\\/");
    if (pos == std::string::npos) {
        return value;
    }
    return value.substr(pos + 1);
}

static std::string stemCopy(const std::string& value) {
    std::string base = baseNameCopy(value);
    size_t dot = base.find_last_of('.');
    if (dot == std::string::npos) {
        return base;
    }
    return base.substr(0, dot);
}

static bool parseBoolParam(const std::string& rawValue, bool defaultValue = false) {
    std::string value = toLowerCopy(rawValue);
    trimParam(value);
    if (value.empty()) {
        return defaultValue;
    }
    if (value == "1" || value == "true" || value == "yes" || value == "on") {
        return true;
    }
    if (value == "0" || value == "false" || value == "no" || value == "off") {
        return false;
    }
    return defaultValue;
}

static std::wstring directoryNameW(const std::wstring& path) {
    const size_t pos = path.find_last_of(L"\\/");
    if (pos == std::wstring::npos) {
        return {};
    }
    return path.substr(0, pos);
}

static std::wstring joinPathW(const std::wstring& dir, const std::wstring& fileName) {
    if (dir.empty()) {
        return fileName;
    }
    if (dir.back() == L'\\' || dir.back() == L'/') {
        return dir + fileName;
    }
    return dir + L"\\" + fileName;
}

static std::wstring getDebuggerDirectoryW() {
    wchar_t modulePath[MAX_PATH * 4] = {};
    DWORD length = GetModuleFileNameW(nullptr, modulePath, ARRAYSIZE(modulePath));
    if (length == 0 || length >= ARRAYSIZE(modulePath)) {
        return {};
    }
    return directoryNameW(std::wstring(modulePath, modulePath + length));
}

static bool fileExistsW(const std::wstring& path) {
    if (path.empty()) {
        return false;
    }
    const DWORD attrs = GetFileAttributesW(path.c_str());
    return attrs != INVALID_FILE_ATTRIBUTES && !(attrs & FILE_ATTRIBUTE_DIRECTORY);
}

static unsigned long long fileSizeW(const std::wstring& path) {
    WIN32_FILE_ATTRIBUTE_DATA data = {};
    if (!GetFileAttributesExW(path.c_str(), GetFileExInfoStandard, &data)) {
        return 0;
    }
    ULARGE_INTEGER size = {};
    size.LowPart = data.nFileSizeLow;
    size.HighPart = data.nFileSizeHigh;
    return static_cast<unsigned long long>(size.QuadPart);
}

static std::string formatWin32ErrorMessage(DWORD errorCode) {
    if (errorCode == 0) {
        return {};
    }
    wchar_t* buffer = nullptr;
    DWORD flags = FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS;
    DWORD length = FormatMessageW(
        flags,
        nullptr,
        errorCode,
        MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        reinterpret_cast<LPWSTR>(&buffer),
        0,
        nullptr);
    std::wstring wideMessage;
    if (length && buffer) {
        wideMessage.assign(buffer, buffer + length);
        while (!wideMessage.empty() && (wideMessage.back() == L'\r' || wideMessage.back() == L'\n' || wideMessage.back() == L' ')) {
            wideMessage.pop_back();
        }
    }
    if (buffer) {
        LocalFree(buffer);
    }
    std::string utf8 = wideToUtf8(wideMessage);
    if (utf8.empty()) {
        std::stringstream ss;
        ss << "Win32 error " << errorCode;
        return ss.str();
    }
    return utf8;
}

static std::string scyllaErrorName(int code) {
    switch (code) {
    case 0:
        return "SCY_ERROR_SUCCESS";
    case -1:
        return "SCY_ERROR_PROCOPEN";
    case -2:
        return "SCY_ERROR_IATWRITE";
    case -3:
        return "SCY_ERROR_IATSEARCH";
    case -4:
        return "SCY_ERROR_IATNOTFOUND";
    case -5:
        return "SCY_ERROR_PIDNOTFOUND";
    case -6:
        return "SCY_ERROR_MODULENOTFOUND";
    default:
        break;
    }
    std::stringstream ss;
    ss << "SCY_ERROR_" << code;
    return ss.str();
}

static std::string scyllaErrorHint(int code) {
    switch (code) {
    case -3:
    case -4:
        return "IAT auto-search failed. Pause closer to the real OEP or provide a better searchStart.";
    case -5:
        return "The requested PID is no longer alive. Re-launch or refresh the debug session.";
    case -6:
        return "The requested module base was not found in the target process.";
    case -2:
        return "Scylla dumped the process, but import reconstruction failed. Keep the raw dump for manual recovery.";
    case -1:
        return "Scylla could not open the process handle. Make sure the debuggee is still active and paused.";
    default:
        return {};
    }
}

typedef const WCHAR* (WINAPI* fnScyllaVersionInformationW)();
typedef BOOL (WINAPI* fnScyllaDumpProcessW)(DWORD_PTR pid, const WCHAR* fileToDump,
                                            DWORD_PTR imagebase, DWORD_PTR entrypoint,
                                            const WCHAR* fileResult);
typedef BOOL (WINAPI* fnScyllaRebuildFileW)(const WCHAR* fileToRebuild, BOOL removeDosStub,
                                            BOOL updatePeHeaderChecksum, BOOL createBackup);
typedef int (WINAPI* fnScyllaIatSearchV098)(DWORD dwProcessId, DWORD_PTR* iatStart,
                                            DWORD* iatSize, DWORD_PTR searchStart,
                                            BOOL advancedSearch);
typedef int (WINAPI* fnScyllaIatFixAutoWV098)(DWORD_PTR iatAddr, DWORD iatSize,
                                              DWORD dwProcessId, const WCHAR* dumpFile,
                                              const WCHAR* iatFixFile);
typedef int (WINAPI* fnScyllaIatSearchModern)(DWORD dwProcessId, DWORD_PTR imagebase,
                                              DWORD_PTR* iatStart, DWORD* iatSize,
                                              DWORD_PTR searchStart, BOOL advancedSearch);
typedef int (WINAPI* fnScyllaIatFixAutoWModern)(DWORD dwProcessId, DWORD_PTR imagebase,
                                                DWORD_PTR iatAddr, DWORD iatSize,
                                                BOOL createNewIat, const WCHAR* dumpFile,
                                                const WCHAR* iatFixFile);

struct LoadedScyllaApi {
    HMODULE module = nullptr;
    bool modernAbi = false;
    std::wstring dllPath;
    std::wstring version;
    fnScyllaDumpProcessW dumpProcessW = nullptr;
    fnScyllaRebuildFileW rebuildFileW = nullptr;
    fnScyllaIatSearchV098 iatSearchV098 = nullptr;
    fnScyllaIatFixAutoWV098 iatFixAutoWV098 = nullptr;
    fnScyllaIatSearchModern iatSearchModern = nullptr;
    fnScyllaIatFixAutoWModern iatFixAutoWModern = nullptr;
};

static void unloadScyllaApi(LoadedScyllaApi& api) {
    if (api.module) {
        FreeLibrary(api.module);
        api.module = nullptr;
    }
}

static bool loadScyllaApi(LoadedScyllaApi& api, std::string& errorText) {
    api = LoadedScyllaApi{};
    const std::wstring debuggerDir = getDebuggerDirectoryW();
    if (debuggerDir.empty()) {
        errorText = "Failed to resolve the x64dbg installation directory.";
        return false;
    }
    api.dllPath = joinPathW(debuggerDir, L"Scylla.dll");
    HMODULE module = LoadLibraryW(api.dllPath.c_str());
    if (!module) {
        std::stringstream ss;
        ss << "LoadLibraryW failed for " << wideToUtf8(api.dllPath)
           << ": " << formatWin32ErrorMessage(GetLastError());
        errorText = ss.str();
        return false;
    }

    api.module = module;
    auto versionFn = reinterpret_cast<fnScyllaVersionInformationW>(
        GetProcAddress(module, "ScyllaVersionInformationW"));
    api.dumpProcessW = reinterpret_cast<fnScyllaDumpProcessW>(
        GetProcAddress(module, "ScyllaDumpProcessW"));
    api.rebuildFileW = reinterpret_cast<fnScyllaRebuildFileW>(
        GetProcAddress(module, "ScyllaRebuildFileW"));

    if (versionFn) {
        const WCHAR* versionText = versionFn();
        if (versionText) {
            api.version.assign(versionText);
        }
    }

    const std::string versionLower = toLowerCopy(wideToUtf8(api.version));
    api.modernAbi = versionLower.find("v0.10") != std::string::npos
        || versionLower.find("v0.11") != std::string::npos
        || versionLower.find("v0.12") != std::string::npos
        || versionLower.find("v1.") != std::string::npos;

    if (api.modernAbi) {
        api.iatSearchModern = reinterpret_cast<fnScyllaIatSearchModern>(
            GetProcAddress(module, "ScyllaIatSearch"));
        api.iatFixAutoWModern = reinterpret_cast<fnScyllaIatFixAutoWModern>(
            GetProcAddress(module, "ScyllaIatFixAutoW"));
    } else {
        api.iatSearchV098 = reinterpret_cast<fnScyllaIatSearchV098>(
            GetProcAddress(module, "ScyllaIatSearch"));
        api.iatFixAutoWV098 = reinterpret_cast<fnScyllaIatFixAutoWV098>(
            GetProcAddress(module, "ScyllaIatFixAutoW"));
    }

    if (!api.dumpProcessW || !api.rebuildFileW ||
        (!api.modernAbi && (!api.iatSearchV098 || !api.iatFixAutoWV098)) ||
        (api.modernAbi && (!api.iatSearchModern || !api.iatFixAutoWModern))) {
        errorText = "Scylla.dll is missing one or more required exports.";
        unloadScyllaApi(api);
        return false;
    }
    return true;
}

static bool moduleNameMatches(const std::string& wantedRaw, const std::string& candidateRaw) {
    std::string wanted = toLowerCopy(wantedRaw);
    std::string candidate = toLowerCopy(candidateRaw);
    trimParam(wanted);
    trimParam(candidate);
    if (wanted.empty() || candidate.empty()) {
        return false;
    }

    const std::string wantedBase = baseNameCopy(wanted);
    const std::string candidateBase = baseNameCopy(candidate);
    const std::string wantedStem = stemCopy(wantedBase);
    const std::string candidateStem = stemCopy(candidateBase);

    return wanted == candidate ||
           wanted == candidateBase ||
           wanted == candidateStem ||
           wantedBase == candidate ||
           wantedBase == candidateBase ||
           wantedBase == candidateStem ||
           wantedStem == candidate ||
           wantedStem == candidateBase ||
           wantedStem == candidateStem;
}

static bool findModuleInfoByName(const std::string& moduleName, Script::Module::ModuleInfo& outModule) {
    ListInfo moduleList = {};
    if (!Script::Module::GetList(&moduleList) || moduleList.data == nullptr) {
        return false;
    }

    bool found = false;
    auto* modules = (Script::Module::ModuleInfo*)moduleList.data;
    for (size_t i = 0; i < moduleList.count; ++i) {
        if (moduleNameMatches(moduleName, modules[i].name) ||
            moduleNameMatches(moduleName, modules[i].path)) {
            outModule = modules[i];
            found = true;
            break;
        }
    }

    BridgeFree(moduleList.data);
    return found;
}

static std::string launchFileIdHex(const std::array<uint8_t, 16>& bytes);

// Resolve and hash the debugger's current main module without trusting a
// caller-supplied path.  The file identity helper opens the file with sharing
// enabled and hashes the independently opened handle, so this is safe while
// x64dbg owns the debuggee image.
static mcplaunch::FileIdentityResult identifyCurrentMainModule() {
    Script::Module::ModuleInfo moduleInfo = {};
    if (!Script::Module::GetMainModuleInfo(&moduleInfo) || moduleInfo.path[0] == '\0') {
        return {};
    }
    return mcplaunch::identifyFileByPath(utf8ToWide(moduleInfo.path));
}

static void ensureDebugSessionImageIdentity() {
    std::string sessionId;
    uint64_t generation = 0;
    std::string existingHash;
    {
        std::lock_guard<std::mutex> lock(g_debugSession.mutex);
        sessionId = g_debugSession.sessionId;
        generation = g_debugSession.generation;
        existingHash = g_debugSession.imageSha256;
    }
    if (sessionId.empty() || !existingHash.empty()) return;

    const auto identity = identifyCurrentMainModule();
    if (!identity.ok) return;
    std::lock_guard<std::mutex> lock(g_debugSession.mutex);
    if (g_debugSession.sessionId == sessionId
        && g_debugSession.generation == generation
        && g_debugSession.imageSha256.empty()) {
        g_debugSession.imagePath = wideToUtf8(identity.finalPath);
        g_debugSession.imageSha256 = identity.sha256;
        g_debugSession.imageSize = identity.size;
        g_debugSession.imageVolumeSerialNumber = identity.volumeSerialNumber;
        g_debugSession.imageFileId = launchFileIdHex(identity.fileId);
    }
}

static bool resolveCurrentModuleAddress(bool wantEntry, duint& outValue) {
    std::string imagePath;
    {
        std::lock_guard<std::mutex> lock(g_debugSession.mutex);
        imagePath = g_debugSession.imagePath;
    }
    if (imagePath.empty()) {
        return false;
    }

    Script::Module::ModuleInfo moduleInfo = {};
    if (!findModuleInfoByName(imagePath, moduleInfo)) {
        return false;
    }

    outValue = wantEntry ? moduleInfo.entry : moduleInfo.base;
    return outValue != 0;
}

static bool applySignedOffset(duint baseValue, long long delta, duint& outValue) {
    if (delta < 0) {
        const auto magnitude = (unsigned long long)(-delta);
        if ((unsigned long long)baseValue < magnitude) {
            return false;
        }
        outValue = (duint)((unsigned long long)baseValue - magnitude);
        return true;
    }
    outValue = (duint)((unsigned long long)baseValue + (unsigned long long)delta);
    return true;
}

static bool splitOffsetSuffix(const std::string& rawValue, std::string& baseExpr, long long& delta) {
    baseExpr = rawValue;
    delta = 0;
    const size_t pos = rawValue.find_last_of("+-");
    if (pos == std::string::npos || pos == 0 || pos + 1 >= rawValue.size()) {
        return false;
    }

    std::string suffix = rawValue.substr(pos + 1);
    trimParam(suffix);
    if (suffix.empty()) {
        return false;
    }

    try {
        size_t consumed = 0;
        const long long parsed = std::stoll(suffix, &consumed, 0);
        if (consumed != suffix.size()) {
            return false;
        }
        baseExpr = rawValue.substr(0, pos);
        trimParam(baseExpr);
        if (baseExpr.empty()) {
            return false;
        }
        delta = rawValue[pos] == '-' ? -parsed : parsed;
        return true;
    } catch (...) {
        return false;
    }
}

static bool resolveLabelAddress(const std::string& labelText, duint& outValue) {
    ListInfo labelList = {};
    if (!Script::Label::GetList(&labelList) || labelList.data == nullptr) {
        return false;
    }

    auto* labels = (Script::Label::LabelInfo*)labelList.data;
    std::string currentImage;
    {
        std::lock_guard<std::mutex> lock(g_debugSession.mutex);
        currentImage = g_debugSession.imagePath;
    }

    auto tryResolve = [&](bool preferCurrent) -> bool {
        for (size_t i = 0; i < labelList.count; ++i) {
            if (_stricmp(labels[i].text, labelText.c_str()) != 0) {
                continue;
            }
            if (preferCurrent && !currentImage.empty() && !moduleNameMatches(currentImage, labels[i].mod)) {
                continue;
            }

            Script::Module::ModuleInfo moduleInfo = {};
            if (!findModuleInfoByName(labels[i].mod, moduleInfo)) {
                continue;
            }
            outValue = moduleInfo.base + labels[i].rva;
            return true;
        }
        return false;
    };

    const bool found = tryResolve(true) || tryResolve(false);
    BridgeFree(labelList.data);
    return found;
}

static bool resolveSymbolAddress(const std::string& moduleNameRaw, const std::string& symbolNameRaw, duint& outValue) {
    std::string moduleName = moduleNameRaw;
    std::string symbolName = symbolNameRaw;
    trimParam(moduleName);
    trimParam(symbolName);
    if (moduleName.empty() || symbolName.empty()) {
        return false;
    }

    Script::Module::ModuleInfo moduleInfo = {};
    if (!findModuleInfoByName(moduleName, moduleInfo)) {
        return false;
    }

    duint remote = 0;
    if (DbgIsDebugging()) {
        remote = Script::Misc::RemoteGetProcAddress(moduleInfo.name, symbolName.c_str());
        if (remote == 0) {
            std::string moduleBase = stemCopy(moduleInfo.name);
            if (!moduleBase.empty() && moduleBase != moduleInfo.name) {
                remote = Script::Misc::RemoteGetProcAddress(moduleBase.c_str(), symbolName.c_str());
            }
        }
    }
    if (remote != 0) {
        outValue = remote;
        return true;
    }

    ListInfo symbolList = {};
    if (!Script::Symbol::GetList(&symbolList) || symbolList.data == nullptr) {
        return false;
    }

    bool found = false;
    auto* symbols = (Script::Symbol::SymbolInfo*)symbolList.data;
    for (size_t i = 0; i < symbolList.count; ++i) {
        if (!moduleNameMatches(moduleInfo.name, symbols[i].mod)) {
            continue;
        }
        if (_stricmp(symbols[i].name, symbolName.c_str()) != 0) {
            continue;
        }
        outValue = moduleInfo.base + symbols[i].rva;
        found = true;
        break;
    }

    BridgeFree(symbolList.data);
    return found;
}

static bool parseFlexibleDuint(const std::string& rawValue, duint& outValue) {
    std::string value = rawValue;
    trimParam(value);
    if (value.empty()) {
        return false;
    }

    bool success = false;
    outValue = DbgEval(value.c_str(), &success);
    if (success) {
        return true;
    }

    success = Script::Misc::ParseExpression(value.c_str(), &outValue);
    if (success) {
        return true;
    }

    std::string baseExpr = value;
    long long delta = 0;
    splitOffsetSuffix(value, baseExpr, delta);
    const std::string alias = toLowerCopy(baseExpr);

    duint resolved = 0;
    if ((alias == "entry" || alias == "module_entry") && resolveCurrentModuleAddress(true, resolved)) {
        return applySignedOffset(resolved, delta, outValue);
    }
    if ((alias == "module" || alias == "imagebase" || alias == "base") && resolveCurrentModuleAddress(false, resolved)) {
        return applySignedOffset(resolved, delta, outValue);
    }

    const size_t bang = baseExpr.find('!');
    if (bang != std::string::npos) {
        std::string moduleName = baseExpr.substr(0, bang);
        std::string symbolName = baseExpr.substr(bang + 1);
        trimParam(moduleName);
        trimParam(symbolName);
        if (resolveSymbolAddress(moduleName, symbolName, resolved)) {
            return applySignedOffset(resolved, delta, outValue);
        }
    }

    if (resolveLabelAddress(baseExpr, resolved)) {
        return applySignedOffset(resolved, delta, outValue);
    }

    Script::Module::ModuleInfo moduleInfo = {};
    if (findModuleInfoByName(baseExpr, moduleInfo)) {
        return applySignedOffset(moduleInfo.base, delta, outValue);
    }

    try {
        size_t consumed = 0;
        if (baseExpr.rfind("0x", 0) == 0 || baseExpr.rfind("0X", 0) == 0) {
            resolved = (duint)std::stoull(baseExpr, &consumed, 16);
        } else {
            resolved = (duint)std::stoull(baseExpr, &consumed, 0);
        }
        if (consumed == 0) {
            return false;
        }
        return applySignedOffset(resolved, delta, outValue);
    } catch (...) {
        return false;
    }
}

static bool parseCountValue(const std::string& rawValue, duint& outValue) {
    std::string value = rawValue;
    trimParam(value);
    if (value.empty()) {
        return false;
    }
    try {
        size_t consumed = 0;
        int base = (value.rfind("0x", 0) == 0 || value.rfind("0X", 0) == 0) ? 16 : 10;
        outValue = (duint)std::stoull(value, &consumed, base);
        return consumed > 0;
    } catch (...) {
        return false;
    }
}

static std::vector<std::string> splitRequestItems(const std::string& rawValue, bool splitCommas) {
    std::vector<std::string> items;
    std::stringstream ss(rawValue);
    std::string line;
    while (std::getline(ss, line)) {
        trimParam(line);
        if (line.empty()) {
            continue;
        }
        if (!splitCommas || line.find(',') == std::string::npos) {
            items.push_back(line);
            continue;
        }
        std::stringstream csv(line);
        std::string item;
        while (std::getline(csv, item, ',')) {
            trimParam(item);
            if (!item.empty()) {
                items.push_back(item);
            }
        }
    }
    return items;
}

static std::string bytesToHex(const unsigned char* data, size_t size) {
    std::stringstream ss;
    for (size_t i = 0; i < size; ++i) {
        ss << std::setw(2) << std::setfill('0') << std::hex << (unsigned int)data[i];
    }
    return ss.str();
}

static std::string bytesToAscii(const unsigned char* data, size_t size, size_t maxChars) {
    std::string text;
    const size_t limit = maxChars > 0 ? (size < maxChars ? size : maxChars) : size;
    text.reserve(limit);
    for (size_t i = 0; i < limit; ++i) {
        unsigned char ch = data[i];
        if (ch == 0) {
            break;
        }
        text.push_back((ch >= 0x20 && ch < 0x7F) ? (char)ch : '.');
    }
    return text;
}

static std::string utf16leBytesToUtf8(const unsigned char* data, size_t size, size_t maxChars) {
    if (!data || size < 2) {
        return {};
    }
    std::wstring wide;
    wide.reserve(size / 2);
    for (size_t i = 0; i + 1 < size; i += 2) {
        wchar_t ch = (wchar_t)(data[i] | (data[i + 1] << 8));
        if (ch == L'\0') {
            break;
        }
        wide.push_back(ch);
        if (maxChars > 0 && wide.size() >= maxChars) {
            break;
        }
    }
    if (wide.empty()) {
        return {};
    }
    int needed = WideCharToMultiByte(CP_UTF8, 0, wide.c_str(), (int)wide.size(), nullptr, 0, nullptr, nullptr);
    if (needed <= 0) {
        return {};
    }
    std::string utf8((size_t)needed, '\0');
    WideCharToMultiByte(CP_UTF8, 0, wide.c_str(), (int)wide.size(), utf8.data(), needed, nullptr, nullptr);
    return utf8;
}

static bool readMemoryStable(duint addr, duint requestedSize, std::vector<unsigned char>& buffer, duint& sizeRead, std::string& errorText) {
    buffer.assign((size_t)requestedSize, 0);
    sizeRead = 0;
    errorText.clear();

    if (requestedSize == 0) {
        return true;
    }

    duint offset = 0;
    while (offset < requestedSize) {
        duint currentAddr = addr + offset;
        duint pageRemain = 0x1000 - (currentAddr & 0xFFF);
        if (pageRemain == 0) {
            pageRemain = 0x1000;
        }
        duint chunk = std::min<duint>(requestedSize - offset, pageRemain);
        if (DbgMemRead(currentAddr, buffer.data() + offset, chunk)) {
            offset += chunk;
            continue;
        }

        bool progressed = false;
        duint probe = chunk / 2;
        while (probe >= 1) {
            if (DbgMemRead(currentAddr, buffer.data() + offset, probe)) {
                offset += probe;
                progressed = true;
                break;
            }
            probe /= 2;
        }
        if (progressed) {
            continue;
        }

        std::stringstream err;
        if (!DbgMemIsValidReadPtr(currentAddr)) {
            err << "Invalid read pointer at 0x" << std::hex << currentAddr;
        } else {
            err << "Failed to read memory at 0x" << std::hex << currentAddr;
        }
        errorText = err.str();
        break;
    }

    sizeRead = offset;
    return offset > 0 || requestedSize == 0;
}

static std::string buildMemoryReadRangeJson(duint addr, duint requestedSize, const std::string& formatRaw, size_t maxChars, const std::string& label = "", const std::string& expression = "") {
    std::string format = toLowerCopy(formatRaw.empty() ? "hex" : formatRaw);
    std::vector<unsigned char> buffer;
    duint sizeRead = 0;
    std::string errorText;
    bool ok = readMemoryStable(addr, requestedSize, buffer, sizeRead, errorText);
    bool complete = ok && sizeRead == requestedSize;

    std::stringstream ss;
    ss << "{";
    ss << "\"ok\":" << (ok ? "true" : "false") << ",";
    ss << "\"addr\":\"0x" << std::hex << addr << "\",";
    ss << "\"sizeRequested\":" << std::dec << requestedSize << ",";
    ss << "\"sizeRead\":" << std::dec << sizeRead << ",";
    ss << "\"complete\":" << (complete ? "true" : "false") << ",";
    ss << "\"format\":\"" << escapeJsonString(format.c_str()) << "\"";
    if (!label.empty()) {
        ss << ",\"label\":\"" << escapeJsonString(label.c_str()) << "\"";
    }
    if (!expression.empty()) {
        ss << ",\"expression\":\"" << escapeJsonString(expression.c_str()) << "\"";
    }
    if (!errorText.empty()) {
        ss << ",\"error\":\"" << escapeJsonString(errorText.c_str()) << "\"";
    }

    const size_t available = (size_t)sizeRead;
    const auto* data = available > 0 ? buffer.data() : nullptr;
    ss << ",\"hex\":\"" << bytesToHex(data, available) << "\"";

    if (format == "bytes") {
        ss << ",\"bytes\":[";
        for (size_t i = 0; i < available; ++i) {
            if (i) ss << ",";
            ss << std::dec << (unsigned int)data[i];
        }
        ss << "]";
    } else if (format == "ascii" || format == "utf8") {
        std::string text = bytesToAscii(data, available, maxChars);
        ss << ",\"text\":\"" << escapeJsonString(text.c_str()) << "\"";
    } else if (format == "utf16") {
        std::string text = utf16leBytesToUtf8(data, available, maxChars);
        ss << ",\"text\":\"" << escapeJsonString(text.c_str()) << "\"";
    } else if (format == "u8" || format == "u16" || format == "u32" || format == "u64") {
        size_t width = format == "u8" ? 1 : format == "u16" ? 2 : format == "u32" ? 4 : 8;
        unsigned long long value = 0;
        size_t limit = available < width ? available : width;
        for (size_t i = 0; i < limit; ++i) {
            value |= (unsigned long long)data[i] << (8 * i);
        }
        ss << ",\"value\":\"0x" << std::hex << value << "\"";
        ss << ",\"valueDecimal\":\"" << std::dec << value << "\"";
    }

    ss << "}";
    return ss.str();
}

static std::string buildEvalEntryJson(const std::string& expression) {
    std::string expr = expression;
    trimParam(expr);
    duint value = 0;
    bool success = !expr.empty() && parseFlexibleDuint(expr, value);

    char labelText[1024] = {};
    char commentText[1024] = {};
    bool hasLabel = success && DbgGetLabelAt(value, SEG_DEFAULT, labelText);
    bool hasComment = success && DbgGetCommentAt(value, commentText);

    std::stringstream ss;
    ss << "{";
    ss << "\"expression\":\"" << escapeJsonString(expr.c_str()) << "\",";
    ss << "\"success\":" << (success ? "true" : "false");
    if (success) {
        ss << ",\"value\":\"0x" << std::hex << value << "\"";
        ss << ",\"valueDecimal\":\"" << std::dec << DUINT_CAST_PRINTF(value) << "\"";
        ss << ",\"isValidPtr\":" << (DbgMemIsValidReadPtr(value) ? "true" : "false");
        if (hasLabel) {
            ss << ",\"label\":\"" << escapeJsonString(safeString(labelText).c_str()) << "\"";
        }
        if (hasComment) {
            ss << ",\"comment\":\"" << escapeJsonString(safeString(commentText).c_str()) << "\"";
        }
    }
    ss << "}";
    return ss.str();
}

static bool parseCaptureRangeSpec(const std::string& rawLine, CaptureRangeSpec& spec, std::string& errorText) {
    std::vector<std::string> parts;
    std::stringstream ss(rawLine);
    std::string part;
    while (std::getline(ss, part, '|')) {
        trimParam(part);
        parts.push_back(part);
    }
    if (parts.size() < 4) {
        errorText = "Capture range spec must be label|expr|size|format";
        return false;
    }

    spec.label = parts[0];
    spec.expression = parts[1];
    spec.format = parts[3].empty() ? "hex" : parts[3];
    if (spec.label.empty()) {
        spec.label = spec.expression;
    }

    duint parsedSize = 0;
    if (!parseCountValue(parts[2], parsedSize)) {
        errorText = "Invalid capture size: " + parts[2];
        return false;
    }
    spec.size = parsedSize;
    return true;
}

static std::string buildEvalBatchJson(const std::string& expressionsRaw) {
    auto expressions = splitRequestItems(expressionsRaw, false);
    std::stringstream ss;
    ss << "{";
    ss << "\"ok\":true,";
    ss << "\"count\":" << std::dec << expressions.size() << ",";
    ss << "\"items\":[";
    bool first = true;
    for (const auto& expr : expressions) {
        if (!first) ss << ",";
        first = false;
        ss << buildEvalEntryJson(expr);
    }
    ss << "]";
    ss << "}";
    return ss.str();
}

static std::string buildContextCaptureJson(const std::string& registersRaw,
                                           const std::string& expressionsRaw,
                                           const std::string& rangesRaw,
                                           const std::string& stackSlotsRaw,
                                           const std::string& baseExprRaw,
                                           bool frameMode) {
    auto registers = splitRequestItems(registersRaw, true);
    auto expressions = splitRequestItems(expressionsRaw, false);
    auto rangeSpecs = splitRequestItems(rangesRaw, false);
    auto stackSpecs = splitRequestItems(stackSlotsRaw, false);

    std::string baseExpr = urlDecode(baseExprRaw);
    trimParam(baseExpr);
    if (baseExpr.empty()) {
#ifdef _WIN64
        baseExpr = "rbp";
#else
        baseExpr = "ebp";
#endif
    }

    std::stringstream ss;
    ss << "{";
    ss << "\"ok\":true,";
    ss << "\"capturedAtMs\":" << std::dec << nowTickMs() << ",";
    ss << "\"state\":" << buildDebugSessionJson(false, 0) << ",";
    if (frameMode) {
        ss << "\"frameBase\":" << buildEvalEntryJson(baseExpr) << ",";
    }
    ss << "\"registers\":{";
    bool firstRegister = true;
    for (const auto& reg : registers) {
        if (!firstRegister) ss << ",";
        firstRegister = false;
        ss << "\"" << escapeJsonString(reg.c_str()) << "\":" << buildEvalEntryJson(reg);
    }
    ss << "},";
    ss << "\"expressions\":[";
    bool firstExpr = true;
    for (const auto& expr : expressions) {
        if (!firstExpr) ss << ",";
        firstExpr = false;
        ss << buildEvalEntryJson(expr);
    }
    ss << "],";

    const auto appendRanges = [&](const std::vector<std::string>& specs, const char* fieldName) {
        ss << "\"" << fieldName << "\":[";
        bool firstItem = true;
        for (const auto& rawLine : specs) {
            CaptureRangeSpec spec;
            std::string parseError;
            if (!parseCaptureRangeSpec(rawLine, spec, parseError)) {
                if (!firstItem) ss << ",";
                firstItem = false;
                ss << "{";
                ss << "\"ok\":false,";
                ss << "\"error\":\"" << escapeJsonString(parseError.c_str()) << "\",";
                ss << "\"spec\":\"" << escapeJsonString(rawLine.c_str()) << "\"";
                ss << "}";
                continue;
            }

            duint addr = 0;
            if (!parseFlexibleDuint(spec.expression, addr)) {
                if (!firstItem) ss << ",";
                firstItem = false;
                ss << "{";
                ss << "\"ok\":false,";
                ss << "\"label\":\"" << escapeJsonString(spec.label.c_str()) << "\",";
                ss << "\"expression\":\"" << escapeJsonString(spec.expression.c_str()) << "\",";
                ss << "\"error\":\"Failed to evaluate address expression\"";
                ss << "}";
                continue;
            }

            if (!firstItem) ss << ",";
            firstItem = false;
            ss << buildMemoryReadRangeJson(addr, spec.size, spec.format, 1024, spec.label, spec.expression);
        }
        ss << "]";
    };

    appendRanges(rangeSpecs, "ranges");
    ss << ",";
    appendRanges(stackSpecs, "stackSlots");
    ss << "}";
    return ss.str();
}

static void trimHistoryUnlocked(DebugSessionState& state) {
    constexpr size_t kMaxHistory = 64;
    while (state.history.size() > kMaxHistory) {
        state.history.pop_front();
    }
}

static std::string childBrokerEnvironmentValue(const wchar_t* name)
{
    if(!name || !*name)
        return {};
    std::vector<wchar_t> buffer(256, L'\0');
    while(buffer.size() <= 32768u)
    {
        const DWORD length = GetEnvironmentVariableW(
            name, buffer.data(), static_cast<DWORD>(buffer.size()));
        if(length == 0)
            return {};
        if(length < buffer.size() - 1u)
            return wideToUtf8(std::wstring(buffer.data(), length));
        buffer.resize(buffer.size() * 2u, L'\0');
    }
    return {};
}

static bool childBrokerAutoEntryFromEnvironment()
{
    const std::string value = childBrokerEnvironmentValue(L"X64DBG_MCP_BROKER_AUTO_ENTRY");
    return value == "1" || value == "true" || value == "TRUE";
}

static const char* exceptionActionName(ExceptionPolicyAction action) {
    return mcpexception::actionName(action);
}

static const char* exceptionChanceName(ExceptionPolicyChance chance) {
    return mcpexception::chanceName(chance);
}

static unsigned int popcount32(DWORD value) {
    unsigned int count = 0;
    while (value) {
        value &= value - 1;
        ++count;
    }
    return count;
}

static bool exceptionSelectorMatches(const ExceptionCodeSelector& selector, DWORD code) {
    switch (selector.kind) {
    case ExceptionSelectorKind::Exact:
        return code == selector.value;
    case ExceptionSelectorKind::Masked:
        return (code & selector.mask) == (selector.value & selector.mask);
    case ExceptionSelectorKind::Wildcard:
    default:
        return true;
    }
}

struct ExceptionPolicyDecision
{
    ExceptionPolicyAction action = ExceptionPolicyAction::Pause;
    std::string source = "default";
    std::string ruleId;
    std::string matchedSelector;
};

static ExceptionPolicyDecision selectExceptionPolicyUnlocked(
        const DebugSessionState& state, DWORD code, bool firstChance) {
    const auto selected = mcpexception::selectPolicy(
        state.exceptionPolicy, static_cast<uint32_t>(code), firstChance);
    ExceptionPolicyDecision decision;
    decision.action = selected.action;
    decision.source = selected.source;
    decision.ruleId = selected.ruleId;
    decision.matchedSelector = selected.matchedSelector;
    return decision;
}

static void trimExceptionHistoryUnlocked(DebugSessionState& state) {
    state.exceptionHistoryDropped += mcpexception::trimBoundedHistory(
        state.exceptionHistory);
}

static ExceptionHistoryRecord* findExceptionHistoryBySeqUnlocked(
        DebugSessionState& state, uint64_t historySeq) {
    for (auto& record : state.exceptionHistory) {
        if (record.seq == historySeq) return &record;
    }
    return nullptr;
}

static ExceptionHistoryRecord* findExceptionHistoryByEventUnlocked(
        DebugSessionState& state, uint64_t eventSeq) {
    for (auto it = state.exceptionHistory.rbegin(); it != state.exceptionHistory.rend(); ++it) {
        if (it->eventSeq == eventSeq) return &*it;
    }
    return nullptr;
}

static void syncRuntimeStateUnlocked(DebugSessionState& state) {
    state.debugging = DbgIsDebugging();
    state.running = state.debugging && DbgIsRunning();
    state.paused = state.debugging && !state.running;
    if (!state.debugging) {
        state.processId = 0;
        state.threadId = 0;
        if (!state.exited) {
            state.state = "not_debugging";
        }
        return;
    }

    state.processId = DbgGetProcessId();
    state.threadId = DbgGetThreadId();
    state.state = state.running ? "running" : "paused";
}

template <typename Fn>
static void mutateDebugSession(const char* eventType, Fn&& fn,
                               PendingExceptionAutoContinuation* autoContinuation = nullptr) {
    std::unique_lock<std::mutex> lock(g_debugSession.mutex);
    syncRuntimeStateUnlocked(g_debugSession);
    fn(g_debugSession);

    if (!g_debugSession.debugging && !g_debugSession.exited) {
        g_debugSession.state = "not_debugging";
    } else if (g_debugSession.exited) {
        g_debugSession.state = "exited";
    } else if (g_debugSession.running) {
        g_debugSession.state = "running";
    } else {
        g_debugSession.state = "paused";
    }

    g_debugSession.lastEventType = eventType ? eventType : "unknown";
    g_debugSession.lastUpdateMs = nowTickMs();
    g_debugSession.eventSeq++;
    if (eventType && strcmp(eventType, "exception") == 0) {
        g_debugSession.exceptionPending = true;
        g_debugSession.exceptionContinuationClaimed = false;
        g_debugSession.exceptionEventSeq = g_debugSession.eventSeq;
        g_debugSession.exceptionDisposition = "default";

        const ExceptionPolicyDecision decision = selectExceptionPolicyUnlocked(
            g_debugSession, g_debugSession.exceptionCode,
            g_debugSession.exceptionFirstChance);
        ExceptionHistoryRecord exceptionRecord;
        exceptionRecord.seq = g_debugSession.exceptionHistoryNextSeq++;
        exceptionRecord.eventSeq = g_debugSession.eventSeq;
        exceptionRecord.sessionGeneration = g_debugSession.generation;
        exceptionRecord.policyVersion = g_debugSession.exceptionPolicy.version;
        exceptionRecord.tickMs = g_debugSession.lastUpdateMs;
        exceptionRecord.lastUpdateMs = exceptionRecord.tickMs;
        exceptionRecord.timestamp100ns = nowTimestamp100ns();
        exceptionRecord.lastUpdateTimestamp100ns = exceptionRecord.timestamp100ns;
        exceptionRecord.bridgeInstanceId = g_bridgeInstanceId;
        exceptionRecord.sessionId = g_debugSession.sessionId;
        exceptionRecord.processId = g_debugSession.processId;
        exceptionRecord.threadId = g_debugSession.threadId;
        exceptionRecord.exceptionCode = g_debugSession.exceptionCode;
        exceptionRecord.firstChance = g_debugSession.exceptionFirstChance;
        exceptionRecord.address = g_debugSession.lastAddress;
        exceptionRecord.ip = g_debugSession.lastIp;
        exceptionRecord.action = exceptionActionName(decision.action);
        exceptionRecord.source = decision.source;
        exceptionRecord.ruleId = decision.ruleId;
        exceptionRecord.matchedSelector = decision.matchedSelector;

        if (decision.action != ExceptionPolicyAction::Pause) {
            // Claim the event while holding the session lock. Manual
            // ContinueException can therefore never race an automatic policy
            // continuation for the same debug event.
            g_debugSession.exceptionContinuationClaimed = true;
            g_debugSession.exceptionDisposition = exceptionActionName(decision.action);
            mcpexception::initializeAutomaticContinuation(
                exceptionRecord.continuation, decision.action);
            if (autoContinuation) {
                autoContinuation->requested = true;
                autoContinuation->command = exceptionRecord.continuation.command;
                autoContinuation->action = exceptionRecord.action;
                autoContinuation->historySeq = exceptionRecord.seq;
                autoContinuation->eventSeq = exceptionRecord.eventSeq;
                autoContinuation->sessionGeneration = g_debugSession.generation;
                autoContinuation->sessionId = g_debugSession.sessionId;
            }
        }
        g_debugSession.exceptionHistory.push_back(std::move(exceptionRecord));
        trimExceptionHistoryUnlocked(g_debugSession);
    }

    SessionEventRecord record;
    record.seq = g_debugSession.eventSeq;
    record.sessionGeneration = g_debugSession.generation;
    record.tickMs = g_debugSession.lastUpdateMs;
    record.sessionId = g_debugSession.sessionId;
    record.type = g_debugSession.lastEventType;
    record.state = g_debugSession.state;
    record.stopReason = g_debugSession.stopReason;
    record.processId = g_debugSession.processId;
    record.threadId = g_debugSession.threadId;
    record.ip = g_debugSession.lastIp;
    record.address = g_debugSession.lastAddress;
    record.exceptionCode = g_debugSession.exceptionCode;
    record.firstChance = g_debugSession.exceptionFirstChance;
    record.exitCode = g_debugSession.exitCode;
    record.imagePath = g_debugSession.imagePath;
    record.breakpointName = g_debugSession.breakpointName;
    record.breakpointModule = g_debugSession.breakpointModule;
    record.note = g_debugSession.note;
    g_debugSession.history.push_back(std::move(record));
    trimHistoryUnlocked(g_debugSession);
    lock.unlock();
    g_debugSession.cv.notify_all();
}

static void resetDebugSessionStateUnlocked(DebugSessionState& state) {
    state.initialized = false;
    state.debugging = false;
    state.running = false;
    state.paused = false;
    state.stopping = false;
    state.exited = false;
    state.processId = 0;
    state.threadId = 0;
    state.exitCode = 0;
    state.exceptionCode = 0;
    state.exceptionFirstChance = false;
    state.exceptionPending = false;
    state.exceptionContinuationClaimed = false;
    state.exceptionEventSeq = 0;
    state.exceptionDisposition = "default";
    state.lastIp = 0;
    state.lastAddress = 0;
    state.imagePath.clear();
    state.imageSha256.clear();
    state.imageSize = 0;
    state.imageVolumeSerialNumber = 0;
    state.imageFileId.clear();
    state.stopReason.clear();
    state.breakpointName.clear();
    state.breakpointModule.clear();
    state.note.clear();
    state.exceptionPolicy = ExceptionPolicyState{};
    state.exceptionHistoryNextSeq = 1;
    state.exceptionHistoryDropped = 0;
    state.exceptionHistory.clear();
}

static bool isAbsoluteRegularFilePathW(const std::wstring& path) {
    if (path.empty()) return false;
    std::wstring lower = path;
    std::transform(lower.begin(), lower.end(), lower.begin(), ::towlower);
    // Never let a dump request target a device object.  The bridge only needs
    // ordinary drive/UNC paths and writes attacker-controlled binary data.
    if (lower.rfind(L"\\\\.\\", 0) == 0
        || lower.rfind(L"\\\\?\\globalroot", 0) == 0) {
        return false;
    }
    const bool driveAbsolute = path.size() >= 3
        && iswalpha(path[0])
        && path[1] == L':'
        && (path[2] == L'\\' || path[2] == L'/');
    const bool uncAbsolute = path.size() >= 3
        && (path[0] == L'\\' || path[0] == L'/')
        && (path[1] == L'\\' || path[1] == L'/');
    return driveAbsolute || uncAbsolute;
}

static bool directoryExistsW(const std::wstring& path) {
    if (path.empty()) return false;
    const DWORD attributes = GetFileAttributesW(path.c_str());
    return attributes != INVALID_FILE_ATTRIBUTES && (attributes & FILE_ATTRIBUTE_DIRECTORY) != 0;
}

static void beginDebugSessionUnlocked(DebugSessionState& state) {
    resetDebugSessionStateUnlocked(state);
    clearMutationLease();
    state.generation++;
    state.sessionId = mcpbridge::createGuidString();
    state.sessionStartTickMs = nowTickMs();
}

static void finalizePendingExceptionResumeUnlocked(DebugSessionState& state) {
    if (!state.exceptionPending || !state.exceptionContinuationClaimed) return;
    ExceptionHistoryRecord* record = findExceptionHistoryByEventUnlocked(
        state, state.exceptionEventSeq);
    if (!record || !record->continuation.autoContinue) return;
    mcpexception::markAutomaticResume(record->continuation);
    record->lastUpdateMs = nowTickMs();
    record->lastUpdateTimestamp100ns = nowTimestamp100ns();
}

static void clearPendingExceptionUnlocked(DebugSessionState& state) {
    if (state.exceptionPending && state.exceptionContinuationClaimed) {
        ExceptionHistoryRecord* record = findExceptionHistoryByEventUnlocked(
            state, state.exceptionEventSeq);
        if (record && record->continuation.appliedDisposition == "pending") {
            mcpexception::markAbandoned(record->continuation);
            record->lastUpdateMs = nowTickMs();
            record->lastUpdateTimestamp100ns = nowTimestamp100ns();
        }
    }
    state.exceptionCode = 0;
    state.exceptionFirstChance = false;
    state.exceptionPending = false;
    state.exceptionContinuationClaimed = false;
    state.exceptionEventSeq = 0;
    state.exceptionDisposition = "default";
}

static std::string buildSessionHistoryJsonUnlocked(const DebugSessionState& state, size_t historyLimit) {
    std::stringstream ss;
    ss << "[";
    size_t total = state.history.size();
    size_t start = 0;
    if (historyLimit > 0 && total > historyLimit) {
        start = total - historyLimit;
    }
    bool first = true;
    for (size_t i = start; i < total; ++i) {
        const auto& record = state.history[i];
        if (!first) {
            ss << ",";
        }
        first = false;
        ss << "{";
        ss << "\"seq\":" << std::dec << record.seq << ",";
        ss << "\"sessionGeneration\":" << std::dec << record.sessionGeneration << ",";
        ss << "\"sessionId\":\"" << escapeJsonString(record.sessionId.c_str()) << "\",";
        ss << "\"tickMs\":" << std::dec << record.tickMs << ",";
        ss << "\"type\":\"" << escapeJsonString(record.type.c_str()) << "\",";
        ss << "\"state\":\"" << escapeJsonString(record.state.c_str()) << "\",";
        ss << "\"stopReason\":\"" << escapeJsonString(record.stopReason.c_str()) << "\",";
        ss << "\"processId\":" << std::dec << record.processId << ",";
        ss << "\"threadId\":" << std::dec << record.threadId << ",";
        ss << "\"ip\":\"0x" << std::hex << record.ip << "\",";
        ss << "\"address\":\"0x" << std::hex << record.address << "\",";
        ss << "\"exceptionCode\":\"0x" << std::hex << record.exceptionCode << "\",";
        ss << "\"firstChance\":" << (record.firstChance ? "true" : "false") << ",";
        ss << "\"exitCode\":" << std::dec << record.exitCode << ",";
        ss << "\"imagePath\":\"" << escapeJsonString(record.imagePath.c_str()) << "\",";
        ss << "\"breakpointName\":\"" << escapeJsonString(record.breakpointName.c_str()) << "\",";
        ss << "\"breakpointModule\":\"" << escapeJsonString(record.breakpointModule.c_str()) << "\",";
        ss << "\"note\":\"" << escapeJsonString(record.note.c_str()) << "\"";
        ss << "}";
    }
    ss << "]";
    return ss.str();
}

static std::string buildDebugSessionJsonUnlocked(const DebugSessionState& state, bool includeHistory, size_t historyLimit) {
    std::stringstream ss;
    ss << "{";
    ss << "\"eventSeq\":" << std::dec << state.eventSeq << ",";
    ss << "\"generation\":" << std::dec << state.generation << ",";
    ss << "\"sessionId\":\"" << escapeJsonString(state.sessionId.c_str()) << "\",";
    ss << "\"sessionStartTickMs\":" << std::dec << state.sessionStartTickMs << ",";
    ss << "\"lastUpdateMs\":" << std::dec << state.lastUpdateMs << ",";
    ss << "\"initialized\":" << (state.initialized ? "true" : "false") << ",";
    ss << "\"debugging\":" << (state.debugging ? "true" : "false") << ",";
    ss << "\"running\":" << (state.running ? "true" : "false") << ",";
    ss << "\"paused\":" << (state.paused ? "true" : "false") << ",";
    ss << "\"stopping\":" << (state.stopping ? "true" : "false") << ",";
    ss << "\"exited\":" << (state.exited ? "true" : "false") << ",";
    ss << "\"processId\":" << std::dec << state.processId << ",";
    ss << "\"threadId\":" << std::dec << state.threadId << ",";
    ss << "\"exitCode\":" << std::dec << state.exitCode << ",";
    ss << "\"exceptionCode\":\"0x" << std::hex << state.exceptionCode << "\",";
    ss << "\"exceptionFirstChance\":" << (state.exceptionFirstChance ? "true" : "false") << ",";
    ss << "\"exceptionPending\":" << (state.exceptionPending ? "true" : "false") << ",";
    ss << "\"exceptionContinuationClaimed\":" << (state.exceptionContinuationClaimed ? "true" : "false") << ",";
    ss << "\"exceptionEventSeq\":" << std::dec << state.exceptionEventSeq << ",";
    ss << "\"exceptionDisposition\":\"" << escapeJsonString(state.exceptionDisposition.c_str()) << "\",";
    ss << "\"ip\":\"0x" << std::hex << state.lastIp << "\",";
    ss << "\"address\":\"0x" << std::hex << state.lastAddress << "\",";
    ss << "\"state\":\"" << escapeJsonString(state.state.c_str()) << "\",";
    ss << "\"lastEventType\":\"" << escapeJsonString(state.lastEventType.c_str()) << "\",";
    ss << "\"stopReason\":\"" << escapeJsonString(state.stopReason.c_str()) << "\",";
    ss << "\"imagePath\":\"" << escapeJsonString(state.imagePath.c_str()) << "\",";
    ss << "\"imageSha256\":\"" << escapeJsonString(state.imageSha256.c_str()) << "\",";
    ss << "\"imageSize\":" << std::dec << state.imageSize << ",";
    ss << "\"imageVolumeSerialNumber\":" << std::dec << state.imageVolumeSerialNumber << ",";
    ss << "\"imageFileId\":\"" << escapeJsonString(state.imageFileId.c_str()) << "\",";
    ss << "\"breakpointName\":\"" << escapeJsonString(state.breakpointName.c_str()) << "\",";
    ss << "\"breakpointModule\":\"" << escapeJsonString(state.breakpointModule.c_str()) << "\",";
    ss << "\"note\":\"" << escapeJsonString(state.note.c_str()) << "\"";
    if (includeHistory) {
        ss << ",\"history\":" << buildSessionHistoryJsonUnlocked(state, historyLimit);
    }
    ss << "}";
    return ss.str();
}

std::string buildDebugSessionJson(bool includeHistory, size_t historyLimit) {
    std::lock_guard<std::mutex> lock(g_debugSession.mutex);
    syncRuntimeStateUnlocked(g_debugSession);
    if (!g_debugSession.debugging && !g_debugSession.exited) {
        g_debugSession.state = "not_debugging";
    } else if (g_debugSession.exited) {
        g_debugSession.state = "exited";
    } else if (g_debugSession.running) {
        g_debugSession.state = "running";
    } else {
        g_debugSession.state = "paused";
    }
    return buildDebugSessionJsonUnlocked(g_debugSession, includeHistory, historyLimit);
}

static bool parseStrictBool(const std::string& raw, bool& value) {
    std::string normalized = toLowerCopy(raw);
    trimParam(normalized);
    if (normalized == "true" || normalized == "1") {
        value = true;
        return true;
    }
    if (normalized == "false" || normalized == "0") {
        value = false;
        return true;
    }
    return false;
}

static bool parseExceptionAction(const std::string& raw, ExceptionPolicyAction& action) {
    std::string normalized = toLowerCopy(raw);
    trimParam(normalized);
    if (normalized == "pause") action = ExceptionPolicyAction::Pause;
    else if (normalized == "handled") action = ExceptionPolicyAction::Handled;
    else if (normalized == "not_handled") action = ExceptionPolicyAction::NotHandled;
    else return false;
    return true;
}

static bool parseExceptionChance(const std::string& raw, ExceptionPolicyChance& chance) {
    std::string normalized = toLowerCopy(raw);
    trimParam(normalized);
    if (normalized == "any") chance = ExceptionPolicyChance::Any;
    else if (normalized == "first") chance = ExceptionPolicyChance::First;
    else if (normalized == "second") chance = ExceptionPolicyChance::Second;
    else return false;
    return true;
}

static bool parseExceptionU32(const std::string& raw, uint32_t& value) {
    std::string text = raw;
    trimParam(text);
    if (text.empty() || text[0] == '+' || text[0] == '-') return false;
    int base = 10;
    const char* begin = text.c_str();
    if (text.size() > 2 && text[0] == '0'
        && (text[1] == 'x' || text[1] == 'X')) {
        begin += 2;
        base = 16;
        if (!*begin) return false;
    }
    errno = 0;
    char* end = nullptr;
    const unsigned long long parsed = std::strtoull(begin, &end, base);
    if (errno == ERANGE || end == begin || !end || *end != '\0'
        || parsed > std::numeric_limits<uint32_t>::max()) return false;
    value = static_cast<uint32_t>(parsed);
    return true;
}

static bool parseStrictPriority(const std::string& raw, int& priority) {
    std::string text = raw;
    trimParam(text);
    if (text.empty()) return false;
    errno = 0;
    char* end = nullptr;
    const long long parsed = std::strtoll(text.c_str(), &end, 10);
    if (errno == ERANGE || end == text.c_str() || !end || *end != '\0'
        || parsed < -100000 || parsed > 100000) return false;
    priority = static_cast<int>(parsed);
    return true;
}

static bool isValidExceptionRuleId(const std::string& ruleId) {
    if (ruleId.empty() || ruleId.size() > 64) return false;
    return std::all_of(ruleId.begin(), ruleId.end(), [](unsigned char ch) {
        return std::isalnum(ch) || ch == '_' || ch == '-' || ch == '.' || ch == ':';
    });
}

static std::string canonicalExceptionCode(uint32_t value) {
    std::stringstream ss;
    ss << "0x" << std::hex << std::setfill('0') << std::setw(8) << value;
    return ss.str();
}

static bool parseExceptionSelectors(const std::string& raw,
                                    std::vector<ExceptionCodeSelector>& selectors,
                                    std::string& error) {
    selectors.clear();
    size_t start = 0;
    while (start <= raw.size()) {
        const size_t comma = raw.find(',', start);
        std::string token = raw.substr(start,
            comma == std::string::npos ? std::string::npos : comma - start);
        trimParam(token);
        if (token.empty()) {
            error = "exception selector list contains an empty item";
            return false;
        }
        ExceptionCodeSelector selector;
        if (token == "*") {
            selector.kind = ExceptionSelectorKind::Wildcard;
            selector.canonical = "*";
        } else {
            const size_t slash = token.find('/');
            if (slash == std::string::npos) {
                if (!parseExceptionU32(token, selector.value)) {
                    error = "invalid exact exception code: " + token;
                    return false;
                }
                selector.kind = ExceptionSelectorKind::Exact;
                selector.mask = std::numeric_limits<DWORD>::max();
                selector.maskBits = 32;
                selector.canonical = canonicalExceptionCode(selector.value);
            } else {
                if (token.find('/', slash + 1) != std::string::npos) {
                    error = "masked exception selector has more than one slash: " + token;
                    return false;
                }
                const std::string valueText = token.substr(0, slash);
                const std::string maskText = token.substr(slash + 1);
                if (!parseExceptionU32(valueText, selector.value)
                    || !parseExceptionU32(maskText, selector.mask)
                    || selector.mask == 0) {
                    error = "masked exception selector requires valid 32-bit value/non-zero mask: " + token;
                    return false;
                }
                selector.kind = ExceptionSelectorKind::Masked;
                selector.maskBits = popcount32(selector.mask);
                selector.value &= selector.mask;
                selector.canonical = canonicalExceptionCode(selector.value)
                    + "/" + canonicalExceptionCode(selector.mask);
            }
        }
        selectors.push_back(std::move(selector));
        if (selectors.size() > 32) {
            error = "a rule may contain at most 32 exception selectors";
            return false;
        }
        if (comma == std::string::npos) break;
        start = comma + 1;
    }
    return !selectors.empty();
}

using ParsedExceptionPolicyUpdate = mcpexception::ParsedUpdate;

static bool parseExceptionPolicyUpdate(
        const std::unordered_map<std::string, std::string>& params,
        ParsedExceptionPolicyUpdate& update, std::string& error) {
    return mcpexception::parsePolicyUpdate(params, update, error);
#if 0
    auto read = [&](const std::string& key) -> const std::string* {
        const auto found = params.find(key);
        return found == params.end() ? nullptr : &found->second;
    };
    if (const std::string* value = read("replace")) {
        if (!parseStrictBool(*value, update.replace)) {
            error = "replace must be true/false or 1/0";
            return false;
        }
    }
    if (const std::string* value = read("enabled")) {
        update.hasEnabled = true;
        if (!parseStrictBool(*value, update.enabled)) {
            error = "enabled must be true/false or 1/0";
            return false;
        }
    }
    if (const std::string* value = read("firstChanceDefault")) {
        update.hasFirstDefault = true;
        if (!parseExceptionAction(*value, update.firstDefault)) {
            error = "firstChanceDefault must be pause, handled or not_handled";
            return false;
        }
    }
    if (const std::string* value = read("secondChanceDefault")) {
        update.hasSecondDefault = true;
        if (!parseExceptionAction(*value, update.secondDefault)) {
            error = "secondChanceDefault must be pause, handled or not_handled";
            return false;
        }
    }
    const std::string* countText = read("ruleCount");
    uint64_t ruleCount = 0;
    if (!countText || !mcpbridge::parseUnsignedDecimalExact(*countText, ruleCount)
        || ruleCount > 64) {
        error = "ruleCount is required and must be an integer from 0 through 64";
        return false;
    }

    std::unordered_set<std::string> incomingIds;
    size_t selectorCount = 0;
    for (uint64_t i = 0; i < ruleCount; ++i) {
        const std::string prefix = "rule" + std::to_string(i);
        const std::string* id = read(prefix + "Id");
        const std::string* codes = read(prefix + "Codes");
        const std::string* chance = read(prefix + "Chance");
        const std::string* action = read(prefix + "Action");
        if (!id || !codes || !chance || !action) {
            error = prefix + " requires Id, Codes, Chance and Action";
            return false;
        }
        ExceptionPolicyRule rule;
        rule.ruleId = *id;
        trimParam(rule.ruleId);
        if (!isValidExceptionRuleId(rule.ruleId)) {
            error = prefix + "Id must be 1-64 ASCII letters/digits or _-.:";
            return false;
        }
        const std::string normalizedRuleId = toLowerCopy(rule.ruleId);
        if (!incomingIds.insert(normalizedRuleId).second) {
            error = "duplicate exception ruleId: " + rule.ruleId;
            return false;
        }
        if (!parseExceptionSelectors(*codes, rule.selectors, error)) {
            error = prefix + "Codes: " + error;
            return false;
        }
        selectorCount += rule.selectors.size();
        if (selectorCount > 512) {
            error = "the policy may contain at most 512 selectors";
            return false;
        }
        if (!parseExceptionChance(*chance, rule.chance)) {
            error = prefix + "Chance must be first, second or any";
            return false;
        }
        if (!parseExceptionAction(*action, rule.action)) {
            error = prefix + "Action must be pause, handled or not_handled";
            return false;
        }
        if (const std::string* priority = read(prefix + "Priority")) {
            if (!parseStrictPriority(*priority, rule.priority)) {
                error = prefix + "Priority must be an integer from -100000 through 100000";
                return false;
            }
        }
        if (const std::string* enabled = read(prefix + "Enabled")) {
            if (!parseStrictBool(*enabled, rule.enabled)) {
                error = prefix + "Enabled must be true/false or 1/0";
                return false;
            }
        }
        update.rules.push_back(std::move(rule));
    }
    return true;
#endif
}

static void appendExceptionPolicyJsonUnlocked(std::stringstream& ss,
                                               const DebugSessionState& state) {
    const auto& policy = state.exceptionPolicy;
    ss << "{";
    ss << "\"enabled\":" << (policy.enabled ? "true" : "false") << ",";
    ss << "\"version\":" << policy.version << ",";
    ss << "\"revision\":" << policy.version << ",";
    ss << "\"firstChanceDefault\":\"" << exceptionActionName(policy.firstChanceDefault) << "\",";
    ss << "\"secondChanceDefault\":\"" << exceptionActionName(policy.secondChanceDefault) << "\",";
    ss << "\"ruleCount\":" << policy.rules.size() << ",\"rules\":[";
    for (size_t i = 0; i < policy.rules.size(); ++i) {
        const auto& rule = policy.rules[i];
        if (i) ss << ",";
        ss << "{";
        ss << "\"ruleId\":\"" << escapeJsonString(rule.ruleId.c_str()) << "\",";
        ss << "\"codes\":[";
        for (size_t j = 0; j < rule.selectors.size(); ++j) {
            if (j) ss << ",";
            ss << "\"" << escapeJsonString(rule.selectors[j].canonical.c_str()) << "\"";
        }
        ss << "],\"chance\":\"" << exceptionChanceName(rule.chance) << "\",";
        ss << "\"action\":\"" << exceptionActionName(rule.action) << "\",";
        ss << "\"priority\":" << rule.priority << ",";
        ss << "\"enabled\":" << (rule.enabled ? "true" : "false") << ",";
        ss << "\"insertionOrder\":" << rule.insertionOrder << "}";
    }
    ss << "],\"sessionScoped\":true}";
}

static void appendExceptionMetaUnlocked(std::stringstream& ss,
                                        const DebugSessionState& state) {
    ss << "{\"bridgeInstanceId\":\"" << escapeJsonString(g_bridgeInstanceId.c_str()) << "\",";
    ss << "\"sessionId\":\"" << escapeJsonString(state.sessionId.c_str()) << "\",";
    ss << "\"sessionGeneration\":" << state.generation << ",";
    ss << "\"processId\":" << state.processId << ",";
    ss << "\"eventSeq\":" << state.eventSeq << "}";
}

static std::string buildExceptionPolicyResponseUnlocked(const DebugSessionState& state) {
    std::stringstream ss;
    ss << "{\"ok\":true,\"data\":{\"policy\":";
    appendExceptionPolicyJsonUnlocked(ss, state);
    ss << "},\"meta\":";
    appendExceptionMetaUnlocked(ss, state);
    ss << "}";
    return ss.str();
}

static void appendExceptionHistoryRecordJson(std::stringstream& ss,
                                             const ExceptionHistoryRecord& record) {
    ss << "{";
    ss << "\"historySeq\":" << record.seq << ",\"seq\":" << record.seq
       << ",\"eventSeq\":" << record.eventSeq << ",";
    ss << "\"sessionGeneration\":" << record.sessionGeneration << ",";
    ss << "\"policyVersion\":" << record.policyVersion << ",";
    ss << "\"tickMs\":" << record.tickMs << ",\"lastUpdateMs\":" << record.lastUpdateMs << ",";
    ss << "\"timestamp100ns\":" << record.timestamp100ns
       << ",\"lastUpdateTimestamp100ns\":" << record.lastUpdateTimestamp100ns << ",";
    ss << "\"bridgeInstanceId\":\"" << escapeJsonString(record.bridgeInstanceId.c_str()) << "\",";
    ss << "\"sessionId\":\"" << escapeJsonString(record.sessionId.c_str()) << "\",";
    ss << "\"processId\":" << record.processId << ",\"threadId\":" << record.threadId << ",";
    ss << "\"exceptionCode\":\"" << canonicalExceptionCode(record.exceptionCode) << "\",";
    ss << "\"chance\":\"" << (record.firstChance ? "first" : "second") << "\",";
    ss << "\"firstChance\":" << (record.firstChance ? "true" : "false") << ",";
    ss << "\"address\":\"0x" << std::hex << record.address << "\",";
    ss << "\"ip\":\"0x" << std::hex << record.ip << "\"," << std::dec;
    ss << "\"action\":\"" << escapeJsonString(record.action.c_str()) << "\",";
    ss << "\"source\":\"" << escapeJsonString(record.source.c_str()) << "\",";
    ss << "\"ruleId\":\"" << escapeJsonString(record.ruleId.c_str()) << "\",";
    ss << "\"matchedSelector\":\"" << escapeJsonString(record.matchedSelector.c_str()) << "\",";
    const auto& continuation = record.continuation;
    ss << "\"autoContinue\":" << (continuation.autoContinue ? "true" : "false") << ",";
    ss << "\"continuationClaimed\":" << (continuation.claimed ? "true" : "false") << ",";
    ss << "\"commandSubmitted\":" << (continuation.commandSubmitted ? "true" : "false") << ",";
    ss << "\"dispositionSubmitted\":" << (continuation.dispositionSubmitted ? "true" : "false") << ",";
    ss << "\"resumeRequested\":" << (continuation.resumeRequested ? "true" : "false") << ",";
    ss << "\"resumeSubmitted\":" << (continuation.resumeSubmitted ? "true" : "false") << ",";
    ss << "\"command\":\"" << escapeJsonString(continuation.command.c_str()) << "\",";
    ss << "\"status\":\"" << escapeJsonString(continuation.status.c_str()) << "\",";
    ss << "\"disposition\":\"" << escapeJsonString(continuation.disposition.c_str()) << "\",";
    ss << "\"requestedDisposition\":\"" << escapeJsonString(continuation.requestedDisposition.c_str()) << "\",";
    ss << "\"appliedDisposition\":\"" << escapeJsonString(continuation.appliedDisposition.c_str()) << "\",";
    ss << "\"outcome\":\"" << escapeJsonString(continuation.outcome.c_str()) << "\",";
    ss << "\"continuationSource\":\"" << escapeJsonString(continuation.source.c_str()) << "\"";
    ss << "}";
}

static std::string buildExceptionHistoryResponseUnlocked(
        const DebugSessionState& state, uint64_t afterSeq, size_t limit) {
    std::vector<uint64_t> retainedSequences;
    retainedSequences.reserve(state.exceptionHistory.size());
    for (const auto& record : state.exceptionHistory) {
        retainedSequences.push_back(record.seq);
    }
    const auto page = mcpexception::computeHistoryPage(
        retainedSequences, state.exceptionHistoryNextSeq,
        state.exceptionHistoryDropped, afterSeq, limit);
    size_t emitted = 0;
    std::stringstream ss;
    ss << "{\"ok\":true,\"data\":{\"records\":[";
    for (const auto& record : state.exceptionHistory) {
        if (record.seq <= afterSeq || emitted >= limit) continue;
        if (emitted++) ss << ",";
        appendExceptionHistoryRecordJson(ss, record);
    }
    ss << "],\"afterSeq\":" << afterSeq
       << ",\"nextAfterSeq\":" << page.nextAfterSeq
       << ",\"limit\":" << limit
       << ",\"returned\":" << page.returned
       << ",\"hasMore\":" << (page.hasMore ? "true" : "false")
       << ",\"oldestAvailableSeq\":" << page.oldestAvailableSeq
       << ",\"latestSeq\":" << page.latestSeq
       << ",\"dropped\":" << state.exceptionHistoryDropped
       << ",\"cursorTruncated\":" << (page.cursorTruncated ? "true" : "false")
       << ",\"cursorExclusive\":true"
       << ",\"retentionLimit\":" << mcpexception::kHistoryRetentionLimit
       << "},\"meta\":";
    appendExceptionMetaUnlocked(ss, state);
    ss << "}";
    return ss.str();
}

void finishNativeTrace(const char* reason) {
    std::lock_guard<std::mutex> lock(g_nativeTrace.mutex);
    if (!g_nativeTrace.active) {
        return;
    }
    g_nativeTrace.active = false;
    g_nativeTrace.completed = true;
    g_nativeTrace.lastTickMs = nowTickMs();
    g_nativeTrace.stopReason = safeString(reason);
    g_nativeTrace.cv.notify_all();
}

static bool nativeTraceMatchesCurrentSession(std::string& errorCode) {
    std::string traceSessionId;
    uint64_t traceGeneration = 0;
    DWORD traceProcessId = 0;
    {
        std::lock_guard<std::mutex> traceLock(g_nativeTrace.mutex);
        traceSessionId = g_nativeTrace.sessionId;
        traceGeneration = g_nativeTrace.sessionGeneration;
        traceProcessId = g_nativeTrace.processId;
    }
    {
        std::lock_guard<std::mutex> sessionLock(g_debugSession.mutex);
        if (g_debugSession.sessionId.empty()
            || traceSessionId.empty()
            || g_debugSession.sessionId != traceSessionId
            || g_debugSession.generation != traceGeneration
            || g_debugSession.processId != traceProcessId) {
            errorCode = "trace_session_mismatch";
            return false;
        }
    }
    return true;
}

static void recordNativeTraceStep(PLUG_CB_TRACEEXECUTE* info) {
    if (!info) {
        return;
    }
    bool requestStop = false;
    {
        std::lock_guard<std::mutex> lock(g_nativeTrace.mutex);
        if (!g_nativeTrace.active) {
            return;
        }
        const duint ip = info->cip;
        const ULONGLONG tick = nowTickMs();
        g_nativeTrace.totalSteps++;
        g_nativeTrace.lastTickMs = tick;
        bool inRange = true;
        if (g_nativeTrace.hasRange) {
            const duint delta = ip - g_nativeTrace.rangeStart;
            inRange = ip >= g_nativeTrace.rangeStart && delta < g_nativeTrace.rangeSize;
        }
        if (inRange) {
            g_nativeTrace.matchedSteps++;
            auto hit = g_nativeTrace.hits.find(ip);
            bool trackedHit = false;
            if (hit != g_nativeTrace.hits.end()) {
                hit->second++;
                trackedHit = true;
            } else if (g_nativeTrace.hits.size() < g_nativeTrace.maxUnique) {
                g_nativeTrace.hits.emplace(ip, 1);
                trackedHit = true;
            } else {
                g_nativeTrace.droppedUnique++;
            }
            if (trackedHit) {
                const auto currentHit = g_nativeTrace.hits.find(ip);
                if (currentHit != g_nativeTrace.hits.end()) {
                    NativeTraceHitUpdate update;
                    update.revision = ++g_nativeTrace.hitRevision;
                    update.ip = ip;
                    update.hits = currentHit->second;
                    if (g_nativeTrace.hitUpdates.size() >= NativeTraceState::kMaxHitUpdates) {
                        g_nativeTrace.hitUpdates.pop_front();
                        g_nativeTrace.droppedHitUpdates++;
                    }
                    g_nativeTrace.hitUpdates.push_back(update);
                }
            }
            if (g_nativeTrace.captureEvents) {
                if (g_nativeTrace.events.size() < g_nativeTrace.maxEvents) {
                    NativeTraceEvent event;
                    event.seq = g_nativeTrace.matchedSteps;
                    event.tickMs = tick;
                    event.threadId = DbgGetThreadId();
                    event.ip = ip;
                    if (g_nativeTrace.enrichEvents)
                        enrichNativeTraceEvent(event);
                    const auto pending =
                        g_nativeTrace.pendingExceptions.find(event.threadId);
                    if(pending != g_nativeTrace.pendingExceptions.end())
                    {
                        event.exceptionTransition = true;
                        event.exceptionCode = pending->second.code;
                        event.exceptionFirstChance =
                            pending->second.firstChance;
                        event.exceptionAddress = pending->second.address;
                        g_nativeTrace.pendingExceptions.erase(pending);
                    }
                    g_nativeTrace.events.push_back(event);
                } else if (!g_nativeTrace.stopOnLimit && g_nativeTrace.maxEvents > 0) {
                    NativeTraceEvent event;
                    event.seq = g_nativeTrace.matchedSteps;
                    event.tickMs = tick;
                    event.threadId = DbgGetThreadId();
                    event.ip = ip;
                    if (g_nativeTrace.enrichEvents)
                        enrichNativeTraceEvent(event);
                    const auto pending =
                        g_nativeTrace.pendingExceptions.find(event.threadId);
                    if(pending != g_nativeTrace.pendingExceptions.end())
                    {
                        event.exceptionTransition = true;
                        event.exceptionCode = pending->second.code;
                        event.exceptionFirstChance =
                            pending->second.firstChance;
                        event.exceptionAddress = pending->second.address;
                        g_nativeTrace.pendingExceptions.erase(pending);
                    }
                    g_nativeTrace.events.pop_front();
                    g_nativeTrace.events.push_back(event);
                    g_nativeTrace.droppedEvents++;
                } else {
                    g_nativeTrace.droppedEvents++;
                }
            }
        }

        const bool stepLimit = g_nativeTrace.maxSteps > 0
            && g_nativeTrace.totalSteps >= g_nativeTrace.maxSteps;
        const bool eventLimit = g_nativeTrace.captureEvents
            && g_nativeTrace.maxEvents > 0
            && g_nativeTrace.events.size() >= g_nativeTrace.maxEvents;
        const bool uniqueLimit = g_nativeTrace.maxUnique > 0
            && g_nativeTrace.hits.size() >= g_nativeTrace.maxUnique;
        if (g_nativeTrace.stopOnLimit && (stepLimit || eventLimit || uniqueLimit)) {
            g_nativeTrace.active = false;
            g_nativeTrace.completed = true;
            g_nativeTrace.stopReason = stepLimit ? "max_steps"
                : eventLimit ? "max_events" : "max_unique";
            requestStop = true;
            g_nativeTrace.cv.notify_all();
        }
    }
    if (requestStop) {
        info->stop = true;
    }
}

static void recordNativeTraceException(const PLUG_CB_EXCEPTION* info) noexcept
{
    try
    {
        if(!info || !info->Exception)
            return;
        const DWORD threadId = DbgGetThreadId();
        if(!threadId)
            return;
        NativeTracePendingException pending;
        pending.code = info->Exception->ExceptionRecord.ExceptionCode;
        pending.firstChance = info->Exception->dwFirstChance != 0;
        pending.address = reinterpret_cast<duint>(
            info->Exception->ExceptionRecord.ExceptionAddress);
        std::lock_guard<std::mutex> lock(g_nativeTrace.mutex);
        if(g_nativeTrace.active && g_nativeTrace.captureEvents)
            g_nativeTrace.pendingExceptions[threadId] = pending;
    }
    catch(...)
    {
        // Trace enrichment must never interfere with exception disposition.
    }
}

static std::string armNativeTraceExceptionResume() noexcept
{
    try
    {
        std::lock_guard<std::mutex> lock(g_nativeTrace.mutex);
        if(!g_nativeTrace.active || !g_nativeTrace.autoResumeExceptions)
            return {};
        const uint64_t remaining =
            g_nativeTrace.maxSteps > g_nativeTrace.totalSteps
            ? g_nativeTrace.maxSteps - g_nativeTrace.totalSteps
            : 1;
        g_nativeTrace.exceptionResumeQueued = true;
        std::stringstream command;
        command << "TraceIntoConditional \"0\", 0x"
                << std::hex << remaining;
        return command.str();
    }
    catch(...)
    {
        return {};
    }
}

static void completeNativeTraceExceptionResume(bool submitted) noexcept
{
    try
    {
        bool shouldFinish = false;
        {
            std::lock_guard<std::mutex> lock(g_nativeTrace.mutex);
            if(!submitted && g_nativeTrace.exceptionResumeQueued)
            {
                g_nativeTrace.exceptionResumeQueued = false;
                shouldFinish = g_nativeTrace.active;
            }
        }
        if(shouldFinish)
            finishNativeTrace("exception_resume_failed");
    }
    catch(...)
    {
    }
}

#if !defined(_WIN64)
static void observeNativeTraceResume() noexcept;

struct NativeTraceResumeGuiWork
{
    std::string command;
};

static void nativeTraceResumeGuiCallback(void* userdata) noexcept
{
    std::unique_ptr<NativeTraceResumeGuiWork> work(
        static_cast<NativeTraceResumeGuiWork*>(userdata));
    if(!work)
        return;
    const bool submitted = DbgCmdExec(work->command.c_str());
    observeNativeTraceResume();
    completeNativeTraceExceptionResume(submitted);
}

static bool submitNativeTraceResumeAfterCallback(
    const std::string& command) noexcept
{
    if(command.empty())
        return false;
    auto* work = new (std::nothrow) NativeTraceResumeGuiWork();
    if(!work)
        return false;
    work->command = command;
    GuiExecuteOnGuiThreadEx(nativeTraceResumeGuiCallback, work);
    return true;
}
#endif

static bool preserveNativeTraceAcrossExceptionPause() noexcept
{
    try
    {
        std::lock_guard<std::mutex> lock(g_nativeTrace.mutex);
        return g_nativeTrace.active
            && g_nativeTrace.autoResumeExceptions
            && g_nativeTrace.exceptionResumeQueued;
    }
    catch(...)
    {
        return false;
    }
}

static bool nativeTraceMayAutoResumeException() noexcept
{
    try
    {
        std::lock_guard<std::mutex> lock(g_nativeTrace.mutex);
        return g_nativeTrace.active && g_nativeTrace.autoResumeExceptions;
    }
    catch(...)
    {
        return false;
    }
}

static void observeNativeTraceResume() noexcept
{
    try
    {
        std::lock_guard<std::mutex> lock(g_nativeTrace.mutex);
        g_nativeTrace.exceptionResumeQueued = false;
    }
    catch(...)
    {
    }
}

std::string buildNativeTraceJson(size_t eventOffset, size_t eventLimit,
                                 size_t hitOffset, size_t hitLimit,
                                 uint64_t eventAfterSeq,
                                 uint64_t hitAfterRevision) {
    std::lock_guard<std::mutex> lock(g_nativeTrace.mutex);
    const auto& trace = g_nativeTrace;
    std::stringstream ss;
    ss << "{";
    ss << "\"ok\":" << (!trace.traceId.empty() ? "true" : "false") << ",";
    ss << "\"traceId\":\"" << escapeJsonString(trace.traceId.c_str()) << "\",";
    ss << "\"sessionId\":\"" << escapeJsonString(trace.sessionId.c_str()) << "\",";
    ss << "\"sessionGeneration\":" << std::dec << trace.sessionGeneration << ",";
    ss << "\"processId\":" << std::dec << trace.processId << ",";
    ss << "\"mode\":\"" << escapeJsonString(trace.mode.c_str()) << "\",";
    ss << "\"active\":" << (trace.active ? "true" : "false") << ",";
    ss << "\"completed\":" << (trace.completed ? "true" : "false") << ",";
    ss << "\"captureEvents\":" << (trace.captureEvents ? "true" : "false") << ",";
    ss << "\"stopOnLimit\":" << (trace.stopOnLimit ? "true" : "false") << ",";
    ss << "\"autoResumeExceptions\":"
       << (trace.autoResumeExceptions ? "true" : "false") << ",";
    ss << "\"exceptionResumeQueued\":"
       << (trace.exceptionResumeQueued ? "true" : "false") << ",";
    ss << "\"enrichEvents\":" << (trace.enrichEvents ? "true" : "false") << ",";
    ss << "\"hasRange\":" << (trace.hasRange ? "true" : "false") << ",";
    ss << "\"rangeStart\":\"0x" << std::hex << trace.rangeStart << "\",";
    ss << "\"rangeSize\":\"0x" << std::hex << trace.rangeSize << "\",";
    ss << "\"maxSteps\":" << std::dec << trace.maxSteps << ",";
    ss << "\"maxEvents\":" << std::dec << trace.maxEvents << ",";
    ss << "\"maxUnique\":" << std::dec << trace.maxUnique << ",";
    ss << "\"totalSteps\":" << std::dec << trace.totalSteps << ",";
    ss << "\"matchedSteps\":" << std::dec << trace.matchedSteps << ",";
    ss << "\"uniqueAddresses\":" << std::dec << trace.hits.size() << ",";
    ss << "\"eventCount\":" << std::dec << trace.events.size() << ",";
    ss << "\"droppedEvents\":" << std::dec << trace.droppedEvents << ",";
    ss << "\"droppedUnique\":" << std::dec << trace.droppedUnique << ",";
    ss << "\"hitRevision\":" << std::dec << trace.hitRevision << ",";
    ss << "\"droppedHitUpdates\":" << std::dec << trace.droppedHitUpdates << ",";
    ss << "\"createdTickMs\":" << std::dec << trace.createdTickMs << ",";
    ss << "\"lastTickMs\":" << std::dec << trace.lastTickMs << ",";
    ss << "\"stopReason\":\"" << escapeJsonString(trace.stopReason.c_str()) << "\",";

    size_t eventStart = std::min(eventOffset, trace.events.size());
    bool eventCursorTruncated = false;
    if (eventAfterSeq > 0 && !trace.events.empty()) {
        const uint64_t oldestSeq = trace.events.front().seq;
        if (eventAfterSeq < oldestSeq && oldestSeq - eventAfterSeq > 1) {
            eventCursorTruncated = true;
            eventStart = 0;
        } else {
            eventStart = static_cast<size_t>(std::distance(
                trace.events.begin(),
                std::find_if(trace.events.begin(), trace.events.end(),
                    [eventAfterSeq](const NativeTraceEvent& event) {
                        return event.seq > eventAfterSeq;
                    })));
        }
    }
    const size_t eventEnd = eventLimit == 0
        ? eventStart
        : std::min(trace.events.size(), eventStart + eventLimit);
    ss << "\"eventOffset\":" << std::dec << eventStart << ",";
    ss << "\"eventReturned\":" << std::dec << (eventEnd - eventStart) << ",";
    ss << "\"eventHasMore\":" << (eventEnd < trace.events.size() ? "true" : "false") << ",";
    ss << "\"eventAfterSeq\":" << std::dec << eventAfterSeq << ",";
    ss << "\"eventNextAfterSeq\":" << std::dec
       << (eventEnd > eventStart ? trace.events[eventEnd - 1].seq : eventAfterSeq) << ",";
    ss << "\"oldestEventSeq\":" << std::dec
       << (trace.events.empty() ? 0 : trace.events.front().seq) << ",";
    ss << "\"latestEventSeq\":" << std::dec
       << (trace.events.empty() ? 0 : trace.events.back().seq) << ",";
    ss << "\"eventCursorTruncated\":" << (eventCursorTruncated ? "true" : "false") << ",";
    ss << "\"eventCursorExclusive\":true,";
    ss << "\"events\":[";
    for (size_t i = eventStart; i < eventEnd; ++i) {
        if (i != eventStart) ss << ",";
        const auto& event = trace.events[i];
        ss << "{\"seq\":" << std::dec << event.seq
           << ",\"tickMs\":" << std::dec << event.tickMs
           << ",\"threadId\":" << std::dec << event.threadId
           << ",\"ip\":\"0x" << std::hex << event.ip << "\""
           << ",\"module\":\"" << escapeJsonString(event.module.c_str()) << "\""
           << ",\"moduleBase\":\"0x" << std::hex << event.moduleBase << "\""
           << ",\"rva\":\"0x" << std::hex << event.rva << "\""
           << ",\"bytes\":\"" << escapeJsonString(event.bytesHex.c_str()) << "\""
           << ",\"instruction\":\"" << escapeJsonString(event.instruction.c_str()) << "\""
           << ",\"instructionSize\":" << std::dec << event.instructionSize
           << ",\"branch\":" << (event.branch ? "true" : "false")
           << ",\"call\":" << (event.call ? "true" : "false")
           << ",\"isReturn\":" << (event.isReturn ? "true" : "false")
           << ",\"branchTarget\":\"0x" << std::hex
           << event.branchTarget << "\""
           << ",\"exceptionTransition\":"
           << (event.exceptionTransition ? "true" : "false")
           << ",\"exceptionCode\":\"0x" << std::hex
           << event.exceptionCode << "\""
           << ",\"exceptionFirstChance\":"
           << (event.exceptionFirstChance ? "true" : "false")
           << ",\"exceptionAddress\":\"0x" << std::hex
           << event.exceptionAddress << "\""
           << "}";
    }
    ss << "],";

    size_t hitUpdateStart = 0;
    bool hitCursorTruncated = false;
    if (hitAfterRevision > 0 && !trace.hitUpdates.empty()) {
        const uint64_t oldestRevision = trace.hitUpdates.front().revision;
        if (hitAfterRevision < oldestRevision && oldestRevision - hitAfterRevision > 1) {
            hitCursorTruncated = true;
            hitUpdateStart = 0;
        } else {
            hitUpdateStart = static_cast<size_t>(std::distance(
                trace.hitUpdates.begin(),
                std::find_if(trace.hitUpdates.begin(), trace.hitUpdates.end(),
                    [hitAfterRevision](const NativeTraceHitUpdate& update) {
                        return update.revision > hitAfterRevision;
                    })));
        }
    }
    const size_t hitUpdateEnd = hitLimit == 0
        ? hitUpdateStart
        : std::min(trace.hitUpdates.size(), hitUpdateStart + hitLimit);
    ss << "\"hitAfterRevision\":" << std::dec << hitAfterRevision << ",";
    ss << "\"hitNextAfterRevision\":" << std::dec
       << (hitUpdateEnd > hitUpdateStart
           ? trace.hitUpdates[hitUpdateEnd - 1].revision
           : hitAfterRevision) << ",";
    ss << "\"oldestHitRevision\":" << std::dec
       << (trace.hitUpdates.empty() ? 0 : trace.hitUpdates.front().revision) << ",";
    ss << "\"latestHitRevision\":" << std::dec
       << (trace.hitUpdates.empty() ? 0 : trace.hitUpdates.back().revision) << ",";
    ss << "\"hitCursorTruncated\":" << (hitCursorTruncated ? "true" : "false") << ",";
    ss << "\"hitCursorExclusive\":true,";
    ss << "\"hitUpdates\":[";
    for (size_t i = hitUpdateStart; i < hitUpdateEnd; ++i) {
        if (i != hitUpdateStart) ss << ",";
        const auto& update = trace.hitUpdates[i];
        ss << "{\"revision\":" << std::dec << update.revision
           << ",\"ip\":\"0x" << std::hex << update.ip
           << "\",\"hits\":" << std::dec << update.hits << "}";
    }
    ss << "],";

    std::vector<std::pair<duint, uint64_t>> sortedHits(trace.hits.begin(), trace.hits.end());
    std::sort(sortedHits.begin(), sortedHits.end(),
        [](const auto& left, const auto& right) { return left.first < right.first; });
    const size_t hitStart = std::min(hitOffset, sortedHits.size());
    const size_t hitEnd = hitLimit == 0
        ? hitStart
        : std::min(sortedHits.size(), hitStart + hitLimit);
    ss << "\"hitOffset\":" << std::dec << hitStart << ",";
    ss << "\"hitReturned\":" << std::dec << (hitEnd - hitStart) << ",";
    ss << "\"hitHasMore\":" << (hitEnd < sortedHits.size() ? "true" : "false") << ",";
    ss << "\"hits\":[";
    for (size_t i = hitStart; i < hitEnd; ++i) {
        if (i != hitStart) ss << ",";
        ss << "{\"ip\":\"0x" << std::hex << sortedHits[i].first
           << "\",\"hits\":" << std::dec << sortedHits[i].second << "}";
    }
    ss << "]}";
    return ss.str();
}

std::string buildNativeApiTraceJson(const std::string& traceId,
                                    uint64_t afterSeq,
                                    size_t limit)
{
    std::vector<NativeApiTraceEvent> matching;
    uint64_t dropped = 0;
    size_t pendingCalls = 0;
    size_t finalizedPendingCalls = 0;
    size_t exceptionUnwoundPendingCalls = 0;
    bool nativeReturnHooks = false;
    uint64_t returnHooksInstalled = 0;
    uint64_t returnHooksRemoved = 0;
    uint64_t returnHookFailures = 0;
    std::string lastReturnHookError;
    std::vector<duint> registeredEntryBreakpoints;
    std::vector<duint> ownedReturnBreakpoints;
    std::vector<duint> preexistingReturnBreakpoints;
    {
        std::lock_guard<std::mutex> lock(g_nativeApiTrace.mutex);
        dropped = g_nativeApiTrace.droppedEvents;
        for(const auto& event : g_nativeApiTrace.events)
        {
            if(event.traceId == traceId)
                matching.push_back(event);
        }
        const auto tracePending =
            g_nativeApiTrace.pending.find(traceId);
        if(tracePending != g_nativeApiTrace.pending.end())
        {
            for(const auto& threadPending : tracePending->second)
                pendingCalls += threadPending.second.size();
        }
        const auto finalized =
            g_nativeApiTrace.finalizedPending.find(traceId);
        if(finalized != g_nativeApiTrace.finalizedPending.end())
            finalizedPendingCalls = finalized->second;
        const auto exceptionUnwound =
            g_nativeApiTrace.exceptionUnwoundPending.find(traceId);
        if(exceptionUnwound != g_nativeApiTrace.exceptionUnwoundPending.end())
            exceptionUnwoundPendingCalls = exceptionUnwound->second;
        const auto config = g_nativeApiTrace.configs.find(traceId);
        if(config != g_nativeApiTrace.configs.end())
        {
            nativeReturnHooks = config->second.nativeReturnHooks;
            returnHooksInstalled = config->second.returnHooksInstalled;
            returnHooksRemoved = config->second.returnHooksRemoved;
            returnHookFailures = config->second.returnHookFailures;
            lastReturnHookError = config->second.lastReturnHookError;
            registeredEntryBreakpoints.assign(
                config->second.registeredEntryBreakpoints.begin(),
                config->second.registeredEntryBreakpoints.end());
            ownedReturnBreakpoints.assign(
                config->second.ownedReturnBreakpoints.begin(),
                config->second.ownedReturnBreakpoints.end());
            preexistingReturnBreakpoints.assign(
                config->second.preexistingReturnBreakpoints.begin(),
                config->second.preexistingReturnBreakpoints.end());
        }
    }
    std::sort(ownedReturnBreakpoints.begin(), ownedReturnBreakpoints.end());
    std::sort(
        registeredEntryBreakpoints.begin(),
        registeredEntryBreakpoints.end());
    std::sort(
        preexistingReturnBreakpoints.begin(),
        preexistingReturnBreakpoints.end());
    const uint64_t oldest = matching.empty() ? 0 : matching.front().seq;
    const uint64_t latest = matching.empty() ? 0 : matching.back().seq;
    const bool truncated = afterSeq > 0 && oldest > afterSeq
        && oldest - afterSeq > 1;
    size_t start = 0;
    if(afterSeq > 0)
    {
        start = static_cast<size_t>(std::distance(
            matching.begin(),
            std::find_if(matching.begin(), matching.end(),
                [afterSeq](const NativeApiTraceEvent& event) {
                    return event.seq > afterSeq;
                })));
    }
    const size_t end = std::min(matching.size(), start + std::min<size_t>(limit, 5000));
    std::stringstream ss;
    ss << "{\"ok\":true,\"traceId\":\"" << escapeJsonString(traceId.c_str())
       << "\",\"eventCount\":" << std::dec << matching.size()
       << ",\"droppedEvents\":" << dropped
       << ",\"globalDroppedEvents\":" << dropped
       << ",\"pendingCalls\":" << pendingCalls
       << ",\"finalizedPendingCalls\":" << finalizedPendingCalls
       << ",\"exceptionUnwoundPendingCalls\":"
       << exceptionUnwoundPendingCalls
       << ",\"nativeReturnHooks\":"
       << (nativeReturnHooks ? "true" : "false")
       << ",\"returnHooksInstalled\":" << returnHooksInstalled
       << ",\"returnHooksRemoved\":" << returnHooksRemoved
       << ",\"returnHookFailures\":" << returnHookFailures
       << ",\"lastReturnHookError\":"
       << (lastReturnHookError.empty()
            ? "null"
            : std::string("\"")
                + escapeJsonString(lastReturnHookError.c_str()) + "\"")
       << ",\"registeredEntryBreakpoints\":[";
    for(size_t index = 0;
        index < registeredEntryBreakpoints.size(); ++index)
    {
        if(index != 0)
            ss << ",";
        ss << "\"0x" << std::hex << registeredEntryBreakpoints[index] << "\"";
    }
    ss << "],\"ownedReturnBreakpoints\":[";
    for(size_t index = 0; index < ownedReturnBreakpoints.size(); ++index)
    {
        if(index != 0)
            ss << ",";
        ss << "\"0x" << std::hex << ownedReturnBreakpoints[index] << "\"";
    }
    ss << "],\"preexistingReturnBreakpoints\":[";
    for(size_t index = 0;
        index < preexistingReturnBreakpoints.size(); ++index)
    {
        if(index != 0)
            ss << ",";
        ss << "\"0x" << std::hex
           << preexistingReturnBreakpoints[index] << "\"";
    }
    ss << "]"
       << ",\"afterSeq\":" << std::dec << afterSeq
       << ",\"nextAfterSeq\":"
       << (end > start ? matching[end - 1].seq : afterSeq)
       << ",\"oldestSeq\":" << oldest
       << ",\"latestSeq\":" << latest
       << ",\"cursorTruncated\":" << (truncated ? "true" : "false")
       << ",\"cursorExclusive\":true,\"events\":[";
    for(size_t index = start; index < end; ++index)
    {
        if(index != start)
            ss << ",";
        const auto& event = matching[index];
        ss << "{\"seq\":" << std::dec << event.seq
           << ",\"callId\":" << event.callId
           << ",\"entrySeq\":" << event.entrySeq
           << ",\"tickMs\":" << event.tickMs
           << ",\"durationMs\":" << event.durationMs
           << ",\"threadId\":" << event.threadId
           << ",\"ip\":\"0x" << std::hex << event.ip << "\""
           << ",\"breakpointAddress\":\"0x"
           << event.breakpointAddress << "\""
           << ",\"apiAddress\":\"0x" << event.apiAddress << "\""
           << ",\"stackPointer\":\"0x" << event.stackPointer << "\""
           << ",\"returnAddress\":\"0x" << event.returnAddress << "\""
           << ",\"returnValue\":\"0x" << event.returnValue << "\""
           << ",\"matchedReturn\":"
           << (event.matchedReturn ? "true" : "false")
           << ",\"unwoundFrames\":" << std::dec << event.unwoundFrames
           << ",\"exceptionCode\":\"0x" << std::hex
           << event.exceptionCode << "\""
           << ",\"exceptionFirstChance\":"
           << (event.exceptionFirstChance ? "true" : "false")
           << ",\"managedException\":"
           << (event.managedException ? "true" : "false")
           << ",\"managedRuntime\":\""
           << escapeJsonString(event.managedRuntime.c_str()) << "\""
           << ",\"managedHResult\":\"0x" << std::hex
           << event.managedHResult << "\""
           << ",\"managedObject\":\"0x" << std::hex
           << event.managedObject << "\""
           << ",\"exceptionParameters\":[";
        for(size_t parameterIndex = 0;
            parameterIndex < event.exceptionParameters.size();
            ++parameterIndex)
        {
            if(parameterIndex != 0)
                ss << ",";
            ss << "\"0x" << std::hex
               << event.exceptionParameters[parameterIndex] << "\"";
        }
        ss << "]"
           << ",\"kind\":\"" << escapeJsonString(event.kind.c_str()) << "\""
           << ",\"name\":\"" << escapeJsonString(event.name.c_str()) << "\""
           << ",\"module\":\"" << escapeJsonString(event.module.c_str()) << "\""
           << ",\"callerModule\":\""
           << escapeJsonString(event.callerModule.c_str()) << "\""
           << ",\"callerModuleBase\":\"0x" << std::hex
           << event.callerModuleBase << "\""
           << ",\"callerRva\":\"0x" << event.callerRva << "\""
           << ",\"arguments\":[";
        for(size_t argumentIndex = 0;
            argumentIndex < event.arguments.size();
            ++argumentIndex)
        {
            if(argumentIndex != 0)
                ss << ",";
            ss << "\"0x" << std::hex
               << event.arguments[argumentIndex] << "\"";
        }
        ss << "]}";
    }
    ss << "]}";
    return ss.str();
}

static bool stateMatchesWaitUnlocked(const DebugSessionState& state,
                                     const std::string& mode,
                                     uint64_t sinceSeq,
                                     duint requestedAddr,
                                     bool hasRequestedAddr,
                                     const std::string& requestedName) {
    if (mode == "pause") {
        if (state.exited || (!state.debugging && state.initialized)) {
            return sinceSeq == 0 || state.eventSeq > sinceSeq;
        }
        if (sinceSeq > 0 && state.eventSeq <= sinceSeq) {
            return false;
        }
        return state.paused;
    }

    if (mode == "exit") {
        return state.exited || (!state.debugging && state.initialized);
    }

    if (mode == "breakpoint") {
        if (state.exited || (!state.debugging && state.initialized)) {
            return true;
        }
        if (!(state.paused && state.stopReason == "breakpoint")) {
            if (sinceSeq > 0 && state.eventSeq <= sinceSeq) {
                return false;
            }
            return false;
        }
        if (sinceSeq > 0 && state.eventSeq <= sinceSeq) {
            return false;
        }
        if (!breakpointMatchesRequestedUnlocked(state, requestedAddr, hasRequestedAddr, requestedName)) {
            return false;
        }
        return true;
    }

    return false;
}

static bool breakpointMatchesRequestedUnlocked(const DebugSessionState& state,
                                               duint requestedAddr,
                                               bool hasRequestedAddr,
                                               const std::string& requestedName) {
    if (!(state.paused && state.stopReason == "breakpoint")) {
        return false;
    }
    if (hasRequestedAddr && state.lastAddress != requestedAddr && state.lastIp != requestedAddr) {
        return false;
    }
    if (!requestedName.empty()) {
        std::string want = requestedName;
        std::string got = state.breakpointName;
        std::transform(want.begin(), want.end(), want.begin(), [](unsigned char c) { return (char)std::tolower(c); });
        std::transform(got.begin(), got.end(), got.begin(), [](unsigned char c) { return (char)std::tolower(c); });
        if (want != got) {
            return false;
        }
    }
    return true;
}

std::string waitForSessionJson(const std::string& mode, unsigned int timeoutMs, uint64_t sinceSeq, duint requestedAddr, bool hasRequestedAddr, const std::string& requestedName, bool& timedOut) {
    std::unique_lock<std::mutex> lock(g_debugSession.mutex);
    auto matches = [&]() {
        return stateMatchesWaitUnlocked(g_debugSession, mode, sinceSeq, requestedAddr, hasRequestedAddr, requestedName);
    };

    if (!matches() && !g_httpServer.stopRequested.load(std::memory_order_acquire)) {
        const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeoutMs);
        while (!matches() && !g_httpServer.stopRequested.load(std::memory_order_acquire)) {
            if (g_debugSession.cv.wait_until(lock, deadline) == std::cv_status::timeout) {
                break;
            }
        }
    }

    timedOut = !matches();
    std::stringstream ss;
    ss << "{";
    ss << "\"timedOut\":" << (timedOut ? "true" : "false") << ",";
    ss << "\"timeoutMs\":" << std::dec << timeoutMs << ",";
    ss << "\"requestedMode\":\"" << escapeJsonString(mode.c_str()) << "\",";
    ss << "\"requestedSinceSeq\":" << std::dec << sinceSeq << ",";
    ss << "\"requestedAddr\":\"0x" << std::hex << requestedAddr << "\",";
    ss << "\"requestedName\":\"" << escapeJsonString(requestedName.c_str()) << "\",";
    ss << "\"state\":" << buildDebugSessionJsonUnlocked(g_debugSession, true, 16);
    ss << "}";
    return ss.str();
}

std::string waitForSessionDetailedJson(const std::string& mode, unsigned int timeoutMs, uint64_t sinceSeq, duint requestedAddr, bool hasRequestedAddr, const std::string& requestedName, bool& timedOut) {
    std::unique_lock<std::mutex> lock(g_debugSession.mutex);
    auto matchesRequested = [&]() {
        return stateMatchesWaitUnlocked(g_debugSession, mode, sinceSeq, requestedAddr, hasRequestedAddr, requestedName);
    };
    auto observedBreakpoint = [&]() {
        return mode == "breakpoint"
            && (sinceSeq == 0 || g_debugSession.eventSeq > sinceSeq)
            && g_debugSession.paused
            && g_debugSession.stopReason == "breakpoint";
    };
    auto shouldReturn = [&]() {
        return matchesRequested() || observedBreakpoint();
    };

    if (!shouldReturn() && !g_httpServer.stopRequested.load(std::memory_order_acquire)) {
        const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeoutMs);
        while (!shouldReturn() && !g_httpServer.stopRequested.load(std::memory_order_acquire)) {
            if (g_debugSession.cv.wait_until(lock, deadline) == std::cv_status::timeout) {
                break;
            }
        }
    }

    const bool observedAnyBreakpoint = observedBreakpoint();
    const bool matchedWait = matchesRequested();
    timedOut = !(matchedWait || observedAnyBreakpoint);
    const auto& state = g_debugSession;
    const bool observedEventAfterSinceSeq = sinceSeq == 0 || state.eventSeq > sinceSeq;
    const bool observedBreakpointNow = observedEventAfterSinceSeq && state.paused && state.stopReason == "breakpoint";
    const bool matchedRequested = observedBreakpointNow && breakpointMatchesRequestedUnlocked(state, requestedAddr, hasRequestedAddr, requestedName);
    const bool hit = !timedOut && matchedRequested;

    std::stringstream ss;
    ss << "{";
    ss << "\"timedOut\":" << (timedOut ? "true" : "false") << ",";
    ss << "\"hit\":" << (hit ? "true" : "false") << ",";
    ss << "\"observedBreakpoint\":" << (observedBreakpointNow ? "true" : "false") << ",";
    ss << "\"matchedRequested\":" << (matchedRequested ? "true" : "false") << ",";
    ss << "\"timeoutMs\":" << std::dec << timeoutMs << ",";
    ss << "\"requestedMode\":\"" << escapeJsonString(mode.c_str()) << "\",";
    ss << "\"requestedSinceSeq\":" << std::dec << sinceSeq << ",";
    ss << "\"requestedAddr\":\"0x" << std::hex << requestedAddr << "\",";
    ss << "\"requestedName\":\"" << escapeJsonString(requestedName.c_str()) << "\",";
    ss << "\"eventSeq\":" << std::dec << state.eventSeq << ",";
    ss << "\"timestampMs\":" << std::dec << state.lastUpdateMs << ",";
    ss << "\"processId\":" << std::dec << state.processId << ",";
    ss << "\"threadId\":" << std::dec << state.threadId << ",";
    ss << "\"rip\":\"0x" << std::hex << state.lastIp << "\",";
    ss << "\"addr\":\"0x" << std::hex << state.lastAddress << "\",";
    ss << "\"lastEventType\":\"" << escapeJsonString(state.lastEventType.c_str()) << "\",";
    ss << "\"stopReason\":\"" << escapeJsonString(state.stopReason.c_str()) << "\",";
    ss << "\"breakpointName\":\"" << escapeJsonString(state.breakpointName.c_str()) << "\",";
    ss << "\"breakpointModule\":\"" << escapeJsonString(state.breakpointModule.c_str()) << "\",";
    ss << "\"note\":\"" << escapeJsonString(state.note.c_str()) << "\",";
    ss << "\"state\":" << buildDebugSessionJsonUnlocked(state, true, 16);
    ss << "}";
    return ss.str();
}

std::unordered_map<std::string, std::string> mergeRequestParams(const std::string& query, const std::string& body) {
    auto params = parseQueryParams(query);
    if (!body.empty() && body.find('=') != std::string::npos) {
        auto bodyParams = parseQueryParams(body);
        for (const auto& entry : bodyParams) {
            params[entry.first] = entry.second;
        }
    }
    return params;
}

static std::string launchFileIdHex(const std::array<uint8_t, 16>& bytes)
{
    static constexpr char digits[] = "0123456789abcdef";
    std::string result(bytes.size() * 2u, '\0');
    for(size_t index = 0; index < bytes.size(); ++index)
    {
        result[index * 2u] = digits[bytes[index] >> 4u];
        result[index * 2u + 1u] = digits[bytes[index] & 0x0fu];
    }
    return result;
}

static bool launchFileIdentityMatches(
    const mcplaunch::FileIdentityResult& expected,
    const mcplaunch::FileIdentityResult& actual)
{
    return expected.ok && actual.ok
        && _stricmp(expected.sha256.c_str(), actual.sha256.c_str()) == 0
        && expected.size == actual.size
        && expected.volumeSerialNumber == actual.volumeSerialNumber
        && expected.fileId == actual.fileId;
}

static std::shared_ptr<ManagedLaunch> findManagedLaunchByProcessId(DWORD processId)
{
    if(processId == 0)
        return {};
    std::lock_guard<std::mutex> lock(g_launchRegistryMutex);
    for(const auto& entry : g_launchRegistry)
    {
        if(entry.second && entry.second->info.processId == processId)
            return entry.second;
    }
    return {};
}

static void completeManagedLaunchCreateObservation(
    const std::shared_ptr<ManagedLaunch>& launch,
    DWORD processId,
    const mcplaunch::FileIdentityResult& actual)
{
    if(!launch)
        return;

    std::string sessionId;
    uint64_t generation = 0;
    uint64_t eventSeq = 0;
    DWORD sessionProcessId = 0;
    {
        std::lock_guard<std::mutex> sessionLock(g_debugSession.mutex);
        sessionId = g_debugSession.sessionId;
        generation = g_debugSession.generation;
        eventSeq = g_debugSession.eventSeq;
        sessionProcessId = g_debugSession.processId;
    }

    {
        std::lock_guard<std::mutex> launchLock(launch->mutex);
        launch->actualIdentity = actual;
        launch->observedProcessId = processId;
        launch->sessionId = std::move(sessionId);
        launch->sessionGeneration = generation;
        launch->sessionEventSeq = eventSeq;
        launch->createProcessObserved = true;
        launch->identityVerified = sessionProcessId == launch->info.processId
            && processId == launch->info.processId
            && launchFileIdentityMatches(launch->expectedIdentity, actual);
        if(launch->identityVerified)
        {
            launch->phase = "attached_identity_verified";
        }
        else
        {
            launch->phase = "identity_failed";
            launch->errorCode = actual.ok
                ? "launch_identity_mismatch"
                : (actual.errorCode.empty()
                    ? "launch_identity_unavailable" : actual.errorCode);
            launch->errorMessage = actual.ok
                ? "The attached process image does not match the pre-launch file identity"
                : actual.error;
        }
    }
    launch->cv.notify_all();
}

static bool childBrokerReadWord(duint address, duint& value)
{
    value = 0;
    if(!address)
        return false;
    return DbgMemRead(address, &value, sizeof(value));
}

static bool childBrokerWriteWord(duint address, duint value)
{
    return address != 0 && DbgMemWrite(address, &value, sizeof(value));
}

static bool childBrokerFindHardwareBreakpoint(duint address, BRIDGEBP* found = nullptr)
{
    BPMAP map = {};
    const int count = DbgGetBpList(bp_hardware, &map);
    bool result = false;
    if(count > 0 && map.bp)
    {
        for(int index = 0; index < count; ++index)
        {
            if(map.bp[index].addr == address)
            {
                result = true;
                if(found)
                    *found = map.bp[index];
                break;
            }
        }
    }
    if(map.bp)
        BridgeFree(map.bp);
    return result;
}

static bool childBrokerFindSoftwareBreakpoint(duint address,
                                              BRIDGEBP* found = nullptr)
{
    BPMAP map = {};
    const int count = DbgGetBpList(bp_normal, &map);
    bool result = false;
    if(count > 0 && map.bp)
    {
        for(int index = 0; index < count; ++index)
        {
            if(map.bp[index].addr == address)
            {
                result = true;
                if(found)
                    *found = map.bp[index];
                break;
            }
        }
    }
    if(map.bp)
        BridgeFree(map.bp);
    return result;
}

static bool childBrokerFindUserReturnAddress(duint& address)
{
    address = 0;
    const DBGFUNCTIONS* functions = DbgFunctions();
    if(!functions || !functions->GetCallStackEx
        || !functions->ModBaseFromAddr || !functions->ModGetParty)
        return false;
    DBGCALLSTACK callstack = {};
    functions->GetCallStackEx(&callstack, false);
    if(callstack.entries)
    {
        for(int index = 0; index < callstack.total; ++index)
        {
            const duint candidate = callstack.entries[index].to;
            if(!candidate)
                continue;
            const duint moduleBase = functions->ModBaseFromAddr(candidate);
            if(moduleBase && functions->ModGetParty(moduleBase) == mod_user)
            {
                address = candidate;
                break;
            }
        }
        BridgeFree(callstack.entries);
    }
    return address != 0;
}

static bool childBrokerInstallParentHandoffBreakpoint(
    duint address,
    uint64_t token,
    bool& ownsBreakpoint,
    std::string& errorCode,
    std::string& errorMessage)
{
    ownsBreakpoint = false;
    errorCode.clear();
    errorMessage.clear();
    BRIDGEBP existing = {};
    if(childBrokerFindSoftwareBreakpoint(address, &existing))
    {
        if(existing.enabled && existing.active)
            return true;
        errorCode = "child_parent_handoff_breakpoint_conflict";
        errorMessage = "a disabled or inactive user breakpoint occupies the parent handoff address";
        return false;
    }

    char command[256] = {};
    _snprintf_s(command, sizeof(command), _TRUNCATE,
                "bp 0x%llx", static_cast<unsigned long long>(address));
    if(!DbgCmdExecDirect(command))
    {
        errorCode = "child_parent_handoff_breakpoint_failed";
        errorMessage = "x64dbg rejected the parent create-wrapper return breakpoint";
        return false;
    }
    ownsBreakpoint = true;
    _snprintf_s(command, sizeof(command), _TRUNCATE,
                "SetBreakpointName 0x%llx,\"MCP child parent handoff %llu\"",
                static_cast<unsigned long long>(address),
                static_cast<unsigned long long>(token));
    const bool named = DbgCmdExecDirect(command);
    _snprintf_s(command, sizeof(command), _TRUNCATE,
                "SetBreakpointSingleshoot 0x%llx,1",
                static_cast<unsigned long long>(address));
    const bool single = named && DbgCmdExecDirect(command);
    BRIDGEBP installed = {};
    if(!single || !childBrokerFindSoftwareBreakpoint(address, &installed)
        || !installed.enabled || !installed.active || !installed.singleshoot)
    {
        _snprintf_s(command, sizeof(command), _TRUNCATE,
                    "bc 0x%llx", static_cast<unsigned long long>(address));
        DbgCmdExecDirect(command);
        ownsBreakpoint = false;
        errorCode = "child_parent_handoff_breakpoint_verification_failed";
        errorMessage = "the parent create-wrapper return breakpoint could not be verified";
        return false;
    }
    return true;
}

static void childBrokerRemoveOwnedSoftwareBreakpoint(duint address)
{
    if(!address)
        return;
    char command[96] = {};
    _snprintf_s(command, sizeof(command), _TRUNCATE,
                "bc 0x%llx", static_cast<unsigned long long>(address));
    DbgCmdExecDirect(command);
}

static bool childBrokerInstallEntryBreakpoint(std::string& errorCode,
                                              std::string& errorMessage)
{
    errorCode.clear();
    errorMessage.clear();
    duint address = 0;
    // The launch waiter is notified from CB_CREATEPROCESS before x64dbg has
    // necessarily finished publishing every loader module.  Resolve with a
    // bounded retry window instead of racing that callback; no target code is
    // resumed until this succeeds.
    for(unsigned int attempt = 0; attempt < 100u && !address; ++attempt)
    {
        resolveSymbolAddress("ntdll.dll", "NtCreateUserProcess", address);
        if(!address)
            Sleep(50);
    }
    if(!address)
    {
        errorCode = "child_broker_entry_unresolved";
        errorMessage = "ntdll.NtCreateUserProcess is not resolved in the debuggee";
        return false;
    }
    {
        std::lock_guard<std::mutex> lock(g_childBroker.mutex);
        if(g_childBroker.entryBreakpointInstalled
            && g_childBroker.entryBreakpointAddress == address)
            return true;
    }
    BRIDGEBP existing = {};
    if(childBrokerFindHardwareBreakpoint(address, &existing))
    {
        if(existing.name[0] == '\0'
            || std::string(existing.name).find("MCP child create") == std::string::npos)
        {
            errorCode = "child_broker_hardware_breakpoint_conflict";
            errorMessage = "the broker will not replace an existing user hardware breakpoint";
            return false;
        }
        std::lock_guard<std::mutex> lock(g_childBroker.mutex);
        g_childBroker.entryBreakpointInstalled = true;
        g_childBroker.entryBreakpointAddress = address;
        return true;
    }
    char command[128] = {};
    _snprintf_s(command, sizeof(command), _TRUNCATE,
                "bphws 0x%llx,x,1", static_cast<unsigned long long>(address));
    if(!DbgCmdExecDirect(command))
    {
        errorCode = "child_broker_hardware_breakpoint_failed";
        errorMessage = "x64dbg rejected the broker NtCreateUserProcess hardware breakpoint";
        return false;
    }
    _snprintf_s(command, sizeof(command), _TRUNCATE,
                "bphwname 0x%llx,\"MCP child create\"",
                static_cast<unsigned long long>(address));
    DbgCmdExecDirect(command);
    {
        std::lock_guard<std::mutex> lock(g_childBroker.mutex);
        g_childBroker.entryBreakpointInstalled = true;
        g_childBroker.entryBreakpointAddress = address;
    }
    return true;
}

static void childBrokerDisableEntryBreakpoint()
{
    duint address = 0;
    bool installed = false;
    {
        std::lock_guard<std::mutex> lock(g_childBroker.mutex);
        address = g_childBroker.entryBreakpointAddress;
        installed = g_childBroker.entryBreakpointInstalled;
        g_childBroker.entryBreakpointInstalled = false;
    }
    if(installed && address)
    {
        char command[96] = {};
        _snprintf_s(command, sizeof(command), _TRUNCATE,
                    "bphwc 0x%llx", static_cast<unsigned long long>(address));
        DbgCmdExecDirect(command);
    }
}

static bool childBrokerCaptureEntryInterception(const PLUG_CB_BREAKPOINT* info)
{
    if(!info || !info->breakpoint)
        return false;
    const duint address = info->breakpoint->addr;
    REGDUMP_AVX512 registers = {};
    if(!DbgGetRegDumpEx(&registers, sizeof(registers)))
        return false;
    const DWORD threadId = DbgGetThreadId();
    if(!threadId)
        return false;
    ChildBrokerInterception interception;
    interception.active = true;
    interception.threadId = threadId;
    interception.entryAddress = address;
    interception.entryStack = static_cast<duint>(registers.regcontext.csp);
#ifdef _WIN64
    const duint processHandleOut = static_cast<duint>(registers.regcontext.ccx);
    const duint threadHandleOut = static_cast<duint>(registers.regcontext.cdx);
    const duint flagsAddress = interception.entryStack + 0x40u;
#else
    duint processHandleOut = 0;
    duint threadHandleOut = 0;
    if(!childBrokerReadWord(interception.entryStack + 0x04u, processHandleOut)
        || !childBrokerReadWord(interception.entryStack + 0x08u, threadHandleOut))
        return false;
    const duint flagsAddress = interception.entryStack + 0x20u;
#endif
    interception.threadFlagsAddress = flagsAddress;
    interception.processHandleOut = processHandleOut;
    interception.threadHandleOut = threadHandleOut;
    if(!processHandleOut || !threadHandleOut
        || !childBrokerReadWord(interception.entryStack, interception.returnAddress)
        || !interception.returnAddress)
        return false;
    if(!childBrokerReadWord(flagsAddress, interception.originalThreadFlags))
        return false;

    std::string policyName;
    {
        std::lock_guard<std::mutex> lock(g_childBroker.mutex);
        const auto decision = mcpchild::reserveChild(g_childBroker.quota, true);
        if(!decision.accepted)
            return false;
        // Reserve the quota before mutating the guest stack.  If the broker
        // refuses this child (for example attach-first already consumed its
        // one slot), the debuggee must be left bit-for-bit unchanged.
        if(!childBrokerWriteWord(flagsAddress, interception.originalThreadFlags | 1u))
        {
            mcpchild::rollbackChildReservation(g_childBroker.quota, true);
            return false;
        }
        interception.token = g_childBroker.nextInterceptionToken++;
        g_childBroker.interceptions[threadId] = interception;
        policyName = g_childBroker.policyName;
    }
    if(policyName == "attach-first")
        childBrokerDisableEntryBreakpoint();
    if(!DbgCmdExec("sti"))
    {
        std::lock_guard<std::mutex> lock(g_childBroker.mutex);
        g_childBroker.interceptions.erase(threadId);
        mcpchild::rollbackChildReservation(g_childBroker.quota, true);
        // The instruction has not been resumed when DbgCmdExec fails, so it
        // is safe to restore the original flag synchronously.
        childBrokerWriteWord(flagsAddress, interception.originalThreadFlags);
        return false;
    }
    return true;
}

static bool childBrokerProcessHandleFromReturn(
    const ChildBrokerInterception& interception,
    DWORD& childPid,
    DWORD& childTid,
    HANDLE& childProcess,
    HANDLE& childThread)
{
    childPid = 0;
    childTid = 0;
    childProcess = nullptr;
    childThread = nullptr;
    REGDUMP_AVX512 registers = {};
    if(!DbgGetRegDumpEx(&registers, sizeof(registers)))
        return false;
    if(static_cast<LONG>(static_cast<ULONG>(registers.regcontext.cax)) < 0)
        return false;
    duint rawProcess = 0;
    duint rawThread = 0;
    if(!childBrokerReadWord(interception.processHandleOut, rawProcess)
        || !childBrokerReadWord(interception.threadHandleOut, rawThread)
        || !rawProcess || !rawThread)
        return false;
    HANDLE parent = DbgGetProcessHandle();
    if(!parent
        || !DuplicateHandle(parent, reinterpret_cast<HANDLE>(rawProcess),
                            GetCurrentProcess(), &childProcess,
                            0, FALSE, DUPLICATE_SAME_ACCESS)
        || !DuplicateHandle(parent, reinterpret_cast<HANDLE>(rawThread),
                            GetCurrentProcess(), &childThread,
                            0, FALSE, DUPLICATE_SAME_ACCESS))
    {
        if(childProcess) CloseHandle(childProcess);
        if(childThread) CloseHandle(childThread);
        childProcess = nullptr;
        childThread = nullptr;
        return false;
    }
    childPid = GetProcessId(childProcess);
    childTid = GetThreadId(childThread);
    if(!childPid || !childTid)
    {
        CloseHandle(childProcess);
        CloseHandle(childThread);
        childProcess = nullptr;
        childThread = nullptr;
        return false;
    }
    return true;
}

struct ChildBridgeDescriptor
{
    std::string token;
    std::string bridgeId;
    DWORD pid = 0;
    ULONGLONG processStartTime100ns = 0;
    int port = 0;
    std::string arch;
};

struct ChildHttpResponse
{
    int status = 0;
    std::string body;
};

static bool childBrokerHexToken(const std::string& value)
{
    if(value.size() != 64)
        return false;
    return std::all_of(value.begin(), value.end(), [](unsigned char ch) {
        return (ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f')
            || (ch >= 'A' && ch <= 'F');
    });
}

static std::wstring childBrokerLocalAppDataPath()
{
    const std::string utf8 = childBrokerEnvironmentValue(L"LOCALAPPDATA");
    return utf8ToWide(utf8);
}

static bool childBrokerReadDescriptor(DWORD debuggerPid,
                                      ChildBridgeDescriptor& descriptor)
{
    descriptor = {};
    if(!debuggerPid)
        return false;
    std::wstring directory = childBrokerLocalAppDataPath();
    if(directory.empty())
        return false;
    if(directory.back() != L'\\')
        directory.push_back(L'\\');
    directory += L"x64dbgMCP\\bridge-";
    directory += std::to_wstring(debuggerPid);
    directory += L".token";
    std::ifstream file(directory);
    if(!file)
        return false;
    std::unordered_map<std::string, std::string> fields;
    std::string line;
    while(std::getline(file, line))
    {
        const size_t separator = line.find('=');
        if(separator == std::string::npos || separator == 0)
            return false;
        const std::string key = line.substr(0, separator);
        if(fields.find(key) != fields.end())
            return false;
        fields.emplace(key, line.substr(separator + 1));
    }
    uint64_t pidValue = 0;
    uint64_t startValue = 0;
    uint64_t portValue = 0;
    if(fields["version"] != "1"
        || !childBrokerHexToken(fields["token"])
        || !mcpbridge::parseUnsignedDecimalExact(fields["pid"], pidValue)
        || !mcpbridge::parseUnsignedDecimalExact(fields["processStartTime100ns"], startValue)
        || !mcpbridge::parseUnsignedDecimalExact(fields["port"], portValue)
        || pidValue != debuggerPid || startValue == 0 || portValue == 0
        || portValue > 65535 || fields["bridgeInstanceId"].empty()
        || (fields["arch"] != "x86" && fields["arch"] != "x64"))
        return false;
    descriptor.token = fields["token"];
    descriptor.bridgeId = fields["bridgeInstanceId"];
    descriptor.pid = static_cast<DWORD>(pidValue);
    descriptor.processStartTime100ns = static_cast<ULONGLONG>(startValue);
    descriptor.port = static_cast<int>(portValue);
    descriptor.arch = fields["arch"];
    return true;
}

static ULONGLONG childBrokerProcessStartTime(HANDLE process)
{
    FILETIME creation = {};
    FILETIME exit = {};
    FILETIME kernel = {};
    FILETIME user = {};
    if(!process || !GetProcessTimes(process, &creation, &exit, &kernel, &user))
        return 0;
    ULARGE_INTEGER value = {};
    value.LowPart = creation.dwLowDateTime;
    value.HighPart = creation.dwHighDateTime;
    return value.QuadPart;
}

static bool childBrokerBuildEnvironmentBlock(
    const std::vector<std::pair<std::wstring, std::wstring>>& overrides,
    std::vector<wchar_t>& block)
{
    block.clear();
    LPWCH raw = GetEnvironmentStringsW();
    if(!raw)
        return false;
    std::vector<std::wstring> entries;
    for(const wchar_t* cursor = raw; *cursor; )
    {
        const size_t length = wcslen(cursor);
        entries.emplace_back(cursor, length);
        cursor += length + 1u;
    }
    FreeEnvironmentStringsW(raw);
    auto nameOf = [](const std::wstring& entry) {
        const size_t separator = entry.find(L'=');
        return separator == std::wstring::npos
            ? entry : entry.substr(0, separator);
    };
    for(const auto& overrideEntry : overrides)
    {
        entries.erase(std::remove_if(entries.begin(), entries.end(), [&](const std::wstring& entry) {
            const std::wstring left = nameOf(entry);
            return _wcsicmp(left.c_str(), overrideEntry.first.c_str()) == 0;
        }), entries.end());
        entries.push_back(overrideEntry.first + L"=" + overrideEntry.second);
    }
    std::sort(entries.begin(), entries.end(), [&](const std::wstring& left, const std::wstring& right) {
        return _wcsicmp(nameOf(left).c_str(), nameOf(right).c_str()) < 0;
    });
    size_t units = 1u;
    for(const auto& entry : entries)
    {
        if(entry.find(L'\0') != std::wstring::npos)
            return false;
        if(entry.size() + 1u > mcplaunch::kMaxUnicodeEnvironmentBlockCodeUnits
            || units > mcplaunch::kMaxUnicodeEnvironmentBlockCodeUnits
                - entry.size() - 1u)
            return false;
        units += entry.size() + 1u;
    }
    block.reserve(units + 1u);
    for(const auto& entry : entries)
    {
        block.insert(block.end(), entry.begin(), entry.end());
        block.push_back(L'\0');
    }
    block.push_back(L'\0');
    return true;
}

static bool childBrokerTargetIsX64(HANDLE process, bool& isX64)
{
    isX64 = false;
    using IsWow64Process2Fn = BOOL (WINAPI*)(HANDLE, USHORT*, USHORT*);
    static IsWow64Process2Fn query = reinterpret_cast<IsWow64Process2Fn>(
        GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "IsWow64Process2"));
    if(query)
    {
        USHORT processMachine = IMAGE_FILE_MACHINE_UNKNOWN;
        USHORT nativeMachine = IMAGE_FILE_MACHINE_UNKNOWN;
        if(!query(process, &processMachine, &nativeMachine))
            return false;
        isX64 = processMachine == IMAGE_FILE_MACHINE_UNKNOWN
            && (nativeMachine == IMAGE_FILE_MACHINE_AMD64
                || nativeMachine == IMAGE_FILE_MACHINE_ARM64);
        return true;
    }
    BOOL wow64 = FALSE;
    if(!IsWow64Process(process, &wow64))
        return false;
    isX64 = !wow64;
    return true;
}

static std::wstring childBrokerDebuggerPath(HANDLE childProcess)
{
    bool childIsX64 = false;
    if(!childBrokerTargetIsX64(childProcess, childIsX64))
        return {};
    wchar_t currentPath[32768] = {};
    const DWORD length = GetModuleFileNameW(nullptr, currentPath, _countof(currentPath));
    if(!length || length >= _countof(currentPath))
        return {};
    std::wstring current(currentPath, length);
    const size_t slash = current.find_last_of(L"\\/");
    if(slash == std::wstring::npos)
        return {};
    std::wstring root = current.substr(0, slash);
    const size_t rootSlash = root.find_last_of(L"\\/");
    if(rootSlash != std::wstring::npos)
        root.resize(rootSlash);
    std::wstring result = root + (childIsX64 ? L"\\x64\\x64dbg.exe" : L"\\x32\\x32dbg.exe");
    return GetFileAttributesW(result.c_str()) == INVALID_FILE_ATTRIBUTES ? std::wstring() : result;
}

static bool childBrokerSpawnDebugger(const std::shared_ptr<ChildBrokerChild>& child,
                                     const std::string& childPolicy)
{
    if(!child)
        return false;
    const std::wstring debuggerPath = childBrokerDebuggerPath(child->processHandle);
    if(debuggerPath.empty())
        return false;
    std::vector<std::pair<std::wstring, std::wstring>> overrides;
    overrides.emplace_back(L"X64DBG_MCP_PORT", L"0");
    overrides.emplace_back(L"X64DBG_MCP_BROKER_POLICY", utf8ToWide(childPolicy));
    std::string brokerId;
    std::string launchId;
    DWORD rootPid = 0;
    {
        std::lock_guard<std::mutex> lock(g_childBroker.mutex);
        brokerId = g_childBroker.brokerId;
        launchId = g_childBroker.rootLaunchId;
        rootPid = g_childBroker.rootPid;
    }
    overrides.emplace_back(L"X64DBG_MCP_BROKER_ID", utf8ToWide(brokerId));
    overrides.emplace_back(L"X64DBG_MCP_BROKER_ROOT_LAUNCH_ID", utf8ToWide(launchId));
    overrides.emplace_back(L"X64DBG_MCP_BROKER_ROOT_PID", std::to_wstring(rootPid));
    overrides.emplace_back(L"X64DBG_MCP_BROKER_PARENT_PID", std::to_wstring(child->parentPid));
    overrides.emplace_back(L"X64DBG_MCP_BROKER_AUTO_ENTRY", L"1");
    std::vector<wchar_t> environment;
    if(!childBrokerBuildEnvironmentBlock(overrides, environment))
        return false;
    std::vector<std::wstring> arguments = {L"-p", std::to_wstring(child->pid)};
    const auto command = mcplaunch::buildWindowsCommandLine(debuggerPath, arguments);
    if(!command.ok)
        return false;
    std::vector<wchar_t> commandLine(command.commandLine.begin(), command.commandLine.end());
    commandLine.push_back(L'\0');
    STARTUPINFOW startup = {};
    startup.cb = sizeof(startup);
    PROCESS_INFORMATION processInfo = {};
    if(!CreateProcessW(debuggerPath.c_str(), commandLine.data(), nullptr, nullptr,
                       FALSE, CREATE_UNICODE_ENVIRONMENT | CREATE_NEW_PROCESS_GROUP,
                       environment.data(), nullptr, &startup, &processInfo))
        return false;
    CloseHandle(processInfo.hThread);
    {
        std::lock_guard<std::mutex> lock(child->mutex);
        child->debuggerProcessHandle = processInfo.hProcess;
        child->debuggerPid = processInfo.dwProcessId;
        child->debuggerSpawned = true;
        child->phase = "debugger_spawned";
    }
    return true;
}

static std::string childBrokerUrlEncode(std::string_view value)
{
    static constexpr char digits[] = "0123456789ABCDEF";
    std::string output;
    for(unsigned char ch : value)
    {
        if((ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z')
            || (ch >= '0' && ch <= '9') || ch == '-' || ch == '_'
            || ch == '.' || ch == '~')
            output.push_back(static_cast<char>(ch));
        else
        {
            output.push_back('%');
            output.push_back(digits[ch >> 4u]);
            output.push_back(digits[ch & 0x0fu]);
        }
    }
    return output;
}

static bool childBrokerHttpRequest(const ChildBridgeDescriptor& descriptor,
                                   const std::string& method,
                                   const std::string& target,
                                   const std::string& body,
                                   bool bridgeGuard,
                                   ChildHttpResponse& response,
                                   const std::string& sessionId = {},
                                   uint64_t sessionGeneration = 0,
                                   DWORD debuggeePid = 0,
                                   const std::string& targetSha256 = {},
                                   uint64_t eventSeq = 0)
{
    response = {};
    WSADATA wsa = {};
    if(WSAStartup(MAKEWORD(2, 2), &wsa) != 0)
        return false;
    SOCKET socketHandle = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if(socketHandle == INVALID_SOCKET)
    {
        WSACleanup();
        return false;
    }
    DWORD timeout = 1000;
    setsockopt(socketHandle, SOL_SOCKET, SO_RCVTIMEO,
               reinterpret_cast<const char*>(&timeout), sizeof(timeout));
    setsockopt(socketHandle, SOL_SOCKET, SO_SNDTIMEO,
               reinterpret_cast<const char*>(&timeout), sizeof(timeout));
    sockaddr_in address = {};
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    address.sin_port = htons(static_cast<u_short>(descriptor.port));
    bool ok = connect(socketHandle, reinterpret_cast<sockaddr*>(&address), sizeof(address)) == 0;
    if(ok)
    {
        std::stringstream request;
        request << method << " " << target << " HTTP/1.1\r\n"
                << "Host: 127.0.0.1:" << descriptor.port << "\r\n"
                << "Connection: close\r\n"
                << "X-MCP-Auth-Token: " << descriptor.token << "\r\n";
        if(bridgeGuard)
            request << "X-MCP-Bridge-Id: " << descriptor.bridgeId << "\r\n";
        if(!sessionId.empty())
        {
            request << "X-MCP-Session-Id: " << sessionId << "\r\n"
                    << "X-MCP-Session-Generation: " << sessionGeneration << "\r\n"
                    << "X-MCP-Debuggee-Pid: " << debuggeePid << "\r\n";
            if(!targetSha256.empty())
                request << "X-MCP-Debuggee-SHA256: " << targetSha256 << "\r\n";
            if(eventSeq != 0)
                request << "X-MCP-Event-Seq: " << eventSeq << "\r\n";
        }
        request << "Content-Length: " << body.size() << "\r\n\r\n" << body;
        const std::string serialized = request.str();
        int sendError = 0;
        ok = mcpbridge::sendAllSocket(socketHandle, serialized.data(), serialized.size(), &sendError);
        std::string received;
        char buffer[4096];
        while(ok)
        {
            const int count = recv(socketHandle, buffer, sizeof(buffer), 0);
            if(count == 0)
                break;
            if(count == SOCKET_ERROR)
            {
                ok = false;
                break;
            }
            received.append(buffer, static_cast<size_t>(count));
            if(received.size() > 4u * 1024u * 1024u)
            {
                ok = false;
                break;
            }
        }
        if(ok)
        {
            const size_t headerEnd = received.find("\r\n\r\n");
            if(headerEnd == std::string::npos)
                ok = false;
            else
            {
                const size_t lineEnd = received.find("\r\n");
                if(lineEnd == std::string::npos)
                    ok = false;
                else
                {
                    std::stringstream statusLine(received.substr(0, lineEnd));
                    std::string httpVersion;
                    statusLine >> httpVersion >> response.status;
                    response.body = received.substr(headerEnd + 4u);
                }
            }
        }
    }
    closesocket(socketHandle);
    WSACleanup();
    return ok && response.status >= 200 && response.status < 300;
}

static bool childBrokerWaitForDescriptor(DWORD debuggerPid,
                                         ChildBridgeDescriptor& descriptor,
                                         DWORD timeoutMs)
{
    const ULONGLONG deadline = nowTickMs() + timeoutMs;
    while(nowTickMs() < deadline)
    {
        if(childBrokerReadDescriptor(debuggerPid, descriptor))
            return true;
        {
            std::lock_guard<std::mutex> lock(g_childBroker.mutex);
            if(g_childBroker.stopping.load(std::memory_order_acquire))
                return false;
        }
        Sleep(50);
    }
    return false;
}

static bool childBrokerBridgeHelloMatches(const ChildBridgeDescriptor& descriptor,
                                          DWORD debuggerPid,
                                          DWORD childPid,
                                          const std::string& body)
{
    const std::string targetPid = std::string("\"processId\":")
        + std::to_string(childPid);
    const std::string debuggerPidMarker = std::string("\"pid\":")
        + std::to_string(debuggerPid);
    const std::string bridgeMarker = std::string("\"bridgeInstanceId\":\"")
        + descriptor.bridgeId + "\"";
    const std::string portMarker = std::string("\"boundPort\":")
        + std::to_string(descriptor.port);
    return body.find(targetPid) != std::string::npos
        && body.find("\"debugging\":true") != std::string::npos
        && body.find(debuggerPidMarker) != std::string::npos
        && body.find(bridgeMarker) != std::string::npos
        && body.find(portMarker) != std::string::npos;
}

static bool childBrokerWaitForAttached(const ChildBridgeDescriptor& descriptor,
                                       DWORD debuggerPid,
                                       DWORD childPid,
                                       DWORD timeoutMs)
{
    const ULONGLONG deadline = nowTickMs() + timeoutMs;
    while(nowTickMs() < deadline)
    {
        ChildHttpResponse response;
        if(childBrokerHttpRequest(descriptor, "GET",
                "/Bridge/Hello", {}, true, response))
        {
            if(childBrokerBridgeHelloMatches(descriptor, debuggerPid, childPid,
                                             response.body))
                return true;
        }
        Sleep(75);
    }
    return false;
}

static bool childBrokerJsonStringField(const std::string& json,
                                       const char* field,
                                       std::string& value)
{
    value.clear();
    const std::string marker = std::string("\"") + field + "\":\"";
    const size_t start = json.find(marker);
    if(start == std::string::npos)
        return false;
    size_t cursor = start + marker.size();
    while(cursor < json.size())
    {
        const char ch = json[cursor++];
        if(ch == '\\')
        {
            if(cursor >= json.size())
                return false;
            const char escaped = json[cursor++];
            // Session IDs and breakpoint names are ASCII in this protocol;
            // retain common JSON escapes while rejecting malformed input.
            switch(escaped)
            {
            case '\\': value.push_back('\\'); break;
            case '"': value.push_back('"'); break;
            case '/': value.push_back('/'); break;
            case 'b': value.push_back('\b'); break;
            case 'f': value.push_back('\f'); break;
            case 'n': value.push_back('\n'); break;
            case 'r': value.push_back('\r'); break;
            case 't': value.push_back('\t'); break;
            default: return false;
            }
        }
        else if(ch == '"')
        {
            return true;
        }
        else
        {
            value.push_back(ch);
        }
    }
    return false;
}

static bool childBrokerJsonUintField(const std::string& json,
                                     const char* field,
                                     uint64_t& value)
{
    value = 0;
    const std::string marker = std::string("\"") + field + "\":";
    const size_t start = json.find(marker);
    if(start == std::string::npos)
        return false;
    size_t cursor = start + marker.size();
    if(cursor >= json.size() || json[cursor] < '0' || json[cursor] > '9')
        return false;
    while(cursor < json.size() && json[cursor] >= '0' && json[cursor] <= '9')
    {
        const uint64_t digit = static_cast<uint64_t>(json[cursor++] - '0');
        if(value > (std::numeric_limits<uint64_t>::max() - digit) / 10u)
            return false;
        value = value * 10u + digit;
    }
    return true;
}

static bool childBrokerJsonBoolField(const std::string& json,
                                     const char* field,
                                     bool& value)
{
    const std::string marker = std::string("\"") + field + "\":";
    const size_t start = json.find(marker);
    if(start == std::string::npos)
        return false;
    const size_t cursor = start + marker.size();
    if(json.compare(cursor, 4u, "true") == 0)
    {
        value = true;
        return true;
    }
    if(json.compare(cursor, 5u, "false") == 0)
    {
        value = false;
        return true;
    }
    return false;
}

static bool childBrokerWaitForPreEntryPause(
    const std::shared_ptr<ChildBrokerChild>& child,
    const ChildBridgeDescriptor& descriptor,
    DWORD childPid,
    DWORD timeoutMs,
    std::string& failureCode,
    std::string& failureMessage)
{
    failureCode.clear();
    failureMessage.clear();
    if(!child)
    {
        failureCode = "child_broker_internal_error";
        failureMessage = "the child handoff state is unavailable";
        return false;
    }
    const ULONGLONG deadline = nowTickMs() + timeoutMs;
    while(nowTickMs() < deadline)
    {
        ChildHttpResponse response;
        {
            std::lock_guard<std::mutex> lock(child->mutex);
            ++child->preEntryPolls;
        }
        if(childBrokerHttpRequest(descriptor, "GET",
                "/Debug/SessionState?includeHistory=false&historyLimit=0",
                {}, true, response))
        {
            {
                std::lock_guard<std::mutex> lock(child->mutex);
                child->preEntryLastHttpStatus = response.status;
                child->preEntryLastObservation = response.body.substr(0, 160);
            }
            const std::string pidMarker = std::string("\"processId\":") + std::to_string(childPid);
            if(response.body.find(pidMarker) != std::string::npos
                && response.body.find("\"paused\":true") != std::string::npos
                && response.body.find("MCP child first user instruction") != std::string::npos)
                return true;

            bool exited = false;
            bool debugging = true;
            childBrokerJsonBoolField(response.body, "exited", exited);
            childBrokerJsonBoolField(response.body, "debugging", debugging);
            if(exited || !debugging)
            {
                failureCode = "child_exited_before_pre_entry";
                failureMessage = "the child exited before its first user instruction rendezvous";
                std::lock_guard<std::mutex> lock(child->mutex);
                child->preEntryLastObservation = failureMessage;
                return false;
            }

            // A freshly attached x64dbg instance first stops on its normal
            // system breakpoint.  The child remains suspended until the
            // secondary debugger consumes that event; advance only this
            // exact initial breakpoint and fail closed on any other stop.
            if(response.body.find("\"lastEventType\":\"exception\"") != std::string::npos
                && response.body.find("\"exceptionCode\":\"0x80000003\"") != std::string::npos
                && response.body.find(pidMarker) != std::string::npos)
            {
                std::string sessionId;
                std::string targetSha256;
                uint64_t generation = 0;
                uint64_t processId = 0;
                uint64_t eventSeq = 0;
                if(!childBrokerJsonStringField(response.body, "sessionId", sessionId)
                    || !childBrokerJsonUintField(response.body, "generation", generation)
                    || !childBrokerJsonUintField(response.body, "eventSeq", eventSeq)
                    || !childBrokerJsonStringField(response.body, "imageSha256", targetSha256)
                    || !childBrokerHexToken(targetSha256)
                    || !childBrokerJsonUintField(response.body, "processId", processId)
                    || processId != childPid)
                {
                    failureCode = "child_session_identity_unavailable";
                    failureMessage = "the child session identity could not be proven before resume";
                    return false;
                }
                ChildHttpResponse resumeResponse;
                {
                    std::lock_guard<std::mutex> lock(child->mutex);
                    ++child->preEntryResumeAttempts;
                }
                if(!childBrokerHttpRequest(descriptor, "POST", "/Debug/Run", {},
                        true, resumeResponse, sessionId, generation,
                        static_cast<DWORD>(processId), targetSha256, eventSeq))
                {
                    std::lock_guard<std::mutex> lock(child->mutex);
                    child->preEntryLastHttpStatus = resumeResponse.status;
                    child->preEntryLastObservation = "initial breakpoint resume request failed";
                    failureCode = "child_initial_breakpoint_resume_failed";
                    failureMessage = "the child debugger rejected the guarded initial-breakpoint resume";
                    return false;
                }
                {
                    std::lock_guard<std::mutex> lock(child->mutex);
                    child->preEntryLastHttpStatus = resumeResponse.status;
                    child->preEntryLastObservation = "initial breakpoint resume submitted";
                }
            }
            else if(response.body.find("\"paused\":true") != std::string::npos
                && response.body.find("\"exited\":false") != std::string::npos)
            {
                // Do not blindly run through an unrelated user breakpoint or
                // exception while proving the handoff.
                failureCode = "child_unexpected_pre_entry_pause";
                failureMessage = "the child paused for an unrelated event before its entry rendezvous";
                return false;
            }
        }
        Sleep(75);
    }
    failureCode = "child_pre_entry_pause_timeout";
    failureMessage = "the child debugger did not prove its one-shot entry breakpoint before timeout";
    return false;
}

static bool childBrokerResumeAfterPreEntry(
    const std::shared_ptr<ChildBrokerChild>& child,
    const ChildBridgeDescriptor& descriptor,
    DWORD childPid,
    std::string& failureCode,
    std::string& failureMessage)
{
    failureCode.clear();
    failureMessage.clear();
    if(!child)
    {
        failureCode = "child_broker_internal_error";
        failureMessage = "the child handoff state is unavailable";
        return false;
    }
    {
        std::lock_guard<std::mutex> lock(child->mutex);
        child->autoResumeAttempted = true;
    }
    ChildHttpResponse stateResponse;
    if(!childBrokerHttpRequest(descriptor, "GET",
            "/Debug/SessionState?includeHistory=false&historyLimit=0",
            {}, true, stateResponse))
    {
        failureCode = "child_pre_entry_state_unavailable";
        failureMessage = "the proven child entry state could not be read for auto-resume";
        return false;
    }
    const std::string pidMarker = std::string("\"processId\":")
        + std::to_string(childPid);
    if(stateResponse.body.find(pidMarker) == std::string::npos
        || stateResponse.body.find("\"paused\":true") == std::string::npos
        || stateResponse.body.find("MCP child first user instruction") == std::string::npos)
    {
        failureCode = "child_pre_entry_state_changed";
        failureMessage = "the child entry pause changed before the guarded auto-resume";
        return false;
    }
    std::string sessionId;
    std::string targetSha256;
    uint64_t generation = 0;
    uint64_t processId = 0;
    uint64_t eventSeq = 0;
    if(!childBrokerJsonStringField(stateResponse.body, "sessionId", sessionId)
        || !childBrokerJsonUintField(stateResponse.body, "generation", generation)
        || !childBrokerJsonUintField(stateResponse.body, "eventSeq", eventSeq)
        || !childBrokerJsonStringField(stateResponse.body, "imageSha256", targetSha256)
        || !childBrokerHexToken(targetSha256)
        || !childBrokerJsonUintField(stateResponse.body, "processId", processId)
        || processId != childPid)
    {
        failureCode = "child_session_identity_unavailable";
        failureMessage = "the child session identity could not be proven for auto-resume";
        return false;
    }
    ChildHttpResponse resumeResponse;
    if(!childBrokerHttpRequest(descriptor, "POST", "/Debug/Run", {},
            true, resumeResponse, sessionId, generation,
            static_cast<DWORD>(processId), targetSha256, eventSeq))
    {
        failureCode = "child_pre_entry_auto_resume_failed";
        failureMessage = "the child debugger rejected the guarded entry auto-resume";
        return false;
    }
    {
        std::lock_guard<std::mutex> lock(child->mutex);
        child->autoResumeSucceeded = true;
        child->preEntryLastHttpStatus = resumeResponse.status;
        child->preEntryLastObservation = "entry auto-resume submitted";
    }
    return true;
}

static void childBrokerHandoffWorker(const std::shared_ptr<ChildBrokerChild>& child)
{
    if(!child)
        return;
    std::string policy;
    mcpchild::Policy requestedPolicy = mcpchild::Policy::None;
    {
        std::lock_guard<std::mutex> lock(g_childBroker.mutex);
        requestedPolicy = g_childBroker.policy;
        policy = g_childBroker.policyName == "attach-first"
            ? "none" : g_childBroker.policyName;
    }
    const bool pauseOnCreate =
        mcpchild::policyRequiresPreEntryPause(requestedPolicy);
    bool success = false;
    std::string failureCode = "child_broker_handoff_failed";
    std::string failureMessage =
        "child debugger did not attach and prove a pre-entry pause";
    ChildBridgeDescriptor descriptor;
    do
    {
        {
            std::lock_guard<std::mutex> lock(child->mutex);
            child->phase = "spawning_debugger";
        }
        if(!childBrokerSpawnDebugger(child, policy))
        {
            failureCode = "child_debugger_spawn_failed";
            failureMessage = "the matching x32/x64 debugger instance could not be started";
            break;
        }
        DWORD debuggerPid = 0;
        {
            std::lock_guard<std::mutex> lock(child->mutex);
            debuggerPid = child->debuggerPid;
        }
        ULONGLONG debuggerStartTime = 0;
        {
            std::lock_guard<std::mutex> lock(child->mutex);
            debuggerStartTime = childBrokerProcessStartTime(
                child->debuggerProcessHandle);
        }
        if(debuggerStartTime == 0)
        {
            failureCode = "child_debugger_identity_unavailable";
            failureMessage = "the spawned debugger process start time is unavailable";
            break;
        }
        if(!childBrokerWaitForDescriptor(debuggerPid, descriptor, 15000u))
        {
            failureCode = "child_bridge_descriptor_timeout";
            failureMessage = "the spawned debugger did not publish an authenticated descriptor";
            break;
        }
        if(descriptor.processStartTime100ns != debuggerStartTime)
        {
            failureCode = "child_bridge_descriptor_stale";
            failureMessage = "the child bridge descriptor does not match the debugger process";
            break;
        }
        {
            std::lock_guard<std::mutex> lock(child->mutex);
            child->phase = "descriptor_verified";
        }
        if(!childBrokerWaitForAttached(descriptor, debuggerPid,
                                      child->pid, 15000u))
        {
            failureCode = "child_debugger_attach_timeout";
            failureMessage = "the secondary debugger did not prove attachment to the child PID";
            break;
        }
        {
            std::lock_guard<std::mutex> lock(child->mutex);
            child->debuggerAttached = true;
            child->identityVerified = descriptor.pid == debuggerPid
                && descriptor.arch == child->architecture;
            child->phase = "debugger_attached";
        }
        if(!child->identityVerified)
        {
            failureCode = "child_debugger_identity_mismatch";
            failureMessage = "the secondary debugger architecture or process identity mismatched";
            break;
        }
        bool brokerOwnedSuspension = true;
        {
            std::lock_guard<std::mutex> lock(child->mutex);
            brokerOwnedSuspension = child->brokerOwnedSuspension;
        }
        const DWORD previous = ResumeThread(child->threadHandle);
        DWORD releaseCalls = previous == static_cast<DWORD>(-1) ? 0u : 1u;
        bool fullyReleased = previous != static_cast<DWORD>(-1)
            && previous != 0 && previous <= 32u;
        if(fullyReleased)
        {
            // The broker adds one barrier count before allowing the parent
            // create wrapper to finish.  An explicit caller-owned
            // CREATE_SUSPENDED count may remain underneath it. Temporarily
            // release every count so the entry breakpoint can be reached.
            for(DWORD expected = previous - 1u; expected > 0; --expected)
            {
                const DWORD observed = ResumeThread(child->threadHandle);
                ++releaseCalls;
                if(observed == static_cast<DWORD>(-1) || observed != expected)
                {
                    fullyReleased = false;
                    break;
                }
            }
        }
        const DWORD preserveSuspensions = fullyReleased && !brokerOwnedSuspension
            ? previous - 1u : 0u;
        {
            std::lock_guard<std::mutex> lock(child->mutex);
            child->resumeAttempted = true;
            child->resumePreviousSuspendCount = previous;
            child->resumeReleaseCalls = releaseCalls;
            child->preservedSuspensionCount = preserveSuspensions;
            child->resumeSucceeded = fullyReleased;
            child->phase = "child_thread_resume_submitted";
        }
        if(!fullyReleased)
        {
            failureCode = "child_thread_resume_failed";
            failureMessage = previous == static_cast<DWORD>(-1)
                ? "ResumeThread failed for the broker suspension"
                : (previous == 0
                    ? "the broker suspension was already released"
                    : "the child suspension count changed unexpectedly during release");
            break;
        }
        {
            std::lock_guard<std::mutex> lock(child->mutex);
            child->phase = "waiting_pre_entry_pause";
        }
        std::string preEntryFailureCode;
        std::string preEntryFailureMessage;
        if(!childBrokerWaitForPreEntryPause(
                child, descriptor, child->pid, 15000u,
                preEntryFailureCode, preEntryFailureMessage))
        {
            failureCode = preEntryFailureCode.empty()
                ? "child_pre_entry_pause_failed" : preEntryFailureCode;
            failureMessage = preEntryFailureMessage.empty()
                ? "the child debugger did not prove its one-shot entry breakpoint"
                : preEntryFailureMessage;
            break;
        }
        if(preserveSuspensions > 0)
        {
            DWORD restorePrevious = 0;
            bool restoreSucceeded = true;
            for(DWORD index = 0; index < preserveSuspensions; ++index)
            {
                restorePrevious = SuspendThread(child->threadHandle);
                if(restorePrevious == static_cast<DWORD>(-1))
                {
                    restoreSucceeded = false;
                    break;
                }
            }
            {
                std::lock_guard<std::mutex> lock(child->mutex);
                child->suspensionRestoreAttempted = true;
                child->suspensionRestorePreviousCount = restorePrevious;
                child->suspensionRestoreSucceeded = restoreSucceeded;
            }
            if(!restoreSucceeded)
            {
                failureCode = "child_thread_suspension_restore_failed";
                failureMessage = "the caller-owned CreateProcess suspension could not be restored";
                break;
            }
        }
        {
            std::lock_guard<std::mutex> lock(child->mutex);
            child->preEntryPaused = true;
            child->phase = pauseOnCreate
                ? "attached_pre_entry_paused" : "entry_pause_proven";
        }
        if(!pauseOnCreate)
        {
            std::string autoResumeFailureCode;
            std::string autoResumeFailureMessage;
            if(!childBrokerResumeAfterPreEntry(
                    child, descriptor, child->pid,
                    autoResumeFailureCode, autoResumeFailureMessage))
            {
                failureCode = autoResumeFailureCode.empty()
                    ? "child_pre_entry_auto_resume_failed"
                    : autoResumeFailureCode;
                failureMessage = autoResumeFailureMessage.empty()
                    ? "the child could not be resumed after its proven entry rendezvous"
                    : autoResumeFailureMessage;
                break;
            }
            std::lock_guard<std::mutex> lock(child->mutex);
            child->phase = "attached_running";
        }
        success = true;
    } while(false);

    if(!success)
    {
        std::lock_guard<std::mutex> lock(child->mutex);
        child->phase = "failed";
        child->errorCode = failureCode;
        child->errorMessage = failureMessage;
        if(child->debuggerProcessHandle)
            TerminateProcess(child->debuggerProcessHandle, 1);
        if(child->processHandle)
            TerminateProcess(child->processHandle, 1);
        if(child->debuggerProcessHandle)
        {
            WaitForSingleObject(child->debuggerProcessHandle, 1000);
            CloseHandle(child->debuggerProcessHandle);
            child->debuggerProcessHandle = nullptr;
        }
        if(child->threadHandle)
        {
            CloseHandle(child->threadHandle);
            child->threadHandle = nullptr;
        }
        if(child->processHandle)
        {
            CloseHandle(child->processHandle);
            child->processHandle = nullptr;
        }
    }
    if(!success)
        childBrokerRollbackReservation(child);
    // The parent is held at the first user-module return after its create
    // wrapper completed. On failure the child is broker-owned and killed; on
    // success it is paused under its own debugger. Either way, release the
    // parent without allowing a second resume from a stale callback.
    if(!g_childBroker.stopping.load(std::memory_order_acquire))
        DbgCmdExec("run");
}

void childBrokerConfigureFromEnvironment()
{
    const std::string requested = childBrokerEnvironmentValue(L"X64DBG_MCP_BROKER_POLICY");
    if(requested.empty())
        return;
    const auto parsed = mcpchild::parsePolicy(requested);
    if(!parsed.ok)
    {
        _plugin_logprintf("[MCP child] invalid broker policy from environment: %s\n",
                          parsed.error.c_str());
        return;
    }
    std::lock_guard<std::mutex> lock(g_childBroker.mutex);
    g_childBroker.policy = parsed.policy;
    g_childBroker.policyName = parsed.canonical;
    g_childBroker.brokerId = childBrokerEnvironmentValue(L"X64DBG_MCP_BROKER_ID");
    g_childBroker.rootLaunchId = childBrokerEnvironmentValue(L"X64DBG_MCP_BROKER_ROOT_LAUNCH_ID");
    uint64_t rootPid = 0;
    uint64_t parentPid = 0;
    const std::string rootPidText =
        childBrokerEnvironmentValue(L"X64DBG_MCP_BROKER_ROOT_PID");
    const std::string parentPidText =
        childBrokerEnvironmentValue(L"X64DBG_MCP_BROKER_PARENT_PID");
    const bool parentPidOk =
        mcpbridge::parseUnsignedDecimalExact(parentPidText, parentPid)
        && parentPid <= std::numeric_limits<DWORD>::max();
    const bool rootPidOk =
        mcpbridge::parseUnsignedDecimalExact(rootPidText, rootPid)
        && rootPid <= std::numeric_limits<DWORD>::max();
    if(rootPidOk)
        g_childBroker.rootPid = static_cast<DWORD>(rootPid);
    else if(parentPidOk)
        g_childBroker.rootPid = static_cast<DWORD>(parentPid);
    else
        g_childBroker.rootPid = 0;
    g_childBroker.parentPid = parentPidOk
        ? static_cast<DWORD>(parentPid) : 0;
    g_childBroker.quota.policy = parsed.policy;
    g_childBroker.configured = parsed.policy != mcpchild::Policy::None;
    g_childBroker.stopping.store(false, std::memory_order_release);
}

bool childBrokerConfigureForLaunch(const std::string& policy,
                                   const std::string& rootLaunchId,
                                   DWORD rootPid,
                                   std::string& errorCode,
                                   std::string& errorMessage)
{
    const auto parsed = mcpchild::parsePolicy(policy);
    if(!parsed.ok)
    {
        errorCode = parsed.errorCode;
        errorMessage = parsed.error;
        return false;
    }
    {
        std::lock_guard<std::mutex> lock(g_childBroker.mutex);
        g_childBroker.policy = parsed.policy;
        g_childBroker.policyName = parsed.canonical;
        g_childBroker.rootLaunchId = rootLaunchId;
        g_childBroker.rootPid = rootPid;
        g_childBroker.parentPid = 0;
        g_childBroker.brokerId = mcpbridge::createGuidString();
        g_childBroker.quota = mcpchild::ChildQuota{parsed.policy, 0, 0};
        g_childBroker.configured = parsed.policy != mcpchild::Policy::None;
        g_childBroker.stopping.store(false, std::memory_order_release);
    }
    if(parsed.policy == mcpchild::Policy::None)
    {
        childBrokerDisableEntryBreakpoint();
        return true;
    }
    return childBrokerInstallEntryBreakpoint(errorCode, errorMessage);
}

static void childBrokerObserveDescendantPolicyReady()
{
    bool needsEntryHook = false;
    {
        std::lock_guard<std::mutex> lock(g_childBroker.mutex);
        needsEntryHook = g_childBroker.configured
            && !g_childBroker.entryBreakpointInstalled
            && !(g_childBroker.policy == mcpchild::Policy::AttachFirst
                && g_childBroker.quota.acceptedDirectChildren != 0);
    }
    if(!needsEntryHook)
        return;
    std::string errorCode;
    std::string errorMessage;
    if(!childBrokerInstallEntryBreakpoint(errorCode, errorMessage))
    {
        _plugin_logprintf(
            "[MCP child] descendant policy hook pending: %s: %s\n",
            errorCode.c_str(), errorMessage.c_str());
    }
}

void childBrokerObserveSessionReady()
{
    if(!childBrokerAutoEntryFromEnvironment())
        return;
    {
        std::lock_guard<std::mutex> lock(g_childBroker.mutex);
        if(g_childBroker.autoEntryBreakpointInstalled)
            return;
        ++g_childBroker.autoEntryResolveAttempts;
    }

    // CB_CREATEPROCESS/CB_ATTACH can precede publication of the executable
    // module and make $exentry temporarily evaluate to zero.  This function
    // is intentionally retried from later PAUSEDEBUG/LOADDLL callbacks.
    duint entry = 0;
    if(!resolveCurrentModuleAddress(true, entry))
        entry = DbgValFromString("$exentry");
    if(!entry)
        return;

    {
        std::lock_guard<std::mutex> lock(g_childBroker.mutex);
        ++g_childBroker.autoEntryInstallAttempts;
    }

    BRIDGEBP existing = {};
    const bool alreadyPresent = childBrokerFindSoftwareBreakpoint(entry, &existing);
    char command[256] = {};
    bool submitted = true;
    if(!alreadyPresent)
    {
        _snprintf_s(command, sizeof(command), _TRUNCATE,
                    "bp 0x%llx", static_cast<unsigned long long>(entry));
        submitted = DbgCmdExecDirect(command);
    }
    if(submitted)
    {
        _snprintf_s(command, sizeof(command), _TRUNCATE,
                    "SetBreakpointName 0x%llx,\"MCP child first user instruction\"",
                    static_cast<unsigned long long>(entry));
        submitted = DbgCmdExecDirect(command);
    }
    if(submitted)
    {
        _snprintf_s(command, sizeof(command), _TRUNCATE,
                    "SetBreakpointSingleshoot 0x%llx,1",
                    static_cast<unsigned long long>(entry));
        submitted = DbgCmdExecDirect(command);
    }

    BRIDGEBP installed = {};
    const bool verified = submitted
        && childBrokerFindSoftwareBreakpoint(entry, &installed)
        && installed.singleshoot
        && std::string(installed.name).find(
            "MCP child first user instruction") != std::string::npos;
    {
        std::lock_guard<std::mutex> lock(g_childBroker.mutex);
        g_childBroker.autoEntryBreakpointInstalled = verified;
        g_childBroker.autoEntryBreakpointAddress = verified ? entry : 0;
        g_childBroker.autoEntryLastError = verified
            ? std::string()
            : (submitted
                ? "entry breakpoint verification failed"
                : "x64dbg rejected the entry breakpoint command");
    }
    if(verified)
    {
        _plugin_logprintf(
            "[MCP child] one-shot entry rendezvous armed at %p in PID %lu\n",
            reinterpret_cast<void*>(entry), DbgGetProcessId());
    }
    else
    {
        _plugin_logprintf(
            "[MCP child] entry rendezvous retry pending for %p in PID %lu\n",
            reinterpret_cast<void*>(entry), DbgGetProcessId());
    }
}

static bool childBrokerHandleParentHandoff(const PLUG_CB_BREAKPOINT* info)
{
    if(!info || !info->breakpoint)
        return false;
    const DWORD threadId = DbgGetThreadId();
    const duint address = info->breakpoint->addr;
    ChildBrokerPendingHandoff pending;
    bool found = false;
    {
        std::lock_guard<std::mutex> lock(g_childBroker.mutex);
        for(auto it = g_childBroker.pendingHandoffs.begin();
            it != g_childBroker.pendingHandoffs.end(); ++it)
        {
            if(it->second.threadId == threadId
                && it->second.address == address)
            {
                pending = it->second;
                g_childBroker.pendingHandoffs.erase(it);
                found = true;
                break;
            }
        }
    }
    if(!found || !pending.child)
        return false;

    {
        std::lock_guard<std::mutex> childLock(pending.child->mutex);
        pending.child->parentBarrierReached = true;
        pending.child->phase = "parent_create_return_reached";
    }

    bool workerStarted = false;
    try
    {
        std::lock_guard<std::mutex> lock(g_childBroker.mutex);
        if(!g_childBroker.stopping.load(std::memory_order_acquire))
        {
            g_childBroker.workerThreads.emplace_back(
                childBrokerHandoffWorker, pending.child);
            workerStarted = true;
        }
    }
    catch(...)
    {
        workerStarted = false;
    }
    if(!workerStarted)
    {
        {
            std::lock_guard<std::mutex> childLock(pending.child->mutex);
            pending.child->phase = "failed";
            pending.child->errorCode = "child_handoff_worker_start_failed";
            pending.child->errorMessage =
                "the secondary debugger handoff worker could not be started";
            if(pending.child->processHandle)
                TerminateProcess(pending.child->processHandle, 1);
        }
        childBrokerRollbackReservation(pending.child);
        DbgCmdExec("run");
    }
    return true;
}

void childBrokerHandleBreakpoint(PLUG_CB_BREAKPOINT* info)
{
    if(!info || !info->breakpoint)
        return;
    if(childBrokerHandleParentHandoff(info))
        return;
    bool isEntryHook = false;
    {
        std::lock_guard<std::mutex> lock(g_childBroker.mutex);
        isEntryHook = g_childBroker.configured
            && g_childBroker.entryBreakpointInstalled
            && info->breakpoint->addr == g_childBroker.entryBreakpointAddress;
    }
    if(isEntryHook)
    {
        childBrokerCaptureEntryInterception(info);
        return;
    }
    if(std::string(info->breakpoint->name).find("MCP child first user instruction") != std::string::npos)
    {
        _plugin_logprintf("[MCP child] pre-entry breakpoint reached in PID %lu\n",
                          DbgGetProcessId());
    }
}

void childBrokerHandleStepped()
{
    const DWORD threadId = DbgGetThreadId();
    ChildBrokerInterception interception;
    {
        std::lock_guard<std::mutex> lock(g_childBroker.mutex);
        const auto it = g_childBroker.interceptions.find(threadId);
        if(it == g_childBroker.interceptions.end())
            return;
        interception = it->second;
    }

    REGDUMP_AVX512 registers = {};
    if(!DbgGetRegDumpEx(&registers, sizeof(registers)))
    {
        std::lock_guard<std::mutex> lock(g_childBroker.mutex);
        g_childBroker.interceptions.erase(threadId);
        mcpchild::rollbackChildReservation(g_childBroker.quota, true);
        childBrokerWriteWord(interception.threadFlagsAddress,
                             interception.originalThreadFlags);
        DbgCmdExec("run");
        return;
    }
    const duint ip = static_cast<duint>(registers.regcontext.cip);
    const duint sp = static_cast<duint>(registers.regcontext.csp);
    if(ip != interception.returnAddress && sp <= interception.entryStack)
    {
        // The syscall/loader has not returned yet. Keep the interception
        // associated with this exact thread and single-step once more.
        DbgCmdExec("sti");
        return;
    }
    {
        std::lock_guard<std::mutex> lock(g_childBroker.mutex);
        g_childBroker.interceptions.erase(threadId);
    }

    // The forced CREATE_SUSPENDED bit is only for the handoff. Restore the
    // original argument before the parent continues.
    childBrokerWriteWord(interception.threadFlagsAddress,
                         interception.originalThreadFlags);

    DWORD childPid = 0;
    DWORD childTid = 0;
    HANDLE childProcess = nullptr;
    HANDLE childThread = nullptr;
    if(!childBrokerProcessHandleFromReturn(interception, childPid, childTid,
                                           childProcess, childThread))
    {
        std::lock_guard<std::mutex> lock(g_childBroker.mutex);
        mcpchild::rollbackChildReservation(g_childBroker.quota, true);
        DbgCmdExec("run");
        return;
    }

    bool childIsX64 = false;
    const ULONGLONG creationTime = childBrokerProcessStartTime(childProcess);
    if(!childBrokerTargetIsX64(childProcess, childIsX64) || creationTime == 0)
    {
        TerminateProcess(childProcess, 1);
        CloseHandle(childProcess);
        CloseHandle(childThread);
        std::lock_guard<std::mutex> lock(g_childBroker.mutex);
        mcpchild::rollbackChildReservation(g_childBroker.quota, true);
        DbgCmdExec("run");
        return;
    }
    wchar_t imagePath[32768] = {};
    DWORD imageLength = _countof(imagePath);
    std::string imageUtf8;
    if(QueryFullProcessImageNameW(childProcess, 0, imagePath, &imageLength))
        imageUtf8 = wideToUtf8(std::wstring(imagePath, imageLength));
    std::string brokerId;
    std::string launchId;
    {
        std::lock_guard<std::mutex> lock(g_childBroker.mutex);
        brokerId = g_childBroker.brokerId;
        launchId = g_childBroker.rootLaunchId;
    }
    auto child = std::make_shared<ChildBrokerChild>();
    child->childId = brokerId + ":" + std::to_string(childPid) + ":"
        + std::to_string(creationTime);
    child->parentLaunchId = launchId;
    child->parentPid = DbgGetProcessId();
    child->pid = childPid;
    child->tid = childTid;
    child->creationTime100ns = creationTime;
    child->imagePath = imageUtf8;
    child->architecture = childIsX64 ? "x64" : "x86";
    child->directChild = interception.directChild;
    child->quotaReservationActive = true;
    child->brokerOwnedSuspension = (interception.originalThreadFlags & 1u) == 0;
    child->processHandle = childProcess;
    child->threadHandle = childThread;

    duint handoffAddress = 0;
    bool ownsHandoffBreakpoint = false;
    std::string handoffErrorCode;
    std::string handoffErrorMessage;
    bool handoffReady = childBrokerFindUserReturnAddress(handoffAddress)
        && childBrokerInstallParentHandoffBreakpoint(
            handoffAddress, interception.token, ownsHandoffBreakpoint,
            handoffErrorCode, handoffErrorMessage);
    if(!handoffReady && handoffErrorCode.empty())
    {
        handoffErrorCode = "child_parent_handoff_return_unresolved";
        handoffErrorMessage = "no user-module return frame was found for the parent create wrapper";
    }

    DWORD suspendPrevious = static_cast<DWORD>(-1);
    if(handoffReady)
    {
        // Do not attach a debugger while CreateProcessInternalW is still
        // completing CSRSS/base initialization. Add one broker-owned suspend
        // count, let the parent wrapper finish, and attach only after its
        // first user-module return. The wrapper may consume its own internal
        // count, but cannot consume this additional barrier.
        suspendPrevious = SuspendThread(childThread);
        handoffReady = suspendPrevious != static_cast<DWORD>(-1);
        if(!handoffReady)
        {
            handoffErrorCode = "child_parent_handoff_suspend_failed";
            handoffErrorMessage = "the broker could not add its parent-wrapper barrier suspension";
        }
    }

    child->parentBarrierArmed = handoffReady;
    child->parentHandoffAddress = handoffAddress;
    child->parentHandoffBreakpointOwned = ownsHandoffBreakpoint;
    child->brokerSuspendIncremented = handoffReady;
    child->brokerSuspendPreviousCount = suspendPrevious;
    child->phase = handoffReady
        ? "waiting_parent_create_return" : "handoff_barrier_failed";

    bool registered = false;
    try
    {
        std::lock_guard<std::mutex> lock(g_childBroker.mutex);
        if(handoffReady
            && !g_childBroker.stopping.load(std::memory_order_acquire))
        {
            g_childBroker.children.push_back(child);
            ChildBrokerPendingHandoff pending;
            pending.token = interception.token;
            pending.threadId = threadId;
            pending.address = handoffAddress;
            pending.ownsBreakpoint = ownsHandoffBreakpoint;
            pending.child = child;
            g_childBroker.pendingHandoffs[interception.token] =
                std::move(pending);
            registered = true;
        }
    }
    catch(...)
    {
        registered = false;
    }

    if(registered && DbgCmdExec("run"))
        return;

    // Preserve the target's original semantics when a safe handoff barrier
    // cannot be established. Undo only counts introduced by the broker and
    // leave CreateProcessInternalW's own count for the wrapper to consume.
    {
        std::lock_guard<std::mutex> lock(g_childBroker.mutex);
        g_childBroker.pendingHandoffs.erase(interception.token);
        g_childBroker.children.erase(
            std::remove(g_childBroker.children.begin(),
                        g_childBroker.children.end(), child),
            g_childBroker.children.end());
    }
    childBrokerRollbackReservation(child);
    if(ownsHandoffBreakpoint)
        childBrokerRemoveOwnedSoftwareBreakpoint(handoffAddress);
    if(handoffReady)
        ResumeThread(childThread);
    if(child->brokerOwnedSuspension)
        ResumeThread(childThread);
    CloseHandle(childProcess);
    CloseHandle(childThread);
    child->processHandle = nullptr;
    child->threadHandle = nullptr;
    _plugin_logprintf("[MCP child] handoff barrier failed: %s: %s\n",
                      handoffErrorCode.c_str(), handoffErrorMessage.c_str());

    std::string ignoredCode;
    std::string ignoredMessage;
    bool reinstallEntryHook = false;
    {
        std::lock_guard<std::mutex> lock(g_childBroker.mutex);
        reinstallEntryHook = g_childBroker.policyName == "attach-first";
        if(reinstallEntryHook)
            g_childBroker.entryBreakpointInstalled = false;
    }
    if(reinstallEntryHook)
        childBrokerInstallEntryBreakpoint(ignoredCode, ignoredMessage);
    DbgCmdExec("run");
}

void childBrokerStop(bool terminateOwnedDebuggers)
{
    g_childBroker.stopping.store(true, std::memory_order_release);
    childBrokerDisableEntryBreakpoint();
    std::vector<std::shared_ptr<ChildBrokerChild>> children;
    std::vector<std::thread> workers;
    std::vector<ChildBrokerPendingHandoff> pendingHandoffs;
    {
        std::lock_guard<std::mutex> lock(g_childBroker.mutex);
        children.swap(g_childBroker.children);
        workers.swap(g_childBroker.workerThreads);
        pendingHandoffs.reserve(g_childBroker.pendingHandoffs.size());
        for(auto& item : g_childBroker.pendingHandoffs)
            pendingHandoffs.push_back(std::move(item.second));
        g_childBroker.pendingHandoffs.clear();
        g_childBroker.interceptions.clear();
        g_childBroker.configured = false;
        g_childBroker.policy = mcpchild::Policy::None;
        g_childBroker.policyName = "none";
    }
    for(const auto& pending : pendingHandoffs)
    {
        if(pending.ownsBreakpoint)
            childBrokerRemoveOwnedSoftwareBreakpoint(pending.address);
        if(pending.child)
        {
            std::lock_guard<std::mutex> childLock(pending.child->mutex);
            if(pending.child->processHandle)
                TerminateProcess(pending.child->processHandle, 1);
            pending.child->phase = "stopping";
        }
    }
    // Workers use the broker mutex while polling their child debugger. Join
    // only after releasing it, otherwise shutdown can deadlock permanently.
    for(auto& worker : workers)
    {
        if(worker.joinable())
            worker.join();
    }
    for(const auto& child : children)
    {
        if(!child)
            continue;
        std::lock_guard<std::mutex> lock(child->mutex);
        if(terminateOwnedDebuggers && child->debuggerProcessHandle)
            TerminateProcess(child->debuggerProcessHandle, 1);
        if(child->debuggerProcessHandle) CloseHandle(child->debuggerProcessHandle);
        if(child->threadHandle) CloseHandle(child->threadHandle);
        if(child->processHandle) CloseHandle(child->processHandle);
        child->debuggerProcessHandle = nullptr;
        child->threadHandle = nullptr;
        child->processHandle = nullptr;
    }
    // Children that reached the worker are retained in ``children``; a
    // pending handoff is normally present there as well, but call the helper
    // for both collections so an exceptional registration path cannot leak a
    // quota reservation.  The helper is idempotent.
    for(const auto& pending : pendingHandoffs)
        childBrokerRollbackReservation(pending.child);
    for(const auto& child : children)
        childBrokerRollbackReservation(child);
}

static std::string buildChildBrokerStateJson()
{
    std::string policy;
    std::string brokerId;
    std::string rootLaunchId;
    DWORD rootPid = 0;
    DWORD parentPid = 0;
    bool configured = false;
    bool entryBreakpointInstalled = false;
    duint entryBreakpointAddress = 0;
    bool autoEntryBreakpointInstalled = false;
    duint autoEntryBreakpointAddress = 0;
    uint32_t autoEntryResolveAttempts = 0;
    uint32_t autoEntryInstallAttempts = 0;
    std::string autoEntryLastError;
    bool stopping = false;
    uint64_t acceptedDirectChildren = 0;
    uint64_t acceptedDescendants = 0;
    size_t pendingHandoffCount = 0;
    std::vector<std::shared_ptr<ChildBrokerChild>> children;
    {
        std::lock_guard<std::mutex> lock(g_childBroker.mutex);
        policy = g_childBroker.policyName;
        brokerId = g_childBroker.brokerId;
        rootLaunchId = g_childBroker.rootLaunchId;
        rootPid = g_childBroker.rootPid;
        parentPid = g_childBroker.parentPid;
        configured = g_childBroker.configured;
        entryBreakpointInstalled = g_childBroker.entryBreakpointInstalled;
        entryBreakpointAddress = g_childBroker.entryBreakpointAddress;
        autoEntryBreakpointInstalled =
            g_childBroker.autoEntryBreakpointInstalled;
        autoEntryBreakpointAddress = g_childBroker.autoEntryBreakpointAddress;
        autoEntryResolveAttempts = g_childBroker.autoEntryResolveAttempts;
        autoEntryInstallAttempts = g_childBroker.autoEntryInstallAttempts;
        autoEntryLastError = g_childBroker.autoEntryLastError;
        stopping = g_childBroker.stopping.load(std::memory_order_acquire);
        acceptedDirectChildren = g_childBroker.quota.acceptedDirectChildren;
        acceptedDescendants = g_childBroker.quota.acceptedDescendants;
        pendingHandoffCount = g_childBroker.pendingHandoffs.size();
        children = g_childBroker.children;
    }
    std::stringstream ss;
    ss << "{\"ok\":true,\"broker\":{";
    ss << "\"configured\":" << (configured ? "true" : "false") << ",";
    ss << "\"stopping\":" << (stopping ? "true" : "false") << ",";
    ss << "\"policy\":\"" << escapeJsonString(policy.c_str()) << "\",";
    ss << "\"brokerId\":\"" << escapeJsonString(brokerId.c_str()) << "\",";
    ss << "\"rootLaunchId\":\"" << escapeJsonString(rootLaunchId.c_str()) << "\",";
    ss << "\"rootPid\":" << rootPid << ",";
    ss << "\"parentPid\":" << parentPid << ",";
    ss << "\"entryBreakpointInstalled\":"
       << (entryBreakpointInstalled ? "true" : "false") << ",";
    ss << "\"entryBreakpointAddress\":\"0x" << std::hex
       << entryBreakpointAddress << "\",";
    ss << "\"autoEntryBreakpointInstalled\":"
       << (autoEntryBreakpointInstalled ? "true" : "false") << ",";
    ss << "\"autoEntryBreakpointAddress\":\"0x" << std::hex
       << autoEntryBreakpointAddress << "\",";
    ss << "\"autoEntryResolveAttempts\":" << std::dec
       << autoEntryResolveAttempts << ",";
    ss << "\"autoEntryInstallAttempts\":"
       << autoEntryInstallAttempts << ",";
    ss << "\"autoEntryLastError\":\""
       << escapeJsonString(autoEntryLastError.c_str()) << "\",";
    ss << "\"acceptedDirectChildren\":" << std::dec
       << acceptedDirectChildren << ",";
    ss << "\"acceptedDescendants\":" << acceptedDescendants << ",";
    ss << "\"pendingHandoffCount\":" << pendingHandoffCount;
    ss << "},\"children\":[";
    bool first = true;
    for(const auto& child : children)
    {
        if(!child)
            continue;
        std::lock_guard<std::mutex> lock(child->mutex);
        if(!first)
            ss << ",";
        first = false;
        ss << "{";
        ss << "\"childId\":\"" << escapeJsonString(child->childId.c_str()) << "\",";
        ss << "\"parentLaunchId\":\""
           << escapeJsonString(child->parentLaunchId.c_str()) << "\",";
        ss << "\"pid\":" << child->pid << ",\"tid\":" << child->tid
           << ",\"parentPid\":" << child->parentPid << ",";
        ss << "\"creationTime100ns\":" << child->creationTime100ns << ",";
        ss << "\"imagePath\":\"" << escapeJsonString(child->imagePath.c_str()) << "\",";
        ss << "\"architecture\":\"" << escapeJsonString(child->architecture.c_str()) << "\",";
        ss << "\"phase\":\"" << escapeJsonString(child->phase.c_str()) << "\",";
        ss << "\"errorCode\":\"" << escapeJsonString(child->errorCode.c_str()) << "\",";
        ss << "\"errorMessage\":\"" << escapeJsonString(child->errorMessage.c_str()) << "\",";
        ss << "\"identityVerified\":" << (child->identityVerified ? "true" : "false") << ",";
        ss << "\"debuggerSpawned\":" << (child->debuggerSpawned ? "true" : "false") << ",";
        ss << "\"debuggerAttached\":" << (child->debuggerAttached ? "true" : "false") << ",";
        ss << "\"preEntryPaused\":" << (child->preEntryPaused ? "true" : "false") << ",";
        ss << "\"autoResumeAttempted\":"
           << (child->autoResumeAttempted ? "true" : "false") << ",";
        ss << "\"autoResumeSucceeded\":"
           << (child->autoResumeSucceeded ? "true" : "false") << ",";
        ss << "\"brokerOwnedSuspension\":"
           << (child->brokerOwnedSuspension ? "true" : "false") << ",";
        ss << "\"parentBarrierArmed\":"
           << (child->parentBarrierArmed ? "true" : "false") << ",";
        ss << "\"parentBarrierReached\":"
           << (child->parentBarrierReached ? "true" : "false") << ",";
        ss << "\"parentHandoffAddress\":\"0x" << std::hex
           << child->parentHandoffAddress << "\",";
        ss << "\"parentHandoffBreakpointOwned\":"
           << (child->parentHandoffBreakpointOwned ? "true" : "false") << ",";
        ss << "\"brokerSuspendIncremented\":"
           << (child->brokerSuspendIncremented ? "true" : "false") << ",";
        ss << "\"brokerSuspendPreviousCount\":" << std::dec
           << child->brokerSuspendPreviousCount << ",";
        ss << "\"directChild\":"
           << (child->directChild ? "true" : "false") << ",";
        ss << "\"quotaReservationActive\":"
           << (child->quotaReservationActive ? "true" : "false") << ",";
        ss << "\"resumeAttempted\":" << (child->resumeAttempted ? "true" : "false") << ",";
        ss << "\"resumeSucceeded\":" << (child->resumeSucceeded ? "true" : "false") << ",";
        ss << "\"resumePreviousSuspendCount\":"
           << child->resumePreviousSuspendCount << ",";
        ss << "\"resumeReleaseCalls\":" << child->resumeReleaseCalls << ",";
        ss << "\"preservedSuspensionCount\":"
           << child->preservedSuspensionCount << ",";
        ss << "\"suspensionRestoreAttempted\":"
           << (child->suspensionRestoreAttempted ? "true" : "false") << ",";
        ss << "\"suspensionRestoreSucceeded\":"
           << (child->suspensionRestoreSucceeded ? "true" : "false") << ",";
        ss << "\"suspensionRestorePreviousCount\":"
           << child->suspensionRestorePreviousCount << ",";
        ss << "\"preEntryPolls\":" << child->preEntryPolls << ",";
        ss << "\"preEntryResumeAttempts\":" << child->preEntryResumeAttempts << ",";
        ss << "\"preEntryLastHttpStatus\":" << child->preEntryLastHttpStatus << ",";
        ss << "\"preEntryLastObservation\":\""
           << escapeJsonString(child->preEntryLastObservation.c_str()) << "\",";
        ss << "\"debuggerPid\":" << child->debuggerPid;
        ss << "}";
    }
    ss << "]}";
    return ss.str();
}

static bool isPersistedMcpBreakpointName(const char* rawName) noexcept
{
    try
    {
        std::string name = safeString(rawName);
        std::transform(name.begin(), name.end(), name.begin(),
            [](unsigned char value)
            {
                return static_cast<char>(std::tolower(value));
            });
        return name.rfind("mcp_api_trace:", 0) == 0
            || name.rfind("mcp child ", 0) == 0;
    }
    catch(...)
    {
        return false;
    }
}

static bool isActiveMcpBreakpointName(const char* rawName) noexcept
{
    try
    {
        std::string name = safeString(rawName);
        std::transform(name.begin(), name.end(), name.begin(),
            [](unsigned char value)
            {
                return static_cast<char>(std::tolower(value));
            });
        constexpr const char* prefix = "mcp_api_trace:";
        if(name.rfind(prefix, 0) != 0)
            return false;
        const size_t idStart = std::strlen(prefix);
        const size_t idEnd = name.find(':', idStart);
        if(idEnd == std::string::npos || idEnd == idStart)
            return false;
        const std::string traceId = name.substr(idStart, idEnd - idStart);
        std::lock_guard<std::mutex> lock(g_nativeApiTrace.mutex);
        return g_nativeApiTrace.configs.find(traceId)
            != g_nativeApiTrace.configs.end();
    }
    catch(...)
    {
        return false;
    }
}

static size_t purgePersistedMcpBreakpoints() noexcept
{
    try
    {
        BPMAP map = {};
        const int returnedCount = DbgGetBpList(bp_normal, &map);
        // The SDK has shipped builds where DbgGetBpList returns a boolean-ish
        // value while the authoritative number of records is BPMAP::count.
        // Prefer the latter whenever it is populated; using only the return
        // value silently skipped persisted breakpoints on those builds.
        const int count = map.count > 0 ? map.count : returnedCount;
        std::vector<duint> stale;
        if(count > 0 && map.bp)
        {
            stale.reserve(static_cast<size_t>(count));
            for(int index = 0; index < count; ++index)
            {
                if(isPersistedMcpBreakpointName(map.bp[index].name)
                    && !isActiveMcpBreakpointName(map.bp[index].name))
                    stale.push_back(map.bp[index].addr);
            }
        }
        _plugin_logprintf(
            "[MCP] persisted-breakpoint preflight: returned=%d mapCount=%d "
            "records=%d stale=%zu\n",
            returnedCount, map.count, count, stale.size());
        if(map.bp)
            BridgeFree(map.bp);

        size_t removed = 0;
        for(const duint address : stale)
        {
            char command[64] = {};
            _snprintf_s(
                command, sizeof(command), _TRUNCATE,
                "bc 0x%llx",
                static_cast<unsigned long long>(address));
            // The command path is the same path used by x64dbg's own UI and
            // also removes a disabled/inactive breakpoint that the script
            // wrapper may report as already absent.
            bool deleted = DbgCmdExecDirect(command);
            if(!deleted)
                deleted = Script::Debug::DeleteBreakpoint(address);
            if(deleted)
                ++removed;
        }
        if(removed)
        {
            _plugin_logprintf(
                "[MCP] removed %zu persisted MCP-owned breakpoint(s) "
                "before user-code execution\n",
                removed);
        }
        return removed;
    }
    catch(...)
    {
        return 0;
    }
}

void debugSessionCallback(CBTYPE cbType, void* callbackInfo) {
    switch (cbType) {
    case CB_TRACEEXECUTE:
        try {
            recordNativeTraceStep(reinterpret_cast<PLUG_CB_TRACEEXECUTE*>(callbackInfo));
        } catch (...) {
            std::lock_guard<std::mutex> lock(g_nativeTrace.mutex);
            if (g_nativeTrace.active) {
                g_nativeTrace.active = false;
                g_nativeTrace.completed = true;
                g_nativeTrace.stopReason = "callback_exception";
                g_nativeTrace.cv.notify_all();
            }
        }
        break;
    case CB_INITDEBUG:
    {
        purgePersistedMcpBreakpoints();
        {
            std::lock_guard<std::mutex> lock(g_nativeApiTrace.mutex);
            g_nativeApiTrace.pending.clear();
            g_nativeApiTrace.exceptionUnwoundPending.clear();
            g_nativeApiTrace.configs.clear();
        }
        {
            std::lock_guard<std::mutex> lock(g_childBroker.mutex);
            g_childBroker.autoEntryBreakpointInstalled = false;
            g_childBroker.autoEntryBreakpointAddress = 0;
            g_childBroker.autoEntryResolveAttempts = 0;
            g_childBroker.autoEntryInstallAttempts = 0;
            g_childBroker.autoEntryLastError.clear();
        }
        std::string initImagePath;
        if (callbackInfo) {
            auto* info = reinterpret_cast<PLUG_CB_INITDEBUG*>(callbackInfo);
            initImagePath = safeString(info->szFileName);
        }
        const auto initIdentity = initImagePath.empty()
            ? mcplaunch::FileIdentityResult{}
            : mcplaunch::identifyFileByPath(utf8ToWide(initImagePath));
        mutateDebugSession("init_debug", [&](DebugSessionState& state) {
            beginDebugSessionUnlocked(state);
            state.initialized = true;
            state.debugging = true;
            state.paused = true;
            state.running = false;
            state.exited = false;
            state.imagePath = initImagePath;
            if (initIdentity.ok) {
                state.imagePath = wideToUtf8(initIdentity.finalPath);
                state.imageSha256 = initIdentity.sha256;
                state.imageSize = initIdentity.size;
                state.imageVolumeSerialNumber = initIdentity.volumeSerialNumber;
                state.imageFileId = launchFileIdHex(initIdentity.fileId);
            }
            state.stopReason = "init_debug";
            state.note = "Debug session initialized";
        });
        ensureDebugSessionImageIdentity();
        break;
    }
    case CB_CREATEPROCESS:
    {
        purgePersistedMcpBreakpoints();
        auto* createInfo = reinterpret_cast<PLUG_CB_CREATEPROCESS*>(callbackInfo);
        DWORD callbackProcessId = 0;
        HANDLE imageFile = nullptr;
        if(createInfo)
        {
            if(createInfo->fdProcessInfo)
                callbackProcessId = createInfo->fdProcessInfo->dwProcessId;
            if(createInfo->CreateProcessInfo)
                imageFile = createInfo->CreateProcessInfo->hFile;
        }
        if(callbackProcessId == 0)
            callbackProcessId = DbgGetProcessId();
        const std::shared_ptr<ManagedLaunch> managedLaunch =
            findManagedLaunchByProcessId(callbackProcessId);
        mcplaunch::FileIdentityResult actualIdentity;
        if(imageFile)
            actualIdentity = mcplaunch::identifyFileByHandle(imageFile);
        if(!actualIdentity.ok && createInfo && createInfo->DebugFileName)
            actualIdentity = mcplaunch::identifyFileByPath(
                utf8ToWide(createInfo->DebugFileName));

        mutateDebugSession("create_process", [&](DebugSessionState& state) {
            if (state.sessionId.empty()) {
                beginDebugSessionUnlocked(state);
            }
            clearPendingExceptionUnlocked(state);
            state.initialized = true;
            state.debugging = true;
            state.paused = true;
            state.running = false;
            state.exited = false;
            state.processId = DbgGetProcessId();
            state.threadId = DbgGetThreadId();
            state.imageSha256.clear();
            state.imageSize = 0;
            state.imageVolumeSerialNumber = 0;
            state.imageFileId.clear();
            state.imagePath.clear();
            if (createInfo) {
                if (createInfo->DebugFileName) {
                    state.imagePath = safeString(createInfo->DebugFileName);
                }
            }
            if(actualIdentity.ok)
            {
                state.imagePath = wideToUtf8(actualIdentity.finalPath);
                state.imageSha256 = actualIdentity.sha256;
                state.imageSize = actualIdentity.size;
                state.imageVolumeSerialNumber = actualIdentity.volumeSerialNumber;
                state.imageFileId = launchFileIdHex(actualIdentity.fileId);
            }
            state.lastIp = tryCaptureCurrentIp();
            state.lastAddress = state.lastIp;
            state.stopReason = "create_process";
            state.note = "Initial process create event";
        });
        completeManagedLaunchCreateObservation(
            managedLaunch, callbackProcessId, actualIdentity);
        ensureDebugSessionImageIdentity();
        childBrokerObserveSessionReady();
        break;
    }
    case CB_SYSTEMBREAKPOINT:
        purgePersistedMcpBreakpoints();
        break;
    case CB_ATTACH:
    {
        const auto* attachInfo = reinterpret_cast<PLUG_CB_ATTACH*>(callbackInfo);
        const DWORD attachedPid = attachInfo && attachInfo->dwProcessId
            ? attachInfo->dwProcessId : DbgGetProcessId();
        const auto attachIdentity = identifyCurrentMainModule();
        mutateDebugSession("attach", [&](DebugSessionState& state) {
            if (state.sessionId.empty()) {
                beginDebugSessionUnlocked(state);
            }
            clearPendingExceptionUnlocked(state);
            state.initialized = true;
            state.debugging = true;
            state.paused = true;
            state.running = false;
            state.exited = false;
            state.processId = attachedPid;
            state.threadId = DbgGetThreadId();
            state.imageSha256.clear();
            state.imageSize = 0;
            state.imageVolumeSerialNumber = 0;
            state.imageFileId.clear();
            state.imagePath.clear();
            if (attachIdentity.ok) {
                state.imagePath = wideToUtf8(attachIdentity.finalPath);
                state.imageSha256 = attachIdentity.sha256;
                state.imageSize = attachIdentity.size;
                state.imageVolumeSerialNumber = attachIdentity.volumeSerialNumber;
                state.imageFileId = launchFileIdHex(attachIdentity.fileId);
            }
            state.lastIp = tryCaptureCurrentIp();
            state.lastAddress = state.lastIp;
            state.stopReason = "attach";
            state.note = "Attached to existing process";
        });
        ensureDebugSessionImageIdentity();
        childBrokerObserveSessionReady();
        break;
    }
    case CB_RESUMEDEBUG:
        mutateDebugSession("resume_debug", [&](DebugSessionState& state) {
            finalizePendingExceptionResumeUnlocked(state);
            clearPendingExceptionUnlocked(state);
            state.initialized = true;
            state.debugging = true;
            state.running = true;
            state.paused = false;
            state.exited = false;
            state.stopping = false;
            state.stopReason.clear();
            state.note = "Execution resumed";
        });
        observeNativeTraceResume();
        break;
    case CB_PAUSEDEBUG:
        mutateDebugSession("pause_debug", [&](DebugSessionState& state) {
            state.initialized = true;
            state.debugging = true;
            state.running = false;
            state.paused = true;
            state.lastIp = tryCaptureCurrentIp();
            if (state.lastIp) {
                state.lastAddress = state.lastIp;
            }
            if (state.stopReason.empty()) {
                state.stopReason = "pause";
            }
            state.note = "Execution paused";
        });
        ensureDebugSessionImageIdentity();
        childBrokerObserveSessionReady();
        childBrokerObserveDescendantPolicyReady();
        break;
    case CB_STEPPED:
        childBrokerHandleStepped();
        mutateDebugSession("stepped", [&](DebugSessionState& state) {
            clearPendingExceptionUnlocked(state);
            state.initialized = true;
            state.debugging = true;
            state.running = false;
            state.paused = true;
            state.lastIp = tryCaptureCurrentIp();
            state.lastAddress = state.lastIp;
            state.stopReason = "step";
            state.note = "Single-step completed";
        });
        break;
    case CB_BREAKPOINT:
        if (callbackInfo) {
            recordNativeApiBreakpoint(
                reinterpret_cast<PLUG_CB_BREAKPOINT*>(callbackInfo));
            childBrokerHandleBreakpoint(
                reinterpret_cast<PLUG_CB_BREAKPOINT*>(callbackInfo));
        }
        mutateDebugSession("breakpoint", [&](DebugSessionState& state) {
            clearPendingExceptionUnlocked(state);
            state.initialized = true;
            state.debugging = true;
            state.running = false;
            state.paused = true;
            state.stopReason = "breakpoint";
            state.note = "Breakpoint hit";
            if (callbackInfo) {
                auto* info = reinterpret_cast<PLUG_CB_BREAKPOINT*>(callbackInfo);
                if (info->breakpoint) {
                    state.lastAddress = info->breakpoint->addr;
                    state.breakpointName = safeString(info->breakpoint->name);
                    state.breakpointModule = safeString(info->breakpoint->mod);
                }
            }
            duint currentIp = tryCaptureCurrentIp();
            state.lastIp = currentIp ? currentIp : state.lastAddress;
        });
        break;
    case CB_EXCEPTION:
    {
        recordNativeTraceException(
            reinterpret_cast<PLUG_CB_EXCEPTION*>(callbackInfo));
        recordNativeApiException(
            reinterpret_cast<PLUG_CB_EXCEPTION*>(callbackInfo));
        PendingExceptionAutoContinuation automatic;
        mutateDebugSession("exception", [&](DebugSessionState& state) {
            state.initialized = true;
            state.debugging = true;
            state.running = false;
            state.paused = true;
            state.stopReason = "exception";
            state.note = "Debugger exception event";
            state.breakpointName.clear();
            state.breakpointModule.clear();
            if (callbackInfo) {
                auto* info = reinterpret_cast<PLUG_CB_EXCEPTION*>(callbackInfo);
                if (info->Exception) {
                    state.exceptionCode = info->Exception->ExceptionRecord.ExceptionCode;
                    state.exceptionFirstChance = info->Exception->dwFirstChance != 0;
                    state.lastAddress = (duint)info->Exception->ExceptionRecord.ExceptionAddress;
                }
            }
            duint currentIp = tryCaptureCurrentIp();
            state.lastIp = currentIp ? currentIp : state.lastAddress;
        }, &automatic);
        if (automatic.requested) {
            // DbgCmdExec uses x64dbg's command queue. Do not call a direct run
            // command while inside CB_EXCEPTION and never hold our state lock
            // while crossing into debugger command execution. Queue the
            // current-event disposition first, then an ordinary run. Using
            // erun/serun here would suppress later first-chance callbacks.
            const std::string traceResumeCommand =
                armNativeTraceExceptionResume();
            const bool dispositionSubmitted =
                DbgCmdExec(automatic.command.c_str());
            // x32dbg delivers CB_RESUMEDEBUG slightly later than x64dbg for
            // a first-chance SEH continuation.  Let the queued con/con 1
            // disposition commit before replacing it with the next bounded
            // conditional-trace command; otherwise the x86 SEH dispatcher
            // can resume at the post-raise cleanup path and skip __except.
            bool resumeSubmitted = false;
            if(dispositionSubmitted)
            {
                if(traceResumeCommand.empty())
                {
                    resumeSubmitted = DbgCmdExec("run");
                }
#if !defined(_WIN64)
                else
                {
                    // x32dbg must return from CB_EXCEPTION before the
                    // conditional trace command is submitted.  Queue it on
                    // the debugger GUI thread after con/con 1 has committed
                    // the exception disposition.
                    resumeSubmitted =
                        submitNativeTraceResumeAfterCallback(
                            traceResumeCommand);
                }
#else
                else
                {
                    resumeSubmitted =
                        DbgCmdExec(traceResumeCommand.c_str());
                }
#endif
            }
            completeNativeTraceExceptionResume(
                traceResumeCommand.empty() || resumeSubmitted);
            {
                std::lock_guard<std::mutex> lock(g_debugSession.mutex);
                ExceptionHistoryRecord* record = findExceptionHistoryBySeqUnlocked(
                    g_debugSession, automatic.historySeq);
                if (record
                    && record->sessionGeneration == automatic.sessionGeneration
                    && record->sessionId == automatic.sessionId) {
                    mcpexception::markAutomaticSubmission(
                        record->continuation, dispositionSubmitted, resumeSubmitted);
                    record->lastUpdateMs = nowTickMs();
                    record->lastUpdateTimestamp100ns = nowTimestamp100ns();
                }
                if (!dispositionSubmitted
                    && g_debugSession.sessionId == automatic.sessionId
                    && g_debugSession.generation == automatic.sessionGeneration
                    && g_debugSession.exceptionEventSeq == automatic.eventSeq) {
                    // Nothing reached x64dbg's queue, so release the claim and
                    // permit a guarded manual retry for this same exception.
                    g_debugSession.exceptionContinuationClaimed = false;
                    g_debugSession.exceptionDisposition = "default";
                }
            }
            g_debugSession.cv.notify_all();
        }
        else
        {
            // Current x64dbg builds deliver CB_PAUSEDEBUG before
            // CB_EXCEPTION.  An exception-aware trace defers the generic
            // pause decision until this semantic callback tells us that the
            // exception will deliberately remain paused.
            finishNativeTrace("exception_paused");
        }
        break;
    }
    case CB_EXITPROCESS:
        {
            std::lock_guard<std::mutex> lock(g_nativeApiTrace.mutex);
            g_nativeApiTrace.pending.clear();
        }
        mutateDebugSession("exit_process", [&](DebugSessionState& state) {
            clearPendingExceptionUnlocked(state);
            state.initialized = true;
            state.debugging = false;
            state.running = false;
            state.paused = false;
            state.exited = true;
            state.stopping = false;
            state.stopReason = "exit";
            state.note = "Debuggee exited";
            if (callbackInfo) {
                auto* info = reinterpret_cast<PLUG_CB_EXITPROCESS*>(callbackInfo);
                if (info->ExitProcess) {
                    state.exitCode = info->ExitProcess->dwExitCode;
                }
            }
        });
        break;
    case CB_STOPPINGDEBUG:
        mutateDebugSession("stopping_debug", [&](DebugSessionState& state) {
            state.stopping = true;
            state.note = "Debugger stop requested";
        });
        break;
    case CB_STOPDEBUG:
    case CB_DETACH:
        // x64dbg may persist the current breakpoint database as the session
        // closes. Remove inactive MCP-owned records before that snapshot so a
        // later launch cannot resurrect trace addresses from an older target.
        purgePersistedMcpBreakpoints();
        {
            std::lock_guard<std::mutex> lock(g_nativeApiTrace.mutex);
            g_nativeApiTrace.pending.clear();
        }
        childBrokerStop(false);
        mutateDebugSession("stop_debug", [&](DebugSessionState& state) {
            clearPendingExceptionUnlocked(state);
            state.initialized = true;
            state.debugging = false;
            state.running = false;
            state.paused = false;
            state.stopping = false;
            if (!state.exited) {
                state.stopReason = "stop";
            }
            if (!state.exited) {
                state.note = "Debug session ended";
            }
        });
        break;
    case CB_LOADDLL:
        // Persisted module breakpoints are materialized by x64dbg only after
        // the corresponding DLL load.  Purge at this point as well, before
        // the loader can transfer control to user code.
        purgePersistedMcpBreakpoints();
        mutateDebugSession("load_dll", [&](DebugSessionState& state) {
            if (callbackInfo) {
                auto* info = reinterpret_cast<PLUG_CB_LOADDLL*>(callbackInfo);
                state.note = std::string("Loaded DLL: ") + safeString(info->modname);
            }
        });
        childBrokerObserveSessionReady();
        break;
    case CB_UNLOADDLL:
        mutateDebugSession("unload_dll", [&](DebugSessionState& state) {
            state.note = "DLL unloaded";
        });
        break;
    default:
        break;
    }

    if (cbType == CB_PAUSEDEBUG) {
        // Preserve opt-in exception-aware traces across x64dbg's leading
        // pause callback. CB_EXCEPTION either queues the continuation or
        // terminates the trace as exception_paused.
        if(!preserveNativeTraceAcrossExceptionPause()
            && !nativeTraceMayAutoResumeException())
            finishNativeTrace("debugger_paused");
    } else if (cbType == CB_BREAKPOINT) {
        finishNativeTrace("breakpoint");
    } else if (cbType == CB_EXITPROCESS) {
        finishNativeTrace("debuggee_exited");
    } else if (cbType == CB_STOPDEBUG || cbType == CB_DETACH || cbType == CB_INITDEBUG) {
        finishNativeTrace("session_changed");
    }
}

void registerCallbacks() {
    _plugin_registercallback(g_pluginHandle, CB_INITDEBUG, debugSessionCallback);
    _plugin_registercallback(g_pluginHandle, CB_CREATEPROCESS, debugSessionCallback);
    _plugin_registercallback(g_pluginHandle, CB_SYSTEMBREAKPOINT, debugSessionCallback);
    _plugin_registercallback(g_pluginHandle, CB_ATTACH, debugSessionCallback);
    _plugin_registercallback(g_pluginHandle, CB_RESUMEDEBUG, debugSessionCallback);
    _plugin_registercallback(g_pluginHandle, CB_PAUSEDEBUG, debugSessionCallback);
    _plugin_registercallback(g_pluginHandle, CB_STEPPED, debugSessionCallback);
    _plugin_registercallback(g_pluginHandle, CB_BREAKPOINT, debugSessionCallback);
    _plugin_registercallback(g_pluginHandle, CB_EXCEPTION, debugSessionCallback);
    _plugin_registercallback(g_pluginHandle, CB_EXITPROCESS, debugSessionCallback);
    _plugin_registercallback(g_pluginHandle, CB_STOPPINGDEBUG, debugSessionCallback);
    _plugin_registercallback(g_pluginHandle, CB_STOPDEBUG, debugSessionCallback);
    _plugin_registercallback(g_pluginHandle, CB_DETACH, debugSessionCallback);
    _plugin_registercallback(g_pluginHandle, CB_LOADDLL, debugSessionCallback);
    _plugin_registercallback(g_pluginHandle, CB_UNLOADDLL, debugSessionCallback);
    _plugin_registercallback(g_pluginHandle, CB_TRACEEXECUTE, debugSessionCallback);
}

void unregisterCallbacks() {
    _plugin_unregistercallback(g_pluginHandle, CB_INITDEBUG);
    _plugin_unregistercallback(g_pluginHandle, CB_CREATEPROCESS);
    _plugin_unregistercallback(g_pluginHandle, CB_SYSTEMBREAKPOINT);
    _plugin_unregistercallback(g_pluginHandle, CB_ATTACH);
    _plugin_unregistercallback(g_pluginHandle, CB_RESUMEDEBUG);
    _plugin_unregistercallback(g_pluginHandle, CB_PAUSEDEBUG);
    _plugin_unregistercallback(g_pluginHandle, CB_STEPPED);
    _plugin_unregistercallback(g_pluginHandle, CB_BREAKPOINT);
    _plugin_unregistercallback(g_pluginHandle, CB_EXCEPTION);
    _plugin_unregistercallback(g_pluginHandle, CB_EXITPROCESS);
    _plugin_unregistercallback(g_pluginHandle, CB_STOPPINGDEBUG);
    _plugin_unregistercallback(g_pluginHandle, CB_STOPDEBUG);
    _plugin_unregistercallback(g_pluginHandle, CB_DETACH);
    _plugin_unregistercallback(g_pluginHandle, CB_LOADDLL);
    _plugin_unregistercallback(g_pluginHandle, CB_UNLOADDLL);
    _plugin_unregistercallback(g_pluginHandle, CB_TRACEEXECUTE);
}

// Case-insensitive lookup of a single request header value from the raw request.
static std::string httpHeaderValue(const std::string& request, const std::string& name,
                                   bool* duplicate) {
    if (duplicate) *duplicate = false;
    size_t headersEnd = request.find("\r\n\r\n");
    std::string block = (headersEnd == std::string::npos) ? request : request.substr(0, headersEnd);
    size_t lineStart = block.find("\r\n"); // skip the request line
    if (lineStart == std::string::npos) return "";
    lineStart += 2;
    std::string lname = name;
    std::transform(lname.begin(), lname.end(), lname.begin(), [](unsigned char c) { return (char)std::tolower(c); });
    std::string found;
    bool hasValue = false;
    while (lineStart < block.size()) {
        size_t lineEnd = block.find("\r\n", lineStart);
        if (lineEnd == std::string::npos) lineEnd = block.size();
        std::string line = block.substr(lineStart, lineEnd - lineStart);
        size_t colon = line.find(':');
        if (colon != std::string::npos) {
            std::string key = line.substr(0, colon);
            std::transform(key.begin(), key.end(), key.begin(), [](unsigned char c) { return (char)std::tolower(c); });
            while (!key.empty() && (key.back() == ' ' || key.back() == '\t')) key.pop_back();
            if (key == lname) {
                std::string val = line.substr(colon + 1);
                size_t b = val.find_first_not_of(" \t");
                std::string normalized;
                if (b != std::string::npos) {
                    size_t e = val.find_last_not_of(" \t");
                    normalized = val.substr(b, e - b + 1);
                }
                if (hasValue) {
                    if (duplicate) *duplicate = true;
                    return "";
                }
                found = std::move(normalized);
                hasValue = true;
            }
        }
        lineStart = lineEnd + 2;
    }
    return found;
}

// Host / [::1] / localhost with an optional :port -> is this a loopback authority?
static bool isLoopbackHostPort(const std::string& hostport) {
    if (hostport.empty()) return true; // no Host header: nothing to rebind
    std::string hp = hostport;
    std::transform(hp.begin(), hp.end(), hp.begin(), [](unsigned char c) { return (char)std::tolower(c); });
    std::string host = hp;
    if (!hp.empty() && hp[0] == '[') {              // [::1]:port
        size_t rb = hp.find(']');
        host = (rb == std::string::npos) ? hp : hp.substr(0, rb + 1);
    } else {                                         // host:port
        size_t colon = hp.find(':');
        if (colon != std::string::npos) host = hp.substr(0, colon);
    }
    return host == "127.0.0.1" || host == "localhost" || host == "[::1]" || host == "::1";
}

// Defends the loopback bridge against browser-driven attacks without a shared
// secret: rejects a foreign Host (DNS-rebinding) and any cross-origin Origin
// (CSRF). Non-browser automation clients (Python bridge) send a loopback Host
// and no Origin, so they pass unchanged. To disable, make this always return true.
static bool isRequestOriginAllowed(const std::string& request) {
    bool duplicateHost = false;
    const std::string host = httpHeaderValue(request, "host", &duplicateHost);
    if (duplicateHost || !isLoopbackHostPort(host)) return false;
    bool duplicateOrigin = false;
    std::string origin = httpHeaderValue(request, "origin", &duplicateOrigin);
    if (duplicateOrigin) return false;
    if (!origin.empty()) { // present only on browser-issued requests
        size_t schemeEnd = origin.find("://");
        std::string hostport = (schemeEnd == std::string::npos) ? origin : origin.substr(schemeEnd + 3);
        size_t slash = hostport.find('/');
        if (slash != std::string::npos) hostport = hostport.substr(0, slash);
        if (!isLoopbackHostPort(hostport)) return false; // also rejects Origin: null
    }
    return true;
}

static const char* httpLifecycleStateName(HttpLifecycleState state) {
    switch (state) {
    case HttpLifecycleState::Stopped: return "stopped";
    case HttpLifecycleState::Starting: return "starting";
    case HttpLifecycleState::Running: return "running";
    case HttpLifecycleState::Stopping: return "stopping";
    case HttpLifecycleState::Failed: return "failed";
    default: return "unknown";
    }
}

static std::string currentProcessImagePathUtf8() {
    std::vector<wchar_t> buffer(1024, L'\0');
    while (buffer.size() <= 32768) {
        DWORD written = GetModuleFileNameW(nullptr, buffer.data(), static_cast<DWORD>(buffer.size()));
        if (!written) return {};
        if (written < buffer.size() - 1) {
            return wideToUtf8(std::wstring(buffer.data(), written));
        }
        buffer.resize(buffer.size() * 2, L'\0');
    }
    return {};
}

static std::string buildBridgeHelloJson() {
    int configuredPort = 0;
    int boundPort = 0;
    HttpLifecycleState lifecycle = HttpLifecycleState::Stopped;
    std::string serverError;
    mcpdispatcher::Snapshot dispatcherSnapshot;
    size_t liveWorkerCount = 0;
    MutationLeaseSnapshot mutationLease = snapshotMutationLease();
    mcpmutation::Snapshot coordinatorState;
    bool coordinatorReady = false;
    if(const auto coordinator = syncMutationCoordinator())
    {
        const auto snapshot = coordinator->snapshot();
        if(snapshot.ok())
        {
            coordinatorState = snapshot.snapshot;
            coordinatorReady = true;
            mutationLease.active = coordinatorState.leaseActive;
            mutationLease.ownerClientId = coordinatorState.leaseOwnerId;
            mutationLease.sessionId = coordinatorState.session.sessionId;
            mutationLease.generation = coordinatorState.session.generation;
            mutationLease.processId = static_cast<DWORD>(
                coordinatorState.session.processId);
            mutationLease.expiresAtTickMs = static_cast<ULONGLONG>(
                coordinatorState.leaseExpiresAt);
            mutationLease.revision = coordinatorState.leaseRevision;
        }
    }
    {
        std::lock_guard<std::mutex> lock(g_httpServer.mutex);
        configuredPort = g_httpServer.configuredPort;
        boundPort = g_httpServer.boundPort;
        lifecycle = g_httpServer.state;
        serverError = g_httpServer.lastError;
        dispatcherSnapshot = g_httpServer.dispatcher.snapshot();
        liveWorkerCount = g_httpServer.liveWorkerCount;
    }
    const std::string processPath = currentProcessImagePathUtf8();
    const std::string sessionJson = buildDebugSessionJson(false, 0);

    std::stringstream ss;
    ss << "{";
    ss << "\"ok\":true,";
    ss << "\"protocolVersion\":4,";
    ss << "\"bridgeInstanceId\":\"" << escapeJsonString(g_bridgeInstanceId.c_str()) << "\",";
    ss << "\"build\":{";
    ss << "\"id\":\"" << escapeJsonString(MCP_BRIDGE_BUILD_ID) << "-" << escapeJsonString(MCP_BRIDGE_SOURCE_ID) << "\",";
    ss << "\"sourceId\":\"" << escapeJsonString(MCP_BRIDGE_SOURCE_ID) << "\",";
    ss << "\"date\":\"" << __DATE__ << "\",";
    ss << "\"time\":\"" << __TIME__ << "\",";
    ss << "\"pluginVersion\":" << PLUGIN_VERSION << ",";
    ss << "\"sdkVersion\":" << PLUG_SDKVERSION;
    ss << "},";
    ss << "\"debugger\":{";
    ss << "\"pid\":" << GetCurrentProcessId() << ",";
    ss << "\"processStartTime100ns\":" << g_debuggerProcessStartTime100ns << ",";
    ss << "\"executablePath\":\"" << escapeJsonString(processPath.c_str()) << "\",";
#ifdef _WIN64
    ss << "\"architecture\":\"x64\",\"pointerBits\":64";
#else
    ss << "\"architecture\":\"x86\",\"pointerBits\":32";
#endif
    ss << "},";
    ss << "\"http\":{";
    ss << "\"configuredPort\":" << configuredPort << ",";
    ss << "\"boundPort\":" << boundPort << ",";
    ss << "\"state\":\"" << httpLifecycleStateName(lifecycle) << "\",";
    ss << "\"admittedRequests\":" << dispatcherSnapshot.admitted << ",";
    ss << "\"activeWorkers\":" << dispatcherSnapshot.running << ",";
    ss << "\"queuedRequests\":" << dispatcherSnapshot.queued << ",";
    ss << "\"liveWorkers\":" << liveWorkerCount;
    if (!serverError.empty()) {
        ss << ",\"lastError\":\"" << escapeJsonString(serverError.c_str()) << "\"";
    }
    ss << "},";
    ss << "\"capabilities\":{";
    ss << "\"authentication\":{\"version\":1,\"scheme\":\"header-token\","
          "\"header\":\"X-MCP-Auth-Token\",\"tokenBits\":256,\"rotatesOnRestart\":true},";
    ss << "\"routePolicy\":{\"version\":1,\"sourceId\":\""
       << escapeJsonString(MCP_ROUTE_POLICY_ID) << "\"},";
    ss << "\"strictSessionGuards\":{\"version\":2,\"targetSha256\":true,\"eventCas\":true,\"recheckBeforeMutation\":true},";
    ss << "\"requestDispatcher\":{\"version\":1,\"fifo\":true,\"maxWorkers\":"
       << MAX_HTTP_CONCURRENT_WORKERS << ",\"maxAdmitted\":"
       << MAX_HTTP_ADMITTED_CLIENTS << ",\"queueDeadlineMs\":"
       << MAX_HTTP_QUEUE_WAIT_MS << ",\"serializedRouteDeadlineMs\":"
       << MAX_SERIALIZED_ROUTE_WAIT_MS
       << ",\"overloadStatus\":503,\"trackedShutdown\":true},";
    ss << "\"mutationLease\":{\"version\":1,\"supported\":true,"
       << "\"active\":" << (mutationLease.active ? "true" : "false") << ","
       << "\"ownerClientId\":\"" << escapeJsonString(mutationLease.ownerClientId.c_str()) << "\","
       << "\"sessionId\":\"" << escapeJsonString(mutationLease.sessionId.c_str()) << "\","
       << "\"generation\":" << mutationLease.generation << ","
       << "\"processId\":" << mutationLease.processId << ","
       << "\"expiresAtTickMs\":" << mutationLease.expiresAtTickMs << ","
       << "\"revision\":" << mutationLease.revision << ","
       << "\"maxTtlMs\":120000,"
       << "\"mutationSeq\":" << coordinatorState.mutationSeq << ","
       << "\"emergencyEpoch\":" << coordinatorState.emergencyEpoch << "},";
    ss << "\"mutationCoordinator\":{\"version\":1,\"ready\":"
       << (coordinatorReady ? "true" : "false")
       << ",\"leaseRevision\":" << coordinatorState.leaseRevision
       << ",\"mutationSeq\":" << coordinatorState.mutationSeq
       << ",\"emergencyEpoch\":" << coordinatorState.emergencyEpoch
       << ",\"mutationInFlight\":"
       << (coordinatorState.mutationInFlight ? "true" : "false")
       << ",\"atomicPermit\":true,\"nonceBinding\":true},";
    ss << "\"sendAll\":true,";
    ss << "\"transactionalMemoryWrite\":true,";
    ss << "\"mutationCas\":{\"version\":1,\"precheck\":true,\"postcheck\":true,\"rollback\":true},";
    ss << "\"exceptionDisposition\":true,";
    ss << "\"exceptionPolicy\":{\"version\":1,\"sessionScoped\":true,"
          "\"atomicSet\":true,\"specificityFirst\":true,"
          "\"boundedCursorHistory\":true,\"automaticDisposition\":true},";
    ss << "\"runExceptionModes\":[\"normal\",\"pass\",\"swallow\"],";
    ss << "\"launch\":{"
          "\"version\":2,\"args\":true,\"argumentsVector\":true,"
          "\"rawCommandLineTail\":true,\"cwd\":true,\"environment\":true,"
          "\"inheritEnvironment\":true,"
          "\"environmentMode\":\"unicode_create_process_block\","
          "\"createMode\":\"suspended_attach_verify_resume\","
          "\"defaultStreams\":\"console\","
          "\"streams\":{\"supported\":true,\"binarySafe\":true,"
          "\"stdin\":[\"inherit\",\"null\",\"file\",\"bytes\",\"pipe\"],"
          "\"stdout\":[\"inherit\",\"null\",\"file\",\"pipe\"],"
          "\"stderr\":[\"inherit\",\"null\",\"file\",\"pipe\"],"
          "\"captureMinBytes\":4096,\"captureMaxBytes\":67108864,"
          "\"ioChunkMaxBytes\":1048576},"
          "\"childPolicies\":[\"none\",\"attach-first\",\"attach-all\",\"break-on-create\"],"
          "\"identity\":{\"sha256\":true,\"fileId\":true,"
          "\"verifyBeforeResume\":true}},";
    ss << "\"nativeTrace\":{\"version\":2,\"instructionEvents\":true,"
          "\"hitCounts\":true,\"threadIds\":true,\"rangeFilter\":true,"
          "\"boundedRetention\":true,\"eventWatermark\":true,"
          "\"hitWatermark\":true,\"independentCursors\":true,"
          "\"eventEnrichment\":true},";
    ss << "\"nativeApiTrace\":{\"version\":5,\"breakpointEntries\":true,"
          "\"returnEntries\":true,\"threadIds\":true,\"boundedRetention\":true,"
          "\"eventWatermark\":true,\"abiArguments\":true,"
          "\"returnValues\":true,\"returnAddresses\":true,"
          "\"perThreadShadowStack\":true,\"callerModuleRva\":true,"
          "\"exceptionEvents\":true,\"exceptionUnwind\":true,"
          "\"exceptionUnwoundCounter\":true,"
          "\"nativeReturnHooks\":true,\"returnHookOwnership\":true,"
          "\"managedExceptionCorrelation\":true,"
          "\"managedRuntimeDetection\":true},";
    ss << "\"heapResourceTrace\":{\"version\":2,\"allocatorFamilies\":true,"
          "\"allocationIds\":true,\"reallocLineage\":true,"
          "\"crossThreadEvidence\":true,\"anomalyEvidence\":true,"
          "\"boundedLifecycle\":true,\"baselineAwareUnknowns\":true},";
    ss << "\"minidump\":{\"version\":1,\"guarded\":true,"
          "\"requiresPausedTarget\":true,\"customTypeFlags\":true},";
    ss << "\"scyllaDump\":{\"version\":2,\"guarded\":true,"
          "\"requiresPausedTarget\":true,\"explicitIatRange\":true,"
          "\"existingDumpRepair\":true,\"overwriteGuard\":true},";
    ss << "\"analysisEvidence\":{\"version\":1,\"moduleRva\":true,"
          "\"labels\":true,\"comments\":true,\"bookmarks\":true,"
          "\"functions\":true,\"eventCas\":true}";
    ss << "},";
    std::string childPolicy = "none";
    std::string childBrokerId;
    std::string childRootLaunchId;
    DWORD childRootPid = 0;
    DWORD childParentPid = 0;
    bool childConfigured = false;
    size_t childCount = 0;
    {
        std::lock_guard<std::mutex> lock(g_childBroker.mutex);
        childPolicy = g_childBroker.policyName;
        childBrokerId = g_childBroker.brokerId;
        childRootLaunchId = g_childBroker.rootLaunchId;
        childRootPid = g_childBroker.rootPid;
        childParentPid = g_childBroker.parentPid;
        childConfigured = g_childBroker.configured;
        childCount = g_childBroker.children.size();
    }
    ss << "\"childBroker\":{";
    ss << "\"configured\":" << (childConfigured ? "true" : "false") << ",";
    ss << "\"policy\":\"" << escapeJsonString(childPolicy.c_str()) << "\",";
    ss << "\"brokerId\":\"" << escapeJsonString(childBrokerId.c_str()) << "\",";
    ss << "\"rootLaunchId\":\"" << escapeJsonString(childRootLaunchId.c_str()) << "\",";
    ss << "\"rootPid\":" << childRootPid << ",";
    ss << "\"parentPid\":" << childParentPid << ",";
    ss << "\"childCount\":" << childCount;
    ss << "},";
    ss << "\"session\":" << sessionJson;
    ss << "}";
    return ss.str();
}

enum class RouteGuardKind {
    UNKNOWN,
    NONE,
    BRIDGE,
    SESSION,
    EXEC_DYNAMIC,
};

static RouteGuardKind routeGuardKind(const std::string& path) {
#define MCP_ROUTE(routePath, guardKind) \
    if (path == routePath) return RouteGuardKind::guardKind;
#include "route_policy.inc"
#undef MCP_ROUTE
    return RouteGuardKind::UNKNOWN;
}

static bool isRawSessionCreationCommand(
        const std::unordered_map<std::string, std::string>& params,
        const std::string& body) {
    auto found = params.find("cmd");
    std::string command = found == params.end() ? std::string() : found->second;
    if (command.empty() && body.find('=') == std::string::npos) command = body;
    trimParam(command);
    size_t separator = command.find_first_of(" \t\r\n");
    std::string first = command.substr(0, separator);
    std::transform(first.begin(), first.end(), first.begin(),
        [](unsigned char ch) { return static_cast<char>(std::tolower(ch)); });
    return first == "init" || first == "initdbg" || first == "attach";
}

static bool isSelfUnloadCommand(
        const std::unordered_map<std::string, std::string>& params,
        const std::string& body) {
    auto found = params.find("cmd");
    std::string command = found == params.end() ? std::string() : found->second;
    if (command.empty() && body.find('=') == std::string::npos) command = body;
    trimParam(command);
    const size_t separator = command.find_first_of(" \t\r\n");
    std::string first = command.substr(0, separator);
    std::transform(first.begin(), first.end(), first.begin(),
        [](unsigned char ch) { return static_cast<char>(std::tolower(ch)); });
    return first == "plugunload" || first == "pluginunload" || first == "unloadplugin";
}

struct MutationGuardDecision {
    bool ok = true;
    int status = 200;
    std::string responseJson;
};

static MutationGuardDecision rejectGuard(int status,
                                         const std::string& code,
                                         const std::string& message,
                                         const DebugSessionState& session) {
    MutationGuardDecision decision;
    decision.ok = false;
    decision.status = status;
    std::stringstream ss;
    ss << "{\"ok\":false,\"error\":{"
       << "\"code\":\"" << escapeJsonString(code.c_str()) << "\","
       << "\"message\":\"" << escapeJsonString(message.c_str()) << "\","
       << "\"retryable\":false},"
       << "\"current\":{"
       << "\"bridgeInstanceId\":\"" << escapeJsonString(g_bridgeInstanceId.c_str()) << "\","
       << "\"sessionId\":\"" << escapeJsonString(session.sessionId.c_str()) << "\","
       << "\"generation\":" << session.generation << ","
       << "\"processId\":" << session.processId << ","
       << "\"eventSeq\":" << session.eventSeq << ","
       << "\"imageSha256\":\"" << escapeJsonString(session.imageSha256.c_str())
       << "\"}}";
    decision.responseJson = ss.str();
    return decision;
}

static bool isStrictSha256(const std::string& value) {
    if (value.size() != 64) return false;
    return std::all_of(value.begin(), value.end(), [](unsigned char ch) {
        return (ch >= '0' && ch <= '9')
            || (ch >= 'a' && ch <= 'f')
            || (ch >= 'A' && ch <= 'F');
    });
}

static std::string lowerAsciiCopy(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(),
        [](unsigned char ch) { return static_cast<char>(std::tolower(ch)); });
    return value;
}

static MutationGuardDecision validateMutationLeaseGuard(
    const std::string& request,
    const std::string& path,
    const DebugSessionState& snapshot);

// Kept as an explicit compatibility spelling for clients that still classify
// the pre-v4 event-CAS response as "stale_event".  New mutation failures use
// the unified stale_mutation_guard code above.
static constexpr const char* kLegacyStaleEventCode = "stale_event";

static MutationGuardDecision validateMutationGuard(const std::string& request,
                                                    const std::string& path,
                                                    const std::unordered_map<std::string, std::string>& params,
                                                    const std::string& body) {
    const RouteGuardKind routeGuard = routeGuardKind(path);
    if (routeGuard == RouteGuardKind::NONE || routeGuard == RouteGuardKind::UNKNOWN) {
        return {};
    }
    // Self-unload is an intentionally inert command.  It must reach the
    // explicit bridge_self_unload_forbidden response even when the debuggee
    // is still producing asynchronous load/exception events; requiring an
    // event-CAS token here would turn the safety check into a misleading
    // stale-session error.
    if (routeGuard == RouteGuardKind::EXEC_DYNAMIC && isSelfUnloadCommand(params, body)) {
        return {};
    }

    DebugSessionState snapshot;
    // DebugSessionState owns synchronization primitives and is not copyable, so
    // copy only the identity fields needed for validation/error reporting.
    {
        std::lock_guard<std::mutex> lock(g_debugSession.mutex);
        snapshot.eventSeq = g_debugSession.eventSeq;
        snapshot.generation = g_debugSession.generation;
        snapshot.sessionId = g_debugSession.sessionId;
        snapshot.processId = g_debugSession.processId;
        snapshot.debugging = g_debugSession.debugging;
        snapshot.imageSha256 = g_debugSession.imageSha256;
    }

    const std::string bridgeId = httpHeaderValue(request, "x-mcp-bridge-id");
    if (bridgeId.empty()) {
        return rejectGuard(428, "missing_bridge_guard", "X-MCP-Bridge-Id is required", snapshot);
    }
    if (_stricmp(bridgeId.c_str(), g_bridgeInstanceId.c_str()) != 0) {
        return rejectGuard(409, "stale_bridge", "The request belongs to another bridge instance", snapshot);
    }

    // Launch and raw init/initdbg/attach create a new session, so immutable
    // bridge identity is their complete precondition even when a previous
    // stopped session remains available for diagnostics. Other raw commands
    // are conservatively session-guarded because they can mutate the target.
    const bool bridgeOnly = routeGuard == RouteGuardKind::BRIDGE
        || (routeGuard == RouteGuardKind::EXEC_DYNAMIC
            && isRawSessionCreationCommand(params, body));
    if (bridgeOnly) return validateMutationLeaseGuard(request, path, snapshot);
    if (snapshot.sessionId.empty()) {
        return rejectGuard(409, "no_session", "There is no current debug session", snapshot);
    }

    const std::string sessionId = httpHeaderValue(request, "x-mcp-session-id");
    const std::string generationText = httpHeaderValue(request, "x-mcp-session-generation");
    const std::string pidText = httpHeaderValue(request, "x-mcp-debuggee-pid");
    if (sessionId.empty() || generationText.empty() || pidText.empty()) {
        return rejectGuard(428, "missing_session_guard",
            "X-MCP-Session-Id, X-MCP-Session-Generation and X-MCP-Debuggee-Pid are required", snapshot);
    }

    uint64_t generation = 0;
    uint64_t pid = 0;
    if (!mcpbridge::parseUnsignedDecimalExact(generationText, generation)
        || !mcpbridge::parseUnsignedDecimalExact(pidText, pid)) {
        return rejectGuard(400, "invalid_session_guard", "Session generation and PID must be decimal integers", snapshot);
    }
    if (_stricmp(sessionId.c_str(), snapshot.sessionId.c_str()) != 0
        || generation != snapshot.generation
        || pid != snapshot.processId) {
        return rejectGuard(409, "stale_mutation_guard", "The guarded debug session no longer matches the active target", snapshot);
    }

    const std::string targetHash = httpHeaderValue(request, "x-mcp-debuggee-sha256");
    if (snapshot.imageSha256.empty()) {
        return rejectGuard(409, "target_identity_unavailable",
            "The active debug session has no verified target SHA-256 identity", snapshot);
    }
    if (targetHash.empty()) {
        return rejectGuard(428, "missing_target_identity",
            "X-MCP-Debuggee-SHA256 is required for a session mutation", snapshot);
    }
    if (!isStrictSha256(targetHash)) {
        return rejectGuard(400, "invalid_target_identity",
            "X-MCP-Debuggee-SHA256 must be exactly 64 hexadecimal characters", snapshot);
    }
    if (_stricmp(targetHash.c_str(), snapshot.imageSha256.c_str()) != 0) {
        return rejectGuard(409, "stale_mutation_guard",
            "The target SHA-256 no longer matches the active debug session", snapshot);
    }

    // Every session mutation carries an event-sequence compare-and-swap
    // token. A resume, pause, exception, module transition, or exit therefore
    // invalidates a request even when PID/session fields have not changed.
    const std::string eventSeqText = httpHeaderValue(request, "x-mcp-event-seq");
    if (eventSeqText.empty()) {
        return rejectGuard(428, "missing_event_guard",
            "X-MCP-Event-Seq is required for a session mutation", snapshot);
    }
    if (!eventSeqText.empty()) {
        uint64_t eventSeq = 0;
        if (!mcpbridge::parseUnsignedDecimalExact(eventSeqText, eventSeq)) {
            return rejectGuard(400, "invalid_event_guard", "X-MCP-Event-Seq must be a decimal integer", snapshot);
        }
        if (eventSeq != snapshot.eventSeq) {
            return rejectGuard(409, "stale_mutation_guard", "The debugger event sequence changed after preflight", snapshot);
        }
    }
    return validateMutationLeaseGuard(request, path, snapshot);
}

// validateMutationGuard runs before request parsing/dispatch. Policy updates are
// atomic session-owned transactions, so repeat the immutable identity check
// under the same lock used for the final swap to close that small preflight to
// commit race.
static bool sessionGuardMatchesUnlocked(const std::string& request,
                                        const DebugSessionState& state) {
    const std::string sessionId = httpHeaderValue(request, "x-mcp-session-id");
    const std::string generationText = httpHeaderValue(request, "x-mcp-session-generation");
    const std::string pidText = httpHeaderValue(request, "x-mcp-debuggee-pid");
    const std::string targetHash = httpHeaderValue(request, "x-mcp-debuggee-sha256");
    uint64_t generation = 0;
    uint64_t pid = 0;
    const std::string eventSeqText = httpHeaderValue(request, "x-mcp-event-seq");
    uint64_t eventSeq = 0;
    const bool eventMatches = !eventSeqText.empty()
        && mcpbridge::parseUnsignedDecimalExact(eventSeqText, eventSeq)
        && eventSeq == state.eventSeq;
    return !sessionId.empty()
        && mcpbridge::parseUnsignedDecimalExact(generationText, generation)
        && mcpbridge::parseUnsignedDecimalExact(pidText, pid)
        && _stricmp(sessionId.c_str(), state.sessionId.c_str()) == 0
        && generation == state.generation
        && pid == state.processId
        && isStrictSha256(targetHash)
        && !state.imageSha256.empty()
        && _stricmp(targetHash.c_str(), state.imageSha256.c_str()) == 0
        && eventMatches;
}

static bool isMutationLeaseControlRoute(const std::string& path)
{
    return path == "/Debug/Mutation/Acquire"
        || path == "/Debug/Mutation/Renew"
        || path == "/Debug/Mutation/Release";
}

static bool isEmergencyMutationRoute(const std::string& path)
{
    // An active transaction must never make the debugger impossible to stop.
    // Pause/Stop are asynchronous command submissions and are therefore the
    // only guarded mutations allowed to bypass an owner's lease.
    return path == "/Debug/Pause" || path == "/Debug/Stop";
}

static MutationGuardDecision validateMutationLeaseGuard(
    const std::string& request,
    const std::string& path,
    const DebugSessionState& snapshot)
{
    if(isMutationLeaseControlRoute(path) || isEmergencyMutationRoute(path))
        return {};

    const std::string clientId = httpHeaderValue(request, "x-mcp-client-id");
    const std::string token = httpHeaderValue(request, "x-mcp-mutation-lease");
    std::lock_guard<std::mutex> lock(g_mutationLease.mutex);
    expireMutationLeaseUnlocked(g_mutationLease);
    if(g_mutationLease.token.empty())
        return {};

    // A lease from an older target is stale by construction; clear it lazily so
    // a new session is not held hostage by a crashed client.
    if(g_mutationLease.bridgeInstanceId != g_bridgeInstanceId
        || g_mutationLease.sessionId != snapshot.sessionId
        || g_mutationLease.generation != snapshot.generation
        || g_mutationLease.processId != snapshot.processId)
    {
        clearMutationLeaseUnlocked(g_mutationLease);
        return {};
    }
    if(token.empty())
        return rejectGuard(423, "mutation_lease_required",
            "Another client owns the active mutation lease", snapshot);
    if(token != g_mutationLease.token || clientId != g_mutationLease.ownerClientId)
        return rejectGuard(423, "mutation_lease_owner_mismatch",
            "The mutation lease belongs to another client", snapshot);
    return {};
}

static bool routeNeedsNativeMutationPermit(
    const std::string& path,
    const std::unordered_map<std::string, std::string>& params,
    const std::string& body)
{
    const RouteGuardKind kind = routeGuardKind(path);
    if(kind != RouteGuardKind::SESSION && kind != RouteGuardKind::EXEC_DYNAMIC)
        return false;
    if(isMutationLeaseControlRoute(path) || isEmergencyMutationRoute(path))
        return false;
    if(kind == RouteGuardKind::EXEC_DYNAMIC
        && isSelfUnloadCommand(params, body))
        return false;
    // init/initdbg/attach establish the very session identity that the native
    // mutation coordinator consumes.  They are already bridge-ID and lease
    // guarded by validateMutationGuard, but cannot require a pre-existing
    // session without making first attach impossible.
    if(kind == RouteGuardKind::EXEC_DYNAMIC
        && isRawSessionCreationCommand(params, body))
        return false;
    return true;
}

static bool beginNativeMutationPermit(
    const std::string& request,
    const std::string& path,
    const std::unordered_map<std::string, std::string>& params,
    const std::string& body,
    SOCKET clientSocket,
    NativeMutationPermitScope& scope)
{
    if(!routeNeedsNativeMutationPermit(path, params, body))
        return true;

    const mcpmutation::SessionIdentity identity =
        currentMutationSessionIdentity();
    if(!identity.valid())
    {
        sendHttpResponse(clientSocket, 409, "application/json",
            "{\"ok\":false,\"error\":{\"code\":\"mutation_session_unavailable\",\"message\":\"A verified debug session is required for this mutation\",\"retryable\":false}}");
        return false;
    }
    scope.coordinator = syncMutationCoordinator();
    if(!scope.coordinator)
    {
        sendHttpResponse(clientSocket, 503, "application/json",
            "{\"ok\":false,\"error\":{\"code\":\"mutation_coordinator_unavailable\",\"message\":\"The native mutation coordinator is not ready\",\"retryable\":true}}");
        return false;
    }
    const mcpmutation::SnapshotResult snapshot =
        scope.coordinator->snapshot();
    if(!snapshot.ok())
    {
        std::stringstream ss;
        ss << "{\"ok\":false,\"error\":{\"code\":\""
           << mcpmutation::errorName(snapshot.error)
           << "\",\"message\":\"Mutation coordinator snapshot failed\",\"retryable\":true}}";
        sendHttpResponse(clientSocket, 503, "application/json", ss.str());
        scope.coordinator.reset();
        return false;
    }

    mcpmutation::BeginMutationRequest begin;
    begin.session = identity;
    const std::string token = mutationHeaderValue(
        request, "x-mcp-mutation-lease");
    if(!token.empty())
    {
        begin.ownerId = mutationHeaderValue(request, "x-mcp-client-id");
        begin.acquisitionNonce = mutationHeaderValue(
            request, "x-mcp-mutation-acquisition-nonce");
        begin.leaseToken = token;
    }
    begin.expectedLeaseRevision = snapshot.snapshot.leaseRevision;
    begin.expectedMutationSeq = snapshot.snapshot.mutationSeq;
    begin.expectedEmergencyEpoch = snapshot.snapshot.emergencyEpoch;
    mcpmutation::BeginMutationResult acquired =
        scope.coordinator->beginMutation(begin);
    if(!acquired.ok())
    {
        const int status = acquired.error == mcpmutation::Error::MutationBusy
            ? 423 : 409;
        std::stringstream ss;
        ss << "{\"ok\":false,\"error\":{\"code\":\""
           << mcpmutation::errorName(acquired.error)
           << "\",\"message\":\"Mutation coordinator rejected the operation\",\"retryable\":"
           << (acquired.error == mcpmutation::Error::MutationBusy
               ? "true" : "false") << "}}";
        sendHttpResponse(clientSocket, status, "application/json", ss.str());
        scope.coordinator.reset();
        return false;
    }
    scope.permit = std::move(acquired.permit);
    return true;
}

static bool invalidateNativeMutationForEmergency(
    const std::string& path,
    SOCKET clientSocket)
{
    if(!isEmergencyMutationRoute(path))
        return true;
    const std::shared_ptr<mcpmutation::MutationCoordinator> coordinator =
        syncMutationCoordinator();
    if(!coordinator)
        return true; // legacy/no-session paths are still handled by the route guard
    const mcpmutation::OperationResult invalidated =
        coordinator->emergencyInvalidate();
    if(invalidated.ok())
        return true;
    std::stringstream ss;
    ss << "{\"ok\":false,\"error\":{\"code\":\""
       << mcpmutation::errorName(invalidated.error)
       << "\",\"message\":\"Emergency mutation invalidation failed\",\"retryable\":true}}";
    sendHttpResponse(clientSocket, 503, "application/json", ss.str());
    return false;
}

struct MutationLeaseHttpResult
{
    int status = 200;
    std::string body;
};

static bool parseMutationLeaseTtl(
    const std::unordered_map<std::string, std::string>& params,
    uint64_t& ttlMs,
    std::string& error)
{
    ttlMs = 60000;
    const auto found = params.find("ttlMs");
    if(found == params.end() || found->second.empty())
        return true;
    if(!mcpbridge::parseUnsignedDecimalExact(found->second, ttlMs)
        || ttlMs < 1000 || ttlMs > 120000)
    {
        error = "ttlMs must be a decimal integer from 1000 through 120000";
        return false;
    }
    return true;
}

static std::string createMutationSecret()
{
    // Two independent GUID values provide 288 bits of entropy while keeping
    // the wire representation printable ASCII.  The GUID helper is backed by
    // the Windows CSPRNG in bridge_core.
    return mcpbridge::createGuidString() + mcpbridge::createGuidString();
}

static MutationLeaseHttpResult coordinatorLeaseResultJson(
    const mcpmutation::LeaseResult& result,
    bool released = false)
{
    const mcpmutation::Snapshot& snapshot = result.snapshot;
    if(!result.ok())
    {
        const bool retryable = result.error == mcpmutation::Error::LeaseBusy
            || result.error == mcpmutation::Error::MutationBusy
            || result.error == mcpmutation::Error::LeaseExpiryPending
            || result.error == mcpmutation::Error::LeaseReleasePending;
        std::stringstream error;
        error << "{\"ok\":false,\"error\":{\"code\":\""
              << mcpmutation::errorName(result.error)
              << "\",\"message\":\"Mutation coordinator lease operation failed\",\"retryable\":"
              << (retryable ? "true" : "false") << "},\"leaseRevision\":"
              << snapshot.leaseRevision << "}";
        return {retryable ? 423 : 409, error.str()};
    }
    std::stringstream body;
    body << "{\"ok\":true,\"lease\":{\"active\":"
         << ((!released && snapshot.leaseActive) ? "true" : "false")
         << ",\"released\":" << (released ? "true" : "false")
         << ",\"ownerClientId\":\"" << escapeJsonString(
             snapshot.leaseOwnerId.c_str()) << "\"";
    if(!released && !result.leaseToken.empty())
        body << ",\"token\":\"" << escapeJsonString(result.leaseToken.c_str()) << "\"";
    body << ",\"sessionId\":\"" << escapeJsonString(
               snapshot.session.sessionId.c_str()) << "\""
         << ",\"generation\":" << snapshot.session.generation
         << ",\"processId\":" << snapshot.session.processId
         << ",\"expiresAtTickMs\":" << result.expiresAt
         << ",\"revision\":" << snapshot.leaseRevision
         << ",\"mutationSeq\":" << snapshot.mutationSeq
         << ",\"emergencyEpoch\":" << snapshot.emergencyEpoch
         << ",\"pending\":" << (result.pending ? "true" : "false")
         << "}}";
    return {200, body.str()};
}

static bool coordinatorLeaseInputs(
    const std::string& request,
    const std::unordered_map<std::string, std::string>& params,
    uint64_t& ttl,
    std::string& owner,
    std::string& nonce,
    std::string& error)
{
    if(!parseMutationLeaseTtl(params, ttl, error))
        return false;
    owner = httpHeaderValue(request, "x-mcp-client-id");
    nonce = params.count("acquisitionNonce")
        ? params.at("acquisitionNonce")
        : httpHeaderValue(request, "x-mcp-mutation-acquisition-nonce");
    if(owner.empty() || nonce.empty())
    {
        error = "X-MCP-Client-Id and acquisitionNonce are required";
        return false;
    }
    return true;
}

static MutationLeaseHttpResult acquireMutationLeaseCoordinator(
    const std::string& request,
    const std::unordered_map<std::string, std::string>& params)
{
    uint64_t ttl = 0;
    std::string owner;
    std::string nonce;
    std::string error;
    if(!coordinatorLeaseInputs(request, params, ttl, owner, nonce, error))
        return {428, std::string("{\"ok\":false,\"error\":{\"code\":\"invalid_mutation_lease_input\",\"message\":\"")
            + escapeJsonString(error.c_str()) + "\",\"retryable\":false}}"};
    const auto coordinator = syncMutationCoordinator();
    if(!coordinator)
        return {503, "{\"ok\":false,\"error\":{\"code\":\"mutation_coordinator_unavailable\",\"message\":\"No verified debug session\",\"retryable\":true}}"};
    const auto snapshot = coordinator->snapshot();
    if(!snapshot.ok())
        return coordinatorLeaseResultJson({snapshot.error, snapshot.snapshot});
    mcpmutation::AcquireLeaseRequest acquire;
    acquire.session = snapshot.snapshot.session;
    acquire.ownerId = owner;
    acquire.acquisitionNonce = nonce;
    acquire.proposedLeaseToken = createMutationSecret();
    acquire.ttl = ttl;
    acquire.expectedLeaseRevision = snapshot.snapshot.leaseRevision;
    return coordinatorLeaseResultJson(coordinator->acquireLease(acquire));
}

static MutationLeaseHttpResult renewMutationLeaseCoordinator(
    const std::string& request,
    const std::unordered_map<std::string, std::string>& params)
{
    uint64_t ttl = 0;
    std::string owner;
    std::string nonce;
    std::string error;
    if(!coordinatorLeaseInputs(request, params, ttl, owner, nonce, error))
        return {428, std::string("{\"ok\":false,\"error\":{\"code\":\"invalid_mutation_lease_input\",\"message\":\"")
            + escapeJsonString(error.c_str()) + "\",\"retryable\":false}}"};
    const std::string token = httpHeaderValue(request, "x-mcp-mutation-lease");
    const auto coordinator = syncMutationCoordinator();
    if(!coordinator || token.empty())
        return {409, "{\"ok\":false,\"error\":{\"code\":\"mutation_lease_not_found\",\"message\":\"No active mutation lease exists\",\"retryable\":false}}"};
    const auto snapshot = coordinator->snapshot();
    if(!snapshot.ok())
        return coordinatorLeaseResultJson({snapshot.error, snapshot.snapshot});
    mcpmutation::RenewLeaseRequest renew;
    renew.session = snapshot.snapshot.session;
    renew.ownerId = owner;
    renew.acquisitionNonce = nonce;
    renew.leaseToken = token;
    renew.ttl = ttl;
    renew.expectedLeaseRevision = snapshot.snapshot.leaseRevision;
    return coordinatorLeaseResultJson(coordinator->renewLease(renew));
}

static MutationLeaseHttpResult releaseMutationLeaseCoordinator(
    const std::string& request,
    const std::unordered_map<std::string, std::string>& params)
{
    uint64_t ignoredTtl = 0;
    std::string owner;
    std::string nonce;
    std::string error;
    if(!coordinatorLeaseInputs(request, params, ignoredTtl, owner, nonce, error))
        return {428, std::string("{\"ok\":false,\"error\":{\"code\":\"invalid_mutation_lease_input\",\"message\":\"")
            + escapeJsonString(error.c_str()) + "\",\"retryable\":false}}"};
    const std::string token = httpHeaderValue(request, "x-mcp-mutation-lease");
    const auto coordinator = syncMutationCoordinator();
    if(!coordinator || token.empty())
        return {200, "{\"ok\":true,\"lease\":{\"active\":false,\"released\":false,\"alreadyReleased\":true}}"};
    const auto snapshot = coordinator->snapshot();
    if(!snapshot.ok())
        return coordinatorLeaseResultJson({snapshot.error, snapshot.snapshot});
    mcpmutation::ReleaseLeaseRequest release;
    release.session = snapshot.snapshot.session;
    release.ownerId = owner;
    release.acquisitionNonce = nonce;
    release.leaseToken = token;
    release.expectedLeaseRevision = snapshot.snapshot.leaseRevision;
    return coordinatorLeaseResultJson(coordinator->releaseLease(release), true);
}

static std::string buildMutationLeaseSuccessJsonUnlocked(
    const MutationLeaseState& lease,
    uint64_t ttlMs,
    bool includeToken,
    bool released)
{
    std::stringstream ss;
    ss << "{\"ok\":true,\"lease\":{"
       << "\"active\":" << (!released && !lease.token.empty() ? "true" : "false") << ","
       << "\"released\":" << (released ? "true" : "false") << ",";
    if(includeToken && !released)
        ss << "\"token\":\"" << escapeJsonString(lease.token.c_str()) << "\",";
    ss << "\"ownerClientId\":\"" << escapeJsonString(lease.ownerClientId.c_str()) << "\","
       << "\"bridgeInstanceId\":\"" << escapeJsonString(lease.bridgeInstanceId.c_str()) << "\","
       << "\"sessionId\":\"" << escapeJsonString(lease.sessionId.c_str()) << "\","
       << "\"generation\":" << lease.generation << ","
       << "\"processId\":" << lease.processId << ","
       << "\"ttlMs\":" << ttlMs << ","
       << "\"expiresAtTickMs\":" << lease.expiresAtTickMs << ","
       << "\"revision\":" << lease.revision << "}}";
    return ss.str();
}

static MutationLeaseHttpResult acquireMutationLease(
    const std::string& request,
    const std::unordered_map<std::string, std::string>& params)
{
    if(params.find("acquisitionNonce") != params.end()
        || !httpHeaderValue(request, "x-mcp-mutation-acquisition-nonce").empty())
    {
        return acquireMutationLeaseCoordinator(request, params);
    }
    uint64_t ttlMs = 0;
    std::string ttlError;
    if(!parseMutationLeaseTtl(params, ttlMs, ttlError))
        return {400, std::string("{\"ok\":false,\"error\":{\"code\":\"invalid_mutation_lease_ttl\",\"message\":\"")
            + escapeJsonString(ttlError.c_str()) + "\",\"retryable\":false}}"};

    const std::string clientId = httpHeaderValue(request, "x-mcp-client-id");
    if(clientId.empty() || clientId.size() > 128
        || std::any_of(clientId.begin(), clientId.end(), [](unsigned char ch) { return ch < 0x21 || ch > 0x7E; }))
    {
        return {428,
            "{\"ok\":false,\"error\":{\"code\":\"mutation_lease_client_required\",\"message\":\"A printable X-MCP-Client-Id of at most 128 bytes is required\",\"retryable\":false}}"};
    }

    std::lock_guard<std::mutex> sessionLock(g_debugSession.mutex);
    if(!sessionGuardMatchesUnlocked(request, g_debugSession))
    {
        const auto rejected = rejectGuard(409, "stale_mutation_guard",
            "The debug session changed before mutation lease acquisition", g_debugSession);
        return {rejected.status, rejected.responseJson};
    }
    std::lock_guard<std::mutex> leaseLock(g_mutationLease.mutex);
    expireMutationLeaseUnlocked(g_mutationLease);
    const bool sameOwner = !g_mutationLease.token.empty()
        && g_mutationLease.ownerClientId == clientId
        && g_mutationLease.bridgeInstanceId == g_bridgeInstanceId
        && g_mutationLease.sessionId == g_debugSession.sessionId
        && g_mutationLease.generation == g_debugSession.generation
        && g_mutationLease.processId == g_debugSession.processId;
    if(!g_mutationLease.token.empty() && !sameOwner)
    {
        return {423,
            "{\"ok\":false,\"error\":{\"code\":\"mutation_lease_busy\",\"message\":\"Another client owns the active mutation lease\",\"retryable\":true}}"};
    }
    if(!sameOwner)
    {
        g_mutationLease.token = mcpbridge::createGuidString();
        if(g_mutationLease.token.empty())
            return {500,
                "{\"ok\":false,\"error\":{\"code\":\"mutation_lease_token_failed\",\"message\":\"Could not create a lease token\",\"retryable\":true}}"};
        g_mutationLease.ownerClientId = clientId;
        g_mutationLease.bridgeInstanceId = g_bridgeInstanceId;
        g_mutationLease.sessionId = g_debugSession.sessionId;
        g_mutationLease.generation = g_debugSession.generation;
        g_mutationLease.processId = g_debugSession.processId;
        ++g_mutationLease.revision;
    }
    g_mutationLease.expiresAtTickMs = nowTickMs() + ttlMs;
    return {200, buildMutationLeaseSuccessJsonUnlocked(
        g_mutationLease, ttlMs, true, false)};
}

static MutationLeaseHttpResult renewMutationLease(
    const std::string& request,
    const std::unordered_map<std::string, std::string>& params)
{
    if(params.find("acquisitionNonce") != params.end()
        || !httpHeaderValue(request, "x-mcp-mutation-acquisition-nonce").empty())
    {
        return renewMutationLeaseCoordinator(request, params);
    }
    uint64_t ttlMs = 0;
    std::string ttlError;
    if(!parseMutationLeaseTtl(params, ttlMs, ttlError))
        return {400, std::string("{\"ok\":false,\"error\":{\"code\":\"invalid_mutation_lease_ttl\",\"message\":\"")
            + escapeJsonString(ttlError.c_str()) + "\",\"retryable\":false}}"};
    const std::string clientId = httpHeaderValue(request, "x-mcp-client-id");
    const std::string token = httpHeaderValue(request, "x-mcp-mutation-lease");
    std::lock_guard<std::mutex> sessionLock(g_debugSession.mutex);
    if(!sessionGuardMatchesUnlocked(request, g_debugSession))
    {
        const auto rejected = rejectGuard(409, "stale_mutation_guard",
            "The debug session changed before mutation lease renewal", g_debugSession);
        return {rejected.status, rejected.responseJson};
    }
    std::lock_guard<std::mutex> leaseLock(g_mutationLease.mutex);
    expireMutationLeaseUnlocked(g_mutationLease);
    if(g_mutationLease.token.empty())
        return {409,
            "{\"ok\":false,\"error\":{\"code\":\"mutation_lease_not_found\",\"message\":\"No active mutation lease exists\",\"retryable\":false}}"};
    if(token != g_mutationLease.token || clientId != g_mutationLease.ownerClientId)
        return {423,
            "{\"ok\":false,\"error\":{\"code\":\"mutation_lease_owner_mismatch\",\"message\":\"The mutation lease belongs to another client\",\"retryable\":false}}"};
    g_mutationLease.expiresAtTickMs = nowTickMs() + ttlMs;
    ++g_mutationLease.revision;
    return {200, buildMutationLeaseSuccessJsonUnlocked(
        g_mutationLease, ttlMs, true, false)};
}

static MutationLeaseHttpResult releaseMutationLease(const std::string& request)
{
    if(!httpHeaderValue(request, "x-mcp-mutation-acquisition-nonce").empty())
    {
        std::unordered_map<std::string, std::string> params;
        params["acquisitionNonce"] = httpHeaderValue(
            request, "x-mcp-mutation-acquisition-nonce");
        return releaseMutationLeaseCoordinator(request, params);
    }
    const std::string clientId = httpHeaderValue(request, "x-mcp-client-id");
    const std::string token = httpHeaderValue(request, "x-mcp-mutation-lease");
    std::lock_guard<std::mutex> sessionLock(g_debugSession.mutex);
    if(!sessionGuardMatchesUnlocked(request, g_debugSession))
    {
        const auto rejected = rejectGuard(409, "stale_mutation_guard",
            "The debug session changed before mutation lease release", g_debugSession);
        return {rejected.status, rejected.responseJson};
    }
    std::lock_guard<std::mutex> leaseLock(g_mutationLease.mutex);
    expireMutationLeaseUnlocked(g_mutationLease);
    if(g_mutationLease.token.empty())
        return {200,
            "{\"ok\":true,\"lease\":{\"active\":false,\"released\":false,\"alreadyReleased\":true}}"};
    if(token != g_mutationLease.token || clientId != g_mutationLease.ownerClientId)
        return {423,
            "{\"ok\":false,\"error\":{\"code\":\"mutation_lease_owner_mismatch\",\"message\":\"The mutation lease belongs to another client\",\"retryable\":false}}"};
    const MutationLeaseState& lease = g_mutationLease;
    const std::string owner = lease.ownerClientId;
    const std::string bridge = lease.bridgeInstanceId;
    const std::string session = lease.sessionId;
    const uint64_t generation = lease.generation;
    const DWORD processId = lease.processId;
    clearMutationLeaseUnlocked(g_mutationLease);
    std::stringstream ss;
    ss << "{\"ok\":true,\"lease\":{\"active\":false,\"released\":true,"
       << "\"ownerClientId\":\"" << escapeJsonString(owner.c_str()) << "\","
       << "\"bridgeInstanceId\":\"" << escapeJsonString(bridge.c_str()) << "\","
       << "\"sessionId\":\"" << escapeJsonString(session.c_str()) << "\","
       << "\"generation\":" << generation << ",\"processId\":" << processId << ","
       << "\"revision\":" << g_mutationLease.revision << "}}";
    return {200, ss.str()};
}

static bool selectRunCommand(const std::string& rawMode,
                             std::string& normalizedMode,
                             const char*& command) {
    normalizedMode = toLowerCopy(rawMode.empty() ? "normal" : rawMode);
    if (normalizedMode == "normal") {
        command = "run";
        return true;
    }
    if (normalizedMode == "pass") {
        command = "erun";
        return true;
    }
    if (normalizedMode == "swallow") {
        command = "serun";
        return true;
    }
    return false;
}

namespace
{
    constexpr size_t kLaunchMinCaptureBytes = 4u * 1024u;
    constexpr size_t kLaunchMaxCaptureBytes = 64u * 1024u * 1024u;
    constexpr size_t kLaunchMaxIoChunkBytes = 1024u * 1024u;
    constexpr unsigned int kLaunchAttachTimeoutMs = 15000u;

    struct JsonRef
    {
        json_t* value = nullptr;
        ~JsonRef()
        {
            if(value)
                json_decref(value);
        }
        JsonRef(const JsonRef&) = delete;
        JsonRef& operator=(const JsonRef&) = delete;
        explicit JsonRef(json_t* input = nullptr) : value(input) {}
    };

    struct LaunchParseResult
    {
        bool ok = false;
        int status = 400;
        std::string errorCode;
        std::string errorMessage;
        mcplaunch::LaunchSpec spec;
        std::string childPolicy = "none";
        size_t environmentOverrideCount = 0;
        std::string commandLineMode = "arguments";
    };

    struct LaunchHttpResult
    {
        int status = 500;
        std::string body;
    };

    static LaunchHttpResult launchHttpError(
        int status,
        const std::string& code,
        const std::string& message,
        bool retryable = false,
        DWORD win32Error = ERROR_SUCCESS)
    {
        std::stringstream ss;
        ss << "{\"ok\":false,\"error\":{"
           << "\"code\":\"" << escapeJsonString(code.c_str()) << "\","
           << "\"message\":\"" << escapeJsonString(message.c_str()) << "\","
           << "\"retryable\":" << (retryable ? "true" : "false");
        if(win32Error != ERROR_SUCCESS)
            ss << ",\"win32Error\":" << std::dec << win32Error;
        ss << "}}";
        return {status, ss.str()};
    }

    static bool jsonStringBytes(json_t* value,
                                std::string& output,
                                std::string& error,
                                const char* fieldName,
                                bool allowEmpty = true)
    {
        if(!json_is_string(value))
        {
            error = std::string(fieldName) + " must be a JSON string";
            return false;
        }
        const char* text = json_string_value(value);
        const size_t length = json_string_length(value);
        if(!text || std::memchr(text, '\0', length) != nullptr)
        {
            error = std::string(fieldName) + " contains a NUL character";
            return false;
        }
        output.assign(text, length);
        if(!allowEmpty && output.empty())
        {
            error = std::string(fieldName) + " must not be empty";
            return false;
        }
        return true;
    }

    static bool utf8FieldToWide(const std::string& input,
                                std::wstring& output,
                                std::string& error,
                                const char* fieldName,
                                bool allowEmpty = true)
    {
        if(input.find('\0') != std::string::npos)
        {
            error = std::string(fieldName) + " contains a NUL character";
            return false;
        }
        if(input.empty())
        {
            output.clear();
            if(!allowEmpty)
            {
                error = std::string(fieldName) + " must not be empty";
                return false;
            }
            return true;
        }
        output = utf8ToWide(input);
        if(output.empty())
        {
            error = std::string(fieldName) + " is not valid UTF-8";
            return false;
        }
        return true;
    }

    static bool parseJsonDocument(const std::string& text,
                                  json_t*& output,
                                  std::string& error,
                                  const char* fieldName)
    {
        json_error_t jsonError = {};
        output = json_loadb(text.data(), text.size(), JSON_REJECT_DUPLICATES,
                            &jsonError);
        if(!output)
        {
            error = std::string("Invalid ") + fieldName + " JSON: "
                + jsonError.text;
            return false;
        }
        return true;
    }

    static bool jsonObjectHasOnly(
        json_t* object,
        std::initializer_list<const char*> allowed,
        std::string& error,
        const char* fieldName)
    {
        std::unordered_set<std::string> names;
        for(const char* name : allowed)
            names.insert(name);
        for(void* iterator = json_object_iter(object); iterator;
            iterator = json_object_iter_next(object, iterator))
        {
            const char* key = json_object_iter_key(iterator);
            if(!key || names.find(key) == names.end())
            {
                error = std::string("Unknown ") + fieldName
                    + " field: " + (key ? key : "<null>");
                return false;
            }
        }
        return true;
    }

    static bool parseJsonSize(json_t* value,
                              size_t minimum,
                              size_t maximum,
                              size_t& output,
                              std::string& error,
                              const char* fieldName)
    {
        if(!json_is_integer(value))
        {
            error = std::string(fieldName) + " must be an integer";
            return false;
        }
        const json_int_t parsed = json_integer_value(value);
        if(parsed < 0
            || static_cast<uint64_t>(parsed) < minimum
            || static_cast<uint64_t>(parsed) > maximum)
        {
            error = std::string(fieldName) + " is outside the supported range";
            return false;
        }
        output = static_cast<size_t>(parsed);
        return true;
    }

    static bool validateOutputFilePath(const std::wstring& path,
                                       std::string& error,
                                       const char* fieldName)
    {
        if(!isAbsoluteRegularFilePathW(path))
        {
            error = std::string(fieldName)
                + " must be an absolute drive or UNC file path";
            return false;
        }
        const DWORD attributes = GetFileAttributesW(path.c_str());
        if(attributes != INVALID_FILE_ATTRIBUTES
            && (attributes & FILE_ATTRIBUTE_DIRECTORY) != 0)
        {
            error = std::string(fieldName) + " names a directory";
            return false;
        }
        const size_t separator = path.find_last_of(L"\\/");
        if(separator == std::wstring::npos)
        {
            error = std::string(fieldName) + " has no parent directory";
            return false;
        }
        std::wstring parent = path.substr(0, separator);
        if(separator == 2u && path.size() >= 3u && path[1] == L':')
            parent.push_back(L'\\');
        if(parent.empty() || !directoryExistsW(parent))
        {
            error = std::string(fieldName)
                + " parent directory does not exist";
            return false;
        }
        return true;
    }

    static bool parseInputStream(json_t* object,
                                 mcplaunch::InputSpec& result,
                                 size_t& pipeCapacity,
                                 std::string& error)
    {
        if(!json_is_object(object))
        {
            error = "stdin must be a JSON object";
            return false;
        }
        if(!jsonObjectHasOnly(object,
                {"mode", "path", "dataBase64", "closeAfterWrite",
                 "capacityBytes"}, error, "stdin"))
            return false;
        json_t* modeValue = json_object_get(object, "mode");
        std::string mode;
        if(!modeValue || !jsonStringBytes(
                modeValue, mode, error, "stdin.mode", false))
            return false;
        mode = toLowerCopy(mode);
        trimParam(mode);
        if(mode == "inherit")
        {
            result.mode = mcplaunch::StdioMode::Inherit;
        }
        else if(mode == "null")
        {
            result.mode = mcplaunch::StdioMode::Null;
        }
        else if(mode == "file")
        {
            result.mode = mcplaunch::StdioMode::File;
            json_t* pathValue = json_object_get(object, "path");
            std::string pathUtf8;
            if(!pathValue || !jsonStringBytes(
                    pathValue, pathUtf8, error, "stdin.path", false)
                || !utf8FieldToWide(
                    pathUtf8, result.filePath, error, "stdin.path", false))
                return false;
            if(!isAbsoluteRegularFilePathW(result.filePath)
                || !fileExistsW(result.filePath))
            {
                error = "stdin.path must identify an existing absolute file";
                return false;
            }
        }
        else if(mode == "bytes")
        {
            result.mode = mcplaunch::StdioMode::Bytes;
            json_t* dataValue = json_object_get(object, "dataBase64");
            std::string encoded;
            if(!dataValue || !jsonStringBytes(
                    dataValue, encoded, error, "stdin.dataBase64"))
                return false;
            const auto decoded = mcplaunch::decodeBase64Strict(
                encoded, kLaunchMaxIoChunkBytes);
            if(!decoded.ok)
            {
                error = decoded.error;
                return false;
            }
            result.initialBytes = decoded.bytes;
            json_t* closeValue = json_object_get(object, "closeAfterWrite");
            if(closeValue && !json_is_true(closeValue))
            {
                error = "stdin.closeAfterWrite must be true for finite bytes mode";
                return false;
            }
        }
        else if(mode == "pipe")
        {
            result.mode = mcplaunch::StdioMode::Pipe;
            json_t* capacityValue = json_object_get(object, "capacityBytes");
            if(capacityValue && !parseJsonSize(
                    capacityValue, kLaunchMinCaptureBytes,
                    kLaunchMaxCaptureBytes, pipeCapacity, error,
                    "stdin.capacityBytes"))
                return false;
        }
        else
        {
            error = "stdin.mode must be inherit, null, file, bytes, or pipe";
            return false;
        }

        if(mode != "file" && json_object_get(object, "path"))
        {
            error = "stdin.path is valid only in file mode";
            return false;
        }
        if(mode != "bytes"
            && (json_object_get(object, "dataBase64")
                || json_object_get(object, "closeAfterWrite")))
        {
            error = "stdin byte fields are valid only in bytes mode";
            return false;
        }
        if(mode != "pipe" && json_object_get(object, "capacityBytes"))
        {
            error = "stdin.capacityBytes is valid only in pipe mode";
            return false;
        }
        return true;
    }

    static bool parseOutputStream(json_t* object,
                                  mcplaunch::OutputSpec& result,
                                  const char* streamName,
                                  std::string& error)
    {
        if(!json_is_object(object))
        {
            error = std::string(streamName) + " must be a JSON object";
            return false;
        }
        if(!jsonObjectHasOnly(
                object, {"mode", "path", "fileMode"}, error, streamName))
            return false;
        json_t* modeValue = json_object_get(object, "mode");
        std::string mode;
        const std::string modeField = std::string(streamName) + ".mode";
        if(!modeValue || !jsonStringBytes(
                modeValue, mode, error, modeField.c_str(), false))
            return false;
        mode = toLowerCopy(mode);
        trimParam(mode);
        if(mode == "inherit")
        {
            result.mode = mcplaunch::StdioMode::Inherit;
        }
        else if(mode == "null")
        {
            result.mode = mcplaunch::StdioMode::Null;
        }
        else if(mode == "pipe")
        {
            result.mode = mcplaunch::StdioMode::Pipe;
        }
        else if(mode == "file")
        {
            result.mode = mcplaunch::StdioMode::File;
            json_t* pathValue = json_object_get(object, "path");
            std::string pathUtf8;
            const std::string pathField = std::string(streamName) + ".path";
            if(!pathValue || !jsonStringBytes(
                    pathValue, pathUtf8, error, pathField.c_str(), false)
                || !utf8FieldToWide(pathUtf8, result.filePath, error,
                                    pathField.c_str(), false)
                || !validateOutputFilePath(
                    result.filePath, error, pathField.c_str()))
                return false;
            json_t* fileModeValue = json_object_get(object, "fileMode");
            if(fileModeValue)
            {
                std::string fileMode;
                const std::string fileModeField =
                    std::string(streamName) + ".fileMode";
                if(!jsonStringBytes(fileModeValue, fileMode, error,
                                    fileModeField.c_str(), false))
                    return false;
                fileMode = toLowerCopy(fileMode);
                trimParam(fileMode);
                if(fileMode == "append")
                    result.writeMode = mcplaunch::FileWriteMode::Append;
                else if(fileMode == "truncate")
                    result.writeMode = mcplaunch::FileWriteMode::Truncate;
                else
                {
                    error = fileModeField + " must be append or truncate";
                    return false;
                }
            }
        }
        else
        {
            error = std::string(streamName)
                + ".mode must be inherit, null, file, or pipe";
            return false;
        }
        if(mode != "file"
            && (json_object_get(object, "path")
                || json_object_get(object, "fileMode")))
        {
            error = std::string(streamName)
                + " file fields are valid only in file mode";
            return false;
        }
        return true;
    }

    static std::string requestValue(
        const std::unordered_map<std::string, std::string>& params,
        const char* name)
    {
        const auto found = params.find(name);
        return found == params.end() ? std::string() : found->second;
    }

    static bool parseLaunchArguments(const std::string& argumentsJson,
                                     const std::string& rawTailUtf8,
                                     mcplaunch::LaunchSpec& spec,
                                     std::string& commandLineMode,
                                     std::string& error)
    {
        json_t* argumentsRoot = nullptr;
        const std::string document = argumentsJson.empty()
            ? "[]" : argumentsJson;
        if(!parseJsonDocument(
                document, argumentsRoot, error, "arguments"))
            return false;
        JsonRef argumentsOwner(argumentsRoot);
        if(!json_is_array(argumentsRoot))
        {
            error = "arguments must be a JSON array";
            return false;
        }
        const size_t count = json_array_size(argumentsRoot);
        if(count > 4096u)
        {
            error = "arguments contains more than 4096 entries";
            return false;
        }
        spec.arguments.reserve(count);
        for(size_t index = 0; index < count; ++index)
        {
            std::string argumentUtf8;
            std::string field = "arguments[" + std::to_string(index) + "]";
            if(!jsonStringBytes(json_array_get(argumentsRoot, index),
                                argumentUtf8, error, field.c_str()))
                return false;
            std::wstring argument;
            if(!utf8FieldToWide(argumentUtf8, argument, error,
                                field.c_str()))
                return false;
            spec.arguments.push_back(std::move(argument));
        }

        std::wstring rawTail;
        if(!utf8FieldToWide(
                rawTailUtf8, rawTail, error, "rawCommandLineTail"))
            return false;
        if(!rawTail.empty())
        {
            if(!spec.arguments.empty())
            {
                error = "arguments and rawCommandLineTail are mutually exclusive";
                return false;
            }
            spec.rawCommandLineTail = std::move(rawTail);
            commandLineMode = "raw";
        }
        else
        {
            commandLineMode = "arguments";
        }
        const auto commandLine = spec.rawCommandLineTail
            ? mcplaunch::buildWindowsCommandLine(
                spec.executable, *spec.rawCommandLineTail)
            : mcplaunch::buildWindowsCommandLine(
                spec.executable, spec.arguments);
        if(!commandLine.ok)
        {
            error = commandLine.error;
            return false;
        }
        return true;
    }

    static bool parseLaunchEnvironment(
        const std::string& environmentJson,
        std::vector<mcplaunch::EnvironmentEntry>& overrides,
        size_t& overrideCount,
        std::string& error)
    {
        json_t* environmentRoot = nullptr;
        const std::string document = environmentJson.empty()
            ? "{}" : environmentJson;
        if(!parseJsonDocument(
                document, environmentRoot, error, "environment"))
            return false;
        JsonRef environmentOwner(environmentRoot);
        if(!json_is_object(environmentRoot))
        {
            error = "environment must be a JSON object";
            return false;
        }
        if(json_object_size(environmentRoot) > 512u)
        {
            error = "environment contains more than 512 variables";
            return false;
        }
        for(void* iterator = json_object_iter(environmentRoot); iterator;
            iterator = json_object_iter_next(environmentRoot, iterator))
        {
            const char* rawName = json_object_iter_key(iterator);
            json_t* rawValue = json_object_iter_value(iterator);
            if(!rawName || !*rawName || std::strchr(rawName, '='))
            {
                error = "Environment variable names must be non-empty and cannot contain '='";
                return false;
            }
            const std::string nameUtf8(rawName);
            std::wstring name;
            if(!utf8FieldToWide(
                    nameUtf8, name, error, "environment variable name", false))
                return false;
            if(json_is_null(rawValue))
            {
                overrides.push_back(
                    mcplaunch::EnvironmentEntry::erase(std::move(name)));
                continue;
            }
            std::string valueUtf8;
            if(!jsonStringBytes(
                    rawValue, valueUtf8, error, "environment value"))
                return false;
            std::wstring value;
            if(!utf8FieldToWide(
                    valueUtf8, value, error, "environment value"))
                return false;
            overrides.push_back(mcplaunch::EnvironmentEntry::set(
                std::move(name), std::move(value)));
        }
        overrideCount = overrides.size();
        const auto validation = mcplaunch::buildUnicodeEnvironmentBlock(
            {}, overrides);
        if(!validation.ok)
        {
            error = validation.error;
            return false;
        }
        return true;
    }

    static LaunchParseResult parseLaunchRequest(
        const std::unordered_map<std::string, std::string>& params)
    {
        LaunchParseResult result;
        const std::string contractVersionText =
            requestValue(params, "contractVersion");
        uint64_t contractVersion = 0;
        if(!mcpbridge::parseUnsignedDecimalExact(
                contractVersionText, contractVersion)
            || contractVersion != 2u)
        {
            result.errorCode = "unsupported_launch_contract";
            result.errorMessage =
                "contractVersion=2 is required by this bridge";
            return result;
        }

        const std::string exeUtf8 = requestValue(params, "exe");
        std::string error;
        if(!utf8FieldToWide(exeUtf8, result.spec.executable, error,
                            "exe", false))
        {
            result.errorCode = "invalid_executable";
            result.errorMessage = error;
            return result;
        }
        if(!isAbsoluteRegularFilePathW(result.spec.executable)
            || !fileExistsW(result.spec.executable))
        {
            result.status = 422;
            result.errorCode = "executable_not_found";
            result.errorMessage =
                "exe must identify an existing absolute regular file";
            return result;
        }

        if(!parseLaunchArguments(
                requestValue(params, "arguments"),
                requestValue(params, "rawCommandLineTail"),
                result.spec, result.commandLineMode, error))
        {
            result.errorCode = "invalid_launch_arguments";
            result.errorMessage = error;
            return result;
        }

        const std::string cwdUtf8 = requestValue(params, "cwd");
        if(!cwdUtf8.empty())
        {
            std::wstring cwd;
            if(!utf8FieldToWide(
                    cwdUtf8, cwd, error, "cwd", false))
            {
                result.errorCode = "invalid_working_directory";
                result.errorMessage = error;
                return result;
            }
            if(!isAbsoluteRegularFilePathW(cwd)
                || !directoryExistsW(cwd))
            {
                result.status = 422;
                result.errorCode = "working_directory_not_found";
                result.errorMessage =
                    "cwd must identify an existing absolute directory";
                return result;
            }
            result.spec.workingDirectory = std::move(cwd);
        }

        const std::string inheritText =
            requestValue(params, "inheritEnvironment");
        if(!inheritText.empty()
            && !parseStrictBool(
                inheritText, result.spec.inheritEnvironment))
        {
            result.errorCode = "invalid_inherit_environment";
            result.errorMessage =
                "inheritEnvironment must be true or false";
            return result;
        }
        if(!parseLaunchEnvironment(
                requestValue(params, "environment"),
                result.spec.environmentOverrides,
                result.environmentOverrideCount, error))
        {
            result.status = 422;
            result.errorCode = "invalid_launch_environment";
            result.errorMessage = error;
            return result;
        }

        size_t captureLimit = 1024u * 1024u;
        const std::string captureText =
            requestValue(params, "captureLimitBytes");
        if(!captureText.empty())
        {
            uint64_t parsed = 0;
            if(!mcpbridge::parseUnsignedDecimalExact(captureText, parsed)
                || parsed < kLaunchMinCaptureBytes
                || parsed > kLaunchMaxCaptureBytes)
            {
                result.errorCode = "invalid_capture_limit";
                result.errorMessage =
                    "captureLimitBytes must be between 4096 and 67108864";
                return result;
            }
            captureLimit = static_cast<size_t>(parsed);
        }
        result.spec.captureCapacity = captureLimit;
        result.spec.stdinQueueCapacity = captureLimit;

        const std::string stdinJson = requestValue(params, "stdin");
        const std::string stdoutJson = requestValue(params, "stdout");
        const std::string stderrJson = requestValue(params, "stderr");
        const bool anyStream = !stdinJson.empty()
            || !stdoutJson.empty() || !stderrJson.empty();
        const bool allStreams = !stdinJson.empty()
            && !stdoutJson.empty() && !stderrJson.empty();
        if(anyStream && !allStreams)
        {
            result.errorCode = "invalid_stream_spec";
            result.errorMessage =
                "stdin, stdout, and stderr must all be supplied together";
            return result;
        }
        if(!anyStream)
        {
            result.spec.stdinSpec.mode = mcplaunch::StdioMode::Console;
            result.spec.stdoutSpec.mode = mcplaunch::StdioMode::Console;
            result.spec.stderrSpec.mode = mcplaunch::StdioMode::Console;
        }
        else
        {
            json_t* stdinRoot = nullptr;
            json_t* stdoutRoot = nullptr;
            json_t* stderrRoot = nullptr;
            if(!parseJsonDocument(
                    stdinJson, stdinRoot, error, "stdin"))
            {
                result.errorCode = "invalid_stream_spec";
                result.errorMessage = error;
                return result;
            }
            JsonRef stdinOwner(stdinRoot);
            if(!parseJsonDocument(
                    stdoutJson, stdoutRoot, error, "stdout"))
            {
                result.errorCode = "invalid_stream_spec";
                result.errorMessage = error;
                return result;
            }
            JsonRef stdoutOwner(stdoutRoot);
            if(!parseJsonDocument(
                    stderrJson, stderrRoot, error, "stderr"))
            {
                result.errorCode = "invalid_stream_spec";
                result.errorMessage = error;
                return result;
            }
            JsonRef stderrOwner(stderrRoot);
            size_t pipeCapacity = captureLimit;
            if(!parseInputStream(
                    stdinRoot, result.spec.stdinSpec, pipeCapacity, error)
                || !parseOutputStream(
                    stdoutRoot, result.spec.stdoutSpec, "stdout", error)
                || !parseOutputStream(
                    stderrRoot, result.spec.stderrSpec, "stderr", error))
            {
                result.status = 422;
                result.errorCode = "invalid_stream_spec";
                result.errorMessage = error;
                return result;
            }
            result.spec.stdinQueueCapacity = std::max(
                pipeCapacity, result.spec.stdinSpec.initialBytes.size());
        }

        result.childPolicy = toLowerCopy(
            requestValue(params, "childPolicy").empty()
                ? "none" : requestValue(params, "childPolicy"));
        trimParam(result.childPolicy);
        const auto childPolicy = mcpchild::parsePolicy(result.childPolicy);
        if(!childPolicy.ok)
        {
            result.status = 422;
            result.errorCode = childPolicy.errorCode;
            result.errorMessage = childPolicy.error;
            return result;
        }
        result.childPolicy = childPolicy.canonical;
        result.ok = true;
        result.status = 200;
        return result;
    }

    static const char* launchStreamModeName(mcplaunch::StdioMode mode)
    {
        switch(mode)
        {
        case mcplaunch::StdioMode::Console: return "console";
        case mcplaunch::StdioMode::Inherit: return "inherit";
        case mcplaunch::StdioMode::Null: return "null";
        case mcplaunch::StdioMode::File: return "file";
        case mcplaunch::StdioMode::Bytes: return "bytes";
        case mcplaunch::StdioMode::Pipe: return "pipe";
        default: return "unknown";
        }
    }

    static void appendRuntimeErrorJson(
        std::stringstream& ss,
        const mcplaunch::RuntimeError& error)
    {
        if(!error)
        {
            ss << "null";
            return;
        }
        ss << "{\"code\":\""
           << escapeJsonString(error.code.c_str()) << "\","
           << "\"message\":\""
           << escapeJsonString(error.message.c_str()) << "\","
           << "\"win32Error\":" << std::dec << error.win32Error << ","
           << "\"retryable\":" << (error.retryable ? "true" : "false")
           << "}";
    }

    static void appendFileIdentityJson(
        std::stringstream& ss,
        const mcplaunch::FileIdentityResult& identity)
    {
        ss << "{\"available\":" << (identity.ok ? "true" : "false")
           << ",\"path\":\""
           << escapeJsonString(wideToUtf8(identity.finalPath).c_str()) << "\""
           << ",\"sha256\":\""
           << escapeJsonString(identity.sha256.c_str()) << "\""
           << ",\"size\":" << std::dec << identity.size
           << ",\"volumeSerialNumber\":" << identity.volumeSerialNumber
           << ",\"fileId\":\"" << launchFileIdHex(identity.fileId) << "\"";
        if(!identity.ok)
        {
            ss << ",\"error\":{\"code\":\""
               << escapeJsonString(identity.errorCode.c_str()) << "\","
               << "\"message\":\""
               << escapeJsonString(identity.error.c_str()) << "\","
               << "\"win32Error\":" << identity.win32Error << "}";
        }
        ss << "}";
    }

    static void appendStreamDescriptorJson(
        std::stringstream& ss,
        const mcplaunch::StreamDescriptor& descriptor,
        bool open,
        bool eof,
        size_t queuedBytes,
        const mcplaunch::RuntimeError& error)
    {
        ss << "{\"mode\":\"" << launchStreamModeName(descriptor.mode) << "\""
           << ",\"path\":\""
           << escapeJsonString(wideToUtf8(descriptor.path).c_str()) << "\""
           << ",\"redirected\":"
           << (descriptor.redirected ? "true" : "false")
           << ",\"captured\":" << (descriptor.captured ? "true" : "false")
           << ",\"writable\":" << (descriptor.writable ? "true" : "false")
           << ",\"open\":" << (open ? "true" : "false")
           << ",\"eof\":" << (eof ? "true" : "false")
           << ",\"queuedBytes\":" << std::dec << queuedBytes
           << ",\"error\":";
        appendRuntimeErrorJson(ss, error);
        ss << "}";
    }

    static void appendTeardownJson(
        std::stringstream& ss,
        const mcplaunch::TeardownStatus& teardown)
    {
        ss << "{\"requested\":" << (teardown.requested ? "true" : "false")
           << ",\"complete\":" << (teardown.complete ? "true" : "false")
           << ",\"timedOut\":" << (teardown.timedOut ? "true" : "false")
           << ",\"processTerminationRequested\":"
           << (teardown.processTerminationRequested ? "true" : "false")
           << ",\"processExited\":"
           << (teardown.processExited ? "true" : "false")
           << ",\"timeoutMs\":" << teardown.timeoutMs
           << ",\"workerCount\":" << teardown.workerCount
           << ",\"workersStopped\":" << teardown.workersStopped
           << ",\"cancellationAttempts\":"
           << teardown.cancellationAttempts
           << ",\"cancellationFailures\":"
           << teardown.cancellationFailures
           << ",\"error\":";
        appendRuntimeErrorJson(ss, teardown.error);
        ss << "}";
    }

    static std::string buildManagedLaunchJson(
        const std::shared_ptr<ManagedLaunch>& launch)
    {
        if(!launch)
            return "{}";
        std::lock_guard<std::mutex> lock(launch->mutex);
        const mcplaunch::ProcessState state = launch->runtime
            ? launch->runtime->state() : mcplaunch::ProcessState{};
        const std::string effectivePhase = state.exited
            ? "exited" : launch->phase;
        std::stringstream ss;
        ss << "{\"ok\":true"
           << ",\"launchId\":\""
           << escapeJsonString(launch->info.launchId.c_str()) << "\""
           << ",\"phase\":\""
           << escapeJsonString(effectivePhase.c_str()) << "\""
           << ",\"submitted\":" << (launch->attachSubmitted ? "true" : "false")
           << ",\"attached\":"
           << (launch->createProcessObserved ? "true" : "false")
           << ",\"identityVerified\":"
           << (launch->identityVerified ? "true" : "false")
           << ",\"resumed\":" << (launch->resumed ? "true" : "false")
           << ",\"resumePreviousSuspendCount\":"
           << launch->resumePreviousSuspendCount
           << ",\"debuggerSuspensionObserved\":"
           << (launch->debuggerSuspensionObserved ? "true" : "false")
           << ",\"ownershipCommitted\":"
           << (launch->ownershipCommitted ? "true" : "false")
           << ",\"resourceLifecycle\":{\"activeOperations\":"
           << launch->activeOperations
           << ",\"closeRequested\":"
           << (launch->closeRequested ? "true" : "false")
           << ",\"closeInProgress\":"
           << (launch->closeInProgress ? "true" : "false")
           << ",\"resourcesClosed\":"
           << (launch->resourcesClosed ? "true" : "false")
           << ",\"teardown\":";
         appendTeardownJson(ss, state.teardown);
         ss << "}"
           << ",\"commandLineMode\":\""
           << escapeJsonString(launch->commandLineMode.c_str()) << "\""
           << ",\"inheritEnvironment\":"
           << (launch->inheritEnvironment ? "true" : "false")
           << ",\"environmentOverrideCount\":"
           << std::dec << launch->environmentOverrideCount
           << ",\"captureLimitBytes\":" << launch->captureLimitBytes
           << ",\"childPolicy\":{\"requested\":\""
           << escapeJsonString(launch->childPolicy.c_str())
           << "\",\"effective\":\""
           << escapeJsonString(launch->childPolicy.c_str()) << "\"}"
           << ",\"process\":{\"pid\":" << launch->info.processId
           << ",\"primaryThreadId\":" << launch->info.primaryThreadId
           << ",\"creationTime100ns\":" << launch->info.creationTime100ns
#ifdef _WIN64
           << ",\"architecture\":\"x64\""
#else
           << ",\"architecture\":\"x86\""
#endif
           << ",\"createdSuspended\":"
           << (launch->info.createdSuspended ? "true" : "false")
           << ",\"suspended\":" << (state.suspended ? "true" : "false")
           << ",\"running\":" << (state.running ? "true" : "false")
           << ",\"exited\":" << (state.exited ? "true" : "false")
           << ",\"exitCodeKnown\":"
           << (state.exitCodeKnown ? "true" : "false")
           << ",\"exitCode\":" << state.exitCode
           << ",\"expectedIdentity\":";
        appendFileIdentityJson(ss, launch->expectedIdentity);
        ss << ",\"actualIdentity\":";
        appendFileIdentityJson(ss, launch->actualIdentity);
        ss << "},\"session\":{\"bridgeInstanceId\":\""
           << escapeJsonString(g_bridgeInstanceId.c_str()) << "\""
           << ",\"sessionId\":\""
           << escapeJsonString(launch->sessionId.c_str()) << "\""
           << ",\"generation\":" << launch->sessionGeneration
           << ",\"eventSeq\":" << launch->sessionEventSeq
           << ",\"processId\":" << launch->observedProcessId
           << "},\"streams\":{\"stdin\":";
        appendStreamDescriptorJson(
            ss, launch->info.stdinStream, state.stdinOpen, !state.stdinOpen,
            state.stdinQueuedBytes, state.stdinError);
        ss << ",\"stdout\":";
        appendStreamDescriptorJson(
            ss, launch->info.stdoutStream, !state.stdoutEof, state.stdoutEof,
            0, state.stdoutError);
        ss << ",\"stderr\":";
        appendStreamDescriptorJson(
            ss, launch->info.stderrStream, !state.stderrEof, state.stderrEof,
            0, state.stderrError);
        ss << "}";
        if(!launch->errorCode.empty())
        {
            ss << ",\"launchError\":{\"code\":\""
               << escapeJsonString(launch->errorCode.c_str()) << "\","
               << "\"message\":\""
               << escapeJsonString(launch->errorMessage.c_str()) << "\"}";
        }
        ss << "}";
        return ss.str();
    }

    static std::shared_ptr<ManagedLaunch> lookupManagedLaunch(
        const std::string& launchId)
    {
        std::lock_guard<std::mutex> lock(g_launchRegistryMutex);
        const auto found = g_launchRegistry.find(launchId);
        return found == g_launchRegistry.end()
            ? std::shared_ptr<ManagedLaunch>() : found->second;
    }

    static bool eraseManagedLaunchIfSame(
        const std::string& launchId,
        const std::shared_ptr<ManagedLaunch>& expected)
    {
        std::lock_guard<std::mutex> lock(g_launchRegistryMutex);
        const auto found = g_launchRegistry.find(launchId);
        if(found == g_launchRegistry.end() || found->second != expected)
            return false;
        g_launchRegistry.erase(found);
        return true;
    }

    static void setManagedLaunchError(
        const std::shared_ptr<ManagedLaunch>& launch,
        const std::string& code,
        const std::string& message)
    {
        if(!launch)
            return;
        std::lock_guard<std::mutex> lock(launch->mutex);
        launch->phase = "failed";
        launch->errorCode = code;
        launch->errorMessage = message;
    }

    static bool abortManagedLaunch(
        const std::shared_ptr<ManagedLaunch>& launch,
        bool stopDebugger)
    {
        if(!launch)
            return false;
        if(stopDebugger)
        {
            bool matchesCurrentSession = false;
            {
                std::lock_guard<std::mutex> lock(g_debugSession.mutex);
                matchesCurrentSession =
                    g_debugSession.processId == launch->info.processId;
            }
            if(matchesCurrentSession)
                DbgCmdExecDirect("stop");
        }
        {
            std::lock_guard<std::mutex> lock(launch->mutex);
            if(!launch->runtime)
                return false;
            if(launch->closeInProgress)
                return false;
            launch->closeRequested = true;
            launch->closeInProgress = true;
            launch->phase = "closing_resources";
        }
        mcplaunch::OperationResult closed =
            launch->runtime->closeResources(5000);
        {
            std::lock_guard<std::mutex> lock(launch->mutex);
            launch->closeInProgress = false;
            if(!closed.ok)
            {
                launch->teardownError = closed.error;
                launch->phase = "resource_close_failed";
                launch->errorCode = closed.error.code.empty()
                    ? "launch_resource_close_failed" : closed.error.code;
                launch->errorMessage = closed.error.message;
            }
            else
            {
                launch->resourcesClosed = true;
                launch->phase = "resources_closed";
            }
        }
        if(!closed.ok)
            return false;
        if(eraseManagedLaunchIfSame(launch->info.launchId, launch))
            return true;
        return false;
    }

    static LaunchHttpResult performManagedLaunch(
        const std::unordered_map<std::string, std::string>& params)
    {
        LaunchParseResult parsed = parseLaunchRequest(params);
        if(!parsed.ok)
            return launchHttpError(
                parsed.status, parsed.errorCode, parsed.errorMessage);
        if(DbgIsDebugging())
        {
            return launchHttpError(
                409, "debug_session_active",
                "Stop the current debug session before starting a new launch");
        }

        const mcplaunch::FileIdentityResult expected =
            mcplaunch::identifyFileByPath(parsed.spec.executable);
        if(!expected.ok)
        {
            return launchHttpError(
                422,
                expected.errorCode.empty()
                    ? "launch_identity_failed" : expected.errorCode,
                expected.error.empty()
                    ? "The executable identity could not be established"
                    : expected.error,
                false, expected.win32Error);
        }

        uint64_t generationBefore = 0;
        {
            std::lock_guard<std::mutex> lock(g_debugSession.mutex);
            generationBefore = g_debugSession.generation;
        }
        mcplaunch::LaunchResult created =
            mcplaunch::LaunchRuntime::createSuspended(parsed.spec);
        if(!created.ok || !created.runtime)
        {
            return launchHttpError(
                422,
                created.error.code.empty()
                    ? "create_process_failed" : created.error.code,
                created.error.message.empty()
                    ? "CreateProcessW failed" : created.error.message,
                created.error.retryable, created.error.win32Error);
        }

        auto launch = std::make_shared<ManagedLaunch>();
        launch->runtime = std::move(created.runtime);
        launch->info = created.info;
        launch->expectedIdentity = expected;
        launch->childPolicy = parsed.childPolicy;
        launch->commandLineMode = parsed.commandLineMode;
        launch->inheritEnvironment = parsed.spec.inheritEnvironment;
        launch->environmentOverrideCount = parsed.environmentOverrideCount;
        launch->captureLimitBytes = parsed.spec.captureCapacity;
        {
            std::lock_guard<std::mutex> lock(g_launchRegistryMutex);
            if(!g_launchRegistry.emplace(
                    launch->info.launchId, launch).second)
            {
                return launchHttpError(
                    500, "launch_id_collision",
                    "The generated launch identifier already exists");
            }
        }

        ManagedLaunchOperationPin launchOperation(launch);
        if(!launchOperation.acquired())
        {
            setManagedLaunchError(
                launch, "launch_operation_pin_failed",
                "The launch runtime could not be pinned before attach");
            (void)abortManagedLaunch(launch, false);
            return launchHttpError(
                500, "launch_operation_pin_failed",
                "The launch runtime could not be pinned before attach");
        }

        char command[64] = {};
        _snprintf_s(command, sizeof(command), _TRUNCATE,
                    "attach 0x%lX",
                    static_cast<unsigned long>(launch->info.processId));
        const bool attachSubmitted = DbgCmdExecDirect(command);
        {
            std::lock_guard<std::mutex> lock(launch->mutex);
            launch->attachSubmitted = attachSubmitted;
            launch->phase = attachSubmitted
                ? "attach_submitted" : "attach_submit_failed";
        }
        if(!attachSubmitted)
        {
            setManagedLaunchError(
                launch, "attach_submit_failed",
                "x64dbg rejected the attach command");
            launchOperation.release();
            (void)abortManagedLaunch(launch, false);
            return launchHttpError(
                500, "attach_submit_failed",
                "x64dbg rejected the attach command");
        }

        bool observed = false;
        {
            std::unique_lock<std::mutex> lock(launch->mutex);
            observed = launch->cv.wait_for(
                lock, std::chrono::milliseconds(kLaunchAttachTimeoutMs),
                [&]() { return launch->createProcessObserved; });
        }
        if(!observed)
        {
            setManagedLaunchError(
                launch, "attach_create_event_timeout",
                "x64dbg did not report the root CREATE_PROCESS event in time");
            launchOperation.release();
            (void)abortManagedLaunch(launch, true);
            return launchHttpError(
                504, "attach_create_event_timeout",
                "x64dbg did not report the root CREATE_PROCESS event in time",
                true);
        }

        bool verified = false;
        std::string verificationCode;
        std::string verificationMessage;
        {
            std::lock_guard<std::mutex> lock(launch->mutex);
            verified = launch->identityVerified
                && !launch->sessionId.empty()
                && launch->sessionGeneration > generationBefore
                && launch->observedProcessId == launch->info.processId;
            verificationCode = launch->errorCode;
            verificationMessage = launch->errorMessage;
        }
        if(!verified)
        {
            if(verificationCode.empty())
                verificationCode = "launch_session_identity_mismatch";
            if(verificationMessage.empty())
                verificationMessage =
                    "The attached x64dbg session did not match the suspended process";
            setManagedLaunchError(
                launch, verificationCode, verificationMessage);
            launchOperation.release();
            (void)abortManagedLaunch(launch, true);
            return launchHttpError(
                409, verificationCode, verificationMessage);
        }

        std::string childBrokerErrorCode;
        std::string childBrokerErrorMessage;
        if(!childBrokerConfigureForLaunch(
                launch->childPolicy, launch->info.launchId,
                launch->info.processId, childBrokerErrorCode,
                childBrokerErrorMessage))
        {
            setManagedLaunchError(
                launch,
                childBrokerErrorCode.empty()
                    ? "child_broker_configuration_failed" : childBrokerErrorCode,
                childBrokerErrorMessage.empty()
                    ? "The requested child policy could not be armed safely"
                    : childBrokerErrorMessage);
            launchOperation.release();
            (void)abortManagedLaunch(launch, true);
            return launchHttpError(
                422,
                childBrokerErrorCode.empty()
                    ? "child_broker_configuration_failed" : childBrokerErrorCode,
                childBrokerErrorMessage.empty()
                    ? "The requested child policy could not be armed safely"
                    : childBrokerErrorMessage);
        }

        const mcplaunch::ResumeResult resumed =
            launch->runtime->resumeAfterValidation();
        if(!resumed.ok)
        {
            const std::string code = resumed.error.code.empty()
                ? "primary_thread_resume_failed" : resumed.error.code;
            const std::string message = resumed.error.message.empty()
                ? "The runtime-created primary-thread suspension could not be released"
                : resumed.error.message;
            setManagedLaunchError(launch, code, message);
            launchOperation.release();
            (void)abortManagedLaunch(launch, true);
            return launchHttpError(
                500, code, message, resumed.error.retryable,
                resumed.error.win32Error);
        }
        {
            std::lock_guard<std::mutex> lock(launch->mutex);
            launch->resumed = true;
            launch->resumePreviousSuspendCount =
                resumed.previousSuspendCount;
            launch->debuggerSuspensionObserved =
                resumed.remainsSuspended;
            launch->phase = "resumed_under_debugger";
        }

        const mcplaunch::OperationResult committed =
            launch->runtime->commitExternalDebuggerOwnership();
        if(!committed.ok)
        {
            const std::string code = committed.error.code.empty()
                ? "debugger_ownership_commit_failed" : committed.error.code;
            const std::string message = committed.error.message.empty()
                ? "External debugger ownership could not be committed"
                : committed.error.message;
            setManagedLaunchError(launch, code, message);
            launchOperation.release();
            (void)abortManagedLaunch(launch, true);
            return launchHttpError(
                500, code, message, committed.error.retryable,
                committed.error.win32Error);
        }
        {
            std::lock_guard<std::mutex> lock(launch->mutex);
            launch->ownershipCommitted = true;
            launch->phase = "attached_paused";
        }
        return {200, buildManagedLaunchJson(launch)};
    }

    static bool validateLaunchId(const std::string& launchId)
    {
        if(launchId.empty() || launchId.size() > 128u)
            return false;
        return std::all_of(
            launchId.begin(), launchId.end(), [](unsigned char character) {
                return character >= 0x21u && character <= 0x7eu;
            });
    }

    static LaunchHttpResult requireManagedLaunch(
        const std::unordered_map<std::string, std::string>& params,
        std::shared_ptr<ManagedLaunch>& launch)
    {
        const std::string launchId = requestValue(params, "launchId");
        if(!validateLaunchId(launchId))
        {
            return launchHttpError(
                400, "invalid_launch_id",
                "launchId must contain 1..128 printable ASCII characters");
        }
        launch = lookupManagedLaunch(launchId);
        if(!launch)
        {
            return launchHttpError(
                404, "launch_not_found",
                "No retained launch has this launchId");
        }
        return {200, {}};
    }

    static bool managedLaunchMatchesCurrentSession(
        const std::shared_ptr<ManagedLaunch>& launch)
    {
        if(!launch)
            return false;
        std::string sessionId;
        uint64_t generation = 0;
        DWORD processId = 0;
        {
            std::lock_guard<std::mutex> lock(launch->mutex);
            sessionId = launch->sessionId;
            generation = launch->sessionGeneration;
            processId = launch->info.processId;
        }
        std::lock_guard<std::mutex> sessionLock(g_debugSession.mutex);
        return !sessionId.empty()
            && _stricmp(sessionId.c_str(),
                       g_debugSession.sessionId.c_str()) == 0
            && generation == g_debugSession.generation
            && processId == g_debugSession.processId;
    }

    static LaunchHttpResult readManagedLaunchStream(
        const std::unordered_map<std::string, std::string>& params)
    {
        std::shared_ptr<ManagedLaunch> launch;
        LaunchHttpResult required = requireManagedLaunch(params, launch);
        if(!launch)
            return required;
        ManagedLaunchOperationPin operation(launch);
        if(!operation.acquired())
        {
            return launchHttpError(
                409, "launch_resources_closing",
                "The launch runtime is closing or has already been released",
                true);
        }
        std::string stream = toLowerCopy(requestValue(params, "stream"));
        trimParam(stream);
        if(stream != "stdout" && stream != "stderr")
        {
            return launchHttpError(
                400, "invalid_launch_stream",
                "stream must be stdout or stderr");
        }
        uint64_t cursor = 0;
        uint64_t maxBytesRaw = 0;
        uint64_t waitMsRaw = 0;
        if(!mcpbridge::parseUnsignedDecimalExact(
                requestValue(params, "cursor"), cursor)
            || !mcpbridge::parseUnsignedDecimalExact(
                requestValue(params, "maxBytes"), maxBytesRaw)
            || maxBytesRaw == 0 || maxBytesRaw > kLaunchMaxIoChunkBytes)
        {
            return launchHttpError(
                400, "invalid_launch_stream_range",
                "cursor must be uint64 and maxBytes must be between 1 and 1048576");
        }
        const std::string waitText = requestValue(params, "waitMs");
        if(!waitText.empty()
            && (!mcpbridge::parseUnsignedDecimalExact(waitText, waitMsRaw)
                || waitMsRaw > 60000u))
        {
            return launchHttpError(
                400, "invalid_launch_wait",
                "waitMs must be between 0 and 60000");
        }
        const unsigned int requestedWait =
            static_cast<unsigned int>(waitMsRaw);
        const unsigned int effectiveWait =
            std::min(requestedWait, MAX_SERVER_WAIT_SLICE_MS);
        const ULONGLONG started = nowTickMs();
        mcplaunch::CaptureReadResult read;
        while(true)
        {
            read = stream == "stdout"
                ? launch->runtime->readStdout(
                    cursor, static_cast<size_t>(maxBytesRaw))
                : launch->runtime->readStderr(
                    cursor, static_cast<size_t>(maxBytesRaw));
            if(!read.ok || !read.capture.bytes.empty()
                || read.capture.eof || effectiveWait == 0)
                break;
            const ULONGLONG elapsed = nowTickMs() - started;
            if(elapsed >= effectiveWait
                || g_httpServer.stopRequested.load(std::memory_order_acquire))
                break;
            const DWORD remaining = static_cast<DWORD>(
                effectiveWait - static_cast<unsigned int>(elapsed));
            Sleep(std::min<DWORD>(remaining, 5u));
        }
        if(!read.ok)
        {
            return launchHttpError(
                409,
                read.error.code.empty()
                    ? "launch_stream_unavailable" : read.error.code,
                read.error.message.empty()
                    ? "The requested stream is not captured" : read.error.message,
                read.error.retryable, read.error.win32Error);
        }
        const auto& capture = read.capture;
        const unsigned int waited = static_cast<unsigned int>(
            std::min<ULONGLONG>(nowTickMs() - started,
                                std::numeric_limits<unsigned int>::max()));
        std::stringstream ss;
        ss << "{\"ok\":true,\"launchId\":\""
           << escapeJsonString(launch->info.launchId.c_str()) << "\""
           << ",\"stream\":\"" << stream << "\""
           << ",\"dataBase64\":\""
           << mcplaunch::encodeBase64(capture.bytes) << "\""
           << ",\"byteCount\":" << capture.bytes.size()
           << ",\"requestedCursor\":" << capture.requestedCursor
           << ",\"effectiveCursor\":" << capture.effectiveCursor
           << ",\"nextCursor\":" << capture.nextCursor
           << ",\"oldestCursor\":" << capture.oldestCursor
           << ",\"newestCursor\":" << capture.newestCursor
           << ",\"availableBytes\":" << capture.availableBytes
           << ",\"totalDroppedBytes\":" << capture.totalDroppedBytes
           << ",\"droppedBeforeCursor\":" << capture.droppedBeforeCursor
           << ",\"cursorTruncated\":"
           << (capture.cursorTruncated ? "true" : "false")
           << ",\"cursorAhead\":"
           << (capture.cursorAhead ? "true" : "false")
           << ",\"limited\":" << (capture.limited ? "true" : "false")
           << ",\"truncated\":" << (capture.truncated ? "true" : "false")
           << ",\"closed\":" << (capture.closed ? "true" : "false")
           << ",\"eof\":" << (capture.eof ? "true" : "false")
           << ",\"requestedWaitMs\":" << requestedWait
           << ",\"effectiveWaitMs\":" << effectiveWait
           << ",\"waitedMs\":" << waited
           << ",\"waitSliceCapped\":"
           << (requestedWait > effectiveWait ? "true" : "false")
           << "}";
        return {200, ss.str()};
    }

    static LaunchHttpResult writeManagedLaunchStdin(
        const std::unordered_map<std::string, std::string>& params)
    {
        std::shared_ptr<ManagedLaunch> launch;
        LaunchHttpResult required = requireManagedLaunch(params, launch);
        if(!launch)
            return required;
        ManagedLaunchOperationPin operation(launch);
        if(!operation.acquired())
        {
            return launchHttpError(
                409, "launch_resources_closing",
                "The launch runtime is closing or has already been released",
                true);
        }
        if(!managedLaunchMatchesCurrentSession(launch))
        {
            return launchHttpError(
                409, "launch_session_mismatch",
                "This launch is not the active debug session");
        }
        const auto decoded = mcplaunch::decodeBase64Strict(
            requestValue(params, "dataBase64"), kLaunchMaxIoChunkBytes);
        if(!decoded.ok || decoded.bytes.empty())
        {
            return launchHttpError(
                400, "invalid_stdin_base64",
                decoded.ok
                    ? "dataBase64 must decode to at least one byte"
                    : decoded.error);
        }
        uint64_t waitMsRaw = 0;
        const std::string waitText = requestValue(params, "waitMs");
        if(!waitText.empty()
            && (!mcpbridge::parseUnsignedDecimalExact(waitText, waitMsRaw)
                || waitMsRaw > 60000u))
        {
            return launchHttpError(
                400, "invalid_launch_wait",
                "waitMs must be between 0 and 60000");
        }
        bool closeAfterWrite = false;
        const std::string closeText =
            requestValue(params, "closeAfterWrite");
        if(!closeText.empty()
            && !parseStrictBool(closeText, closeAfterWrite))
        {
            return launchHttpError(
                400, "invalid_close_after_write",
                "closeAfterWrite must be true or false");
        }
        const DWORD effectiveWait = static_cast<DWORD>(
            std::min<uint64_t>(waitMsRaw, MAX_SERVER_WAIT_SLICE_MS));
        const mcplaunch::WriteInputResult written =
            launch->runtime->writeInput(decoded.bytes, effectiveWait);
        if(!written.ok)
        {
            std::stringstream message;
            message << (written.error.message.empty()
                ? "The stdin write failed" : written.error.message)
                << " (queued " << written.queuedBytes
                << " of " << written.queueCapacity << " bytes)";
            return launchHttpError(
                written.wouldBlock ? 429 : 409,
                written.error.code.empty()
                    ? "launch_stdin_write_failed" : written.error.code,
                message.str(), written.error.retryable,
                written.error.win32Error);
        }
        if(closeAfterWrite)
        {
            const mcplaunch::OperationResult closed =
                launch->runtime->closeInput();
            if(!closed.ok)
            {
                return launchHttpError(
                    409,
                    closed.error.code.empty()
                        ? "launch_stdin_close_failed" : closed.error.code,
                    closed.error.message.empty()
                        ? "stdin was queued but could not be closed"
                        : closed.error.message,
                    closed.error.retryable, closed.error.win32Error);
            }
        }
        std::stringstream ss;
        ss << "{\"ok\":true,\"launchId\":\""
           << escapeJsonString(launch->info.launchId.c_str()) << "\""
           << ",\"acceptedBytes\":" << written.acceptedBytes
           << ",\"queuedBytes\":" << written.queuedBytes
           << ",\"queueCapacity\":" << written.queueCapacity
           << ",\"closed\":" << (closeAfterWrite ? "true" : "false")
           << ",\"requestedWaitMs\":" << waitMsRaw
           << ",\"effectiveWaitMs\":" << effectiveWait
           << ",\"waitSliceCapped\":"
           << (waitMsRaw > effectiveWait ? "true" : "false")
           << "}";
        return {200, ss.str()};
    }

    static LaunchHttpResult closeManagedLaunchStdin(
        const std::unordered_map<std::string, std::string>& params)
    {
        std::shared_ptr<ManagedLaunch> launch;
        LaunchHttpResult required = requireManagedLaunch(params, launch);
        if(!launch)
            return required;
        ManagedLaunchOperationPin operation(launch);
        if(!operation.acquired())
        {
            return launchHttpError(
                409, "launch_resources_closing",
                "The launch runtime is closing or has already been released",
                true);
        }
        if(!managedLaunchMatchesCurrentSession(launch))
        {
            return launchHttpError(
                409, "launch_session_mismatch",
                "This launch is not the active debug session");
        }
        const mcplaunch::OperationResult closed =
            launch->runtime->closeInput();
        if(!closed.ok)
        {
            return launchHttpError(
                409,
                closed.error.code.empty()
                    ? "launch_stdin_close_failed" : closed.error.code,
                closed.error.message.empty()
                    ? "stdin could not be closed" : closed.error.message,
                closed.error.retryable, closed.error.win32Error);
        }
        return {200, std::string("{\"ok\":true,\"launchId\":\"")
            + escapeJsonString(launch->info.launchId.c_str())
            + "\",\"closed\":true}"};
    }

    static LaunchHttpResult closeManagedLaunchResources(
        const std::unordered_map<std::string, std::string>& params)
    {
        std::shared_ptr<ManagedLaunch> launch;
        LaunchHttpResult required = requireManagedLaunch(params, launch);
        if(!launch)
            return required;
        uint64_t timeoutRaw = 5000;
        const std::string timeoutText = requestValue(params, "timeoutMs");
        if(!timeoutText.empty()
           && (!mcpbridge::parseUnsignedDecimalExact(timeoutText, timeoutRaw)
               || timeoutRaw > 30000u))
        {
            return launchHttpError(
                400, "invalid_teardown_timeout",
                "timeoutMs must be between 0 and 30000");
        }
        const std::string launchId = launch->info.launchId;
        {
            std::lock_guard<std::mutex> lock(launch->mutex);
            if(launch->resourcesClosed)
            {
                return launchHttpError(
                    409, "launch_resources_closed",
                    "Launch resources have already been released");
            }
            if(launch->closeInProgress)
            {
                return launchHttpError(
                    409, "launch_resources_close_in_progress",
                    "Another resource-close operation is already in progress",
                    true);
            }
            if(launch->activeOperations != 0)
            {
                return launchHttpError(
                    409, "launch_in_use",
                    "Launch resources are still in use by an in-flight operation",
                    true);
            }
            if(!launch->runtime)
            {
                return launchHttpError(
                    409, "launch_runtime_unavailable",
                    "The launch runtime is no longer available");
            }
            launch->closeRequested = true;
            launch->closeInProgress = true;
            launch->phase = "closing_resources";
        }

        mcplaunch::OperationResult closed =
            launch->runtime->closeResources(
                static_cast<DWORD>(timeoutRaw));
        {
            std::lock_guard<std::mutex> lock(launch->mutex);
            launch->closeInProgress = false;
            if(closed.ok)
            {
                launch->resourcesClosed = true;
                launch->phase = "resources_closed";
                launch->teardownError = mcplaunch::RuntimeError{};
            }
            else
            {
                launch->phase = "resource_close_failed";
                launch->teardownError = closed.error;
                launch->errorCode = closed.error.code.empty()
                    ? "launch_resource_close_failed" : closed.error.code;
                launch->errorMessage = closed.error.message;
            }
        }
        if(!closed.ok)
        {
            const int status = closed.error.code == "launch_teardown_timeout"
                || closed.error.retryable ? 504 : 409;
            std::stringstream ss;
            ss << "{\"ok\":false,\"launchId\":\""
               << escapeJsonString(launchId.c_str())
               << "\",\"released\":false,\"error\":";
            appendRuntimeErrorJson(ss, closed.error);
            ss << ",\"state\":" << buildManagedLaunchJson(launch) << "}";
            return {status, ss.str()};
        }
        if(!eraseManagedLaunchIfSame(launchId, launch))
        {
            return launchHttpError(
                409, "launch_registry_changed",
                "The launch registry changed while resources were closing",
                true);
        }
        std::stringstream ss;
        ss << "{\"ok\":true,\"launchId\":\""
           << escapeJsonString(launchId.c_str())
           << "\",\"released\":true,\"timeoutMs\":" << timeoutRaw
           << "}";
        return {200, ss.str()};
    }
}

DWORD WINAPI HttpServerThread(LPVOID lpParam) {
    // Turn structured exceptions on this thread into catchable C++ exceptions so
    // a faulting request handler returns HTTP 500 instead of crashing x64dbg.
    installSehTranslator();
    int configuredPort = DEFAULT_PORT;
    {
        std::lock_guard<std::mutex> lock(g_httpServer.mutex);
        configuredPort = g_httpServer.configuredPort;
    }

    WSADATA wsaData;
    int result = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (result != 0) {
        _plugin_logprintf("WSAStartup failed with error: %d\n", result);
        {
            std::lock_guard<std::mutex> lock(g_httpServer.mutex);
            g_httpServer.state = HttpLifecycleState::Failed;
            g_httpServer.threadExitCode = 1;
            g_httpServer.lastError = "WSAStartup failed: " + std::to_string(result);
        }
        g_httpServer.cv.notify_all();
        return 1;
    }

    SOCKET listenSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    auto failStartup = [&](const std::string& message, DWORD exitCode) -> DWORD {
        clearBridgeAuthToken();
        bool closeOwnedSocket = false;
        {
            std::lock_guard<std::mutex> lock(g_httpServer.mutex);
            if (g_httpServer.listenSocket == listenSocket) {
                g_httpServer.listenSocket = INVALID_SOCKET;
                closeOwnedSocket = listenSocket != INVALID_SOCKET;
            } else if (g_httpServer.listenSocket == INVALID_SOCKET
                       && !g_httpServer.stopRequested.load(std::memory_order_acquire)) {
                // The socket was never published (for example socket() failed).
                closeOwnedSocket = listenSocket != INVALID_SOCKET;
            }
            g_httpServer.state = g_httpServer.stopRequested.load(std::memory_order_acquire)
                ? HttpLifecycleState::Stopped
                : HttpLifecycleState::Failed;
            g_httpServer.boundPort = 0;
            g_httpServer.threadExitCode = exitCode;
            g_httpServer.lastError = message;
        }
        if (closeOwnedSocket) {
            closesocket(listenSocket);
        }
        g_httpServer.cv.notify_all();
        WSACleanup();
        return exitCode;
    };

    if (listenSocket == INVALID_SOCKET) {
        const int error = WSAGetLastError();
        _plugin_logprintf("Failed to create socket, error: %d\n", error);
        return failStartup("socket failed: " + std::to_string(error), 1);
    }
    bool startCanceled = false;
    {
        std::lock_guard<std::mutex> lock(g_httpServer.mutex);
        if (g_httpServer.stopRequested.load(std::memory_order_acquire)) {
            startCanceled = true;
        } else {
            g_httpServer.listenSocket = listenSocket;
        }
    }
    if (startCanceled) {
        return failStartup("server start canceled", 0);
    }
    sockaddr_in serverAddr;
    ZeroMemory(&serverAddr, sizeof(serverAddr));
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    serverAddr.sin_port = htons((u_short)configuredPort);
    if (bind(listenSocket, (sockaddr*)&serverAddr, sizeof(serverAddr)) == SOCKET_ERROR) {
        const int error = WSAGetLastError();
        _plugin_logprintf("Bind failed with error: %d\n", error);
        return failStartup("bind failed: " + std::to_string(error), 1);
    }
    sockaddr_in boundAddress = {};
    int boundAddressLength = sizeof(boundAddress);
    if (getsockname(listenSocket, (sockaddr*)&boundAddress, &boundAddressLength) == SOCKET_ERROR) {
        const int error = WSAGetLastError();
        return failStartup("getsockname failed: " + std::to_string(error), 1);
    }
    const int actualBoundPort = static_cast<int>(ntohs(boundAddress.sin_port));
    if(actualBoundPort <= 0 || actualBoundPort > 65535)
        return failStartup("getsockname returned an invalid bound port", 1);
    bool boundPortStartCanceled = false;
    {
        std::lock_guard<std::mutex> lock(g_httpServer.mutex);
        boundPortStartCanceled = g_httpServer.stopRequested.load(std::memory_order_acquire);
        if(!boundPortStartCanceled)
            g_httpServer.boundPort = actualBoundPort;
    }
    if(boundPortStartCanceled)
        return failStartup("server start canceled", 0);
    if (listen(listenSocket, SOMAXCONN) == SOCKET_ERROR) {
        const int error = WSAGetLastError();
        _plugin_logprintf("Listen failed with error: %d\n", error);
        return failStartup("listen failed: " + std::to_string(error), 1);
    }

    u_long mode = 1;
    if (ioctlsocket(listenSocket, FIONBIO, &mode) == SOCKET_ERROR) {
        const int error = WSAGetLastError();
        return failStartup("ioctlsocket(FIONBIO) failed: " + std::to_string(error), 1);
    }
    // Publish the protected bootstrap descriptor only after this process owns
    // the loopback listening socket. A failed bind must never advertise a token.
    if (!rotateBridgeAuthToken()) {
        return failStartup("failed to publish bridge authentication token", 1);
    }
    startCanceled = false;
    {
        std::lock_guard<std::mutex> lock(g_httpServer.mutex);
        if (g_httpServer.stopRequested.load(std::memory_order_acquire)) {
            startCanceled = true;
        } else {
            g_httpServer.boundPort = actualBoundPort;
            g_httpServer.state = HttpLifecycleState::Running;
            g_httpServer.lastError.clear();
        }
    }
    if (startCanceled) {
        return failStartup("server start canceled", 0);
    }
    g_httpServer.cv.notify_all();
    _plugin_logprintf("HTTP server started at http://localhost:%d/\n", actualBoundPort);

    while (!g_httpServer.stopRequested.load(std::memory_order_acquire)) {
        sockaddr_in clientAddr;
        int clientAddrSize = sizeof(clientAddr);
        SOCKET clientSocket = accept(listenSocket, (sockaddr*)&clientAddr, &clientAddrSize);

        if (clientSocket == INVALID_SOCKET) {
            if (g_httpServer.stopRequested.load(std::memory_order_acquire)) {
                break;
            }
            if (WSAGetLastError() != WSAEWOULDBLOCK) {
                _plugin_logprintf("Accept failed with error: %d\n", WSAGetLastError());
            }
            Sleep(100);
            continue;
        }
        bool acceptDuringStop = false;
        bool admissionOverloaded = false;
        uint64_t admissionTicket = 0;
        {
            std::lock_guard<std::mutex> lock(g_httpServer.mutex);
            acceptDuringStop = g_httpServer.stopRequested.load(std::memory_order_acquire);
            if (!acceptDuringStop) {
                if(!g_httpServer.dispatcher.tryAdmit(admissionTicket))
                    admissionOverloaded = true;
                else
                {
                    g_httpServer.activeClientSockets.insert(clientSocket);
                    ++g_httpServer.liveWorkerCount;
                }
            }
        }
        if (acceptDuringStop) {
            closesocket(clientSocket);
            break;
        }
        if(admissionOverloaded)
        {
            sendHttpResponse(clientSocket, 503, "application/json",
                "{\"ok\":false,\"data\":null,\"error\":{\"code\":\"request_queue_full\","
                "\"message\":\"The bounded HTTP request queue is full\","
                "\"retryable\":true},\"meta\":{\"contractVersion\":1}}");
            closesocket(clientSocket);
            continue;
        }
        // Each admitted connection owns one bounded worker/queue slot.  The
        // detached thread waits for one of the fixed execution slots; the
        // server thread continues accepting health/pause requests immediately.
        try {
        std::thread([clientSocket, admissionTicket]() {
        HttpRequestWorkerScope requestWorkerScope;
        // _set_se_translator is thread-local.  Every request worker needs its
        // own translator or an AV in a Script/x64dbg API tears down x64dbg.
        installSehTranslator();
        bool runningSlot = false;
        bool queueTimedOut = false;
        {
        ClientSocketGuard clientGuard(clientSocket);
        {
            std::unique_lock<std::mutex> lock(g_httpServer.mutex);
            const auto queueDeadline = std::chrono::steady_clock::now()
                + std::chrono::milliseconds(MAX_HTTP_QUEUE_WAIT_MS);
            while(!g_httpServer.stopRequested.load(std::memory_order_acquire)
                && !g_httpServer.dispatcher.canStart(admissionTicket))
            {
                if(g_httpServer.cv.wait_until(lock, queueDeadline) == std::cv_status::timeout
                    && !g_httpServer.dispatcher.canStart(admissionTicket))
                {
                    g_httpServer.dispatcher.cancel(admissionTicket);
                    queueTimedOut = true;
                    break;
                }
            }
            if(!queueTimedOut)
            {
                if(g_httpServer.stopRequested.load(std::memory_order_acquire))
                {
                    g_httpServer.dispatcher.cancel(admissionTicket);
                }
                else if(g_httpServer.dispatcher.tryStart(admissionTicket)
                    == mcpdispatcher::StartDecision::Started)
                {
                    runningSlot = true;
                }
                else
                {
                    g_httpServer.dispatcher.cancel(admissionTicket);
                    queueTimedOut = true;
                }
            }
        }
        g_httpServer.cv.notify_all();
        if(queueTimedOut
            && !g_httpServer.stopRequested.load(std::memory_order_acquire))
        {
            sendHttpResponse(clientSocket, 503, "application/json",
                "{\"ok\":false,\"data\":null,\"error\":{\"code\":\"request_queue_timeout\",\"message\":\"Timed out in the bounded HTTP request queue\",\"retryable\":true},\"meta\":{\"contractVersion\":1}}" );
        }
        if(runningSlot) try { do {
        int readErrorStatus = 0;
        std::string readErrorCode;
        std::string readErrorText;
        std::string requestData = readHttpRequest(
            clientSocket, readErrorStatus, readErrorCode, readErrorText);
        if (readErrorStatus != 0) {
            const bool retryable = readErrorStatus == 408 || readErrorStatus == 429
                || readErrorStatus == 502 || readErrorStatus == 503 || readErrorStatus == 504;
            std::stringstream errorResponse;
            errorResponse << "{\"ok\":false,\"data\":null,\"error\":{\"code\":\""
                << escapeJsonString((readErrorCode.empty() ? (std::string("HTTP_")
                    + std::to_string(readErrorStatus)) : readErrorCode).c_str())
                << "\",\"message\":\""
                << escapeJsonString(readErrorText.c_str()) << "\",\"retryable\":"
                << (retryable ? "true" : "false") << ",\"httpStatus\":"
                << readErrorStatus << "},\"meta\":{\"contractVersion\":1}}";
            sendHttpResponse(clientSocket, readErrorStatus, "application/json", errorResponse.str());
            continue;
        }
        if (!requestData.empty()) {
            // Authenticate and enforce loopback origin before parsing the
            // request target or decoding any query/body parameters.  This
            // keeps unauthenticated input on the bounded header-only path.
            if (!isRequestOriginAllowed(requestData)) {
                sendHttpResponse(clientSocket, 403, "text/plain",
                    "Forbidden: request rejected (non-loopback Host or cross-origin Origin)");
                continue;
            }
            if (!isBridgeAuthenticationValid(requestData)) {
                sendHttpResponse(clientSocket, 401, "application/json",
                    "{\"ok\":false,\"data\":null,\"error\":{\"code\":\"authentication_required\","
                    "\"message\":\"A valid X-MCP-Auth-Token header is required\","
                    "\"retryable\":false},\"meta\":{\"contractVersion\":1}}");
                continue;
            }
            std::string method, path, query, body;
            if (!parseHttpRequest(requestData, method, path, query, body)) {
                sendHttpResponse(clientSocket, 400, "application/json",
                    "{\"ok\":false,\"data\":null,\"error\":{\"code\":\"malformed_request_line\",\"message\":\"Malformed HTTP request line or headers\",\"retryable\":false},\"meta\":{\"contractVersion\":1}}");
                continue;
            }
            if (method != "GET" && method != "POST") {
                sendHttpResponse(clientSocket, 405, "application/json",
                    "{\"ok\":false,\"error\":{\"code\":\"method_not_allowed\",\"message\":\"Only GET and POST are supported\",\"retryable\":false}}");
                continue;
            }
            // Origin/authentication have already succeeded; only now decode
            // attacker-controlled query/body parameters.
            std::unordered_map<std::string, std::string> queryParams = mergeRequestParams(query, body);
            if (path == "/Bridge/Hello") {
                sendHttpResponse(clientSocket, 200, "application/json", buildBridgeHelloJson());
                continue;
            }
            const bool exceptionPolicyReadRoute = path == "/Debug/ExceptionPolicy/Get"
                || path == "/Debug/ExceptionHistory/Get";
            const bool exceptionPolicyMutationRoute = path == "/Debug/ExceptionPolicy/Set"
                || path == "/Debug/ExceptionPolicy/Clear"
                || path == "/Debug/ExceptionHistory/Clear";
            if ((exceptionPolicyReadRoute && method != "GET")
                || (exceptionPolicyMutationRoute && method != "POST")) {
                sendHttpResponse(clientSocket, 405, "application/json",
                    "{\"ok\":false,\"error\":{\"code\":\"method_not_allowed\",\"message\":\"This exception endpoint requires its declared GET or POST method\",\"retryable\":false}}");
                continue;
            }
            const MutationGuardDecision guard = validateMutationGuard(
                requestData, path, queryParams, body);
            if (!guard.ok) {
                sendHttpResponse(clientSocket, guard.status, "application/json", guard.responseJson);
                continue;
            }
            // The first validation above protects parsing and routing.  A
            // second validation immediately before dispatch closes the
            // session-switch window between HTTP preflight and the debugger
            // API call.  Long-running handlers perform an additional check at
            // their final commit point (Memory/Write and RunBlocking below).
            const auto finalMutationGuard = [&]() -> bool {
                const MutationGuardDecision decision = validateMutationGuard(
                    requestData, path, queryParams, body);
                if (decision.ok) return true;
                sendHttpResponse(clientSocket, decision.status,
                    "application/json", decision.responseJson);
                return false;
            };
            SerializedRouteLease serializedRouteLease;
            if(!mcpdispatcher::routeMayRunConcurrently(path))
            {
                const SerializedRouteAcquireResult acquireResult =
                    acquireSerializedRouteLease(serializedRouteLease);
                if(acquireResult != SerializedRouteAcquireResult::Acquired)
                {
                    if(acquireResult == SerializedRouteAcquireResult::ServerStopping)
                    {
                        sendHttpResponse(clientSocket, 503, "application/json",
                            "{\"ok\":false,\"data\":null,\"error\":{\"code\":\"server_stopping\",\"message\":\"The bridge is stopping\",\"retryable\":true},\"meta\":{\"contractVersion\":1}}" );
                    }
                    else if(acquireResult == SerializedRouteAcquireResult::QueueFull)
                    {
                        sendHttpResponse(clientSocket, 503, "application/json",
                            "{\"ok\":false,\"data\":null,\"error\":{\"code\":\"serialized_route_queue_full\",\"message\":\"The serialized debugger route queue is full\",\"retryable\":true},\"meta\":{\"contractVersion\":1}}" );
                    }
                    else
                    {
                        sendHttpResponse(clientSocket, 504, "application/json",
                            "{\"ok\":false,\"data\":null,\"error\":{\"code\":\"serialized_route_timeout\",\"message\":\"Timed out waiting for serialized debugger execution\",\"retryable\":true},\"meta\":{\"contractVersion\":1}}" );
                    }
                    continue;
                }
            }
            try {
                if (!finalMutationGuard()) {
                    continue;
                }
                if(!invalidateNativeMutationForEmergency(path, clientSocket)) {
                    continue;
                }
                NativeMutationPermitScope nativeMutationPermit;
                if(!beginNativeMutationPermit(
                    requestData, path, queryParams, body, clientSocket,
                    nativeMutationPermit))
                {
                    continue;
                }
                if (path == "/ExecCommand") {
                    // queryParams values are already URL-decoded by
                    // mergeRequestParams -> parseQueryParams; decoding again here
                    // corrupted any command containing a literal '%'.
                    std::string cmd = queryParams["cmd"];
                    if (cmd.empty() && !body.empty()) {
                        cmd = body;
                    }

                    if (cmd.empty()) {
                        sendHttpResponse(clientSocket, 400, "text/plain", "Missing command parameter");
                        continue;
                    }
                    std::string commandName = cmd;
                    trimParam(commandName);
                    const size_t commandSeparator = commandName.find_first_of(" \t\r\n");
                    commandName = commandName.substr(0, commandSeparator);
                    std::transform(commandName.begin(), commandName.end(), commandName.begin(),
                        [](unsigned char ch) { return static_cast<char>(std::tolower(ch)); });
                    if(commandName == "httpserver" || commandName == "httpport")
                    {
                        sendHttpResponse(clientSocket, 409, "application/json",
                            "{\"ok\":false,\"error\":{\"code\":\"server_control_command_forbidden\",\"message\":\"HTTP server lifecycle commands cannot run from an HTTP request\",\"retryable\":false}}");
                        continue;
                    }
                    if(commandName == "plugunload"
                        || commandName == "pluginunload"
                        || commandName == "unloadplugin")
                    {
                        sendHttpResponse(clientSocket, 409, "application/json",
                            "{\"ok\":false,\"error\":{\"code\":\"bridge_self_unload_forbidden\",\"message\":\"The active bridge plugin cannot unload itself from an HTTP request\",\"retryable\":false}}");
                        continue;
                    }
                    int refRowCountBefore = GuiReferenceGetRowCount();
                    bool success = DbgCmdExecDirect(cmd.c_str());
                    int refRowCountAfter = GuiReferenceGetRowCount();
                    bool refChanged = (refRowCountAfter != refRowCountBefore);
                    if (!refChanged && refRowCountAfter > 0) {
                        std::string cmdLower = cmd;
                        std::transform(cmdLower.begin(), cmdLower.end(), cmdLower.begin(), ::tolower);
                        if (cmdLower.find("refstr") == 0 ||
                            cmdLower.find("reffind") == 0 ||
                            cmdLower.find("reffindrange") == 0 ||
                            cmdLower.find("findall") == 0 ||
                            cmdLower.find("findallmem") == 0 ||
                            cmdLower.find("findasm") == 0 ||
                            cmdLower.find("modcallfind") == 0 ||
                            cmdLower.find("guidfind") == 0 ||
                            cmdLower.find("strref") == 0) {
                            refChanged = true;
                        }
                    }
                    int refOffset = 0;
                    int refLimit = 100;
                    if (!queryParams["offset"].empty()) {
                        try { refOffset = std::stoi(queryParams["offset"]); } catch (...) {}
                        if (refOffset < 0) refOffset = 0;
                    }
                    if (!queryParams["limit"].empty()) {
                        try { refLimit = std::stoi(queryParams["limit"]); } catch (...) {}
                        if (refLimit < 1) refLimit = 1;
                        if (refLimit > 5000) refLimit = 5000;
                    }
                    if (!success) {
                        std::stringstream ss;
                        ss << "{\"success\":false,\"refView\":{\"rowCount\":0,\"rows\":[]}}";
                        sendHttpResponse(clientSocket, 200, "application/json", ss.str());
                    } else {
                        int totalRows = refChanged ? refRowCountAfter : 0;

                        std::stringstream ss;
                        ss << "{";
                        ss << "\"success\":true,";
                        ss << "\"refView\":{";
                        ss << "\"rowCount\":" << totalRows << ",";
                        ss << "\"rows\":[";

                        if (totalRows > 0) {
                            if (refOffset >= totalRows) refOffset = totalRows;
                            int endRow = refOffset + refLimit;
                            if (endRow > totalRows) endRow = totalRows;
                            int numCols = 0;
                            for (int c = 0; c < 10; c++) {
                                char* cell = GuiReferenceGetCellContent(0, c);
                                if (cell) {
                                    if (cell[0] != '\0') {
                                        numCols = c + 1;
                                    }
                                    BridgeFree(cell);
                                }
                            }
                            if (numCols < 2) numCols = 2;

                            bool firstRow = true;
                            for (int row = refOffset; row < endRow; row++) {
                                if (!firstRow) ss << ",";
                                firstRow = false;
                                ss << "[";
                                for (int col = 0; col < numCols; col++) {
                                    if (col > 0) ss << ",";
                                    char* cell = GuiReferenceGetCellContent(row, col);
                                    if (cell) {
                                        ss << "\"" << escapeJsonString(cell) << "\"";
                                        BridgeFree(cell);
                                    } else {
                                        ss << "\"\"";
                                    }
                                }
                                ss << "]";
                            }
                        }

                        ss << "]}}";
                        sendHttpResponse(clientSocket, 200, "application/json", ss.str());
                    }
                }
                else if (path == "/IsDebugActive") {
                    bool isRunning = DbgIsRunning();
                    _plugin_logprintf("DbgIsRunning() called, result: %s\n", isRunning ? "true" : "false");
                    std::stringstream ss;
                    ss << "{\"isRunning\":" << (isRunning ? "true" : "false") << "}";
                    sendHttpResponse(clientSocket, 200, "application/json", ss.str());
                }
                else if (path == "/Is_Debugging") {
                    bool isDebugging = DbgIsDebugging();
                    std::stringstream ss;
                    ss << "{\"isDebugging\":" << (isDebugging ? "true" : "false") << "}";
                    sendHttpResponse(clientSocket, 200, "application/json", ss.str());
                }
                else if (path == "/Debug/ChildBroker/State") {
                    if(method != "GET") {
                        sendHttpResponse(clientSocket, 405, "application/json",
                            "{\"ok\":false,\"error\":{\"code\":\"method_not_allowed\",\"message\":\"ChildBroker/State requires GET\",\"retryable\":false}}");
                        continue;
                    }
                    sendHttpResponse(clientSocket, 200, "application/json",
                        buildChildBrokerStateJson());
                }
                else if (path == "/Debug/SessionState") {
                    bool includeHistory = true;
                    size_t historyLimit = 16;
                    if (!queryParams["includeHistory"].empty()) {
                        std::string v = queryParams["includeHistory"];
                        std::transform(v.begin(), v.end(), v.begin(), [](unsigned char c) { return (char)std::tolower(c); });
                        includeHistory = (v != "false" && v != "0");
                    }
                    if (!queryParams["historyLimit"].empty()) {
                        try {
                            historyLimit = (size_t)std::stoul(queryParams["historyLimit"]);
                        } catch (...) {
                            historyLimit = 16;
                        }
                    }
                    sendHttpResponse(clientSocket, 200, "application/json", buildDebugSessionJson(includeHistory, historyLimit));
                }
                else if (path == "/Debug/Mutation/Acquire") {
                    if(method != "POST") {
                        sendHttpResponse(clientSocket, 405, "application/json",
                            "{\"ok\":false,\"error\":{\"code\":\"method_not_allowed\",\"message\":\"Mutation lease acquisition requires POST\",\"retryable\":false}}" );
                        continue;
                    }
                    const MutationLeaseHttpResult result =
                        acquireMutationLease(requestData, queryParams);
                    sendHttpResponse(clientSocket, result.status,
                        "application/json", result.body);
                }
                else if (path == "/Debug/Mutation/Renew") {
                    if(method != "POST") {
                        sendHttpResponse(clientSocket, 405, "application/json",
                            "{\"ok\":false,\"error\":{\"code\":\"method_not_allowed\",\"message\":\"Mutation lease renewal requires POST\",\"retryable\":false}}" );
                        continue;
                    }
                    const MutationLeaseHttpResult result =
                        renewMutationLease(requestData, queryParams);
                    sendHttpResponse(clientSocket, result.status,
                        "application/json", result.body);
                }
                else if (path == "/Debug/Mutation/Release") {
                    if(method != "POST") {
                        sendHttpResponse(clientSocket, 405, "application/json",
                            "{\"ok\":false,\"error\":{\"code\":\"method_not_allowed\",\"message\":\"Mutation lease release requires POST\",\"retryable\":false}}" );
                        continue;
                    }
                    const MutationLeaseHttpResult result =
                        releaseMutationLease(requestData);
                    sendHttpResponse(clientSocket, result.status,
                        "application/json", result.body);
                }
                else if (path == "/Debug/ExceptionPolicy/Get") {
                    if (method != "GET") {
                        sendHttpResponse(clientSocket, 405, "application/json",
                            "{\"ok\":false,\"error\":{\"code\":\"method_not_allowed\",\"message\":\"ExceptionPolicy/Get requires GET\",\"retryable\":false}}");
                        continue;
                    }
                    std::string response;
                    {
                        std::lock_guard<std::mutex> lock(g_debugSession.mutex);
                        response = buildExceptionPolicyResponseUnlocked(g_debugSession);
                    }
                    sendHttpResponse(clientSocket, 200, "application/json", response);
                }
                else if (path == "/Debug/ExceptionPolicy/Set") {
                    if (method != "POST") {
                        sendHttpResponse(clientSocket, 405, "application/json",
                            "{\"ok\":false,\"error\":{\"code\":\"method_not_allowed\",\"message\":\"ExceptionPolicy/Set requires POST\",\"retryable\":false}}");
                        continue;
                    }
                    ParsedExceptionPolicyUpdate update;
                    std::string parseError;
                    if (!parseExceptionPolicyUpdate(queryParams, update, parseError)) {
                        std::stringstream ss;
                        ss << "{\"ok\":false,\"error\":{\"code\":\"invalid_exception_policy\",";
                        ss << "\"message\":\"" << escapeJsonString(parseError.c_str())
                           << "\",\"retryable\":false}}";
                        sendHttpResponse(clientSocket, 400, "application/json", ss.str());
                        continue;
                    }

                    int status = 200;
                    std::string response;
                    {
                        std::lock_guard<std::mutex> lock(g_debugSession.mutex);
                        if (!sessionGuardMatchesUnlocked(requestData, g_debugSession)) {
                            const auto rejected = rejectGuard(409, "stale_session",
                                "The debug session changed while the exception policy was parsed",
                                g_debugSession);
                            status = rejected.status;
                            response = rejected.responseJson;
                        } else {
                            ExceptionPolicyState candidate;
                            std::string mergeError;
                            const bool mergeValid = mcpexception::mergePolicy(
                                g_debugSession.exceptionPolicy, std::move(update),
                                candidate, mergeError);
                            if (!mergeValid) {
                                status = 409;
                                std::stringstream ss;
                                ss << "{\"ok\":false,\"error\":{\"code\":\"exception_policy_merge_conflict\",";
                                ss << "\"message\":\"" << escapeJsonString(mergeError.c_str())
                                   << "\",\"retryable\":false},\"meta\":";
                                appendExceptionMetaUnlocked(ss, g_debugSession);
                                ss << "}";
                                response = ss.str();
                            } else {
                                g_debugSession.exceptionPolicy = std::move(candidate);
                                response = buildExceptionPolicyResponseUnlocked(g_debugSession);
                            }
                        }
                    }
                    sendHttpResponse(clientSocket, status, "application/json", response);
                }
                else if (path == "/Debug/ExceptionPolicy/Clear") {
                    if (method != "POST") {
                        sendHttpResponse(clientSocket, 405, "application/json",
                            "{\"ok\":false,\"error\":{\"code\":\"method_not_allowed\",\"message\":\"ExceptionPolicy/Clear requires POST\",\"retryable\":false}}");
                        continue;
                    }
                    bool clearHistory = false;
                    const auto clearHistoryParam = queryParams.find("clearHistory");
                    if (clearHistoryParam != queryParams.end()
                        && !parseStrictBool(clearHistoryParam->second, clearHistory)) {
                        sendHttpResponse(clientSocket, 400, "application/json",
                            "{\"ok\":false,\"error\":{\"code\":\"invalid_clear_history\",\"message\":\"clearHistory must be true/false or 1/0\",\"retryable\":false}}");
                        continue;
                    }
                    int status = 200;
                    std::string response;
                    {
                        std::lock_guard<std::mutex> lock(g_debugSession.mutex);
                        if (!sessionGuardMatchesUnlocked(requestData, g_debugSession)) {
                            const auto rejected = rejectGuard(409, "stale_session",
                                "The debug session changed before the exception policy clear",
                                g_debugSession);
                            status = rejected.status;
                            response = rejected.responseJson;
                        } else {
                            const uint64_t nextVersion = g_debugSession.exceptionPolicy.version + 1;
                            g_debugSession.exceptionPolicy = ExceptionPolicyState{};
                            g_debugSession.exceptionPolicy.version = nextVersion;
                            const size_t historyCleared = clearHistory
                                ? g_debugSession.exceptionHistory.size() : 0;
                            if (clearHistory) {
                                g_debugSession.exceptionHistoryDropped += historyCleared;
                                g_debugSession.exceptionHistory.clear();
                            }
                            std::stringstream ss;
                            ss << "{\"ok\":true,\"data\":{\"cleared\":true,";
                            ss << "\"historyCleared\":" << historyCleared << ",\"policy\":";
                            appendExceptionPolicyJsonUnlocked(ss, g_debugSession);
                            ss << "},\"meta\":";
                            appendExceptionMetaUnlocked(ss, g_debugSession);
                            ss << "}";
                            response = ss.str();
                        }
                    }
                    sendHttpResponse(clientSocket, status, "application/json", response);
                }
                else if (path == "/Debug/ExceptionHistory/Get") {
                    if (method != "GET") {
                        sendHttpResponse(clientSocket, 405, "application/json",
                            "{\"ok\":false,\"error\":{\"code\":\"method_not_allowed\",\"message\":\"ExceptionHistory/Get requires GET\",\"retryable\":false}}");
                        continue;
                    }
                    uint64_t afterSeq = 0;
                    uint64_t parsedLimit = 100;
                    if ((!queryParams["afterSeq"].empty()
                            && !mcpbridge::parseUnsignedDecimalExact(queryParams["afterSeq"], afterSeq))
                        || (!queryParams["limit"].empty()
                            && !mcpbridge::parseUnsignedDecimalExact(queryParams["limit"], parsedLimit))
                        || parsedLimit == 0 || parsedLimit > 256) {
                        sendHttpResponse(clientSocket, 400, "application/json",
                            "{\"ok\":false,\"error\":{\"code\":\"invalid_exception_history_cursor\",\"message\":\"afterSeq must be unsigned decimal and limit must be 1 through 256\",\"retryable\":false}}");
                        continue;
                    }
                    std::string response;
                    {
                        std::lock_guard<std::mutex> lock(g_debugSession.mutex);
                        response = buildExceptionHistoryResponseUnlocked(
                            g_debugSession, afterSeq, static_cast<size_t>(parsedLimit));
                    }
                    sendHttpResponse(clientSocket, 200, "application/json", response);
                }
                else if (path == "/Debug/ExceptionHistory/Clear") {
                    if (method != "POST") {
                        sendHttpResponse(clientSocket, 405, "application/json",
                            "{\"ok\":false,\"error\":{\"code\":\"method_not_allowed\",\"message\":\"ExceptionHistory/Clear requires POST\",\"retryable\":false}}");
                        continue;
                    }
                    int status = 200;
                    std::string response;
                    {
                        std::lock_guard<std::mutex> lock(g_debugSession.mutex);
                        if (!sessionGuardMatchesUnlocked(requestData, g_debugSession)) {
                            const auto rejected = rejectGuard(409, "stale_session",
                                "The debug session changed before the exception history clear",
                                g_debugSession);
                            status = rejected.status;
                            response = rejected.responseJson;
                        } else {
                            const size_t cleared = g_debugSession.exceptionHistory.size();
                            const uint64_t clearedThroughSeq = g_debugSession.exceptionHistoryNextSeq > 1
                                ? g_debugSession.exceptionHistoryNextSeq - 1 : 0;
                            g_debugSession.exceptionHistoryDropped += cleared;
                            g_debugSession.exceptionHistory.clear();
                            std::stringstream ss;
                            ss << "{\"ok\":true,\"data\":{\"cleared\":" << cleared
                               << ",\"clearedThroughSeq\":" << clearedThroughSeq
                               << "},\"meta\":";
                            appendExceptionMetaUnlocked(ss, g_debugSession);
                            ss << "}";
                            response = ss.str();
                        }
                    }
                    sendHttpResponse(clientSocket, status, "application/json", response);
                }
                else if (path == "/ApiTrace/Configure") {
                    if (method != "POST") {
                        sendHttpResponse(clientSocket, 405, "application/json",
                            "{\"ok\":false,\"error\":{\"code\":\"method_not_allowed\",\"message\":\"ApiTrace/Configure requires POST\",\"retryable\":false}}");
                        continue;
                    }
                    const std::string requestedTraceId = queryParams["traceId"];
                    if (requestedTraceId.empty()) {
                        sendHttpResponse(clientSocket, 400, "application/json",
                            "{\"ok\":false,\"error\":{\"code\":\"missing_trace_id\",\"message\":\"traceId is required\",\"retryable\":false}}");
                        continue;
                    }
                    const bool nativeReturnHooks = parseBoolParam(
                        queryParams["nativeReturnHooks"], true);
                    std::vector<duint> entryAddresses;
                    const std::string rawEntryAddresses =
                        urlDecode(queryParams["entryAddresses"]);
                    if(!rawEntryAddresses.empty())
                    {
                        for(const auto& item :
                            splitRequestItems(rawEntryAddresses, true))
                        {
                            duint address = 0;
                            if(!parseFlexibleDuint(item, address) || !address)
                            {
                                sendHttpResponse(clientSocket, 400,
                                    "application/json",
                                    "{\"ok\":false,\"error\":{\"code\":\"invalid_entry_address\",\"message\":\"entryAddresses must contain only valid non-zero addresses\",\"retryable\":false}}");
                                entryAddresses.clear();
                                break;
                            }
                            entryAddresses.push_back(address);
                        }
                        if(entryAddresses.empty()
                            && !rawEntryAddresses.empty())
                            continue;
                    }
                    size_t registeredEntryCount = 0;
                    {
                        std::lock_guard<std::mutex> lock(g_nativeApiTrace.mutex);
                        auto& config = g_nativeApiTrace.configs[requestedTraceId];
                        config.nativeReturnHooks = nativeReturnHooks;
                        for(const duint address : entryAddresses)
                            config.registeredEntryBreakpoints.insert(address);
                        registeredEntryCount =
                            config.registeredEntryBreakpoints.size();
                    }
                    std::stringstream ss;
                    ss << "{\"ok\":true,\"traceId\":\""
                       << escapeJsonString(requestedTraceId.c_str())
                       << "\",\"nativeReturnHooks\":"
                       << (nativeReturnHooks ? "true" : "false")
                       << ",\"registeredEntryBreakpoints\":"
                       << registeredEntryCount << "}";
                    sendHttpResponse(clientSocket, 200, "application/json", ss.str());
                }
                else if (path == "/ApiTrace/Entry") {
                    if (method != "POST") {
                        sendHttpResponse(clientSocket, 405, "application/json",
                            "{\"ok\":false,\"error\":{\"code\":\"method_not_allowed\",\"message\":\"ApiTrace/Entry requires POST\",\"retryable\":false}}");
                        continue;
                    }
                    const std::string requestedTraceId = queryParams["traceId"];
                    duint apiAddress = 0;
                    if (requestedTraceId.empty()
                        || !parseFlexibleDuint(
                            queryParams["apiAddress"], apiAddress)
                        || !apiAddress) {
                        sendHttpResponse(clientSocket, 400, "application/json",
                            "{\"ok\":false,\"error\":{\"code\":\"invalid_entry\",\"message\":\"traceId and a non-zero apiAddress are required\",\"retryable\":false}}");
                        continue;
                    }
                    uint64_t entrySeq = 0;
                    uint64_t callId = 0;
                    bool duplicate = false;
                    const bool recorded = recordNativeApiEntryRoute(
                        requestedTraceId,
                        apiAddress,
                        urlDecode(queryParams["module"]),
                        entrySeq,
                        callId,
                        duplicate);
                    std::stringstream ss;
                    ss << "{\"ok\":" << (recorded ? "true" : "false")
                       << ",\"traceId\":\""
                       << escapeJsonString(requestedTraceId.c_str())
                       << "\",\"entrySeq\":" << entrySeq
                       << ",\"callId\":" << callId
                       << ",\"duplicate\":" << (duplicate ? "true" : "false")
                       << "}";
                    sendHttpResponse(
                        clientSocket,
                        recorded ? 200 : 409,
                        "application/json",
                        ss.str());
                }
                else if (path == "/ApiTrace/ReturnHooks/Release") {
                    if (method != "POST") {
                        sendHttpResponse(clientSocket, 405, "application/json",
                            "{\"ok\":false,\"error\":{\"code\":\"method_not_allowed\",\"message\":\"ApiTrace/ReturnHooks/Release requires POST\",\"retryable\":false}}");
                        continue;
                    }
                    const std::string requestedTraceId = queryParams["traceId"];
                    if (requestedTraceId.empty()) {
                        sendHttpResponse(clientSocket, 400, "application/json",
                            "{\"ok\":false,\"error\":{\"code\":\"missing_trace_id\",\"message\":\"traceId is required\",\"retryable\":false}}");
                        continue;
                    }
                    std::vector<duint> owned;
                    {
                        std::lock_guard<std::mutex> lock(g_nativeApiTrace.mutex);
                        const auto config =
                            g_nativeApiTrace.configs.find(requestedTraceId);
                        if(config != g_nativeApiTrace.configs.end())
                            owned.assign(
                                config->second.ownedReturnBreakpoints.begin(),
                                config->second.ownedReturnBreakpoints.end());
                    }
                    std::vector<duint> stillActive;
                    for(const duint address : owned) {
                        if(nativeApiFindSoftwareBreakpoint(address))
                            stillActive.push_back(address);
                    }
                    if(!stillActive.empty()) {
                        std::stringstream ss;
                        ss << "{\"ok\":false,\"error\":{\"code\":\"return_hooks_still_active\",\"message\":\"native-owned return hooks are still installed\",\"retryable\":true},\"traceId\":\""
                           << escapeJsonString(requestedTraceId.c_str())
                           << "\",\"activeReturnBreakpoints\":[";
                        for(size_t index = 0; index < stillActive.size(); ++index) {
                            if(index != 0) ss << ",";
                            ss << "\"0x" << std::hex << stillActive[index] << "\"";
                        }
                        ss << "]}";
                        sendHttpResponse(clientSocket, 409, "application/json", ss.str());
                        continue;
                    }
                    size_t released = 0;
                    {
                        std::lock_guard<std::mutex> lock(g_nativeApiTrace.mutex);
                        released = g_nativeApiTrace.configs.erase(requestedTraceId);
                    }
                    std::stringstream ss;
                    ss << "{\"ok\":true,\"traceId\":\""
                       << escapeJsonString(requestedTraceId.c_str())
                       << "\",\"released\":" << std::dec << released << "}";
                    sendHttpResponse(clientSocket, 200, "application/json", ss.str());
                }
                else if (path == "/ApiTrace/Status") {
                    if (method != "GET") {
                        sendHttpResponse(clientSocket, 405, "application/json",
                            "{\"ok\":false,\"error\":{\"code\":\"method_not_allowed\",\"message\":\"ApiTrace/Status requires GET\",\"retryable\":false}}");
                        continue;
                    }
                    const std::string requestedTraceId = queryParams["traceId"];
                    if (requestedTraceId.empty()) {
                        sendHttpResponse(clientSocket, 400, "application/json",
                            "{\"ok\":false,\"error\":{\"code\":\"missing_trace_id\",\"message\":\"traceId is required\",\"retryable\":false}}");
                        continue;
                    }
                    uint64_t afterSeq = 0;
                    size_t limit = 100;
                    try {
                        if (!queryParams["afterSeq"].empty())
                            afterSeq = std::stoull(queryParams["afterSeq"]);
                        if (!queryParams["limit"].empty())
                            limit = std::min<size_t>(5000, (size_t)std::stoull(queryParams["limit"]));
                    } catch (...) {
                        sendHttpResponse(clientSocket, 400, "application/json",
                            "{\"ok\":false,\"error\":{\"code\":\"invalid_trace_cursor\",\"message\":\"afterSeq and limit must be decimal integers\",\"retryable\":false}}");
                        continue;
                    }
                    sendHttpResponse(clientSocket, 200, "application/json",
                        buildNativeApiTraceJson(requestedTraceId, afterSeq, limit));
                }
                else if (path == "/ApiTrace/Clear") {
                    if (method != "POST") {
                        sendHttpResponse(clientSocket, 405, "application/json",
                            "{\"ok\":false,\"error\":{\"code\":\"method_not_allowed\",\"message\":\"ApiTrace/Clear requires POST\",\"retryable\":false}}");
                        continue;
                    }
                    const std::string requestedTraceId = queryParams["traceId"];
                    if (requestedTraceId.empty()) {
                        sendHttpResponse(clientSocket, 400, "application/json",
                            "{\"ok\":false,\"error\":{\"code\":\"missing_trace_id\",\"message\":\"traceId is required\",\"retryable\":false}}");
                        continue;
                    }
                    size_t cleared = 0;
                    {
                        std::lock_guard<std::mutex> lock(g_nativeApiTrace.mutex);
                        const auto oldEnd = g_nativeApiTrace.events.size();
                        g_nativeApiTrace.events.erase(
                            std::remove_if(g_nativeApiTrace.events.begin(),
                                           g_nativeApiTrace.events.end(),
                                           [&](const NativeApiTraceEvent& event) {
                                               return event.traceId == requestedTraceId;
                                           }),
                            g_nativeApiTrace.events.end());
                        cleared = oldEnd - g_nativeApiTrace.events.size();
                        g_nativeApiTrace.pending.erase(requestedTraceId);
                        g_nativeApiTrace.finalizedPending.erase(requestedTraceId);
                        g_nativeApiTrace.exceptionUnwoundPending.erase(requestedTraceId);
                        const auto config =
                            g_nativeApiTrace.configs.find(requestedTraceId);
                        if(config != g_nativeApiTrace.configs.end()) {
                            config->second.nativeReturnHooks = false;
                            if(config->second.ownedReturnBreakpoints.empty())
                                g_nativeApiTrace.configs.erase(config);
                        }
                    }
                    std::stringstream ss;
                    ss << "{\"ok\":true,\"traceId\":\""
                       << escapeJsonString(requestedTraceId.c_str())
                       << "\",\"cleared\":" << cleared << "}";
                    sendHttpResponse(clientSocket, 200, "application/json", ss.str());
                }
                else if (path == "/ApiTrace/Finalize") {
                    if (method != "POST") {
                        sendHttpResponse(clientSocket, 405, "application/json",
                            "{\"ok\":false,\"error\":{\"code\":\"method_not_allowed\",\"message\":\"ApiTrace/Finalize requires POST\",\"retryable\":false}}");
                        continue;
                    }
                    const std::string requestedTraceId = queryParams["traceId"];
                    if (requestedTraceId.empty()) {
                        sendHttpResponse(clientSocket, 400, "application/json",
                            "{\"ok\":false,\"error\":{\"code\":\"missing_trace_id\",\"message\":\"traceId is required\",\"retryable\":false}}");
                        continue;
                    }
                    size_t finalized = 0;
                    uint64_t installed = 0;
                    uint64_t removed = 0;
                    uint64_t failures = 0;
                    std::vector<duint> ownedReturnHooks;
                    {
                        std::lock_guard<std::mutex> lock(g_nativeApiTrace.mutex);
                        const auto tracePending =
                            g_nativeApiTrace.pending.find(requestedTraceId);
                        if (tracePending != g_nativeApiTrace.pending.end()) {
                            for (const auto& threadPending : tracePending->second)
                                finalized += threadPending.second.size();
                            g_nativeApiTrace.pending.erase(tracePending);
                        }
                        g_nativeApiTrace.finalizedPending[requestedTraceId] += finalized;
                        const auto config =
                            g_nativeApiTrace.configs.find(requestedTraceId);
                        if(config != g_nativeApiTrace.configs.end()) {
                            config->second.nativeReturnHooks = false;
                            installed = config->second.returnHooksInstalled;
                            removed = config->second.returnHooksRemoved;
                            failures = config->second.returnHookFailures;
                            ownedReturnHooks.assign(
                                config->second.ownedReturnBreakpoints.begin(),
                                config->second.ownedReturnBreakpoints.end());
                        }
                    }
                    std::sort(ownedReturnHooks.begin(), ownedReturnHooks.end());
                    std::stringstream ss;
                    ss << "{\"ok\":true,\"traceId\":\""
                       << escapeJsonString(requestedTraceId.c_str())
                       << "\",\"finalizedPendingCalls\":" << std::dec
                       << finalized
                       << ",\"returnHooksInstalled\":" << installed
                       << ",\"returnHooksRemoved\":" << removed
                       << ",\"returnHookFailures\":" << failures
                       << ",\"ownedReturnBreakpoints\":[";
                    for(size_t index = 0; index < ownedReturnHooks.size(); ++index) {
                        if(index != 0) ss << ",";
                        ss << "\"0x" << std::hex << ownedReturnHooks[index] << "\"";
                    }
                    ss << "]}";
                    sendHttpResponse(clientSocket, 200, "application/json", ss.str());
                }
                else if (path == "/Trace/Start") {
                    std::string mode = toLowerCopy(queryParams["mode"]);
                    trimParam(mode);
                    if (mode.empty()) mode = "both";
                    if (mode != "instruction" && mode != "coverage" && mode != "both") {
                        sendHttpResponse(clientSocket, 400, "application/json",
                            "{\"ok\":false,\"error\":{\"code\":\"invalid_trace_mode\",\"message\":\"mode must be instruction, coverage, or both\",\"retryable\":false}}");
                        continue;
                    }
                    DebugSessionState sessionSnapshot;
                    {
                        std::lock_guard<std::mutex> lock(g_debugSession.mutex);
                        sessionSnapshot.sessionId = g_debugSession.sessionId;
                        sessionSnapshot.generation = g_debugSession.generation;
                        sessionSnapshot.processId = g_debugSession.processId;
                        sessionSnapshot.debugging = g_debugSession.debugging;
                        sessionSnapshot.paused = g_debugSession.paused;
                    }
                    if (!sessionSnapshot.debugging || !sessionSnapshot.paused
                        || sessionSnapshot.sessionId.empty() || sessionSnapshot.processId == 0) {
                        sendHttpResponse(clientSocket, 409, "application/json",
                            "{\"ok\":false,\"error\":{\"code\":\"trace_requires_paused_session\",\"message\":\"Native trace must be armed while the guarded debuggee is paused\",\"retryable\":true}}");
                        continue;
                    }
                    duint rangeStart = 0;
                    duint rangeSize = 0;
                    const bool hasStartText = !queryParams["rangeStart"].empty();
                    const bool hasSizeText = !queryParams["rangeSize"].empty();
                    if (hasStartText != hasSizeText
                        || (hasStartText && (!parseFlexibleDuint(queryParams["rangeStart"], rangeStart)
                            || !parseFlexibleDuint(queryParams["rangeSize"], rangeSize)
                            || rangeSize == 0
                            || rangeStart > std::numeric_limits<duint>::max() - (rangeSize - 1)))) {
                        sendHttpResponse(clientSocket, 400, "application/json",
                            "{\"ok\":false,\"error\":{\"code\":\"invalid_trace_range\",\"message\":\"rangeStart and a non-zero, non-overflowing rangeSize must be supplied together\",\"retryable\":false}}");
                        continue;
                    }
                    auto parseBoundedU64 = [&](const char* key, uint64_t defaultValue,
                                               uint64_t minimum, uint64_t maximum,
                                               uint64_t& output) -> bool {
                        output = defaultValue;
                        const std::string value = queryParams[key];
                        if (value.empty()) return true;
                        try {
                            size_t used = 0;
                            const uint64_t parsed = std::stoull(value, &used, 10);
                            if (used != value.size() || parsed < minimum || parsed > maximum) return false;
                            output = parsed;
                            return true;
                        } catch (...) {
                            return false;
                        }
                    };
                    uint64_t maxSteps = 100000;
                    uint64_t maxEvents64 = mode == "coverage" ? 1 : 100000;
                    uint64_t maxUnique64 = 100000;
                    if (!parseBoundedU64("maxSteps", 100000, 1, 10000000, maxSteps)
                        || !parseBoundedU64("maxEvents", maxEvents64, 1, 500000, maxEvents64)
                        || !parseBoundedU64("maxUnique", 100000, 1, 500000, maxUnique64)) {
                        sendHttpResponse(clientSocket, 400, "application/json",
                            "{\"ok\":false,\"error\":{\"code\":\"invalid_trace_limit\",\"message\":\"Trace limits are decimal integers within the advertised bounds\",\"retryable\":false}}");
                        continue;
                    }
                    std::string stopOnLimitText = toLowerCopy(queryParams["stopOnLimit"]);
                    trimParam(stopOnLimitText);
                    if (!stopOnLimitText.empty() && stopOnLimitText != "true"
                        && stopOnLimitText != "false" && stopOnLimitText != "1"
                        && stopOnLimitText != "0") {
                        sendHttpResponse(clientSocket, 400, "application/json",
                            "{\"ok\":false,\"error\":{\"code\":\"invalid_stop_on_limit\",\"message\":\"stopOnLimit must be true or false\",\"retryable\":false}}");
                        continue;
                    }
                    const bool stopOnLimit = parseBoolParam(stopOnLimitText, true);
                    std::string enrichEventsText = toLowerCopy(queryParams["enrichEvents"]);
                    trimParam(enrichEventsText);
                    if (!enrichEventsText.empty() && enrichEventsText != "true"
                        && enrichEventsText != "false" && enrichEventsText != "1"
                        && enrichEventsText != "0") {
                        sendHttpResponse(clientSocket, 400, "application/json",
                            "{\"ok\":false,\"error\":{\"code\":\"invalid_enrich_events\",\"message\":\"enrichEvents must be true or false\",\"retryable\":false}}");
                        continue;
                    }
                    const bool enrichEvents = parseBoolParam(enrichEventsText, false);
                    std::string autoResumeExceptionsText =
                        toLowerCopy(queryParams["autoResumeExceptions"]);
                    trimParam(autoResumeExceptionsText);
                    if (!autoResumeExceptionsText.empty()
                        && autoResumeExceptionsText != "true"
                        && autoResumeExceptionsText != "false"
                        && autoResumeExceptionsText != "1"
                        && autoResumeExceptionsText != "0") {
                        sendHttpResponse(clientSocket, 400, "application/json",
                            "{\"ok\":false,\"error\":{\"code\":\"invalid_auto_resume_exceptions\",\"message\":\"autoResumeExceptions must be true or false\",\"retryable\":false}}");
                        continue;
                    }
                    const bool autoResumeExceptions =
                        parseBoolParam(autoResumeExceptionsText, false);
                    {
                        std::lock_guard<std::mutex> lock(g_nativeTrace.mutex);
                        if (g_nativeTrace.active) {
                            sendHttpResponse(clientSocket, 409, "application/json",
                                "{\"ok\":false,\"error\":{\"code\":\"trace_already_active\",\"message\":\"Stop the active native trace before starting another\",\"retryable\":false}}");
                            continue;
                        }
                        g_nativeTrace.traceId = mcpbridge::createGuidString();
                        g_nativeTrace.sessionId = sessionSnapshot.sessionId;
                        g_nativeTrace.sessionGeneration = sessionSnapshot.generation;
                        g_nativeTrace.processId = sessionSnapshot.processId;
                        g_nativeTrace.mode = mode;
                        g_nativeTrace.active = true;
                        g_nativeTrace.completed = false;
                        g_nativeTrace.captureEvents = mode != "coverage";
                        g_nativeTrace.stopOnLimit = stopOnLimit;
                        g_nativeTrace.autoResumeExceptions =
                            autoResumeExceptions;
                        g_nativeTrace.exceptionResumeQueued = false;
                        g_nativeTrace.enrichEvents = enrichEvents;
                        g_nativeTrace.hasRange = hasStartText;
                        g_nativeTrace.rangeStart = rangeStart;
                        g_nativeTrace.rangeSize = rangeSize;
                        g_nativeTrace.maxSteps = maxSteps;
                        g_nativeTrace.maxEvents = (size_t)maxEvents64;
                        g_nativeTrace.maxUnique = (size_t)maxUnique64;
                        g_nativeTrace.totalSteps = 0;
                        g_nativeTrace.matchedSteps = 0;
                        g_nativeTrace.droppedEvents = 0;
                        g_nativeTrace.droppedUnique = 0;
                        g_nativeTrace.hitRevision = 0;
                        g_nativeTrace.droppedHitUpdates = 0;
                        g_nativeTrace.createdTickMs = nowTickMs();
                        g_nativeTrace.lastTickMs = g_nativeTrace.createdTickMs;
                        g_nativeTrace.stopReason.clear();
                        g_nativeTrace.events.clear();
                        g_nativeTrace.hits.clear();
                        g_nativeTrace.hitUpdates.clear();
                        g_nativeTrace.pendingExceptions.clear();
                    }
                    sendHttpResponse(clientSocket, 200, "application/json",
                        buildNativeTraceJson(0, 0, 0, 0));
                }
                else if (path == "/Trace/Status") {
                    size_t eventOffset = 0, eventLimit = 0, hitOffset = 0, hitLimit = 0;
                    uint64_t eventAfterSeq = 0;
                    uint64_t hitAfterRevision = 0;
                    try { if (!queryParams["eventOffset"].empty()) eventOffset = (size_t)std::stoull(queryParams["eventOffset"]); } catch (...) {}
                    try { if (!queryParams["eventLimit"].empty()) eventLimit = std::min<size_t>(5000, (size_t)std::stoull(queryParams["eventLimit"])); } catch (...) {}
                    try { if (!queryParams["hitOffset"].empty()) hitOffset = (size_t)std::stoull(queryParams["hitOffset"]); } catch (...) {}
                    try { if (!queryParams["hitLimit"].empty()) hitLimit = std::min<size_t>(5000, (size_t)std::stoull(queryParams["hitLimit"])); } catch (...) {}
                    try { if (!queryParams["eventAfterSeq"].empty()) eventAfterSeq = std::stoull(queryParams["eventAfterSeq"]); } catch (...) {}
                    try { if (!queryParams["hitAfterRevision"].empty()) hitAfterRevision = std::stoull(queryParams["hitAfterRevision"]); } catch (...) {}
                    const std::string requestedTraceId = queryParams["traceId"];
                    {
                        std::lock_guard<std::mutex> lock(g_nativeTrace.mutex);
                        if (g_nativeTrace.traceId.empty()
                            || (!requestedTraceId.empty() && requestedTraceId != g_nativeTrace.traceId)) {
                            sendHttpResponse(clientSocket, 404, "application/json",
                                "{\"ok\":false,\"error\":{\"code\":\"trace_not_found\",\"message\":\"Native trace was not found\",\"retryable\":false}}");
                            continue;
                        }
                    }
                    {
                        std::string traceError;
                        if (!nativeTraceMatchesCurrentSession(traceError)) {
                            sendHttpResponse(clientSocket, 409, "application/json",
                                "{\"ok\":false,\"error\":{\"code\":\"trace_session_mismatch\",\"message\":\"Native trace belongs to a different debug session\",\"retryable\":false}}");
                            continue;
                        }
                    }
                    sendHttpResponse(clientSocket, 200, "application/json",
                        buildNativeTraceJson(eventOffset, eventLimit, hitOffset, hitLimit, eventAfterSeq, hitAfterRevision));
                }
                else if (path == "/Trace/Wait") {
                    unsigned int timeoutMs = MAX_SERVER_WAIT_SLICE_MS;
                    if (!queryParams["timeoutMs"].empty()) {
                        try { timeoutMs = std::min(MAX_SERVER_WAIT_SLICE_MS, (unsigned int)std::stoul(queryParams["timeoutMs"])); } catch (...) {}
                    }
                    const std::string requestedTraceId = queryParams["traceId"];
                    std::string validatedTraceId;
                    {
                        std::unique_lock<std::mutex> lock(g_nativeTrace.mutex);
                        if (g_nativeTrace.traceId.empty()
                            || (!requestedTraceId.empty() && requestedTraceId != g_nativeTrace.traceId)) {
                            lock.unlock();
                            sendHttpResponse(clientSocket, 404, "application/json",
                                "{\"ok\":false,\"error\":{\"code\":\"trace_not_found\",\"message\":\"Native trace was not found\",\"retryable\":false}}");
                            continue;
                        }
                        validatedTraceId = g_nativeTrace.traceId;
                        lock.unlock();
                        std::string traceError;
                        if (!nativeTraceMatchesCurrentSession(traceError)) {
                            sendHttpResponse(clientSocket, 409, "application/json",
                                "{\"ok\":false,\"error\":{\"code\":\"trace_session_mismatch\",\"message\":\"Native trace belongs to a different debug session\",\"retryable\":false}}");
                            continue;
                        }
                        lock.lock();
                        if (g_nativeTrace.traceId != validatedTraceId) {
                            lock.unlock();
                            sendHttpResponse(clientSocket, 409, "application/json",
                                "{\"ok\":false,\"error\":{\"code\":\"trace_changed\",\"message\":\"Native trace changed while validating the debug session\",\"retryable\":true}}");
                            continue;
                        }
                        if (g_nativeTrace.active) {
                            g_nativeTrace.cv.wait_for(lock, std::chrono::milliseconds(timeoutMs), [&]() {
                                return g_nativeTrace.traceId != validatedTraceId
                                    || !g_nativeTrace.active
                                    || g_httpServer.stopRequested.load(std::memory_order_acquire);
                            });
                        }
                        if (g_nativeTrace.traceId != validatedTraceId) {
                            lock.unlock();
                            sendHttpResponse(clientSocket, 409, "application/json",
                                "{\"ok\":false,\"error\":{\"code\":\"trace_changed\",\"message\":\"Native trace changed while waiting\",\"retryable\":true}}");
                            continue;
                        }
                    }
                    sendHttpResponse(clientSocket, 200, "application/json",
                        buildNativeTraceJson(0, 0, 0, 0));
                }
                else if (path == "/Trace/Stop") {
                    const std::string requestedTraceId = queryParams["traceId"];
                    {
                        std::lock_guard<std::mutex> lock(g_nativeTrace.mutex);
                        if (g_nativeTrace.traceId.empty()
                            || (!requestedTraceId.empty() && requestedTraceId != g_nativeTrace.traceId)) {
                            sendHttpResponse(clientSocket, 404, "application/json",
                                "{\"ok\":false,\"error\":{\"code\":\"trace_not_found\",\"message\":\"Native trace was not found\",\"retryable\":false}}");
                            continue;
                        }
                    }
                    {
                        std::string traceError;
                        if (!nativeTraceMatchesCurrentSession(traceError)) {
                            sendHttpResponse(clientSocket, 409, "application/json",
                                "{\"ok\":false,\"error\":{\"code\":\"trace_session_mismatch\",\"message\":\"Native trace belongs to a different debug session\",\"retryable\":false}}");
                            continue;
                        }
                    }
                    finishNativeTrace("user_stop");
                    sendHttpResponse(clientSocket, 200, "application/json",
                        buildNativeTraceJson(0, 0, 0, 0));
                }
                else if (path == "/Trace/Clear") {
                    const std::string requestedTraceId = queryParams["traceId"];
                    {
                        std::lock_guard<std::mutex> lock(g_nativeTrace.mutex);
                        if (g_nativeTrace.traceId.empty()
                            || requestedTraceId.empty()
                            || requestedTraceId != g_nativeTrace.traceId) {
                            sendHttpResponse(clientSocket, 404, "application/json",
                                "{\"ok\":false,\"error\":{\"code\":\"trace_not_found\",\"message\":\"Native trace was not found\",\"retryable\":false}}");
                            continue;
                        }
                        if (g_nativeTrace.active) {
                            sendHttpResponse(clientSocket, 409, "application/json",
                                "{\"ok\":false,\"error\":{\"code\":\"trace_active\",\"message\":\"Stop the native trace before clearing it\",\"retryable\":false}}");
                            continue;
                        }
                        g_nativeTrace.traceId.clear();
                        g_nativeTrace.sessionId.clear();
                        g_nativeTrace.sessionGeneration = 0;
                        g_nativeTrace.processId = 0;
                        g_nativeTrace.active = false;
                        g_nativeTrace.completed = false;
                        g_nativeTrace.autoResumeExceptions = false;
                        g_nativeTrace.exceptionResumeQueued = false;
                        g_nativeTrace.totalSteps = 0;
                        g_nativeTrace.matchedSteps = 0;
                        g_nativeTrace.droppedEvents = 0;
                        g_nativeTrace.droppedUnique = 0;
                        g_nativeTrace.hitRevision = 0;
                        g_nativeTrace.droppedHitUpdates = 0;
                        g_nativeTrace.stopReason.clear();
                        g_nativeTrace.events.clear();
                        g_nativeTrace.hits.clear();
                        g_nativeTrace.hitUpdates.clear();
                        g_nativeTrace.pendingExceptions.clear();
                    }
                    sendHttpResponse(clientSocket, 200, "application/json", "{\"ok\":true,\"cleared\":true}");
                }
                else if (path == "/Debug/WaitForPause") {
                    unsigned int timeoutMs = 10000;
                    uint64_t sinceSeq = 0;
                    if (!queryParams["timeoutMs"].empty()) {
                        try { timeoutMs = std::min(MAX_SERVER_WAIT_SLICE_MS, (unsigned int)std::stoul(queryParams["timeoutMs"])); } catch (...) {}
                    }
                    timeoutMs = std::min(timeoutMs, MAX_SERVER_WAIT_SLICE_MS);
                    if (!queryParams["sinceSeq"].empty()) {
                        try { sinceSeq = std::stoull(queryParams["sinceSeq"]); } catch (...) {}
                    }
                    bool timedOut = false;
                    sendHttpResponse(clientSocket, 200, "application/json",
                        waitForSessionJson("pause", timeoutMs, sinceSeq, 0, false, "", timedOut));
                }
                else if (path == "/Debug/WaitForBreakpoint") {
                    unsigned int timeoutMs = 10000;
                    uint64_t sinceSeq = 0;
                    duint requestedAddr = 0;
                    bool hasRequestedAddr = false;
                    std::string requestedName;
                    if (!queryParams["timeoutMs"].empty()) {
                        try { timeoutMs = std::min(MAX_SERVER_WAIT_SLICE_MS, (unsigned int)std::stoul(queryParams["timeoutMs"])); } catch (...) {}
                    }
                    timeoutMs = std::min(timeoutMs, MAX_SERVER_WAIT_SLICE_MS);
                    if (!queryParams["sinceSeq"].empty()) {
                        try { sinceSeq = std::stoull(queryParams["sinceSeq"]); } catch (...) {}
                    }
                    if (!queryParams["addr"].empty()) {
                        std::string addrStr = urlDecode(queryParams["addr"]);
                        hasRequestedAddr = parseFlexibleDuint(addrStr, requestedAddr);
                    }
                    if (!queryParams["name"].empty()) {
                        requestedName = urlDecode(queryParams["name"]);
                    }
                    bool timedOut = false;
                    sendHttpResponse(clientSocket, 200, "application/json",
                        waitForSessionJson("breakpoint", timeoutMs, sinceSeq, requestedAddr, hasRequestedAddr, requestedName, timedOut));
                }
                else if (path == "/Debug/WaitForBreakpointDetailed") {
                    unsigned int timeoutMs = 10000;
                    uint64_t sinceSeq = 0;
                    duint requestedAddr = 0;
                    bool hasRequestedAddr = false;
                    std::string requestedName;
                    if (!queryParams["timeoutMs"].empty()) {
                        try { timeoutMs = std::min(MAX_SERVER_WAIT_SLICE_MS, (unsigned int)std::stoul(queryParams["timeoutMs"])); } catch (...) {}
                    }
                    timeoutMs = std::min(timeoutMs, MAX_SERVER_WAIT_SLICE_MS);
                    if (!queryParams["sinceSeq"].empty()) {
                        try { sinceSeq = std::stoull(queryParams["sinceSeq"]); } catch (...) {}
                    }
                    if (!queryParams["addr"].empty()) {
                        hasRequestedAddr = parseFlexibleDuint(queryParams["addr"], requestedAddr);
                    }
                    if (!queryParams["name"].empty()) {
                        requestedName = urlDecode(queryParams["name"]);
                    }
                    bool timedOut = false;
                    sendHttpResponse(clientSocket, 200, "application/json",
                        waitForSessionDetailedJson("breakpoint", timeoutMs, sinceSeq, requestedAddr, hasRequestedAddr, requestedName, timedOut));
                }
                else if (path == "/Debug/WaitForExit") {
                    unsigned int timeoutMs = 10000;
                    uint64_t sinceSeq = 0;
                    if (!queryParams["timeoutMs"].empty()) {
                        try { timeoutMs = std::min(MAX_SERVER_WAIT_SLICE_MS, (unsigned int)std::stoul(queryParams["timeoutMs"])); } catch (...) {}
                    }
                    timeoutMs = std::min(timeoutMs, MAX_SERVER_WAIT_SLICE_MS);
                    if (!queryParams["sinceSeq"].empty()) {
                        try { sinceSeq = std::stoull(queryParams["sinceSeq"]); } catch (...) {}
                    }
                    bool timedOut = false;
                    sendHttpResponse(clientSocket, 200, "application/json",
                        waitForSessionJson("exit", timeoutMs, sinceSeq, 0, false, "", timedOut));
                }
                else if (path == "/Eval/Batch") {
                    auto requestParams = mergeRequestParams(query, body);
                    std::string expressions = requestParams["expressions"];
                    if (expressions.empty() && !body.empty() && body.find('=') == std::string::npos) {
                        expressions = body;
                    }
                    sendHttpResponse(clientSocket, 200, "application/json", buildEvalBatchJson(expressions));
                }
                else if (path == "/Context/Capture") {
                    auto requestParams = mergeRequestParams(query, body);
                    std::string registers = requestParams["registers"];
                    std::string expressions = requestParams["expressions"];
                    std::string ranges = requestParams["ranges"];
                    std::string stackSlots = requestParams["stackSlots"];
                    sendHttpResponse(clientSocket, 200, "application/json",
                        buildContextCaptureJson(registers, expressions, ranges, stackSlots, "", false));
                }
                else if (path == "/Frame/Snapshot") {
                    auto requestParams = mergeRequestParams(query, body);
                    std::string registers = requestParams["registers"];
                    std::string expressions = requestParams["expressions"];
                    std::string ranges = requestParams["ranges"];
                    std::string stackSlots = requestParams["slots"];
                    std::string baseExpr = requestParams["baseExpr"];
                    sendHttpResponse(clientSocket, 200, "application/json",
                        buildContextCaptureJson(registers, expressions, ranges, stackSlots, baseExpr, true));
                }
                else if (path == "/Register/Get") {
                    std::string regName = queryParams["register"];
                    if (regName.empty()) {
                        sendHttpResponse(clientSocket, 400, "text/plain", "Missing register parameter");
                        continue;
                    }
                    Script::Register::RegisterEnum reg;
                    if (regName == "EAX" || regName == "eax") reg = Script::Register::EAX;
                    else if (regName == "EBX" || regName == "ebx") reg = Script::Register::EBX;
                    else if (regName == "ECX" || regName == "ecx") reg = Script::Register::ECX;
                    else if (regName == "EDX" || regName == "edx") reg = Script::Register::EDX;
                    else if (regName == "ESI" || regName == "esi") reg = Script::Register::ESI;
                    else if (regName == "EDI" || regName == "edi") reg = Script::Register::EDI;
                    else if (regName == "EBP" || regName == "ebp") reg = Script::Register::EBP;
                    else if (regName == "ESP" || regName == "esp") reg = Script::Register::ESP;
                    else if (regName == "EIP" || regName == "eip") reg = Script::Register::EIP;
#ifdef _WIN64
                    else if (regName == "RAX" || regName == "rax") reg = Script::Register::RAX;
                    else if (regName == "RBX" || regName == "rbx") reg = Script::Register::RBX;
                    else if (regName == "RCX" || regName == "rcx") reg = Script::Register::RCX;
                    else if (regName == "RDX" || regName == "rdx") reg = Script::Register::RDX;
                    else if (regName == "RSI" || regName == "rsi") reg = Script::Register::RSI;
                    else if (regName == "RDI" || regName == "rdi") reg = Script::Register::RDI;
                    else if (regName == "RBP" || regName == "rbp") reg = Script::Register::RBP;
                    else if (regName == "RSP" || regName == "rsp") reg = Script::Register::RSP;
                    else if (regName == "RIP" || regName == "rip") {
#ifdef _WIN64
                        reg = Script::Register::RIP;
#else
                        reg = Script::Register::EIP;
#endif
                    }
                    else if (regName == "R8" || regName == "r8") reg = Script::Register::R8;
                    else if (regName == "R9" || regName == "r9") reg = Script::Register::R9;
                    else if (regName == "R10" || regName == "r10") reg = Script::Register::R10;
                    else if (regName == "R11" || regName == "r11") reg = Script::Register::R11;
                    else if (regName == "R12" || regName == "r12") reg = Script::Register::R12;
                    else if (regName == "R13" || regName == "r13") reg = Script::Register::R13;
                    else if (regName == "R14" || regName == "r14") reg = Script::Register::R14;
                    else if (regName == "R15" || regName == "r15") reg = Script::Register::R15;
#endif
                    else if (regName == "EFLAGS" || regName == "eflags"
                        || regName == "CFLAGS" || regName == "cflags") {
                        reg = Script::Register::CFLAGS;
                    }
                    else {
                        sendHttpResponse(clientSocket, 400, "text/plain", "Unknown register");
                        continue;
                    }
                    
                    duint value = Script::Register::Get(reg);
                    std::stringstream ss;
                    ss << "0x" << std::hex << value;
                    sendHttpResponse(clientSocket, 200, "text/plain", ss.str());
                }
                else if (path == "/Register/Set") {
                    std::string regName = queryParams["register"];
                    std::string valueStr = queryParams["value"];
                    if (regName.empty() || valueStr.empty()) {
                        sendHttpResponse(clientSocket, 400, "text/plain", "Missing register or value parameter");
                        continue;
                    }
                    Script::Register::RegisterEnum reg;
                    if (regName == "EAX" || regName == "eax") reg = Script::Register::EAX;
                    else if (regName == "EBX" || regName == "ebx") reg = Script::Register::EBX;
                    else if (regName == "ECX" || regName == "ecx") reg = Script::Register::ECX;
                    else if (regName == "EDX" || regName == "edx") reg = Script::Register::EDX;
                    else if (regName == "ESI" || regName == "esi") reg = Script::Register::ESI;
                    else if (regName == "EDI" || regName == "edi") reg = Script::Register::EDI;
                    else if (regName == "EBP" || regName == "ebp") reg = Script::Register::EBP;
                    else if (regName == "ESP" || regName == "esp") reg = Script::Register::ESP;
                    else if (regName == "EIP" || regName == "eip") reg = Script::Register::EIP;
#ifdef _WIN64
                    else if (regName == "RAX" || regName == "rax") reg = Script::Register::RAX;
                    else if (regName == "RBX" || regName == "rbx") reg = Script::Register::RBX;
                    else if (regName == "RCX" || regName == "rcx") reg = Script::Register::RCX;
                    else if (regName == "RDX" || regName == "rdx") reg = Script::Register::RDX;
                    else if (regName == "RSI" || regName == "rsi") reg = Script::Register::RSI;
                    else if (regName == "RDI" || regName == "rdi") reg = Script::Register::RDI;
                    else if (regName == "RBP" || regName == "rbp") reg = Script::Register::RBP;
                    else if (regName == "RSP" || regName == "rsp") reg = Script::Register::RSP;
                    else if (regName == "RIP" || regName == "rip") {
#ifdef _WIN64
                        reg = Script::Register::RIP;
#else
                        reg = Script::Register::EIP;
#endif
                    }
                    else if (regName == "R8" || regName == "r8") reg = Script::Register::R8;
                    else if (regName == "R9" || regName == "r9") reg = Script::Register::R9;
                    else if (regName == "R10" || regName == "r10") reg = Script::Register::R10;
                    else if (regName == "R11" || regName == "r11") reg = Script::Register::R11;
                    else if (regName == "R12" || regName == "r12") reg = Script::Register::R12;
                    else if (regName == "R13" || regName == "r13") reg = Script::Register::R13;
                    else if (regName == "R14" || regName == "r14") reg = Script::Register::R14;
                    else if (regName == "R15" || regName == "r15") reg = Script::Register::R15;
#endif
                    else if (regName == "EFLAGS" || regName == "eflags"
                        || regName == "CFLAGS" || regName == "cflags") {
                        reg = Script::Register::CFLAGS;
                    }
                    else {
                        sendHttpResponse(clientSocket, 400, "text/plain", "Unknown register");
                        continue;
                    }
                    
                    duint value = 0;
                    if (!parseFlexibleDuint(valueStr, value)) {
                        sendHttpResponse(clientSocket, 400, "text/plain", "Invalid value format");
                        continue;
                    }

                    if (!finalMutationGuard()) {
                        continue;
                    }

                    const duint originalValue = Script::Register::Get(reg);
                    const bool writeSucceeded = Script::Register::Set(reg, value);
                    const duint observedValue = writeSucceeded
                        ? Script::Register::Get(reg) : originalValue;
                    const MutationGuardDecision postWriteGuard =
                        validateMutationGuard(requestData, path, queryParams, body);
                    const bool guardStillMatches = postWriteGuard.ok;
                    const bool verified = writeSucceeded
                        && observedValue == value
                        && guardStillMatches;
                    bool rollbackSucceeded = true;
                    if(!verified && writeSucceeded)
                    {
                        rollbackSucceeded = Script::Register::Set(reg, originalValue)
                            && Script::Register::Get(reg) == originalValue;
                    }
                    bool committed = false;
                    if(verified && nativeMutationPermit.active())
                    {
                        const mcpmutation::CommitResult commit =
                            nativeMutationPermit.permit.commit(
                                currentMutationSessionIdentity());
                        committed = commit.ok();
                    }
                    const bool success = verified && committed;
                    if(success)
                    {
                        sendHttpResponse(clientSocket, 200, "text/plain",
                            "Register set successfully");
                    }
                    else
                    {
                        std::stringstream ss;
                        ss << "{\"ok\":false,\"error\":{\"code\":\""
                           << (guardStillMatches
                               ? (rollbackSucceeded
                                   ? "register_write_verification_failed"
                                   : "register_rollback_failed")
                               : "stale_mutation_guard")
                           << "\",\"message\":\"Register write was not committed atomically\","
                           << "\"retryable\":false},\"original\":\"0x\"" << std::hex
                           << originalValue << "\",\"observed\":\"0x\"" << observedValue
                           << "\",\"rollbackSucceeded\":"
                           << (rollbackSucceeded ? "true" : "false") << "}";
                        sendHttpResponse(clientSocket, 500, "application/json", ss.str());
                    }
                }
                else if (path == "/Memory/Read") {
                    std::string addrStr = queryParams["addr"];
                    std::string sizeStr = queryParams["size"];
                    
                    if (addrStr.empty() || sizeStr.empty()) {
                        sendHttpResponse(clientSocket, 400, "text/plain", "Missing address or size");
                        continue;
                    }
                    
                    duint addr = 0;
                    duint size = 0;
                    if (!parseFlexibleDuint(addrStr, addr) || !parseCountValue(sizeStr, size)) {
                        sendHttpResponse(clientSocket, 400, "text/plain", "Invalid address or size format");
                        continue;
                    }
                    
                    if (size > 1024 * 1024) {
                        sendHttpResponse(clientSocket, 400, "text/plain", "Size too large");
                        continue;
                    }

                    std::vector<unsigned char> buffer;
                    duint sizeRead = 0;
                    std::string errorText;
                    if (!readMemoryStable(addr, size, buffer, sizeRead, errorText) && sizeRead == 0) {
                        sendHttpResponse(clientSocket, 500, "text/plain", errorText.empty() ? "Failed to read memory" : errorText);
                        continue;
                    }

                    sendHttpResponse(clientSocket, 200, "text/plain", bytesToHex(buffer.data(), (size_t)sizeRead));
                }
                else if (path == "/Memory/ReadRange") {
                    std::string addrStr = queryParams["addr"];
                    std::string sizeStr = queryParams["size"];
                    std::string format = queryParams["format"];
                    std::string maxCharsStr = queryParams["maxChars"];
                    if (addrStr.empty() || sizeStr.empty()) {
                        sendHttpResponse(clientSocket, 400, "application/json",
                            "{\"ok\":false,\"error\":\"Missing address or size\"}");
                        continue;
                    }

                    duint addr = 0;
                    duint size = 0;
                    if (!parseFlexibleDuint(addrStr, addr) || !parseCountValue(sizeStr, size)) {
                        sendHttpResponse(clientSocket, 400, "application/json",
                            "{\"ok\":false,\"error\":\"Invalid address or size format\"}");
                        continue;
                    }
                    if (size > 4 * 1024 * 1024) {
                        sendHttpResponse(clientSocket, 400, "application/json",
                            "{\"ok\":false,\"error\":\"Size too large\"}");
                        continue;
                    }

                    duint maxCharsValue = 1024;
                    if (!maxCharsStr.empty()) {
                        parseCountValue(maxCharsStr, maxCharsValue);
                    }
                    sendHttpResponse(clientSocket, 200, "application/json",
                        buildMemoryReadRangeJson(addr, size, format, (size_t)maxCharsValue));
                }
                else if (path == "/Dump/MiniDump") {
                    if (method != "POST") {
                        sendHttpResponse(clientSocket, 405, "application/json",
                            "{\"ok\":false,\"error\":{\"code\":\"method_not_allowed\","
                            "\"message\":\"MiniDump creation requires POST\",\"retryable\":false}}");
                        continue;
                    }
                    const std::string outputPathUtf8 = queryParams["outputPath"];
                    const std::string dumpTypeText = queryParams["dumpType"];
                    const bool overwrite = parseBoolParam(queryParams["overwrite"], false);
                    if (outputPathUtf8.empty() || dumpTypeText.empty()) {
                        sendHttpResponse(clientSocket, 400, "application/json",
                            "{\"ok\":false,\"error\":{\"code\":\"missing_minidump_input\","
                            "\"message\":\"outputPath and dumpType are required\",\"retryable\":false}}");
                        continue;
                    }
                    std::wstring outputPathW = utf8ToWide(outputPathUtf8);
                    duint dumpTypeValue = 0;
                    if (!isAbsoluteRegularFilePathW(outputPathW)
                        || !parseFlexibleDuint(dumpTypeText, dumpTypeValue)
                        || static_cast<unsigned long long>(dumpTypeValue) > 0xFFFFFFFFULL) {
                        sendHttpResponse(clientSocket, 400, "application/json",
                            "{\"ok\":false,\"error\":{\"code\":\"invalid_minidump_input\","
                            "\"message\":\"outputPath must be an absolute regular-file path and dumpType a 32-bit mask\","
                            "\"retryable\":false}}");
                        continue;
                    }

                    DWORD sessionPid = 0;
                    bool sessionDebugging = false;
                    bool sessionPaused = false;
                    {
                        std::lock_guard<std::mutex> lock(g_debugSession.mutex);
                        sessionPid = g_debugSession.processId;
                        sessionDebugging = g_debugSession.debugging;
                        sessionPaused = g_debugSession.paused;
                    }
                    if (!sessionDebugging || sessionPid == 0) {
                        sendHttpResponse(clientSocket, 409, "application/json",
                            "{\"ok\":false,\"error\":{\"code\":\"target_not_debugging\","
                            "\"message\":\"MiniDump creation requires an active debug target\",\"retryable\":true}}");
                        continue;
                    }
                    if (!sessionPaused) {
                        sendHttpResponse(clientSocket, 409, "application/json",
                            "{\"ok\":false,\"error\":{\"code\":\"target_not_paused\","
                            "\"message\":\"MiniDump creation requires a paused target for a coherent snapshot\","
                            "\"retryable\":true}}");
                        continue;
                    }

                    const bool existedBefore = fileExistsW(outputPathW);
                    HANDLE dumpFile = CreateFileW(
                        outputPathW.c_str(),
                        GENERIC_WRITE,
                        FILE_SHARE_READ,
                        nullptr,
                        overwrite ? CREATE_ALWAYS : CREATE_NEW,
                        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN,
                        nullptr);
                    if (dumpFile == INVALID_HANDLE_VALUE) {
                        const DWORD fileError = GetLastError();
                        std::stringstream ss;
                        ss << "{\"ok\":false,\"error\":{"
                           << "\"code\":\"minidump_file_open_failed\","
                           << "\"message\":\"" << escapeJsonString(formatWin32ErrorMessage(fileError).c_str()) << "\","
                           << "\"retryable\":false},"
                           << "\"win32Error\":" << fileError << ","
                           << "\"outputPath\":\"" << escapeJsonString(outputPathUtf8.c_str()) << "\"}";
                        sendHttpResponse(clientSocket,
                            fileError == ERROR_FILE_EXISTS || fileError == ERROR_ALREADY_EXISTS ? 409 : 500,
                            "application/json", ss.str());
                        continue;
                    }

                    HANDLE processHandle = DbgGetProcessHandle();
                    bool closeProcessHandle = false;
                    if (!processHandle || GetProcessId(processHandle) != sessionPid) {
                        processHandle = OpenProcess(
                            PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_DUP_HANDLE,
                            FALSE,
                            sessionPid);
                        closeProcessHandle = processHandle != nullptr;
                    }
                    BOOL dumpSucceeded = FALSE;
                    DWORD dumpError = ERROR_INVALID_HANDLE;
                    if (processHandle) {
                        SetLastError(ERROR_SUCCESS);
                        dumpSucceeded = MiniDumpWriteDump(
                            processHandle,
                            sessionPid,
                            dumpFile,
                            static_cast<MINIDUMP_TYPE>(static_cast<ULONG>(dumpTypeValue)),
                            nullptr,
                            nullptr,
                            nullptr);
                        dumpError = dumpSucceeded ? ERROR_SUCCESS : GetLastError();
                    }
                    FlushFileBuffers(dumpFile);
                    CloseHandle(dumpFile);
                    if (closeProcessHandle) CloseHandle(processHandle);

                    const bool dumpExists = fileExistsW(outputPathW);
                    const unsigned long long dumpSize = dumpExists ? fileSizeW(outputPathW) : 0ULL;
                    if (!dumpSucceeded || !dumpExists || dumpSize < sizeof(MINIDUMP_HEADER)) {
                        const bool partialRemoved = dumpExists
                            ? DeleteFileW(outputPathW.c_str()) == TRUE
                            : true;
                        std::stringstream ss;
                        ss << "{\"ok\":false,\"error\":{"
                           << "\"code\":\"minidump_write_failed\","
                           << "\"message\":\"" << escapeJsonString(formatWin32ErrorMessage(dumpError).c_str()) << "\","
                           << "\"retryable\":false},"
                           << "\"win32Error\":" << dumpError << ","
                           << "\"processId\":" << sessionPid << ","
                           << "\"dumpType\":\"0x" << std::hex << static_cast<unsigned long long>(dumpTypeValue) << "\","
                           << "\"partialRemoved\":" << (partialRemoved ? "true" : "false") << ","
                           << "\"outputPath\":\"" << escapeJsonString(outputPathUtf8.c_str()) << "\"}";
                        sendHttpResponse(clientSocket, 500, "application/json", ss.str());
                        continue;
                    }

                    std::stringstream ss;
                    ss << "{\"ok\":true,"
                       << "\"processId\":" << sessionPid << ","
                       << "\"paused\":true,"
                       << "\"dumpType\":\"0x" << std::hex << static_cast<unsigned long long>(dumpTypeValue) << "\","
                       << "\"outputPath\":\"" << escapeJsonString(outputPathUtf8.c_str()) << "\","
                       << "\"size\":" << std::dec << dumpSize << ","
                       << "\"overwroteExisting\":" << (existedBefore && overwrite ? "true" : "false") << ","
                       << "\"exceptionInfoIncluded\":false}";
                    sendHttpResponse(clientSocket, 200, "application/json", ss.str());
                }
                else if (path == "/Scylla/DumpFix") {
                    std::string pidStr = queryParams["pid"];
                    std::string imageBaseStr = queryParams["imageBase"];
                    std::string entrypointStr = queryParams["entrypoint"];
                    std::string dumpPathUtf8 = queryParams["dumpPath"];
                    std::string fixedPathUtf8 = queryParams["fixedPath"];
                    std::string sourcePathUtf8 = queryParams["sourcePath"];
                    std::string searchStartStr = queryParams["searchStart"];
                    std::string requestedIatStartStr = queryParams["iatStart"];
                    std::string requestedIatSizeStr = queryParams["iatSize"];
                    const bool dumpProcess = parseBoolParam(queryParams["dumpProcess"], true);
                    const bool overwrite = parseBoolParam(queryParams["overwrite"], false);
                    if (pidStr.empty() || dumpPathUtf8.empty()
                        || (dumpProcess && entrypointStr.empty())) {
                        sendHttpResponse(
                            clientSocket,
                            400,
                            "application/json",
                            "{\"ok\":false,\"error\":\"Missing pid/dumpPath or entrypoint for process dumping\"}");
                        continue;
                    }

                    duint pidValue = 0;
                    duint imageBase = 0;
                    duint entrypoint = 0;
                    duint searchStart = 0;
                    duint requestedIatStart = 0;
                    duint requestedIatSize = 0;
                    const bool hasRequestedIatStart = !requestedIatStartStr.empty();
                    const bool hasRequestedIatSize = !requestedIatSizeStr.empty();
                    if (!parseCountValue(pidStr, pidValue)
                        || (!entrypointStr.empty() && !parseFlexibleDuint(entrypointStr, entrypoint))
                        || (!imageBaseStr.empty() && !parseFlexibleDuint(imageBaseStr, imageBase))
                        || (!searchStartStr.empty() && !parseFlexibleDuint(searchStartStr, searchStart))
                        || (hasRequestedIatStart && !parseFlexibleDuint(requestedIatStartStr, requestedIatStart))
                        || (hasRequestedIatSize && !parseCountValue(requestedIatSizeStr, requestedIatSize))
                        || hasRequestedIatStart != hasRequestedIatSize
                        || (hasRequestedIatStart && (requestedIatStart == 0 || requestedIatSize == 0))
                        || requestedIatSize > static_cast<duint>(std::numeric_limits<DWORD>::max())) {
                        sendHttpResponse(
                            clientSocket,
                            400,
                            "application/json",
                            "{\"ok\":false,\"error\":\"Invalid pid/image/entry/search or explicit IAT range\"}");
                        continue;
                    }

                    DWORD guardedPid = 0;
                    bool guardedDebugging = false;
                    bool guardedPaused = false;
                    {
                        std::lock_guard<std::mutex> lock(g_debugSession.mutex);
                        guardedPid = g_debugSession.processId;
                        guardedDebugging = g_debugSession.debugging;
                        guardedPaused = g_debugSession.paused;
                    }
                    if (!guardedDebugging || guardedPid == 0
                        || static_cast<unsigned long long>(pidValue) != guardedPid) {
                        sendHttpResponse(clientSocket, 409, "application/json",
                            "{\"ok\":false,\"error\":{\"code\":\"target_pid_mismatch\","
                            "\"message\":\"Scylla PID must exactly match the guarded debug session\","
                            "\"retryable\":false}}");
                        continue;
                    }
                    if (!guardedPaused) {
                        sendHttpResponse(clientSocket, 409, "application/json",
                            "{\"ok\":false,\"error\":{\"code\":\"target_not_paused\","
                            "\"message\":\"Scylla dump/IAT operations require a paused target\","
                            "\"retryable\":true}}");
                        continue;
                    }

                    if (searchStart == 0) {
                        searchStart = entrypoint;
                    }

                    const bool fixImports = parseBoolParam(queryParams["fixImports"], !fixedPathUtf8.empty());
                    const bool advancedSearch = parseBoolParam(queryParams["advancedSearch"], true);
                    const bool rebuild = parseBoolParam(queryParams["rebuild"], fixImports);
                    const bool removeDosStub = parseBoolParam(queryParams["removeDosStub"], false);
                    const bool updateChecksum = parseBoolParam(queryParams["updatePeHeaderChecksum"], true);
                    const bool createBackup = parseBoolParam(queryParams["createBackup"], false);
                    const bool createNewIat = parseBoolParam(queryParams["createNewIat"], true);

                    std::wstring dumpPathW = utf8ToWide(dumpPathUtf8);
                    std::wstring fixedPathW = utf8ToWide(fixedPathUtf8);
                    std::wstring sourcePathW = utf8ToWide(sourcePathUtf8);
                    if (dumpPathW.empty() || !isAbsoluteRegularFilePathW(dumpPathW)
                        || (fixImports && !isAbsoluteRegularFilePathW(fixedPathW))) {
                        sendHttpResponse(
                            clientSocket,
                            400,
                            "application/json",
                            "{\"ok\":false,\"error\":\"dumpPath/fixedPath must be absolute regular-file paths\"}");
                        continue;
                    }
                    if (fixImports && fixedPathW.empty()) {
                        sendHttpResponse(
                            clientSocket,
                            400,
                            "application/json",
                            "{\"ok\":false,\"error\":\"fixedPath is required when fixImports=true\"}");
                        continue;
                    }
                    if (fixImports && dumpPathW == fixedPathW) {
                        sendHttpResponse(
                            clientSocket,
                            400,
                            "application/json",
                            "{\"ok\":false,\"error\":\"dumpPath and fixedPath must be different when fixImports=true\"}");
                        continue;
                    }

                    if (!dumpProcess && !fileExistsW(dumpPathW)) {
                        sendHttpResponse(clientSocket, 404, "application/json",
                            "{\"ok\":false,\"error\":\"Existing dumpPath was not found for IAT-only repair\"}");
                        continue;
                    }
                    if (dumpProcess && fileExistsW(dumpPathW) && !overwrite) {
                        sendHttpResponse(clientSocket, 409, "application/json",
                            "{\"ok\":false,\"error\":\"dumpPath already exists; overwrite was not authorized\"}");
                        continue;
                    }
                    if (fixImports && fileExistsW(fixedPathW) && !overwrite) {
                        sendHttpResponse(clientSocket, 409, "application/json",
                            "{\"ok\":false,\"error\":\"fixedPath already exists; overwrite was not authorized\"}");
                        continue;
                    }
                    if (dumpProcess && overwrite && fileExistsW(dumpPathW)
                        && !DeleteFileW(dumpPathW.c_str())) {
                        sendHttpResponse(clientSocket, 500, "application/json",
                            "{\"ok\":false,\"error\":\"Failed to replace existing dumpPath\"}");
                        continue;
                    }
                    if (fixImports && overwrite && fileExistsW(fixedPathW)
                        && !DeleteFileW(fixedPathW.c_str())) {
                        sendHttpResponse(clientSocket, 500, "application/json",
                            "{\"ok\":false,\"error\":\"Failed to replace existing fixedPath\"}");
                        continue;
                    }

                    LoadedScyllaApi scylla;
                    std::string loadError;
                    if (!loadScyllaApi(scylla, loadError)) {
                        std::stringstream ss;
                        ss << "{"
                           << "\"ok\":false,"
                           << "\"stage\":\"load\","
                           << "\"error\":\"" << escapeJsonString(loadError.c_str()) << "\""
                           << "}";
                        sendHttpResponse(clientSocket, 500, "application/json", ss.str());
                        continue;
                    }

                    BOOL dumpOk = TRUE;
                    if (dumpProcess) {
                        dumpOk = scylla.dumpProcessW(
                            static_cast<DWORD_PTR>(pidValue),
                            sourcePathW.empty() ? nullptr : sourcePathW.c_str(),
                            static_cast<DWORD_PTR>(imageBase),
                            static_cast<DWORD_PTR>(entrypoint),
                            dumpPathW.c_str());
                    }
                    const bool dumpExists = fileExistsW(dumpPathW);
                    const unsigned long long dumpSize = dumpExists ? fileSizeW(dumpPathW) : 0ULL;

                    int searchResult = 0;
                    DWORD_PTR iatStart = static_cast<DWORD_PTR>(requestedIatStart);
                    DWORD iatSize = static_cast<DWORD>(requestedIatSize);
                    int fixResult = 0;
                    BOOL rebuildOk = TRUE;
                    bool fixedExists = false;
                    unsigned long long fixedSize = 0ULL;
                    std::string stage = dumpProcess ? "dump" : "iat_input";
                    std::string iatSource = (iatStart != 0 && iatSize != 0) ? "explicit" : "search";
                    std::string errorText;
                    std::string hintText;
                    bool ok = dumpOk == TRUE && dumpExists;

                    if (!ok) {
                        errorText = dumpExists
                            ? "ScyllaDumpProcessW returned failure even though a dump file exists."
                            : "ScyllaDumpProcessW did not create a dump file.";
                    } else if (fixImports) {
                        if (iatSource == "search") {
                            stage = "iat_search";
                            if (scylla.modernAbi) {
                                searchResult = scylla.iatSearchModern(
                                    static_cast<DWORD>(pidValue),
                                    static_cast<DWORD_PTR>(imageBase),
                                    &iatStart,
                                    &iatSize,
                                    static_cast<DWORD_PTR>(searchStart),
                                    advancedSearch ? TRUE : FALSE);
                            } else {
                                searchResult = scylla.iatSearchV098(
                                    static_cast<DWORD>(pidValue),
                                    &iatStart,
                                    &iatSize,
                                    static_cast<DWORD_PTR>(searchStart),
                                    advancedSearch ? TRUE : FALSE);
                            }
                        }
                        if (searchResult != 0) {
                            ok = false;
                            errorText = scyllaErrorName(searchResult);
                            hintText = scyllaErrorHint(searchResult);
                        } else {
                            stage = "iat_fix";
                            if (scylla.modernAbi) {
                                fixResult = scylla.iatFixAutoWModern(
                                    static_cast<DWORD>(pidValue),
                                    static_cast<DWORD_PTR>(imageBase),
                                    static_cast<DWORD_PTR>(iatStart),
                                    static_cast<DWORD>(iatSize),
                                    createNewIat ? TRUE : FALSE,
                                    dumpPathW.c_str(),
                                    fixedPathW.c_str());
                            } else {
                                fixResult = scylla.iatFixAutoWV098(
                                    static_cast<DWORD_PTR>(iatStart),
                                    static_cast<DWORD>(iatSize),
                                    static_cast<DWORD>(pidValue),
                                    dumpPathW.c_str(),
                                    fixedPathW.c_str());
                            }
                            fixedExists = fileExistsW(fixedPathW);
                            fixedSize = fixedExists ? fileSizeW(fixedPathW) : 0ULL;
                            ok = (fixResult == 0) && fixedExists;
                            if (!ok) {
                                errorText = fixResult != 0
                                    ? scyllaErrorName(fixResult)
                                    : "ScyllaIatFixAutoW returned success but no fixed file was created.";
                                hintText = scyllaErrorHint(fixResult);
                            } else if (rebuild) {
                                stage = "rebuild";
                                rebuildOk = scylla.rebuildFileW(
                                    fixedPathW.c_str(),
                                    removeDosStub ? TRUE : FALSE,
                                    updateChecksum ? TRUE : FALSE,
                                    createBackup ? TRUE : FALSE);
                                ok = rebuildOk == TRUE && fileExistsW(fixedPathW);
                                fixedExists = fileExistsW(fixedPathW);
                                fixedSize = fixedExists ? fileSizeW(fixedPathW) : 0ULL;
                                if (!ok) {
                                    errorText = "ScyllaRebuildFileW failed.";
                                    hintText = "The dump was fixed, but PE header rebuild failed. Inspect the fixed file manually.";
                                }
                            }
                        }
                    }

                    std::stringstream ss;
                    ss << "{"
                       << "\"ok\":" << (ok ? "true" : "false") << ","
                       << "\"stage\":\"" << escapeJsonString(stage.c_str()) << "\","
                       << "\"scyllaDll\":\"" << escapeJsonString(wideToUtf8(scylla.dllPath).c_str()) << "\","
                       << "\"scyllaVersion\":\"" << escapeJsonString(wideToUtf8(scylla.version).c_str()) << "\","
                       << "\"modernAbi\":" << (scylla.modernAbi ? "true" : "false") << ","
                       << "\"pid\":" << static_cast<unsigned long long>(pidValue) << ","
                       << "\"imageBase\":\"0x" << std::hex << imageBase << "\","
                       << "\"entrypoint\":\"0x" << std::hex << entrypoint << "\","
                       << "\"searchStart\":\"0x" << std::hex << searchStart << "\","
                       << "\"advancedSearch\":" << (advancedSearch ? "true" : "false") << ","
                       << "\"dumpProcess\":" << (dumpProcess ? "true" : "false") << ","
                       << "\"overwrite\":" << (overwrite ? "true" : "false") << ","
                       << "\"fixImports\":" << (fixImports ? "true" : "false") << ","
                       << "\"dumpPath\":\"" << escapeJsonString(dumpPathUtf8.c_str()) << "\","
                       << "\"dumpExists\":" << (dumpExists ? "true" : "false") << ","
                       << "\"dumpSize\":" << std::dec << dumpSize << ","
                       << "\"dumpSucceeded\":" << (dumpOk == TRUE ? "true" : "false") << ","
                       << "\"iatStart\":\"0x" << std::hex << static_cast<unsigned long long>(iatStart) << "\","
                       << "\"iatSize\":\"0x" << std::hex << static_cast<unsigned long long>(iatSize) << "\","
                       << "\"iatSource\":\"" << iatSource << "\","
                       << "\"searchResult\":" << std::dec << searchResult << ","
                       << "\"searchResultName\":\"" << escapeJsonString(scyllaErrorName(searchResult).c_str()) << "\","
                       << "\"fixResult\":" << fixResult << ","
                       << "\"fixResultName\":\"" << escapeJsonString(scyllaErrorName(fixResult).c_str()) << "\","
                       << "\"rebuildRequested\":" << (rebuild ? "true" : "false") << ","
                       << "\"rebuildSucceeded\":" << (rebuildOk == TRUE ? "true" : "false");
                    if (fixImports) {
                        ss << ",\"fixedPath\":\"" << escapeJsonString(fixedPathUtf8.c_str()) << "\""
                           << ",\"fixedExists\":" << (fixedExists ? "true" : "false")
                           << ",\"fixedSize\":" << fixedSize;
                    }
                    if (!sourcePathUtf8.empty()) {
                        ss << ",\"sourcePath\":\"" << escapeJsonString(sourcePathUtf8.c_str()) << "\"";
                    }
                    if (!errorText.empty()) {
                        ss << ",\"error\":\"" << escapeJsonString(errorText.c_str()) << "\"";
                    }
                    if (!hintText.empty()) {
                        ss << ",\"hint\":\"" << escapeJsonString(hintText.c_str()) << "\"";
                    }
                    ss << "}";
                    unloadScyllaApi(scylla);
                    sendHttpResponse(clientSocket, ok ? 200 : 500, "application/json", ss.str());
                }
                else if (path == "/Memory/Write") {
                    std::string addrStr = queryParams["addr"];
                    std::string dataStr = queryParams["data"];
                    if (dataStr.empty() && !body.empty() && body.find('=') == std::string::npos) {
                        dataStr = body; // explicit raw-body compatibility
                    }

                    if (addrStr.empty() || dataStr.empty()) {
                        sendHttpResponse(clientSocket, 400, "application/json",
                            "{\"ok\":false,\"error\":{\"code\":\"missing_memory_write_input\",\"message\":\"addr and data are required\",\"retryable\":false}}");
                        continue;
                    }

                    duint addr = 0;
                    if (!parseFlexibleDuint(addrStr, addr)) {
                        sendHttpResponse(clientSocket, 400, "application/json",
                            "{\"ok\":false,\"error\":{\"code\":\"invalid_address\",\"message\":\"Invalid address format\",\"retryable\":false}}");
                        continue;
                    }

                    constexpr size_t kMaxMemoryWriteBytes = 8u * 1024u * 1024u;
                    auto parsed = mcpbridge::parseHexExact(dataStr, kMaxMemoryWriteBytes);
                    if (!parsed.ok) {
                        std::stringstream ss;
                        ss << "{\"ok\":false,\"error\":{"
                           << "\"code\":\"invalid_hex_payload\","
                           << "\"message\":\"" << escapeJsonString(parsed.error.c_str()) << "\","
                           << "\"offset\":" << parsed.errorOffset << ","
                           << "\"retryable\":false}}";
                        sendHttpResponse(clientSocket,
                            parsed.error.find("limit") != std::string::npos ? 413 : 400,
                            "application/json", ss.str());
                        continue;
                    }

                    // Release-gate-only fault injection: it is authenticated,
                    // explicitly acknowledged by a separate header, performs
                    // the real write, and then forces the normal verified
                    // rollback path.  This is intentionally not advertised as
                    // a public capability and cannot turn a failed write into
                    // success.
                    const std::string transactionFault = queryParams["transactionFault"];
                    const bool forceVerifyFailure = transactionFault == "verify_readback";
                    if (!transactionFault.empty() && !forceVerifyFailure) {
                        sendHttpResponse(clientSocket, 400, "application/json",
                            "{\"ok\":false,\"error\":{\"code\":\"invalid_transaction_fault\",\"message\":\"transactionFault must be verify_readback when supplied\",\"retryable\":false}}");
                        continue;
                    }
                    if (forceVerifyFailure
                        && httpHeaderValue(requestData, "x-mcp-test-intent") != "rollback-gate-v1") {
                        sendHttpResponse(clientSocket, 403, "application/json",
                            "{\"ok\":false,\"error\":{\"code\":\"transaction_fault_not_authorized\",\"message\":\"X-MCP-Test-Intent: rollback-gate-v1 is required\",\"retryable\":false}}");
                        continue;
                    }

                    const size_t byteCount = parsed.bytes.size();
                    const duint maxAddress = std::numeric_limits<duint>::max();
                    if (addr > maxAddress - static_cast<duint>(byteCount - 1u)) {
                        sendHttpResponse(clientSocket, 422, "application/json",
                            "{\"ok\":false,\"error\":{\"code\":\"address_overflow\",\"message\":\"The requested memory range wraps the address space\",\"retryable\":false}}");
                        continue;
                    }
                    bool targetPaused = false;
                    {
                        std::lock_guard<std::mutex> lock(g_debugSession.mutex);
                        targetPaused = g_debugSession.debugging && g_debugSession.paused;
                    }
                    if (!targetPaused) {
                        sendHttpResponse(clientSocket, 409, "application/json",
                            "{\"ok\":false,\"error\":{\"code\":\"target_not_paused\",\"message\":\"Memory writes require a paused debug target\",\"retryable\":true}}");
                        continue;
                    }

                    // Snapshotting the destination is a potentially
                    // blocking debugger read. Re-pin the session immediately
                    // before it and again immediately before the write.
                    if (!finalMutationGuard()) {
                        continue;
                    }

                    DWORD pinnedPid = 0;
                    {
                        std::lock_guard<std::mutex> lock(g_debugSession.mutex);
                        pinnedPid = g_debugSession.processId;
                    }
                    ScopedWinHandle pinnedProcess;
                    HANDLE debuggerProcess = DbgGetProcessHandle();
                    if(pinnedPid != 0)
                    {
                        pinnedProcess.value = OpenProcess(
                            PROCESS_QUERY_INFORMATION | PROCESS_VM_READ
                                | PROCESS_VM_WRITE | PROCESS_VM_OPERATION,
                            FALSE, pinnedPid);
                    }
                    if(!pinnedProcess.value && debuggerProcess
                        && GetProcessId(debuggerProcess) == pinnedPid)
                    {
                        HANDLE duplicate = nullptr;
                        if(DuplicateHandle(
                            GetCurrentProcess(), debuggerProcess,
                            GetCurrentProcess(), &duplicate, 0, FALSE,
                            DUPLICATE_SAME_ACCESS))
                            pinnedProcess.value = duplicate;
                    }
                    if(!pinnedProcess.value
                        || GetProcessId(pinnedProcess.value) != pinnedPid)
                    {
                        sendHttpResponse(clientSocket, 409, "application/json",
                            "{\"ok\":false,\"error\":{\"code\":\"transaction_target_handle_unavailable\",\"message\":\"The debug target process identity could not be pinned for this transaction\",\"retryable\":true}}");
                        continue;
                    }
                    auto pinnedRead = [&](duint address,
                                          unsigned char* destination,
                                          size_t length,
                                          duint& bytesRead) -> bool {
                        SIZE_T transferred = 0;
                        const BOOL ok = ReadProcessMemory(
                            pinnedProcess.value,
                            reinterpret_cast<LPCVOID>(address),
                            destination, length, &transferred);
                        bytesRead = static_cast<duint>(transferred);
                        return ok == TRUE && transferred == length;
                    };
                    auto pinnedWrite = [&](duint address,
                                           const unsigned char* source,
                                           size_t length,
                                           duint& bytesWritten) -> bool {
                        MEMORY_BASIC_INFORMATION memoryInfo = {};
                        DWORD originalProtect = 0;
                        bool protectionChanged = false;
                        if(VirtualQueryEx(
                            pinnedProcess.value,
                            reinterpret_cast<LPCVOID>(address),
                            &memoryInfo, sizeof(memoryInfo)) == 0
                            || memoryInfo.State != MEM_COMMIT)
                        {
                            bytesWritten = 0;
                            return false;
                        }
                        const DWORD currentProtect = memoryInfo.Protect
                            & 0xFFu;
                        if(currentProtect == PAGE_READONLY
                            || currentProtect == PAGE_EXECUTE_READ
                            || currentProtect == PAGE_EXECUTE)
                        {
                            protectionChanged = VirtualProtectEx(
                                pinnedProcess.value,
                                reinterpret_cast<LPVOID>(address),
                                length, PAGE_EXECUTE_READWRITE,
                                &originalProtect) == TRUE;
                            if(!protectionChanged)
                            {
                                bytesWritten = 0;
                                return false;
                            }
                        }
                        SIZE_T transferred = 0;
                        const BOOL ok = WriteProcessMemory(
                            pinnedProcess.value,
                            reinterpret_cast<LPVOID>(address),
                            source, length, &transferred);
                        bytesWritten = static_cast<duint>(transferred);
                        if(ok == TRUE && transferred == length)
                            FlushInstructionCache(
                                pinnedProcess.value,
                                reinterpret_cast<LPCVOID>(address), length);
                        if(protectionChanged)
                        {
                            DWORD ignoredProtect = 0;
                            VirtualProtectEx(
                                pinnedProcess.value,
                                reinterpret_cast<LPVOID>(address),
                                length, originalProtect, &ignoredProtect);
                        }
                        return ok == TRUE && transferred == length;
                    };

                    std::vector<unsigned char> original(byteCount);
                    duint sizeRead = 0;
                    const bool originalRead = pinnedRead(
                        addr, original.data(), byteCount, sizeRead);
                    if (!originalRead || sizeRead != static_cast<duint>(byteCount)) {
                        std::stringstream ss;
                        ss << "{\"ok\":false,\"error\":{"
                           << "\"code\":\"transaction_pre_read_failed\","
                           << "\"message\":\"Could not snapshot the complete destination range before writing\","
                           << "\"retryable\":true},\"requestedBytes\":" << byteCount
                           << ",\"readBytes\":" << sizeRead << "}";
                        sendHttpResponse(clientSocket, 500, "application/json", ss.str());
                        continue;
                    }

                    const std::string expectedStr = queryParams["expected"];
                    if (!expectedStr.empty()) {
                        auto expected = mcpbridge::parseHexExact(expectedStr, kMaxMemoryWriteBytes);
                        if (!expected.ok || expected.bytes.size() != byteCount) {
                            sendHttpResponse(clientSocket, 400, "application/json",
                                "{\"ok\":false,\"error\":{\"code\":\"invalid_expected_hex\",\"message\":\"expected must be valid hex with exactly the same byte length as data\",\"retryable\":false}}");
                            continue;
                        }
                        if (expected.bytes != original) {
                            sendHttpResponse(clientSocket, 409, "application/json",
                                "{\"ok\":false,\"error\":{\"code\":\"memory_compare_mismatch\",\"message\":\"Destination bytes do not match expected; nothing was written\",\"retryable\":false}}");
                            continue;
                        }
                    }

                    if (!finalMutationGuard()) {
                        continue;
                    }

                    duint sizeWritten = 0;
                    const bool writeCallSucceeded = pinnedWrite(
                        addr, parsed.bytes.data(), byteCount, sizeWritten);
                    std::vector<unsigned char> verified(byteCount);
                    duint verifyRead = 0;
                    const bool verifySucceeded = !forceVerifyFailure
                        && writeCallSucceeded
                        && sizeWritten == static_cast<duint>(byteCount)
                        && pinnedRead(addr, verified.data(), byteCount, verifyRead)
                        && verifyRead == static_cast<duint>(byteCount)
                        && verified == parsed.bytes;

                    const MutationGuardDecision postWriteGuard = validateMutationGuard(
                        requestData, path, queryParams, body);
                    const bool guardStillMatches = postWriteGuard.ok;

                    bool rollbackAttempted = false;
                    bool rollbackSucceeded = false;
                    if (!verifySucceeded || !guardStillMatches) {
                        rollbackAttempted = true;
                        duint rollbackWritten = 0;
                        std::vector<unsigned char> rollbackVerified(byteCount);
                        duint rollbackRead = 0;
                        rollbackSucceeded = pinnedWrite(
                            addr, original.data(), byteCount, rollbackWritten)
                            && rollbackWritten == static_cast<duint>(byteCount)
                            && pinnedRead(addr, rollbackVerified.data(), byteCount, rollbackRead)
                            && rollbackRead == static_cast<duint>(byteCount)
                            && rollbackVerified == original;
                    }

                    bool transactionSucceeded = verifySucceeded && guardStillMatches;
                    if(transactionSucceeded && nativeMutationPermit.active())
                    {
                        const mcpmutation::CommitResult commit =
                            nativeMutationPermit.permit.commit(
                                currentMutationSessionIdentity());
                        transactionSucceeded = commit.ok();
                    }
                    std::stringstream ss;
                    ss << "{\"ok\":" << (transactionSucceeded ? "true" : "false") << ","
                       << "\"address\":\"0x" << std::hex << addr << "\"," << std::dec
                       << "\"requestedBytes\":" << byteCount << ","
                       << "\"writtenBytes\":" << sizeWritten << ","
                       << "\"verified\":" << (transactionSucceeded ? "true" : "false") << ","
                       << "\"rollbackAttempted\":" << (rollbackAttempted ? "true" : "false") << ","
                       << "\"rollbackSucceeded\":" << (rollbackSucceeded ? "true" : "false") << ","
                       << "\"faultInjected\":" << (forceVerifyFailure ? "true" : "false");
                    if (!guardStillMatches) {
                        ss << ",\"error\":{\"code\":\"stale_mutation_guard\","
                           << "\"message\":\"The session changed during the memory transaction; original bytes were restored when possible\","
                           << "\"retryable\":false}";
                    } else if (!verifySucceeded) {
                        ss << ",\"error\":{\"code\":\"memory_write_verification_failed\","
                           << "\"message\":\"The complete write could not be verified"
                           << (rollbackSucceeded ? "; the original bytes were restored" : "; rollback could not be verified")
                           << "\",\"retryable\":false}";
                    }
                    ss << "}";
                    sendHttpResponse(clientSocket, transactionSucceeded ? 200 : 500, "application/json", ss.str());
                }
                else if (path == "/Memory/IsValidPtr") {
                    std::string addrStr = queryParams["addr"];
                    if (addrStr.empty()) {
                        sendHttpResponse(clientSocket, 400, "text/plain", "Missing address parameter");
                        continue;
                    }

                    duint addr = 0;
                    if (!parseFlexibleDuint(addrStr, addr)) {
                        sendHttpResponse(clientSocket, 400, "text/plain", "Invalid address format");
                        continue;
                    }

                    bool isValid = Script::Memory::IsValidPtr(addr);
                    sendHttpResponse(clientSocket, 200, "text/plain", isValid ? "true" : "false");
                }
                else if (path == "/Memory/GetProtect") {
                    std::string addrStr = queryParams["addr"];
                    if (addrStr.empty()) {
                        sendHttpResponse(clientSocket, 400, "text/plain", "Missing address parameter");
                        continue;
                    }

                    duint addr = 0;
                    if (!parseFlexibleDuint(addrStr, addr)) {
                        sendHttpResponse(clientSocket, 400, "text/plain", "Invalid address format");
                        continue;
                    }

                    unsigned int protect = Script::Memory::GetProtect(addr);
                    std::stringstream ss;
                    ss << "0x" << std::hex << protect;
                    sendHttpResponse(clientSocket, 200, "text/plain", ss.str());
                }

                else if (path == "/Debug/Launch") {
                    if(method != "POST") {
                        sendHttpResponse(clientSocket, 405, "application/json",
                            "{\"ok\":false,\"error\":{\"code\":\"method_not_allowed\",\"message\":\"Debug/Launch requires POST\",\"retryable\":false}}");
                        continue;
                    }
                    const LaunchHttpResult launchResult =
                        performManagedLaunch(queryParams);
                    sendHttpResponse(clientSocket, launchResult.status,
                        "application/json", launchResult.body);
                }
                else if (path == "/Debug/Launch/State") {
                    if(method != "GET") {
                        sendHttpResponse(clientSocket, 405, "application/json",
                            "{\"ok\":false,\"error\":{\"code\":\"method_not_allowed\",\"message\":\"Launch state requires GET\",\"retryable\":false}}");
                        continue;
                    }
                    std::shared_ptr<ManagedLaunch> launch;
                    const LaunchHttpResult required =
                        requireManagedLaunch(queryParams, launch);
                    if(!launch) {
                        sendHttpResponse(clientSocket, required.status,
                            "application/json", required.body);
                        continue;
                    }
                    ManagedLaunchOperationPin operation(launch, true);
                    if(!operation.acquired()) {
                        const LaunchHttpResult closing = launchHttpError(
                            409, "launch_resources_closing",
                            "The launch runtime is closing or has already been released",
                            true);
                        sendHttpResponse(clientSocket, closing.status,
                            "application/json", closing.body);
                        continue;
                    }
                    sendHttpResponse(clientSocket, 200, "application/json",
                        buildManagedLaunchJson(launch));
                }
                else if (path == "/Debug/Launch/Stream/Read") {
                    if(method != "GET") {
                        sendHttpResponse(clientSocket, 405, "application/json",
                            "{\"ok\":false,\"error\":{\"code\":\"method_not_allowed\",\"message\":\"Launch stream read requires GET\",\"retryable\":false}}");
                        continue;
                    }
                    const LaunchHttpResult readResult =
                        readManagedLaunchStream(queryParams);
                    sendHttpResponse(clientSocket, readResult.status,
                        "application/json", readResult.body);
                }
                else if (path == "/Debug/Launch/Stdin/Write") {
                    if(method != "POST") {
                        sendHttpResponse(clientSocket, 405, "application/json",
                            "{\"ok\":false,\"error\":{\"code\":\"method_not_allowed\",\"message\":\"Launch stdin write requires POST\",\"retryable\":false}}");
                        continue;
                    }
                    const LaunchHttpResult writeResult =
                        writeManagedLaunchStdin(queryParams);
                    sendHttpResponse(clientSocket, writeResult.status,
                        "application/json", writeResult.body);
                }
                else if (path == "/Debug/Launch/Stdin/Close") {
                    if(method != "POST") {
                        sendHttpResponse(clientSocket, 405, "application/json",
                            "{\"ok\":false,\"error\":{\"code\":\"method_not_allowed\",\"message\":\"Launch stdin close requires POST\",\"retryable\":false}}");
                        continue;
                    }
                    const LaunchHttpResult closeResult =
                        closeManagedLaunchStdin(queryParams);
                    sendHttpResponse(clientSocket, closeResult.status,
                        "application/json", closeResult.body);
                }
                else if (path == "/Debug/Launch/Resources/Close") {
                    if(method != "POST") {
                        sendHttpResponse(clientSocket, 405, "application/json",
                            "{\"ok\":false,\"error\":{\"code\":\"method_not_allowed\",\"message\":\"Launch resource close requires POST\",\"retryable\":false}}");
                        continue;
                    }
                    const LaunchHttpResult closeResult =
                        closeManagedLaunchResources(queryParams);
                    sendHttpResponse(clientSocket, closeResult.status,
                        "application/json", closeResult.body);
                }
                else if (path == "/Debug/Run") {
                    std::string mode;
                    const char* command = nullptr;
                    if (!selectRunCommand(queryParams["exceptionMode"], mode, command)) {
                        sendHttpResponse(clientSocket, 400, "application/json",
                            "{\"ok\":false,\"error\":{\"code\":\"invalid_exception_mode\",\"message\":\"exceptionMode must be normal, pass or swallow\",\"retryable\":false}}");
                        continue;
                    }
                    if (!finalMutationGuard()) {
                        continue;
                    }
                    const bool success = DbgCmdExec(command);
                    std::stringstream ss;
                    ss << "{\"ok\":" << (success ? "true" : "false")
                       << ",\"submitted\":" << (success ? "true" : "false")
                       << ",\"exceptionMode\":\"" << mode << "\""
                       << ",\"command\":\"" << command << "\"}";
                    sendHttpResponse(clientSocket, success ? 202 : 500, "application/json", ss.str());
                }
                else if (path == "/Debug/RunBlocking") {
                    std::string mode;
                    const char* command = nullptr;
                    if (!selectRunCommand(queryParams["exceptionMode"], mode, command)) {
                        sendHttpResponse(clientSocket, 400, "application/json",
                            "{\"ok\":false,\"error\":{\"code\":\"invalid_exception_mode\",\"message\":\"exceptionMode must be normal, pass or swallow\",\"retryable\":false}}");
                        continue;
                    }
                    unsigned int timeoutMs = 30000;
                    if (!queryParams["timeoutMs"].empty()) {
                        try { timeoutMs = std::min(MAX_SERVER_WAIT_SLICE_MS, (unsigned int)std::stoul(queryParams["timeoutMs"])); }
                        catch (...) {
                            sendHttpResponse(clientSocket, 400, "application/json",
                                "{\"ok\":false,\"error\":{\"code\":\"invalid_timeout\",\"message\":\"timeoutMs must be an unsigned integer\",\"retryable\":false}}");
                            continue;
                        }
                    }
                    timeoutMs = std::min(timeoutMs, MAX_SERVER_WAIT_SLICE_MS);
                    if (!finalMutationGuard()) {
                        continue;
                    }
                    uint64_t sinceSeq = 0;
                    {
                        std::lock_guard<std::mutex> lock(g_debugSession.mutex);
                        sinceSeq = g_debugSession.eventSeq;
                    }
                    if (!DbgCmdExec(command)) {
                        sendHttpResponse(clientSocket, 500, "application/json",
                            "{\"ok\":false,\"error\":{\"code\":\"run_submission_failed\",\"message\":\"x64dbg rejected the run command\",\"retryable\":true}}");
                        continue;
                    }
                    bool timedOut = false;
                    std::string waitJson = waitForSessionJson("pause", timeoutMs, sinceSeq, 0, false, "", timedOut);
                    std::stringstream ss;
                    ss << "{\"ok\":true"
                       << ",\"completed\":" << (timedOut ? "false" : "true")
                       << ",\"timedOut\":" << (timedOut ? "true" : "false")
                       << ",\"exceptionMode\":\"" << mode << "\""
                       << ",\"wait\":" << waitJson << "}";
                    sendHttpResponse(clientSocket, timedOut ? 202 : 200, "application/json", ss.str());
                }
                else if (path == "/Debug/Pause") {
                    // Use x64dbg's own joined command queue. No plugin-owned
                    // detached thread can survive plugstop/FreeLibrary.
                    if (!finalMutationGuard()) {
                        continue;
                    }
                    const bool success = DbgCmdExec("pause");
                    sendHttpResponse(clientSocket, success ? 202 : 500, "application/json",
                        success ? "{\"ok\":true,\"submitted\":true,\"command\":\"pause\"}"
                                : "{\"ok\":false,\"error\":{\"code\":\"pause_submission_failed\",\"message\":\"x64dbg rejected pause\",\"retryable\":true}}");
                }
                else if (path == "/Debug/Stop") {
                    if (!finalMutationGuard()) {
                        continue;
                    }
                    const bool success = DbgCmdExec("stop");
                    sendHttpResponse(clientSocket, success ? 202 : 500, "application/json",
                        success ? "{\"ok\":true,\"submitted\":true,\"command\":\"stop\"}"
                                : "{\"ok\":false,\"error\":{\"code\":\"stop_submission_failed\",\"message\":\"x64dbg rejected stop\",\"retryable\":true}}");
                }
                else if (path == "/Debug/ContinueException") {
                    std::string disposition = toLowerCopy(queryParams["disposition"]);
                    if (disposition != "handled" && disposition != "not_handled") {
                        sendHttpResponse(clientSocket, 400, "application/json",
                            "{\"ok\":false,\"error\":{\"code\":\"invalid_exception_disposition\",\"message\":\"disposition must be handled or not_handled\",\"retryable\":false}}");
                        continue;
                    }
                    const std::string expectedEventText = httpHeaderValue(requestData, "x-mcp-event-seq");
                    uint64_t expectedEventSeq = 0;
                    if (expectedEventText.empty()) {
                        sendHttpResponse(clientSocket, 428, "application/json",
                            "{\"ok\":false,\"error\":{\"code\":\"missing_event_guard\",\"message\":\"X-MCP-Event-Seq is required for exception disposition\",\"retryable\":false}}");
                        continue;
                    }
                    if (!mcpbridge::parseUnsignedDecimalExact(expectedEventText, expectedEventSeq)) {
                        sendHttpResponse(clientSocket, 400, "application/json",
                            "{\"ok\":false,\"error\":{\"code\":\"invalid_event_guard\",\"message\":\"X-MCP-Event-Seq must be a decimal integer\",\"retryable\":false}}");
                        continue;
                    }
                    DWORD exceptionCode = 0;
                    bool firstChance = false;
                    bool currentExceptionMatches = false;
                    bool alreadyClaimed = false;
                    uint64_t manualHistorySeq = 0;
                    uint64_t manualGeneration = 0;
                    std::string manualSessionId;
                    const char* continueCommand = disposition == "handled" ? "con" : "con 1";
                    {
                        std::lock_guard<std::mutex> lock(g_debugSession.mutex);
                        currentExceptionMatches = g_debugSession.debugging
                            && g_debugSession.paused
                            && g_debugSession.exceptionPending
                            && g_debugSession.stopReason == "exception"
                            && expectedEventSeq == g_debugSession.exceptionEventSeq;
                        if (currentExceptionMatches) {
                            exceptionCode = g_debugSession.exceptionCode;
                            firstChance = g_debugSession.exceptionFirstChance;
                            alreadyClaimed = g_debugSession.exceptionContinuationClaimed;
                            if (!alreadyClaimed) {
                                // Claim before crossing into x64dbg. A duplicate
                                // HTTP request or an automatic policy decision
                                // can never apply a second disposition.
                                g_debugSession.exceptionContinuationClaimed = true;
                                g_debugSession.exceptionDisposition = disposition;
                                ExceptionHistoryRecord* record = findExceptionHistoryByEventUnlocked(
                                    g_debugSession, expectedEventSeq);
                                if (!record) {
                                    ExceptionHistoryRecord created;
                                    created.seq = g_debugSession.exceptionHistoryNextSeq++;
                                    created.eventSeq = expectedEventSeq;
                                    created.sessionGeneration = g_debugSession.generation;
                                    created.policyVersion = g_debugSession.exceptionPolicy.version;
                                    created.tickMs = nowTickMs();
                                    created.lastUpdateMs = created.tickMs;
                                    created.timestamp100ns = nowTimestamp100ns();
                                    created.lastUpdateTimestamp100ns = created.timestamp100ns;
                                    created.bridgeInstanceId = g_bridgeInstanceId;
                                    created.sessionId = g_debugSession.sessionId;
                                    created.processId = g_debugSession.processId;
                                    created.threadId = g_debugSession.threadId;
                                    created.exceptionCode = exceptionCode;
                                    created.firstChance = firstChance;
                                    created.address = g_debugSession.lastAddress;
                                    created.ip = g_debugSession.lastIp;
                                    g_debugSession.exceptionHistory.push_back(std::move(created));
                                    trimExceptionHistoryUnlocked(g_debugSession);
                                    record = findExceptionHistoryByEventUnlocked(
                                        g_debugSession, expectedEventSeq);
                                }
                                if (record) {
                                    mcpexception::claimManualContinuation(
                                        record->continuation, disposition, continueCommand);
                                    record->lastUpdateMs = nowTickMs();
                                    record->lastUpdateTimestamp100ns = nowTimestamp100ns();
                                    manualHistorySeq = record->seq;
                                }
                                manualGeneration = g_debugSession.generation;
                                manualSessionId = g_debugSession.sessionId;
                            }
                        }
                    }
                    if (!currentExceptionMatches) {
                        sendHttpResponse(clientSocket, 409, "application/json",
                            "{\"ok\":false,\"error\":{\"code\":\"stale_exception_event\",\"message\":\"The guarded exception is no longer the current paused event\",\"retryable\":false}}");
                        continue;
                    }
                    if (alreadyClaimed) {
                        sendHttpResponse(clientSocket, 409, "application/json",
                            "{\"ok\":false,\"error\":{\"code\":\"exception_already_claimed\",\"message\":\"A policy or prior request already claimed this exception event\",\"retryable\":false}}");
                        continue;
                    }
                    if (!DbgCmdExecDirect(continueCommand)) {
                        {
                            std::lock_guard<std::mutex> lock(g_debugSession.mutex);
                            if (g_debugSession.sessionId == manualSessionId
                                && g_debugSession.generation == manualGeneration
                                && g_debugSession.exceptionEventSeq == expectedEventSeq) {
                                g_debugSession.exceptionContinuationClaimed = false;
                                g_debugSession.exceptionDisposition = "default";
                            }
                            ExceptionHistoryRecord* record = findExceptionHistoryBySeqUnlocked(
                                g_debugSession, manualHistorySeq);
                            if (record) {
                                mcpexception::markManualDisposition(
                                    record->continuation, false);
                                record->lastUpdateMs = nowTickMs();
                                record->lastUpdateTimestamp100ns = nowTimestamp100ns();
                            }
                        }
                        sendHttpResponse(clientSocket, 500, "application/json",
                            "{\"ok\":false,\"error\":{\"code\":\"exception_disposition_failed\",\"message\":\"x64dbg rejected the exception disposition\",\"retryable\":true}}");
                        continue;
                    }
                    {
                        std::lock_guard<std::mutex> lock(g_debugSession.mutex);
                        ExceptionHistoryRecord* record = findExceptionHistoryBySeqUnlocked(
                            g_debugSession, manualHistorySeq);
                        if (record) {
                            mcpexception::markManualDisposition(
                                record->continuation, true);
                            record->lastUpdateMs = nowTickMs();
                            record->lastUpdateTimestamp100ns = nowTimestamp100ns();
                        }
                    }
                    const bool resume = parseBoolParam(queryParams["resume"], true);
                    const bool resumeSubmitted = resume && DbgCmdExec("run");
                    const bool resumeOk = !resume || resumeSubmitted;
                    {
                        std::lock_guard<std::mutex> lock(g_debugSession.mutex);
                        ExceptionHistoryRecord* record = findExceptionHistoryBySeqUnlocked(
                            g_debugSession, manualHistorySeq);
                        if (record) {
                            mcpexception::markManualResume(
                                record->continuation, resume, resumeSubmitted);
                            record->lastUpdateMs = nowTickMs();
                            record->lastUpdateTimestamp100ns = nowTimestamp100ns();
                        }
                    }
                    g_debugSession.cv.notify_all();
                    std::stringstream ss;
                    ss << "{\"ok\":" << (resumeOk ? "true" : "false")
                       << ",\"disposition\":\"" << disposition << "\""
                       << ",\"windowsStatus\":\""
                       << (disposition == "handled" ? "DBG_CONTINUE" : "DBG_EXCEPTION_NOT_HANDLED") << "\""
                       << ",\"exceptionCode\":\"0x" << std::hex << exceptionCode << "\""
                       << ",\"firstChance\":" << (firstChance ? "true" : "false")
                       << ",\"eventSeq\":" << std::dec << expectedEventSeq
                       << ",\"historySeq\":" << manualHistorySeq
                       << ",\"resumeRequested\":" << (resume ? "true" : "false")
                       << ",\"resumeSubmitted\":" << (resumeSubmitted ? "true" : "false") << "}";
                    sendHttpResponse(clientSocket, resumeOk ? 200 : 500, "application/json", ss.str());
                }
                else if (path == "/Debug/StepIn") {
                    if (!finalMutationGuard()) {
                        continue;
                    }
                    const bool success = DbgCmdExec("sti");
                    sendHttpResponse(clientSocket, success ? 202 : 500, "application/json",
                        success ? "{\"ok\":true,\"submitted\":true,\"command\":\"sti\"}"
                                : "{\"ok\":false,\"error\":{\"code\":\"step_submission_failed\",\"message\":\"x64dbg rejected step-in\",\"retryable\":true}}");
                }
                else if (path == "/Debug/StepOver") {
                    if (!finalMutationGuard()) {
                        continue;
                    }
                    const bool success = DbgCmdExec("sto");
                    sendHttpResponse(clientSocket, success ? 202 : 500, "application/json",
                        success ? "{\"ok\":true,\"submitted\":true,\"command\":\"sto\"}"
                                : "{\"ok\":false,\"error\":{\"code\":\"step_submission_failed\",\"message\":\"x64dbg rejected step-over\",\"retryable\":true}}");
                }
                else if (path == "/Debug/StepOut") {
                    if (!finalMutationGuard()) {
                        continue;
                    }
                    const bool success = DbgCmdExec("rtr");
                    sendHttpResponse(clientSocket, success ? 202 : 500, "application/json",
                        success ? "{\"ok\":true,\"submitted\":true,\"command\":\"rtr\"}"
                                : "{\"ok\":false,\"error\":{\"code\":\"step_submission_failed\",\"message\":\"x64dbg rejected step-out\",\"retryable\":true}}");
                }
                else if (path == "/Debug/SetBreakpoint") {
                    std::string addrStr = queryParams["addr"];
                    if (addrStr.empty()) {
                        sendHttpResponse(clientSocket, 400, "text/plain", "Missing address parameter");
                        continue;
                    }
                    
                    duint addr = 0;
                    if (!parseFlexibleDuint(addrStr, addr)) {
                        sendHttpResponse(clientSocket, 400, "text/plain", "Invalid address format");
                        continue;
                    }
                    
                    bool success = Script::Debug::SetBreakpoint(addr);
                    sendHttpResponse(clientSocket, success ? 200 : 500, "text/plain", 
                        success ? "Breakpoint set successfully" : "Failed to set breakpoint");
                }
                else if (path == "/Debug/DeleteBreakpoint") {
                    std::string addrStr = queryParams["addr"];
                    if (addrStr.empty()) {
                        sendHttpResponse(clientSocket, 400, "text/plain", "Missing address parameter");
                        continue;
                    }
                    
                    duint addr = 0;
                    if (!parseFlexibleDuint(addrStr, addr)) {
                        sendHttpResponse(clientSocket, 400, "text/plain", "Invalid address format");
                        continue;
                    }
                    
                    bool success = Script::Debug::DeleteBreakpoint(addr);
                    sendHttpResponse(clientSocket, success ? 200 : 500, "text/plain", 
                        success ? "Breakpoint deleted successfully" : "Failed to delete breakpoint");
                }
                
                else if (path == "/Assembler/Assemble") {
                    std::string addrStr = queryParams["addr"];
                    std::string instruction = queryParams["instruction"];
                    if (instruction.empty() && !body.empty()) {
                        instruction = body;
                    }
                    
                    if (addrStr.empty() || instruction.empty()) {
                        sendHttpResponse(clientSocket, 400, "text/plain", "Missing address or instruction parameter");
                        continue;
                    }
                    
                    duint addr = 0;
                    if (!parseFlexibleDuint(addrStr, addr)) {
                        sendHttpResponse(clientSocket, 400, "text/plain", "Invalid address format");
                        continue;
                    }
                    
                    unsigned char dest[16];
                    int size = 16;
                    bool success = Script::Assembler::Assemble(addr, dest, &size, instruction.c_str());
                    
                    if (success) {
                        std::stringstream ss;
                        ss << "{\"success\":true,\"size\":" << size << ",\"bytes\":\"";
                        for (int i = 0; i < size; i++) {
                            ss << std::setw(2) << std::setfill('0') << std::hex << (int)dest[i];
                        }
                        ss << "\"}";
                        sendHttpResponse(clientSocket, 200, "application/json", ss.str());
                    } else {
                        sendHttpResponse(clientSocket, 500, "text/plain", "Failed to assemble instruction");
                    }
                }
                else if (path == "/Assembler/AssembleMem") {
                    std::string addrStr = queryParams["addr"];
                    std::string instruction = queryParams["instruction"];
                    if (instruction.empty() && !body.empty()) {
                        instruction = body;
                    }
                    
                    if (addrStr.empty() || instruction.empty()) {
                        sendHttpResponse(clientSocket, 400, "text/plain", "Missing address or instruction parameter");
                        continue;
                    }
                    
                    duint addr = 0;
                    if (!parseFlexibleDuint(addrStr, addr)) {
                        sendHttpResponse(clientSocket, 400, "text/plain", "Invalid address format");
                        continue;
                    }
                    
                    bool success = Script::Assembler::AssembleMem(addr, instruction.c_str());
                    sendHttpResponse(clientSocket, success ? 200 : 500, "text/plain", 
                        success ? "Instruction assembled in memory successfully" : "Failed to assemble instruction in memory");
                }
                else if (path == "/Stack/Pop") {
                    duint value = Script::Stack::Pop();
                    std::stringstream ss;
                    ss << "0x" << std::hex << value;
                    sendHttpResponse(clientSocket, 200, "text/plain", ss.str());
                }
                else if (path == "/Stack/Push") {
                    std::string valueStr = queryParams["value"];
                    if (valueStr.empty()) {
                        sendHttpResponse(clientSocket, 400, "text/plain", "Missing value parameter");
                        continue;
                    }
                    
                    duint value = 0;
                    if (!parseFlexibleDuint(valueStr, value)) {
                        sendHttpResponse(clientSocket, 400, "text/plain", "Invalid value format");
                        continue;
                    }
                    
                    duint prevTop = Script::Stack::Push(value);
                    std::stringstream ss;
                    ss << "0x" << std::hex << prevTop;
                    sendHttpResponse(clientSocket, 200, "text/plain", ss.str());
                }
                else if (path == "/Stack/Peek") {
                    std::string offsetStr = queryParams["offset"];
                    int offset = 0;
                    if (!offsetStr.empty()) {
                        try {
                            offset = std::stoi(offsetStr);
                        } catch (const std::exception& e) {
                            sendHttpResponse(clientSocket, 400, "text/plain", "Invalid offset format");
                            continue;
                        }
                    }
                    
                    duint value = Script::Stack::Peek(offset);
                    std::stringstream ss;
                    ss << "0x" << std::hex << value;
                    sendHttpResponse(clientSocket, 200, "text/plain", ss.str());
                }
                else if (path == "/Disasm/GetInstructionRange") {
                    std::string addrStr = queryParams["addr"];
                    std::string countStr = queryParams["count"];
                    
                    if (addrStr.empty()) {
                        sendHttpResponse(clientSocket, 400, "text/plain", "Missing address parameter");
                        continue;
                    }
                    
                    duint addr = 0;
                    int count = 1;
                    
                    if (!parseFlexibleDuint(addrStr, addr)) {
                        sendHttpResponse(clientSocket, 400, "text/plain", "Invalid address or count format");
                        continue;
                    }
                    try {
                        if (!countStr.empty()) {
                            count = std::stoi(countStr);
                        }
                    } catch (const std::exception& e) {
                        sendHttpResponse(clientSocket, 400, "text/plain", "Invalid address or count format");
                        continue;
                    }
                    
                    if (count <= 0 || count > 100) {
                        sendHttpResponse(clientSocket, 400, "text/plain", "Count must be between 1 and 100");
                        continue;
                    }
                    
                    // Get multiple instructions
                    std::stringstream ss;
                    ss << "{";
                    ss << "\"ok\":true,";
                    ss << "\"requestedAddr\":\"0x" << std::hex << addr << "\",";
                    ss << "\"requestedCount\":" << std::dec << count << ",";
                    ss << "\"instructions\":[";
                    
                    duint currentAddr = addr;
                    int emitted = 0;
                    for (int i = 0; i < count; i++) {
                        DISASM_INSTR instr;
                        DbgDisasmAt(currentAddr, &instr);
                        
                        if (instr.instr_size > 0) {
                            if (emitted > 0) ss << ",";
                            
                            ss << "{";
                            ss << "\"address\":\"0x" << std::hex << currentAddr << "\",";
                            ss << "\"instruction\":\"" << escapeJsonString(instr.instruction) << "\",";
                            ss << "\"size\":" << std::dec << instr.instr_size;
                            ss << "}";
                            
                            currentAddr += instr.instr_size;
                            emitted++;
                        } else {
                            break;
                        }
                    }
                    
                    ss << "],";
                    ss << "\"count\":" << emitted;
                    ss << "}";
                    sendHttpResponse(clientSocket, 200, "application/json", ss.str());
                }
                else if (path == "/Disasm/StepInWithDisasm") {
                    // Step in first
                    Script::Debug::StepIn();
                    
                    // Then get current instruction
                    duint rip = Script::Register::Get(REG_IP);
                    
                    DISASM_INSTR instr;
                    DbgDisasmAt(rip, &instr);
                    
                    // Create JSON response
                    std::stringstream ss;
                    ss << "{";
                    ss << "\"step_result\":\"Step in executed\",";
                    ss << "\"rip\":\"0x" << std::hex << rip << "\",";
                    ss << "\"instruction\":\"" << escapeJsonString(instr.instruction) << "\",";
                    ss << "\"size\":" << std::dec << instr.instr_size;
                    ss << "}";
                    
                    sendHttpResponse(clientSocket, 200, "application/json", ss.str());
                }
                else if (path == "/Flag/Get") {
                    std::string flagName = queryParams["flag"];
                    if (flagName.empty()) {
                        sendHttpResponse(clientSocket, 400, "text/plain", "Missing flag parameter");
                        continue;
                    }
                    bool val = false;
                    if (flagName == "ZF" || flagName == "zf") val = Script::Flag::GetZF();
                    else if (flagName == "OF" || flagName == "of") val = Script::Flag::GetOF();
                    else if (flagName == "CF" || flagName == "cf") val = Script::Flag::GetCF();
                    else if (flagName == "PF" || flagName == "pf") val = Script::Flag::GetPF();
                    else if (flagName == "SF" || flagName == "sf") val = Script::Flag::GetSF();
                    else if (flagName == "TF" || flagName == "tf") val = Script::Flag::GetTF();
                    else if (flagName == "AF" || flagName == "af") val = Script::Flag::GetAF();
                    else if (flagName == "DF" || flagName == "df") val = Script::Flag::GetDF();
                    else if (flagName == "IF" || flagName == "if") val = Script::Flag::GetIF();
                    else {
                        sendHttpResponse(clientSocket, 400, "text/plain", "Unknown flag");
                        continue;
                    }
                    sendHttpResponse(clientSocket, 200, "text/plain", val ? "true" : "false");
                }
                else if (path == "/Flag/Set") {
                    std::string flagName = queryParams["flag"];
                    std::string valueStr = queryParams["value"];
                    if (flagName.empty() || valueStr.empty()) {
                        sendHttpResponse(clientSocket, 400, "text/plain", "Missing flag or value parameter");
                        continue;
                    }
                    std::string vLower = valueStr;
                    std::transform(vLower.begin(), vLower.end(), vLower.begin(), ::tolower);
                    bool value = (vLower == "true" || vLower == "1");
                    bool success = false;
                    if (flagName == "ZF" || flagName == "zf") success = Script::Flag::SetZF(value);
                    else if (flagName == "OF" || flagName == "of") success = Script::Flag::SetOF(value);
                    else if (flagName == "CF" || flagName == "cf") success = Script::Flag::SetCF(value);
                    else if (flagName == "PF" || flagName == "pf") success = Script::Flag::SetPF(value);
                    else if (flagName == "SF" || flagName == "sf") success = Script::Flag::SetSF(value);
                    else if (flagName == "TF" || flagName == "tf") success = Script::Flag::SetTF(value);
                    else if (flagName == "AF" || flagName == "af") success = Script::Flag::SetAF(value);
                    else if (flagName == "DF" || flagName == "df") success = Script::Flag::SetDF(value);
                    else if (flagName == "IF" || flagName == "if") success = Script::Flag::SetIF(value);
                    else {
                        sendHttpResponse(clientSocket, 400, "text/plain", "Unknown flag");
                        continue;
                    }
                    if (success)
                        GuiUpdateRegisterView();
                    sendHttpResponse(clientSocket, success ? 200 : 500, "text/plain",
                        success ? "Flag set successfully" : "Failed to set flag");
                }
                
                else if (path == "/Pattern/FindMem") {
                    std::string startStr = queryParams["start"];
                    std::string sizeStr = queryParams["size"];
                    std::string pattern = queryParams["pattern"];
                    std::string Pattern = urlDecode(pattern);
                    if (startStr.empty() || sizeStr.empty() || pattern.empty()) {
                        sendHttpResponse(clientSocket, 400, "text/plain", "Missing start, size, or pattern parameter");
                        continue;
                    }
                    
                    duint start = 0, size = 0;

                    Pattern.erase(std::remove_if(pattern.begin(), pattern.end(), 
                                  [](unsigned char c) { return std::isspace(c); }), 
                    Pattern.end());

                    if (!parseFlexibleDuint(startStr, start) || !parseCountValue(sizeStr, size)) {
                        sendHttpResponse(clientSocket, 400, "text/plain", "Invalid start or size format");
                        continue;
                    }
                    
                    duint result = Script::Pattern::FindMem(start, size, Pattern.c_str());
                    if (result != 0) {
                        std::stringstream ss;
                        ss << "0x" << std::hex << result;
                        sendHttpResponse(clientSocket, 200, "text/plain", ss.str());
                    } else {
                        sendHttpResponse(clientSocket, 404, "text/plain", "Pattern not found");
                    }
                }
                else if (path == "/Misc/ParseExpression") {
                    std::string expression = queryParams["expression"];
                    bool fromRawBody = false;
                    if (expression.empty() && !body.empty()) {
                        expression = body;
                        fromRawBody = true;
                    }
                    if (fromRawBody) {
                        expression = urlDecode(expression);
                    }
                    trimParam(expression);

                    if (expression.empty()) {
                        sendHttpResponse(clientSocket, 400, "text/plain", "Missing expression parameter");
                        continue;
                    }

                    const bool wantJson = (queryParams["format"] == "json");
                    duint value = 0;
                    bool success = parseFlexibleDuint(expression, value);

                    if (!success) {
                        _plugin_logprintf(
                            "[HTTP /Misc/ParseExpression] failed (see DBG log). expr: %s\n",
                            expression.c_str());
                        if (wantJson) {
                            sendHttpResponse(clientSocket, 500, "application/json",
                                "{\"ok\":false,\"error\":\"Failed to parse expression\"}");
                        } else {
                            sendHttpResponse(clientSocket, 500, "text/plain", "Failed to parse expression");
                        }
                        continue;
                    }

                    if (wantJson) {
                        std::stringstream ss;
                        ss << "{\"ok\":true,\"value\":\"0x" << std::hex << value << "\"}";
                        sendHttpResponse(clientSocket, 200, "application/json", ss.str());
                    } else {
                        std::stringstream ss;
                        ss << "0x" << std::hex << value;
                        sendHttpResponse(clientSocket, 200, "text/plain", ss.str());
                    }
                }
                else if (path == "/Misc/RemoteGetProcAddress") {
                    std::string module = queryParams["module"];
                    std::string api = queryParams["api"];
                    
                    if (module.empty() || api.empty()) {
                        sendHttpResponse(clientSocket, 400, "text/plain", "Missing module or api parameter");
                        continue;
                    }
                    
                    duint addr = Script::Misc::RemoteGetProcAddress(module.c_str(), api.c_str());
                    if (addr != 0) {
                        std::stringstream ss;
                        ss << "0x" << std::hex << addr;
                        sendHttpResponse(clientSocket, 200, "text/plain", ss.str());
                    } else {
                        sendHttpResponse(clientSocket, 404, "text/plain", "Function not found");
                    }
                }
                else if (path == "/MemoryBase") {
                    std::string addrStr = queryParams["addr"];
                    if (addrStr.empty() && !body.empty()) {
                        addrStr = body;
                    }
                    // Convert string address to duint
                    duint addr = 0;
                    if (!parseFlexibleDuint(addrStr, addr)) {
                        sendHttpResponse(clientSocket, 400, "text/plain", "Invalid address format");
                        continue;
                    }
                    // Get the base address and size
                    duint size = 0;
                    duint baseAddr = DbgMemFindBaseAddr(addr, &size);
                    if (baseAddr == 0) {
                        sendHttpResponse(clientSocket, 404, "text/plain", "No module found for this address");
                    }
                    else {
                        // Format the response as JSON
                        std::stringstream ss;
                        ss << "{\"base_address\":\"0x" << std::hex << baseAddr << "\",\"size\":\"0x" << std::hex << size << "\"}";
                        sendHttpResponse(clientSocket, 200, "application/json", ss.str());
                    }
                }
                else if (path == "/GetModuleList") {
                    // Create a list to store the module information
                    ListInfo moduleList;
                    
                    // Get the list of modules
                    bool success = Script::Module::GetList(&moduleList);
                    
                    if (!success) {
                        sendHttpResponse(clientSocket, 500, "text/plain", "Failed to get module list");
                    }
                    else {
                        // Create a JSON array to hold the module information
                        std::stringstream jsonResponse;
                        jsonResponse << "[";
                        
                        // Iterate through each module in the list
                        size_t count = moduleList.count;
                        Script::Module::ModuleInfo* modules = (Script::Module::ModuleInfo*)moduleList.data;
                        
                        for (size_t i = 0; i < count; i++) {
                            if (i > 0) jsonResponse << ",";
                            
                            // Add module info as JSON object
                            jsonResponse << "{";
                            jsonResponse << "\"name\":\"" << escapeJsonString(modules[i].name) << "\",";
                            jsonResponse << "\"base\":\"0x" << std::hex << modules[i].base << "\",";
                            jsonResponse << "\"size\":\"0x" << std::hex << modules[i].size << "\",";
                            jsonResponse << "\"entry\":\"0x" << std::hex << modules[i].entry << "\",";
                            jsonResponse << "\"sectionCount\":" << std::dec << modules[i].sectionCount << ",";
                            jsonResponse << "\"path\":\"" << escapeJsonString(modules[i].path) << "\"";
                            jsonResponse << "}";
                        }

                        // Script::Module::GetList can transiently succeed with
                        // an empty list immediately after CREATE_PROCESS. A
                        // typed launch is already attached at that point, so
                        // expose the authoritative main-module record instead
                        // of returning a misleading empty array.
                        if (count == 0 && DbgIsDebugging()) {
                            Script::Module::ModuleInfo mainModule = {};
                            if (Script::Module::GetMainModuleInfo(&mainModule)) {
                                jsonResponse << "{";
                                jsonResponse << "\"name\":\"" << escapeJsonString(mainModule.name) << "\",";
                                jsonResponse << "\"base\":\"0x" << std::hex << mainModule.base << "\",";
                                jsonResponse << "\"size\":\"0x" << std::hex << mainModule.size << "\",";
                                jsonResponse << "\"entry\":\"0x" << std::hex << mainModule.entry << "\",";
                                jsonResponse << "\"sectionCount\":" << std::dec << mainModule.sectionCount << ",";
                                jsonResponse << "\"path\":\"" << escapeJsonString(mainModule.path) << "\"";
                                jsonResponse << "}";
                            }
                        }
                        
                        jsonResponse << "]";
                        
                        // Free the list
                        BridgeFree(moduleList.data);
                        
                        // Send the response
                        sendHttpResponse(clientSocket, 200, "application/json", jsonResponse.str());
                    }
                }
                else if (path == "/SymbolEnum") {
                    // Module name is required to keep response sizes manageable
                    std::string moduleFilter = queryParams["module"];
                    if (moduleFilter.empty()) {
                        sendHttpResponse(clientSocket, 400, "application/json",
                            "{\"error\":\"Missing required 'module' parameter. Use GetModuleList to discover module names.\"}");
                        continue;
                    }
                    
                    // Parse pagination parameters
                    std::string offsetStr = queryParams["offset"];
                    std::string limitStr = queryParams["limit"];
                    
                    int offset = 0;
                    int limit = 5000;
                    
                    if (!offsetStr.empty()) {
                        try { offset = std::stoi(offsetStr); } catch (...) { offset = 0; }
                    }
                    if (!limitStr.empty()) {
                        try { limit = std::stoi(limitStr); } catch (...) { limit = 5000; }
                    }
                    
                    // Clamp values
                    if (offset < 0) offset = 0;
                    if (limit <= 0) limit = 5000;
                    if (limit > 50000) limit = 50000;
                    
                    std::string moduleFilterDecoded = urlDecode(moduleFilter);
                    auto normalizedModuleName = [](std::string value) {
                        std::replace(value.begin(), value.end(), '\\', '/');
                        const size_t slash = value.find_last_of('/');
                        if(slash != std::string::npos)
                            value = value.substr(slash + 1);
                        std::transform(
                            value.begin(), value.end(), value.begin(),
                            [](unsigned char character) {
                                return static_cast<char>(
                                    std::tolower(character));
                            });
                        for(const char* extension :
                            {".exe", ".dll", ".sys", ".ocx"})
                        {
                            const size_t length = std::strlen(extension);
                            if(value.size() > length
                                && value.compare(
                                    value.size() - length,
                                    length,
                                    extension) == 0)
                            {
                                value.resize(value.size() - length);
                                break;
                            }
                        }
                        return value;
                    };
                    const std::string normalizedModuleFilter =
                        normalizedModuleName(moduleFilterDecoded);
                    
                    // Get all symbols using Script::Symbol::GetList
                    ListInfo symbolList;
                    bool success = Script::Symbol::GetList(&symbolList);
                    
                    if (!success || symbolList.data == nullptr) {
                        sendHttpResponse(clientSocket, 500, "application/json",
                            "{\"error\":\"Failed to enumerate symbols\",\"symbols\":[],\"total\":0}");
                        continue;
                    }
                    
                    size_t totalCount = symbolList.count;
                    Script::Symbol::SymbolInfo* symbols = (Script::Symbol::SymbolInfo*)symbolList.data;
                    
                    // Build JSON response - filter to requested module only
                    std::stringstream jsonResponse;
                    
                    int matchIndex = 0;   // Index among matching symbols
                    int emitted = 0;      // Number of symbols emitted in this page
                    int filteredTotal = 0; // Total matching symbols for this module
                    
                    // First pass: count total matching symbols for this module
                    for (size_t i = 0; i < totalCount; i++) {
                        if (normalizedModuleName(symbols[i].mod)
                            == normalizedModuleFilter) {
                            filteredTotal++;
                        }
                    }
                    
                    // Write header
                    jsonResponse << "{\"total\":" << filteredTotal
                                 << ",\"module\":\"" << escapeJsonString(moduleFilterDecoded.c_str()) << "\""
                                 << ",\"offset\":" << offset
                                 << ",\"limit\":" << limit
                                 << ",\"symbols\":[";
                    
                    // Second pass: emit symbols with pagination
                    for (size_t i = 0; i < totalCount && emitted < limit; i++) {
                        // Filter to requested module
                        if (normalizedModuleName(symbols[i].mod)
                            != normalizedModuleFilter) {
                            continue;
                        }
                        
                        // Apply offset (skip first N matching symbols)
                        if (matchIndex < offset) {
                            matchIndex++;
                            continue;
                        }
                        matchIndex++;
                        
                        // Determine type string
                        const char* typeStr = "unknown";
                        switch (symbols[i].type) {
                            case Script::Symbol::Function: typeStr = "function"; break;
                            case Script::Symbol::Import:   typeStr = "import"; break;
                            case Script::Symbol::Export:   typeStr = "export"; break;
                        }
                        
                        if (emitted > 0) jsonResponse << ",";
                        
                        jsonResponse << "{"
                                     << "\"rva\":\"0x" << std::hex << symbols[i].rva << "\","
                                     << "\"name\":\"" << escapeJsonString(symbols[i].name) << "\","
                                     << "\"manual\":" << (symbols[i].manual ? "true" : "false") << ","
                                     << "\"type\":\"" << typeStr << "\""
                                     << "}";
                        
                        emitted++;
                    }
                    
                    jsonResponse << "]}";
                    
                    // Free the list
                    BridgeFree(symbolList.data);

                    sendHttpResponse(clientSocket, 200, "application/json", jsonResponse.str());
                }
                else if (path == "/GetThreadList") {
                    THREADLIST threadList;
                    memset(&threadList, 0, sizeof(threadList));
                    DbgGetThreadList(&threadList);
                    
                    if (threadList.count == 0 || threadList.list == nullptr) {
                        sendHttpResponse(clientSocket, 200, "application/json",
                            "{\"count\":0,\"currentThread\":-1,\"threads\":[]}");
                        continue;
                    }
                    
                    std::stringstream jsonResponse;
                    jsonResponse << "{\"count\":" << threadList.count
                                 << ",\"currentThread\":" << threadList.CurrentThread
                                 << ",\"threads\":[";
                    
                    for (int i = 0; i < threadList.count; i++) {
                        THREADALLINFO& t = threadList.list[i];
                        
                        if (i > 0) jsonResponse << ",";
                        
                        // Map priority enum to readable string
                        const char* priorityStr = "Unknown";
                        switch (t.Priority) {
                            case _PriorityIdle:          priorityStr = "Idle"; break;
                            case _PriorityAboveNormal:   priorityStr = "AboveNormal"; break;
                            case _PriorityBelowNormal:   priorityStr = "BelowNormal"; break;
                            case _PriorityHighest:       priorityStr = "Highest"; break;
                            case _PriorityLowest:        priorityStr = "Lowest"; break;
                            case _PriorityNormal:        priorityStr = "Normal"; break;
                            case _PriorityTimeCritical:  priorityStr = "TimeCritical"; break;
                            default: break;
                        }
                        
                        // Map wait reason enum to readable string
                        const char* waitStr = "Unknown";
                        switch (t.WaitReason) {
                            case _Executive:        waitStr = "Executive"; break;
                            case _FreePage:         waitStr = "FreePage"; break;
                            case _PageIn:           waitStr = "PageIn"; break;
                            case _PoolAllocation:   waitStr = "PoolAllocation"; break;
                            case _DelayExecution:   waitStr = "DelayExecution"; break;
                            case _Suspended:        waitStr = "Suspended"; break;
                            case _UserRequest:      waitStr = "UserRequest"; break;
                            case _WrExecutive:      waitStr = "WrExecutive"; break;
                            case _WrFreePage:       waitStr = "WrFreePage"; break;
                            case _WrPageIn:         waitStr = "WrPageIn"; break;
                            case _WrPoolAllocation: waitStr = "WrPoolAllocation"; break;
                            case _WrDelayExecution: waitStr = "WrDelayExecution"; break;
                            case _WrSuspended:      waitStr = "WrSuspended"; break;
                            case _WrUserRequest:    waitStr = "WrUserRequest"; break;
                            case _WrQueue:          waitStr = "WrQueue"; break;
                            case _WrLpcReceive:     waitStr = "WrLpcReceive"; break;
                            case _WrLpcReply:       waitStr = "WrLpcReply"; break;
                            case _WrVirtualMemory:  waitStr = "WrVirtualMemory"; break;
                            case _WrPageOut:        waitStr = "WrPageOut"; break;
                            case _WrRendezvous:     waitStr = "WrRendezvous"; break;
                            default: break;
                        }
                        
                        jsonResponse << "{"
                            << "\"threadNumber\":" << t.BasicInfo.ThreadNumber << ","
                            << "\"threadId\":" << std::dec << t.BasicInfo.ThreadId << ","
                            << "\"threadName\":\"" << escapeJsonString(t.BasicInfo.threadName) << "\","
                            << "\"startAddress\":\"0x" << std::hex << t.BasicInfo.ThreadStartAddress << "\","
                            << "\"localBase\":\"0x" << std::hex << t.BasicInfo.ThreadLocalBase << "\","
                            << "\"cip\":\"0x" << std::hex << t.ThreadCip << "\","
                            << "\"suspendCount\":" << std::dec << t.SuspendCount << ","
                            << "\"priority\":\"" << priorityStr << "\","
                            << "\"waitReason\":\"" << waitStr << "\","
                            << "\"lastError\":" << std::dec << t.LastError << ","
                            << "\"cycles\":" << std::dec << t.Cycles
                            << "}";
                    }
                    
                    jsonResponse << "]}";
                    
                    // Free the thread list
                    BridgeFree(threadList.list);
                    
                    sendHttpResponse(clientSocket, 200, "application/json", jsonResponse.str());
                }
                else if (path == "/GetTebAddress") {
                    std::string tidStr = queryParams["tid"];
                    if (tidStr.empty()) {
                        sendHttpResponse(clientSocket, 400, "text/plain", "Missing 'tid' parameter (thread ID)");
                        continue;
                    }
                    
                    DWORD tid = 0;
                    try {
                        tid = (DWORD)std::stoul(tidStr, nullptr, 0);
                    } catch (const std::exception& e) {
                        sendHttpResponse(clientSocket, 400, "text/plain", "Invalid tid format");
                        continue;
                    }
                    
                    duint tebAddr = DbgGetTebAddress(tid);
                    if (tebAddr == 0) {
                        sendHttpResponse(clientSocket, 404, "application/json",
                            "{\"error\":\"TEB not found for given thread ID\"}");
                        continue;
                    }
                    
                    std::stringstream ss;
                    ss << "{\"tid\":" << std::dec << tid
                       << ",\"tebAddress\":\"0x" << std::hex << tebAddr << "\"}";
                    sendHttpResponse(clientSocket, 200, "application/json", ss.str());
                }
                else if (path == "/String/GetAt") {
                    std::string addrStr = queryParams["addr"];
                    if (addrStr.empty()) {
                        sendHttpResponse(clientSocket, 400, "application/json",
                            "{\"error\":\"Missing required 'addr' parameter\"}");
                        continue;
                    }
                    
                    duint addr = 0;
                    if (!parseFlexibleDuint(addrStr, addr)) {
                        sendHttpResponse(clientSocket, 400, "application/json",
                            "{\"error\":\"Invalid address format\"}");
                        continue;
                    }
                    
                    char text[MAX_STRING_SIZE] = {0};
                    bool found = DbgGetStringAt(addr, text);
                    
                    std::stringstream ss;
                    ss << "{\"address\":\"0x" << std::hex << addr << "\","
                       << "\"found\":" << (found ? "true" : "false") << ","
                       << "\"string\":\"" << escapeJsonString(text) << "\"}";
                    sendHttpResponse(clientSocket, 200, "application/json", ss.str());
                }
                else if (path == "/Xref/Get") {
                    std::string addrStr = queryParams["addr"];
                    if (addrStr.empty()) {
                        sendHttpResponse(clientSocket, 400, "application/json",
                            "{\"error\":\"Missing required 'addr' parameter\"}");
                        continue;
                    }
                    
                    duint addr = 0;
                    if (!parseFlexibleDuint(addrStr, addr)) {
                        sendHttpResponse(clientSocket, 400, "application/json",
                            "{\"error\":\"Invalid address format\"}");
                        continue;
                    }
                    
                    XREF_INFO xrefInfo = {0};
                    bool success = DbgXrefGet(addr, &xrefInfo);
                    const size_t totalRefs = success
                        ? static_cast<size_t>(xrefInfo.refcount)
                        : 0;
                    const bool pagingRequested =
                        !queryParams["offset"].empty()
                        || !queryParams["limit"].empty();
                    duint offsetValue = 0;
                    duint limitValue = 100;
                    if (!queryParams["offset"].empty()
                        && !parseCountValue(queryParams["offset"], offsetValue)) {
                        if (success && xrefInfo.references != nullptr)
                            BridgeFree(xrefInfo.references);
                        sendHttpResponse(clientSocket, 400, "application/json",
                            "{\"ok\":false,\"error\":{\"code\":\"invalid_offset\","
                            "\"message\":\"offset must be a non-negative integer\","
                            "\"retryable\":false}}");
                        continue;
                    }
                    if (!queryParams["limit"].empty()
                        && !parseCountValue(queryParams["limit"], limitValue)) {
                        if (success && xrefInfo.references != nullptr)
                            BridgeFree(xrefInfo.references);
                        sendHttpResponse(clientSocket, 400, "application/json",
                            "{\"ok\":false,\"error\":{\"code\":\"invalid_limit\","
                            "\"message\":\"limit must be an integer\","
                            "\"retryable\":false}}");
                        continue;
                    }
                    const size_t pageOffset = pagingRequested
                        ? std::min<size_t>(static_cast<size_t>(offsetValue), totalRefs)
                        : 0;
                    const size_t pageLimit = pagingRequested
                        ? std::max<size_t>(1, std::min<size_t>(
                            static_cast<size_t>(limitValue), 5000))
                        : totalRefs;
                    const size_t pageEnd = std::min(totalRefs, pageOffset + pageLimit);
                    
                    std::stringstream ss;
                    ss << "{\"address\":\"0x" << std::hex << addr << "\","
                       << "\"refcount\":" << std::dec << totalRefs << ","
                       << "\"offset\":" << std::dec << pageOffset << ","
                       << "\"returned\":" << std::dec << (pageEnd - pageOffset) << ","
                       << "\"hasMore\":" << (pageEnd < totalRefs ? "true" : "false") << ","
                       << "\"nextOffset\":" << std::dec
                       << (pageEnd < totalRefs ? pageEnd : 0) << ","
                       << "\"references\":[";
                    
                    if (success && xrefInfo.references != nullptr) {
                        for (size_t i = pageOffset; i < pageEnd; i++) {
                            if (i > pageOffset) ss << ",";
                            
                            const char* typeStr = "none";
                            switch (xrefInfo.references[i].type) {
                                case XREF_DATA: typeStr = "data"; break;
                                case XREF_JMP:  typeStr = "jmp"; break;
                                case XREF_CALL: typeStr = "call"; break;
                                default: typeStr = "none"; break;
                            }
                            
                            // Also try to get the string at the target address for context
                            char refString[MAX_STRING_SIZE] = {0};
                            DbgGetStringAt(xrefInfo.references[i].addr, refString);
                            
                            ss << "{\"addr\":\"0x" << std::hex << xrefInfo.references[i].addr << "\","
                               << "\"type\":\"" << typeStr << "\"";
                            
                            if (refString[0] != '\0') {
                                ss << ",\"string\":\"" << escapeJsonString(refString) << "\"";
                            }
                            
                            ss << "}";
                        }
                        
                        // Free the references array
                        BridgeFree(xrefInfo.references);
                    }
                    
                    ss << "]}";
                    sendHttpResponse(clientSocket, 200, "application/json", ss.str());
                }
                else if (path == "/Xref/Count") {
                    std::string addrStr = queryParams["addr"];
                    if (addrStr.empty()) {
                        sendHttpResponse(clientSocket, 400, "application/json",
                            "{\"error\":\"Missing required 'addr' parameter\"}");
                        continue;
                    }
                    
                    duint addr = 0;
                    if (!parseFlexibleDuint(addrStr, addr)) {
                        sendHttpResponse(clientSocket, 400, "application/json",
                            "{\"error\":\"Invalid address format\"}");
                        continue;
                    }
                    
                    size_t count = DbgGetXrefCountAt(addr);
                    
                    std::stringstream ss;
                    ss << "{\"address\":\"0x" << std::hex << addr << "\","
                       << "\"count\":" << std::dec << count << "}";
                    sendHttpResponse(clientSocket, 200, "application/json", ss.str());
                }
                else if (path == "/MemoryMap") {
                    MEMMAP memmap;
                    memset(&memmap, 0, sizeof(memmap));
                    bool success = DbgMemMap(&memmap);
                    
                    if (!success || memmap.page == nullptr || memmap.count == 0) {
                        sendHttpResponse(clientSocket, 500, "application/json",
                            "{\"error\":\"Failed to get memory map\",\"pages\":[]}");
                        continue;
                    }
                    
                    std::stringstream ss;
                    ss << "{\"count\":" << memmap.count << ",\"pages\":[";
                    
                    for (int i = 0; i < memmap.count; i++) {
                        if (i > 0) ss << ",";
                        MEMPAGE& p = memmap.page[i];
                        
                        // Decode protection to string
                        const char* protectStr = "---";
                        DWORD prot = p.mbi.Protect & 0xFF;
                        if (prot == PAGE_EXECUTE_READWRITE) protectStr = "ERW";
                        else if (prot == PAGE_EXECUTE_READ) protectStr = "ER-";
                        else if (prot == PAGE_EXECUTE_WRITECOPY) protectStr = "ERW";
                        else if (prot == PAGE_READWRITE) protectStr = "-RW";
                        else if (prot == PAGE_READONLY) protectStr = "-R-";
                        else if (prot == PAGE_WRITECOPY) protectStr = "-RW";
                        else if (prot == PAGE_EXECUTE) protectStr = "E--";
                        else if (prot == PAGE_NOACCESS) protectStr = "---";
                        
                        // Decode type
                        const char* typeStr = "Unknown";
                        if (p.mbi.Type == MEM_IMAGE) typeStr = "IMG";
                        else if (p.mbi.Type == MEM_MAPPED) typeStr = "MAP";
                        else if (p.mbi.Type == MEM_PRIVATE) typeStr = "PRV";
                        
                        ss << "{\"base\":\"0x" << std::hex << (duint)p.mbi.BaseAddress << "\","
                           << "\"size\":\"0x" << std::hex << p.mbi.RegionSize << "\","
                           << "\"protect\":\"" << protectStr << "\","
                           << "\"type\":\"" << typeStr << "\","
                           << "\"info\":\"" << escapeJsonString(p.info) << "\"}";
                    }
                    
                    ss << "]}";
                    sendHttpResponse(clientSocket, 200, "application/json", ss.str());
                }
                else if (path == "/Memory/SetPageRights") {
                    const std::string addrStr = queryParams["addr"];
                    const std::string rights = queryParams["rights"];
                    if (addrStr.empty() || rights.empty()) {
                        sendHttpResponse(clientSocket, 400, "application/json",
                            "{\"ok\":false,\"error\":{\"code\":\"missing_page_rights_input\",\"message\":\"addr and rights are required\",\"retryable\":false}}");
                        continue;
                    }
                    duint addr = 0;
                    if (!parseFlexibleDuint(addrStr, addr)) {
                        sendHttpResponse(clientSocket, 400, "application/json",
                            "{\"ok\":false,\"error\":{\"code\":\"invalid_address\",\"message\":\"Invalid address format\",\"retryable\":false}}");
                        continue;
                    }
                    const bool printableRights = rights.size() <= 64
                        && std::all_of(rights.begin(), rights.end(), [](unsigned char ch) {
                            return ch >= 0x20 && ch < 0x7f;
                        });
                    if (!printableRights) {
                        sendHttpResponse(clientSocket, 400, "application/json",
                            "{\"ok\":false,\"error\":{\"code\":\"invalid_page_rights\",\"message\":\"rights must be a printable x64dbg page-rights string of at most 64 characters\",\"retryable\":false}}");
                        continue;
                    }
                    const DBGFUNCTIONS* dbgFunc = DbgFunctions();
                    if (!dbgFunc || !dbgFunc->SetPageRights) {
                        sendHttpResponse(clientSocket, 503, "application/json",
                            "{\"ok\":false,\"error\":{\"code\":\"page_rights_unavailable\",\"message\":\"DbgFunctions::SetPageRights is unavailable\",\"retryable\":false}}");
                        continue;
                    }
                    const bool success = dbgFunc->SetPageRights(addr, rights.c_str());
                    std::stringstream ss;
                    ss << "{\"ok\":" << (success ? "true" : "false")
                       << ",\"success\":" << (success ? "true" : "false")
                       << ",\"address\":\"0x" << std::hex << addr << "\""
                       << ",\"rights\":\"" << escapeJsonString(rights.c_str()) << "\"";
                    if (!success) {
                        ss << ",\"error\":{\"code\":\"set_page_rights_failed\",\"message\":\"x64dbg rejected the requested page rights\",\"retryable\":false}";
                    }
                    ss << "}";
                    sendHttpResponse(clientSocket, success ? 200 : 500, "application/json", ss.str());
                }
                else if (path == "/Memory/RemoteAlloc") {
                    auto requestParams = mergeRequestParams(query, body);
                    std::string addrStr = requestParams["addr"];
                    std::string sizeStr = requestParams["size"];
                    
                    if (sizeStr.empty()) {
                        sendHttpResponse(clientSocket, 400, "application/json",
                            "{\"error\":\"Missing required 'size' parameter\"}");
                        continue;
                    }
                    
                    duint addr = 0;
                    duint size = 0;
                    if (!addrStr.empty() && !parseFlexibleDuint(addrStr, addr)) {
                        sendHttpResponse(clientSocket, 400, "application/json",
                            "{\"error\":\"Invalid addr parameter\"}");
                        continue;
                    }
                    if (!parseCountValue(sizeStr, size)) {
                        sendHttpResponse(clientSocket, 400, "application/json",
                            "{\"error\":\"Invalid size parameter\"}");
                        continue;
                    }
                    
                    duint result = Script::Memory::RemoteAlloc(addr, size);
                    
                    if (result == 0) {
                        std::stringstream err;
                        err << "{"
                            << "\"error\":\"RemoteAlloc failed\","
                            << "\"addr\":\"0x" << std::hex << addr << "\","
                            << "\"size\":\"0x" << std::hex << size << "\""
                            << "}";
                        sendHttpResponse(clientSocket, 500, "application/json",
                            err.str());
                    } else {
                        std::stringstream ss;
                        ss << "{\"address\":\"0x" << std::hex << result << "\","
                           << "\"size\":\"0x" << std::hex << size << "\"}";
                        sendHttpResponse(clientSocket, 200, "application/json", ss.str());
                    }
                }
                else if (path == "/Memory/RemoteFree") {
                    auto requestParams = mergeRequestParams(query, body);
                    std::string addrStr = requestParams["addr"];
                    if (addrStr.empty()) {
                        sendHttpResponse(clientSocket, 400, "application/json",
                            "{\"error\":\"Missing required 'addr' parameter\"}");
                        continue;
                    }
                    
                    duint addr = 0;
                    if (!parseFlexibleDuint(addrStr, addr)) {
                        sendHttpResponse(clientSocket, 400, "application/json",
                            "{\"error\":\"Invalid addr parameter\"}");
                        continue;
                    }
                    
                    bool success = Script::Memory::RemoteFree(addr);
                    std::stringstream ss;
                    ss << "{\"success\":" << (success ? "true" : "false") << "}";
                    sendHttpResponse(clientSocket, 200, "application/json", ss.str());
                }
                else if (path == "/GetBranchDestination") {
                    std::string addrStr = queryParams["addr"];
                    if (addrStr.empty()) {
                        sendHttpResponse(clientSocket, 400, "application/json",
                            "{\"error\":\"Missing required 'addr' parameter\"}");
                        continue;
                    }
                    
                    duint addr = 0;
                    if (!parseFlexibleDuint(addrStr, addr)) {
                        sendHttpResponse(clientSocket, 400, "application/json",
                            "{\"error\":\"Invalid address format\"}");
                        continue;
                    }
                    
                    duint dest = DbgGetBranchDestination(addr);
                    
                    std::stringstream ss;
                    ss << "{\"address\":\"0x" << std::hex << addr << "\","
                       << "\"destination\":\"0x" << std::hex << dest << "\","
                       << "\"resolved\":" << (dest != 0 ? "true" : "false") << "}";
                    sendHttpResponse(clientSocket, 200, "application/json", ss.str());
                }
                else if (path == "/GetCallStack") {
                    const DBGFUNCTIONS* dbgFunc = DbgFunctions();
                    if (!dbgFunc || !dbgFunc->GetCallStackEx) {
                        sendHttpResponse(clientSocket, 500, "application/json",
                            "{\"error\":\"GetCallStackEx not available\"}");
                        continue;
                    }
                    
                    DBGCALLSTACK callstack;
                    memset(&callstack, 0, sizeof(callstack));
                    std::string cacheText = toLowerCopy(queryParams["cache"]);
                    trimParam(cacheText);
                    const bool useCache = parseBoolParam(cacheText, false);
                    dbgFunc->GetCallStackEx(&callstack, useCache);
                    
                    std::stringstream ss;
                    ss << "{\"total\":" << callstack.total
                       << ",\"cached\":" << (useCache ? "true" : "false")
                       << ",\"entries\":[";
                    
                    if (callstack.entries != nullptr) {
                        for (int i = 0; i < callstack.total; i++) {
                            if (i > 0) ss << ",";
                            DBGCALLSTACKENTRY& e = callstack.entries[i];
                            ss << "{\"addr\":\"0x" << std::hex << e.addr << "\","
                               << "\"from\":\"0x" << std::hex << e.from << "\","
                               << "\"to\":\"0x" << std::hex << e.to << "\","
                               << "\"comment\":\"" << escapeJsonString(e.comment) << "\"}";
                        }
                        BridgeFree(callstack.entries);
                    }
                    
                    ss << "]}";
                    sendHttpResponse(clientSocket, 200, "application/json", ss.str());
                }
                else if (path == "/Breakpoint/List") {
                    std::string typeStr = queryParams["type"];
                    
                    // Default to listing all breakpoint types
                    BPXTYPE bpType = bp_normal;
                    if (typeStr == "hardware") bpType = bp_hardware;
                    else if (typeStr == "memory") bpType = bp_memory;
                    else if (typeStr == "dll") bpType = bp_dll;
                    else if (typeStr == "exception") bpType = bp_exception;
                    else if (typeStr == "normal" || typeStr.empty()) bpType = bp_normal;
                    
                    // If type is "all", we gather all types
                    bool getAllTypes = (typeStr == "all" || typeStr.empty());
                    
                    std::stringstream ss;
                    ss << "{\"breakpoints\":[";
                    
                    int totalEmitted = 0;
                    
                    // Types to iterate
                    BPXTYPE types[] = { bp_normal, bp_hardware, bp_memory, bp_dll, bp_exception };
                    int numTypes = getAllTypes ? 5 : 1;
                    BPXTYPE* typeList = getAllTypes ? types : &bpType;
                    
                    for (int t = 0; t < numTypes; t++) {
                        BPMAP bpmap;
                        memset(&bpmap, 0, sizeof(bpmap));
                        int returnedCount = DbgGetBpList(typeList[t], &bpmap);
                        // BPMAP::count is authoritative on SDK builds that
                        // return a boolean-ish value from DbgGetBpList.
                        int count = bpmap.count > 0 ? bpmap.count : returnedCount;
                        
                        if (count > 0 && bpmap.bp != nullptr) {
                            for (int i = 0; i < bpmap.count; i++) {
                                if (totalEmitted > 0) ss << ",";
                                BRIDGEBP& bp = bpmap.bp[i];
                                
                                const char* bpTypeStr = "unknown";
                                switch (bp.type) {
                                    case bp_normal:    bpTypeStr = "normal"; break;
                                    case bp_hardware:  bpTypeStr = "hardware"; break;
                                    case bp_memory:    bpTypeStr = "memory"; break;
                                    case bp_dll:       bpTypeStr = "dll"; break;
                                    case bp_exception: bpTypeStr = "exception"; break;
                                    default: break;
                                }
                                
                                ss << "{\"type\":\"" << bpTypeStr << "\","
                                   << "\"addr\":\"0x" << std::hex << bp.addr << "\","
                                   << "\"enabled\":" << (bp.enabled ? "true" : "false") << ","
                                   << "\"singleshoot\":" << (bp.singleshoot ? "true" : "false") << ","
                                   << "\"active\":" << (bp.active ? "true" : "false") << ","
                                   << "\"name\":\"" << escapeJsonString(bp.name) << "\","
                                   << "\"module\":\"" << escapeJsonString(bp.mod) << "\","
                                   << "\"hitCount\":" << std::dec << bp.hitCount << ","
                                   << "\"fastResume\":" << (bp.fastResume ? "true" : "false") << ","
                                   << "\"silent\":" << (bp.silent ? "true" : "false") << ","
                                   << "\"breakCondition\":\"" << escapeJsonString(bp.breakCondition) << "\","
                                   << "\"logText\":\"" << escapeJsonString(bp.logText) << "\","
                                   << "\"commandText\":\"" << escapeJsonString(bp.commandText) << "\""
                                   << "}";
                                totalEmitted++;
                            }
                            BridgeFree(bpmap.bp);
                        }
                    }
                    
                    ss << "],\"count\":" << std::dec << totalEmitted << "}";
                    sendHttpResponse(clientSocket, 200, "application/json", ss.str());
                }
                else if (path == "/Label/Set") {
                    std::string addrStr = queryParams["addr"];
                    std::string text = queryParams["text"];
                    if (!body.empty() && text.empty()) text = body;
                    
                    if (addrStr.empty() || text.empty()) {
                        sendHttpResponse(clientSocket, 400, "application/json",
                            "{\"error\":\"Missing required 'addr' and 'text' parameters\"}");
                        continue;
                    }
                    if (text.find('\0') != std::string::npos || text.size() >= MAX_LABEL_SIZE) {
                        sendHttpResponse(clientSocket, 400, "application/json",
                            "{\"ok\":false,\"error\":{\"code\":\"invalid_label_text\","
                            "\"message\":\"Label text must be valid, non-NUL, and shorter than MAX_LABEL_SIZE bytes\","
                            "\"retryable\":false}}");
                        continue;
                    }
                    
                    duint addr = 0;
                    if (!parseFlexibleDuint(addrStr, addr)) {
                        sendHttpResponse(clientSocket, 400, "application/json",
                            "{\"error\":\"Invalid address format\"}");
                        continue;
                    }
                    
                    const bool manual = parseBoolParam(queryParams["manual"], true);
                    bool success = Script::Label::Set(addr, text.c_str(), manual, false);
                    std::stringstream ss;
                    ss << "{\"success\":" << (success ? "true" : "false") << ","
                       << "\"address\":\"0x" << std::hex << addr << "\","
                       << "\"label\":\"" << escapeJsonString(text.c_str()) << "\","
                       << "\"manual\":" << (manual ? "true" : "false") << "}";
                    sendHttpResponse(clientSocket, 200, "application/json", ss.str());
                }
                else if (path == "/Label/Delete") {
                    duint addr = 0;
                    if (queryParams["addr"].empty() || !parseFlexibleDuint(queryParams["addr"], addr)) {
                        sendHttpResponse(clientSocket, 400, "application/json",
                            "{\"ok\":false,\"error\":{\"code\":\"invalid_address\","
                            "\"message\":\"A valid addr is required\",\"retryable\":false}}");
                        continue;
                    }
                    const bool deleted = Script::Label::Delete(addr);
                    std::stringstream ss;
                    ss << "{\"ok\":true,\"success\":" << (deleted ? "true" : "false")
                       << ",\"deleted\":" << (deleted ? "true" : "false")
                       << ",\"address\":\"0x" << std::hex << addr << "\"}";
                    sendHttpResponse(clientSocket, 200, "application/json", ss.str());
                }
                else if (path == "/Label/Get") {
                    std::string addrStr = queryParams["addr"];
                    if (addrStr.empty()) {
                        sendHttpResponse(clientSocket, 400, "application/json",
                            "{\"error\":\"Missing required 'addr' parameter\"}");
                        continue;
                    }
                    
                    duint addr = 0;
                    if (!parseFlexibleDuint(addrStr, addr)) {
                        sendHttpResponse(clientSocket, 400, "application/json",
                            "{\"error\":\"Invalid address format\"}");
                        continue;
                    }
                    
                    char text[MAX_LABEL_SIZE] = {0};
                    bool found = DbgGetLabelAt(addr, SEG_DEFAULT, text);
                    
                    std::stringstream ss;
                    ss << "{\"address\":\"0x" << std::hex << addr << "\","
                       << "\"found\":" << (found ? "true" : "false") << ","
                       << "\"label\":\"" << escapeJsonString(text) << "\"}";
                    sendHttpResponse(clientSocket, 200, "application/json", ss.str());
                }
                else if (path == "/Label/List") {
                    ListInfo labelList;
                    bool success = Script::Label::GetList(&labelList);
                    
                    if (!success || labelList.data == nullptr) {
                        sendHttpResponse(clientSocket, 200, "application/json",
                            "{\"count\":0,\"labels\":[]}");
                        continue;
                    }
                    
                    Script::Label::LabelInfo* labels = (Script::Label::LabelInfo*)labelList.data;
                    size_t count = labelList.count;
                    
                    std::stringstream ss;
                    ss << "{\"count\":" << std::dec << count << ",\"labels\":[";
                    
                    for (size_t i = 0; i < count; i++) {
                        if (i > 0) ss << ",";
                        ss << "{\"module\":\"" << escapeJsonString(labels[i].mod) << "\","
                           << "\"rva\":\"0x" << std::hex << labels[i].rva << "\","
                           << "\"text\":\"" << escapeJsonString(labels[i].text) << "\","
                           << "\"manual\":" << (labels[i].manual ? "true" : "false") << "}";
                    }
                    
                    ss << "]}";
                    BridgeFree(labelList.data);
                    sendHttpResponse(clientSocket, 200, "application/json", ss.str());
                }
                else if (path == "/Comment/Set") {
                    std::string addrStr = queryParams["addr"];
                    std::string text = queryParams["text"];
                    if (!body.empty() && text.empty()) text = body;
                    
                    if (addrStr.empty() || text.empty()) {
                        sendHttpResponse(clientSocket, 400, "application/json",
                            "{\"error\":\"Missing required 'addr' and 'text' parameters\"}");
                        continue;
                    }
                    if (text.find('\0') != std::string::npos || text.size() >= MAX_COMMENT_SIZE) {
                        sendHttpResponse(clientSocket, 400, "application/json",
                            "{\"ok\":false,\"error\":{\"code\":\"invalid_comment_text\","
                            "\"message\":\"Comment text must be valid, non-NUL, and shorter than MAX_COMMENT_SIZE bytes\","
                            "\"retryable\":false}}");
                        continue;
                    }
                    
                    duint addr = 0;
                    if (!parseFlexibleDuint(addrStr, addr)) {
                        sendHttpResponse(clientSocket, 400, "application/json",
                            "{\"error\":\"Invalid address format\"}");
                        continue;
                    }
                    
                    const bool manual = parseBoolParam(queryParams["manual"], true);
                    bool success = Script::Comment::Set(addr, text.c_str(), manual);
                    std::stringstream ss;
                    ss << "{\"success\":" << (success ? "true" : "false") << ","
                       << "\"address\":\"0x" << std::hex << addr << "\","
                       << "\"manual\":" << (manual ? "true" : "false") << "}";
                    sendHttpResponse(clientSocket, 200, "application/json", ss.str());
                }
                else if (path == "/Comment/Delete") {
                    duint addr = 0;
                    if (queryParams["addr"].empty() || !parseFlexibleDuint(queryParams["addr"], addr)) {
                        sendHttpResponse(clientSocket, 400, "application/json",
                            "{\"ok\":false,\"error\":{\"code\":\"invalid_address\","
                            "\"message\":\"A valid addr is required\",\"retryable\":false}}");
                        continue;
                    }
                    const bool deleted = Script::Comment::Delete(addr);
                    std::stringstream ss;
                    ss << "{\"ok\":true,\"success\":" << (deleted ? "true" : "false")
                       << ",\"deleted\":" << (deleted ? "true" : "false")
                       << ",\"address\":\"0x" << std::hex << addr << "\"}";
                    sendHttpResponse(clientSocket, 200, "application/json", ss.str());
                }
                else if (path == "/Comment/Get") {
                    std::string addrStr = queryParams["addr"];
                    if (addrStr.empty()) {
                        sendHttpResponse(clientSocket, 400, "application/json",
                            "{\"error\":\"Missing required 'addr' parameter\"}");
                        continue;
                    }
                    
                    duint addr = 0;
                    if (!parseFlexibleDuint(addrStr, addr)) {
                        sendHttpResponse(clientSocket, 400, "application/json",
                            "{\"error\":\"Invalid address format\"}");
                        continue;
                    }
                    
                    char text[MAX_COMMENT_SIZE] = {0};
                    bool found = DbgGetCommentAt(addr, text);
                    
                    std::stringstream ss;
                    ss << "{\"address\":\"0x" << std::hex << addr << "\","
                       << "\"found\":" << (found ? "true" : "false") << ","
                       << "\"comment\":\"" << escapeJsonString(text) << "\"}";
                    sendHttpResponse(clientSocket, 200, "application/json", ss.str());
                }
                else if (path == "/Comment/List") {
                    const std::string moduleFilter = queryParams["module"];
                    duint offsetValue = 0;
                    duint limitValue = 500;
                    if (!queryParams["offset"].empty()) parseCountValue(queryParams["offset"], offsetValue);
                    if (!queryParams["limit"].empty()) parseCountValue(queryParams["limit"], limitValue);
                    const size_t offset = static_cast<size_t>(offsetValue);
                    const size_t limit = static_cast<size_t>(std::max<duint>(1, std::min<duint>(limitValue, 5000)));
                    // Script::Comment::GetList is unsafe for valid comments over
                    // MAX_LABEL_SIZE: upstream copies the dynamic comment string
                    // into CommentInfo::text[256] with strcpy_s, invoking the
                    // process-wide invalid-parameter handler.  The built-in
                    // `commentlist 1` command enumerates the native std::string
                    // records safely into the Reference view. Read only its
                    // address column, then fetch each full comment individually
                    // through the correctly-sized MAX_COMMENT_SIZE API.
                    if (!DbgCmdExecDirect("commentlist 1")) {
                        sendHttpResponse(clientSocket, 500, "application/json",
                            "{\"ok\":false,\"error\":{\"code\":\"comment_enumeration_failed\","
                            "\"message\":\"The debugger commentlist command failed\",\"retryable\":false}}");
                        continue;
                    }
                    struct SafeCommentRecord {
                        std::string module;
                        duint rva = 0;
                        std::string text;
                        bool manual = true;
                    };
                    std::vector<SafeCommentRecord> records;
                    const int rowCount = std::max(0, GuiReferenceGetRowCount());
                    records.reserve(static_cast<size_t>(rowCount));
                    for (int row = 0; row < rowCount; ++row) {
                        char* addressText = GuiReferenceGetCellContent(row, 0);
                        if (!addressText) continue;
                        duint address = 0;
                        const bool parsed = parseFlexibleDuint(addressText, address);
                        BridgeFree(addressText);
                        if (!parsed) continue;
                        char fullText[MAX_COMMENT_SIZE] = {0};
                        if (!Script::Comment::Get(address, fullText)) continue;
                        SafeCommentRecord record;
                        const char* textStart = fullText;
                        if (fullText[0] == '\1') {
                            record.manual = false;
                            textStart = fullText + 1;
                        }
                        record.text = textStart;
                        Script::Module::ModuleInfo moduleInfo = {};
                        if (Script::Module::InfoFromAddr(address, &moduleInfo)) {
                            record.module = moduleInfo.name;
                            record.rva = address - moduleInfo.base;
                        } else {
                            record.rva = address;
                        }
                        if (!moduleFilter.empty()
                            && !moduleNameMatches(moduleFilter, record.module)) continue;
                        records.push_back(std::move(record));
                    }
                    std::sort(records.begin(), records.end(), [](const SafeCommentRecord& left,
                                                                 const SafeCommentRecord& right) {
                        const int moduleOrder = _stricmp(left.module.c_str(), right.module.c_str());
                        return moduleOrder == 0 ? left.rva < right.rva : moduleOrder < 0;
                    });
                    const size_t matching = records.size();
                    const size_t start = std::min(offset, matching);
                    const size_t end = std::min(matching, start + limit);
                    std::stringstream ss;
                    ss << "{\"ok\":true,\"comments\":[";
                    for (size_t i = start; i < end; ++i) {
                        if (i != start) ss << ",";
                        const auto& item = records[i];
                        ss << "{\"module\":\"" << escapeJsonString(item.module.c_str()) << "\","
                           << "\"rva\":\"0x" << std::hex << item.rva << "\","
                           << "\"text\":\"" << escapeJsonString(item.text.c_str()) << "\","
                           << "\"manual\":" << (item.manual ? "true" : "false") << "}";
                    }
                    const size_t emitted = end - start;
                    ss << "],\"count\":" << std::dec << matching
                       << ",\"offset\":" << offset
                       << ",\"returned\":" << emitted
                       << ",\"hasMore\":" << (offset + emitted < matching ? "true" : "false")
                       << ",\"nextOffset\":";
                    if (offset + emitted < matching) ss << (offset + emitted); else ss << "null";
                    ss << "}";
                    sendHttpResponse(clientSocket, 200, "application/json", ss.str());
                }
                else if (path == "/Bookmark/Set") {
                    duint addr = 0;
                    if (queryParams["addr"].empty() || !parseFlexibleDuint(queryParams["addr"], addr)) {
                        sendHttpResponse(clientSocket, 400, "application/json",
                            "{\"ok\":false,\"error\":\"A valid addr is required\"}");
                        continue;
                    }
                    const bool manual = parseBoolParam(queryParams["manual"], true);
                    const bool success = Script::Bookmark::Set(addr, manual);
                    std::stringstream ss;
                    ss << "{\"ok\":true,\"success\":" << (success ? "true" : "false")
                       << ",\"address\":\"0x" << std::hex << addr << "\","
                       << "\"manual\":" << (manual ? "true" : "false") << "}";
                    sendHttpResponse(clientSocket, 200, "application/json", ss.str());
                }
                else if (path == "/Bookmark/Delete") {
                    duint addr = 0;
                    if (queryParams["addr"].empty() || !parseFlexibleDuint(queryParams["addr"], addr)) {
                        sendHttpResponse(clientSocket, 400, "application/json",
                            "{\"ok\":false,\"error\":{\"code\":\"invalid_address\","
                            "\"message\":\"A valid addr is required\",\"retryable\":false}}");
                        continue;
                    }
                    const bool deleted = Script::Bookmark::Delete(addr);
                    std::stringstream ss;
                    ss << "{\"ok\":true,\"success\":" << (deleted ? "true" : "false")
                       << ",\"deleted\":" << (deleted ? "true" : "false")
                       << ",\"address\":\"0x" << std::hex << addr << "\"}";
                    sendHttpResponse(clientSocket, 200, "application/json", ss.str());
                }
                else if (path == "/Bookmark/Get") {
                    duint addr = 0;
                    if (queryParams["addr"].empty() || !parseFlexibleDuint(queryParams["addr"], addr)) {
                        sendHttpResponse(clientSocket, 400, "application/json",
                            "{\"ok\":false,\"error\":\"A valid addr is required\"}");
                        continue;
                    }
                    Script::Bookmark::BookmarkInfo info = {};
                    const bool found = Script::Bookmark::GetInfo(addr, &info);
                    std::stringstream ss;
                    ss << "{\"ok\":true,\"address\":\"0x" << std::hex << addr << "\","
                       << "\"found\":" << (found ? "true" : "false");
                    if (found) {
                        ss << ",\"module\":\"" << escapeJsonString(info.mod) << "\","
                           << "\"rva\":\"0x" << std::hex << info.rva << "\","
                           << "\"manual\":" << (info.manual ? "true" : "false");
                    }
                    ss << "}";
                    sendHttpResponse(clientSocket, 200, "application/json", ss.str());
                }
                else if (path == "/Bookmark/List") {
                    ListInfo list = {};
                    const bool success = Script::Bookmark::GetList(&list);
                    const std::string moduleFilter = queryParams["module"];
                    duint offsetValue = 0;
                    duint limitValue = 500;
                    if (!queryParams["offset"].empty()) parseCountValue(queryParams["offset"], offsetValue);
                    if (!queryParams["limit"].empty()) parseCountValue(queryParams["limit"], limitValue);
                    const size_t offset = static_cast<size_t>(offsetValue);
                    const size_t limit = static_cast<size_t>(std::max<duint>(1, std::min<duint>(limitValue, 5000)));
                    if (!success || list.data == nullptr) {
                        if (list.data != nullptr) BridgeFree(list.data);
                        sendHttpResponse(clientSocket, 200, "application/json",
                            "{\"ok\":true,\"count\":0,\"offset\":0,\"returned\":0,\"hasMore\":false,\"bookmarks\":[]}");
                        continue;
                    }
                    auto* items = static_cast<Script::Bookmark::BookmarkInfo*>(list.data);
                    size_t matching = 0;
                    size_t emitted = 0;
                    std::stringstream ss;
                    ss << "{\"ok\":true,\"bookmarks\":[";
                    for (size_t i = 0; i < list.count; ++i) {
                        if (!moduleFilter.empty() && !moduleNameMatches(moduleFilter, items[i].mod)) continue;
                        const size_t matchIndex = matching++;
                        if (matchIndex < offset || emitted >= limit) continue;
                        if (emitted++) ss << ",";
                        ss << "{\"module\":\"" << escapeJsonString(items[i].mod) << "\","
                           << "\"rva\":\"0x" << std::hex << items[i].rva << "\","
                           << "\"manual\":" << (items[i].manual ? "true" : "false") << "}";
                    }
                    ss << "],\"count\":" << std::dec << matching
                       << ",\"offset\":" << offset
                       << ",\"returned\":" << emitted
                       << ",\"hasMore\":" << (offset + emitted < matching ? "true" : "false")
                       << ",\"nextOffset\":";
                    if (offset + emitted < matching) ss << (offset + emitted); else ss << "null";
                    ss << "}";
                    BridgeFree(list.data);
                    sendHttpResponse(clientSocket, 200, "application/json", ss.str());
                }
                else if (path == "/Function/Add") {
                    duint start = 0;
                    duint end = 0;
                    duint instructionCount = 0;
                    if (queryParams["start"].empty() || queryParams["end"].empty()
                        || !parseFlexibleDuint(queryParams["start"], start)
                        || !parseFlexibleDuint(queryParams["end"], end)
                        || end < start
                        || (!queryParams["instructionCount"].empty()
                            && !parseCountValue(queryParams["instructionCount"], instructionCount))) {
                        sendHttpResponse(clientSocket, 400, "application/json",
                            "{\"ok\":false,\"error\":\"Valid start/end and instructionCount are required\"}");
                        continue;
                    }
                    const bool manual = parseBoolParam(queryParams["manual"], true);
                    const bool success = Script::Function::Add(start, end, manual, instructionCount);
                    std::stringstream ss;
                    ss << "{\"ok\":true,\"success\":" << (success ? "true" : "false") << ","
                       << "\"start\":\"0x" << std::hex << start << "\","
                       << "\"end\":\"0x" << std::hex << end << "\","
                       << "\"manual\":" << (manual ? "true" : "false") << ","
                       << "\"instructionCount\":" << std::dec << instructionCount << "}";
                    sendHttpResponse(clientSocket, 200, "application/json", ss.str());
                }
                else if (path == "/Function/Delete") {
                    duint addr = 0;
                    if (queryParams["addr"].empty() || !parseFlexibleDuint(queryParams["addr"], addr)) {
                        sendHttpResponse(clientSocket, 400, "application/json",
                            "{\"ok\":false,\"error\":{\"code\":\"invalid_address\","
                            "\"message\":\"A valid function address is required\",\"retryable\":false}}");
                        continue;
                    }
                    const bool deleted = Script::Function::Delete(addr);
                    std::stringstream ss;
                    ss << "{\"ok\":true,\"success\":" << (deleted ? "true" : "false")
                       << ",\"deleted\":" << (deleted ? "true" : "false")
                       << ",\"address\":\"0x" << std::hex << addr << "\"}";
                    sendHttpResponse(clientSocket, 200, "application/json", ss.str());
                }
                else if (path == "/Function/List") {
                    ListInfo list = {};
                    const bool success = Script::Function::GetList(&list);
                    const std::string moduleFilter = queryParams["module"];
                    duint offsetValue = 0;
                    duint limitValue = 500;
                    if (!queryParams["offset"].empty()) parseCountValue(queryParams["offset"], offsetValue);
                    if (!queryParams["limit"].empty()) parseCountValue(queryParams["limit"], limitValue);
                    const size_t offset = static_cast<size_t>(offsetValue);
                    const size_t limit = static_cast<size_t>(std::max<duint>(1, std::min<duint>(limitValue, 5000)));
                    if (!success || list.data == nullptr) {
                        if (list.data != nullptr) BridgeFree(list.data);
                        sendHttpResponse(clientSocket, 200, "application/json",
                            "{\"ok\":true,\"count\":0,\"offset\":0,\"returned\":0,\"hasMore\":false,\"functions\":[]}");
                        continue;
                    }
                    auto* items = static_cast<Script::Function::FunctionInfo*>(list.data);
                    size_t matching = 0;
                    size_t emitted = 0;
                    std::stringstream ss;
                    ss << "{\"ok\":true,\"functions\":[";
                    for (size_t i = 0; i < list.count; ++i) {
                        if (!moduleFilter.empty() && !moduleNameMatches(moduleFilter, items[i].mod)) continue;
                        const size_t matchIndex = matching++;
                        if (matchIndex < offset || emitted >= limit) continue;
                        if (emitted++) ss << ",";
                        ss << "{\"module\":\"" << escapeJsonString(items[i].mod) << "\","
                           << "\"rvaStart\":\"0x" << std::hex << items[i].rvaStart << "\","
                           << "\"rvaEnd\":\"0x" << std::hex << items[i].rvaEnd << "\","
                           << "\"manual\":" << (items[i].manual ? "true" : "false") << ","
                           << "\"instructionCount\":" << std::dec << items[i].instructioncount << "}";
                    }
                    ss << "],\"count\":" << std::dec << matching
                       << ",\"offset\":" << offset
                       << ",\"returned\":" << emitted
                       << ",\"hasMore\":" << (offset + emitted < matching ? "true" : "false")
                       << ",\"nextOffset\":";
                    if (offset + emitted < matching) ss << (offset + emitted); else ss << "null";
                    ss << "}";
                    BridgeFree(list.data);
                    sendHttpResponse(clientSocket, 200, "application/json", ss.str());
                }
                else if (path == "/RegisterDump") {
                    REGDUMP_AVX512 regdump;
                    memset(&regdump, 0, sizeof(regdump));
                    bool success = DbgGetRegDumpEx(&regdump, sizeof(regdump));
                    
                    if (!success) {
                        sendHttpResponse(clientSocket, 500, "application/json",
                            "{\"error\":\"Failed to get register dump\"}");
                        continue;
                    }
                    
                    std::stringstream ss;
                    const ULONG_PTR rflags = regdump.regcontext.eflags;
                    const auto rflag = [rflags](unsigned bit) {
                        return ((rflags >> bit) & 1) != 0;
                    };
                    ss << "{";
                    
                    // General purpose registers
                    ss << "\"cax\":\"0x" << std::hex << regdump.regcontext.cax << "\","
                       << "\"ccx\":\"0x" << std::hex << regdump.regcontext.ccx << "\","
                       << "\"cdx\":\"0x" << std::hex << regdump.regcontext.cdx << "\","
                       << "\"cbx\":\"0x" << std::hex << regdump.regcontext.cbx << "\","
                       << "\"csp\":\"0x" << std::hex << regdump.regcontext.csp << "\","
                       << "\"cbp\":\"0x" << std::hex << regdump.regcontext.cbp << "\","
                       << "\"csi\":\"0x" << std::hex << regdump.regcontext.csi << "\","
                       << "\"cdi\":\"0x" << std::hex << regdump.regcontext.cdi << "\","
#ifdef _WIN64
                       << "\"r8\":\"0x" << std::hex << regdump.regcontext.r8 << "\","
                       << "\"r9\":\"0x" << std::hex << regdump.regcontext.r9 << "\","
                       << "\"r10\":\"0x" << std::hex << regdump.regcontext.r10 << "\","
                       << "\"r11\":\"0x" << std::hex << regdump.regcontext.r11 << "\","
                       << "\"r12\":\"0x" << std::hex << regdump.regcontext.r12 << "\","
                       << "\"r13\":\"0x" << std::hex << regdump.regcontext.r13 << "\","
                       << "\"r14\":\"0x" << std::hex << regdump.regcontext.r14 << "\","
                       << "\"r15\":\"0x" << std::hex << regdump.regcontext.r15 << "\","
#endif
                       << "\"cip\":\"0x" << std::hex << regdump.regcontext.cip << "\","
                       << "\"eflags\":\"0x" << std::hex << regdump.regcontext.eflags << "\","
                    
                    // Segment registers
                       << "\"gs\":\"0x" << std::hex << regdump.regcontext.gs << "\","
                       << "\"fs\":\"0x" << std::hex << regdump.regcontext.fs << "\","
                       << "\"es\":\"0x" << std::hex << regdump.regcontext.es << "\","
                       << "\"ds\":\"0x" << std::hex << regdump.regcontext.ds << "\","
                       << "\"cs\":\"0x" << std::hex << regdump.regcontext.cs << "\","
                       << "\"ss\":\"0x" << std::hex << regdump.regcontext.ss << "\","
                    
                    // Debug registers
                       << "\"dr0\":\"0x" << std::hex << regdump.regcontext.dr0 << "\","
                       << "\"dr1\":\"0x" << std::hex << regdump.regcontext.dr1 << "\","
                       << "\"dr2\":\"0x" << std::hex << regdump.regcontext.dr2 << "\","
                       << "\"dr3\":\"0x" << std::hex << regdump.regcontext.dr3 << "\","
                       << "\"dr6\":\"0x" << std::hex << regdump.regcontext.dr6 << "\","
                       << "\"dr7\":\"0x" << std::hex << regdump.regcontext.dr7 << "\","
                    
                    // RFLAGS condition codes (REGDUMP_AVX512 has no separate FLAGS; decode from eflags)
                       << "\"flags\":{"
                       << "\"ZF\":" << (rflag(6) ? "true" : "false") << ","
                       << "\"OF\":" << (rflag(11) ? "true" : "false") << ","
                       << "\"CF\":" << (rflag(0) ? "true" : "false") << ","
                       << "\"PF\":" << (rflag(2) ? "true" : "false") << ","
                       << "\"SF\":" << (rflag(7) ? "true" : "false") << ","
                       << "\"TF\":" << (rflag(8) ? "true" : "false") << ","
                       << "\"AF\":" << (rflag(4) ? "true" : "false") << ","
                       << "\"DF\":" << (rflag(10) ? "true" : "false") << ","
                       << "\"IF\":" << (rflag(9) ? "true" : "false")
                       << "},"
                    
                    // Last error/status (codes only in REGDUMP_AVX512)
                       << "\"lastError\":{\"code\":" << std::dec << regdump.lastError << ",\"name\":\"\"},"
                       << "\"lastStatus\":{\"code\":" << std::dec << regdump.lastStatus << ",\"name\":\"\"}"
                       << "}";
                    
                    sendHttpResponse(clientSocket, 200, "application/json", ss.str());
                }
                else if (path == "/Debug/SetHardwareBreakpoint") {
                    std::string addrStr = queryParams["addr"];
                    std::string typeStr = queryParams["type"]; // access, write, execute
                    
                    if (addrStr.empty()) {
                        sendHttpResponse(clientSocket, 400, "application/json",
                            "{\"error\":\"Missing required 'addr' parameter\"}");
                        continue;
                    }
                    
                    duint addr = 0;
                    if (!parseFlexibleDuint(addrStr, addr)) {
                        sendHttpResponse(clientSocket, 400, "application/json",
                            "{\"error\":\"Invalid address format\"}");
                        continue;
                    }
                    
                    Script::Debug::HardwareType hwType = Script::Debug::HardwareExecute;
                    if (typeStr == "access") hwType = Script::Debug::HardwareAccess;
                    else if (typeStr == "write") hwType = Script::Debug::HardwareWrite;
                    else if (typeStr == "execute") hwType = Script::Debug::HardwareExecute;
                    
                    bool success = Script::Debug::SetHardwareBreakpoint(addr, hwType);
                    std::stringstream ss;
                    ss << "{\"success\":" << (success ? "true" : "false") << ","
                       << "\"address\":\"0x" << std::hex << addr << "\"}";
                    sendHttpResponse(clientSocket, 200, "application/json", ss.str());
                }
                else if (path == "/Debug/DeleteHardwareBreakpoint") {
                    std::string addrStr = queryParams["addr"];
                    if (addrStr.empty()) {
                        sendHttpResponse(clientSocket, 400, "application/json",
                            "{\"error\":\"Missing required 'addr' parameter\"}");
                        continue;
                    }
                    
                    duint addr = 0;
                    if (!parseFlexibleDuint(addrStr, addr)) {
                        sendHttpResponse(clientSocket, 400, "application/json",
                            "{\"error\":\"Invalid address format\"}");
                        continue;
                    }
                    
                    bool success = Script::Debug::DeleteHardwareBreakpoint(addr);
                    std::stringstream ss;
                    ss << "{\"success\":" << (success ? "true" : "false") << ","
                       << "\"address\":\"0x" << std::hex << addr << "\"}";
                    sendHttpResponse(clientSocket, 200, "application/json", ss.str());
                }
                else if (path == "/EnumTcpConnections") {
                    const DBGFUNCTIONS* dbgFunc = DbgFunctions();
                    if (!dbgFunc || !dbgFunc->EnumTcpConnections) {
                        sendHttpResponse(clientSocket, 500, "application/json",
                            "{\"error\":\"EnumTcpConnections not available\"}");
                        continue;
                    }
                    
                    ListInfo tcpList;
                    bool success = dbgFunc->EnumTcpConnections(&tcpList);
                    
                    if (!success || tcpList.data == nullptr) {
                        sendHttpResponse(clientSocket, 200, "application/json",
                            "{\"count\":0,\"connections\":[]}");
                        continue;
                    }
                    
                    TCPCONNECTIONINFO* connections = (TCPCONNECTIONINFO*)tcpList.data;
                    size_t count = tcpList.count;
                    
                    std::stringstream ss;
                    ss << "{\"count\":" << std::dec << count << ",\"connections\":[";
                    
                    for (size_t i = 0; i < count; i++) {
                        if (i > 0) ss << ",";
                        ss << "{\"remoteAddress\":\"" << escapeJsonString(connections[i].RemoteAddress) << "\","
                           << "\"remotePort\":" << std::dec << connections[i].RemotePort << ","
                           << "\"localAddress\":\"" << escapeJsonString(connections[i].LocalAddress) << "\","
                           << "\"localPort\":" << std::dec << connections[i].LocalPort << ","
                           << "\"state\":\"" << escapeJsonString(connections[i].StateText) << "\"}";
                    }
                    
                    ss << "]}";
                    BridgeFree(tcpList.data);
                    sendHttpResponse(clientSocket, 200, "application/json", ss.str());
                }
                else if (path == "/Patch/List") {
                    const DBGFUNCTIONS* dbgFunc = DbgFunctions();
                    if (!dbgFunc || !dbgFunc->PatchEnum) {
                        sendHttpResponse(clientSocket, 500, "application/json",
                            "{\"error\":\"PatchEnum not available\"}");
                        continue;
                    }
                    
                    // First call to get size needed
                    size_t cbsize = 0;
                    dbgFunc->PatchEnum(nullptr, &cbsize);
                    
                    if (cbsize == 0) {
                        sendHttpResponse(clientSocket, 200, "application/json",
                            "{\"count\":0,\"patches\":[]}");
                        continue;
                    }
                    
                    size_t count = cbsize / sizeof(DBGPATCHINFO);
                    std::vector<DBGPATCHINFO> patches(count);
                    
                    if (!dbgFunc->PatchEnum(patches.data(), &cbsize)) {
                        sendHttpResponse(clientSocket, 500, "application/json",
                            "{\"error\":\"PatchEnum failed\"}");
                        continue;
                    }
                    
                    std::stringstream ss;
                    ss << "{\"count\":" << std::dec << count << ",\"patches\":[";
                    
                    for (size_t i = 0; i < count; i++) {
                        if (i > 0) ss << ",";
                        ss << "{\"module\":\"" << escapeJsonString(patches[i].mod) << "\","
                           << "\"address\":\"0x" << std::hex << patches[i].addr << "\","
                           << "\"oldByte\":\"0x" << std::hex << (int)patches[i].oldbyte << "\","
                           << "\"newByte\":\"0x" << std::hex << (int)patches[i].newbyte << "\"}";
                    }
                    
                    ss << "]}";
                    sendHttpResponse(clientSocket, 200, "application/json", ss.str());
                }
                else if (path == "/Patch/Get") {
                    std::string addrStr = queryParams["addr"];
                    if (addrStr.empty()) {
                        sendHttpResponse(clientSocket, 400, "application/json",
                            "{\"error\":\"Missing required 'addr' parameter\"}");
                        continue;
                    }
                    
                    duint addr = 0;
                    if (!parseFlexibleDuint(addrStr, addr)) {
                        sendHttpResponse(clientSocket, 400, "application/json",
                            "{\"error\":\"Invalid address format\"}");
                        continue;
                    }
                    
                    const DBGFUNCTIONS* dbgFunc = DbgFunctions();
                    if (!dbgFunc) {
                        sendHttpResponse(clientSocket, 500, "application/json",
                            "{\"error\":\"DbgFunctions not available\"}");
                        continue;
                    }
                    
                    DBGPATCHINFO patchInfo;
                    memset(&patchInfo, 0, sizeof(patchInfo));
                    bool found = false;
                    
                    if (dbgFunc->PatchGetEx) {
                        found = dbgFunc->PatchGetEx(addr, &patchInfo);
                    } else if (dbgFunc->PatchGet) {
                        found = dbgFunc->PatchGet(addr);
                    }
                    
                    std::stringstream ss;
                    ss << "{\"address\":\"0x" << std::hex << addr << "\","
                       << "\"patched\":" << (found ? "true" : "false");
                    
                    if (found && dbgFunc->PatchGetEx) {
                        ss << ",\"module\":\"" << escapeJsonString(patchInfo.mod) << "\","
                           << "\"oldByte\":\"0x" << std::hex << (int)patchInfo.oldbyte << "\","
                           << "\"newByte\":\"0x" << std::hex << (int)patchInfo.newbyte << "\"";
                    }
                    
                    ss << "}";
                    sendHttpResponse(clientSocket, 200, "application/json", ss.str());
                }
                else if (path == "/EnumHandles") {
                    const DBGFUNCTIONS* dbgFunc = DbgFunctions();
                    if (!dbgFunc || !dbgFunc->EnumHandles) {
                        sendHttpResponse(clientSocket, 500, "application/json",
                            "{\"error\":\"EnumHandles not available\"}");
                        continue;
                    }
                    
                    ListInfo handleList;
                    bool success = dbgFunc->EnumHandles(&handleList);
                    
                    if (!success || handleList.data == nullptr) {
                        sendHttpResponse(clientSocket, 200, "application/json",
                            "{\"count\":0,\"handles\":[]}");
                        continue;
                    }
                    
                    HANDLEINFO* handles = (HANDLEINFO*)handleList.data;
                    size_t count = handleList.count;
                    
                    std::stringstream ss;
                    ss << "{\"count\":" << std::dec << count << ",\"handles\":[";
                    
                    for (size_t i = 0; i < count; i++) {
                        if (i > 0) ss << ",";
                        
                        // Try to get the handle name and type
                        char handleName[256] = {0};
                        char typeName[256] = {0};
                        if (dbgFunc->GetHandleName) {
                            dbgFunc->GetHandleName(handles[i].Handle, handleName, sizeof(handleName), typeName, sizeof(typeName));
                        }
                        
                        ss << "{\"handle\":\"0x" << std::hex << handles[i].Handle << "\","
                           << "\"typeNumber\":" << std::dec << (int)handles[i].TypeNumber << ","
                           << "\"grantedAccess\":\"0x" << std::hex << handles[i].GrantedAccess << "\","
                           << "\"name\":\"" << escapeJsonString(handleName) << "\","
                           << "\"typeName\":\"" << escapeJsonString(typeName) << "\"}";
                    }
                    
                    ss << "]}";
                    BridgeFree(handleList.data);
                    sendHttpResponse(clientSocket, 200, "application/json", ss.str());
                }
                else {
                    // No route matched: answer explicitly instead of dropping the
                    // connection with no response.
                    sendHttpResponse(clientSocket, 404, "text/plain", "Not Found: unknown endpoint");
                }
            }
            catch (const std::exception& e) {
                sendHttpResponse(clientSocket, 500, "text/plain", std::string("Internal Server Error: ") + e.what());
            }
        }
        } while(false); }
        catch(const std::exception& e)
        {
            sendHttpResponse(clientSocket, 500, "text/plain",
                std::string("Internal Server Error: ") + e.what());
        }
        catch(...)
        {
            sendHttpResponse(clientSocket, 500, "text/plain",
                "Internal Server Error: unknown worker exception");
        }
        }
        {
            std::lock_guard<std::mutex> lock(g_httpServer.mutex);
            if(runningSlot)
                g_httpServer.dispatcher.finish(admissionTicket);
            else
                g_httpServer.dispatcher.cancel(admissionTicket);
            if(g_httpServer.liveWorkerCount > 0)
                --g_httpServer.liveWorkerCount;
        }
        g_httpServer.cv.notify_all();
        // clientSocket is closed by clientGuard's destructor at scope exit.
        }).detach();
        } catch(const std::exception& e) {
            bool closeOwnedSocket = false;
            {
                std::lock_guard<std::mutex> lock(g_httpServer.mutex);
                g_httpServer.dispatcher.cancel(admissionTicket);
                if(g_httpServer.liveWorkerCount > 0)
                    --g_httpServer.liveWorkerCount;
                closeOwnedSocket = g_httpServer.activeClientSockets.erase(clientSocket) != 0;
            }
            g_httpServer.cv.notify_all();
            if(closeOwnedSocket) {
                if(!g_httpServer.stopRequested.load(std::memory_order_acquire))
                    sendHttpResponse(clientSocket, 503, "application/json",
                        "{\"ok\":false,\"data\":null,\"error\":{\"code\":\"worker_creation_failed\",\"message\":\"Unable to create a request worker\",\"retryable\":true},\"meta\":{\"contractVersion\":1}}" );
                closesocket(clientSocket);
            }
            _plugin_logprintf("HTTP worker creation failed: %s\n", e.what());
        } catch(...) {
            bool closeOwnedSocket = false;
            {
                std::lock_guard<std::mutex> lock(g_httpServer.mutex);
                g_httpServer.dispatcher.cancel(admissionTicket);
                if(g_httpServer.liveWorkerCount > 0)
                    --g_httpServer.liveWorkerCount;
                closeOwnedSocket = g_httpServer.activeClientSockets.erase(clientSocket) != 0;
            }
            g_httpServer.cv.notify_all();
            if(closeOwnedSocket) {
                closesocket(clientSocket);
            }
            _plugin_logputs("HTTP worker creation failed: unknown exception");
        }
    }
    // Detached request threads are safe only while plugin code remains loaded.
    // stopHttpServer closes every tracked socket; wait until all admitted
    // workers (including queued ones) have observed shutdown and exited.
    {
        std::unique_lock<std::mutex> lock(g_httpServer.mutex);
        g_httpServer.cv.wait(lock, []() {
            return g_httpServer.liveWorkerCount == 0;
        });
    }
    bool closeOwnedSocket = false;
    {
        std::lock_guard<std::mutex> lock(g_httpServer.mutex);
        if (g_httpServer.listenSocket == listenSocket) {
            g_httpServer.listenSocket = INVALID_SOCKET;
            closeOwnedSocket = true;
        }
        g_httpServer.boundPort = 0;
        if (g_httpServer.stopRequested.load(std::memory_order_acquire)) {
            g_httpServer.state = HttpLifecycleState::Stopped;
        } else {
            g_httpServer.state = HttpLifecycleState::Failed;
            g_httpServer.lastError = "accept loop ended unexpectedly";
        }
        g_httpServer.threadExitCode = 0;
    }
    if (closeOwnedSocket) {
        closesocket(listenSocket);
    }

    WSACleanup();
    g_httpServer.cv.notify_all();
    return 0;
}

std::string readHttpRequest(SOCKET clientSocket, int& errorStatus,
                            std::string& errorCode, std::string& errorText) {
    errorStatus = 0;
    errorCode.clear();
    errorText.clear();
    std::string request;
    char buffer[MAX_REQUEST_SIZE];
    u_long mode = 0;
    if(ioctlsocket(clientSocket, FIONBIO, &mode) == SOCKET_ERROR)
    {
        errorStatus = 500;
        errorCode = "socket_mode_failed";
        errorText = "Could not configure the accepted socket";
        return {};
    }

    // Bound a silent/slow client with an absolute request deadline.  Updating
    // SO_RCVTIMEO from the remaining budget prevents a slowloris from resetting
    // a fresh ten-second timeout on every tiny segment.
    constexpr auto kRequestDeadline = std::chrono::milliseconds(10000);
    const auto deadline = std::chrono::steady_clock::now() + kRequestDeadline;
    auto setRemainingTimeout = [&]() -> bool {
        const auto now = std::chrono::steady_clock::now();
        if(now >= deadline) return false;
        const auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(deadline - now).count();
        const DWORD timeoutMs = static_cast<DWORD>(std::max<long long>(1, std::min<long long>(remaining, 10000)));
        const int receiveResult = setsockopt(clientSocket, SOL_SOCKET, SO_RCVTIMEO,
            (const char*)&timeoutMs, sizeof(timeoutMs));
        const int sendResult = setsockopt(clientSocket, SOL_SOCKET, SO_SNDTIMEO,
            (const char*)&timeoutMs, sizeof(timeoutMs));
        return receiveResult != SOCKET_ERROR && sendResult != SOCKET_ERROR;
    };
    if(!setRemainingTimeout())
    {
        errorStatus = 500;
        errorCode = "socket_timeout_configuration_failed";
        errorText = "Could not configure bounded socket timeouts";
        return {};
    }
    const size_t kMaxRequestBytes = mcphttp::kDefaultMaxRequestBytes;
    const size_t kMaxHeaderBytes = mcphttp::kDefaultMaxHeaderBytes;

    // 1) Read until the full header block ("\r\n\r\n") has arrived. A single
    //    recv could return just part of the request across TCP segments.
    size_t headerEnd = std::string::npos;
    while (headerEnd == std::string::npos) {
        if(!setRemainingTimeout()) {
            errorStatus = 408;
            errorCode = "request_deadline_exceeded";
            errorText = "HTTP request deadline exceeded while reading headers";
            return {};
        }
        int n = recv(clientSocket, buffer, sizeof(buffer), 0);
        if (n == 0) {
            if (!request.empty()) {
                errorStatus = 400;
                errorCode = "headers_incomplete";
                errorText = "connection ended before the complete HTTP headers arrived";
            }
            return request;
        }
        if (n == SOCKET_ERROR) {
            const int socketError = WSAGetLastError();
            if(socketError == WSAEINTR)
                continue;
            if(socketError == WSAETIMEDOUT) {
                errorStatus = 408;
                errorCode = "request_deadline_exceeded";
                errorText = "HTTP request deadline exceeded while reading headers";
                return {};
            }
            errorStatus = g_httpServer.stopRequested.load(std::memory_order_acquire)
                ? 503 : 400;
            errorCode = g_httpServer.stopRequested.load(std::memory_order_acquire)
                ? "server_stopping" : "header_receive_failed";
            errorText = g_httpServer.stopRequested.load(std::memory_order_acquire)
                ? "The bridge is stopping" : "Socket receive failed while reading headers";
            return {};
        }
        request.append(buffer, (size_t)n);
        if (request.size() > kMaxHeaderBytes) {
            errorStatus = 431;
            errorCode = "headers_too_large";
            errorText = "HTTP headers exceed 64 KiB";
            return {};
        }
        headerEnd = request.find("\r\n\r\n");
    }

    // Validate the header block before decoding query/body parameters.  This
    // is deliberately allocation-bounded and rejects ambiguous framing.
    const auto headers = mcphttp::parseHeaders(
        std::string_view(request.data(), headerEnd + 4u), kMaxHeaderBytes, kMaxRequestBytes);
    if(!headers.ok) {
        errorStatus = headers.status;
        errorCode = headers.errorCode;
        errorText = headers.errorMessage;
        return {};
    }
    // Authenticate the bounded header block before reading a potentially large
    // request body.  Untrusted local clients cannot occupy every worker with a
    // slow multi-megabyte upload and only then be rejected.
    const std::string headerRequest = request.substr(0, headers.headerBytes);
    if(!isRequestOriginAllowed(headerRequest))
    {
        errorStatus = 403;
        errorCode = "origin_forbidden";
        errorText = "Request rejected due to non-loopback Host or cross-origin Origin";
        return {};
    }
    if(!isBridgeAuthenticationValid(headerRequest))
    {
        errorStatus = 401;
        errorCode = "authentication_required";
        errorText = "A valid X-MCP-Auth-Token header is required";
        return {};
    }
    const uint64_t prefixBytes = static_cast<uint64_t>(headers.headerBytes);
    if (headers.contentLength > kMaxRequestBytes
        || prefixBytes > kMaxRequestBytes
        || headers.contentLength > kMaxRequestBytes - prefixBytes) {
        errorStatus = 413;
        errorCode = "request_too_large";
        errorText = "HTTP request body exceeds the configured limit";
        return {};
    }
    const size_t needTotal = static_cast<size_t>(prefixBytes + headers.contentLength);
    if (request.size() > needTotal) {
        errorStatus = 400;
        errorCode = "trailing_bytes";
        errorText = "unexpected bytes after the declared HTTP request body";
        return {};
    }
    while (request.size() < needTotal) {
        if(!setRemainingTimeout()) {
            errorStatus = 408;
            errorCode = "request_deadline_exceeded";
            errorText = "HTTP request deadline exceeded while reading the body";
            return {};
        }
        int n = recv(clientSocket, buffer, sizeof(buffer), 0);
        if (n == 0) {
            errorStatus = 400;
            errorCode = "body_incomplete";
            errorText = "connection ended before Content-Length bytes arrived";
            return {};
        }
        if (n == SOCKET_ERROR) {
            const int socketError = WSAGetLastError();
            if(socketError == WSAEINTR)
                continue;
            if(socketError == WSAETIMEDOUT) {
                errorStatus = 408;
                errorCode = "request_deadline_exceeded";
                errorText = "HTTP request deadline exceeded while reading the body";
                return {};
            }
            errorStatus = g_httpServer.stopRequested.load(std::memory_order_acquire)
                ? 503 : 400;
            errorCode = g_httpServer.stopRequested.load(std::memory_order_acquire)
                ? "server_stopping" : "body_receive_failed";
            errorText = g_httpServer.stopRequested.load(std::memory_order_acquire)
                ? "The bridge is stopping" : "Socket receive failed while reading the body";
            return {};
        }
        request.append(buffer, (size_t)n);
        if (request.size() > needTotal) {
            errorStatus = 400;
            errorCode = "trailing_bytes";
            errorText = "unexpected bytes after the declared HTTP request body";
            return {};
        }
    }
    if (!headers.hasContentLength && request.size() != headerEnd + 4) {
        errorStatus = 400;
        errorCode = "body_length_required";
        errorText = "request body requires Content-Length";
        return {};
    }

    return request;
}

bool parseHttpRequest(const std::string& request, std::string& method, std::string& path, std::string& query, std::string& body) {
    const auto parsed = mcphttp::parseRequest(request);
    if(!parsed.ok) return false;
    method = parsed.method;
    path = parsed.path;
    query = parsed.query;
    body = parsed.body;
    return true;
}

bool sendHttpResponse(SOCKET clientSocket, int statusCode, const std::string& contentType, const std::string& responseBody) {
    std::string statusText;
    std::string responseContentType = contentType;
    std::string normalizedBody = responseBody;
    std::string loweredContentType = contentType;
    std::transform(loweredContentType.begin(), loweredContentType.end(), loweredContentType.begin(), [](unsigned char c) { return (char)std::tolower(c); });
    // The public bridge contract is JSON for every HTTP error.  A few legacy
    // routes still pass text/plain diagnostics; normalize only non-success
    // responses that are not already an error envelope, preserving ordinary
    // successful command output byte-for-byte.
    if (statusCode >= 400 && loweredContentType.find("json") == std::string::npos) {
        const bool retryable = statusCode == 408 || statusCode == 425 || statusCode == 429
            || statusCode == 502 || statusCode == 503 || statusCode == 504;
        const std::string boundedMessage = responseBody.size() > 4096
            ? responseBody.substr(0, 4096) + "..."
            : responseBody;
        std::ostringstream envelope;
        envelope << "{\"ok\":false,\"data\":null,\"error\":{\"code\":\"HTTP_"
                 << statusCode << "\",\"message\":\""
                 << escapeJsonString(boundedMessage.c_str())
                 << "\",\"retryable\":" << (retryable ? "true" : "false")
                 << ",\"httpStatus\":" << statusCode
                 << "},\"meta\":{\"contractVersion\":1}}";
        normalizedBody = envelope.str();
        responseContentType = "application/json";
    }
    // JSON-producing legacy handlers may omit data/meta.  Do not attempt a
    // lossy parser here; Python's strict transport normalizes those payloads
    // before they cross the MCP boundary.  Native errors are nevertheless
    // guaranteed to be valid JSON and carry a stable error object.
    std::string loweredResponseContentType = responseContentType;
    std::transform(loweredResponseContentType.begin(), loweredResponseContentType.end(),
        loweredResponseContentType.begin(), [](unsigned char c) { return (char)std::tolower(c); });
    if (loweredResponseContentType.find("charset=") == std::string::npos) {
        responseContentType += "; charset=utf-8";
    }
    switch (statusCode) {
        case 200: statusText = "OK"; break;
        case 201: statusText = "Created"; break;
        case 202: statusText = "Accepted"; break;
        case 400: statusText = "Bad Request"; break;
        case 408: statusText = "Request Timeout"; break;
        case 401: statusText = "Unauthorized"; break;
        case 425: statusText = "Too Early"; break;
        case 429: statusText = "Too Many Requests"; break;
        case 405: statusText = "Method Not Allowed"; break;
        case 409: statusText = "Conflict"; break;
        case 413: statusText = "Payload Too Large"; break;
        case 422: statusText = "Unprocessable Content"; break;
        case 423: statusText = "Locked"; break;
        case 428: statusText = "Precondition Required"; break;
        case 431: statusText = "Request Header Fields Too Large"; break;
        case 403: statusText = "Forbidden"; break;
        case 404: statusText = "Not Found"; break;
        case 503: statusText = "Service Unavailable"; break;
        case 500: statusText = "Internal Server Error"; break;
        default: statusText = "Unknown";
    }
    std::stringstream response;
    response << "HTTP/1.1 " << statusCode << " " << statusText << "\r\n";
    response << "Content-Type: " << responseContentType << "\r\n";
    response << "Content-Length: " << normalizedBody.length() << "\r\n";
    response << "Connection: close\r\n";
    response << "\r\n";
    response << normalizedBody;
    std::string responseStr = response.str();
    int sendError = 0;
    const bool sent = mcpbridge::sendAllSocket(
        clientSocket, responseStr.data(), responseStr.size(), &sendError);
    if (!sent) {
        _plugin_logprintf("[MCP] sendAll failed with WSA error %d\n", sendError);
    }
    return sent;
}

std::unordered_map<std::string, std::string> parseQueryParams(const std::string& query) {
    std::unordered_map<std::string, std::string> params;
    
    size_t pos = 0;
    size_t nextPos;
    
    while (pos < query.length()) {
        nextPos = query.find('&', pos);
        if (nextPos == std::string::npos) {
            nextPos = query.length();
        }
        
        std::string pair = query.substr(pos, nextPos - pos);
        size_t equalPos = pair.find('=');
        
        if (equalPos != std::string::npos) {
            std::string key = pair.substr(0, equalPos);
            std::string value = pair.substr(equalPos + 1);
            params[urlDecode(key)] = urlDecode(value);
        }
        
        pos = nextPos + 1;
    }
    
    return params;
}

bool cbEnableHttpServer(int argc, char* argv[]) {
    bool running = false;
    {
        std::lock_guard<std::mutex> lock(g_httpServer.mutex);
        running = g_httpServer.state == HttpLifecycleState::Running
            || g_httpServer.state == HttpLifecycleState::Starting;
    }
    if (running) {
        _plugin_logputs("Stopping HTTP server...");
        if (stopHttpServer()) _plugin_logputs("HTTP server stopped");
        else _plugin_logputs("HTTP server failed to stop safely");
    } else {
        _plugin_logputs("Starting HTTP server...");
        if (startHttpServer()) {
            int boundPort = 0;
            {
                std::lock_guard<std::mutex> lock(g_httpServer.mutex);
                boundPort = g_httpServer.boundPort;
            }
            _plugin_logprintf("HTTP server started on port %d\n", boundPort);
        } else {
            _plugin_logputs("Failed to start HTTP server");
        }
    }
    return true;
}

bool cbSetHttpPort(int argc, char* argv[]) {
    if (argc < 2) {
        _plugin_logputs("Usage: httpport [port_number]");
        return false;
    }
    
    int port;
    try {
        port = std::stoi(argv[1]);
    }
    catch (const std::exception&) {
        _plugin_logputs("Invalid port number");
        return false;
    }
    
    if (port < 0 || port > 65535) {
        _plugin_logputs("Port number must be between 0 and 65535 (0 = ephemeral)");
        return false;
    }
    
    bool restart = false;
    {
        std::lock_guard<std::mutex> lock(g_httpServer.mutex);
        restart = g_httpServer.state == HttpLifecycleState::Running
            || g_httpServer.state == HttpLifecycleState::Starting;
        g_httpServer.configuredPort = port;
    }

    if (restart) {
        _plugin_logputs("Restarting HTTP server with new port...");
        stopHttpServer();
        if (startHttpServer()) {
            _plugin_logprintf("HTTP server restarted on port %d\n", port);
        } else {
            _plugin_logputs("Failed to restart HTTP server");
        }
    } else {
        _plugin_logprintf("HTTP port set to %d\n", port);
    }
    
    return true;
}

void registerCommands() {
    _plugin_registercommand(g_pluginHandle, "httpserver", cbEnableHttpServer, 
                           "Toggle HTTP server on/off");
    _plugin_registercommand(g_pluginHandle, "httpport", cbSetHttpPort, 
                           "Set HTTP server port");
}

void unregisterCommands() {
    _plugin_unregistercommand(g_pluginHandle, "httpserver");
    _plugin_unregistercommand(g_pluginHandle, "httpport");
}
