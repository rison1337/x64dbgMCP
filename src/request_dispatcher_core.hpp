#pragma once

#include <cstddef>
#include <cstdint>
#include <deque>
#include <string_view>
#include <unordered_set>

namespace mcpdispatcher
{

// This state machine is intentionally lock-free internally: the HTTP server
// owns one mutex/CV around every call.  Keeping admission policy separate from
// sockets makes FIFO, capacity, cancellation, and accounting deterministic and
// directly testable in both native builds.
enum class StartDecision
{
    Started,
    Queued,
    UnknownTicket,
};

struct Snapshot
{
    size_t maxRunning = 0;
    size_t maxAdmitted = 0;
    size_t admitted = 0;
    size_t running = 0;
    size_t queued = 0;
};

class FairAdmissionQueue
{
public:
    FairAdmissionQueue(size_t maxRunning, size_t maxAdmitted);

    bool tryAdmit(uint64_t& ticket);
    bool canStart(uint64_t ticket) const;
    StartDecision tryStart(uint64_t ticket);
    bool cancel(uint64_t ticket);
    bool finish(uint64_t ticket);
    bool contains(uint64_t ticket) const;
    Snapshot snapshot() const;
    void reset();

private:
    size_t maxRunning_;
    size_t maxAdmitted_;
    uint64_t nextTicket_ = 1;
    std::deque<uint64_t> queued_;
    std::unordered_set<uint64_t> running_;
};

// Only routes implemented entirely through bridge-owned mutex-protected state,
// OS handles, or x64dbg's asynchronous command queue may bypass the debugger
// route mutex.  Unknown/new routes fail closed to serialized execution.
bool routeMayRunConcurrently(std::string_view path) noexcept;

} // namespace mcpdispatcher
