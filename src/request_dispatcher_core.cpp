#include "request_dispatcher_core.hpp"

#include <algorithm>
#include <array>
#include <limits>

namespace mcpdispatcher
{

FairAdmissionQueue::FairAdmissionQueue(size_t maxRunning, size_t maxAdmitted)
    : maxRunning_(std::max<size_t>(1, maxRunning)),
      maxAdmitted_(std::max(maxRunning_, maxAdmitted))
{
}

bool FairAdmissionQueue::tryAdmit(uint64_t& ticket)
{
    if(queued_.size() + running_.size() >= maxAdmitted_)
        return false;

    // Ticket zero is reserved for "not admitted".  Wrap is practically
    // unreachable, but skipping live values keeps the contract total.
    for(size_t attempts = 0; attempts <= maxAdmitted_; ++attempts)
    {
        const uint64_t candidate = nextTicket_++;
        if(nextTicket_ == 0)
            nextTicket_ = 1;
        if(candidate != 0 && !contains(candidate))
        {
            queued_.push_back(candidate);
            ticket = candidate;
            return true;
        }
    }
    return false;
}

bool FairAdmissionQueue::canStart(uint64_t ticket) const
{
    return running_.size() < maxRunning_
        && !queued_.empty()
        && queued_.front() == ticket;
}

StartDecision FairAdmissionQueue::tryStart(uint64_t ticket)
{
    if(canStart(ticket))
    {
        queued_.pop_front();
        running_.insert(ticket);
        return StartDecision::Started;
    }
    if(std::find(queued_.begin(), queued_.end(), ticket) != queued_.end())
        return StartDecision::Queued;
    return StartDecision::UnknownTicket;
}

bool FairAdmissionQueue::cancel(uint64_t ticket)
{
    const auto queued = std::find(queued_.begin(), queued_.end(), ticket);
    if(queued != queued_.end())
    {
        queued_.erase(queued);
        return true;
    }
    return running_.erase(ticket) != 0;
}

bool FairAdmissionQueue::finish(uint64_t ticket)
{
    return running_.erase(ticket) != 0;
}

bool FairAdmissionQueue::contains(uint64_t ticket) const
{
    return running_.find(ticket) != running_.end()
        || std::find(queued_.begin(), queued_.end(), ticket) != queued_.end();
}

Snapshot FairAdmissionQueue::snapshot() const
{
    Snapshot result;
    result.maxRunning = maxRunning_;
    result.maxAdmitted = maxAdmitted_;
    result.running = running_.size();
    result.queued = queued_.size();
    result.admitted = result.running + result.queued;
    return result;
}

void FairAdmissionQueue::reset()
{
    queued_.clear();
    running_.clear();
    nextTicket_ = 1;
}

bool routeMayRunConcurrently(std::string_view path) noexcept
{
    // Pause/Stop are the only entries below that call an x64dbg API.  Both use
    // DbgCmdExec, whose contract is an asynchronous, joined debugger command
    // submission; every direct/read/write Script API route remains serialized.
    static constexpr std::array<std::string_view, 24> concurrentRoutes = {{
        "/Bridge/Hello",
        "/Debug/ChildBroker/State",
        "/Debug/SessionState",
        "/Debug/ExceptionPolicy/Get",
        "/Debug/ExceptionPolicy/Set",
        "/Debug/ExceptionPolicy/Clear",
        "/Debug/ExceptionHistory/Get",
        "/Debug/ExceptionHistory/Clear",
        "/Debug/WaitForPause",
        "/Debug/WaitForBreakpoint",
        "/Debug/WaitForBreakpointDetailed",
        "/Debug/WaitForExit",
        "/Debug/Launch/State",
        "/Debug/Launch/Stream/Read",
        "/Debug/Launch/Stdin/Write",
        "/Debug/Launch/Stdin/Close",
        "/Debug/Launch/Resources/Close",
        "/Debug/Pause",
        "/Debug/Stop",
        "/Trace/Start",
        "/Trace/Status",
        "/Trace/Wait",
        "/Trace/Stop",
        "/Trace/Clear",
    }};
    return std::find(concurrentRoutes.begin(), concurrentRoutes.end(), path)
        != concurrentRoutes.end();
}

} // namespace mcpdispatcher
