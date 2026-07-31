#pragma once

#include <cstdint>
#include <string>
#include <string_view>

namespace mcpchild
{
    enum class Policy
    {
        None,
        AttachFirst,
        AttachAll,
        BreakOnCreate,
    };

    struct PolicyParseResult
    {
        bool ok = false;
        Policy policy = Policy::None;
        std::string canonical;
        std::string errorCode;
        std::string error;
    };

    PolicyParseResult parsePolicy(std::string_view value);
    const char* policyName(Policy policy) noexcept;
    bool policyTracksChildren(Policy policy) noexcept;
    bool policyRequiresPreEntryPause(Policy policy) noexcept;

    // A broker-owned interception is intentionally a small state machine.  It
    // is independent from x64dbg SDK objects so native tests can prove that a
    // second child cannot accidentally pass an attach-first quota or that a
    // stale return event cannot consume a newer interception.
    struct ChildQuota
    {
        Policy policy = Policy::None;
        uint64_t acceptedDirectChildren = 0;
        uint64_t acceptedDescendants = 0;
    };

    struct QuotaDecision
    {
        bool accepted = false;
        std::string errorCode;
        std::string error;
    };

    QuotaDecision reserveChild(ChildQuota& quota, bool directChild);
    void rollbackChildReservation(ChildQuota& quota, bool directChild) noexcept;
}
