#include "child_broker_core.hpp"

#include <algorithm>
#include <cctype>

namespace mcpchild
{
    PolicyParseResult parsePolicy(std::string_view value)
    {
        PolicyParseResult result;
        std::string normalized(value);
        std::transform(normalized.begin(), normalized.end(), normalized.begin(),
            [](unsigned char ch) { return static_cast<char>(std::tolower(ch)); });
        if(normalized.empty() || normalized == "none")
        {
            result.ok = true;
            result.policy = Policy::None;
            result.canonical = "none";
            return result;
        }
        if(normalized == "attach-first" || normalized == "attach_first")
        {
            result.ok = true;
            result.policy = Policy::AttachFirst;
            result.canonical = "attach-first";
            return result;
        }
        if(normalized == "attach-all" || normalized == "attach_all")
        {
            result.ok = true;
            result.policy = Policy::AttachAll;
            result.canonical = "attach-all";
            return result;
        }
        if(normalized == "break-on-create" || normalized == "break_on_create")
        {
            result.ok = true;
            result.policy = Policy::BreakOnCreate;
            result.canonical = "break-on-create";
            return result;
        }
        result.errorCode = "invalid_child_policy";
        result.error = "child policy must be none, attach-first, attach-all, or break-on-create";
        return result;
    }

    const char* policyName(Policy policy) noexcept
    {
        switch(policy)
        {
        case Policy::None: return "none";
        case Policy::AttachFirst: return "attach-first";
        case Policy::AttachAll: return "attach-all";
        case Policy::BreakOnCreate: return "break-on-create";
        default: return "unknown";
        }
    }

    bool policyTracksChildren(Policy policy) noexcept
    {
        return policy != Policy::None;
    }

    bool policyRequiresPreEntryPause(Policy policy) noexcept
    {
        return policy == Policy::BreakOnCreate;
    }

    QuotaDecision reserveChild(ChildQuota& quota, bool directChild)
    {
        if(quota.policy == Policy::None)
            return {false, "child_policy_disabled", "child broker is disabled"};
        if(quota.policy == Policy::AttachFirst && !directChild)
            return {false, "child_policy_direct_only", "attach-first only accepts a direct child"};
        if(quota.policy == Policy::AttachFirst && quota.acceptedDirectChildren != 0)
            return {false, "child_policy_quota_exhausted", "attach-first already accepted its direct child"};
        ++quota.acceptedDescendants;
        if(directChild)
            ++quota.acceptedDirectChildren;
        return {true, {}, {}};
    }

    void rollbackChildReservation(ChildQuota& quota, bool directChild) noexcept
    {
        if(quota.acceptedDescendants != 0)
            --quota.acceptedDescendants;
        if(directChild && quota.acceptedDirectChildren != 0)
            --quota.acceptedDirectChildren;
    }
}
