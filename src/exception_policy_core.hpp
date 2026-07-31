#pragma once

#include <cstdint>
#include <cstddef>
#include <deque>
#include <string>
#include <unordered_map>
#include <vector>

namespace mcpexception
{
constexpr size_t kMaxRules = 64;
constexpr size_t kMaxSelectorsPerRule = 32;
constexpr size_t kMaxSelectorsTotal = 512;
constexpr int kMinPriority = -100000;
constexpr int kMaxPriority = 100000;
constexpr size_t kHistoryRetentionLimit = 512;

template <typename T>
size_t trimBoundedHistory(std::deque<T>& records,
                          size_t limit = kHistoryRetentionLimit)
{
    size_t removed = 0;
    while(records.size() > limit)
    {
        records.pop_front();
        ++removed;
    }
    return removed;
}

struct HistoryPage
{
    size_t firstIndex = 0;
    size_t available = 0;
    size_t returned = 0;
    uint64_t oldestAvailableSeq = 1;
    uint64_t latestSeq = 0;
    uint64_t nextAfterSeq = 0;
    bool hasMore = false;
    bool cursorTruncated = false;
};

enum class Chance { Any, First, Second };
enum class Action { Pause, Handled, NotHandled };
enum class SelectorKind { Wildcard, Masked, Exact };

struct Selector
{
    SelectorKind kind = SelectorKind::Wildcard;
    uint32_t value = 0;
    uint32_t mask = 0;
    unsigned int maskBits = 0;
    std::string canonical = "*";
};

struct Rule
{
    std::string ruleId;
    std::vector<Selector> selectors;
    Chance chance = Chance::Any;
    Action action = Action::Pause;
    int priority = 0;
    bool enabled = true;
    uint64_t insertionOrder = 0;
};

struct Policy
{
    bool enabled = false;
    Action firstChanceDefault = Action::Pause;
    Action secondChanceDefault = Action::Pause;
    uint64_t version = 0;
    uint64_t nextInsertionOrder = 1;
    std::vector<Rule> rules;
};

struct ParsedUpdate
{
    bool replace = true;
    bool hasEnabled = false;
    bool enabled = true;
    bool hasFirstDefault = false;
    Action firstDefault = Action::Pause;
    bool hasSecondDefault = false;
    Action secondDefault = Action::Pause;
    std::vector<Rule> rules;
};

struct Decision
{
    Action action = Action::Pause;
    std::string source = "default";
    std::string ruleId;
    std::string matchedSelector;
};

struct Continuation
{
    bool autoContinue = false;
    bool claimed = false;
    bool commandSubmitted = false;
    bool dispositionSubmitted = false;
    bool resumeRequested = false;
    bool resumeSubmitted = false;
    std::string command;
    std::string status = "paused";
    std::string disposition = "default";
    std::string requestedDisposition = "pause";
    std::string appliedDisposition = "none";
    std::string outcome = "paused";
    std::string source = "none";
};

const char* actionName(Action action);
const char* chanceName(Chance chance);
bool parsePolicyUpdate(const std::unordered_map<std::string, std::string>& params,
                       ParsedUpdate& update, std::string& error);
bool mergePolicy(const Policy& current, ParsedUpdate update,
                 Policy& merged, std::string& error);
Decision selectPolicy(const Policy& policy, uint32_t code, bool firstChance);
HistoryPage computeHistoryPage(const std::vector<uint64_t>& retainedSequences,
                               uint64_t nextSequence, uint64_t dropped,
                               uint64_t afterSequence, size_t limit);

void initializeAutomaticContinuation(Continuation& state, Action action);
bool claimManualContinuation(Continuation& state, const std::string& disposition,
                             const std::string& command);
void markAutomaticSubmission(Continuation& state, bool dispositionSubmitted,
                             bool resumeSubmitted);
void markAutomaticResume(Continuation& state);
void markAbandoned(Continuation& state);
void markManualDisposition(Continuation& state, bool applied);
void markManualResume(Continuation& state, bool resumeRequested, bool submitted);
}
