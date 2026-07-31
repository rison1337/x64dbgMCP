#include "exception_policy_core.hpp"

#include <algorithm>
#include <cerrno>
#include <cctype>
#include <cstdlib>
#include <iomanip>
#include <limits>
#include <sstream>
#include <unordered_set>

namespace mcpexception
{
static void trim(std::string& value)
{
    const auto first = value.find_first_not_of(" \t\r\n");
    if(first == std::string::npos) { value.clear(); return; }
    const auto last = value.find_last_not_of(" \t\r\n");
    value = value.substr(first, last - first + 1);
}

static std::string lower(std::string value)
{
    std::transform(value.begin(), value.end(), value.begin(),
        [](unsigned char ch) { return static_cast<char>(std::tolower(ch)); });
    return value;
}

const char* actionName(Action action)
{
    switch(action)
    {
    case Action::Handled: return "handled";
    case Action::NotHandled: return "not_handled";
    default: return "pause";
    }
}

const char* chanceName(Chance chance)
{
    switch(chance)
    {
    case Chance::First: return "first";
    case Chance::Second: return "second";
    default: return "any";
    }
}

static bool parseBool(const std::string& raw, bool& value)
{
    std::string text = lower(raw); trim(text);
    if(text == "true" || text == "1") { value = true; return true; }
    if(text == "false" || text == "0") { value = false; return true; }
    return false;
}

static bool parseAction(const std::string& raw, Action& action)
{
    std::string text = lower(raw); trim(text);
    if(text == "pause") action = Action::Pause;
    else if(text == "handled") action = Action::Handled;
    else if(text == "not_handled") action = Action::NotHandled;
    else return false;
    return true;
}

static bool parseChance(const std::string& raw, Chance& chance)
{
    std::string text = lower(raw); trim(text);
    if(text == "any") chance = Chance::Any;
    else if(text == "first") chance = Chance::First;
    else if(text == "second") chance = Chance::Second;
    else return false;
    return true;
}

static bool parseU64Decimal(const std::string& raw, uint64_t& result)
{
    if(raw.empty() || !std::all_of(raw.begin(), raw.end(),
        [](unsigned char ch) { return std::isdigit(ch) != 0; })) return false;
    errno = 0; char* end = nullptr;
    const auto value = std::strtoull(raw.c_str(), &end, 10);
    if(errno == ERANGE || !end || *end) return false;
    result = static_cast<uint64_t>(value);
    return true;
}

static bool parseU32(const std::string& raw, uint32_t& result)
{
    std::string text = raw; trim(text);
    if(text.empty() || text[0] == '+' || text[0] == '-') return false;
    int base = 10; const char* begin = text.c_str();
    if(text.size() > 2 && text[0] == '0' && (text[1] == 'x' || text[1] == 'X'))
    { begin += 2; base = 16; if(!*begin) return false; }
    errno = 0; char* end = nullptr;
    const auto value = std::strtoull(begin, &end, base);
    if(errno == ERANGE || end == begin || !end || *end
        || value > std::numeric_limits<uint32_t>::max()) return false;
    result = static_cast<uint32_t>(value);
    return true;
}

static bool parsePriority(const std::string& raw, int& result)
{
    std::string text = raw; trim(text);
    if(text.empty()) return false;
    errno = 0; char* end = nullptr;
    const auto value = std::strtoll(text.c_str(), &end, 10);
    if(errno == ERANGE || end == text.c_str() || !end || *end
        || value < kMinPriority || value > kMaxPriority) return false;
    result = static_cast<int>(value);
    return true;
}

static unsigned int popcount(uint32_t value)
{
    unsigned int count = 0;
    while(value) { value &= value - 1; ++count; }
    return count;
}

static std::string canonical(uint32_t value)
{
    std::stringstream ss;
    ss << "0x" << std::hex << std::setfill('0') << std::setw(8) << value;
    return ss.str();
}

static bool parseSelectors(const std::string& raw, std::vector<Selector>& out,
                           std::string& error)
{
    size_t start = 0;
    while(start <= raw.size())
    {
        const size_t comma = raw.find(',', start);
        std::string token = raw.substr(start,
            comma == std::string::npos ? std::string::npos : comma - start);
        trim(token);
        if(token.empty()) { error = "selector list contains an empty item"; return false; }
        Selector selector;
        if(token == "*") selector.canonical = "*";
        else
        {
            const size_t slash = token.find('/');
            if(slash == std::string::npos)
            {
                if(!parseU32(token, selector.value))
                { error = "invalid exact exception code: " + token; return false; }
                selector.kind = SelectorKind::Exact;
                selector.mask = std::numeric_limits<uint32_t>::max();
                selector.maskBits = 32;
                selector.canonical = canonical(selector.value);
            }
            else
            {
                if(token.find('/', slash + 1) != std::string::npos
                    || !parseU32(token.substr(0, slash), selector.value)
                    || !parseU32(token.substr(slash + 1), selector.mask)
                    || selector.mask == 0)
                { error = "invalid masked exception selector: " + token; return false; }
                selector.kind = SelectorKind::Masked;
                selector.maskBits = popcount(selector.mask);
                selector.value &= selector.mask;
                selector.canonical = canonical(selector.value) + "/" + canonical(selector.mask);
            }
        }
        out.push_back(std::move(selector));
        if(out.size() > kMaxSelectorsPerRule)
        { error = "a rule may contain at most 32 selectors"; return false; }
        if(comma == std::string::npos) break;
        start = comma + 1;
    }
    return !out.empty();
}

static bool validId(const std::string& id)
{
    return !id.empty() && id.size() <= 64
        && std::all_of(id.begin(), id.end(), [](unsigned char ch) {
            return std::isalnum(ch) || ch == '_' || ch == '-' || ch == '.' || ch == ':';
        });
}

bool parsePolicyUpdate(const std::unordered_map<std::string, std::string>& params,
                       ParsedUpdate& update, std::string& error)
{
    auto read = [&](const std::string& key) -> const std::string* {
        const auto it = params.find(key); return it == params.end() ? nullptr : &it->second;
    };
    if(const auto value = read("replace"); value && !parseBool(*value, update.replace))
    { error = "replace must be boolean"; return false; }
    if(const auto value = read("enabled"))
    { update.hasEnabled = true; if(!parseBool(*value, update.enabled)) { error = "enabled must be boolean"; return false; } }
    if(const auto value = read("firstChanceDefault"))
    { update.hasFirstDefault = true; if(!parseAction(*value, update.firstDefault)) { error = "invalid firstChanceDefault"; return false; } }
    if(const auto value = read("secondChanceDefault"))
    { update.hasSecondDefault = true; if(!parseAction(*value, update.secondDefault)) { error = "invalid secondChanceDefault"; return false; } }
    uint64_t count = 0;
    const auto countText = read("ruleCount");
    if(!countText || !parseU64Decimal(*countText, count) || count > kMaxRules)
    { error = "ruleCount must be 0 through 64"; return false; }
    std::unordered_set<std::string> ids;
    size_t selectors = 0;
    for(uint64_t i = 0; i < count; ++i)
    {
        const std::string prefix = "rule" + std::to_string(i);
        const auto id = read(prefix + "Id"); const auto codes = read(prefix + "Codes");
        const auto chance = read(prefix + "Chance"); const auto action = read(prefix + "Action");
        if(!id || !codes || !chance || !action)
        { error = prefix + " requires Id/Codes/Chance/Action"; return false; }
        Rule rule; rule.ruleId = *id; trim(rule.ruleId);
        if(!validId(rule.ruleId) || !ids.insert(lower(rule.ruleId)).second)
        { error = "invalid or duplicate ruleId: " + rule.ruleId; return false; }
        if(!parseSelectors(*codes, rule.selectors, error)
            || !parseChance(*chance, rule.chance) || !parseAction(*action, rule.action))
        { if(error.empty()) error = "invalid chance/action"; return false; }
        selectors += rule.selectors.size();
        if(selectors > kMaxSelectorsTotal) { error = "too many selectors"; return false; }
        if(const auto value = read(prefix + "Priority"); value && !parsePriority(*value, rule.priority))
        { error = "invalid priority"; return false; }
        if(const auto value = read(prefix + "Enabled"); value && !parseBool(*value, rule.enabled))
        { error = "invalid rule enabled"; return false; }
        update.rules.push_back(std::move(rule));
    }
    return true;
}

bool mergePolicy(const Policy& current, ParsedUpdate update, Policy& merged, std::string& error)
{
    Policy candidate = update.replace ? Policy{} : current;
    if(update.hasEnabled) candidate.enabled = update.enabled;
    if(update.hasFirstDefault) candidate.firstChanceDefault = update.firstDefault;
    if(update.hasSecondDefault) candidate.secondChanceDefault = update.secondDefault;
    std::unordered_set<std::string> ids; size_t selectorCount = 0;
    if(candidate.rules.size() > kMaxRules) { error = "too many existing rules"; return false; }
    for(const auto& rule : candidate.rules)
    {
        if(!validId(rule.ruleId) || !ids.insert(lower(rule.ruleId)).second)
        { error = "duplicate existing ruleId: " + rule.ruleId; return false; }
        if(rule.selectors.empty() || rule.selectors.size() > kMaxSelectorsPerRule)
        { error = "invalid existing selector count"; return false; }
        selectorCount += rule.selectors.size();
    }
    if(selectorCount > kMaxSelectorsTotal)
    { error = "existing policy exceeds selector limit"; return false; }
    uint64_t order = update.replace ? 1 : candidate.nextInsertionOrder;
    for(auto& rule : update.rules)
    {
        if(!ids.insert(lower(rule.ruleId)).second)
        { error = "duplicate ruleId in merged policy: " + rule.ruleId; return false; }
        selectorCount += rule.selectors.size();
        if(candidate.rules.size() >= kMaxRules || selectorCount > kMaxSelectorsTotal)
        { error = "merged policy exceeds limits"; return false; }
        rule.insertionOrder = order++;
        candidate.rules.push_back(std::move(rule));
    }
    candidate.nextInsertionOrder = order;
    candidate.version = current.version + 1;
    merged = std::move(candidate);
    return true;
}

static bool matches(const Selector& selector, uint32_t code)
{
    if(selector.kind == SelectorKind::Exact) return code == selector.value;
    if(selector.kind == SelectorKind::Masked) return (code & selector.mask) == (selector.value & selector.mask);
    return true;
}

Decision selectPolicy(const Policy& policy, uint32_t code, bool firstChance)
{
    Decision result;
    if(!policy.enabled) { result.source = "policy_disabled"; return result; }
    const Rule* bestRule = nullptr; const Selector* bestSelector = nullptr;
    int bestKind = -1, bestBits = -1;
    for(const auto& rule : policy.rules)
    {
        if(!rule.enabled || (rule.chance == Chance::First && !firstChance)
            || (rule.chance == Chance::Second && firstChance)) continue;
        for(const auto& selector : rule.selectors)
        {
            if(!matches(selector, code)) continue;
            const int kind = selector.kind == SelectorKind::Exact ? 2 : selector.kind == SelectorKind::Masked ? 1 : 0;
            const int bits = selector.kind == SelectorKind::Masked ? static_cast<int>(selector.maskBits) : 0;
            const bool better = !bestRule || kind > bestKind || (kind == bestKind && bits > bestBits)
                || (kind == bestKind && bits == bestBits && rule.priority > bestRule->priority)
                || (kind == bestKind && bits == bestBits && rule.priority == bestRule->priority
                    && rule.insertionOrder < bestRule->insertionOrder)
                || (kind == bestKind && bits == bestBits && rule.priority == bestRule->priority
                    && rule.insertionOrder == bestRule->insertionOrder && rule.ruleId < bestRule->ruleId);
            if(better) { bestRule = &rule; bestSelector = &selector; bestKind = kind; bestBits = bits; }
        }
    }
    if(bestRule)
    {
        result.action = bestRule->action; result.source = "rule";
        result.ruleId = bestRule->ruleId; result.matchedSelector = bestSelector->canonical;
    }
    else
    {
        result.action = firstChance ? policy.firstChanceDefault : policy.secondChanceDefault;
        result.source = firstChance ? "first_chance_default" : "second_chance_default";
    }
    return result;
}

HistoryPage computeHistoryPage(const std::vector<uint64_t>& retainedSequences,
                               uint64_t nextSequence, uint64_t dropped,
                               uint64_t afterSequence, size_t limit)
{
    HistoryPage page;
    page.oldestAvailableSeq = retainedSequences.empty()
        ? nextSequence : retainedSequences.front();
    page.latestSeq = nextSequence > 1 ? nextSequence - 1 : 0;
    page.nextAfterSeq = afterSequence;
    page.cursorTruncated = dropped > 0
        && afterSequence < page.oldestAvailableSeq
        && page.oldestAvailableSeq - afterSequence > 1;
    while(page.firstIndex < retainedSequences.size()
          && retainedSequences[page.firstIndex] <= afterSequence)
    {
        ++page.firstIndex;
    }
    page.available = retainedSequences.size() - page.firstIndex;
    page.returned = std::min(limit, page.available);
    page.hasMore = page.available > page.returned;
    if(page.returned > 0)
    {
        page.nextAfterSeq = retainedSequences[page.firstIndex + page.returned - 1];
    }
    return page;
}

void initializeAutomaticContinuation(Continuation& state, Action action)
{
    state.autoContinue = true; state.claimed = true;
    // erun/serun are sticky modes and bypass later first-chance callbacks.
    // Set only this event's disposition; the bridge queues ordinary run next.
    state.command = action == Action::Handled ? "con" : "con 1";
    state.resumeRequested = true;
    state.status = "queued"; state.disposition = actionName(action);
    state.requestedDisposition = actionName(action); state.appliedDisposition = "pending";
    state.outcome = "queued"; state.source = "policy";
}

bool claimManualContinuation(Continuation& state, const std::string& disposition,
                             const std::string& command)
{
    if(state.claimed) return false;
    state.autoContinue = false; state.claimed = true; state.commandSubmitted = false;
    state.dispositionSubmitted = false; state.resumeRequested = false;
    state.resumeSubmitted = false;
    state.command = command; state.status = "manual_claimed"; state.disposition = disposition;
    state.requestedDisposition = disposition; state.appliedDisposition = "pending";
    state.outcome = "claimed"; state.source = "manual"; return true;
}

void markAutomaticSubmission(Continuation& state, bool dispositionSubmitted,
                             bool resumeSubmitted)
{
    state.commandSubmitted = dispositionSubmitted;
    state.dispositionSubmitted = dispositionSubmitted;
    state.resumeRequested = true;
    state.resumeSubmitted = resumeSubmitted;
    if(state.outcome == "applied") return;
    if(dispositionSubmitted && resumeSubmitted)
    {
        state.status = "submitted"; state.outcome = "submitted";
    }
    else if(!dispositionSubmitted)
    {
        state.status = "submission_failed"; state.outcome = "submission_failed";
        state.claimed = false; state.disposition = "default";
        state.appliedDisposition = "none";
    }
    else
    {
        // The disposition is already queued. Preserve exactly-once ownership;
        // a later ordinary run can complete this pending resume safely.
        state.status = "resume_submission_failed";
        state.outcome = "applied_resume_failed";
    }
}

void markAutomaticResume(Continuation& state)
{
    if(!state.autoContinue || !state.claimed) return;
    state.commandSubmitted = true; state.dispositionSubmitted = true;
    state.resumeRequested = true; state.resumeSubmitted = true;
    state.appliedDisposition = state.requestedDisposition; state.disposition = state.requestedDisposition;
    state.outcome = "applied"; state.status = "auto_resumed";
}

void markAbandoned(Continuation& state)
{
    if(state.appliedDisposition != "pending") return;
    state.appliedDisposition = "none"; state.outcome = "abandoned"; state.status = "abandoned_before_resume";
}

void markManualDisposition(Continuation& state, bool applied)
{
    state.commandSubmitted = applied; state.dispositionSubmitted = applied;
    if(applied)
    { state.status = "disposition_applied"; state.appliedDisposition = state.requestedDisposition; state.outcome = "applied"; }
    else
    { state.claimed = false; state.status = "manual_disposition_failed"; state.disposition = "default";
      state.appliedDisposition = "none"; state.outcome = "disposition_failed"; }
}

void markManualResume(Continuation& state, bool requested, bool submitted)
{
    state.resumeRequested = requested;
    state.resumeSubmitted = requested && submitted;
    state.status = !requested ? "disposition_applied" : submitted ? "resume_submitted" : "resume_submission_failed";
    if(requested && !submitted) state.outcome = "applied_resume_failed";
}
}
