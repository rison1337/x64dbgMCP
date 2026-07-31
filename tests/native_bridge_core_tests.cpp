#include "bridge_core.hpp"
#include "exception_policy_core.hpp"
#include "file_identity.hpp"
#include "launch_core.hpp"
#include "child_broker_core.hpp"
#include "http_parser_core.hpp"
#include "request_dispatcher_core.hpp"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <iostream>
#include <limits>
#include <string>
#include <thread>
#include <type_traits>
#include <vector>

#ifdef _WIN32
#include <shellapi.h>
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

static void testHexParser()
{
    auto parsed = mcpbridge::parseHexExact("00a5FF", 3);
    CHECK(parsed.ok);
    CHECK((parsed.bytes == std::vector<unsigned char>{0x00, 0xA5, 0xFF}));

    for(const std::string invalid : {"", "0", "000", "0g", "001x", " 00", "00 "})
    {
        parsed = mcpbridge::parseHexExact(invalid, 64);
        CHECK(!parsed.ok);
        CHECK(parsed.bytes.empty());
        CHECK(!parsed.error.empty());
    }

    parsed = mcpbridge::parseHexExact("0001", 1);
    CHECK(!parsed.ok);
    CHECK(parsed.bytes.empty());
}

static void testDecimalParser()
{
    uint64_t value = 0;
    CHECK(mcpbridge::parseUnsignedDecimalExact("0", value) && value == 0);
    CHECK(mcpbridge::parseUnsignedDecimalExact("18446744073709551615", value));
    CHECK(value == std::numeric_limits<uint64_t>::max());
    CHECK(!mcpbridge::parseUnsignedDecimalExact("", value));
    CHECK(!mcpbridge::parseUnsignedDecimalExact("-1", value));
    CHECK(!mcpbridge::parseUnsignedDecimalExact("1x", value));
    CHECK(!mcpbridge::parseUnsignedDecimalExact("18446744073709551616", value));
}

static void testHttpParserContract()
{
    using namespace mcphttp;
    const std::string valid =
        "POST /Memory/Write?x=1 HTTP/1.1\r\n"
        "Host: 127.0.0.1:8888\r\n"
        "Content-Type: application/x-www-form-urlencoded\r\n"
        "Content-Length: 7\r\n\r\n"
        "a=1&b=2";
    const auto parsed = parseRequest(valid);
    CHECK(parsed.ok);
    CHECK(parsed.status == 200);
    CHECK(parsed.method == "POST");
    CHECK(parsed.path == "/Memory/Write");
    CHECK(parsed.query == "x=1");
    CHECK(parsed.body == "a=1&b=2");
    CHECK(parsed.headers.hasContentLength && parsed.headers.contentLength == 7);

    const auto noBody = parseRequest("GET /Bridge/Hello HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n");
    CHECK(noBody.ok && noBody.body.empty() && !noBody.headers.hasContentLength);

    const std::vector<std::string> invalid = {
        "GET / HTTP/1.1\r\nHost: x\r\nContent-Length: 0\r\nContent-Length: 0\r\n\r\n",
        "POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n",
        "POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 1x\r\n\r\na",
        "POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 4\r\n\r\na",
        "POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 1\r\naZ",
        "GET / HTTP/1.1\r\nBad Header: x\r\n\r\n",
        "GET http://evil HTTP/1.1\r\nHost: x\r\n\r\n",
        "get / HTTP/1.1\r\nHost: x\r\n\r\n",
        "GET / HTTP/1.2\r\nHost: x\r\n\r\n",
    };
    for(const auto& request : invalid)
    {
        const auto rejected = parseRequest(request);
        CHECK(!rejected.ok);
        CHECK(rejected.status >= 400 && rejected.status <= 499);
        CHECK(!rejected.errorCode.empty());
        CHECK(!rejected.errorMessage.empty());
    }

    const std::string hugeHeader = "GET / HTTP/1.1\r\nX-Test: "
        + std::string(128, 'a') + "\r\n\r\n";
    const auto headerLimit = parseRequest(hugeHeader, 64, 1024);
    CHECK(!headerLimit.ok && headerLimit.status == 431);
    const std::string hugeBody = "POST / HTTP/1.1\r\nContent-Length: 100\r\n\r\n";
    const auto bodyLimit = parseRequest(hugeBody, 1024, 32);
    CHECK(!bodyLimit.ok && bodyLimit.status == 413);

    // Property-style corpus: arbitrary bytes must never throw or produce an
    // unbounded success payload.  This is intentionally deterministic so CI
    // and release reports are reproducible.
    std::uint32_t state = 0xC0DEC0DEu;
    for(int iteration = 0; iteration < 10000; ++iteration)
    {
        std::string fuzz;
        const std::size_t length = static_cast<std::size_t>((state = state * 1664525u + 1013904223u) % 512u);
        fuzz.resize(length);
        for(char& ch : fuzz)
        {
            state = state * 1664525u + 1013904223u;
            ch = static_cast<char>(state >> 24);
        }
        const auto result = parseRequest(fuzz, 1024, 4096);
        CHECK(result.errorMessage.size() <= 512);
        CHECK(result.errorCode.size() <= 128);
        if(result.ok)
        {
            CHECK(result.body.size() <= 4096);
            CHECK(result.path.size() <= 1024);
        }
        else
        {
            CHECK(result.status >= 400 && result.status <= 599);
        }
    }
}

static void testChildBrokerCore()
{
    using namespace mcpchild;
    for(const auto& value : {"none", "", "ATTACH-FIRST", "attach_all", "break-on-create"})
    {
        const auto parsed = parsePolicy(value);
        CHECK(parsed.ok);
        CHECK(!parsed.canonical.empty());
    }
    const auto invalid = parsePolicy("watch-polling");
    CHECK(!invalid.ok && invalid.errorCode == "invalid_child_policy");

    ChildQuota first{Policy::AttachFirst};
    CHECK(reserveChild(first, true).accepted);
    CHECK(!reserveChild(first, true).accepted);
    CHECK(!reserveChild(first, false).accepted);
    rollbackChildReservation(first, true);
    CHECK(reserveChild(first, true).accepted);

    ChildQuota all{Policy::AttachAll};
    CHECK(reserveChild(all, true).accepted);
    CHECK(reserveChild(all, false).accepted);
    CHECK(all.acceptedDescendants == 2);
    rollbackChildReservation(all, false);
    CHECK(all.acceptedDescendants == 1);

    ChildQuota disabled{Policy::None};
    const auto disabledDecision = reserveChild(disabled, true);
    CHECK(!disabledDecision.accepted && disabledDecision.errorCode == "child_policy_disabled");
    CHECK(std::string(policyName(Policy::BreakOnCreate)) == "break-on-create");
    CHECK(policyRequiresPreEntryPause(Policy::BreakOnCreate));
    CHECK(!policyRequiresPreEntryPause(Policy::AttachAll));
}

static void testTcpPortParser()
{
    uint16_t port = 1234;
    CHECK(mcpbridge::parseTcpPortExact("1", port) && port == 1);
    CHECK(mcpbridge::parseTcpPortExact("80", port) && port == 80);
    CHECK(mcpbridge::parseTcpPortExact("00888", port) && port == 888);
    CHECK(mcpbridge::parseTcpPortExact("65535", port) && port == 65535);

    const std::vector<std::string> invalid = {
        "", "0", "00000", "65536", "99999999999999999999999999999999",
        "+1", "-1", " 1", "1 ", "1\t", "1\r\n", "0x22b8", "1.0",
        "1_000", "12x", std::string("12\0" "34", 5),
        std::string("\xff", 1),
    };
    for(const auto& text : invalid)
    {
        port = 1234;
        CHECK(!mcpbridge::parseTcpPortExact(text, port));
        CHECK(port == 0);
    }
}

static void testListenPortParser()
{
    int port = 1234;
    CHECK(mcpbridge::parseListenPortExact("0", port) && port == 0);
    CHECK(mcpbridge::parseListenPortExact("00000", port) && port == 0);
    CHECK(mcpbridge::parseListenPortExact("1", port) && port == 1);
    CHECK(mcpbridge::parseListenPortExact("00888", port) && port == 888);
    CHECK(mcpbridge::parseListenPortExact("65535", port) && port == 65535);

    const std::vector<std::string> invalid = {
        "", "65536", "99999999999999999999999999999999",
        "+0", "-0", " 0", "0 ", "0\t", "0\r\n", "0x0", "0.0",
        "1_000", "12x", std::string("12\0" "34", 5),
        std::string("\xff", 1),
    };
    for(const auto& text : invalid)
    {
        port = 1234;
        CHECK(!mcpbridge::parseListenPortExact(text, port));
        CHECK(port == -1);
    }
}

static void testConstantTimeEqual()
{
    const std::string token(64, 'a');
    CHECK(mcpbridge::constantTimeEqual(token, token, 64));
    CHECK(!mcpbridge::constantTimeEqual(token, std::string(64, 'b'), 64));
    CHECK(!mcpbridge::constantTimeEqual(token, token.substr(1), 64));
    CHECK(!mcpbridge::constantTimeEqual("", "", 0));
    CHECK(mcpbridge::constantTimeEqual("abc", "abc"));
}

static void testSendAll()
{
    const std::string payload(10003, 'A');
    std::string sink;
    int calls = 0;
    int error = 0;
    const bool ok = mcpbridge::sendAllUsing(
        payload.data(),
        payload.size(),
        [&](const char* data, int length, int& sendError) {
            ++calls;
            const int take = std::min(length, 37);
            sink.append(data, static_cast<size_t>(take));
            sendError = 0;
            return take;
        },
        &error);
    CHECK(ok);
    CHECK(error == 0);
    CHECK(calls > 1);
    CHECK(sink == payload);

    calls = 0;
    CHECK(mcpbridge::sendAllUsing(
        payload.data(), payload.size(),
        [&](const char*, int, int& sendError) {
            ++calls;
            if(calls == 1)
            {
                sendError = WSAEINTR;
                return SOCKET_ERROR;
            }
            sendError = WSAECONNRESET;
            return SOCKET_ERROR;
        },
        &error) == false);
    CHECK(calls == 2);
    CHECK(error == WSAECONNRESET);

    CHECK(!mcpbridge::sendAllUsing(
        payload.data(), payload.size(),
        [](const char*, int, int& sendError) {
            sendError = 0;
            return 0;
        },
        &error));
    CHECK(error == WSAECONNRESET);
}

static void testCommandTokenEncoder()
{
    auto token = mcpbridge::encodeX64dbgCommandToken(
        "C:\\Program Files\\sample; one.exe", false);
    CHECK(token.ok);
    CHECK(token.encoded == "\"C:\\Program Files\\sample; one.exe\"");

    token = mcpbridge::encodeX64dbgCommandToken("say \\\"hello\\\"", true);
    CHECK(!token.ok); // upstream cannot preserve a raw backslash immediately before a quote

    token = mcpbridge::encodeX64dbgCommandToken("C:\\work\\", false);
    CHECK(!token.ok);
    token = mcpbridge::encodeX64dbgCommandToken("C:\\work\\", true);
    CHECK(token.ok);
    CHECK(token.encoded == "\"C:\\work\"\\");

    token = mcpbridge::encodeX64dbgCommandToken("a,b; c\"d", true);
    CHECK(token.ok);
    CHECK(token.encoded == "\"a,b; c\\\"d\"");
    CHECK(!mcpbridge::encodeX64dbgCommandToken("{cip}", true).ok);
}

static void testGuid()
{
    const std::string first = mcpbridge::createGuidString();
    const std::string second = mcpbridge::createGuidString();
    CHECK(first.size() == 36);
    CHECK(second.size() == 36);
    CHECK(first != second);
    CHECK(first[8] == '-' && first[13] == '-' && first[18] == '-' && first[23] == '-');
}

static mcpexception::Selector exactSelector(uint32_t value)
{
    mcpexception::Selector selector;
    selector.kind = mcpexception::SelectorKind::Exact;
    selector.value = value;
    selector.mask = 0xffffffffu;
    selector.maskBits = 32;
    selector.canonical = "exact";
    return selector;
}

static mcpexception::Selector maskedSelector(uint32_t value, uint32_t mask,
                                             unsigned int bits)
{
    mcpexception::Selector selector;
    selector.kind = mcpexception::SelectorKind::Masked;
    selector.value = value & mask;
    selector.mask = mask;
    selector.maskBits = bits;
    selector.canonical = "masked";
    return selector;
}

static mcpexception::Selector wildcardSelector()
{
    return {};
}

static mcpexception::Rule policyRule(
    std::string id, mcpexception::Selector selector, mcpexception::Action action,
    int priority, uint64_t order,
    mcpexception::Chance chance = mcpexception::Chance::Any)
{
    mcpexception::Rule rule;
    rule.ruleId = std::move(id);
    rule.selectors.push_back(std::move(selector));
    rule.action = action;
    rule.priority = priority;
    rule.insertionOrder = order;
    rule.chance = chance;
    return rule;
}

static void testExceptionPolicySpecificityAndChance()
{
    using namespace mcpexception;
    Policy policy;
    policy.enabled = true;
    policy.firstChanceDefault = Action::Handled;
    policy.secondChanceDefault = Action::NotHandled;
    // A very high-priority wildcard must never beat a more specific selector.
    policy.rules.push_back(policyRule("wild", wildcardSelector(), Action::Pause, 100000, 1));
    policy.rules.push_back(policyRule("mask-low", maskedSelector(0xC0000000u, 0xF0000000u, 4), Action::NotHandled, -50, 2));
    policy.rules.push_back(policyRule("mask-high", maskedSelector(0xC0000000u, 0xFF000000u, 8), Action::Handled, -100, 3));
    policy.rules.push_back(policyRule("exact", exactSelector(0xC0000005u), Action::Pause, -100000, 4));

    auto decision = selectPolicy(policy, 0xC0000005u, true);
    CHECK(decision.ruleId == "exact");
    decision = selectPolicy(policy, 0xC0123456u, true);
    CHECK(decision.ruleId == "mask-high");
    decision = selectPolicy(policy, 0xDEADBEEFu, true);
    CHECK(decision.ruleId == "wild");

    Policy defaults;
    defaults.enabled = true;
    defaults.firstChanceDefault = Action::Handled;
    defaults.secondChanceDefault = Action::NotHandled;
    defaults.rules.push_back(policyRule("first-only", exactSelector(7), Action::Pause, 0, 1, Chance::First));
    CHECK(selectPolicy(defaults, 8, true).action == Action::Handled);
    CHECK(selectPolicy(defaults, 7, false).action == Action::NotHandled);
    CHECK(selectPolicy(defaults, 7, true).ruleId == "first-only");
    defaults.enabled = false;
    CHECK(selectPolicy(defaults, 7, true).source == "policy_disabled");
}

static std::unordered_map<std::string, std::string> oneRuleParams(
    const std::string& id, const std::string& codes)
{
    return {
        {"enabled", "true"}, {"replace", "true"}, {"ruleCount", "1"},
        {"rule0Id", id}, {"rule0Codes", codes}, {"rule0Chance", "any"},
        {"rule0Action", "handled"}, {"rule0Priority", "0"}, {"rule0Enabled", "true"},
    };
}

static void testExceptionPolicyParserAndAtomicMerge()
{
    using namespace mcpexception;
    ParsedUpdate parsed; std::string error;
    auto params = oneRuleParams("Exact", "0xc0000005");
    CHECK(parsePolicyUpdate(params, parsed, error));
    CHECK(parsed.rules.size() == 1 && parsed.rules[0].selectors[0].kind == SelectorKind::Exact);

    params = oneRuleParams("mask", "0xe1234567/0xf0000000");
    parsed = {}; error.clear();
    CHECK(parsePolicyUpdate(params, parsed, error));
    CHECK(parsed.rules[0].selectors[0].value == 0xE0000000u);

    params = {
        {"ruleCount", "2"}, {"rule0Id", "same"}, {"rule0Codes", "*"},
        {"rule0Chance", "any"}, {"rule0Action", "pause"},
        {"rule1Id", "SAME"}, {"rule1Codes", "0x1"},
        {"rule1Chance", "any"}, {"rule1Action", "pause"},
    };
    parsed = {}; error.clear();
    CHECK(!parsePolicyUpdate(params, parsed, error));

    std::string tooMany;
    for(size_t i = 0; i < kMaxSelectorsPerRule + 1; ++i)
    { if(i) tooMany += ','; tooMany += std::to_string(i + 1); }
    params = oneRuleParams("too-many", tooMany);
    parsed = {}; error.clear();
    CHECK(!parsePolicyUpdate(params, parsed, error));
    params = oneRuleParams("priority", "0x1");
    params["rule0Priority"] = "100001";
    parsed = {}; error.clear();
    CHECK(!parsePolicyUpdate(params, parsed, error));

    Policy current;
    current.enabled = true;
    current.version = 9;
    current.nextInsertionOrder = 2;
    current.rules.push_back(policyRule("existing", exactSelector(1), Action::Pause, 0, 1));
    ParsedUpdate append;
    append.replace = false;
    append.rules.push_back(policyRule("EXISTING", exactSelector(2), Action::Handled, 0, 0));
    Policy unchanged;
    unchanged.version = 777;
    error.clear();
    CHECK(!mergePolicy(current, append, unchanged, error));
    CHECK(unchanged.version == 777); // failed transaction published nothing

    append.rules[0].ruleId = "new";
    Policy merged;
    error.clear();
    CHECK(mergePolicy(current, append, merged, error));
    CHECK(merged.version == 10 && merged.rules.size() == 2);
    CHECK(merged.rules[0].ruleId == "existing" && merged.rules[1].insertionOrder == 2);

    Policy full;
    full.nextInsertionOrder = kMaxRules + 1;
    for(size_t i = 0; i < kMaxRules; ++i)
        full.rules.push_back(policyRule("r" + std::to_string(i), exactSelector(static_cast<uint32_t>(i)), Action::Pause, 0, i + 1));
    ParsedUpdate over; over.replace = false;
    over.rules.push_back(policyRule("overflow", exactSelector(999), Action::Pause, 0, 0));
    CHECK(!mergePolicy(full, over, merged, error));

    Policy selectorOverflow;
    for(size_t i = 0; i < 17; ++i)
    {
        auto rule = policyRule("s" + std::to_string(i), exactSelector(static_cast<uint32_t>(i)), Action::Pause, 0, i + 1);
        while(rule.selectors.size() < kMaxSelectorsPerRule)
            rule.selectors.push_back(exactSelector(static_cast<uint32_t>(rule.selectors.size() + 1000 * i)));
        selectorOverflow.rules.push_back(std::move(rule));
    }
    ParsedUpdate noChange; noChange.replace = false;
    CHECK(!mergePolicy(selectorOverflow, noChange, merged, error));
}

static void testExceptionContinuationStateMachine()
{
    using namespace mcpexception;
    Continuation manual;
    CHECK(claimManualContinuation(manual, "handled", "con"));
    CHECK(!claimManualContinuation(manual, "not_handled", "con 1"));
    markManualDisposition(manual, true);
    CHECK(manual.appliedDisposition == "handled" && manual.outcome == "applied");
    markManualResume(manual, true, false);
    CHECK(manual.outcome == "applied_resume_failed");

    Continuation automatic;
    initializeAutomaticContinuation(automatic, Action::NotHandled);
    CHECK(automatic.claimed && automatic.command == "con 1" && automatic.source == "policy");
    CHECK(automatic.resumeRequested && !automatic.resumeSubmitted);
    markAutomaticSubmission(automatic, true, true);
    markAutomaticResume(automatic);
    CHECK(automatic.status == "auto_resumed");
    CHECK(automatic.appliedDisposition == "not_handled" && automatic.outcome == "applied");
    // A re-entrant resume callback may finalize before DbgCmdExec returns. A
    // later failed return must never undo an already-observed application.
    markAutomaticSubmission(automatic, false, false);
    CHECK(automatic.outcome == "applied" && automatic.appliedDisposition == "not_handled");

    Continuation retry;
    initializeAutomaticContinuation(retry, Action::Handled);
    CHECK(retry.command == "con");
    markAutomaticSubmission(retry, false, false);
    CHECK(!retry.claimed && retry.appliedDisposition == "none");
    CHECK(claimManualContinuation(retry, "handled", "con"));

    Continuation resumeRetry;
    initializeAutomaticContinuation(resumeRetry, Action::Handled);
    markAutomaticSubmission(resumeRetry, true, false);
    CHECK(resumeRetry.claimed && resumeRetry.commandSubmitted);
    CHECK(resumeRetry.dispositionSubmitted && !resumeRetry.resumeSubmitted);
    CHECK(resumeRetry.status == "resume_submission_failed");
    CHECK(resumeRetry.outcome == "applied_resume_failed");

    Continuation abandoned;
    initializeAutomaticContinuation(abandoned, Action::Handled);
    markAutomaticSubmission(abandoned, true, true);
    markAbandoned(abandoned);
    CHECK(abandoned.outcome == "abandoned" && abandoned.appliedDisposition == "none");
}

static void testExceptionHistoryRetentionAndPaging()
{
    using namespace mcpexception;
    std::deque<uint64_t> retained;
    for(uint64_t seq = 1; seq <= 600; ++seq)
        retained.push_back(seq);
    const size_t removed = trimBoundedHistory(retained);
    CHECK(removed == 88);
    CHECK(retained.size() == kHistoryRetentionLimit);
    CHECK(retained.front() == 89 && retained.back() == 600);

    const std::vector<uint64_t> sequences(retained.begin(), retained.end());
    const HistoryPage truncated = computeHistoryPage(sequences, 601, 88, 0, 10);
    CHECK(truncated.firstIndex == 0 && truncated.available == 512);
    CHECK(truncated.returned == 10 && truncated.nextAfterSeq == 98);
    CHECK(truncated.oldestAvailableSeq == 89 && truncated.latestSeq == 600);
    CHECK(truncated.hasMore && truncated.cursorTruncated);

    const HistoryPage boundary = computeHistoryPage(sequences, 601, 88, 88, 1);
    CHECK(!boundary.cursorTruncated && boundary.nextAfterSeq == 89);
    CHECK(boundary.returned == 1 && boundary.hasMore);

    const HistoryPage tail = computeHistoryPage(sequences, 601, 88, 598, 10);
    CHECK(tail.returned == 2 && tail.nextAfterSeq == 600 && !tail.hasMore);

    const HistoryPage empty = computeHistoryPage({}, 1, 0, 0, 100);
    CHECK(empty.oldestAvailableSeq == 1 && empty.latestSeq == 0);
    CHECK(empty.returned == 0 && empty.nextAfterSeq == 0);
    CHECK(!empty.hasMore && !empty.cursorTruncated);
}

static void testWindowsArgumentQuoting()
{
    using namespace mcplaunch;
    CHECK(quoteWindowsCrtArgument(L"plain") == L"plain");
    CHECK(quoteWindowsCrtArgument(L"") == L"\"\"");
    CHECK(quoteWindowsCrtArgument(L"two words") == L"\"two words\"");
    CHECK(quoteWindowsCrtArgument(L"two\twords") == L"\"two\twords\"");
    CHECK(quoteWindowsCrtArgument(L"a\"b") == L"\"a\\\"b\"");
    CHECK(quoteWindowsCrtArgument(L"C:\\plain\\") == L"C:\\plain\\");
    CHECK(quoteWindowsCrtArgument(L"C:\\Program Files\\") ==
          L"\"C:\\Program Files\\\\\"");
    CHECK(quoteWindowsCrtArgument(L"a\\\"b") == L"\"a\\\\\\\"b\"");
    CHECK(quoteWindowsCrtArgument(L"\\\\\"") == L"\"\\\\\\\\\\\"\"");
    CHECK(quoteWindowsCrtArgument(L"雪 и лёд") == L"\"雪 и лёд\"");

    auto quoted = quoteWindowsArgument(L"a b");
    CHECK(quoted.ok && quoted.quoted == L"\"a b\"");
    std::wstring embeddedNul(L"a\0b", 3);
    quoted = quoteWindowsArgument(embeddedNul);
    CHECK(!quoted.ok && quoted.quoted.empty());
    CHECK(quoted.errorCode == "argument_nul");

    auto built = buildWindowsCommandLine(
        L"C:\\Program Files\\target.exe",
        std::vector<std::wstring>{L"", L"plain", L"a b", L"a\"b",
                                  L"tail\\", L"Юникод"});
    CHECK(built.ok);
    CHECK(built.commandLine ==
          L"\"C:\\Program Files\\target.exe\" \"\" plain \"a b\" "
          L"\"a\\\"b\" tail\\ Юникод");
    CHECK(built.codeUnitsIncludingNul == built.commandLine.size() + 1);

    built = buildWindowsCommandLine(L"x.exe", L"--raw \"two words\" ");
    CHECK(built.ok && built.commandLine == L"x.exe --raw \"two words\" ");
    built = buildWindowsCommandLine(L"x.exe", std::wstring_view{});
    CHECK(built.ok && built.commandLine == L"x.exe");

    built = buildWindowsCommandLine(L"", std::vector<std::wstring>{});
    CHECK(!built.ok && built.errorCode == "executable_empty");
    built = buildWindowsCommandLine(embeddedNul,
                                    std::vector<std::wstring>{});
    CHECK(!built.ok && built.errorCode == "argument_nul");
    built = buildWindowsCommandLine(L"x", std::vector<std::wstring>{embeddedNul});
    CHECK(!built.ok && built.argumentIndex == 1 && built.commandLine.empty());

    const std::wstring exact(
        kMaxCreateProcessCommandLineCodeUnits - 1, L'x');
    built = buildWindowsCommandLine(exact,
                                    std::vector<std::wstring>{});
    CHECK(built.ok);
    CHECK(built.codeUnitsIncludingNul ==
          kMaxCreateProcessCommandLineCodeUnits);
    built = buildWindowsCommandLine(exact + L"x",
                                    std::vector<std::wstring>{});
    CHECK(!built.ok && built.errorCode == "command_line_too_long");
    CHECK(built.commandLine.empty());

    const std::wstring exactTail(
        kMaxCreateProcessCommandLineCodeUnits - 1 - 1 - 1, L't');
    built = buildWindowsCommandLine(L"x", std::wstring_view(exactTail));
    CHECK(built.ok && built.codeUnitsIncludingNul ==
                          kMaxCreateProcessCommandLineCodeUnits);
    built = buildWindowsCommandLine(L"x", std::wstring_view(exactTail + L"t"));
    CHECK(!built.ok && built.commandLine.empty());

    // Quoting can expand a source argument beyond the CreateProcess limit.
    built = buildWindowsCommandLine(
        L"x", std::vector<std::wstring>{L" " + std::wstring(20000, L'\\') + L"\""});
    CHECK(!built.ok && built.errorCode == "command_line_too_long");

#ifdef _WIN32
    // Prove the complete builder against Windows' canonical argv splitter,
    // rather than checking only hand-written encoded strings.  This matrix
    // deliberately mixes empty values, whitespace, embedded quotes, runs of
    // backslashes before quotes, trailing backslashes and non-BMP Unicode.
    const std::wstring roundTripExe = L"C:\\Program Files\\probe.exe";
    const std::vector<std::wstring> roundTripArgs = {
        L"", L"plain", L"two words", L"tab\tvalue", L"quote\"inside",
        L"one\\\"quote", L"three\\\\\\\"quote", L"tail\\",
        L"C:\\path with spaces\\", L",;{literal}", L"Привет-世界-\U0001F642"
    };
    built = buildWindowsCommandLine(roundTripExe, roundTripArgs);
    CHECK(built.ok);
    int parsedCount = 0;
    LPWSTR* parsed = CommandLineToArgvW(built.commandLine.c_str(), &parsedCount);
    CHECK(parsed != nullptr);
    if(parsed)
    {
        CHECK(parsedCount == static_cast<int>(roundTripArgs.size() + 1));
        if(parsedCount == static_cast<int>(roundTripArgs.size() + 1))
        {
            CHECK(std::wstring(parsed[0]) == roundTripExe);
            for(size_t index = 0; index < roundTripArgs.size(); ++index)
                CHECK(std::wstring(parsed[index + 1]) == roundTripArgs[index]);
        }
        LocalFree(parsed);
    }
#endif
}

static std::vector<std::wstring> splitEnvironmentBlock(
    const std::vector<wchar_t>& block)
{
    std::vector<std::wstring> result;
    size_t cursor = 0;
    while(cursor < block.size() && block[cursor] != L'\0')
    {
        const size_t begin = cursor;
        while(cursor < block.size() && block[cursor] != L'\0')
            ++cursor;
        result.emplace_back(block.data() + begin, cursor - begin);
        ++cursor;
    }
    return result;
}

static void testUnicodeEnvironmentBlock()
{
    using namespace mcplaunch;
    const std::vector<EnvironmentEntry> inherited = {
        EnvironmentEntry::set(L"z", L"last"),
        EnvironmentEntry::set(L"Path", L"old"),
        EnvironmentEntry::set(L"=C:", L"C:\\old"),
        EnvironmentEntry::set(L"=ExitCode", L"00000000"),
        EnvironmentEntry::set(L"Delete", L"gone"),
        EnvironmentEntry::set(L"Ж", L"снег"),
    };
    const std::vector<EnvironmentEntry> overrides = {
        EnvironmentEntry::set(L"PATH", L"new=with=equals"),
        EnvironmentEntry::erase(L"delete"),
        EnvironmentEntry::set(L"=c:", L"C:\\new"),
        EnvironmentEntry::set(L"A", L"first"),
        EnvironmentEntry::erase(L"absent"),
    };
    auto built = buildUnicodeEnvironmentBlock(inherited, overrides);
    CHECK(built.ok);
    CHECK(built.codeUnitsIncludingFinalNuls == built.block.size());
    CHECK(built.block.size() >= 2);
    CHECK(built.block[built.block.size() - 1] == L'\0');
    CHECK(built.block[built.block.size() - 2] == L'\0');
    const auto strings = splitEnvironmentBlock(built.block);
    CHECK((strings == std::vector<std::wstring>{
        L"=c:=C:\\new", L"=ExitCode=00000000", L"A=first", L"PATH=new=with=equals",
        L"z=last", L"Ж=снег"}));
    CHECK(built.entries.size() == strings.size());
    CHECK(built.entries[0].name == L"=c:");

    built = buildUnicodeEnvironmentBlock({}, {});
    CHECK(built.ok && built.entries.empty());
    CHECK((built.block == std::vector<wchar_t>{L'\0', L'\0'}));

    built = buildUnicodeEnvironmentBlock(
        {EnvironmentEntry::set(L"Path", L"1"),
         EnvironmentEntry::set(L"PATH", L"2")}, {});
    CHECK(!built.ok && built.errorCode == "environment_snapshot_duplicate");
    CHECK(built.block.empty());
    built = buildUnicodeEnvironmentBlock(
        {}, {EnvironmentEntry::set(L"Path", L"1"),
             EnvironmentEntry::erase(L"path")});
    CHECK(!built.ok && built.errorCode == "environment_override_duplicate");

    const std::vector<EnvironmentEntry> invalidEntries = {
        EnvironmentEntry::set(L"", L"x"),
        EnvironmentEntry::set(L"A=B", L"x"),
        EnvironmentEntry::set(L"=BAD=MORE", L"x"),
        EnvironmentEntry::set(std::wstring(L"A\0B", 3), L"x"),
        EnvironmentEntry::set(L"A", std::wstring(L"x\0y", 3)),
    };
    for(const auto& invalid : invalidEntries)
    {
        built = buildUnicodeEnvironmentBlock({}, {invalid});
        CHECK(!built.ok);
        CHECK(built.block.empty());
        CHECK(!built.errorCode.empty());
    }
    built = buildUnicodeEnvironmentBlock(
        {EnvironmentEntry::erase(L"A")}, {});
    CHECK(!built.ok && built.errorCode == "environment_snapshot_delete");

    // One entry costs name + '=' + value + NUL plus the final NUL.
    built = buildUnicodeEnvironmentBlock(
        {}, {EnvironmentEntry::set(
            L"A", std::wstring(kMaxUnicodeEnvironmentBlockCodeUnits - 4, L'v'))});
    CHECK(built.ok);
    CHECK(built.block.size() == kMaxUnicodeEnvironmentBlockCodeUnits);
    built = buildUnicodeEnvironmentBlock(
        {}, {EnvironmentEntry::set(
            L"A", std::wstring(kMaxUnicodeEnvironmentBlockCodeUnits - 3, L'v'))});
    CHECK(!built.ok && built.errorCode == "environment_block_too_large");
    CHECK(built.entries.empty() && built.block.empty());

    // Hidden variables are independent and deletable case-insensitively.
    built = buildUnicodeEnvironmentBlock(
        {EnvironmentEntry::set(L"=D:", L"D:\\dir"),
         EnvironmentEntry::set(L"Normal", L"yes")},
        {EnvironmentEntry::erase(L"=d:")});
    CHECK(built.ok);
    CHECK((splitEnvironmentBlock(built.block) ==
           std::vector<std::wstring>{L"Normal=yes"}));
}

static std::string byteString(const std::vector<uint8_t>& bytes)
{
    return std::string(bytes.begin(), bytes.end());
}

static void testStrictBase64()
{
    using namespace mcplaunch;
    const std::vector<uint8_t> binary = {
        0x00, 0x01, 0x02, 0x7f, 0x80, 0xfe, 0xff, 'A', '\r', '\n'
    };
    const std::string encoded = encodeBase64(binary);
    CHECK(encoded == "AAECf4D+/0ENCg==");
    auto decoded = decodeBase64Strict(encoded, binary.size());
    CHECK(decoded.ok && decoded.bytes == binary);
    decoded = decodeBase64Strict("", 0);
    CHECK(decoded.ok && decoded.bytes.empty());

    for(const std::string invalid : {
            "A", "AAA", "A===", "=AAA", "AA=A", "AAAA=", "AA A",
            "AB==", // non-zero unused low four bits
            "AAB="  // non-zero unused low two bits
        })
    {
        decoded = decodeBase64Strict(invalid, 1024);
        CHECK(!decoded.ok);
        CHECK(decoded.bytes.empty());
        CHECK(!decoded.errorCode.empty());
    }
    decoded = decodeBase64Strict("AAAA", 2);
    CHECK(!decoded.ok && decoded.errorCode == "base64_too_large");
    CHECK(encodeBase64(nullptr, 1).empty());
}

static void testBoundedByteRing()
{
    using namespace mcplaunch;
    BoundedByteRing ring(4);
    CHECK(ring.capacity() == 4 && ring.retainedSize() == 0);
    CHECK(ring.append("abc"));
    auto read = ring.read(0, 2);
    CHECK(byteString(read.bytes) == "ab");
    CHECK(read.effectiveCursor == 0 && read.nextCursor == 2);
    CHECK(read.availableBytes == 3 && read.limited && read.truncated);
    CHECK(!read.cursorTruncated && !read.eof);

    CHECK(ring.append("def"));
    CHECK(ring.oldestCursor() == 2 && ring.newestCursor() == 6);
    CHECK(ring.retainedSize() == 4);
    read = ring.read(0, 99);
    CHECK(byteString(read.bytes) == "cdef");
    CHECK(read.cursorTruncated && read.droppedBeforeCursor == 2);
    CHECK(read.totalDroppedBytes == 2 && read.effectiveCursor == 2);
    CHECK(read.nextCursor == 6 && read.truncated && !read.limited);

    read = ring.read(2, 2);
    CHECK(byteString(read.bytes) == "cd" && read.nextCursor == 4);
    CHECK(read.limited && !read.eof);
    ring.markEof();
    CHECK(ring.isClosed());
    read = ring.read(2, 2);
    CHECK(!read.eof); // retained tail remains
    read = ring.read(read.nextCursor, 99);
    CHECK(byteString(read.bytes) == "ef" && read.eof);
    CHECK(!ring.append("x"));
    CHECK(!ring.append(nullptr, 1));

    read = ring.read(999, 10);
    CHECK(read.cursorAhead && read.effectiveCursor == 6);
    CHECK(read.bytes.empty() && read.nextCursor == 6 && read.eof);
    read = ring.snapshot();
    CHECK(byteString(read.bytes) == "cdef");
    CHECK(read.cursorTruncated && read.eof);

    BoundedByteRing largeWrite(5);
    CHECK(largeWrite.append("0123456789"));
    read = largeWrite.read(0, 100);
    CHECK(byteString(read.bytes) == "56789");
    CHECK(read.oldestCursor == 5 && read.newestCursor == 10);
    CHECK(read.droppedBeforeCursor == 5);

    BoundedByteRing noRetention(0);
    CHECK(noRetention.append("xyz"));
    read = noRetention.read(0, 10);
    CHECK(read.bytes.empty() && read.cursorTruncated);
    CHECK(read.droppedBeforeCursor == 3 && !read.eof);
    noRetention.close();
    read = noRetention.read(3, 10);
    CHECK(read.eof && read.newestCursor == 3);
}

static void testBoundedByteRingConcurrency()
{
    using namespace mcplaunch;
    constexpr size_t count = 10000;
    BoundedByteRing ring(count);
    std::string expected;
    expected.reserve(count);
    for(size_t index = 0; index < count; ++index)
        expected.push_back(static_cast<char>('A' + (index % 26)));

    std::thread producer([&]() {
        for(const char value : expected)
        {
            CHECK(ring.append(&value, 1));
            if((ring.newestCursor() & 127) == 0)
                std::this_thread::yield();
        }
        ring.markEof();
    });

    uint64_t cursor = 0;
    std::string observed;
    while(true)
    {
        const auto page = ring.read(cursor, 73);
        observed.append(page.bytes.begin(), page.bytes.end());
        cursor = page.nextCursor;
        if(page.eof)
            break;
        if(page.bytes.empty())
            std::this_thread::yield();
    }
    producer.join();
    CHECK(observed == expected);
    CHECK(cursor == count);
}

static void testFairRequestDispatcher()
{
    using namespace mcpdispatcher;
    FairAdmissionQueue queue(2, 4);
    uint64_t first = 0, second = 0, third = 0, fourth = 0, rejected = 0;
    CHECK(queue.tryAdmit(first));
    CHECK(queue.tryAdmit(second));
    CHECK(queue.tryAdmit(third));
    CHECK(queue.tryAdmit(fourth));
    CHECK(!queue.tryAdmit(rejected));
    CHECK(first < second && second < third && third < fourth);
    CHECK(queue.snapshot().admitted == 4 && queue.snapshot().queued == 4);

    CHECK(queue.canStart(first));
    CHECK(queue.tryStart(first) == StartDecision::Started);
    CHECK(queue.canStart(second));
    CHECK(queue.tryStart(second) == StartDecision::Started);
    CHECK(!queue.canStart(third));
    CHECK(queue.tryStart(third) == StartDecision::Queued);

    CHECK(queue.finish(first));
    CHECK(queue.canStart(third));
    CHECK(queue.tryStart(third) == StartDecision::Started);
    CHECK(queue.finish(second));
    CHECK(queue.canStart(fourth));
    CHECK(queue.tryStart(fourth) == StartDecision::Started);
    CHECK(queue.finish(third));
    CHECK(queue.finish(fourth));
    CHECK(!queue.finish(fourth));
    CHECK(queue.snapshot().admitted == 0);

    CHECK(routeMayRunConcurrently("/Bridge/Hello"));
    CHECK(routeMayRunConcurrently("/Debug/Pause"));
    CHECK(routeMayRunConcurrently("/Trace/Wait"));
    CHECK(!routeMayRunConcurrently("/Memory/Write"));
    CHECK(!routeMayRunConcurrently("/ExecCommand"));
    CHECK(!routeMayRunConcurrently("/future/unknown"));

    queue.reset();
    CHECK(queue.snapshot().admitted == 0);
    CHECK(queue.tryAdmit(first));
    CHECK(queue.cancel(first));
    CHECK(queue.snapshot().admitted == 0);
    CHECK(queue.tryStart(first) == StartDecision::UnknownTicket);
}

#ifdef _WIN32
static bool syntheticHandleFailure(HANDLE& observed)
{
    mcplaunch::UniqueHandle handle(CreateEventW(nullptr, FALSE, FALSE, nullptr));
    observed = handle.get();
    return false;
}

static void testUniqueHandleAndExplicitInheritance()
{
    using namespace mcplaunch;
    static_assert(!std::is_copy_constructible_v<UniqueHandle>);
    static_assert(!std::is_copy_assignable_v<UniqueHandle>);
    static_assert(std::is_nothrow_move_constructible_v<UniqueHandle>);
    static_assert(std::is_nothrow_move_assignable_v<UniqueHandle>);

    UniqueHandle empty;
    CHECK(!empty);
    UniqueHandle invalid(INVALID_HANDLE_VALUE);
    CHECK(!invalid);

    DWORD before = 0;
    CHECK(GetProcessHandleCount(GetCurrentProcess(), &before));
    for(size_t iteration = 0; iteration < 100; ++iteration)
    {
        HANDLE raw = nullptr;
        CHECK(!syntheticHandleFailure(raw));
        CHECK(isValidHandle(raw));
        DWORD flags = 0;
        SetLastError(ERROR_SUCCESS);
        CHECK(!GetHandleInformation(raw, &flags));
        CHECK(GetLastError() == ERROR_INVALID_HANDLE);
    }
    DWORD after = 0;
    CHECK(GetProcessHandleCount(GetCurrentProcess(), &after));
    CHECK(after <= before + 1);

    UniqueHandle first(CreateEventW(nullptr, FALSE, FALSE, nullptr));
    CHECK(first);
    const HANDLE firstRaw = first.get();
    first.reset(first.get());
    DWORD flags = 0;
    CHECK(GetHandleInformation(firstRaw, &flags));
    UniqueHandle moved(std::move(first));
    CHECK(!first && moved.get() == firstRaw);

    UniqueHandle replaced(CreateEventW(nullptr, FALSE, FALSE, nullptr));
    const HANDLE replacedRaw = replaced.get();
    replaced = std::move(moved);
    CHECK(replaced.get() == firstRaw && !moved);
    CHECK(!GetHandleInformation(replacedRaw, &flags));

    HANDLE released = replaced.release();
    CHECK(!replaced && isValidHandle(released));
    CHECK(CloseHandle(released));

    SECURITY_ATTRIBUTES attributes{};
    attributes.nLength = sizeof(attributes);
    attributes.bInheritHandle = TRUE;
    HANDLE readRaw = nullptr;
    HANDLE writeRaw = nullptr;
    CHECK(CreatePipe(&readRaw, &writeRaw, &attributes, 0));
    UniqueHandle readPipe(readRaw);
    UniqueHandle writePipe(writeRaw);
    auto validation = validateExplicitInheritanceList(
        {readPipe.get(), writePipe.get()});
    CHECK(validation.ok && validation.handles.size() == 2);

    DWORD error = 123;
    CHECK(setHandleInheritable(readPipe.get(), false, &error));
    CHECK(error == ERROR_SUCCESS);
    validation = validateExplicitInheritanceList({readPipe.get()});
    CHECK(!validation.ok);
    CHECK(validation.errorCode == "inheritance_handle_not_inheritable");
    validation = validateExplicitInheritanceList({readPipe.get()}, false);
    CHECK(validation.ok);
    CHECK(setHandleInheritable(readPipe.get(), true, &error));

    validation = validateExplicitInheritanceList(
        {readPipe.get(), readPipe.get()});
    CHECK(!validation.ok &&
          validation.errorCode == "inheritance_handle_duplicate" &&
          validation.failingIndex == 1);
    validation = validateExplicitInheritanceList({nullptr});
    CHECK(!validation.ok &&
          validation.errorCode == "inheritance_handle_invalid");
    validation = validateExplicitInheritanceList({});
    CHECK(validation.ok && validation.handles.empty());
    CHECK(!setHandleInheritable(INVALID_HANDLE_VALUE, true, &error));
    CHECK(error == ERROR_INVALID_HANDLE);
}

static void testFileIdentityWithoutPointerMutation()
{
    using namespace mcplaunch;
    wchar_t tempDirectory[MAX_PATH] = {};
    CHECK(GetTempPathW(_countof(tempDirectory), tempDirectory) != 0);
    wchar_t tempPath[MAX_PATH] = {};
    CHECK(GetTempFileNameW(tempDirectory, L"mli", 0, tempPath) != 0);

    UniqueHandle file(CreateFileW(
        tempPath, GENERIC_READ | GENERIC_WRITE | FILE_READ_ATTRIBUTES,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_TEMPORARY, nullptr));
    CHECK(file);
    const char payload[] = "abc";
    DWORD written = 0;
    CHECK(WriteFile(file.get(), payload, 3, &written, nullptr));
    CHECK(written == 3);
    CHECK(FlushFileBuffers(file.get()));
    LARGE_INTEGER offset{};
    offset.QuadPart = 1;
    CHECK(SetFilePointerEx(file.get(), offset, nullptr, FILE_BEGIN));

    const auto byHandle = identifyFileByHandle(file.get());
    CHECK(byHandle.ok);
    CHECK(byHandle.size == 3);
    CHECK(byHandle.sha256 ==
          "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    CHECK(!byHandle.finalPath.empty());
    LARGE_INTEGER current{};
    offset.QuadPart = 0;
    CHECK(SetFilePointerEx(file.get(), offset, &current, FILE_CURRENT));
    CHECK(current.QuadPart == 1);

    const auto byPath = identifyFileByPath(tempPath);
    CHECK(byPath.ok && byPath.sha256 == byHandle.sha256);
    CHECK(byPath.size == byHandle.size);
    CHECK(byPath.volumeSerialNumber == byHandle.volumeSerialNumber);
    CHECK(byPath.fileId == byHandle.fileId);

    const auto invalid = identifyFileByHandle(INVALID_HANDLE_VALUE);
    CHECK(!invalid.ok && invalid.errorCode == "file_handle_invalid");
    file.reset();
    CHECK(DeleteFileW(tempPath));
}
#endif

int main()
{
    testHexParser();
    testDecimalParser();
    testHttpParserContract();
    testChildBrokerCore();
    testTcpPortParser();
    testListenPortParser();
    testConstantTimeEqual();
    testSendAll();
    testCommandTokenEncoder();
    testGuid();
    testExceptionPolicySpecificityAndChance();
    testExceptionPolicyParserAndAtomicMerge();
    testExceptionContinuationStateMachine();
    testExceptionHistoryRetentionAndPaging();
    testWindowsArgumentQuoting();
    testUnicodeEnvironmentBlock();
    testStrictBase64();
    testBoundedByteRing();
    testBoundedByteRingConcurrency();
    testFairRequestDispatcher();
#ifdef _WIN32
    testUniqueHandleAndExplicitInheritance();
    testFileIdentityWithoutPointerMutation();
#endif
    if(failures)
    {
        std::cerr << failures << " native bridge-core test(s) failed\n";
        return 1;
    }
    std::cout << "native bridge-core tests passed\n";
    return 0;
}
