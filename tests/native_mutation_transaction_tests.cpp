#include "mutation_transaction_core.hpp"

#include <atomic>
#include <cstdint>
#include <exception>
#include <iostream>
#include <memory>
#include <stdexcept>
#include <string>
#include <thread>
#include <utility>
#include <vector>

namespace
{

using namespace mcpmutation;

int failures = 0;

#define CHECK(expr)                                                            \
    do                                                                         \
    {                                                                          \
        if(!(expr))                                                            \
        {                                                                      \
            std::cerr << __FILE__ << ':' << __LINE__                           \
                      << ": CHECK failed: " #expr << '\n';                     \
            ++failures;                                                        \
        }                                                                      \
    } while(false)

struct ClockControl
{
    std::atomic<Tick> now{0};
    std::atomic<bool> fail{false};
};

Clock makeClock(const std::shared_ptr<ClockControl>& control)
{
    return [control]() -> Tick {
        if(control->fail.load(std::memory_order_acquire))
            throw std::runtime_error("injected clock failure");
        return control->now.load(std::memory_order_acquire);
    };
}

SessionIdentity session(std::uint64_t generation = 1,
                        std::uint64_t processId = 100,
                        std::string bridge = "bridge-A",
                        std::string sessionId = "session-A",
                        char hashByte = 'a')
{
    SessionIdentity value;
    value.bridgeInstanceId = std::move(bridge);
    value.sessionId = std::move(sessionId);
    value.generation = generation;
    value.processId = processId;
    value.targetSha256 = std::string(64, hashByte);
    return value;
}

std::string secret(char byte)
{
    return std::string(64, byte);
}

Snapshot checkedSnapshot(MutationCoordinator& coordinator)
{
    const auto result = coordinator.snapshot();
    CHECK(result.ok());
    return result.snapshot;
}

AcquireLeaseRequest acquireRequest(
    const SessionIdentity& identity,
    std::string owner,
    char nonceByte,
    char tokenByte,
    Tick ttl,
    std::uint64_t revision)
{
    AcquireLeaseRequest request;
    request.session = identity;
    request.ownerId = std::move(owner);
    request.acquisitionNonce = secret(nonceByte);
    request.proposedLeaseToken = secret(tokenByte);
    request.ttl = ttl;
    request.expectedLeaseRevision = revision;
    return request;
}

RenewLeaseRequest renewRequest(
    const SessionIdentity& identity,
    std::string owner,
    char nonceByte,
    char tokenByte,
    Tick ttl,
    std::uint64_t revision)
{
    RenewLeaseRequest request;
    request.session = identity;
    request.ownerId = std::move(owner);
    request.acquisitionNonce = secret(nonceByte);
    request.leaseToken = secret(tokenByte);
    request.ttl = ttl;
    request.expectedLeaseRevision = revision;
    return request;
}

ReleaseLeaseRequest releaseRequest(
    const SessionIdentity& identity,
    std::string owner,
    char nonceByte,
    char tokenByte,
    std::uint64_t revision)
{
    ReleaseLeaseRequest request;
    request.session = identity;
    request.ownerId = std::move(owner);
    request.acquisitionNonce = secret(nonceByte);
    request.leaseToken = secret(tokenByte);
    request.expectedLeaseRevision = revision;
    return request;
}

BeginMutationRequest beginRequest(
    const SessionIdentity& identity,
    std::uint64_t leaseRevision,
    std::uint64_t mutationSeq,
    std::uint64_t emergencyEpoch)
{
    BeginMutationRequest request;
    request.session = identity;
    request.expectedLeaseRevision = leaseRevision;
    request.expectedMutationSeq = mutationSeq;
    request.expectedEmergencyEpoch = emergencyEpoch;
    return request;
}

BeginMutationRequest leasedBeginRequest(
    const SessionIdentity& identity,
    std::string owner,
    char nonceByte,
    char tokenByte,
    std::uint64_t leaseRevision,
    std::uint64_t mutationSeq,
    std::uint64_t emergencyEpoch)
{
    auto request = beginRequest(
        identity, leaseRevision, mutationSeq, emergencyEpoch);
    request.ownerId = std::move(owner);
    request.acquisitionNonce = secret(nonceByte);
    request.leaseToken = secret(tokenByte);
    return request;
}

void testInputAndClockContract()
{
    auto clock = std::make_shared<ClockControl>();
    clock->now = 100;
    const auto firstSession = session();

    bool rejectedInvalidSession = false;
    try
    {
        auto invalid = firstSession;
        invalid.targetSha256 = "not-a-hash";
        MutationCoordinator ignored(invalid, makeClock(clock));
    }
    catch(const std::invalid_argument&)
    {
        rejectedInvalidSession = true;
    }
    CHECK(rejectedInvalidSession);

    MutationCoordinator coordinator(firstSession, makeClock(clock));
    auto snapshot = checkedSnapshot(coordinator);
    CHECK(snapshot.observedAt == 100);
    CHECK(snapshot.leaseRevision == 0);
    CHECK(snapshot.mutationSeq == 0);
    CHECK(snapshot.emergencyEpoch == 0);
    CHECK(!snapshot.leaseActive);

    auto request = acquireRequest(firstSession, "owner-A", 'n', 't', 10, 0);
    request.ownerId.clear();
    CHECK(coordinator.acquireLease(request).error == Error::InvalidOwner);
    request = acquireRequest(firstSession, "owner-A", 'n', 't', 10, 0);
    request.acquisitionNonce = "short";
    CHECK(coordinator.acquireLease(request).error
          == Error::InvalidAcquisitionNonce);
    request = acquireRequest(firstSession, "owner-A", 'n', 't', 10, 0);
    request.proposedLeaseToken = request.acquisitionNonce;
    CHECK(coordinator.acquireLease(request).error
          == Error::InvalidLeaseToken);
    request = acquireRequest(firstSession, "owner-A", 'n', 't', 0, 0);
    CHECK(coordinator.acquireLease(request).error == Error::InvalidTtl);

    clock->now = 99;
    CHECK(coordinator.snapshot().error == Error::ClockRegression);
    clock->now = 100;
    clock->fail = true;
    CHECK(coordinator.snapshot().error == Error::ClockFailure);
    clock->fail = false;
    CHECK(coordinator.snapshot().ok());

    CHECK(std::string(errorName(Error::ExpiredLeaseToken))
          == "expired_lease_token");
}

void testCompetingOwnersAndAcquireReplay()
{
    auto clock = std::make_shared<ClockControl>();
    clock->now = 1'000;
    const auto identity = session();
    MutationCoordinator coordinator(identity, makeClock(clock));

    const auto acquired = coordinator.acquireLease(
        acquireRequest(identity, "owner-A", 'n', 't', 100, 0));
    CHECK(acquired.ok());
    CHECK(acquired.leaseToken == secret('t'));
    CHECK(acquired.expiresAt == 1'100);
    CHECK(acquired.snapshot.leaseRevision == 1);

    const auto replayed = coordinator.acquireLease(
        acquireRequest(identity, "owner-A", 'n', 'u', 500, 1));
    CHECK(replayed.ok());
    CHECK(replayed.replayed);
    CHECK(replayed.leaseToken == secret('t'));
    CHECK(replayed.expiresAt == 1'100);
    CHECK(replayed.snapshot.leaseRevision == 1);

    CHECK(coordinator.acquireLease(
        acquireRequest(identity, "owner-A", 'x', 'u', 100, 1)).error
        == Error::AcquisitionNonceMismatch);
    CHECK(coordinator.acquireLease(
        acquireRequest(identity, "owner-B", 'n', 'u', 100, 1)).error
        == Error::LeaseBusy);

    auto noCredentials = beginRequest(identity, 1, 0, 0);
    CHECK(coordinator.beginMutation(noCredentials).error
          == Error::LeaseRequired);
    CHECK(coordinator.beginMutation(leasedBeginRequest(
        identity, "owner-B", 'n', 't', 1, 0, 0)).error
        == Error::OwnerMismatch);
    CHECK(coordinator.beginMutation(leasedBeginRequest(
        identity, "owner-A", 'x', 't', 1, 0, 0)).error
        == Error::AcquisitionNonceMismatch);
    CHECK(coordinator.beginMutation(leasedBeginRequest(
        identity, "owner-A", 'n', 'z', 1, 0, 0)).error
        == Error::UnknownLeaseToken);

    {
        auto begun = coordinator.beginMutation(leasedBeginRequest(
            identity, "owner-A", 'n', 't', 1, 0, 0));
        CHECK(begun.ok());
        CHECK(begun.snapshot.mutationInFlight);
    }
    CHECK(!checkedSnapshot(coordinator).mutationInFlight);
}

void testConcurrentOwnerAcquisitionIsSerialized()
{
    auto clock = std::make_shared<ClockControl>();
    clock->now = 50;
    const auto identity = session();
    MutationCoordinator coordinator(identity, makeClock(clock));

    constexpr std::size_t ownerCount = 12;
    std::vector<Error> errors(ownerCount, Error::None);
    std::atomic<bool> start{false};
    std::vector<std::thread> threads;
    threads.reserve(ownerCount);
    for(std::size_t index = 0; index < ownerCount; ++index)
    {
        threads.emplace_back([&, index] {
            while(!start.load(std::memory_order_acquire))
                std::this_thread::yield();
            const char nonceByte = static_cast<char>('A' + index);
            const char tokenByte = static_cast<char>('a' + index);
            errors[index] = coordinator.acquireLease(acquireRequest(
                identity, "owner-" + std::to_string(index),
                nonceByte, tokenByte, 100, 0)).error;
        });
    }
    start.store(true, std::memory_order_release);
    for(auto& thread : threads)
        thread.join();

    std::size_t successes = 0;
    std::size_t busy = 0;
    for(const Error error : errors)
    {
        if(error == Error::None)
            ++successes;
        else if(error == Error::LeaseBusy)
            ++busy;
    }
    CHECK(successes == 1);
    CHECK(busy == ownerCount - 1);
    const auto snapshot = checkedSnapshot(coordinator);
    CHECK(snapshot.leaseActive);
    CHECK(snapshot.leaseRevision == 1);
}

void testExpiryBoundaryAndPinnedHandoff()
{
    auto clock = std::make_shared<ClockControl>();
    clock->now = 100;
    const auto identity = session();
    MutationCoordinator coordinator(identity, makeClock(clock));

    CHECK(coordinator.acquireLease(
        acquireRequest(identity, "owner-A", 'n', 't', 10, 0)).ok());
    clock->now = 109;
    auto begun = coordinator.beginMutation(leasedBeginRequest(
        identity, "owner-A", 'n', 't', 1, 0, 0));
    CHECK(begun.ok());

    clock->now = 110;
    auto snapshot = checkedSnapshot(coordinator);
    CHECK(snapshot.leaseActive);
    CHECK(snapshot.leaseExpiryPending);
    CHECK(snapshot.mutationInFlight);
    CHECK(snapshot.leaseRevision == 2);
    CHECK(coordinator.acquireLease(
        acquireRequest(identity, "owner-B", 'm', 'u', 20, 2)).error
        == Error::LeaseExpiryPending);

    const auto committed = begun.permit.commit(identity);
    CHECK(committed.ok());
    CHECK(committed.committedMutationSeq == 1);
    CHECK(!committed.snapshot.leaseActive);
    CHECK(!committed.snapshot.mutationInFlight);
    CHECK(committed.snapshot.leaseRevision == 3);

    CHECK(coordinator.renewLease(
        renewRequest(identity, "owner-A", 'n', 't', 10, 3)).error
        == Error::ExpiredLeaseToken);
    CHECK(coordinator.beginMutation(leasedBeginRequest(
        identity, "owner-A", 'n', 't', 3, 1, 0)).error
        == Error::ExpiredLeaseToken);

    const auto handoff = coordinator.acquireLease(
        acquireRequest(identity, "owner-B", 'm', 'u', 20, 3));
    CHECK(handoff.ok());
    CHECK(handoff.snapshot.leaseRevision == 4);
}

void testExactExpiryWithoutPermit()
{
    auto clock = std::make_shared<ClockControl>();
    clock->now = 200;
    const auto identity = session();
    MutationCoordinator coordinator(identity, makeClock(clock));
    CHECK(coordinator.acquireLease(
        acquireRequest(identity, "owner-A", 'n', 't', 10, 0)).ok());

    clock->now = 209;
    CHECK(checkedSnapshot(coordinator).leaseActive);
    clock->now = 210;
    const auto snapshot = checkedSnapshot(coordinator);
    CHECK(!snapshot.leaseActive);
    CHECK(snapshot.leaseRevision == 2);
    CHECK(coordinator.releaseLease(
        releaseRequest(identity, "owner-A", 'n', 't', 2)).error
        == Error::ExpiredLeaseToken);
}

void testRenewWhilePinned()
{
    auto clock = std::make_shared<ClockControl>();
    clock->now = 300;
    const auto identity = session();
    MutationCoordinator coordinator(identity, makeClock(clock));
    CHECK(coordinator.acquireLease(
        acquireRequest(identity, "owner-A", 'n', 't', 10, 0)).ok());
    auto begun = coordinator.beginMutation(leasedBeginRequest(
        identity, "owner-A", 'n', 't', 1, 0, 0));
    CHECK(begun.ok());

    clock->now = 310;
    auto snapshot = checkedSnapshot(coordinator);
    CHECK(snapshot.leaseExpiryPending);
    CHECK(snapshot.leaseRevision == 2);

    const auto renewed = coordinator.renewLease(
        renewRequest(identity, "owner-A", 'n', 't', 40, 2));
    CHECK(renewed.ok());
    CHECK(renewed.expiresAt == 350);
    CHECK(renewed.snapshot.leaseRevision == 3);
    CHECK(!renewed.snapshot.leaseExpiryPending);

    const auto committed = begun.permit.commit(identity);
    CHECK(committed.ok());
    CHECK(committed.snapshot.leaseActive);
    CHECK(committed.snapshot.leaseRevision == 3);
    CHECK(committed.snapshot.mutationSeq == 1);
}

void testReleaseWhilePinnedAndStaleToken()
{
    auto clock = std::make_shared<ClockControl>();
    clock->now = 400;
    const auto identity = session();
    MutationCoordinator coordinator(identity, makeClock(clock));
    CHECK(coordinator.acquireLease(
        acquireRequest(identity, "owner-A", 'n', 't', 100, 0)).ok());
    auto begun = coordinator.beginMutation(leasedBeginRequest(
        identity, "owner-A", 'n', 't', 1, 0, 0));
    CHECK(begun.ok());

    const auto release = coordinator.releaseLease(
        releaseRequest(identity, "owner-A", 'n', 't', 1));
    CHECK(release.ok());
    CHECK(release.pending);
    CHECK(release.snapshot.leaseActive);
    CHECK(release.snapshot.leaseReleasePending);
    CHECK(release.snapshot.leaseRevision == 2);

    CHECK(coordinator.renewLease(
        renewRequest(identity, "owner-A", 'n', 't', 10, 2)).error
        == Error::LeaseReleasePending);
    CHECK(coordinator.acquireLease(
        acquireRequest(identity, "owner-B", 'm', 'u', 10, 2)).error
        == Error::LeaseReleasePending);

    const auto repeated = coordinator.releaseLease(
        releaseRequest(identity, "owner-A", 'n', 't', 2));
    CHECK(repeated.ok());
    CHECK(repeated.pending);
    CHECK(repeated.snapshot.leaseRevision == 2);

    const auto committed = begun.permit.commit(identity);
    CHECK(committed.ok());
    CHECK(committed.snapshot.mutationSeq == 1);
    CHECK(!committed.snapshot.leaseActive);
    CHECK(committed.snapshot.leaseRevision == 3);

    CHECK(coordinator.releaseLease(
        releaseRequest(identity, "owner-A", 'n', 't', 3)).error
        == Error::StaleLeaseToken);
    CHECK(coordinator.beginMutation(leasedBeginRequest(
        identity, "owner-A", 'n', 't', 3, 1, 0)).error
        == Error::StaleLeaseToken);

    CHECK(coordinator.acquireLease(
        acquireRequest(identity, "owner-B", 'm', 'u', 10, 3)).ok());
}

void testReleasePendingAbandonFinalizesWithoutCommit()
{
    auto clock = std::make_shared<ClockControl>();
    clock->now = 500;
    const auto identity = session();
    MutationCoordinator coordinator(identity, makeClock(clock));
    CHECK(coordinator.acquireLease(
        acquireRequest(identity, "owner-A", 'n', 't', 100, 0)).ok());

    {
        auto begun = coordinator.beginMutation(leasedBeginRequest(
            identity, "owner-A", 'n', 't', 1, 0, 0));
        CHECK(begun.ok());
        CHECK(coordinator.releaseLease(
            releaseRequest(identity, "owner-A", 'n', 't', 1)).pending);
    }

    const auto snapshot = checkedSnapshot(coordinator);
    CHECK(!snapshot.leaseActive);
    CHECK(!snapshot.mutationInFlight);
    CHECK(snapshot.mutationSeq == 0);
    CHECK(snapshot.leaseRevision == 3);
}

void testMutationCasSerializationAndCommit()
{
    auto clock = std::make_shared<ClockControl>();
    clock->now = 600;
    const auto identity = session();
    MutationCoordinator coordinator(identity, makeClock(clock));

    CHECK(coordinator.beginMutation(
        beginRequest(identity, 1, 0, 0)).error
        == Error::StaleLeaseRevision);
    CHECK(coordinator.beginMutation(
        beginRequest(identity, 0, 1, 0)).error
        == Error::StaleMutationSequence);
    CHECK(coordinator.beginMutation(
        beginRequest(identity, 0, 0, 1)).error
        == Error::StaleEmergencyEpoch);

    auto first = coordinator.beginMutation(
        beginRequest(identity, 0, 0, 0));
    CHECK(first.ok());
    CHECK(coordinator.beginMutation(
        beginRequest(identity, 0, 0, 0)).error
        == Error::MutationBusy);

    MutationPermit moved = std::move(first.permit);
    CHECK(!first.permit.active());
    CHECK(moved.active());
    const auto committed = moved.commit(identity);
    CHECK(committed.ok());
    CHECK(committed.committedMutationSeq == 1);
    CHECK(committed.snapshot.mutationSeq == 1);
    CHECK(!committed.snapshot.mutationInFlight);
    CHECK(moved.commit(identity).error == Error::PermitAlreadyCommitted);
    CHECK(checkedSnapshot(coordinator).mutationSeq == 1);

    CHECK(coordinator.beginMutation(
        beginRequest(identity, 0, 0, 0)).error
        == Error::StaleMutationSequence);
    {
        auto second = coordinator.beginMutation(
            beginRequest(identity, 0, 1, 0));
        CHECK(second.ok());
    }
    CHECK(checkedSnapshot(coordinator).mutationSeq == 1);
}

void testEmergencyInvalidationEpoch()
{
    auto clock = std::make_shared<ClockControl>();
    clock->now = 700;
    const auto identity = session();
    MutationCoordinator coordinator(identity, makeClock(clock));
    CHECK(coordinator.acquireLease(
        acquireRequest(identity, "owner-A", 'n', 't', 100, 0)).ok());
    auto begun = coordinator.beginMutation(leasedBeginRequest(
        identity, "owner-A", 'n', 't', 1, 0, 0));
    CHECK(begun.ok());

    const auto invalidated = coordinator.emergencyInvalidate();
    CHECK(invalidated.ok());
    CHECK(invalidated.snapshot.emergencyEpoch == 1);
    CHECK(invalidated.snapshot.mutationSeq == 0);
    CHECK(invalidated.snapshot.mutationInFlight);

    const auto rejectedCommit = begun.permit.commit(identity);
    CHECK(rejectedCommit.error == Error::EmergencyInvalidated);
    CHECK(rejectedCommit.snapshot.mutationSeq == 0);
    CHECK(!rejectedCommit.snapshot.mutationInFlight);
    CHECK(rejectedCommit.snapshot.leaseActive);

    CHECK(coordinator.beginMutation(leasedBeginRequest(
        identity, "owner-A", 'n', 't', 1, 0, 0)).error
        == Error::StaleEmergencyEpoch);
    auto retry = coordinator.beginMutation(leasedBeginRequest(
        identity, "owner-A", 'n', 't', 1, 0, 1));
    CHECK(retry.ok());
    const auto committed = retry.permit.commit(identity);
    CHECK(committed.ok());
    CHECK(committed.snapshot.mutationSeq == 1);
    CHECK(committed.snapshot.emergencyEpoch == 1);
}

void testSessionTurnoverPinsAndInvalidates()
{
    auto clock = std::make_shared<ClockControl>();
    clock->now = 800;
    const auto firstSession = session(1, 100, "bridge-A", "session-A", 'a');
    const auto secondSession = session(
        2, 200, "bridge-A", "session-B", 'b');
    MutationCoordinator coordinator(firstSession, makeClock(clock));
    CHECK(coordinator.acquireLease(acquireRequest(
        firstSession, "owner-A", 'n', 't', 100, 0)).ok());
    auto begun = coordinator.beginMutation(leasedBeginRequest(
        firstSession, "owner-A", 'n', 't', 1, 0, 0));
    CHECK(begun.ok());

    auto staleSession = secondSession;
    staleSession.generation = 1;
    CHECK(coordinator.replaceSession(staleSession).error
          == Error::StaleSessionGeneration);

    const auto replaced = coordinator.replaceSession(secondSession);
    CHECK(replaced.ok());
    CHECK(replaced.snapshot.session == secondSession);
    CHECK(replaced.snapshot.emergencyEpoch == 1);
    CHECK(replaced.snapshot.leaseActive);
    CHECK(replaced.snapshot.leaseSessionInvalidationPending);
    CHECK(replaced.snapshot.leaseRevision == 2);
    CHECK(replaced.snapshot.mutationInFlight);

    CHECK(coordinator.acquireLease(acquireRequest(
        secondSession, "owner-B", 'm', 'u', 100, 2)).error
        == Error::LeaseSessionInvalidationPending);

    const auto rejectedCommit = begun.permit.commit(firstSession);
    CHECK(rejectedCommit.error == Error::SessionChanged);
    CHECK(rejectedCommit.snapshot.mutationSeq == 0);
    CHECK(!rejectedCommit.snapshot.leaseActive);
    CHECK(!rejectedCommit.snapshot.mutationInFlight);
    CHECK(rejectedCommit.snapshot.leaseRevision == 3);

    CHECK(coordinator.beginMutation(leasedBeginRequest(
        secondSession, "owner-A", 'n', 't', 3, 0, 1)).error
        == Error::StaleLeaseToken);
    CHECK(coordinator.acquireLease(acquireRequest(
        secondSession, "owner-B", 'm', 'u', 100, 3)).ok());

    auto oldSessionRequest = leasedBeginRequest(
        firstSession, "owner-B", 'm', 'u', 4, 0, 1);
    CHECK(coordinator.beginMutation(oldSessionRequest).error
          == Error::SessionMismatch);
}

void testUnleasedPermitAlsoPinsSessionHandoff()
{
    auto clock = std::make_shared<ClockControl>();
    clock->now = 900;
    const auto firstSession = session();
    const auto secondSession = session(
        2, 101, "bridge-A", "session-B", 'b');
    MutationCoordinator coordinator(firstSession, makeClock(clock));
    auto begun = coordinator.beginMutation(
        beginRequest(firstSession, 0, 0, 0));
    CHECK(begun.ok());
    CHECK(coordinator.replaceSession(secondSession).ok());

    CHECK(coordinator.acquireLease(acquireRequest(
        secondSession, "owner-A", 'n', 't', 100, 0)).error
        == Error::MutationBusy);
    CHECK(begun.permit.commit(firstSession).error
          == Error::SessionChanged);
    CHECK(coordinator.acquireLease(acquireRequest(
        secondSession, "owner-A", 'n', 't', 100, 0)).ok());
}

void testPermitDestructorContainsClockFailure()
{
    auto clock = std::make_shared<ClockControl>();
    clock->now = 1'000;
    const auto identity = session();
    MutationCoordinator coordinator(identity, makeClock(clock));

    {
        auto begun = coordinator.beginMutation(
            beginRequest(identity, 0, 0, 0));
        CHECK(begun.ok());
        clock->fail = true;
        // Destruction must neither throw nor leave the state-machine permit
        // pinned even when the injected clock fails.
    }
    clock->fail = false;
    const auto snapshot = checkedSnapshot(coordinator);
    CHECK(!snapshot.mutationInFlight);
    CHECK(snapshot.mutationSeq == 0);

    auto begun = coordinator.beginMutation(
        beginRequest(identity, 0, 0, 0));
    CHECK(begun.ok());
    clock->fail = true;
    const auto commit = begun.permit.commit(identity);
    CHECK(commit.error == Error::ClockFailure);
    clock->fail = false;
    CHECK(!checkedSnapshot(coordinator).mutationInFlight);
}

} // namespace

int main()
{
    testInputAndClockContract();
    testCompetingOwnersAndAcquireReplay();
    testConcurrentOwnerAcquisitionIsSerialized();
    testExpiryBoundaryAndPinnedHandoff();
    testExactExpiryWithoutPermit();
    testRenewWhilePinned();
    testReleaseWhilePinnedAndStaleToken();
    testReleasePendingAbandonFinalizesWithoutCommit();
    testMutationCasSerializationAndCommit();
    testEmergencyInvalidationEpoch();
    testSessionTurnoverPinsAndInvalidates();
    testUnleasedPermitAlsoPinsSessionHandoff();
    testPermitDestructorContainsClockFailure();

    if(failures != 0)
    {
        std::cerr << failures
                  << " native mutation transaction test(s) failed\n";
        return 1;
    }
    std::cout << "native mutation transaction tests passed\n";
    return 0;
}
