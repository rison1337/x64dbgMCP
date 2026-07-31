#include "mutation_transaction_core.hpp"

#include <algorithm>
#include <limits>
#include <mutex>
#include <stdexcept>
#include <string_view>
#include <utility>

namespace mcpmutation
{
namespace
{

constexpr std::size_t kMinimumSecretLength = 32;
constexpr std::size_t kMaximumSecretLength = 256;
constexpr std::size_t kMaximumOwnerLength = 128;
constexpr std::size_t kMaximumIdentityLength = 256;

enum class TombstoneReason
{
    None,
    Expired,
    Released,
    SessionInvalidated,
};

bool isPrintableAscii(std::string_view value) noexcept
{
    return std::all_of(value.begin(), value.end(), [](unsigned char ch) {
        return ch >= 0x21 && ch <= 0x7e;
    });
}

bool validIdentityText(std::string_view value) noexcept
{
    return !value.empty() && value.size() <= kMaximumIdentityLength
        && isPrintableAscii(value);
}

bool validOwner(std::string_view value) noexcept
{
    return !value.empty() && value.size() <= kMaximumOwnerLength
        && isPrintableAscii(value);
}

bool validSecret(std::string_view value) noexcept
{
    return value.size() >= kMinimumSecretLength
        && value.size() <= kMaximumSecretLength
        && isPrintableAscii(value);
}

bool constantTimeSecretEqual(std::string_view left,
                             std::string_view right) noexcept
{
    const std::size_t count = std::max(left.size(), right.size());
    std::size_t difference = left.size() ^ right.size();
    for(std::size_t index = 0; index < count; ++index)
    {
        const unsigned char leftByte = index < left.size()
            ? static_cast<unsigned char>(left[index])
            : 0;
        const unsigned char rightByte = index < right.size()
            ? static_cast<unsigned char>(right[index])
            : 0;
        difference |= static_cast<std::size_t>(leftByte ^ rightByte);
    }
    return difference == 0;
}

bool checkedDeadline(Tick now, Tick ttl, Tick& deadline) noexcept
{
    if(ttl == 0 || ttl > std::numeric_limits<Tick>::max() - now)
        return false;
    deadline = now + ttl;
    return true;
}

bool bump(std::uint64_t& value) noexcept
{
    if(value == std::numeric_limits<std::uint64_t>::max())
        return false;
    ++value;
    return true;
}

} // namespace

namespace detail
{

struct LeaseState
{
    bool active = false;
    std::uint64_t incarnation = 0;
    std::string token;
    std::string ownerId;
    std::string acquisitionNonce;
    SessionIdentity session;
    Tick expiresAt = 0;
    bool expiryPending = false;
    bool releasePending = false;
    bool sessionInvalidationPending = false;
};

struct Tombstone
{
    std::string token;
    TombstoneReason reason = TombstoneReason::None;
};

struct InFlightState
{
    bool active = false;
    std::uint64_t permitId = 0;
    std::uint64_t leaseIncarnation = 0;
    SessionIdentity session;
    std::uint64_t mutationSeq = 0;
    std::uint64_t emergencyEpoch = 0;
};

struct State
{
    State(SessionIdentity initialSession, Clock injectedClock)
        : session(std::move(initialSession)),
          clock(std::move(injectedClock))
    {
    }

    std::mutex mutex;
    SessionIdentity session;
    Clock clock;
    Tick lastObservedAt = 0;
    std::uint64_t leaseRevision = 0;
    std::uint64_t mutationSeq = 0;
    std::uint64_t emergencyEpoch = 0;
    std::uint64_t nextLeaseIncarnation = 0;
    std::uint64_t nextPermitId = 0;
    bool counterExhausted = false;
    LeaseState lease;
    Tombstone tombstone;
    InFlightState inFlight;
};

} // namespace detail

namespace
{

using detail::State;

bool readClock(const std::shared_ptr<State>& state, Tick& now) noexcept
{
    try
    {
        now = state->clock();
        return true;
    }
    catch(...)
    {
        now = 0;
        return false;
    }
}

Snapshot snapshotLocked(const State& state)
{
    Snapshot result;
    result.session = state.session;
    result.leaseRevision = state.leaseRevision;
    result.mutationSeq = state.mutationSeq;
    result.emergencyEpoch = state.emergencyEpoch;
    result.observedAt = state.lastObservedAt;
    result.leaseExpiresAt = state.lease.active
        ? state.lease.expiresAt
        : 0;
    result.leaseOwnerId = state.lease.active
        ? state.lease.ownerId
        : std::string();
    result.leaseActive = state.lease.active;
    result.leaseExpiryPending = state.lease.expiryPending;
    result.leaseReleasePending = state.lease.releasePending;
    result.leaseSessionInvalidationPending =
        state.lease.sessionInvalidationPending;
    result.mutationInFlight = state.inFlight.active;
    return result;
}

Error bumpLeaseRevisionLocked(State& state) noexcept
{
    if(!bump(state.leaseRevision))
    {
        state.counterExhausted = true;
        return Error::CounterExhausted;
    }
    return Error::None;
}

Error classifyNonCurrentTokenLocked(const State& state,
                                    std::string_view token) noexcept
{
    if(!state.tombstone.token.empty()
        && constantTimeSecretEqual(token, state.tombstone.token))
    {
        return state.tombstone.reason == TombstoneReason::Expired
            ? Error::ExpiredLeaseToken
            : Error::StaleLeaseToken;
    }
    return Error::UnknownLeaseToken;
}

Error finalizeLeaseLocked(State& state, TombstoneReason reason) noexcept
{
    state.tombstone.token = std::move(state.lease.token);
    state.tombstone.reason = reason;
    state.lease = detail::LeaseState{};
    return bumpLeaseRevisionLocked(state);
}

Error refreshExpiryLocked(State& state, Tick now) noexcept
{
    if(!state.lease.active || state.lease.sessionInvalidationPending
        || state.lease.releasePending || state.lease.expiryPending
        || now < state.lease.expiresAt)
    {
        return Error::None;
    }

    if(state.inFlight.active
        && state.inFlight.leaseIncarnation == state.lease.incarnation)
    {
        state.lease.expiryPending = true;
        return bumpLeaseRevisionLocked(state);
    }
    return finalizeLeaseLocked(state, TombstoneReason::Expired);
}

Error prepareLocked(State& state, Tick now) noexcept
{
    if(state.counterExhausted)
        return Error::CounterExhausted;
    if(now < state.lastObservedAt)
        return Error::ClockRegression;
    state.lastObservedAt = now;
    return refreshExpiryLocked(state, now);
}

Error validateRequestSessionLocked(const State& state,
                                   const SessionIdentity& session) noexcept
{
    if(!session.valid())
        return Error::InvalidSession;
    if(session != state.session)
        return Error::SessionMismatch;
    return Error::None;
}

Error validateCurrentLeaseCredentialsLocked(
    const State& state,
    std::string_view ownerId,
    std::string_view acquisitionNonce,
    std::string_view token) noexcept
{
    if(!state.lease.active
        || !constantTimeSecretEqual(token, state.lease.token))
    {
        return classifyNonCurrentTokenLocked(state, token);
    }
    if(ownerId != state.lease.ownerId)
        return Error::OwnerMismatch;
    if(!constantTimeSecretEqual(acquisitionNonce,
                                state.lease.acquisitionNonce))
    {
        return Error::AcquisitionNonceMismatch;
    }
    return Error::None;
}

Error finalizePendingLeaseLocked(State& state, Tick now) noexcept
{
    if(!state.lease.active || state.inFlight.active)
        return Error::None;
    if(state.lease.sessionInvalidationPending)
        return finalizeLeaseLocked(state, TombstoneReason::SessionInvalidated);
    if(state.lease.releasePending)
        return finalizeLeaseLocked(state, TombstoneReason::Released);
    if(state.lease.expiryPending || now >= state.lease.expiresAt)
        return finalizeLeaseLocked(state, TombstoneReason::Expired);
    return Error::None;
}

void closePermitLocked(State& state, std::uint64_t permitId,
                       Tick now) noexcept
{
    if(!state.inFlight.active || state.inFlight.permitId != permitId)
        return;
    state.inFlight = detail::InFlightState{};
    const Error finalizationError = finalizePendingLeaseLocked(state, now);
    if(finalizationError == Error::CounterExhausted)
        state.counterExhausted = true;
}

LeaseResult leaseErrorLocked(const State& state, Error error)
{
    LeaseResult result;
    result.error = error;
    result.snapshot = snapshotLocked(state);
    return result;
}

OperationResult operationErrorLocked(const State& state, Error error)
{
    OperationResult result;
    result.error = error;
    result.snapshot = snapshotLocked(state);
    return result;
}

} // namespace

const char* errorName(Error error) noexcept
{
    switch(error)
    {
    case Error::None: return "none";
    case Error::InvalidSession: return "invalid_session";
    case Error::SessionMismatch: return "session_mismatch";
    case Error::StaleSessionGeneration: return "stale_session_generation";
    case Error::InvalidOwner: return "invalid_owner";
    case Error::InvalidAcquisitionNonce: return "invalid_acquisition_nonce";
    case Error::InvalidLeaseToken: return "invalid_lease_token";
    case Error::InvalidTtl: return "invalid_ttl";
    case Error::LeaseBusy: return "lease_busy";
    case Error::LeaseRequired: return "lease_required";
    case Error::UnknownLeaseToken: return "unknown_lease_token";
    case Error::ExpiredLeaseToken: return "expired_lease_token";
    case Error::StaleLeaseToken: return "stale_lease_token";
    case Error::OwnerMismatch: return "owner_mismatch";
    case Error::AcquisitionNonceMismatch:
        return "acquisition_nonce_mismatch";
    case Error::StaleLeaseRevision: return "stale_lease_revision";
    case Error::StaleMutationSequence: return "stale_mutation_sequence";
    case Error::StaleEmergencyEpoch: return "stale_emergency_epoch";
    case Error::LeaseExpiryPending: return "lease_expiry_pending";
    case Error::LeaseReleasePending: return "lease_release_pending";
    case Error::LeaseSessionInvalidationPending:
        return "lease_session_invalidation_pending";
    case Error::MutationBusy: return "mutation_busy";
    case Error::PermitNotActive: return "permit_not_active";
    case Error::PermitAlreadyCommitted: return "permit_already_committed";
    case Error::SessionChanged: return "session_changed";
    case Error::EmergencyInvalidated: return "emergency_invalidated";
    case Error::ClockFailure: return "clock_failure";
    case Error::ClockRegression: return "clock_regression";
    case Error::CounterExhausted: return "counter_exhausted";
    default: return "unknown";
    }
}

bool SessionIdentity::valid() const noexcept
{
    if(!validIdentityText(bridgeInstanceId)
        || !validIdentityText(sessionId)
        || generation == 0 || processId == 0)
    {
        return false;
    }
    if(targetSha256.size() != 64)
        return false;
    return std::all_of(targetSha256.begin(), targetSha256.end(),
        [](unsigned char ch) {
            return (ch >= '0' && ch <= '9')
                || (ch >= 'a' && ch <= 'f')
                || (ch >= 'A' && ch <= 'F');
        });
}

bool operator==(const SessionIdentity& left,
                const SessionIdentity& right) noexcept
{
    return left.bridgeInstanceId == right.bridgeInstanceId
        && left.sessionId == right.sessionId
        && left.generation == right.generation
        && left.processId == right.processId
        && left.targetSha256 == right.targetSha256;
}

bool operator!=(const SessionIdentity& left,
                const SessionIdentity& right) noexcept
{
    return !(left == right);
}

MutationCoordinator::MutationCoordinator(SessionIdentity initialSession,
                                         Clock clock)
{
    if(!initialSession.valid())
        throw std::invalid_argument("initial mutation session is invalid");
    if(!clock)
        throw std::invalid_argument("mutation clock is empty");
    state_ = std::make_shared<detail::State>(
        std::move(initialSession), std::move(clock));
}

SnapshotResult MutationCoordinator::snapshot()
{
    SnapshotResult result;
    Tick now = 0;
    if(!readClock(state_, now))
    {
        std::lock_guard<std::mutex> lock(state_->mutex);
        result.error = Error::ClockFailure;
        result.snapshot = snapshotLocked(*state_);
        return result;
    }
    std::lock_guard<std::mutex> lock(state_->mutex);
    result.error = prepareLocked(*state_, now);
    result.snapshot = snapshotLocked(*state_);
    return result;
}

LeaseResult MutationCoordinator::acquireLease(
    const AcquireLeaseRequest& request)
{
    if(!request.session.valid())
        return {Error::InvalidSession};
    if(!validOwner(request.ownerId))
        return {Error::InvalidOwner};
    if(!validSecret(request.acquisitionNonce))
        return {Error::InvalidAcquisitionNonce};
    if(!validSecret(request.proposedLeaseToken)
        || constantTimeSecretEqual(request.proposedLeaseToken,
                                   request.acquisitionNonce))
    {
        return {Error::InvalidLeaseToken};
    }

    Tick now = 0;
    Tick deadline = 0;
    if(!readClock(state_, now))
        return {Error::ClockFailure};
    if(!checkedDeadline(now, request.ttl, deadline))
        return {Error::InvalidTtl};

    std::lock_guard<std::mutex> lock(state_->mutex);
    Error error = prepareLocked(*state_, now);
    if(error != Error::None)
        return leaseErrorLocked(*state_, error);
    error = validateRequestSessionLocked(*state_, request.session);
    if(error != Error::None)
        return leaseErrorLocked(*state_, error);

    if(state_->lease.active)
    {
        if(state_->lease.sessionInvalidationPending)
        {
            return leaseErrorLocked(
                *state_, Error::LeaseSessionInvalidationPending);
        }
        if(state_->lease.releasePending)
            return leaseErrorLocked(*state_, Error::LeaseReleasePending);
        if(state_->lease.expiryPending)
            return leaseErrorLocked(*state_, Error::LeaseExpiryPending);
        if(request.ownerId != state_->lease.ownerId)
            return leaseErrorLocked(*state_, Error::LeaseBusy);
        if(!constantTimeSecretEqual(request.acquisitionNonce,
                                    state_->lease.acquisitionNonce))
        {
            return leaseErrorLocked(
                *state_, Error::AcquisitionNonceMismatch);
        }
        if(request.expectedLeaseRevision != state_->leaseRevision)
            return leaseErrorLocked(*state_, Error::StaleLeaseRevision);

        LeaseResult result;
        result.snapshot = snapshotLocked(*state_);
        result.leaseToken = state_->lease.token;
        result.expiresAt = state_->lease.expiresAt;
        result.replayed = true;
        return result;
    }

    if(state_->inFlight.active)
        return leaseErrorLocked(*state_, Error::MutationBusy);
    if(request.expectedLeaseRevision != state_->leaseRevision)
        return leaseErrorLocked(*state_, Error::StaleLeaseRevision);
    const Error candidateClassification =
        classifyNonCurrentTokenLocked(*state_, request.proposedLeaseToken);
    if(candidateClassification != Error::UnknownLeaseToken)
        return leaseErrorLocked(*state_, candidateClassification);
    if(!bump(state_->nextLeaseIncarnation))
    {
        state_->counterExhausted = true;
        return leaseErrorLocked(*state_, Error::CounterExhausted);
    }
    error = bumpLeaseRevisionLocked(*state_);
    if(error != Error::None)
        return leaseErrorLocked(*state_, error);

    state_->lease.active = true;
    state_->lease.incarnation = state_->nextLeaseIncarnation;
    state_->lease.token = request.proposedLeaseToken;
    state_->lease.ownerId = request.ownerId;
    state_->lease.acquisitionNonce = request.acquisitionNonce;
    state_->lease.session = request.session;
    state_->lease.expiresAt = deadline;

    LeaseResult result;
    result.snapshot = snapshotLocked(*state_);
    result.leaseToken = state_->lease.token;
    result.expiresAt = deadline;
    return result;
}

LeaseResult MutationCoordinator::renewLease(
    const RenewLeaseRequest& request)
{
    if(!request.session.valid())
        return {Error::InvalidSession};
    if(!validOwner(request.ownerId))
        return {Error::InvalidOwner};
    if(!validSecret(request.acquisitionNonce))
        return {Error::InvalidAcquisitionNonce};
    if(!validSecret(request.leaseToken))
        return {Error::InvalidLeaseToken};

    Tick now = 0;
    Tick deadline = 0;
    if(!readClock(state_, now))
        return {Error::ClockFailure};
    if(!checkedDeadline(now, request.ttl, deadline))
        return {Error::InvalidTtl};

    std::lock_guard<std::mutex> lock(state_->mutex);
    Error error = prepareLocked(*state_, now);
    if(error != Error::None)
        return leaseErrorLocked(*state_, error);
    error = validateRequestSessionLocked(*state_, request.session);
    if(error != Error::None)
        return leaseErrorLocked(*state_, error);
    error = validateCurrentLeaseCredentialsLocked(
        *state_, request.ownerId, request.acquisitionNonce,
        request.leaseToken);
    if(error != Error::None)
        return leaseErrorLocked(*state_, error);
    if(state_->lease.sessionInvalidationPending)
    {
        return leaseErrorLocked(
            *state_, Error::LeaseSessionInvalidationPending);
    }
    if(state_->lease.releasePending)
        return leaseErrorLocked(*state_, Error::LeaseReleasePending);
    if(request.expectedLeaseRevision != state_->leaseRevision)
        return leaseErrorLocked(*state_, Error::StaleLeaseRevision);

    error = bumpLeaseRevisionLocked(*state_);
    if(error != Error::None)
        return leaseErrorLocked(*state_, error);
    state_->lease.expiresAt = deadline;
    state_->lease.expiryPending = false;

    LeaseResult result;
    result.snapshot = snapshotLocked(*state_);
    result.leaseToken = state_->lease.token;
    result.expiresAt = deadline;
    return result;
}

LeaseResult MutationCoordinator::releaseLease(
    const ReleaseLeaseRequest& request)
{
    if(!request.session.valid())
        return {Error::InvalidSession};
    if(!validOwner(request.ownerId))
        return {Error::InvalidOwner};
    if(!validSecret(request.acquisitionNonce))
        return {Error::InvalidAcquisitionNonce};
    if(!validSecret(request.leaseToken))
        return {Error::InvalidLeaseToken};

    Tick now = 0;
    if(!readClock(state_, now))
        return {Error::ClockFailure};

    std::lock_guard<std::mutex> lock(state_->mutex);
    Error error = prepareLocked(*state_, now);
    if(error != Error::None)
        return leaseErrorLocked(*state_, error);
    error = validateRequestSessionLocked(*state_, request.session);
    if(error != Error::None)
        return leaseErrorLocked(*state_, error);
    error = validateCurrentLeaseCredentialsLocked(
        *state_, request.ownerId, request.acquisitionNonce,
        request.leaseToken);
    if(error != Error::None)
        return leaseErrorLocked(*state_, error);
    if(state_->lease.sessionInvalidationPending)
    {
        return leaseErrorLocked(
            *state_, Error::LeaseSessionInvalidationPending);
    }
    if(request.expectedLeaseRevision != state_->leaseRevision)
        return leaseErrorLocked(*state_, Error::StaleLeaseRevision);

    if(state_->lease.releasePending)
    {
        LeaseResult result;
        result.snapshot = snapshotLocked(*state_);
        result.pending = true;
        return result;
    }

    const bool pinned = state_->inFlight.active
        && state_->inFlight.leaseIncarnation
            == state_->lease.incarnation;
    if(pinned)
    {
        error = bumpLeaseRevisionLocked(*state_);
        if(error != Error::None)
            return leaseErrorLocked(*state_, error);
        state_->lease.releasePending = true;
        state_->lease.expiryPending = false;

        LeaseResult result;
        result.snapshot = snapshotLocked(*state_);
        result.pending = true;
        return result;
    }

    error = finalizeLeaseLocked(*state_, TombstoneReason::Released);
    LeaseResult result;
    result.error = error;
    result.snapshot = snapshotLocked(*state_);
    return result;
}

BeginMutationResult MutationCoordinator::beginMutation(
    const BeginMutationRequest& request)
{
    BeginMutationResult result;
    if(!request.session.valid())
    {
        result.error = Error::InvalidSession;
        return result;
    }

    const bool hasAnyCredentials = !request.ownerId.empty()
        || !request.acquisitionNonce.empty() || !request.leaseToken.empty();
    if(hasAnyCredentials)
    {
        if(!validOwner(request.ownerId))
        {
            result.error = Error::InvalidOwner;
            return result;
        }
        if(!validSecret(request.acquisitionNonce))
        {
            result.error = Error::InvalidAcquisitionNonce;
            return result;
        }
        if(!validSecret(request.leaseToken))
        {
            result.error = Error::InvalidLeaseToken;
            return result;
        }
    }

    Tick now = 0;
    if(!readClock(state_, now))
    {
        result.error = Error::ClockFailure;
        return result;
    }

    std::lock_guard<std::mutex> lock(state_->mutex);
    Error error = prepareLocked(*state_, now);
    if(error == Error::None)
        error = validateRequestSessionLocked(*state_, request.session);
    if(error == Error::None && state_->lease.active)
    {
        if(!hasAnyCredentials)
            error = Error::LeaseRequired;
        else
            error = validateCurrentLeaseCredentialsLocked(
                *state_, request.ownerId, request.acquisitionNonce,
                request.leaseToken);
        if(error == Error::None
            && state_->lease.sessionInvalidationPending)
        {
            error = Error::LeaseSessionInvalidationPending;
        }
        if(error == Error::None && state_->lease.releasePending)
            error = Error::LeaseReleasePending;
        if(error == Error::None && state_->lease.expiryPending)
            error = Error::LeaseExpiryPending;
    }
    else if(error == Error::None && hasAnyCredentials)
    {
        error = classifyNonCurrentTokenLocked(
            *state_, request.leaseToken);
    }
    // Explicit credentials are classified before CAS checks.  This keeps an
    // expired/stale/unknown token fail-closed even when a caller also carries
    // an old revision; an empty-credential request still gets the normal CAS
    // result below.
    if(error == Error::None && request.expectedLeaseRevision
        != state_->leaseRevision)
    {
        error = Error::StaleLeaseRevision;
    }
    if(error == Error::None && request.expectedMutationSeq
        != state_->mutationSeq)
    {
        error = Error::StaleMutationSequence;
    }
    if(error == Error::None && request.expectedEmergencyEpoch
        != state_->emergencyEpoch)
    {
        error = Error::StaleEmergencyEpoch;
    }
    if(error == Error::None && state_->inFlight.active)
        error = Error::MutationBusy;

    if(error != Error::None)
    {
        result.error = error;
        result.snapshot = snapshotLocked(*state_);
        return result;
    }

    if(!bump(state_->nextPermitId))
    {
        state_->counterExhausted = true;
        result.error = Error::CounterExhausted;
        result.snapshot = snapshotLocked(*state_);
        return result;
    }
    state_->inFlight.active = true;
    state_->inFlight.permitId = state_->nextPermitId;
    state_->inFlight.leaseIncarnation =
        state_->lease.active ? state_->lease.incarnation : 0;
    state_->inFlight.session = request.session;
    state_->inFlight.mutationSeq = state_->mutationSeq;
    state_->inFlight.emergencyEpoch = state_->emergencyEpoch;

    result.snapshot = snapshotLocked(*state_);
    result.permit = MutationPermit(state_, state_->inFlight.permitId);
    return result;
}

OperationResult MutationCoordinator::emergencyInvalidate()
{
    Tick now = 0;
    if(!readClock(state_, now))
        return {Error::ClockFailure};
    std::lock_guard<std::mutex> lock(state_->mutex);
    Error error = prepareLocked(*state_, now);
    if(error == Error::None && !bump(state_->emergencyEpoch))
    {
        state_->counterExhausted = true;
        error = Error::CounterExhausted;
    }
    OperationResult result;
    result.error = error;
    result.snapshot = snapshotLocked(*state_);
    return result;
}

OperationResult MutationCoordinator::replaceSession(
    const SessionIdentity& newSession)
{
    if(!newSession.valid())
        return {Error::InvalidSession};

    Tick now = 0;
    if(!readClock(state_, now))
        return {Error::ClockFailure};
    std::lock_guard<std::mutex> lock(state_->mutex);
    Error error = prepareLocked(*state_, now);
    if(error != Error::None)
        return operationErrorLocked(*state_, error);
    if(newSession == state_->session)
        return operationErrorLocked(*state_, Error::None);
    if(newSession.bridgeInstanceId == state_->session.bridgeInstanceId
        && newSession.generation <= state_->session.generation)
    {
        return operationErrorLocked(
            *state_, Error::StaleSessionGeneration);
    }
    if(!bump(state_->emergencyEpoch))
    {
        state_->counterExhausted = true;
        return operationErrorLocked(*state_, Error::CounterExhausted);
    }
    state_->session = newSession;

    if(state_->lease.active)
    {
        const bool pinned = state_->inFlight.active
            && state_->inFlight.leaseIncarnation
                == state_->lease.incarnation;
        if(pinned)
        {
            state_->lease.sessionInvalidationPending = true;
            state_->lease.releasePending = false;
            state_->lease.expiryPending = false;
            error = bumpLeaseRevisionLocked(*state_);
        }
        else
        {
            error = finalizeLeaseLocked(
                *state_, TombstoneReason::SessionInvalidated);
        }
    }

    OperationResult result;
    result.error = error;
    result.snapshot = snapshotLocked(*state_);
    return result;
}

MutationPermit::MutationPermit(std::shared_ptr<detail::State> state,
                               std::uint64_t permitId) noexcept
    : state_(std::move(state)),
      permitId_(permitId),
      localState_(LocalState::Open)
{
}

MutationPermit::~MutationPermit() noexcept
{
    abandon();
}

MutationPermit::MutationPermit(MutationPermit&& other) noexcept
    : state_(std::move(other.state_)),
      permitId_(other.permitId_),
      localState_(other.localState_)
{
    other.permitId_ = 0;
    other.localState_ = LocalState::Empty;
}

MutationPermit& MutationPermit::operator=(MutationPermit&& other) noexcept
{
    if(this == &other)
        return *this;
    abandon();
    state_ = std::move(other.state_);
    permitId_ = other.permitId_;
    localState_ = other.localState_;
    other.permitId_ = 0;
    other.localState_ = LocalState::Empty;
    return *this;
}

bool MutationPermit::active() const noexcept
{
    return localState_ == LocalState::Open
        && state_ && permitId_ != 0;
}

CommitResult MutationPermit::commit(
    const SessionIdentity& observedSession)
{
    CommitResult result;
    if(localState_ == LocalState::Committed)
    {
        result.error = Error::PermitAlreadyCommitted;
        return result;
    }
    if(!active())
    {
        result.error = Error::PermitNotActive;
        return result;
    }

    Tick now = 0;
    if(!readClock(state_, now))
    {
        std::lock_guard<std::mutex> lock(state_->mutex);
        closePermitLocked(*state_, permitId_, state_->lastObservedAt);
        localState_ = LocalState::Closed;
        result.error = Error::ClockFailure;
        result.snapshot = snapshotLocked(*state_);
        return result;
    }

    std::lock_guard<std::mutex> lock(state_->mutex);
    if(now < state_->lastObservedAt)
    {
        closePermitLocked(*state_, permitId_, state_->lastObservedAt);
        localState_ = LocalState::Closed;
        result.error = Error::ClockRegression;
        result.snapshot = snapshotLocked(*state_);
        return result;
    }
    state_->lastObservedAt = now;

    if(!state_->inFlight.active
        || state_->inFlight.permitId != permitId_)
    {
        localState_ = LocalState::Closed;
        result.error = Error::PermitNotActive;
        result.snapshot = snapshotLocked(*state_);
        return result;
    }

    Error error = Error::None;
    if(state_->counterExhausted)
    {
        error = Error::CounterExhausted;
    }
    else if(!observedSession.valid()
        || observedSession != state_->inFlight.session
        || state_->session != state_->inFlight.session)
    {
        error = Error::SessionChanged;
    }
    else if(state_->emergencyEpoch
        != state_->inFlight.emergencyEpoch)
    {
        error = Error::EmergencyInvalidated;
    }
    else if(state_->inFlight.leaseIncarnation != 0
        && (!state_->lease.active
            || state_->lease.incarnation
                != state_->inFlight.leaseIncarnation))
    {
        error = Error::StaleLeaseToken;
    }
    else if(state_->mutationSeq != state_->inFlight.mutationSeq)
    {
        error = Error::StaleMutationSequence;
    }

    if(error == Error::None && !bump(state_->mutationSeq))
    {
        state_->counterExhausted = true;
        error = Error::CounterExhausted;
    }
    if(error == Error::None)
        result.committedMutationSeq = state_->mutationSeq;

    closePermitLocked(*state_, permitId_, now);
    localState_ = error == Error::None
        ? LocalState::Committed
        : LocalState::Closed;
    result.error = error;
    result.snapshot = snapshotLocked(*state_);
    return result;
}

void MutationPermit::abandon() noexcept
{
    if(!active())
        return;
    try
    {
        Tick now = 0;
        const bool clockOk = readClock(state_, now);
        std::lock_guard<std::mutex> lock(state_->mutex);
        if(!clockOk || now < state_->lastObservedAt)
            now = state_->lastObservedAt;
        else
            state_->lastObservedAt = now;
        closePermitLocked(*state_, permitId_, now);
    }
    catch(...)
    {
        // A C++ destructor may not leak synchronization or clock failures.
        // If std::mutex itself is unusable there is no safe recovery action,
        // but the exception still must not cross this noexcept boundary.
    }
    localState_ = LocalState::Closed;
    permitId_ = 0;
    state_.reset();
}

} // namespace mcpmutation
