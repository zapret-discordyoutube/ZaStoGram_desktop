from pathlib import Path


SOURCE_DIR = Path(__file__).resolve().parents[1]
ROOT = SOURCE_DIR.parents[1]
ARBITER_H = SOURCE_DIR / "mtproto" / "proxy" / "endpoint_admission_arbiter.h"
LIVE_POOL_H = SOURCE_DIR / "mtproto" / "proxy" / "endpoint_live_pool.h"
LIVE_POOL_CPP = SOURCE_DIR / "mtproto" / "proxy" / "endpoint_live_pool.cpp"
STATE_H = SOURCE_DIR / "mtproto" / "proxy" / "mtproxy" / "endpoint_health_state.h"
POLICY_CPP = SOURCE_DIR / "mtproto" / "proxy" / "mtproxy" / "endpoint_health_policy.cpp"
HEALTH_CPP = SOURCE_DIR / "mtproto" / "proxy" / "mtproxy" / "endpoint_health.cpp"
ARBITER_CPP = SOURCE_DIR / "mtproto" / "proxy" / "endpoint_admission_arbiter.cpp"


def read(path):
    assert path.exists(), f"missing expected source file: {path}"
    return path.read_text(encoding="utf-8")


def test_endpoint_policy_owns_a_separate_four_slot_reducer():
    cmake = read(ROOT / "Telegram" / "CMakeLists.txt")
    header = read(ARBITER_H)
    pool_header = read(LIVE_POOL_H)
    pool_source = read(LIVE_POOL_CPP)
    state = read(STATE_H)
    source = read(ARBITER_CPP)

    assert "mtproto/proxy/endpoint_live_pool.cpp" in cmake
    assert "mtproto/proxy/endpoint_live_pool.h" in cmake
    assert "inline constexpr auto kEndpointLiveSlotCount = 4;" in pool_header
    assert "std::array<EndpointLiveSlot, kEndpointLiveSlotCount> slots;" in (
        pool_header)
    for phase in ("Empty", "Reserved", "Opening", "Live", "Closing"):
        assert phase in function_body(pool_header, "enum class LiveSlotPhase")
    assert "std::optional<EndpointOpeningOwner> opening;" in pool_header
    assert "std::optional<CapacityProbe> capacityProbe;" in pool_header
    assert "std::optional<EndpointReclaim> reclaim;" in pool_header
    assert "OpenSlotSchedule openings;" in pool_header
    assert "QPointer" not in pool_header
    assert "Fn<" not in pool_header
    assert "QMutexLocker" not in pool_source
    assert '#include "mtproto/proxy/endpoint_live_pool.h"' in header
    assert "std::map<QString, MtProxy::EndpointLivePool> _pools;" in source
    assert "EndpointOpeningPermit" not in header
    assert "_permits" not in source
    reserve = function_body(
        pool_source, "LiveSlotReserveReduction ReserveLiveSlot(")
    boundary = function_body(
        source, "TicketOpeningBoundary OpeningBoundaryForTicket(")
    assert "ReservationWaitReason(result.pool, request)" in reserve
    assert "FirstEmptySlot(result.pool)" in reserve
    assert "ReserveOpenSlot(" in reserve
    assert "NextIncarnation(" in reserve
    assert "LiveSlotPhase::Reserved" in reserve
    assert "result.pool.opening = request.owner;" in reserve
    assert ".at = ticket.notBeforeAt" in boundary
    assert "OpeningRetryBoundaryFor" not in boundary
    assert "openingPressure" not in boundary
    assert "EndpointAdmissionPolicyInput" not in state
    assert "EndpointUseCounts active" not in state
    assert "EndpointUseCounts scheduled" not in state
    assert "EvaluateEndpointAdmission(" not in state


def test_transfer_uses_exact_proof_or_one_shot_continuation():
    arbiter = function_body(
        read(ARBITER_CPP),
        "auto EndpointAdmissionArbiter::Private::transferAdmissionBasisLocked(")

    assert "DemandTransferContinuationMatches(" in arbiter
    assert arbiter.index("DemandTransferContinuationMatches(") < arbiter.index(
        "MtProxy::HasCurrentMainRelayProof(state")
    assert "DemandTransferContinuationStage::Released" in arbiter
    assert "TransferAdmissionBasis::ReleasedContinuation" in arbiter
    assert "TransferAdmissionBasis::MainRelayProof" in arbiter
    assert "TransferAdmissionBasis::None" in arbiter
    assert "MtProxy::HasCurrentMainRelayProof(state" in arbiter
    assert "ticket.key.runtimeId" in arbiter
    assert "ticket.proxyGeneration" in arbiter
    assert "EndpointMainRelayProof" not in arbiter
    assert "urgentWaiters" not in arbiter
    source = read(ARBITER_CPP)
    assert "baseEligibleLocked" not in source
    assert "mainRelayProven" not in source


def test_released_continuation_owns_selection_until_foreground_main_override():
    assign = function_body(
        read(ARBITER_CPP),
        "void EndpointAdmissionArbiter::Private::assignReservationsLocked(")

    released = assign.split("auto releasedSuccessor", 1)[1].split(
        "auto eligible", 1)[0]
    assert "DemandTransferContinuationStage::Released" in released
    assert "ticket->use == MtProxy::EndpointUse::Main" in released
    assert "ticket->key.runtimeId == _storage.foregroundRuntimeId" in released
    assert "ticketCurrentLocked(*ticket, state)" in released
    assert "boundary.at <= inputs.now" in released
    assert "MtProxy::CancelLiveSlotSuccessor(" in released
    assert released.index("MtProxy::CancelLiveSlotSuccessor(") < released.index(
        "releasedSuccessor.reset();")
    assert "std::remove_if(" in released
    assert "DemandTransferContinuationMatches(" in released
    assert "const auto selected = foregroundOverride" in assign


def test_physical_slot_releases_only_the_exact_incarnation_and_attempt():
    pool_source = read(LIVE_POOL_CPP)
    arbiter = read(ARBITER_CPP)
    release = function_body(
        pool_source, "LiveSlotReleaseReduction ReleaseLiveSlot(")
    authorization = function_body(
        pool_source, "auto AuthorizeLiveSlotReclaim(")
    reclaim_action = function_body(arbiter, "void ReclaimAction::run()")
    forwarding = function_body(
        arbiter, "void EndpointAdmissionArbiter::Private::releaseLiveSlot(")

    assert "auto slot = FindSlot(result.pool, request.key);" in release
    assert "AttemptOwnerMatches(*owner, request.attempt)" in release
    assert "LiveSlotPhase::Opening" in release
    assert "LiveSlotPhase::Live" in release
    assert "LiveSlotPhase::Closing" in release
    assert release.index("slot->phase = LiveSlotPhase::Closing;") < (
        release.index("slot->phase = LiveSlotPhase::Empty;"))
    assert "ResetLearningIfEmpty(result.pool);" in release
    assert "DemandTransferContinuationStage::AwaitingRelease" in release
    assert "EndpointReclaimStage::Requested" in authorization
    assert "EndpointReclaimStage::Authorized" in authorization
    assert "slot->phase != LiveSlotPhase::Closing" in authorization
    assert "slot->phase = LiveSlotPhase::Live;" in authorization
    assert "request.attempt.runtimeId != request.foregroundRuntimeId" in (
        authorization)
    assert "ReclaimMatchesContinuation(" in authorization
    assert "QMutexLocker" not in reclaim_action
    assert reclaim_action.index("authorizeLiveSlotReclaim(") < (
        reclaim_action.index("(*callback)(slotKey, purpose);"))
    assert "callbackReady" in reclaim_action
    assert "reclaimToken" in reclaim_action
    assert "std::shared_ptr<Fn<void(" in arbiter
    assert "lastIncarnation" not in release
    assert "MtProxy::ReleaseLiveSlot(" in forwarding
    assert "if (reduction.slotReleased)" in forwarding
    assert forwarding.index("if (reduction.slotReleased)") < forwarding.index(
        "_slotBindings.erase(slotKey);")
    assert forwarding.count("_slotBindings.erase(slotKey);") == 1
    assert "reduction.continuationChanged" in forwarding
    assert "bool slotReleased = false;" in read(LIVE_POOL_H)
    assert "bool continuationChanged = false;" in read(LIVE_POOL_H)
    assert "_pools.erase" not in arbiter
    assert "markTransportReady" not in arbiter
    assert "kHealthyActiveCap" not in arbiter
    assert "mainLaneReserved" not in arbiter


def test_main_replacement_prefers_foreground_then_demand_bootstrap():
    source = read(ARBITER_CPP)
    pool_source = read(LIVE_POOL_CPP)
    header = read(LIVE_POOL_H)
    candidate = function_body(
        source,
        "EndpointAdmissionArbiter::Private::mainReplacementCandidateLocked(")
    reducer = function_body(
        pool_source,
        "LiveSlotCloseReduction PlanMainReplacement(")

    purposes = function_body(header, "enum class MainReplacementPurpose")
    assert purposes.index("ForegroundRecovery") < purposes.index(
        "DemandBootstrap") < purposes.index("BackgroundDuty")
    assert candidate.index("ForegroundRecovery") < candidate.index(
        "DemandBootstrap") < candidate.index("BackgroundDuty")
    assert "OpeningBoundaryForTicket(ticket).at > now" in candidate
    assert "TransferAdmissionBasis::None" in candidate
    assert "MainReplacementPurpose::ForegroundRecovery" in reducer
    assert "MainReplacementPurpose::BackgroundDuty" in reducer
    assert "request.facts.admissibleTransferWaiting" in reducer
    assert "request.facts.transferActive" in reducer
    assert "owner->attempt.runtimeId" in pool_source
    assert "request.successor.key.runtimeId" in pool_source


def test_opening_pressure_remains_health_owned_but_not_an_admission_gate():
    health = function_body(
        read(HEALTH_CPP), "void EndpointHealth::reportFailure(")
    arbiter = read(ARBITER_CPP)

    assert "struct EndpointOpeningPressure" in read(STATE_H)
    assert "OpeningRetryBoundaryFor(" in read(POLICY_CPP)
    assert "return state.openingPressure;" in read(POLICY_CPP)
    assert "terminal->finalAttemptTerminal" in health
    assert "FailureReason::ClientHelloSentNoServerHello" in health
    assert "state.openingPressure.retryUntil" in health
    assert "state.openingPressure = {" in health
    assert "OpeningRetryBoundaryFor(" not in arbiter
    assert "openingPressure" not in arbiter
    boundary = function_body(
        arbiter, "TicketOpeningBoundary OpeningBoundaryForTicket(")
    assert ".at = ticket.notBeforeAt" in boundary
    assert "report.routesExhausted" in health
    assert "FailureNeedsRecipeEscalation(report.reason)" in health
    assert "state.recipeFailureStreak" in health
    for deleted in (
        "PressureFailure",
        "kPressureWindow",
        "kOpenDelays",
        "EndpointOpenGateStage",
        "applyOpeningEventLocked",
    ):
        assert deleted not in arbiter


def test_route_failures_remain_local_until_routes_are_exhausted():
    policy_source = read(POLICY_CPP)
    traits = function_body(policy_source, "FailureTraits TraitsFor(")
    failure = function_body(
        read(HEALTH_CPP), "void EndpointHealth::reportFailure(")

    for reason in ("TcpConnectTimeout", "TcpConnectedNoClientHelloWrite"):
        row = traits.split(
            f"case FailureReason::{reason}:", 1)[1].split(
                "case FailureReason::", 1)[0]
        assert ".routeOnly = true" in row
    assert "NoteRouteFailure(" in failure
    assert "report.endpoint.route" in failure
    assert "report.reason" in failure
    assert "FailureIsRouteOnly(report.reason)" in failure
    assert "!report.routesExhausted" in failure


def test_arbiter_prioritizes_and_fairly_ages_endpoint_requests():
    source = read(ARBITER_CPP)
    priority = function_body(
        source, "PriorityClass EndpointAdmissionArbiter::Private::priorityForLocked(")
    select = function_body(
        source, "Ticket *EndpointAdmissionArbiter::Private::selectLocked(")

    assert "kAgingStep = crl::time(15 * 1000)" in source
    for name in (
            "ForegroundMain",
            "ForegroundTransfer",
            "DemandedTransfer",
            "UrgentMain",
            "OrdinaryMain",
            "Auxiliary",
            "Background",
            "ReclaimedMainResume"):
        assert name in source
    assert source.index("ForegroundMain,") < source.index("ForegroundTransfer,")
    assert source.index("ForegroundTransfer,") < source.index(
        "DemandedTransfer,")
    assert source.index("DemandedTransfer,") < source.index("UrgentMain,")
    assert source.index("UrgentMain,") < source.index("Auxiliary,")
    assert source.index("Background,") < source.index("ReclaimedMainResume,")
    foreground = priority.index(
        "ticket.use == MtProxy::EndpointUse::Main && foreground")
    resume = priority.index(
        "ticket.purpose == MtProxy::AdmissionPurpose::ReclaimedMainResume")
    aging = priority.index("const auto age =")
    assert foreground < resume < aging
    assert priority.index("return PriorityClass::ForegroundMain;") < (
        priority.index("return PriorityClass::ReclaimedMainResume;"))
    assert resume < aging
    assert "return PriorityClass::ReclaimedMainResume;" in priority
    assert "ticket.use == MtProxy::EndpointUse::Main" in priority
    assert "IsTransfer(ticket.use)" in priority
    assert "transferAdmissionBasis" in priority
    assert "PriorityClass::ForegroundTransfer" in priority
    assert "PriorityClass::DemandedTransfer" in priority
    assert "ownsMainRecoveryLocked" not in priority
    assert "PriorityClass::OrdinaryMain" in priority
    assert "PriorityClass::UrgentMain" in priority
    assert "PriorityIndex(PriorityClass::OrdinaryMain)" in priority
    assert "PriorityIndex(result) - improvement" in priority
    recovery = function_body(
        source,
        "bool EndpointAdmissionArbiter::Private::ownsMainRecoveryLocked(")
    assert "AdmissionPurpose::ReclaimedMainResume" in recovery
    assert "return false;" in recovery.split(
        "AdmissionPurpose::ReclaimedMainResume", 1)[1]
    assert "other->sequence < ticket->sequence" in select
    assert "runtimes.upper_bound(last)" in select
    assert "ticket->enqueuedAt < result->enqueuedAt" in select

def function_body(text: str, signature: str) -> str:
    start = text.index(signature)
    brace = text.index(" {\n", start) + 1
    depth = 0
    for index in range(brace, len(text)):
        char = text[index]
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return text[brace + 1:index]
    raise AssertionError(f"body not found for {signature}")


if __name__ == "__main__":
    test_endpoint_policy_owns_a_separate_four_slot_reducer()
    test_transfer_uses_exact_proof_or_one_shot_continuation()
    test_released_continuation_owns_selection_until_foreground_main_override()
    test_physical_slot_releases_only_the_exact_incarnation_and_attempt()
    test_main_replacement_prefers_foreground_then_demand_bootstrap()
    test_opening_pressure_remains_health_owned_but_not_an_admission_gate()
    test_route_failures_remain_local_until_routes_are_exhausted()
    test_arbiter_prioritizes_and_fairly_ages_endpoint_requests()
