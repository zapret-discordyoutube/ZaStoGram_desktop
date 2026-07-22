from pathlib import Path


SOURCE_DIR = Path(__file__).resolve().parents[1]
ROOT = SOURCE_DIR.parents[1]
ARBITER_H = SOURCE_DIR / "mtproto" / "proxy" / "endpoint_admission_arbiter.h"
DIAL_GATE_H = SOURCE_DIR / "mtproto" / "proxy" / "endpoint_dial_gate.h"
DIAL_GATE_CPP = SOURCE_DIR / "mtproto" / "proxy" / "endpoint_dial_gate.cpp"
STATE_H = SOURCE_DIR / "mtproto" / "proxy" / "mtproxy" / "endpoint_health_state.h"
POLICY_CPP = SOURCE_DIR / "mtproto" / "proxy" / "mtproxy" / "endpoint_health_policy.cpp"
HEALTH_CPP = SOURCE_DIR / "mtproto" / "proxy" / "mtproxy" / "endpoint_health.cpp"
ARBITER_CPP = SOURCE_DIR / "mtproto" / "proxy" / "endpoint_admission_arbiter.cpp"


def read(path):
    assert path.exists(), f"missing expected source file: {path}"
    return path.read_text(encoding="utf-8")


def test_endpoint_policy_owns_a_single_opening_gate():
    cmake = read(ROOT / "Telegram" / "CMakeLists.txt")
    header = read(ARBITER_H)
    pool_header = read(DIAL_GATE_H)
    pool_source = read(DIAL_GATE_CPP)
    state = read(STATE_H)
    source = read(ARBITER_CPP)

    assert "mtproto/proxy/endpoint_dial_gate.cpp" in cmake
    assert "mtproto/proxy/endpoint_dial_gate.h" in cmake
    assert "EndpointDialSlot slot;" in pool_header
    for phase in ("Empty", "Reserved", "Opening"):
        assert phase in function_body(pool_header, "enum class DialSlotPhase")
    for phase in ("Live", "Closing"):
        assert phase not in function_body(pool_header, "enum class DialSlotPhase")
    assert "OpenSlotSchedule openings;" in pool_header
    assert "QPointer" not in pool_header
    assert "Fn<" not in pool_header
    assert "QMutexLocker" not in pool_source
    assert '#include "mtproto/proxy/endpoint_dial_gate.h"' in header
    assert "std::map<QString, MtProxy::EndpointDialGate> _dialGates;" in source
    assert "EndpointOpeningPermit" not in header
    assert "_permits" not in source
    reserve = function_body(
        pool_source, "DialSlotReserveReduction ReserveDialSlot(")
    boundary = function_body(
        source, "TicketOpeningBoundary OpeningBoundaryForTicket(")
    assert "ReservationWaitReason(result.gate)" in reserve
    assert "ReserveOpenSlot(" in reserve
    assert "NextIncarnation(" in reserve
    assert "DialSlotPhase::Reserved" in reserve
    assert "result.gate.slot" in reserve
    assert "EndpointUse" not in pool_header
    assert "RuntimeGenerationKey" not in pool_header
    assert ".at = ticket.notBeforeAt" in boundary
    assert "CurrentPhysicalOpeningBoundary(" in boundary
    assert "physical.retryUntil > result.at" in boundary
    assert "EndpointAdmissionPolicyInput" not in state
    assert "EndpointUseCounts active" not in state
    assert "EndpointUseCounts scheduled" not in state
    assert "EvaluateEndpointAdmission(" not in state


def test_transfer_admission_does_not_depend_on_main_proof():
    source = read(ARBITER_CPP)
    priority = function_body(
        source, "PriorityClass EndpointAdmissionArbiter::Private::priorityForLocked(")
    assert "IsTransfer(ticket.use)" in priority
    assert "PriorityClass::ForegroundTransfer" in priority
    assert "PriorityClass::DemandedTransfer" in priority
    for legacy in (
            "TransferAdmissionBasis",
            "DemandTransferContinuation",
            "transferAdmissionBasisLocked"):
        assert legacy not in source


def test_reservation_selection_has_no_reclaim_continuation():
    assign = function_body(
        read(ARBITER_CPP),
        "void EndpointAdmissionArbiter::Private::assignReservationsLocked(")

    assert "const auto selected = selectLocked(" in assign
    assert "reserveTicketLocked(" in assign
    assert "PlanDemandTransferReservation" not in assign
    assert "releasedSuccessor" not in assign
    assert "reclaim" not in assign.lower()


def test_physical_slot_releases_only_the_exact_incarnation_and_attempt():
    pool_source = read(DIAL_GATE_CPP)
    arbiter = read(ARBITER_CPP)
    release = function_body(
        pool_source, "DialSlotReleaseReduction ReleaseDialSlot(")
    forwarding = function_body(
        arbiter, "void EndpointAdmissionArbiter::Private::releaseDialSlot(")

    assert "auto slot = FindSlot(result.gate, request.key);" in release
    assert "AttemptOwnerMatches(*owner, request.attempt)" in release
    assert "DialSlotPhase::Opening" in release
    assert "DialSlotPhase::Live" not in release
    assert "DialSlotPhase::Closing" not in release
    assert "slot->phase = DialSlotPhase::Empty;" in release
    assert "AuthorizeLiveSlotReclaim" not in pool_source
    assert "ReclaimAction" not in arbiter
    assert "lastIncarnation" not in release
    assert "MtProxy::ReleaseDialSlot(" in forwarding
    assert "if (!reduction.slotReleased)" in forwarding
    assert "bool slotReleased = false;" in read(DIAL_GATE_H)
    assert "continuationChanged" not in read(DIAL_GATE_H)
    assert "_dialGates.erase" not in arbiter
    assert "markTransportReady" not in arbiter
    assert "kHealthyActiveCap" not in arbiter
    assert "mainLaneReserved" not in arbiter


def test_live_connection_replacement_is_not_part_of_admission():
    source = read(ARBITER_CPP)
    pool_source = read(DIAL_GATE_CPP)
    header = read(DIAL_GATE_H)
    for legacy in (
            "MainReplacementPurpose",
            "PlanMainReplacement",
            "mainReplacementCandidateLocked",
            "EndpointReclaim",
            "CapacityProbe"):
        assert legacy not in source
        assert legacy not in pool_source
        assert legacy not in header


def test_physical_opening_boundary_is_freshly_applied_by_admission():
    health = function_body(
        read(HEALTH_CPP), "void EndpointHealth::reportFailure(")
    arbiter = read(ARBITER_CPP)

    assert "struct EndpointPhysicalOpeningBoundary" in read(STATE_H)
    assert "CurrentPhysicalOpeningBoundary(" in read(POLICY_CPP)
    assert "state.physicalOpeningBoundary" in read(POLICY_CPP)
    assert "terminal->finalAttemptTerminal" in health
    assert "physicalOpeningBoundary" not in health
    assert "ApplyPhysicalOpeningTerminal(" in arbiter
    assert "ApplyPostReclaimOpeningHandoff(" not in arbiter
    assert "ApplyPhysicalOpeningRelay(" in arbiter
    boundary = function_body(
        arbiter, "TicketOpeningBoundary OpeningBoundaryForTicket(")
    assert ".at = ticket.notBeforeAt" in boundary
    assert "CurrentPhysicalOpeningBoundary(" in boundary
    assert "physical.retryUntil > result.at" in boundary
    assert arbiter.count("OpeningBoundaryForTicket(") >= 6
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
            "Background"):
        assert name in source
    assert source.index("ForegroundMain,") < source.index("ForegroundTransfer,")
    assert source.index("ForegroundTransfer,") < source.index(
        "DemandedTransfer,")
    assert source.index("DemandedTransfer,") < source.index("UrgentMain,")
    assert source.index("UrgentMain,") < source.index("Auxiliary,")
    foreground = priority.index(
        "ticket.use == MtProxy::EndpointUse::Main && foreground")
    aging = priority.index("const auto age =")
    assert foreground < aging
    assert "ticket.use == MtProxy::EndpointUse::Main" in priority
    assert "IsTransfer(ticket.use)" in priority
    assert "transferAdmissionBasis" not in priority
    assert "PriorityClass::ForegroundTransfer" in priority
    assert "PriorityClass::DemandedTransfer" in priority
    assert "ownsMainRecoveryLocked" not in priority
    assert "ownsMainRecoveryLocked" in select
    assert "PriorityClass::OrdinaryMain" in priority
    assert "PriorityClass::UrgentMain" in priority
    assert "PriorityIndex(PriorityClass::OrdinaryMain)" in priority
    assert "PriorityIndex(result) - improvement" in priority
    assert "AdmissionPurpose" not in source
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
    test_endpoint_policy_owns_a_single_opening_gate()
    test_transfer_admission_does_not_depend_on_main_proof()
    test_reservation_selection_has_no_reclaim_continuation()
    test_physical_slot_releases_only_the_exact_incarnation_and_attempt()
    test_live_connection_replacement_is_not_part_of_admission()
    test_physical_opening_boundary_is_freshly_applied_by_admission()
    test_route_failures_remain_local_until_routes_are_exhausted()
    test_arbiter_prioritizes_and_fairly_ages_endpoint_requests()
