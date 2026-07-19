from pathlib import Path


SOURCE_DIR = Path(__file__).resolve().parents[1]
ARBITER_H = SOURCE_DIR / "mtproto" / "proxy" / "endpoint_admission_arbiter.h"
STATE_H = SOURCE_DIR / "mtproto" / "proxy" / "mtproxy" / "endpoint_health_state.h"
POLICY_CPP = SOURCE_DIR / "mtproto" / "proxy" / "mtproxy" / "endpoint_health_policy.cpp"
HEALTH_CPP = SOURCE_DIR / "mtproto" / "proxy" / "mtproxy" / "endpoint_health.cpp"
ARBITER_CPP = SOURCE_DIR / "mtproto" / "proxy" / "endpoint_admission_arbiter.cpp"


def read(path):
    assert path.exists(), f"missing expected source file: {path}"
    return path.read_text(encoding="utf-8")


def test_endpoint_policy_accounts_for_every_live_slot_phase():
    header = read(ARBITER_H)
    state = read(STATE_H)
    source = read(ARBITER_CPP)

    assert "inline constexpr auto kEndpointLiveSlotCount = 4;" in header
    assert "std::array<EndpointLiveSlot, kEndpointLiveSlotCount>" in header
    for phase in ("Empty", "Reserved", "Opening", "Live", "Closing"):
        assert f"{phase}," in header
    reserve = function_body(
        source, "bool EndpointAdmissionArbiter::Private::reserveTicketLocked(")
    assert "pool.slots[slotIndex].phase != MtProxy::LiveSlotPhase::Empty" in reserve
    assert "slot.phase = MtProxy::LiveSlotPhase::Reserved;" in reserve
    assert "std::map<QString, MtProxy::EndpointLivePool> _pools;" in source
    assert "EndpointAdmissionPolicyInput" not in state
    assert "EndpointUseCounts active" not in state
    assert "EndpointUseCounts scheduled" not in state
    assert "EvaluateEndpointAdmission(" not in state


def test_transfer_requires_current_main_proof_and_yields_to_main_recovery():
    arbiter = function_body(
        read(ARBITER_CPP),
        "bool EndpointAdmissionArbiter::Private::baseEligibleLocked(")

    assert "!urgentWaiters" in arbiter
    assert "MtProxy::HasCurrentMainRelayProof(state" in arbiter
    assert "ticket.key.runtimeId" in arbiter
    assert "ticket.proxyGeneration" in arbiter


def test_fixed_pool_exposes_four_occupied_slot_records():
    header = read(ARBITER_H)
    source = read(ARBITER_CPP)
    ready = function_body(
        source, "void EndpointAdmissionArbiter::Private::markTransportReady(")
    release = function_body(
        source, "void EndpointAdmissionArbiter::Private::releaseLiveSlot(")

    assert "kEndpointLiveSlotCount = 4" in header
    assert "LiveSlotPhase::Opening" in ready
    assert "slot.phase = MtProxy::LiveSlotPhase::Live;" in ready
    assert "slot.incarnation != slotKey.incarnation" in ready
    assert "slot.phase = MtProxy::LiveSlotPhase::Empty;" in release
    assert "AttemptOwnerMatches" in release
    assert "slot.incarnation != slotKey.incarnation" in release
    assert "kHealthyActiveCap" not in source
    assert "mainLaneReserved" not in source


def test_dpi_failures_stay_health_owned_without_capacity_breaker():
    health = function_body(
        read(HEALTH_CPP), "void EndpointHealth::reportFailure(")
    arbiter = read(ARBITER_CPP)

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
    for name in ("UrgentMain", "OrdinaryMain", "ProxyCheck", "Background"):
        assert name in source
    assert "PriorityClass::OrdinaryMain" in priority
    assert "PriorityClass::UrgentMain" in priority
    assert "PriorityIndex(PriorityClass::OrdinaryMain)" in priority
    assert "PriorityIndex(result) - improvement" in priority
    assert "other->sequence < ticket->sequence" in select
    assert "runtimes.upper_bound(last)" in select
    assert "ticket->enqueuedAt < result->enqueuedAt" in select


def compact(text):
    return " ".join(text.split())


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
    test_endpoint_policy_accounts_for_every_live_slot_phase()
    test_transfer_requires_current_main_proof_and_yields_to_main_recovery()
    test_fixed_pool_exposes_four_occupied_slot_records()
    test_dpi_failures_stay_health_owned_without_capacity_breaker()
    test_route_failures_remain_local_until_routes_are_exhausted()
    test_arbiter_prioritizes_and_fairly_ages_endpoint_requests()
