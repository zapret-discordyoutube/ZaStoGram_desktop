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


def test_endpoint_policy_accounts_for_active_and_scheduled_slots():
    header = read(ARBITER_H)
    state = read(STATE_H)
    source = read(ARBITER_CPP)

    assert "inline constexpr auto kEndpointOpeningPermitCount = 4;" in header
    assert "std::optional<EndpointOpeningPermit>" in header
    assert "OpeningAdmissionDecision" in header
    assert "while (freePermitLocked(gate) >= 0)" in source
    assert "assignPermitLocked(" in source
    assert "EndpointAdmissionPolicyInput" not in state
    assert "EndpointUseCounts active" not in state
    assert "EndpointUseCounts scheduled" not in state
    assert "EvaluateEndpointAdmission(" not in state


def test_background_requires_current_main_proof_and_yields_to_urgent_main():
    arbiter = function_body(
        read(ARBITER_CPP),
        "bool EndpointAdmissionArbiter::Private::baseEligibleLocked(")

    assert "!urgentWaiters" in arbiter
    assert "MtProxy::HasCurrentMainRelayProof(state" in arbiter
    assert "ticket.key.runtimeId" in arbiter
    assert "ticket.proxyGeneration" in arbiter


def test_closed_gate_exposes_four_opening_permits():
    header = read(ARBITER_H)
    source = read(ARBITER_CPP)
    decision = function_body(
        source,
        "EndpointAdmissionArbiter::Private::openingAdmissionDecisionLocked(")

    assert "kEndpointOpeningPermitCount = 4" in header
    assert "case MtProxy::EndpointOpenGateStage::Closed:" in decision
    assert "freePermitLocked(current) >= 0" in decision
    assert "ticket.key.runtimeId == request.requester.runtimeId" in decision
    assert "ticket.proxyGeneration" in decision
    assert "request.requester.proxyGeneration" in decision
    assert "while (freePermitLocked(gate) >= 0)" in source
    assert "kHealthyActiveCap" not in source
    assert "mainLaneReserved" not in source


def test_dpi_failures_keep_strict_cap_and_recipe_escalation():
    health = function_body(
        read(HEALTH_CPP), "void EndpointHealth::reportFailure(")
    arbiter = function_body(
        read(ARBITER_CPP),
        "EndpointAdmissionArbiter::Private::applyOpeningEventLocked(\n"
        "\t\tconst MtProxy::PressureFailure &event,")

    assert "report.routesExhausted" in health
    assert "FailureReason::ClientHelloSentNoServerHello" in health
    assert "pressureFailure = PressureFailure{" in health
    assert "state.recipeFailureStreak" in health
    assert "kPressureWindow = crl::time(12 * 1000)" in read(ARBITER_CPP)
    assert "gate.pressureWindow.size() >= 3 && flows.size() >= 2" in arbiter
    assert "TlsAlertAfterClientHello" not in arbiter
    assert "ServerHelloHmacMismatch" not in arbiter


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
    test_endpoint_policy_accounts_for_active_and_scheduled_slots()
    test_background_requires_current_main_proof_and_yields_to_urgent_main()
    test_closed_gate_exposes_four_opening_permits()
    test_dpi_failures_keep_strict_cap_and_recipe_escalation()
    test_route_failures_remain_local_until_routes_are_exhausted()
    test_arbiter_prioritizes_and_fairly_ages_endpoint_requests()
