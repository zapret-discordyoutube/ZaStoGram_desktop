from pathlib import Path


SOURCE_DIR = Path(__file__).resolve().parents[1]
POLICY_H = SOURCE_DIR / "mtproto" / "proxy" / "mtproxy" / "endpoint_health_policy.h"
POLICY_CPP = SOURCE_DIR / "mtproto" / "proxy" / "mtproxy" / "endpoint_health_policy.cpp"
STATE_H = SOURCE_DIR / "mtproto" / "proxy" / "mtproxy" / "endpoint_health_state.h"
HEALTH_CPP = SOURCE_DIR / "mtproto" / "proxy" / "mtproxy" / "endpoint_health.cpp"
ARBITER_CPP = SOURCE_DIR / "mtproto" / "proxy" / "endpoint_admission_arbiter.cpp"


def read(path):
    assert path.exists(), f"missing expected source file: {path}"
    return path.read_text(encoding="utf-8")


def test_endpoint_policy_accounts_for_active_and_scheduled_slots():
    header = read(POLICY_H)
    state = read(STATE_H)
    policy = function_body(
        read(POLICY_CPP),
        "EndpointConcurrencyPolicy EvaluateEndpointAdmission(")

    assert "struct EndpointAdmissionPolicyInput" in state
    assert "EndpointUseCounts active;" in state
    assert "EndpointUseCounts scheduled;" in state
    assert "int urgentMainDemand = 0;" in state
    assert "bool mainLaneReserved = false;" in state
    assert "EvaluateEndpointAdmission(" in header
    assert "TotalEndpointUseCount(input.active)" in policy
    assert "+ TotalEndpointUseCount(input.scheduled)" in policy
    assert "policy.admissionAllowed = policy.useAllowed" in policy
    assert "occupied < availableCap" in policy


def test_background_requires_current_main_proof_and_yields_to_urgent_main():
    policy = function_body(
        read(POLICY_CPP),
        "EndpointConcurrencyPolicy EvaluateEndpointAdmission(")
    arbiter = function_body(
        read(ARBITER_CPP),
        "bool EndpointAdmissionArbiter::Private::baseEligibleLocked(")

    assert "input.mainProof != MainRelayProofStrength::None" in compact(policy)
    assert "background && (!hasMainProof || urgentMainDemand > 0)" in compact(policy)
    assert "policy.useAllowed = false;" in policy
    assert "!urgentWaiters" in arbiter
    assert "MtProxy::HasCurrentMainRelayProof(state" in arbiter
    assert "ticket.key.runtimeId" in arbiter
    assert "ticket.proxyGeneration" in arbiter


def test_capacity_two_reserves_one_lane_for_main():
    source = read(POLICY_CPP)
    policy = function_body(
        source, "EndpointConcurrencyPolicy EvaluateEndpointAdmission(")

    assert "kHealthyActiveCap = 1" in source
    assert "kFastHealthyActiveCap = 2" in source
    assert "input.fastWarmup && repeatedMainProof" in policy
    assert "policy.mainLaneReserved = (urgentMainDemand > 0)" in policy
    assert "!candidateIsUrgentMain" in policy
    assert "policy.activeCap - (policy.mainLaneReserved ? 1 : 0)" in compact(policy)


def test_dpi_failures_keep_strict_cap_and_recipe_escalation():
    source = read(POLICY_CPP)
    traits = function_body(source, "FailureTraits TraitsFor(")
    policy = function_body(
        source, "EndpointConcurrencyPolicy EvaluateEndpointAdmission(")

    for reason in (
        "ClientHelloSentNoServerHello",
        "TlsAlertAfterClientHello",
        "ServerHelloHmacMismatch",
    ):
        row = traits.split(
            f"case FailureReason::{reason}:", 1)[1].split(
                "case FailureReason::", 1)[0]
        assert ".escalatesRecipe = true" in row
    assert "FailureNeedsRecipeEscalation(input.lastFailure)" in policy
    assert "policy.activeCap = kDpiFailureActiveCap;" in policy
    assert "policy.recipeEscalationAllowed = true;" in policy


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
    test_capacity_two_reserves_one_lane_for_main()
    test_dpi_failures_keep_strict_cap_and_recipe_escalation()
    test_route_failures_remain_local_until_routes_are_exhausted()
    test_arbiter_prioritizes_and_fairly_ages_endpoint_requests()
