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


def test_endpoint_policy_owns_one_short_opening_permit():
    header = read(ARBITER_H)
    state = read(STATE_H)
    source = read(ARBITER_CPP)

    assert "struct EndpointOpeningPermit" in header
    assert "EndpointOpeningPermitOwner owner;" in header
    assert "OpeningPermitTicketOwner" in header
    assert "ProxyConnectionAttempt>" in header
    reserve = function_body(
        source, "bool EndpointAdmissionArbiter::Private::reserveTicketLocked(")
    revalidate = function_body(
        source,
        "void EndpointAdmissionArbiter::Private::revalidateReservationsLocked(")
    assign = function_body(
        source,
        "void EndpointAdmissionArbiter::Private::assignReservationsLocked(")
    boundary = function_body(
        source, "TicketOpeningBoundary OpeningBoundaryForTicket(")
    assert "std::holds_alternative<std::monostate>(permit.owner)" in reserve
    assert "permit.owner = MtProxy::OpeningPermitTicketOwner{" in reserve
    assert "if (std::holds_alternative<std::monostate>(permit.owner))" in assign
    assert ".at = std::max(ticket.notBeforeAt, pressure.retryUntil)" in boundary
    assert "if (boundary.at > inputs.now)" in reserve
    assert reserve.index("if (boundary.at > inputs.now)") < reserve.index(
        "MtProxy::ReserveOpenSlot(")
    assert reserve.index("if (boundary.at > inputs.now)") < reserve.index(
        "permit.owner = MtProxy::OpeningPermitTicketOwner{")
    assert "|| boundary.at > inputs.now" in revalidate
    assert "&& boundary.at <= inputs.now" in assign
    assert assign.index("&& boundary.at <= inputs.now") < assign.index(
        "const auto selected = selectLocked(")
    assert assign.index("if (boundary.at > inputs.now)") < assign.index(
        "if (occupied)")
    delayed_status = assign.split(
        "if (boundary.at > inputs.now)", 1)[1].split("if (occupied)", 1)[0]
    assert "EndpointAdmissionWaitReason::HealthOrNotBefore" in delayed_status
    assert "boundary.at - inputs.now" in delayed_status
    assert "boundary.at" in delayed_status
    assert "std::map<QString, MtProxy::EndpointOpeningPermit> _permits;" in source
    assert "LiveSlot" not in header
    assert "LiveSlot" not in source
    assert "EndpointAdmissionPolicyInput" not in state
    assert "EndpointUseCounts active" not in state
    assert "EndpointUseCounts scheduled" not in state
    assert "EvaluateEndpointAdmission(" not in state


def test_transfer_requires_exact_current_local_main_proof():
    arbiter = function_body(
        read(ARBITER_CPP),
        "bool EndpointAdmissionArbiter::Private::baseEligibleLocked(")

    assert "MtProxy::HasCurrentMainRelayProof(state" in arbiter
    assert "ticket.key.runtimeId" in arbiter
    assert "ticket.proxyGeneration" in arbiter
    assert "EndpointMainRelayProof" not in arbiter
    assert "urgentWaiters" not in arbiter


def test_opening_permit_releases_only_the_exact_attempt():
    header = read(ARBITER_H)
    source = read(ARBITER_CPP)
    release = function_body(
        source, "void EndpointAdmissionArbiter::Private::releaseOpeningPermit(")

    assert "EndpointOpeningPermitOwner" in header
    assert "const auto owner = std::get_if<ProxyConnectionAttempt>" in release
    assert "AttemptOwnerMatches" in release
    assert "permit->second.owner = std::monostate();" in release
    assert "drainEndpointLocked(endpointKey, inputs, actions);" in release
    assert "markTransportReady" not in source
    assert "releaseLiveSlot" not in source
    assert "kHealthyActiveCap" not in source
    assert "mainLaneReserved" not in source


def test_opening_pressure_is_health_owned_and_read_by_the_arbiter():
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
    assert "const auto pressure = MtProxy::OpeningRetryBoundaryFor(state);" in arbiter
    assert ".at = std::max(ticket.notBeforeAt, pressure.retryUntil)" in arbiter
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
            "UrgentMain",
            "OrdinaryMain",
            "Auxiliary",
            "Background"):
        assert name in source
    assert source.index("ForegroundMain,") < source.index("ForegroundTransfer,")
    assert source.index("ForegroundTransfer,") < source.index("UrgentMain,")
    assert source.index("UrgentMain,") < source.index("Auxiliary,")
    compact_priority = compact(priority)
    assert "ticket.use == MtProxy::EndpointUse::Main" in priority
    assert "result = foreground ? PriorityClass::ForegroundMain" in compact_priority
    assert "&& IsTransfer(ticket.use) && hasMainProof" in compact_priority
    assert "result = PriorityClass::ForegroundTransfer;" in priority
    assert "ownsMainRecoveryLocked" not in priority
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
    test_endpoint_policy_owns_one_short_opening_permit()
    test_transfer_requires_exact_current_local_main_proof()
    test_opening_permit_releases_only_the_exact_attempt()
    test_opening_pressure_is_health_owned_and_read_by_the_arbiter()
    test_route_failures_remain_local_until_routes_are_exhausted()
    test_arbiter_prioritizes_and_fairly_ages_endpoint_requests()
