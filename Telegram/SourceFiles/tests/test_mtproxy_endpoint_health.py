from pathlib import Path


SOURCE_DIR = Path(__file__).resolve().parents[1]
ROOT = SOURCE_DIR.parents[1]
MTPROXY_DIR = SOURCE_DIR / "mtproto" / "proxy" / "mtproxy"
HEALTH_H = MTPROXY_DIR / "endpoint_health.h"
HEALTH_CPP = MTPROXY_DIR / "endpoint_health.cpp"
STATE_H = MTPROXY_DIR / "endpoint_health_state.h"
POLICY_CPP = MTPROXY_DIR / "endpoint_health_policy.cpp"
POLICY_H = MTPROXY_DIR / "endpoint_health_policy.h"
CONTEXT_CPP = SOURCE_DIR / "mtproto" / "proxy" / "proxy_endpoint_context.cpp"
ARBITER_CPP = SOURCE_DIR / "mtproto" / "proxy" / "endpoint_admission_arbiter.cpp"
TLS_CPP = MTPROXY_DIR / "tls_socket.cpp"
RESOLVING_CPP = SOURCE_DIR / "mtproto" / "proxy" / "resolving_connection.cpp"


def read(path):
    assert path.exists(), f"missing expected source file: {path}"
    return path.read_text(encoding="utf-8")


def test_endpoint_health_declares_typed_view_and_verdict_contracts():
    header = read(HEALTH_H)
    state = read(STATE_H)
    cmake = read(ROOT / "Telegram" / "CMakeLists.txt")

    for name in (
        "endpoint_health.cpp",
        "endpoint_health.h",
        "endpoint_health_lifecycle.cpp",
        "endpoint_health_policy.cpp",
        "endpoint_health_state.h",
    ):
        assert f"mtproto/proxy/mtproxy/{name}" in cmake
    assert "struct EndpointVerdict" in header
    assert "struct MainRelayProofView" in header
    assert "struct ProxyEndpointView" in header
    assert "RuntimeGenerationKey runtimeGeneration;" in header
    assert "ProxyFailureAttribution attribution" in header
    assert "ProxySchedulerLifecycle schedulerLifecycle" in header
    assert "int recipeLevel" in state
    assert "QString lastDiagnostic" in state
    assert "struct EndpointPhysicalOpeningBoundary" in state
    assert "ProxyConnectionAttempt pressureAttempt;" in state
    assert "FailureReason pressureReason = FailureReason::None;" in state
    assert "crl::time pressureUntil = 0;" in state
    assert "handoffSourceKey" not in state
    assert "handoffUntil" not in state
    assert "EndpointPhysicalOpeningBoundary physicalOpeningBoundary;" in state
    assert "CurrentPhysicalOpeningBoundary(" in read(POLICY_H)
    reader = function_body(read(POLICY_CPP), "CurrentPhysicalOpeningBoundary(")
    assert "state.physicalOpeningBoundary" in reader
    assert "boundary.pressureUntil > now" in reader
    assert "boundary.handoffUntil" not in reader
    assert "canonicalVerdicts" not in reader
    assert "runtime" not in reader
    assert "Snapshot" not in header
    assert "EndpointEvent" not in header


def test_scheduled_attempt_freezes_plan_and_serverhello_budget():
    source = read(HEALTH_CPP)
    begin = function_body(
        source, "EndpointHealth::BeginScheduledAttemptLocked(")

    assert "RuntimeProxyGenerationIsStale(" in begin
    assert "BuildAttemptPlan(request, state.recipeLevel)" in begin
    assert "plan.serverHelloTimeout = ServerHelloTimeoutFor(" in begin
    assert "ProxySchedulerLifecycle::HandedOff" in begin
    assert "ProxyAdmissionPhase::Resolving" in begin
    assert "ProxyConnectionPhase::Resolving" in begin
    assert ".ticketKey = ticketKey" in begin
    assert ".plan = std::move(plan)" in begin


def test_terminal_outcome_is_recorded_once_per_current_attempt():
    source = read(HEALTH_CPP)
    terminal = function_body(source, "RecordTerminalAttemptLocked(")
    failure = function_body(source, "void EndpointHealth::reportFailure(")
    capacity_terminal = function_body(
        read(ARBITER_CPP),
        "void EndpointAdmissionArbiter::Private::markOpeningTerminal(")

    assert "FailureFromStaleAttempt(report, state)" in terminal
    assert "attempt->second.terminalVerdict" in terminal
    assert "return std::nullopt;" in terminal
    assert "attempt.terminalVerdict = verdict;" in terminal
    assert "RecordCurrentTerminalEvidence(" in terminal
    assert "const auto terminal = RecordTerminalAttemptLocked(" in failure
    assert "if (!terminal)" in failure
    assert failure.index("if (!terminal)") < failure.index(
        "state.lastFailure = report.reason;")
    assert "physicalOpeningBoundary" not in failure
    assert "const auto exactOpening" in capacity_terminal
    assert "MtProxy::MarkDialSlotOpeningTerminal(" in capacity_terminal
    assert capacity_terminal.index("if (!reduction.applied)") < (
        capacity_terminal.index("MtProxy::ApplyPhysicalOpeningTerminal("))
    assert "terminalAt" in capacity_terminal
    assert failure.index("if (!terminal)") < failure.index(
        "if (terminal->finalAttemptTerminal")


def test_only_main_without_live_main_proof_can_degrade_canonical_view():
    failure = function_body(
        read(HEALTH_CPP), "void EndpointHealth::reportFailure(")
    canonical = failure.split("const auto canonicalEligible", 1)[1].split(
        "if (canonicalEligible)", 1)[0]

    assert "report.use" in canonical
    assert "EndpointUse::Main" in canonical
    assert "!routeOnly" in canonical
    assert "!alternateRoute" in canonical
    assert "!HasCurrentMainRelayProof(" in canonical
    assert "SetCurrentCanonicalVerdict(" in failure
    assert "ProxyDiagnosticsPhase::CanonicalDegraded" in failure
    assert "report.use == EndpointUse::ProxyCheck" in failure
    probe_tail = failure.split("report.use == EndpointUse::ProxyCheck", 1)[1]
    assert "LogProbeAttemptFailure" in probe_tail


def test_relay_success_is_generation_scoped_and_main_proof_is_typed():
    source = read(HEALTH_CPP)
    success = function_body(source, "void EndpointHealth::reportSuccess(")
    context = function_body(read(CONTEXT_CPP), "ComposeEndpointViewLocked(")

    assert "SuccessFromStaleAttempt(report, state)" in success
    assert "if (report.scope != SuccessScope::Relay)" in success
    assert "CurrentMainRelayProof(" in success
    assert "PromoteRelayProof(" in success
    assert "RefreshRelayProofPayload(" in success
    assert "if (probe)" in success
    assert "RetireRelayProof(state, identity)" in success
    assert "if (report.use == EndpointUse::Main)" in success
    assert "PruneEndpointOutcomesAfterSuccess(" in success
    assert "physicalOpeningBoundary" not in success
    assert "result.mainProof = MtProxy::CurrentMainRelayProof(" in context
    assert "runtimeGeneration" in context


def test_old_generation_reports_are_rejected_before_state_mutation():
    policy = read(POLICY_CPP)
    stale_failure = function_body(policy, "bool FailureFromStaleAttempt(")
    stale_success = function_body(policy, "bool SuccessFromStaleAttempt(")

    for body in (stale_failure, stale_success):
        assert "RuntimeGenerationIsCurrent(state, runtimeGeneration)" in body
        assert "attempt->second.proxyGeneration != report.proxyGeneration" in body
        assert "attempt->second.terminalVerdict.has_value()" in body
        assert "ReportMatchesAttempt(" in body


def test_endpoint_view_rejects_a_mismatched_generation():
    compose = function_body(read(CONTEXT_CPP), "ComposeEndpointViewLocked(")

    assert "generation->second != runtimeGeneration.proxyGeneration" in compose
    mismatch = compose.index(
        "generation->second != runtimeGeneration.proxyGeneration")
    assert compose.index("return result;", mismatch) < compose.index(
        "result.mainProof = MtProxy::CurrentMainRelayProof(")
    assert "state.canonicalVerdicts.find(" in compose
    assert "arbiter.composeEndpointViewLocked(" in compose
    assert "EndpointOpenGateStage" not in compose
    assert "openDeadline" not in compose
    assert "recoveryNextOpenAt" not in compose


def test_tls_socket_owns_one_absolute_serverhello_terminal():
    source = read(TLS_CPP)
    timeout = function_body(source, "void TlsSocket::timedOut()")
    error = function_body(source, "void TlsSocket::handleError(int errorCode)")
    terminal = function_body(source, "bool TlsSocket::finishTerminal(")

    assert "_serverHelloDeadline = now + _mtproxyPlan.serverHelloTimeout;" in source
    assert "_serverHelloTimer.callOnce(_mtproxyPlan.serverHelloTimeout);" in source
    assert "_serverHelloDeadline - now" in source
    assert "finishTerminal(" in timeout
    assert "finishTerminal(" in error
    assert "if (_terminal)" in terminal
    assert "_terminal = true;" in terminal
    assert "_serverHelloTimer.cancel();" in terminal
    assert "_terminalFailure = collectTransportFailure();" in terminal
    assert "reportTransportEvent(" in terminal


def test_resolving_forwards_phase_and_keeps_the_frozen_serverhello_budget():
    source = read(RESOLVING_CPP)
    budget = function_body(
        source, "crl::time ResolvingConnection::fullConnectTimeout() const")
    add_route = function_body(source, "void ResolvingConnection::addRouteAttempt(")
    phase = function_body(source, "HandshakePhase ResolvingConnection::handshakePhase() const")

    assert "_mtproxyPlan.serverHelloTimeout" in budget
    assert "kRouteAttemptTimeout" in budget
    assert budget.count("kOnlyRouteAttemptTimeout") == 3
    assert "kRouteRaceDelay" in budget
    assert "kMaxParallelRouteAttempts" in budget
    assert "+ serverHelloTimeout" in budget
    assert "MergeExhaustedFailure(" in source
    assert "TypedRouteFailure(" in source
    assert "&AbstractConnection::handshakeProgress" in add_route
    assert add_route.index("refreshAttemptTimeout();") < add_route.index(
        "handshakeProgress();")
    assert "_child->handshakePhase()" in phase
    assert "ChildHandshakePhase(attempt.child.get())" in phase


def test_arbiter_handoff_is_the_only_attempt_creation_path():
    arbiter = read(ARBITER_CPP)
    grant = function_body(
        arbiter, "void EndpointAdmissionArbiter::Private::deliverGrant(")

    assert "EndpointHealth::BeginScheduledAttemptLocked(" in grant
    assert "ProxySchedulerLifecycle::Granted" in grant
    assert "ticket.lifecycle = ProxySchedulerLifecycle::HandedOff;" in grant
    assert "takeTicketLocked(key)" in grant


def function_body(text, signature):
    start = text.index(signature)
    brace = text.index("{", start)
    depth = 0
    for index in range(brace, len(text)):
        if text[index] == "{":
            depth += 1
        elif text[index] == "}":
            depth -= 1
            if depth == 0:
                return text[brace + 1:index]
    raise AssertionError(f"function body not found: {signature}")


if __name__ == "__main__":
    test_endpoint_health_declares_typed_view_and_verdict_contracts()
    test_scheduled_attempt_freezes_plan_and_serverhello_budget()
    test_terminal_outcome_is_recorded_once_per_current_attempt()
    test_only_main_without_live_main_proof_can_degrade_canonical_view()
    test_relay_success_is_generation_scoped_and_main_proof_is_typed()
    test_old_generation_reports_are_rejected_before_state_mutation()
    test_endpoint_view_rejects_a_mismatched_generation()
    test_tls_socket_owns_one_absolute_serverhello_terminal()
    test_resolving_forwards_phase_and_keeps_the_frozen_serverhello_budget()
    test_arbiter_handoff_is_the_only_attempt_creation_path()
