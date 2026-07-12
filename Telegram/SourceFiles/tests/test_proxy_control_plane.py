from pathlib import Path
from session_private_sources import read_session_private_sources


SOURCE_DIR = Path(__file__).resolve().parents[1]
ROOT = SOURCE_DIR.parents[1]
PROXY_DIR = SOURCE_DIR / "mtproto" / "proxy"
CONTROL_H = PROXY_DIR / "control_plane.h"
CONTROL_CPP = PROXY_DIR / "control_plane.cpp"
BROKER_CPP = PROXY_DIR / "connection_broker.cpp"
ARBITER_CPP = PROXY_DIR / "endpoint_admission_arbiter.cpp"
HEALTH_CPP = PROXY_DIR / "mtproxy" / "endpoint_health.cpp"
HEALTH_H = PROXY_DIR / "mtproxy" / "endpoint_health.h"
TLS_CPP = PROXY_DIR / "mtproxy" / "tls_socket.cpp"
RESOLVING_CPP = PROXY_DIR / "resolving_connection.cpp"
ADAPTER_CPP = PROXY_DIR / "session_proxy_adapter.cpp"


def read(path):
    assert path.exists(), f"missing expected source file: {path}"
    return path.read_text(encoding="utf-8")


def test_control_plane_publishes_composed_mtproxy_views():
    cmake = read(ROOT / "Telegram" / "CMakeLists.txt")
    header = read(CONTROL_H)
    source = read(CONTROL_CPP)

    assert "mtproto/proxy/control_plane.cpp" in cmake
    assert "mtproto/proxy/control_plane.h" in cmake
    assert "class ProxyControlPlane final" in header
    assert "submitFact(const ProxyEventReport &report)" in header
    assert "mtproxyEndpointView(" in header
    assert "mtproxyEndpointViewChanges()" in header
    assert "mtproxyEndpointRetryUntil(" in header
    assert "admit(ProxyAdmissionRequest request)" not in header
    assert "endpointViewChanges(" in source
    assert "invalidateMtproxyEndpointView(" in source
    assert "flushMtproxyEndpointViews()" in source


def test_selected_mtproxy_projection_has_strict_truth_priority():
    source = read(CONTROL_CPP)
    projection = function_body(
        source, "void ProxyControlPlane::updateSelectedMtproxyProjection(")

    proof = projection.index("if (hasMainProof)")
    network = projection.index("ActiveMainNetworkFact(view")
    admission = projection.index("view.admissionPhase != ProxyAdmissionPhase::Idle")
    verdict = projection.index("view.canonicalVerdict")
    assert proof < network < admission < verdict
    assert "status.phase = ProxyConnectionPhase::Connected;" in projection
    assert "ProxyAdmissionPhase::Queued" in projection
    assert "ProxyAdmissionPhase::Scheduled" in projection
    assert "status.phase = ProxyConnectionPhase::Failed;" in projection
    assert "status.terminalUntil = view.retryUntil;" in projection


def test_only_exact_current_main_network_fact_overlays_the_view():
    source = read(CONTROL_CPP)
    active = function_body(source, "bool ActiveMainNetworkFact(")
    view = function_body(
        source, "MtProxy::ProxyEndpointView ProxyControlPlane::mtproxyEndpointView(")

    assert "view.mainAttempt.attemptId" in active
    assert "attempt.runtimeId == view.runtimeGeneration.runtimeId" in active
    assert "attempt.proxyGeneration" in active
    assert "attempt.use == ProxyConnectionUse::Main" in active
    assert "attempt.ticketKey == view.mainAttempt.ticketKey" in active
    assert "ActiveMainNetworkFact(result, i->second.status)" in view
    assert "result.networkPhase = i->second.status.phase;" in view


def test_raw_reducer_rejects_probe_and_stale_generation_facts():
    source = read(CONTROL_CPP)
    reduce = function_body(
        source, "ProxyConnectionStatus ProxyControlPlane::Reduce(")
    update = function_body(source, "ProxyConnectionStatus ApplySelectedStatusUpdate(")

    assert "IsProxyCheck(fact.status.attempt.use)" in reduce
    assert "return current;" in reduce.split(
        "IsProxyCheck(fact.status.attempt.use)", 1)[1].split("}", 1)[0]
    assert "IsOlderProxyGeneration(current.attempt, update.attempt)" in update
    assert "IsOlderAttempt(current.attempt, update.attempt)" in update
    assert "NonMtproxyRelaySuccessIsFresh(current)" in update
    assert "kNonMtproxyFreshRelaySuccessWindow" in source


def test_admission_is_owned_by_shared_arbiter_not_control_plane():
    broker = read(BROKER_CPP)
    arbiter = read(ARBITER_CPP)

    assert "endpointAdmissionArbiter().enqueue(" in broker
    assert "control().admit(" not in broker
    assert "std::map<AdmissionTicketKey, std::unique_ptr<Ticket>> _tickets;" in arbiter
    assert "ProxySchedulerLifecycle::Queued" in arbiter
    assert "ProxySchedulerLifecycle::Scheduled" in arbiter
    assert "ProxySchedulerLifecycle::Granted" in arbiter
    assert "ProxySchedulerLifecycle::HandedOff" in arbiter
    assert "ProxySchedulerLifecycle::Cancelled" in arbiter


def test_tls_socket_owns_serverhello_timeout_and_one_terminal_path():
    source = read(TLS_CPP)
    timeout = function_body(source, "void TlsSocket::handleServerHelloTimeout()")
    terminal = function_body(source, "bool TlsSocket::finishTerminal(")

    assert "_serverHelloDeadline" in timeout
    assert "_serverHelloDeadline - now" in timeout
    assert "finishTerminal(" in timeout
    assert "if (_terminal)" in terminal
    assert "_terminal = true;" in terminal
    assert "_serverHelloTimer.cancel();" in terminal
    assert "_terminalFailure = collectTransportFailure();" in terminal
    assert "reportTransportEvent(" in terminal


def test_resolving_wrapper_keeps_typed_route_and_full_cycle_boundaries():
    source = read(RESOLVING_CPP)
    budget = function_body(
        source, "crl::time ResolvingConnection::fullConnectTimeout() const")

    assert "TypedRouteFailure(" in source
    assert "MergeExhaustedFailure(" in source
    assert "_mtproxyPlan.serverHelloTimeout" in budget
    assert "kRouteAttemptTimeout" in budget
    assert "kOnlyRouteAttemptTimeout" in budget
    assert "kFullConnectTimeoutSafetyMargin" in budget


def test_session_receive_timeout_reports_stage_specific_terminal():
    session = read_session_private_sources()
    adapter = read(ADAPTER_CPP)
    receive = function_body(
        adapter, "void ProductionSessionProxyPort::reportReceiveTimeout(")

    assert "kMtproxyMinReceiveTimeout = crl::time(8000)" in session
    assert "ProxyMtproxyTerminalReason::MtpReceiveTimeoutAfterData" in receive
    assert "ProxyMtproxyTerminalReason::ConnectedNoMtprotoData" in receive
    assert "ProxyMtproxyTerminalReason::ServerHelloOkNoMtprotoData" in receive
    assert "MtProxy::FromProxyMtproxyTerminalReason(reason)" in receive


def test_health_reports_invalidate_view_after_typed_reduction():
    source = read(CONTROL_CPP)
    health = read(HEALTH_CPP)
    header = read(HEALTH_H)
    failure = function_body(source, "void ProxyControlPlane::reportMtproxyFailure(")
    success = function_body(source, "void ProxyControlPlane::reportMtproxySuccess(")

    assert "struct EndpointVerdict" in header
    assert "struct ProxyEndpointView" in header
    assert "_endpointHealth->reportFailure(" in failure
    assert "notifyEndpointViewChanged(endpoint)" in failure
    assert "_endpointHealth->reportSuccess(" in success
    assert "notifyEndpointViewChanged(endpoint)" in success
    assert "SetCurrentCanonicalVerdict(" in health
    assert "CurrentMainRelayProof(" in health


def test_windows_ci_runs_source_guards_before_build():
    workflow = read(ROOT / ".github" / "workflows" / "win.yml")
    guard = workflow.split(
        "- name: Proxy control-plane source guards.", 1)[1].split(
            "- name: Telegram Desktop build.", 1)[0]

    for script in (
        "test_connection_broker.py",
        "test_mtproxy_endpoint_health.py",
        "test_mtproxy_tls_psk.py",
        "test_proxy_control_plane_truth_table.py",
        "test_proxy_wss_default.py",
    ):
        assert script in guard


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
    test_control_plane_publishes_composed_mtproxy_views()
    test_selected_mtproxy_projection_has_strict_truth_priority()
    test_only_exact_current_main_network_fact_overlays_the_view()
    test_raw_reducer_rejects_probe_and_stale_generation_facts()
    test_admission_is_owned_by_shared_arbiter_not_control_plane()
    test_tls_socket_owns_serverhello_timeout_and_one_terminal_path()
    test_resolving_wrapper_keeps_typed_route_and_full_cycle_boundaries()
    test_session_receive_timeout_reports_stage_specific_terminal()
    test_health_reports_invalidate_view_after_typed_reduction()
    test_windows_ci_runs_source_guards_before_build()
