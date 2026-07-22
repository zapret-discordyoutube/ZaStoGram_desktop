from pathlib import Path


SOURCE_DIR = Path(__file__).resolve().parents[1]
CHECK_H = SOURCE_DIR / "mtproto" / "proxy" / "check.h"
CHECK_CPP = SOURCE_DIR / "mtproto" / "proxy" / "check.cpp"
CONTROL_CPP = SOURCE_DIR / "mtproto" / "proxy" / "control_plane.cpp"
HEALTH_CPP = SOURCE_DIR / "mtproto" / "proxy" / "mtproxy" / "endpoint_health.cpp"
CONNECTION_BOX_CPP = SOURCE_DIR / "boxes" / "connection_box.cpp"
CONNECTION_BOX_H = SOURCE_DIR / "boxes" / "connection_box.h"
STATUS_TYPES_H = SOURCE_DIR / "mtproto" / "runtime" / "connection_status_types.h"
LANG = SOURCE_DIR.parent / "Resources" / "langs" / "lang.strings"


def read(path):
    assert path.exists(), f"missing expected source file: {path}"
    return path.read_text(encoding="utf-8")


def test_proxy_check_has_a_dedicated_progress_model():
    header = read(CHECK_H)
    source = read(CHECK_CPP)

    assert "enum class ProxyCheckStatus" in header
    for status in (
        "WaitingForConnectionSlot",
        "Resolving",
        "TcpConnected",
        "ClientHelloSent",
        "ServerHelloOk",
        "FirstTlsAppData",
        "FirstMtprotoPayload",
        "ConnectedByActiveSession",
    ):
        assert status in header
    assert "Fn<void(ProxyCheckStatus status)> progress" in header
    assert "ProxyCheckStatus progressStatus" in header
    assert "void SetProxyCheckProgress(" in source
    assert "state->progress = progress;" in source


def test_active_session_shortcut_requires_a_live_main_proof():
    source = read(CHECK_CPP)
    active = function_body(source, "bool ActiveSessionProvesProxy(")
    start = function_body(source, "void StartProxyCheck(")

    assert "control.mtproxyEndpointView(endpoint)" in active
    assert "view.mainProof.strength" in active
    assert "MainRelayProofStrength::None" in active
    assert "lastRelaySuccessAt" not in active
    assert "ActiveProxyCheckKeys" in source
    assert "ActiveSessionProvesProxy(" in start
    assert "ProxyCheckStatus::ConnectedByActiveSession" in start


def test_queued_and_rejected_admission_have_distinct_probe_outcomes():
    start = function_body(read(CHECK_CPP), "void StartProxyCheck(")

    assert ".reclaim = [" in start
    reclaim = function_body(start, ".reclaim = [")
    assert "state->connection.get() != raw" in reclaim
    assert "state->mtproxyLease.slotKey() != key" in reclaim
    assert "ResetProxyCheckState(" in reclaim
    assert "ProxyCloseOrigin::BrokerCancelled" in reclaim
    assert ".status = [=](details::ConnectionBrokerDecision decision)" in start
    assert "ConnectionBrokerAction::Queued" in start
    assert "ConnectionBrokerAction::StartAfter" in start
    assert "ProxyCheckStatus::WaitingForConnectionSlot" in start
    assert "ConnectionBrokerAction::Rejected" in start
    rejected = start.split("ConnectionBrokerAction::Rejected", 1)[1]
    assert "finishWithFail" in rejected


def test_proxy_check_reports_progressive_transport_phases():
    source = read(CHECK_CPP)
    start = function_body(source, "void StartProxyCheck(")
    phase_map = function_body(
        source, "ProxyCheckStatus ProxyCheckStatusForHandshake(")

    assert "&Connection::handshakeProgress" in start
    for status in (
        "ProxyCheckStatus::TcpConnected",
        "ProxyCheckStatus::ClientHelloSent",
        "ProxyCheckStatus::ServerHelloOk",
        "ProxyCheckStatus::FirstTlsAppData",
    ):
        assert status in phase_map
    assert "const auto phase = raw->handshakePhase();" in start
    assert "ProxyCheckStatusForHandshake(phase)" in start
    handshake = function_body(
        start, "raw->connect(raw, &Connection::handshakeProgress")
    assert "transportReady();" not in handshake
    assert "ProxyCheckStatus::FirstMtprotoPayload" in start
    assert ".scope = MtProxy::SuccessScope::Relay" in start
    connected = function_body(
        start, "raw->connect(raw, &Connection::connected")
    assert connected.count("state->mtproxyLease.transportReady();") == 1
    assert connected.index("ClaimProxyCheckTerminal(") < connected.index(
        "reportMtproxySuccess({")
    assert connected.index("reportMtproxySuccess({") < connected.index(
        "state->mtproxyLease.transportReady();")


def test_probe_timeout_starts_after_handoff_and_uses_network_budget():
    source = read(CHECK_CPP)
    header = read(CHECK_H)
    start = function_body(source, "void StartProxyCheck(")

    assert "ProxyStealthOptions mtproxyStealth;" in header
    assert "ProxyTlsProfile mtproxySentProfile" in header
    assert "state->mtproxyAttempt = start.attempt;" in start
    assert "state->mtproxyPlan = start.plan;" in start
    assert "state->networkStarted = true;" in start
    assert "QTimer::singleShot(int(raw->fullConnectTimeout()), raw" in start
    assert start.index("state->networkStarted = true;") < start.index(
        "QTimer::singleShot(int(raw->fullConnectTimeout()), raw")
    timeout = start.split(
        "QTimer::singleShot(int(raw->fullConnectTimeout()), raw", 1)[1]
    assert "ProxyConnectionError::Timeout" in timeout


def test_probe_facts_do_not_publish_selected_main_status():
    status = read(STATUS_TYPES_H)
    control = read(CONTROL_CPP)
    reduce = function_body(
        control, "ProxyConnectionStatus ProxyControlPlane::Reduce(")

    assert "ProxyConnectionUse use = ProxyConnectionUse::Main;" in status
    assert "IsProxyCheck(fact.status.attempt.use)" in reduce
    assert "return current;" in reduce.split(
        "IsProxyCheck(fact.status.attempt.use)", 1)[1].split("}", 1)[0]


def test_probe_terminal_is_telemetry_not_canonical_health():
    check = function_body(read(CHECK_CPP), "void StartProxyCheck(")
    health = read(HEALTH_CPP)
    failure = function_body(health, "void EndpointHealth::reportFailure(")
    success = function_body(health, "void EndpointHealth::reportSuccess(")

    assert ".use = MtProxy::EndpointUse::ProxyCheck" in check
    assert "report.use == EndpointUse::ProxyCheck" in failure
    assert "LogProbeAttemptFailure(_runtime, report)" in failure
    assert "const auto probe = (report.use == EndpointUse::ProxyCheck);" in success
    assert "RetireRelayProof(state, identity)" in success
    assert "LogProbeAttemptSuccess(_runtime, report)" in success
    canonical = failure.split("const auto canonicalEligible", 1)[1].split(
        "if (canonicalEligible)", 1)[0]
    assert "report.use" in canonical
    assert "EndpointUse::Main" in canonical


def test_probe_terminal_callbacks_reset_before_exact_lease_release():
    source = read(CHECK_CPP)
    start = function_body(source, "void StartProxyCheck(")
    finish = function_body(start, "const auto finishWithFail = [=](")
    terminal = function_body(
        finish, "if (!MtProxy::EndpointEmpty(state->mtproxyEndpoint))")
    reset = function_body(source, "void ResetProxyCheckState(")
    connected = function_body(
        start, "raw->connect(raw, &Connection::connected")

    assert "reportMtproxyFailure({" in terminal
    assert terminal.index("reportMtproxyFailure({") < terminal.index(
        "state->mtproxyLease.capacityTerminal(reason, true);")
    assert "ClaimProxyCheckTerminal(runtime, state)" in terminal
    assert "IsProxyCheckCapacityTerminal(reason)" in terminal
    assert "state->mtproxyLease.release();" not in finish
    assert finish.index("fail(raw);") < finish.index(
        "if (state->connection.get() == raw)")
    assert finish.index("if (state->connection.get() == raw)") < finish.index(
        "ResetProxyCheckState(")
    assert connected.index("done(raw, ping);") < connected.index(
        "if (state->connection.get() == raw)")
    assert connected.index("if (state->connection.get() == raw)") < (
        connected.index("ResetProxyCheckState("))
    assert reset.index("state->connection.reset();") < reset.index(
        "state->mtproxyLease.release();")
    assert "state->connectionTicket.cancel();" in reset
    assert "state->handshakeGate.release();" in reset


def test_probe_non_capacity_paths_cannot_train_capacity():
    source = read(CHECK_CPP)
    capacity = function_body(source, "bool IsProxyCheckCapacityTerminal(")
    reset = function_body(source, "void ResetProxyCheckState(")
    start = function_body(source, "void StartProxyCheck(")
    handshake = function_body(
        start, "raw->connect(raw, &Connection::handshakeProgress")
    reclaim = function_body(start, ".reclaim = [")

    for reason in (
        "TcpConnectTimeout",
        "ClientHelloSentNoServerHello",
        "ServerHelloOkNoAppData",
        "ServerHelloOkNoMtprotoData",
        "ConnectedNoMtprotoData",
    ):
        assert f"MtProxy::FailureReason::{reason}" in capacity
    for reason in (
        "DnsFailed",
        "BrokerCancelled",
        "RemoteClosed",
    ):
        assert f"MtProxy::FailureReason::{reason}" not in capacity
    assert "capacityTerminal(" not in reset
    assert "capacityTerminal(" not in reclaim
    assert "capacityTerminal(" not in handshake


def test_connection_box_uses_probe_status_and_composed_view():
    source = read(CONNECTION_BOX_CPP)
    header = read(CONNECTION_BOX_H)
    lang = read(LANG)
    refresh = function_body(source, "void ProxiesBoxController::refreshChecker(")

    assert "ProxyCheckStatusText(" in source
    assert "ProxyCheckStatusColor(" in source
    assert "progressStatus" in header
    assert "MTP::ProxyCheckStatus::WaitingForConnectionSlot" in source
    assert "MTP::ProxyCheckStatus::ConnectedByActiveSession" in source
    assert "mtproxyEndpointView(endpoint)" in source
    assert "view.mainProof.strength" in source
    assert "view.canonicalVerdict" in source
    assert "progressStatus" in refresh
    for key in (
        "lng_proxy_box_table_waiting_slot",
        "lng_proxy_box_table_resolving",
        "lng_proxy_box_table_tcp_connected",
        "lng_proxy_box_table_client_hello_sent",
        "lng_proxy_box_table_server_hello_ok",
        "lng_proxy_box_table_first_tls_appdata",
        "lng_proxy_box_table_first_mtproto",
        "lng_proxy_box_table_connected_active",
    ):
        assert key in lang


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
    test_proxy_check_has_a_dedicated_progress_model()
    test_active_session_shortcut_requires_a_live_main_proof()
    test_queued_and_rejected_admission_have_distinct_probe_outcomes()
    test_proxy_check_reports_progressive_transport_phases()
    test_probe_timeout_starts_after_handoff_and_uses_network_budget()
    test_probe_facts_do_not_publish_selected_main_status()
    test_probe_terminal_is_telemetry_not_canonical_health()
    test_probe_terminal_callbacks_reset_before_exact_lease_release()
    test_probe_non_capacity_paths_cannot_train_capacity()
    test_connection_box_uses_probe_status_and_composed_view()
