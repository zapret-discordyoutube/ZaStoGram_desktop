from pathlib import Path


SOURCE_DIR = Path(__file__).resolve().parents[1]
CHECK_H = SOURCE_DIR / "mtproto" / "proxy" / "check.h"
CHECK_CPP = SOURCE_DIR / "mtproto" / "proxy" / "check.cpp"
STATUS_H = SOURCE_DIR / "mtproto" / "proxy" / "status.h"
CONTROL_CPP = SOURCE_DIR / "mtproto" / "proxy" / "control_plane.cpp"
CONNECTION_BOX_CPP = SOURCE_DIR / "boxes" / "connection_box.cpp"
CONNECTION_BOX_H = SOURCE_DIR / "boxes" / "connection_box.h"
LANG = SOURCE_DIR.parent / "Resources" / "langs" / "lang.strings"


def read(path):
    assert path.exists(), f"missing expected source file: {path}"
    return path.read_text(encoding="utf-8")


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


def test_proxy_check_has_dedicated_probe_status_model():
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
    assert "kProxyCheckUiTimeout = crl::time(9000)" in source
    assert "void SetProxyCheckProgress(" in source
    assert "state->progress = progress;" in source


def test_proxy_check_dedupes_clicks_and_short_circuits_active_session():
    source = read(CHECK_CPP)
    start = function_body(source, "void StartProxyCheck(")
    reset = function_body(source, "void ProxyCheckConnection::reset(")
    active = function_body(source, "bool ActiveSessionProvesProxy(")

    assert "ActiveProxyCheckKeys" in source
    assert "ProxyCapabilityKey(proxy)" in start
    assert "ActiveProxyCheckKeys.contains(probeKey)" in start
    assert "RetainActiveProxyCheckKey(probeKey)" in start
    assert "ReleaseActiveProxyCheckKey(_data->probeKey)" in reset
    assert "if (progress && HasProxyCheckers(v4, v6))" in start
    assert "CurrentProxyCheckStatus(v4, v6)" in start
    assert "if (progress && ActiveSessionProvesProxy(" in start
    assert "ProxyCheckStatus::ConnectedByActiveSession" in start
    assert "return;" in start.split(
        "ProxyCheckStatus::ConnectedByActiveSession", 1)[1].split("}", 1)[0]

    assert "ProxyControlPlane::MtproxyEndpointSnapshot(" in active
    assert "endpoint)" in active
    assert "snapshot.relayProven" in active
    assert "snapshot.lastRelaySuccessAt" in active
    assert "kProxyCheckActiveSessionWindow" in active


def test_shield_active_session_uses_relay_proven_snapshot_not_timestamp_only():
    source = read(CHECK_CPP)
    health_header = read(
        SOURCE_DIR / "mtproto" / "proxy" / "mtproxy" / "endpoint_health.h")
    health_source = read(
        SOURCE_DIR / "mtproto" / "proxy" / "mtproxy" / "endpoint_health.cpp")
    active = function_body(source, "bool ActiveSessionProvesProxy(")
    snapshot = function_body(health_source, "Snapshot MakeSnapshot(")

    assert "bool relayProven = false;" in health_header
    assert ".relayProven = state.relayProven," in snapshot
    assert "snapshot.relayProven" in active
    assert active.index("snapshot.relayProven") < active.index(
        "snapshot.lastRelaySuccessAt")


def test_proxy_check_queue_is_progress_not_failure():
    source = read(CHECK_CPP)
    start = function_body(source, "void StartProxyCheck(")

    assert ".status = [=](details::ConnectionBrokerDecision decision)" in start
    assert "ProxyAdmissionAction" not in start
    assert "ConnectionBrokerAction::Queued" in start
    assert "ConnectionBrokerAction::StartAfter" in start
    assert "ProxyCheckStatus::WaitingForConnectionSlot" in start
    waiting = start.split("ProxyCheckStatus::WaitingForConnectionSlot", 1)[1]
    assert "finishWithFail" not in waiting.split("});", 1)[0]


def test_proxy_check_reports_progressive_fake_tls_phases():
    source = read(CHECK_CPP)
    start = function_body(source, "void StartProxyCheck(")
    phase_map = function_body(source, "ProxyCheckStatus ProxyCheckStatusForHandshake(")

    assert "raw->connect(raw, &Connection::handshakeProgress" in start
    for status in (
        "ProxyCheckStatus::TcpConnected",
        "ProxyCheckStatus::ClientHelloSent",
        "ProxyCheckStatus::ServerHelloOk",
        "ProxyCheckStatus::FirstTlsAppData",
    ):
        assert status in phase_map
    assert "ProxyCheckStatusForHandshake(raw->handshakePhase())" in start
    assert "ProxyCheckStatus::FirstMtprotoPayload" in start
    assert start.index("ProxyCheckStatus::FirstMtprotoPayload") < (
        start.index("proxy check succeeded"))
    assert ".scope = MtProxy::SuccessScope::Relay" in start
    assert ".stealth = state->mtproxyStealth" in start
    assert ".sentProfile = state->mtproxySentProfile" in start


def test_proxy_check_sets_attempt_and_hard_ui_timeout_after_start():
    source = read(CHECK_CPP)
    header = read(CHECK_H)
    start = function_body(source, "void StartProxyCheck(")

    assert "ProxyStealthOptions mtproxyStealth;" in header
    assert "ProxyTlsProfile mtproxySentProfile" in header
    assert "raw->setMtproxyAttempt({" in start
    assert ".proxyGeneration = start.proxyGeneration" in start
    assert ".proxyEpoch = start.proxyEpoch" in start
    assert ".attemptId = start.attemptId" in start
    assert ".connectionId = raw->debugId()" in start
    assert ".probe = true" in start
    assert "start.attemptStartedAt" in start
    assert "state->mtproxyStealth = start.stealth;" in start
    assert "state->mtproxySentProfile = start.effectiveTlsProfile;" in start
    assert "state->networkStarted = true;" in start
    assert "QTimer::singleShot(int(kProxyCheckUiTimeout), raw," in start
    hard_timeout = start.split(
        "QTimer::singleShot(int(kProxyCheckUiTimeout), raw,", 1)[1]
    assert "state->networkStarted" in hard_timeout
    assert "ProxyConnectionError::Timeout" in hard_timeout


def test_probe_attempts_do_not_publish_selected_status():
    status = read(STATUS_H)
    control = read(CONTROL_CPP)
    reduce_body = function_body(
        control,
        "ProxyConnectionStatus ProxyControlPlane::Reduce(")
    fact_body = function_body(
        control,
        "ProxyFact ProxyControlPlane::FactFromReport(")

    assert "bool probe = false;" in status
    assert "&& (probe == other.probe)" in status
    assert "fact.status.attempt.probe" in reduce_body
    assert "return current;" in reduce_body.split(
        "fact.status.attempt.probe", 1)[1].split("}", 1)[0]
    finished = fact_body.split(
        "case ProxyDiagnosticsPhase::ProxyCheckFinished:", 1)[1].split(
        "case ProxyDiagnosticsPhase::AdmissionQueued:", 1)[0]
    assert "fact.status.error = ProxyConnectionError::None;" in finished
    assert "fact.status.mtproxyReason = ProxyMtproxyTerminalReason::None;" in (
        finished)


def test_proxy_check_failure_is_probe_telemetry_not_canonical_health():
    source = read(CHECK_CPP)
    health_source = read(
        SOURCE_DIR / "mtproto" / "proxy" / "mtproxy" / "endpoint_health.cpp")
    start = function_body(source, "void StartProxyCheck(")
    report_failure = function_body(
        health_source,
        "void EndpointHealth::reportFailure(")

    failure = start.split("ProxyControlPlane::ReportMtproxyFailure({", 1)[1]
    assert ".use = MtProxy::EndpointUse::ProxyCheck" in failure.split("});", 1)[0]
    assert "report.use == EndpointUse::ProxyCheck" in report_failure
    assert "LogProbeAttemptFailure(report" in report_failure


def test_connection_box_uses_probe_status_instead_of_spinner_only():
    source = read(CONNECTION_BOX_CPP)
    header = read(CONNECTION_BOX_H)
    lang = read(LANG)
    refresh = function_body(source, "void ProxiesBoxController::refreshChecker(")

    assert "MTP::ProxyCheckStatus status" in source
    assert "ProxyCheckStatusText(" in source
    assert "ProxyCheckStatusColor(" in source
    assert "progressStatus" in header
    assert "state->progressStatus" in source
    assert "MTP::ProxyCheckStatus::WaitingForConnectionSlot" in source
    assert "MTP::ProxyCheckStatus::ConnectedByActiveSession" in source
    assert "MTP::HasProxyCheckers(item.checker, item.checkerv6)" in refresh
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


if __name__ == "__main__":
    test_proxy_check_has_dedicated_probe_status_model()
    test_proxy_check_dedupes_clicks_and_short_circuits_active_session()
    test_shield_active_session_uses_relay_proven_snapshot_not_timestamp_only()
    test_proxy_check_queue_is_progress_not_failure()
    test_proxy_check_reports_progressive_fake_tls_phases()
    test_proxy_check_sets_attempt_and_hard_ui_timeout_after_start()
    test_probe_attempts_do_not_publish_selected_status()
    test_proxy_check_failure_is_probe_telemetry_not_canonical_health()
    test_connection_box_uses_probe_status_instead_of_spinner_only()
