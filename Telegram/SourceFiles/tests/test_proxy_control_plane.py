from pathlib import Path
from session_private_sources import read_session_private_sources


SOURCE_DIR = Path(__file__).resolve().parents[1]
ROOT = SOURCE_DIR.parents[1]
CMAKE = ROOT / "Telegram" / "CMakeLists.txt"
WIN_WORKFLOW = ROOT / ".github" / "workflows" / "win.yml"
PROXY_DIR = SOURCE_DIR / "mtproto" / "proxy"
PROXY_SERVICES_H = PROXY_DIR / "proxy_services.h"
PROXY_SERVICES_CPP = PROXY_DIR / "proxy_services.cpp"
CONTROL_H = PROXY_DIR / "control_plane.h"
CONTROL_CPP = PROXY_DIR / "control_plane.cpp"
STATUS_H = PROXY_DIR / "status.h"
STATUS_CPP = PROXY_DIR / "status.cpp"
DIAGNOSTICS_CPP = PROXY_DIR / "diagnostics.cpp"
STATUS_TYPES_H = SOURCE_DIR / "mtproto" / "runtime" / "connection_status_types.h"
RUNTIME_PROXY_ENDPOINT_H = SOURCE_DIR / "mtproto" / "runtime" / "proxy_endpoint.h"
RUNTIME_CPP = SOURCE_DIR / "mtproto" / "runtime" / "runtime_environment.cpp"
INSTANCE_CPP = SOURCE_DIR / "mtproto" / "instance" / "mtp_instance.cpp"
INSTANCE_H = SOURCE_DIR / "mtproto" / "instance" / "mtp_instance.h"
CONNECTION_STATUS_CPP = (
    SOURCE_DIR / "mtproto" / "runtime" / "connection_status.cpp")
CONNECTION_STATUS_H = (
    SOURCE_DIR / "mtproto" / "runtime" / "connection_status.h")
ADAPTIVE_POLICY_CPP = PROXY_DIR / "mtproxy" / "adaptive_policy.cpp"
CONNECTION_BROKER_CPP = PROXY_DIR / "connection_broker.cpp"
SESSION_PROXY_ADAPTER_CPP = PROXY_DIR / "session_proxy_adapter.cpp"
ENDPOINT_HEALTH_CPP = PROXY_DIR / "mtproxy" / "endpoint_health.cpp"
ENDPOINT_HEALTH_H = PROXY_DIR / "mtproxy" / "endpoint_health.h"
ENDPOINT_HEALTH_POLICY_CPP = PROXY_DIR / "mtproxy" / "endpoint_health_policy.cpp"
ENDPOINT_IDENTITY_CPP = PROXY_DIR / "mtproxy" / "endpoint_identity.cpp"
ROTATION_MANAGER_CPP = SOURCE_DIR / "core" / "proxy_rotation_manager.cpp"
ROTATION_MANAGER_H = SOURCE_DIR / "core" / "proxy_rotation_manager.h"
SESSION_CPP = SOURCE_DIR / "mtproto" / "session" / "private" / "session_private.cpp"
TLS_SOCKET_CPP = PROXY_DIR / "mtproxy" / "tls_socket.cpp"
RESOLVING_CONNECTION_CPP = PROXY_DIR / "resolving_connection.cpp"
CONNECTING_WIDGET = SOURCE_DIR / "window" / "window_connecting_widget.cpp"
LANG = ROOT / "Telegram" / "Resources" / "langs" / "lang.strings"


def read(path):
    assert path.exists(), f"missing expected source file: {path}"
    return path.read_text(encoding="utf-8")


def function_body(source, signature):
    start = source.index(signature)
    brace = source.index("{", start)
    depth = 0
    for index in range(brace, len(source)):
        if source[index] == "{":
            depth += 1
        elif source[index] == "}":
            depth -= 1
            if depth == 0:
                return source[brace:index + 1]
    raise AssertionError(f"function body not found: {signature}")


def test_control_plane_is_the_proxy_publication_path():
    cmake = read(CMAKE)
    services_header = read(PROXY_SERVICES_H)
    header = read(CONTROL_H)
    source = read(CONTROL_CPP)
    diagnostics = read(DIAGNOSTICS_CPP)
    runtime = read(RUNTIME_CPP)
    report_body = function_body(runtime, "RuntimeEnvironment::RuntimeEnvironment(")

    assert "mtproto/proxy/control_plane.cpp" in cmake
    assert "mtproto/proxy/control_plane.h" in cmake
    assert "mtproto/proxy/proxy_services.cpp" in cmake
    assert "mtproto/proxy/proxy_services.h" in cmake
    assert "class ProxyServices final" in services_header
    assert "ProxyControlPlane &control();" in services_header
    assert "class ProxyControlPlane final" in header
    assert "explicit ProxyControlPlane(" in header
    assert "submitFact(const ProxyEventReport &report)" in header
    assert "admit(ProxyAdmissionRequest request)" in header
    assert "selectedStatus() const" in header
    assert "endpointSnapshot() const" in header
    assert '#include "mtproto/proxy/proxy_services.h"' in runtime
    assert "proxyServices().control().submitFact(report);" in report_body
    assert "setProxyConnectionStatus(status)" not in report_body
    assert "StatusPhaseFromDiagnostics" not in diagnostics
    assert "runtime->diagnostics().reportProxyEvent" in diagnostics
    assert "WriteProxyDiagnosticsLine(runtime, {" in runtime
    assert "ProxyControlPlane::FactFromReport(" in source


def test_windows_ci_runs_proxy_control_plane_source_guards_before_build():
    workflow = read(WIN_WORKFLOW)
    guard = workflow.split(
        "- name: Proxy control-plane source guards.", 1)[1].split(
        "- name: Telegram Desktop build.", 1)[0]

    for script in (
        "test_connection_broker.py",
        "test_connection_concurrency_policy.py",
        "test_mtproto_relay_silence.py",
        "test_mtproxy_client_hello_profiles.py",
        "test_mtproxy_endpoint_health.py",
        "test_mtproxy_endpoint_identity.py",
        "test_mtproxy_faketls_hardening.py",
        "test_mtproxy_minimal_hotfix.py",
        "test_mtproxy_open_scheduler.py",
        "test_mtproxy_phase_cooldown.py",
        "test_mtproxy_policy.py",
        "test_mtproxy_target_flow.py",
        "test_mtproxy_tls_psk.py",
        "test_proxy_atomic_switch.py",
        "test_proxy_capability_cache.py",
        "test_proxy_capability_key_contract.py",
        "test_proxy_connection_status.py",
        "test_proxy_control_plane.py",
        "test_proxy_control_plane_truth_table.py",
        "test_proxy_diagnostics.py",
        "test_proxy_list_checks.py",
        "test_proxy_logging_events.py",
        "test_proxy_rotation_health_switch.py",
        "test_proxy_shield_probe.py",
        "test_proxy_wss_default.py",
        "test_session_endpoint_cooldown.py",
    ):
        assert f"python Telegram/SourceFiles/tests/{script}" in guard
    assert workflow.index("- name: Proxy control-plane source guards.") < (
        workflow.index("- name: Telegram Desktop build."))


def test_mtp_first_data_is_relay_success_fact():
    source = read(CONTROL_CPP)
    fact_body = function_body(
        source,
        "ProxyFact ProxyControlPlane::FactFromReport(")

    assert "ProxyControlPlaneSuccessScope::Relay" in source
    assert "ProxyDiagnosticsPhase::MtpFirstDataReceived" in fact_body
    assert "fact.successScope = ProxyControlPlaneSuccessScope::Relay;" in (
        fact_body)
    assert "fact.status.phase = ProxyConnectionPhase::Connected;" in fact_body
    assert "kFreshRelaySuccessWindow" in source
    assert "successUntil" in read(STATUS_TYPES_H)


def test_fresh_relay_success_shadows_late_sibling_failures():
    source = read(CONTROL_CPP)
    status_header = read(STATUS_TYPES_H)
    reducer = function_body(
        source,
        "ProxyConnectionStatus ProxyControlPlane::Reduce(")
    shadow_helper = function_body(source, "bool ShadowedByFreshRelaySuccess(")

    assert "ShadowedByFreshRelaySuccess(current, fact)" in reducer
    assert "RelaySuccessIsFresh(current)" in shadow_helper
    assert "IsTerminalFailure(fact.status)" in shadow_helper
    assert "IsNewerProxyEpoch(current.attempt, fact.status.attempt)" in (
        shadow_helper)
    assert "return current;" in reducer.split(
        "ShadowedByFreshRelaySuccess(current, fact)", 1)[1]
    assert "RelaySuccessIsFresh" in source
    assert "shadowed_by_fresh_success" in source
    assert "successUntil" in status_header


def test_reducer_rejects_older_progress_attempts():
    source = read(CONTROL_CPP)
    reducer = function_body(
        source,
        "ProxyConnectionStatus ProxyControlPlane::Reduce(")
    apply = function_body(source, "ProxyConnectionStatus ApplySelectedStatusUpdate(")

    assert "bool IsOlderAttempt(" in source
    assert "IsOlderAttempt(current.attempt, update.attempt)" in apply
    assert apply.index(
        "IsOlderAttempt(current.attempt, update.attempt)") < apply.index(
            "!IsMtproxyTerminalFailure(current.mtproxyReason)")
    assert "ApplySelectedStatusUpdate(" in reducer


def test_no_appdata_is_relay_stall_not_no_serverhello_or_recipe_source():
    status = read(STATUS_CPP)
    control = read(CONTROL_CPP)
    adaptive = read(ADAPTIVE_POLICY_CPP)
    recipe_body = function_body(adaptive, "bool FailureNeedsRecipe(")
    rotation_body = function_body(
        adaptive,
        "bool FailureNeedsTlsProfileRotation(")

    assert "ProxyMtproxyTerminalReason::ServerHelloOkNoAppData" in status
    assert "ProxyConnectionStatusKind::MtproxyServerHelloOkNoAppData" in status
    assert "MtproxyNoServerHello" not in status.split(
        "case ProxyMtproxyTerminalReason::ServerHelloOkNoAppData:", 1)[1].split(
            "case ProxyMtproxyTerminalReason::AppDataRemoteClosed:", 1)[0]
    assert "ProxyMtproxyTerminalReason::ServerHelloOkNoAppData" in control
    assert 'u"server_hello_ok_no_appdata"_q' not in recipe_body
    assert 'u"server_hello_ok_no_appdata"_q' not in rotation_body


def test_no_serverhello_no_appdata_and_mtproto_stalls_are_distinct():
    status_h = read(STATUS_TYPES_H)
    status = read(STATUS_CPP)
    diagnostics = read(DIAGNOSTICS_CPP)
    endpoint_h = read(RUNTIME_PROXY_ENDPOINT_H)
    identity = read(ENDPOINT_IDENTITY_CPP)
    widget = read(CONNECTING_WIDGET)
    lang = read(LANG)
    kind_body = function_body(
        status,
        "ProxyConnectionStatusKind ProxyConnectionStatusKindFor(")
    reason_text = function_body(
        diagnostics,
        "QString MtproxyReasonText(")
    legacy = function_body(identity, "QString ToLegacyDiagnostic(")
    terminal = function_body(
        identity, "ProxyMtproxyTerminalReason ToProxyMtproxyTerminalReason(")

    for reason in (
        "ClientHelloSentNoServerHello",
        "ServerHelloOkNoAppData",
        "ServerHelloOkNoMtprotoData",
        "MtpReceiveTimeoutAfterData",
    ):
        assert reason in status_h
        assert reason in endpoint_h

    no_appdata_block = kind_body.split(
        "case ProxyMtproxyTerminalReason::ServerHelloOkNoAppData:", 1)[1].split(
            "case ProxyMtproxyTerminalReason::ServerHelloOkNoMtprotoData:", 1)[0]
    assert "ProxyConnectionStatusKind::MtproxyServerHelloOkNoAppData" in (
        no_appdata_block)
    assert "MtproxyNoServerHello" not in no_appdata_block

    no_mtproto_block = kind_body.split(
        "case ProxyMtproxyTerminalReason::ServerHelloOkNoMtprotoData:", 1)[1].split(
            "case ProxyMtproxyTerminalReason::AppDataRemoteClosed:", 1)[0]
    assert "ProxyConnectionStatusKind::MtproxyConnectedNoMtprotoData" in (
        no_mtproto_block)
    assert "MtproxyServerHelloOkNoAppData" not in no_mtproto_block

    receive_after_data_block = kind_body.split(
        "case ProxyMtproxyTerminalReason::MtpReceiveTimeoutAfterData:", 1)[1].split(
            "case ProxyMtproxyTerminalReason::ProxyProtocolBadResponse:", 1)[0]
    assert "ProxyConnectionStatusKind::MtproxyMtpReceiveTimeoutAfterData" in (
        receive_after_data_block)

    for diagnostic in (
        "server_hello_ok_no_appdata",
        "server_hello_ok_no_mtproto_data",
        "connected_no_mtproto_data",
        "mtp_receive_timeout_after_data",
    ):
        assert diagnostic in reason_text
        assert diagnostic in legacy

    assert (
        "return ProxyMtproxyTerminalReason::ServerHelloOkNoMtprotoData;"
        in terminal)
    assert (
        "return ProxyMtproxyTerminalReason::MtpReceiveTimeoutAfterData;"
        in terminal)

    for kind in (
        "MtproxyNoServerHello",
        "MtproxyServerHelloOkNoAppData",
        "MtproxyConnectedNoMtprotoData",
        "MtproxyMtpReceiveTimeoutAfterData",
    ):
        assert f"ProxyConnectionStatusKind::{kind}" in widget

    assert (
        '"lng_proxy_status_mtproxy_no_server_hello" = '
        '"MTProxy FakeTLS failed: no ServerHello";'
    ) in lang
    assert (
        '"lng_proxy_status_mtproxy_no_appdata" = '
        '"MTProxy FakeTLS handshake OK, but no Telegram data";'
    ) in lang
    assert (
        '"lng_proxy_status_mtproxy_connected_no_mtproto_data" = '
        '"Proxy connected, MTProto data stalled";'
    ) in lang


def test_serverhello_progress_prevents_no_serverhello_terminal_repaint():
    control = read(CONTROL_CPP)
    tls = read(TLS_SOCKET_CPP)
    resolving = read(RESOLVING_CONNECTION_CPP)
    reducer = function_body(
        control,
        "ProxyConnectionStatus ProxyControlPlane::Reduce(")
    normalize = function_body(control, "void NormalizeMtproxyTerminalReason(")
    tls_failure = function_body(
        tls,
        "MtProxy::FailureReason TlsSocket::failureReason() const")
    route_timeout = function_body(
        resolving,
        "MtProxy::FailureReason RouteTimeoutReason(")

    assert "NormalizeMtproxyTerminalReason(current, fact.status);" in reducer
    assert "ProxyConnectionPhase::CheckingTelegram" in normalize
    assert "ProxyMtproxyTerminalReason::ClientHelloSentNoServerHello" in (
        normalize)
    assert "ProxyMtproxyTerminalReason::ServerHelloOkNoAppData" in normalize

    after_serverhello = tls_failure.split(
        "case HandshakePhase::ServerHelloOk:", 1)[1].split(
            "case HandshakePhase::FirstDataReceived:", 1)[0]
    assert "ServerHelloOkNoAppData" in after_serverhello
    assert "ClientHelloSentNoServerHello" not in after_serverhello

    route_after_serverhello = route_timeout.split(
        "case HandshakePhase::ServerHelloOk:", 1)[1].split(
            "return MtProxy::FailureReason::ServerHelloOkNoAppData;", 1)[0]
    assert "ClientHelloSentNoServerHello" not in route_after_serverhello


def test_session_receive_timeout_reports_stage_specific_terminal_status():
    session = read_session_private_sources()
    adapter = read(SESSION_PROXY_ADAPTER_CPP)
    wait_received = function_body(
        session,
        "void SessionTransport::waitReceivedFailed(")
    report_timeout = function_body(
        adapter,
        "void ProductionSessionProxyPort::reportReceiveTimeout(")
    relay_stall = function_body(
        adapter,
        "void ProductionSessionProxyPort::reportRelayStall(")

    assert "ProxyDiagnosticsPhase::MtpReceiveTimeout" in wait_received
    assert "_owner->_proxyPort->reportReceiveTimeout(" in wait_received
    assert "ProxyDiagnosticsPhase::Failed" in report_timeout
    assert "ProxyConnectionError::Timeout" in report_timeout
    assert "ProxyMtproxyTerminalReason::ServerHelloOkNoMtprotoData" in (
        report_timeout)
    assert "ProxyMtproxyTerminalReason::MtpReceiveTimeoutAfterData" in (
        report_timeout)
    assert "MtProxy::FailureReason::ServerHelloOkNoMtprotoData" in (
        report_timeout)
    assert "reportRelayStall(attempt);" in report_timeout
    assert "proxyServices().control().noteMtproxyRelayStall(" in relay_stall
    relay_stall_call = relay_stall.split(
        "proxyServices().control().noteMtproxyRelayStall(", 1
        )[1].split("});", 1)[0]
    assert ".proxyGeneration = attempt.attempt.proxyGeneration" in (
        relay_stall_call)
    assert ".attemptId = attempt.attempt.attemptId" in (
        relay_stall_call)
    assert ".proxyEpoch = attempt.attempt.proxyEpoch" in (
        relay_stall_call)
    assert ".attemptStartedAt = attempt.attemptStartedAt" in (
        relay_stall_call)


def test_admission_keeps_scouts_until_relay_proof():
    header = read(CONTROL_H)
    control = read(CONTROL_CPP)
    broker = read(CONNECTION_BROKER_CPP)
    health = read(ENDPOINT_HEALTH_CPP)
    policy = read(ENDPOINT_HEALTH_POLICY_CPP)
    admit_body = function_body(
        control,
        "ProxyAdmissionDecision ProxyControlPlane::admit(")

    assert "struct ProxyAdmissionRequest" in header
    assert "struct ProxyAdmissionDecision" in header
    assert "ProxyAdmissionDecision admit(" in header
    assert '#include "mtproto/proxy/control_plane.h"' in broker
    assert "_runtime->proxyServices().control().admit({" in broker
    assert "EndpointHealth::Instance().admit" not in broker
    assert "EndpointHealth::Instance().admit" not in control
    assert "_endpointHealth->admit({" in admit_body
    assert "MtProxy::EndpointAttemptLease lease" in header
    assert "MtProxy::FailureReason blockedBy" in header
    assert "effectiveTlsProfile" in header
    assert "proxyEpoch" in header
    assert "EndpointConcurrencyPolicyFor" in health
    assert "relayProven" in health
    assert "kUnknownActiveCap" in policy
    assert "kColdActiveCap" in policy


def test_proxy_restart_backoff_is_not_one_ms_herd():
    session = read_session_private_sources()
    restart_body = function_body(session, "void SessionTransport::restart(")

    assert "_sessionState.options->proxy.type != ProxyData::Type::None" in restart_body
    assert "_timing.retryTimeout < kProxyReconnectMinTimeout" in restart_body
    assert "_timing.retryTimeout = kProxyReconnectMinTimeout;" in restart_body
    assert restart_body.index("kProxyReconnectMinTimeout") < (
        restart_body.index("ProxyDiagnosticsPhase::MtpRestart"))


def test_mtproxy_health_policy_is_control_plane_owned():
    header = read(CONTROL_H)
    control = read(CONTROL_CPP)
    rotation_header = read(ROTATION_MANAGER_H)
    rotation = read(ROTATION_MANAGER_CPP)

    for name in (
        "reportMtproxyFailure(",
        "reportMtproxySuccess(",
        "noteMtproxyRelayStall(",
        "mtproxyEndpointSnapshot(",
        "mtproxyEndpointChanges(",
    ):
        assert name in header
        assert f"ProxyControlPlane::{name}" in control

    assert '#include "mtproto/proxy/control_plane.h"' in rotation_header
    assert '#include "mtproto/proxy/mtproxy/endpoint_health.h"' not in (
        rotation_header)
    assert '#include "mtproto/runtime/runtime_environment.h"' in rotation
    assert "runtimeEnvironment().proxyServices().control().mtproxyEndpointChanges(" in (
        rotation)

    for source in (SOURCE_DIR / "mtproto").rglob("*.cpp"):
        relative = source.relative_to(SOURCE_DIR)
        if relative in (
                Path("mtproto/proxy/control_plane.cpp"),
                Path("mtproto/proxy/mtproxy/endpoint_health.cpp")):
            continue
        text = source.read_text(encoding="utf-8")
        for call in (
                "EndpointHealth::Instance().reportFailure(",
                "EndpointHealth::Instance().reportSuccess(",
                "EndpointHealth::Instance().noteRelayStall(",
                "EndpointHealth::Instance().snapshot(",
                "EndpointHealth::Instance().changes("):
            assert call not in text, f"{relative} bypasses ProxyControlPlane"

    assert "EndpointHealth::Instance().changes(" not in rotation


def test_instance_status_sink_does_not_reduce_control_plane_output_again():
    control = read(CONTROL_CPP)
    status_header = read(STATUS_H)
    status_source = read(STATUS_CPP)
    connection_status = read(CONNECTION_STATUS_CPP)
    submit = function_body(control, "void ProxyControlPlane::submitFact(")
    sink = function_body(
        connection_status,
        "void ConnectionStatus::setProxyStatus(")

    assert "ProxyControlPlane::Reduce(current, normalized)" in submit
    assert "ApplySelectedStatusUpdate(" in control
    assert "ApplyProxyConnectionStatusUpdate(" not in status_header
    assert "ApplyProxyConnectionStatusUpdate(" not in status_source
    assert "ApplyProxyConnectionStatusUpdate(" not in sink
    assert "_proxyStatus = status;" in sink


def test_instance_status_sink_is_private_to_runtime_gateway():
    header = read(INSTANCE_H)
    status_header = read(CONNECTION_STATUS_H)
    control = read(CONTROL_CPP)

    assert "class RuntimeEnvironment;" in header
    assert "friend class ProxyControlPlane;" not in header
    assert "void setProxyConnectionStatus(ProxyConnectionStatus status);" not in header
    assert "ConnectionStatus &connectionStatus() const;" in header
    assert "void setProxyStatus(ProxyConnectionStatus status);" in status_header

    submit = function_body(control, "void ProxyControlPlane::submitFact(")
    assert "_runtime->instance().connectionStatus->setProxyStatus(" in submit


if __name__ == "__main__":
    test_control_plane_is_the_proxy_publication_path()
    test_windows_ci_runs_proxy_control_plane_source_guards_before_build()
    test_mtp_first_data_is_relay_success_fact()
    test_fresh_relay_success_shadows_late_sibling_failures()
    test_reducer_rejects_older_progress_attempts()
    test_no_appdata_is_relay_stall_not_no_serverhello_or_recipe_source()
    test_instance_status_sink_is_private_to_runtime_gateway()
    test_no_serverhello_no_appdata_and_mtproto_stalls_are_distinct()
    test_serverhello_progress_prevents_no_serverhello_terminal_repaint()
    test_session_receive_timeout_reports_stage_specific_terminal_status()
    test_admission_keeps_scouts_until_relay_proof()
    test_proxy_restart_backoff_is_not_one_ms_herd()
    test_mtproxy_health_policy_is_control_plane_owned()
    test_instance_status_sink_does_not_reduce_control_plane_output_again()
