from pathlib import Path
from session_private_sources import read_session_private_sources


SOURCE_DIR = Path(__file__).resolve().parents[1]
MTPROXY_DIR = SOURCE_DIR / "mtproto" / "proxy" / "mtproxy"
RUNTIME_DIR = SOURCE_DIR / "mtproto" / "runtime"
ENDPOINT_IDENTITY_H = MTPROXY_DIR / "endpoint_identity.h"
ENDPOINT_HEALTH_H = MTPROXY_DIR / "endpoint_health.h"
ENDPOINT_HEALTH_CPP = MTPROXY_DIR / "endpoint_health.cpp"
ENDPOINT_HEALTH_STATE_H = MTPROXY_DIR / "endpoint_health_state.h"
ENDPOINT_HEALTH_CAPABILITIES_CPP = MTPROXY_DIR / "endpoint_health_capabilities.cpp"
ENDPOINT_HEALTH_POLICY_CPP = MTPROXY_DIR / "endpoint_health_policy.cpp"
ADAPTIVE_POLICY_CPP = MTPROXY_DIR / "adaptive_policy.cpp"
TLS_SOCKET_H = MTPROXY_DIR / "tls_socket.h"
TLS_SOCKET_CPP = MTPROXY_DIR / "tls_socket.cpp"
STATUS_H = SOURCE_DIR / "mtproto" / "proxy" / "status.h"
STATUS_CPP = SOURCE_DIR / "mtproto" / "proxy" / "status.cpp"
DIAGNOSTICS_CPP = SOURCE_DIR / "mtproto" / "proxy" / "diagnostics.cpp"
PROXY_ADAPTER_CPP = SOURCE_DIR / "mtproto" / "proxy" / "session_proxy_adapter.cpp"
SESSION_CPP = SOURCE_DIR / "mtproto" / "session" / "private" / "session_private.cpp"
CHECK_CPP = SOURCE_DIR / "mtproto" / "proxy" / "check.cpp"
ARBITER_H = SOURCE_DIR / "mtproto" / "proxy" / "endpoint_admission_arbiter.h"
ARBITER_CPP = SOURCE_DIR / "mtproto" / "proxy" / "endpoint_admission_arbiter.cpp"
LIVE_POOL_H = SOURCE_DIR / "mtproto" / "proxy" / "endpoint_live_pool.h"
LIVE_POOL_CPP = SOURCE_DIR / "mtproto" / "proxy" / "endpoint_live_pool.cpp"
PROXY_ENDPOINT_H = RUNTIME_DIR / "proxy_endpoint.h"
CONNECTION_STATUS_TYPES_H = RUNTIME_DIR / "connection_status_types.h"
LANG = SOURCE_DIR.parent / "Resources" / "langs" / "lang.strings"
CONNECTING_WIDGET = SOURCE_DIR / "window" / "window_connecting_widget.cpp"


def read(path):
    assert path.exists(), f"missing expected source file: {path}"
    return path.read_text(encoding="utf-8")


def function_body(source, signature):
    start = source.index(signature)
    brace = source.index("{", start)
    depth = 0
    for i in range(brace, len(source)):
        if source[i] == "{":
            depth += 1
        elif source[i] == "}":
            depth -= 1
            if depth == 0:
                return source[brace:i + 1]
    raise AssertionError(f"function body not found: {signature}")


def test_failure_reason_enum_is_phase_specific():
    header = read(PROXY_ENDPOINT_H)

    assert "enum class FailureReason" in header
    assert header.index("enum class FailureReason") < (
        header.index("struct CanonicalProxyEndpoint"))
    for reason in (
        "DnsFailed",
        "TcpConnectTimeout",
        "TcpConnectedNoClientHelloWrite",
        "ClientHelloSentNoServerHello",
        "TlsAlertAfterClientHello",
        "ServerHelloHmacMismatch",
        "ServerHelloOkNoAppData",
        "AppDataRemoteClosed",
        "ProxyProtocolBadResponse",
    ):
        assert reason in header

    for old_reason in (
        "\tDnsHostNotFound,",
        "\tNoServerHelloAfterClientHello,",
        "\tPostHandshakeNoAppData,",
        "\tRemoteClosed,",
        "\tTimeout,",
        "\tBadResponse,",
    ):
        assert old_reason not in header


def test_tls_socket_reports_timeout_by_handshake_phase():
    header = read(TLS_SOCKET_H)
    source = read(TLS_SOCKET_CPP)
    failure_body = function_body(
        source,
        "MtProxy::FailureReason TlsSocket::failureReason() const")
    error_body = function_body(source, "void TlsSocket::handleError(int errorCode)")

    assert "bool _firstAppDataReceived = false;" in header
    assert "MtProxy::FailureReason::TcpConnectTimeout" in failure_body
    assert "MtProxy::FailureReason::TcpConnectedNoClientHelloWrite" in failure_body
    assert "MtProxy::FailureReason::ClientHelloSentNoServerHello" in failure_body
    assert "MtProxy::FailureReason::ServerHelloOkNoAppData" in failure_body
    assert "MtProxy::FailureReason::AppDataRemoteClosed" in error_body
    assert "PostHandshakeNoAppData" not in failure_body
    assert "TcpNotConnected" not in failure_body


def trait_row(traits_body, reason):
    segment = traits_body.split(f"case FailureReason::{reason}:", 1)[1]
    return segment.split("case FailureReason::", 1)[0]


def test_phase_cooldown_and_recipe_policy_is_reason_based():
    source = read(ENDPOINT_HEALTH_CPP)
    policy = read(ENDPOINT_HEALTH_POLICY_CPP)
    adaptive = read(ADAPTIVE_POLICY_CPP)
    traits = function_body(policy, "FailureTraits TraitsFor(")
    report_failure = function_body(source, "void EndpointHealth::reportFailure(")
    adaptive_recipe = function_body(adaptive, "bool FailureNeedsRecipe(")
    adaptive_rotation = function_body(adaptive, "bool FailureNeedsTlsProfileRotation(")

    assert "FailureNeedsRecipeEscalation(report.reason)" in report_failure
    assert "FailureNeedsTlsRotation(report.reason)" not in source
    assert "state.recipeLevel < 2" in report_failure
    assert "recentRelay" in report_failure
    assert "state.recipeFailureStreak >= 1" in report_failure
    assert "if (!FailureNeedsRecipeEscalation(report.reason))" in report_failure
    reset = report_failure.index(
        "if (!FailureNeedsRecipeEscalation(report.reason))")
    escalate = report_failure.index("const auto recentRelay", reset)
    assert report_failure.index(
        "state.recipeFailureStreak = 0;", reset) < escalate
    escalation_block = report_failure.split(
        "FailureNeedsRecipeEscalation(report.reason)", 1)[1].split(
            "const auto canonicalEligible", 1)[0]
    assert "recentRelay" in escalation_block
    assert "state.recipeFailureStreak >= 1" in escalation_block
    assert "FailureNeedsRecipe(diagnostic)" not in source
    assert "FailureNeedsTlsProfileRotation(diagnostic)" not in source

    # The helpers must stay thin readers over the traits table.
    assert "return TraitsFor(reason).needsCooldown;" in function_body(
        policy, "bool FailureNeedsCooldown(")
    assert "return TraitsFor(reason).escalatesRecipe;" in function_body(
        policy, "bool FailureNeedsRecipeEscalation(")
    assert "return TraitsFor(reason).rotatesTls;" in function_body(
        policy, "bool FailureNeedsTlsRotation(")
    assert "return TraitsFor(reason).routeOnly;" in function_body(
        policy, "bool FailureIsRouteOnly(")

    # Every reason has an explicit row in the table.
    for reason in (
        "None",
        "DnsFailed",
        "TcpConnectTimeout",
        "TcpConnectedNoClientHelloWrite",
        "ClientHelloSentNoServerHello",
        "TlsAlertAfterClientHello",
        "ServerHelloHmacMismatch",
        "ServerHelloOkNoAppData",
        "ServerHelloOkNoMtprotoData",
        "AppDataRemoteClosed",
        "ConnectedNoMtprotoData",
        "MtpReceiveTimeoutAfterData",
        "Network",
        "ProxyProtocolBadResponse",
    ):
        assert f"case FailureReason::{reason}:" in traits

    assert ".needsCooldown = true" in trait_row(traits, "DnsFailed")
    assert ".needsCooldown = true" not in trait_row(traits, "TcpConnectTimeout")
    assert ".needsCooldown = true" not in trait_row(
        traits, "TcpConnectedNoClientHelloWrite")
    assert ".needsCooldown = true" in trait_row(
        traits, "ClientHelloSentNoServerHello")
    assert ".needsCooldown = true" in trait_row(traits, "ServerHelloOkNoAppData")
    assert ".needsCooldown = true" not in trait_row(traits, "AppDataRemoteClosed")

    assert ".escalatesRecipe = true" not in trait_row(traits, "DnsFailed")
    assert ".escalatesRecipe = true" not in trait_row(traits, "TcpConnectTimeout")
    assert ".escalatesRecipe = true" in trait_row(
        traits, "ClientHelloSentNoServerHello")
    assert ".escalatesRecipe = true" not in trait_row(
        traits, "ServerHelloOkNoAppData")

    assert ".rotatesTls = true" in trait_row(traits, "ClientHelloSentNoServerHello")
    assert ".rotatesTls = true" not in trait_row(traits, "ServerHelloOkNoAppData")
    assert ".routeOnly = true" in trait_row(traits, "TcpConnectTimeout")
    assert ".routeOnly = true" in trait_row(
        traits, "TcpConnectedNoClientHelloWrite")
    assert "FailureIsRouteOnly(report.reason)" in report_failure
    assert report_failure.index("NoteRouteFailure(") < report_failure.index(
        "FailureIsRouteOnly(report.reason)")
    assert report_failure.index("FailureIsRouteOnly(report.reason)") < (
        report_failure.index("state.lastFailure = report.reason;"))

    assert 'u"server_hello_ok_no_appdata"_q' not in adaptive_recipe
    assert 'u"tcp_connect_timeout"_q' not in adaptive_recipe
    assert 'u"server_hello_ok_no_appdata"_q' not in adaptive_rotation


def test_serverhello_ok_no_appdata_keeps_recipe_and_profile():
    health = read(ENDPOINT_HEALTH_CPP)
    capabilities = read(ENDPOINT_HEALTH_CAPABILITIES_CPP)
    policy_source = read(ENDPOINT_HEALTH_POLICY_CPP)
    adaptive = read(ADAPTIVE_POLICY_CPP)
    report_failure = function_body(health, "void EndpointHealth::reportFailure(")
    traits = function_body(policy_source, "FailureTraits TraitsFor(")
    adaptive_recipe = function_body(adaptive, "bool FailureNeedsRecipe(")
    adaptive_rotation = function_body(
        adaptive,
        "bool FailureNeedsTlsProfileRotation(")

    for diagnostic in (
        "client_hello_sent_no_server_hello",
        "tls_alert_after_client_hello",
        "server_hello_hmac_mismatch",
    ):
        assert diagnostic in adaptive_recipe
        assert diagnostic in adaptive_rotation

    for forbidden in (
        "server_hello_ok_no_appdata",
        "server_hello_ok_no_mtproto_data",
        "connected_no_mtproto_data",
        "mtp_receive_timeout_after_data",
    ):
        assert forbidden not in adaptive_recipe
        assert forbidden not in adaptive_rotation

    no_appdata_row = trait_row(traits, "ServerHelloOkNoAppData")
    assert ".escalatesRecipe = true" not in no_appdata_row
    assert ".rotatesTls = true" not in no_appdata_row

    assert "runtime->proxyServices().capabilities().noteMtproxyFailure(" in (
        capabilities)
    assert "report.reason" in report_failure
    assert "FailureReason::ServerHelloOkNoAppData" in report_failure
    assert "FailureReason::ServerHelloOkNoMtprotoData" in report_failure
    assert "FailureReason::ConnectedNoMtprotoData" in report_failure

    assert "FailureNeedsTlsRotation(report.reason)" not in report_failure
    assert "DowngradeRecipeForRelayStall" not in policy_source
    assert "--state.recipeLevel;" not in policy_source
    assert "DowngradeRecipeForRelayStall" not in report_failure
    assert "++state.recipeLevel;" in report_failure
    assert "FailureNeedsRecipeEscalation(report.reason)" in report_failure

    assert "EndpointConcurrencyPolicy" not in policy_source
    assert "EvaluateEndpointAdmission(" not in policy_source
    assert "activeCap" not in policy_source
    arbiter_header = read(ARBITER_H)
    arbiter = read(ARBITER_CPP)
    pool_header = read(LIVE_POOL_H)
    pool_source = read(LIVE_POOL_CPP)
    for deleted in (
        "EndpointOpenGateStage",
        "kEndpointOpeningPermitCount",
        "kPressureWindow",
        "kOpenDelays",
        "kRecoveryOpenSpacing",
    ):
        assert deleted not in arbiter_header
        assert deleted not in arbiter
    assert '#include "mtproto/proxy/endpoint_live_pool.h"' in arbiter_header
    assert "struct EndpointLivePool" in pool_header
    assert "std::map<QString, MtProxy::EndpointLivePool> _pools;" in arbiter
    assert "EndpointOpeningPermit" not in arbiter_header
    assert "struct EndpointPhysicalOpeningBoundary" in read(
        ENDPOINT_HEALTH_STATE_H)
    assert "CurrentPhysicalOpeningBoundary(" in arbiter
    boundary = function_body(
        arbiter, "TicketOpeningBoundary OpeningBoundaryForTicket(")
    assert ".at = ticket.notBeforeAt" in boundary
    assert "CurrentPhysicalOpeningBoundary(" in boundary
    assert "physical.retryUntil > result.at" in boundary
    pressure_reasons = function_body(
        pool_source, "bool IsCapacityPressureTerminal(")
    for reason in (
            "TcpConnectTimeout",
            "ClientHelloSentNoServerHello",
            "ServerHelloOkNoAppData",
            "ServerHelloOkNoMtprotoData",
            "ConnectedNoMtprotoData"):
        assert f"case FailureReason::{reason}:" in pressure_reasons
    terminal = function_body(
        pool_source,
        "LiveSlotTerminalReduction MarkLiveSlotCapacityTerminal(")
    assert "!request.finalEndpointTerminal" in terminal
    assert "!IsCapacityPressureTerminal(request.reason)" in terminal
    for rejected in (
            "DnsFailed",
            "TcpConnectedNoClientHelloWrite",
            "TlsAlertAfterClientHello",
            "ServerHelloHmacMismatch",
            "AppDataRemoteClosed",
            "MtpReceiveTimeoutAfterData",
            "Network",
            "ProxyProtocolBadResponse"):
        row = pressure_reasons.split(
            f"case FailureReason::{rejected}:", 1)[1]
        assert "return false;" in row
    assert "physicalOpeningBoundary" not in report_failure
    capacity_terminal = function_body(
        arbiter,
        "void EndpointAdmissionArbiter::Private::markCapacityTerminal(")
    assert "const auto exactOpening" in capacity_terminal
    assert "MtProxy::ApplyPhysicalOpeningTerminal(" in capacity_terminal


def test_logs_and_proxy_status_use_phase_specific_names():
    status_h = read(STATUS_H)
    status_types = read(CONNECTION_STATUS_TYPES_H)
    status_cpp = read(STATUS_CPP)
    diagnostics = read(DIAGNOSTICS_CPP)
    widget = read(CONNECTING_WIDGET)
    lang = read(LANG)

    for reason in (
        "DnsFailed",
        "TcpConnectTimeout",
        "TcpConnectedNoClientHelloWrite",
        "ClientHelloSentNoServerHello",
        "ServerHelloOkNoAppData",
        "AppDataRemoteClosed",
        "ProxyProtocolBadResponse",
    ):
        assert f"ProxyMtproxyTerminalReason::{reason}" in status_cpp
        assert reason in status_types

    for diagnostic in (
        "dns_failed",
        "tcp_connect_timeout",
        "tcp_connected_no_client_hello_write",
        "client_hello_sent_no_server_hello",
        "server_hello_ok_no_appdata",
        "appdata_remote_closed",
        "proxy_protocol_bad_response",
    ):
        assert diagnostic in diagnostics

    for kind in (
        "MtproxyDnsFailed",
        "MtproxyTcpConnectTimeout",
        "MtproxyTcpConnectedNoClientHelloWrite",
        "MtproxyServerHelloOkNoAppData",
        "MtproxyAppDataRemoteClosed",
        "MtproxyProxyProtocolBadResponse",
    ):
        assert f"ProxyConnectionStatusKind::{kind}" in status_cpp
        assert kind in status_h
        assert kind in widget

    for key in (
        "lng_proxy_status_mtproxy_dns_failed",
        "lng_proxy_status_mtproxy_tcp_timeout",
        "lng_proxy_status_mtproxy_tcp_no_client_hello",
        "lng_proxy_status_mtproxy_no_server_hello",
        "lng_proxy_status_mtproxy_no_appdata",
        "lng_proxy_status_mtproxy_appdata_closed",
        "lng_proxy_status_mtproxy_bad_response",
    ):
        assert f'"{key}' in lang


def test_proxy_check_timeout_uses_phase_reasons_without_session_admission():
    session = read_session_private_sources()
    check = read(CHECK_CPP)
    adapter = read(PROXY_ADAPTER_CPP)
    timeout_body = function_body(session, "void SessionTransport::connectingTimedOut()")
    report_timeout = function_body(
        adapter, "void ProductionSessionProxyPort::reportConnectTimeout(")
    check_reason = function_body(check, "MtProxy::FailureReason ProxyCheckFailureReason(")

    assert "connection.data->timedOut();" in timeout_body
    assert "reportConnectTimeout(" not in timeout_body
    assert "proxyAttempt(connection)" not in timeout_body
    assert "mtproxyLease" not in timeout_body
    assert "MtProxy::FailureReason::TcpConnectTimeout" in report_timeout
    assert "ClaimAttemptTerminal(attempt)" in report_timeout
    assert "lease->capacityTerminal(reason, true);" in report_timeout
    assert report_timeout.index("ReportConnectionFailure(") < (
        report_timeout.index("lease->capacityTerminal(reason, true);"))
    assert "MtProxy::FailureReason::TcpConnectTimeout" in check_reason
    assert "MtProxy::FailureReason::DnsFailed" in check_reason
    assert "MtProxy::FailureReason::AppDataRemoteClosed" in check_reason
    assert "MtProxy::FailureReason::ProxyProtocolBadResponse" in check_reason
    assert "MtProxy::FailureReason::Timeout" not in timeout_body


if __name__ == "__main__":
    test_failure_reason_enum_is_phase_specific()
    test_tls_socket_reports_timeout_by_handshake_phase()
    test_phase_cooldown_and_recipe_policy_is_reason_based()
    test_serverhello_ok_no_appdata_keeps_recipe_and_profile()
    test_logs_and_proxy_status_use_phase_specific_names()
    test_proxy_check_timeout_uses_phase_reasons_without_session_admission()
