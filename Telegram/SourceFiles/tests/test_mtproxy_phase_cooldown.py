from pathlib import Path


SOURCE_DIR = Path(__file__).resolve().parents[1]
MTPROXY_DIR = SOURCE_DIR / "mtproto" / "proxy" / "mtproxy"
ENDPOINT_HEALTH_H = MTPROXY_DIR / "endpoint_health.h"
ENDPOINT_HEALTH_CPP = MTPROXY_DIR / "endpoint_health.cpp"
ADAPTIVE_POLICY_CPP = MTPROXY_DIR / "adaptive_policy.cpp"
TLS_SOCKET_H = MTPROXY_DIR / "tls_socket.h"
TLS_SOCKET_CPP = MTPROXY_DIR / "tls_socket.cpp"
STATUS_H = SOURCE_DIR / "mtproto" / "proxy" / "status.h"
STATUS_CPP = SOURCE_DIR / "mtproto" / "proxy" / "status.cpp"
DIAGNOSTICS_CPP = SOURCE_DIR / "mtproto" / "proxy" / "diagnostics.cpp"
SESSION_CPP = SOURCE_DIR / "mtproto" / "session_private.cpp"
CHECK_CPP = SOURCE_DIR / "mtproto" / "proxy" / "check.cpp"
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
    header = read(ENDPOINT_HEALTH_H)

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


def test_phase_cooldown_and_recipe_policy_is_reason_based():
    source = read(ENDPOINT_HEALTH_CPP)
    adaptive = read(ADAPTIVE_POLICY_CPP)
    cooldown_body = function_body(source, "bool FailureNeedsCooldown(")
    recipe_body = function_body(source, "bool FailureNeedsRecipeEscalation(")
    rotation_body = function_body(source, "bool FailureNeedsTlsRotation(")
    route_only_body = function_body(source, "bool FailureIsRouteOnly(")
    report_failure = function_body(source, "void EndpointHealth::reportFailure(")
    adaptive_recipe = function_body(adaptive, "bool FailureNeedsRecipe(")
    adaptive_rotation = function_body(adaptive, "bool FailureNeedsTlsProfileRotation(")

    assert "FailureNeedsRecipeEscalation(state.lastFailure)" in source
    assert "policy.recipeEscalationAllowed" in report_failure
    assert "FailureNeedsTlsRotation(report.reason)" in source
    assert "FailureNeedsRecipe(diagnostic)" not in source
    assert "FailureNeedsTlsProfileRotation(diagnostic)" not in source

    assert "case FailureReason::DnsFailed:" in cooldown_body
    assert "case FailureReason::TcpConnectTimeout:" in cooldown_body
    assert "case FailureReason::TcpConnectedNoClientHelloWrite:" in cooldown_body
    assert "case FailureReason::ClientHelloSentNoServerHello:" in cooldown_body
    assert "case FailureReason::ServerHelloOkNoAppData:" in cooldown_body
    assert "case FailureReason::AppDataRemoteClosed:" in cooldown_body

    assert "case FailureReason::DnsFailed:" in recipe_body
    assert "case FailureReason::TcpConnectTimeout:" in recipe_body
    assert "case FailureReason::ClientHelloSentNoServerHello:" in recipe_body
    assert "case FailureReason::ServerHelloOkNoAppData:" in recipe_body
    assert "return false;" in recipe_body.split("case FailureReason::TcpConnectTimeout:")[1]
    assert "return true;" in recipe_body.split("case FailureReason::ClientHelloSentNoServerHello:")[1]

    assert "case FailureReason::ClientHelloSentNoServerHello:" in rotation_body
    assert "case FailureReason::ServerHelloOkNoAppData:" in rotation_body
    assert "return false;" in rotation_body.split("case FailureReason::ServerHelloOkNoAppData:")[1]
    assert "case FailureReason::TcpConnectTimeout:" in route_only_body
    assert "case FailureReason::TcpConnectedNoClientHelloWrite:" in route_only_body
    assert "return true;" in route_only_body.split("case FailureReason::TcpConnectTimeout:")[1]
    assert "FailureIsRouteOnly(report.reason)" in report_failure
    assert report_failure.index("NoteRouteFailure(") < report_failure.index(
        "FailureIsRouteOnly(report.reason)")
    assert report_failure.index("FailureIsRouteOnly(report.reason)") < (
        report_failure.index("state.lastFailure = report.reason;"))

    assert 'u"server_hello_ok_no_appdata"_q' in adaptive_recipe
    assert 'u"tcp_connect_timeout"_q' not in adaptive_recipe
    assert 'u"server_hello_ok_no_appdata"_q' not in adaptive_rotation


def test_logs_and_proxy_status_use_phase_specific_names():
    status_h = read(STATUS_H)
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
        assert reason in status_h

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


def test_proxy_check_and_session_timeout_use_phase_reasons():
    session = read(SESSION_CPP)
    check = read(CHECK_CPP)
    timeout_body = function_body(session, "void SessionPrivate::connectingTimedOut()")
    check_reason = function_body(check, "MtProxy::FailureReason ProxyCheckFailureReason(")

    assert "MtProxy::FailureReason::TcpConnectTimeout" in timeout_body
    assert "MtProxy::FailureReason::TcpConnectTimeout" in check_reason
    assert "MtProxy::FailureReason::DnsFailed" in check_reason
    assert "MtProxy::FailureReason::AppDataRemoteClosed" in check_reason
    assert "MtProxy::FailureReason::ProxyProtocolBadResponse" in check_reason
    assert "MtProxy::FailureReason::Timeout" not in timeout_body


if __name__ == "__main__":
    test_failure_reason_enum_is_phase_specific()
    test_tls_socket_reports_timeout_by_handshake_phase()
    test_phase_cooldown_and_recipe_policy_is_reason_based()
    test_logs_and_proxy_status_use_phase_specific_names()
    test_proxy_check_and_session_timeout_use_phase_reasons()
