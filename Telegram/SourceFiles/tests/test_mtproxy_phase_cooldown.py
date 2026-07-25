from pathlib import Path
from session_private_sources import read_session_private_sources


SOURCE_DIR = Path(__file__).resolve().parents[1]
MTPROXY_DIR = SOURCE_DIR / "mtproto" / "proxy" / "mtproxy"
RUNTIME_DIR = SOURCE_DIR / "mtproto" / "runtime"
ENDPOINT_IDENTITY_H = MTPROXY_DIR / "endpoint_identity.h"
TLS_SOCKET_H = MTPROXY_DIR / "tls_socket.h"
TLS_SOCKET_CPP = MTPROXY_DIR / "tls_socket.cpp"
STATUS_H = SOURCE_DIR / "mtproto" / "proxy" / "status.h"
STATUS_CPP = SOURCE_DIR / "mtproto" / "proxy" / "status.cpp"
DIAGNOSTICS_CPP = SOURCE_DIR / "mtproto" / "proxy" / "diagnostics.cpp"
SESSION_CPP = SOURCE_DIR / "mtproto" / "session" / "private" / "session_private.cpp"
CHECK_CPP = SOURCE_DIR / "mtproto" / "proxy" / "check.cpp"
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
