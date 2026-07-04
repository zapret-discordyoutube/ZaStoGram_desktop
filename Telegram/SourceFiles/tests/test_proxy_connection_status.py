import re
from pathlib import Path


SOURCE_DIR = Path(__file__).resolve().parents[1]
LANG = SOURCE_DIR.parent / "Resources" / "langs" / "lang.strings"
INSTANCE_H = SOURCE_DIR / "mtproto" / "mtp_instance.h"
INSTANCE_CPP = SOURCE_DIR / "mtproto" / "mtp_instance.cpp"
ABSTRACT_CONNECTION_H = SOURCE_DIR / "mtproto" / "connection_abstract.h"
STATUS_H = SOURCE_DIR / "mtproto" / "proxy" / "status.h"
STATUS_CPP = SOURCE_DIR / "mtproto" / "proxy" / "status.cpp"
DIAGNOSTICS_CPP = SOURCE_DIR / "mtproto" / "proxy" / "diagnostics.cpp"
TCP_CONNECTION_CPP = SOURCE_DIR / "mtproto" / "connection_tcp.cpp"
ABSTRACT_SOCKET_H = SOURCE_DIR / "mtproto" / "details" / "mtproto_abstract_socket.h"
ABSTRACT_SOCKET_CPP = SOURCE_DIR / "mtproto" / "details" / "mtproto_abstract_socket.cpp"
CONNECTING_WIDGET_H = SOURCE_DIR / "window" / "window_connecting_widget.h"
CONNECTING_WIDGET = SOURCE_DIR / "window" / "window_connecting_widget.cpp"


def test_proxy_status_model_is_exposed_to_ui():
    status_header = STATUS_H.read_text(encoding="utf-8")
    instance_header = INSTANCE_H.read_text(encoding="utf-8")
    abstract_connection = ABSTRACT_CONNECTION_H.read_text(encoding="utf-8")
    source = INSTANCE_CPP.read_text(encoding="utf-8")
    widget_header = CONNECTING_WIDGET_H.read_text(encoding="utf-8")
    widget = CONNECTING_WIDGET.read_text(encoding="utf-8")

    assert "struct ProxyConnectionStatus" in status_header
    assert "enum class ProxyConnectionPhase" in status_header
    assert "enum class ProxyConnectionError" in status_header
    assert "enum class ProxyMtproxyTerminalReason" in status_header
    assert "struct ProxyConnectionAttempt" in status_header
    assert "ProxyMtproxyTerminalReason mtproxyReason" in status_header
    assert "ProxyConnectionAttempt attempt" in status_header
    assert "crl::time terminalUntil" in status_header
    assert "ApplyProxyConnectionStatusUpdate(" in status_header
    assert "struct ProxyConnectionStatus" not in abstract_connection
    assert '#include "mtproto/proxy/status.h"' in instance_header
    assert '#include "mtproto/proxy/status.h"' in widget_header
    assert "proxyConnectionStatusValue()" in instance_header
    assert "setProxyConnectionStatus(ProxyConnectionStatus status)" in instance_header
    assert "rpl::variable<ProxyConnectionStatus> _proxyConnectionStatus" in source
    assert "proxyConnectionStatusValue()" in widget
    assert "ProxyConnectionStatusKindText(" in widget


def test_connection_notice_model_is_visible_without_proxy():
    status_header = STATUS_H.read_text(encoding="utf-8")
    instance_header = INSTANCE_H.read_text(encoding="utf-8")
    source = INSTANCE_CPP.read_text(encoding="utf-8")
    widget_header = CONNECTING_WIDGET_H.read_text(encoding="utf-8")
    widget = CONNECTING_WIDGET.read_text(encoding="utf-8")
    lang = LANG.read_text(encoding="utf-8")

    assert "enum class ConnectionNotice" in status_header
    assert "WssDirectFallback" in status_header
    assert "connectionNoticeValue()" in instance_header
    assert "setConnectionNotice(ShiftedDcId shiftedDcId, ConnectionNotice notice)" in instance_header
    assert "rpl::variable<ConnectionNotice> _connectionNotice" in source
    assert "connectionNoticeValue()" in widget
    assert "ConnectionNoticeText(" in widget
    assert "MTP::ConnectionNotice connectionNotice" in widget_header
    assert "ConnectionNoticeText(state.connectionNotice)" in widget
    assert "lng_connection_wss_direct_fallback" in lang


def test_proxy_status_tracks_phases_and_socket_errors():
    status_header = STATUS_H.read_text(encoding="utf-8")
    abstract_socket_h = ABSTRACT_SOCKET_H.read_text(encoding="utf-8")
    abstract_socket_cpp = ABSTRACT_SOCKET_CPP.read_text(encoding="utf-8")
    diagnostics = DIAGNOSTICS_CPP.read_text(encoding="utf-8")
    tcp_connection = TCP_CONNECTION_CPP.read_text(encoding="utf-8")

    assert "enum class ProxyConnectionPhase" in status_header
    assert "enum class ProxyConnectionError" in status_header
    assert '#include "mtproto/proxy/status.h"' in abstract_socket_h
    assert "void connectionProgress(HandshakePhase phase)" in abstract_socket_h
    assert "rpl::producer<HandshakePhase> progress() const" in abstract_socket_h
    assert "ProxyAuthenticationRequiredError" in abstract_socket_cpp
    assert "ProxyConnectionError::Authentication" in abstract_socket_cpp
    assert "ReportProxyEvent(_instance, {" in tcp_connection
    assert "setProxyConnectionStatus(status)" in diagnostics
    assert "ProxyConnectionPhase::CheckingTelegram" in diagnostics


def test_mtproxy_terminal_status_is_sticky_until_new_attempt_or_success():
    status_header = STATUS_H.read_text(encoding="utf-8")
    diagnostics = DIAGNOSTICS_CPP.read_text(encoding="utf-8")
    source = INSTANCE_CPP.read_text(encoding="utf-8")
    widget = CONNECTING_WIDGET.read_text(encoding="utf-8")

    assert "ServerHelloHmacMismatch" in status_header
    assert "IsMtproxyTerminalFailure(" in status_header
    assert "ApplyProxyConnectionStatusUpdate(" in source
    assert "ApplyProxyConnectionStatusUpdate(" in status_header
    assert "report.mtproxyReason" in diagnostics
    assert "report.attempt" in diagnostics
    assert "ProxyConnectionStatusKind::MtproxyServerHelloHmacMismatch" in widget
    assert "lng_proxy_status_mtproxy_hmac_mismatch" in LANG.read_text(
        encoding="utf-8")


def test_proxy_status_kind_and_severity_are_centralized():
    status_header = STATUS_H.read_text(encoding="utf-8")
    status_source = STATUS_CPP.read_text(encoding="utf-8")
    widget = CONNECTING_WIDGET.read_text(encoding="utf-8")
    style = (SOURCE_DIR / "window" / "window.style").read_text(
        encoding="utf-8")

    assert "enum class ProxyConnectionStatusKind" in status_header
    assert "enum class ProxyConnectionStatusSeverity" in status_header
    assert "ProxyConnectionStatusKindFor(" in status_header
    assert "ProxyConnectionStatusSeverityFor(" in status_header
    assert "ProxyConnectionStatusKindFor(status)" in widget
    assert "ProxyConnectionStatusKindText(" in widget
    assert "ProxyConnectionStatusSeverityFor(status)" in widget
    assert "ProxyConnectionStatusSeverity::Warning" in status_source
    assert "ProxyConnectionStatusSeverity::Error" in status_source
    assert "ProxyConnectionStatusSeverity::Success" in status_source
    assert "ProxyConnectionStatusKind::MtproxyServerHelloHmacMismatch" in (
        status_source)
    assert "ProxyConnectionStatusKind::MtproxyPostHandshakeNoAppData" in (
        status_source)
    assert "ProxyConnectionStatusKind::HostNotFound" in status_source
    assert "ProxyConnectionStatusKind::Timeout" in status_source
    assert "status.mtproxyReason" not in widget
    assert "status.error" not in widget
    assert "ProxyConnectionErrorText(" not in widget
    assert "connectingProxyProgress" in style
    assert "connectingProxySuccess" in style
    assert "connectingProxyWarning" in style
    assert "connectingProxyError" in style


def test_visible_proxy_phrases_exist():
    lang = LANG.read_text(encoding="utf-8")

    for key in (
        "lng_proxy_status_resolving",
        "lng_proxy_status_connecting",
        "lng_proxy_status_handshake",
        "lng_proxy_status_checking",
        "lng_proxy_status_timeout",
        "lng_proxy_status_refused",
        "lng_proxy_status_auth_failed",
        "lng_proxy_status_host_not_found",
        "lng_proxy_status_retry",
        "lng_proxy_status_retry_with_error",
    ):
        assert f'"{key}' in lang


def test_proxy_retry_with_error_uses_generated_argument_order():
    widget = CONNECTING_WIDGET.read_text(encoding="utf-8")
    call = re.search(
        r"tr::lng_proxy_status_retry_with_error\((.*?)\);",
        widget,
        re.S)

    assert call
    assert re.search(
        r"tr::now,\s*lt_count,\s*state\.waitTillRetry,\s*lt_error,\s*statusText",
        call.group(1))


if __name__ == "__main__":
    test_proxy_status_model_is_exposed_to_ui()
    test_connection_notice_model_is_visible_without_proxy()
    test_proxy_status_tracks_phases_and_socket_errors()
    test_mtproxy_terminal_status_is_sticky_until_new_attempt_or_success()
    test_proxy_status_kind_and_severity_are_centralized()
    test_visible_proxy_phrases_exist()
    test_proxy_retry_with_error_uses_generated_argument_order()
