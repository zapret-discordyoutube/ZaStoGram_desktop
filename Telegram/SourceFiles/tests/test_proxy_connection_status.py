import re
from pathlib import Path


SOURCE_DIR = Path(__file__).resolve().parents[1]
LANG = SOURCE_DIR.parent / "Resources" / "langs" / "lang.strings"
INSTANCE_H = SOURCE_DIR / "mtproto" / "mtp_instance.h"
INSTANCE_CPP = SOURCE_DIR / "mtproto" / "mtp_instance.cpp"
ABSTRACT_CONNECTION_H = SOURCE_DIR / "mtproto" / "connection_abstract.h"
DIAGNOSTICS_CPP = SOURCE_DIR / "mtproto" / "proxy_diagnostics.cpp"
TCP_CONNECTION_CPP = SOURCE_DIR / "mtproto" / "connection_tcp.cpp"
ABSTRACT_SOCKET_H = SOURCE_DIR / "mtproto" / "details" / "mtproto_abstract_socket.h"
ABSTRACT_SOCKET_CPP = SOURCE_DIR / "mtproto" / "details" / "mtproto_abstract_socket.cpp"
CONNECTING_WIDGET = SOURCE_DIR / "window" / "window_connecting_widget.cpp"


def test_proxy_status_model_is_exposed_to_ui():
    instance_header = INSTANCE_H.read_text(encoding="utf-8")
    abstract_connection = ABSTRACT_CONNECTION_H.read_text(encoding="utf-8")
    source = INSTANCE_CPP.read_text(encoding="utf-8")
    widget = CONNECTING_WIDGET.read_text(encoding="utf-8")

    assert "struct ProxyConnectionStatus" in abstract_connection
    assert "proxyConnectionStatusValue()" in instance_header
    assert "setProxyConnectionStatus(ProxyConnectionStatus status)" in instance_header
    assert "rpl::variable<ProxyConnectionStatus> _proxyConnectionStatus" in source
    assert "proxyConnectionStatusValue()" in widget
    assert "ProxyConnectionStatusText(" in widget


def test_proxy_status_tracks_phases_and_socket_errors():
    abstract_connection = ABSTRACT_CONNECTION_H.read_text(encoding="utf-8")
    abstract_socket_h = ABSTRACT_SOCKET_H.read_text(encoding="utf-8")
    abstract_socket_cpp = ABSTRACT_SOCKET_CPP.read_text(encoding="utf-8")
    diagnostics = DIAGNOSTICS_CPP.read_text(encoding="utf-8")
    tcp_connection = TCP_CONNECTION_CPP.read_text(encoding="utf-8")

    assert "enum class ProxyConnectionPhase" in abstract_connection
    assert "enum class ProxyConnectionError" in abstract_connection
    assert "void connectionProgress(HandshakePhase phase)" in abstract_socket_h
    assert "rpl::producer<HandshakePhase> progress() const" in abstract_socket_h
    assert "ProxyAuthenticationRequiredError" in abstract_socket_cpp
    assert "ProxyConnectionError::Authentication" in abstract_socket_cpp
    assert "ReportProxyEvent(_instance, {" in tcp_connection
    assert "setProxyConnectionStatus(status)" in diagnostics
    assert "ProxyConnectionPhase::CheckingTelegram" in diagnostics


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
        r"tr::now,\s*lt_count,\s*state\.waitTillRetry,\s*lt_error,\s*error",
        call.group(1))


if __name__ == "__main__":
    test_proxy_status_model_is_exposed_to_ui()
    test_proxy_status_tracks_phases_and_socket_errors()
    test_visible_proxy_phrases_exist()
    test_proxy_retry_with_error_uses_generated_argument_order()
