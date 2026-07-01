from pathlib import Path


SOURCE_DIR = Path(__file__).resolve().parents[1]
ROOT = SOURCE_DIR.parents[1]
CMAKE = ROOT / "Telegram" / "CMakeLists.txt"
LANG = SOURCE_DIR.parent / "Resources" / "langs" / "lang.strings"
DIAGNOSTICS_H = SOURCE_DIR / "mtproto" / "proxy_diagnostics.h"
DIAGNOSTICS_CPP = SOURCE_DIR / "mtproto" / "proxy_diagnostics.cpp"
INSTANCE_CPP = SOURCE_DIR / "mtproto" / "mtp_instance.cpp"
ABSTRACT_CONNECTION_CPP = SOURCE_DIR / "mtproto" / "connection_abstract.cpp"
ABSTRACT_SOCKET_CPP = SOURCE_DIR / "mtproto" / "details" / "mtproto_abstract_socket.cpp"
RESOLVING_CPP = SOURCE_DIR / "mtproto" / "connection_resolving.cpp"
TCP_CPP = SOURCE_DIR / "mtproto" / "connection_tcp.cpp"
HTTP_CPP = SOURCE_DIR / "mtproto" / "connection_http.cpp"
PROXY_CHECK_CPP = SOURCE_DIR / "mtproto" / "proxy_check.cpp"
CONNECTION_BOX_CPP = SOURCE_DIR / "boxes" / "connection_box.cpp"


def read(path):
    assert path.exists(), f"missing expected source file: {path}"
    return path.read_text(encoding="utf-8")


def test_diagnostics_model_is_registered_and_bounded():
    cmake = read(CMAKE)
    header = read(DIAGNOSTICS_H)
    source = read(DIAGNOSTICS_CPP)

    assert "mtproto/proxy_diagnostics.cpp" in cmake
    assert "mtproto/proxy_diagnostics.h" in cmake
    assert "enum class ProxyDiagnosticsSource" in header
    assert "enum class ProxyDiagnosticsPhase" in header
    assert "struct ProxyDiagnosticsEvent" in header
    assert "ProxyDiagnosticsEventsValue()" in header
    assert "ProxyDiagnosticsSnapshot()" in header
    assert "LoadProxyDiagnosticsTail(" in header
    assert "constexpr auto kProxyDiagnosticsLimit" in source
    assert "while (copy.size() > kProxyDiagnosticsLimit)" in source


def test_diagnostics_event_stream_does_not_require_event_equality():
    source = read(DIAGNOSTICS_CPP)

    assert "Events.force_assign(std::move(copy));" in source
    assert "Events = std::move(copy);" not in source


def test_diagnostics_redacts_secret_material():
    source = read(DIAGNOSTICS_CPP)

    assert "RedactProxyData" in source
    assert "RedactMessage" in source
    assert "password = u\"<redacted>\"_q" in source
    assert "secret = u\"<redacted>\"_q" in source
    assert "proxy.password" in source
    assert "secret|password|pass" in source
    assert "<redacted>" in source


def test_transport_paths_emit_diagnostics():
    instance = read(INSTANCE_CPP)
    abstract_connection = read(ABSTRACT_CONNECTION_CPP)
    abstract_socket = read(ABSTRACT_SOCKET_CPP)
    resolving = read(RESOLVING_CPP)
    tcp = read(TCP_CPP)
    http = read(HTTP_CPP)
    proxy_check = read(PROXY_CHECK_CPP)

    assert "AddProxyDiagnosticsEvent" in instance
    assert "ProxyDiagnosticsPhaseFromStatus" in instance
    assert "WriteProxyDiagnosticsLine" in abstract_connection
    assert "WriteProxyDiagnosticsLine" in abstract_socket
    assert "ProxyDiagnosticsPhase::Resolving" in resolving
    assert "ProxyDiagnosticsPhase::TcpConnected" in tcp
    assert "ProxyDiagnosticsPhase::ClientHelloSent" in tcp
    assert "ProxyDiagnosticsPhase::ServerHelloOk" in tcp
    assert "ProxyDiagnosticsPhase::TelegramCheck" in tcp
    assert "ProxyDiagnosticsPhase::Connected" in tcp
    assert "ProxyDiagnosticsPhase::Failed" in tcp
    assert "ProxyDiagnosticsPhase::TelegramCheck" in http
    assert "ProxyDiagnosticsPhase::ProxyCheckStarted" in proxy_check
    assert "ProxyDiagnosticsPhase::ProxyCheckFinished" in proxy_check


def test_proxy_settings_logs_tab_exists():
    lang = read(LANG)
    box = read(CONNECTION_BOX_CPP)

    for key in (
        "lng_proxy_logs_tab",
        "lng_proxy_logs_filter_all",
        "lng_proxy_logs_filter_mtproxy",
        "lng_proxy_logs_filter_network",
        "lng_proxy_logs_refresh",
        "lng_proxy_logs_copy",
        "lng_proxy_logs_open_folder",
        "lng_proxy_logs_clear",
        "lng_proxy_logs_search",
        "lng_proxy_logs_empty",
        "lng_proxy_logs_file_error",
    ):
        assert f'"{key}' in lang

    assert "setupLogsSection()" in box
    assert "ProxyDiagnosticsEventsValue()" in box
    assert "LoadProxyDiagnosticsTail(" in box
    assert "File::ShowInFolder(cWorkingDir() + u\"DebugLogs\"" in box
    assert "TextUtilities::SetClipboardText" in box
    assert "Ui::SettingsSlider" in box
    assert "_logsSearch" in box
    assert "_logsSearchQuery" in box


if __name__ == "__main__":
    test_diagnostics_model_is_registered_and_bounded()
    test_diagnostics_redacts_secret_material()
    test_transport_paths_emit_diagnostics()
    test_proxy_settings_logs_tab_exists()
