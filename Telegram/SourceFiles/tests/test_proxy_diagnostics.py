from pathlib import Path


SOURCE_DIR = Path(__file__).resolve().parents[1]
ROOT = SOURCE_DIR.parents[1]
CMAKE = ROOT / "Telegram" / "CMakeLists.txt"
LANG = SOURCE_DIR.parent / "Resources" / "langs" / "lang.strings"
PROXY_DIR = SOURCE_DIR / "mtproto" / "proxy"
DIAGNOSTICS_H = PROXY_DIR / "diagnostics.h"
DIAGNOSTICS_CPP = PROXY_DIR / "diagnostics.cpp"
INSTANCE_CPP = SOURCE_DIR / "mtproto" / "mtp_instance.cpp"
ABSTRACT_CONNECTION_CPP = SOURCE_DIR / "mtproto" / "connection_abstract.cpp"
ABSTRACT_SOCKET_CPP = SOURCE_DIR / "mtproto" / "details" / "mtproto_abstract_socket.cpp"
RESOLVING_CPP = PROXY_DIR / "resolving_connection.cpp"
TCP_CPP = SOURCE_DIR / "mtproto" / "connection_tcp.cpp"
HTTP_CPP = SOURCE_DIR / "mtproto" / "connection_http.cpp"
PROXY_CHECK_CPP = PROXY_DIR / "check.cpp"
CONNECTION_BOX_CPP = SOURCE_DIR / "boxes" / "connection_box.cpp"
CONNECTION_BOX_H = SOURCE_DIR / "boxes" / "connection_box.h"
SETTINGS_MAIN_CPP = SOURCE_DIR / "settings" / "sections" / "settings_main.cpp"


def read(path):
    assert path.exists(), f"missing expected source file: {path}"
    return path.read_text(encoding="utf-8")


def test_diagnostics_model_is_registered_and_bounded():
    cmake = read(CMAKE)
    header = read(DIAGNOSTICS_H)
    source = read(DIAGNOSTICS_CPP)

    assert "mtproto/proxy/diagnostics.cpp" in cmake
    assert "mtproto/proxy/diagnostics.h" in cmake
    assert "enum class ProxyDiagnosticsSource" in header
    assert "enum class ProxyDiagnosticsPhase" in header
    assert "struct ProxyDiagnosticsEvent" in header
    assert "ProxyDiagnosticsEventsValue()" in header
    assert "ProxyDiagnosticsSnapshot()" in header
    assert "LoadProxyDiagnosticsTail(" in header
    assert "constexpr auto kProxyDiagnosticsLimit" in source
    assert "if (copy.size() > kProxyDiagnosticsLimit)" in source
    assert "copy.erase(copy.begin(), copy.end() - kProxyDiagnosticsLimit);" in source
    assert "while (copy.size() > kProxyDiagnosticsLimit)" not in source


def test_diagnostics_event_stream_does_not_require_event_equality():
    source = read(DIAGNOSTICS_CPP)

    assert "Events.force_assign(std::move(copy));" in source
    assert "Events = std::move(copy);" not in source


def test_diagnostics_tail_trimming_is_linear():
    source = read(DIAGNOSTICS_CPP)

    assert "removeFirst()" not in source
    assert "result.erase(begin(result));" not in source
    assert "result = result.mid(result.size() - maxLines);" in source
    assert "result.erase(result.begin(), result.end() - maxLines);" in source


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
    abstract_connection = read(ABSTRACT_CONNECTION_CPP)
    abstract_socket = read(ABSTRACT_SOCKET_CPP)
    resolving = read(RESOLVING_CPP)
    tcp = read(TCP_CPP)
    http = read(HTTP_CPP)
    proxy_check = read(PROXY_CHECK_CPP)

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


def test_proxy_reporting_is_centralized():
    header = read(DIAGNOSTICS_H)
    diagnostics = read(DIAGNOSTICS_CPP)
    instance = read(INSTANCE_CPP)
    resolving = read(RESOLVING_CPP)
    tcp = read(TCP_CPP)
    http = read(HTTP_CPP)
    proxy_check = read(PROXY_CHECK_CPP)

    assert "struct ProxyEventReport" in header
    assert "void ReportProxyEvent(" in header
    assert "StatusPhaseFromDiagnostics" in diagnostics
    assert "SourceForProxy" in diagnostics
    assert "setProxyConnectionStatus" in diagnostics
    assert "crl::on_main" in diagnostics

    for transport in (resolving, tcp, http):
        assert "ReportProxyEvent(_instance, {" in transport
        assert "SetProxyConnectionStatus" not in transport
        assert "AddProxyDiagnosticsEvent" not in transport
    assert "ReportProxyEvent(mtproto, {" in proxy_check
    assert "AddProxyDiagnosticsEvent" not in proxy_check

    assert "selected proxy status changed" not in instance
    assert "AddProxyDiagnosticsEvent" not in instance


def test_proxy_logs_have_separate_settings_entry():
    lang = read(LANG)
    box = read(CONNECTION_BOX_CPP)
    header = read(CONNECTION_BOX_H)
    settings = read(SETTINGS_MAIN_CPP)

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

    assert "class ProxyLogsBox final : public Ui::BoxContent" in box
    assert "ProxiesBoxController::CreateLogsBox()" in box
    assert "static object_ptr<Ui::BoxContent> CreateLogsBox();" in header
    assert 'id = u"main/proxy_logs"_q' in settings
    assert "tr::lng_proxy_logs_tab()" in settings
    assert "ProxiesBoxController::CreateLogsBox()" in settings
    assert "setupLogsSection" not in box
    assert "ProxyDiagnosticsEventsValue(" in box
    assert "LoadProxyDiagnosticsTail(" in box
    assert "File::ShowInFolder(cWorkingDir() + u\"DebugLogs\"" in box
    assert "TextUtilities::SetClipboardText" in box
    assert "Ui::SettingsSlider" in box
    assert "_logsSearch" in box
    assert "_logsSearchQuery" in box


def test_proxy_logs_file_tail_load_is_user_triggered():
    box = read(CONNECTION_BOX_CPP)
    setup_start = box.index("void ProxyLogsBox::setupContent()")
    refresh_button = box.index(
        "const auto refresh = Settings::AddButtonWithIcon",
        setup_start)
    open_button = box.index("const auto open = Settings::AddButtonWithIcon")
    initial_setup = box[setup_start:refresh_button]
    refresh_block = box[refresh_button:open_button]

    assert "_logsSnapshot = MTP::ProxyDiagnosticsSnapshot();" in initial_setup
    assert "LoadProxyDiagnosticsTail(" not in initial_setup
    assert "LoadProxyDiagnosticsTail(" in refresh_block


def test_proxy_logs_initial_snapshot_is_rendered_once():
    box = read(CONNECTION_BOX_CPP)
    setup = box[
        box.index("void ProxyLogsBox::setupContent()"):
        box.index("void ProxyLogsBox::refreshLogsView()")]

    assert "_logsSnapshot = MTP::ProxyDiagnosticsSnapshot();" in setup
    assert "ProxyDiagnosticsEventsValue(\n\t) | rpl::skip(1)" in setup
    assert "refreshLogsView();\n\n\tinner->resizeToWidth" in setup


def test_logs_view_renders_one_text_string_per_line():
    box = read(CONNECTION_BOX_CPP)

    # Ui::Text::String stores block positions as uint16 (64K chars max),
    # so feeding the whole joined log tail into one FlatLabel overflows
    # them and asserts in lib_ui text.cpp:590 (crash on opening the
    # proxy diagnostics logs). The logs view must keep one Text::String per
    # log line, with a defensive per-line length cap.
    assert "class ProxyLogsView" in box
    assert "QPointer<ProxyLogsView> _logsView" in box
    assert "_logsView->setLines(" in box
    assert "constexpr auto kMaxLineLength" in box
    assert "QPointer<Ui::FlatLabel> _logsView" not in box


if __name__ == "__main__":
    test_diagnostics_model_is_registered_and_bounded()
    test_diagnostics_event_stream_does_not_require_event_equality()
    test_diagnostics_tail_trimming_is_linear()
    test_diagnostics_redacts_secret_material()
    test_transport_paths_emit_diagnostics()
    test_proxy_reporting_is_centralized()
    test_proxy_logs_have_separate_settings_entry()
    test_proxy_logs_file_tail_load_is_user_triggered()
    test_proxy_logs_initial_snapshot_is_rendered_once()
    test_logs_view_renders_one_text_string_per_line()
