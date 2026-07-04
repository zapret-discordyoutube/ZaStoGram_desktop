import re
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


def proxy_event_report_fields():
    header = read(DIAGNOSTICS_H)
    body = header.split("struct ProxyEventReport {", 1)[1].split("};", 1)[0]
    fields = []
    for statement in body.split(";"):
        declaration = statement.split("=", 1)[0].strip()
        if not declaration:
            continue
        fields.append(declaration.rsplit(None, 1)[1])
    return fields


def test_diagnostics_model_is_disk_only():
    cmake = read(CMAKE)
    header = read(DIAGNOSTICS_H)
    source = read(DIAGNOSTICS_CPP)

    assert "mtproto/proxy/diagnostics.cpp" in cmake
    assert "mtproto/proxy/diagnostics.h" in cmake
    assert "enum class ProxyDiagnosticsSource" in header
    assert "enum class ProxyDiagnosticsPhase" in header
    assert "struct ProxyDiagnosticsEvent" in header
    assert "ProxyMtproxyTerminalReason mtproxyReason" in header
    assert "ProxyConnectionAttempt attempt" in header
    assert "WriteProxyDiagnosticsLine(" in header
    assert "Logs::writeMtproxy(line);" in source
    assert "ProxyDiagnosticsEventsValue" not in header
    assert "ProxyDiagnosticsSnapshot" not in header
    assert "LoadProxyDiagnosticsTail(" not in header
    assert "AddProxyDiagnosticsEvent" not in header
    assert "rpl::variable" not in source
    assert "Events.current()" not in source


def test_diagnostics_has_no_in_memory_event_stream():
    source = read(DIAGNOSTICS_CPP)

    assert "Events.force_assign" not in source
    assert "Events.value()" not in source
    assert "std::vector<ProxyDiagnosticsEvent>" not in source


def test_diagnostics_does_not_read_back_log_files():
    source = read(DIAGNOSTICS_CPP)

    assert "TailLines(" not in source
    assert "SourceFromFileName(" not in source
    assert "SeverityFromLine(" not in source
    assert "removeFirst()" not in source
    assert "result.erase(begin(result));" not in source
    assert "result = result.mid(result.size() - maxLines);" not in source
    assert "result.erase(result.begin(), result.end() - maxLines);" not in source


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
    assert "ProxyMtproxyTerminalReason mtproxyReason" in header
    assert "ProxyConnectionAttempt attempt" in header
    assert "void ReportProxyEvent(" in header
    assert "StatusPhaseFromDiagnostics" in diagnostics
    assert "SourceForProxy" in diagnostics
    assert "setProxyConnectionStatus" in diagnostics
    assert "WriteProxyDiagnosticsLine({" in diagnostics
    assert "report.mtproxyReason" in diagnostics
    assert "report.attempt" in diagnostics
    assert "InvokeQueued(instance" in diagnostics

    for transport in (resolving, tcp, http):
        assert "ReportProxyEvent(_instance, {" in transport
        assert "SetProxyConnectionStatus" not in transport
        assert "AddProxyDiagnosticsEvent" not in transport
    assert "ReportProxyEvent(mtproto, {" in proxy_check
    assert "AddProxyDiagnosticsEvent" not in proxy_check

    assert "selected proxy status changed" not in instance
    assert "AddProxyDiagnosticsEvent" not in instance


def test_proxy_event_report_designators_follow_declaration_order():
    order = {
        name: index
        for index, name in enumerate(proxy_event_report_fields())
    }

    for path in (SOURCE_DIR / "mtproto").rglob("*.cpp"):
        text = read(path)
        for match in re.finditer(
                r"ReportProxyEvent\([^;]*?\{(?P<body>.*?)\}\);",
                text,
                re.DOTALL):
            designators = [
                name
                for name in re.findall(r"\.(\w+)\s*=", match.group("body"))
                if name in order
            ]
            indexes = [order[name] for name in designators]
            assert indexes == sorted(indexes), (
                f"{path.relative_to(ROOT)} has out-of-order "
                f"ProxyEventReport designators: {designators}")


def test_proxy_logs_have_no_separate_settings_entry():
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
        assert f'"{key}' not in lang

    assert "class ProxyLogsBox final : public Ui::BoxContent" not in box
    assert "class ProxyLogsView" not in box
    assert "ProxiesBoxController::CreateLogsBox()" not in box
    assert "static object_ptr<Ui::BoxContent> CreateLogsBox();" not in header
    assert 'id = u"main/proxy_logs"_q' not in settings
    assert "tr::lng_proxy_logs_tab()" not in settings
    assert "ProxyDiagnosticsEventsValue(" not in box
    assert "LoadProxyDiagnosticsTail(" not in box
    assert "_logsSearch" not in box
    assert "_logsSearchQuery" not in box


def test_proxy_logs_ui_does_not_render_log_memory():
    box = read(CONNECTION_BOX_CPP)

    assert "ProxyDiagnosticsSnapshot" not in box
    assert "_logsSnapshot" not in box
    assert "_logsVisibleText" not in box
    assert "QPointer<ProxyLogsView> _logsView" not in box


if __name__ == "__main__":
    test_diagnostics_model_is_disk_only()
    test_diagnostics_has_no_in_memory_event_stream()
    test_diagnostics_does_not_read_back_log_files()
    test_diagnostics_redacts_secret_material()
    test_transport_paths_emit_diagnostics()
    test_proxy_reporting_is_centralized()
    test_proxy_logs_have_no_separate_settings_entry()
    test_proxy_logs_ui_does_not_render_log_memory()
