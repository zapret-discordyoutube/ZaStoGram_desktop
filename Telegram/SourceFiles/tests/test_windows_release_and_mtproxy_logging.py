from pathlib import Path


SOURCE_DIR = Path(__file__).resolve().parents[1]
ROOT = SOURCE_DIR.parents[1]
PREPARE_PY = ROOT / "Telegram" / "build" / "prepare" / "prepare.py"
ROOT_CMAKE = ROOT / "CMakeLists.txt"
TELEGRAM_CMAKE = ROOT / "Telegram" / "CMakeLists.txt"
CONNECTION_BOX_CPP = SOURCE_DIR / "boxes" / "connection_box.cpp"
LOGS_H = SOURCE_DIR / "logs.h"
LOGS_CPP = SOURCE_DIR / "logs.cpp"
ABSTRACT_CONNECTION_CPP = SOURCE_DIR / "mtproto" / "transport" / "connection_abstract.cpp"
ABSTRACT_SOCKET_CPP = (
    SOURCE_DIR / "mtproto" / "transport" / "details" / "mtproto_abstract_socket.cpp"
)
TCP_CONNECTION_CPP = SOURCE_DIR / "mtproto" / "transport" / "connection_tcp.cpp"
DIAGNOSTICS_H = SOURCE_DIR / "mtproto" / "proxy" / "diagnostics.h"
DIAGNOSTICS_CPP = SOURCE_DIR / "mtproto" / "proxy" / "diagnostics.cpp"
RUNTIME_CPP = SOURCE_DIR / "mtproto" / "runtime" / "runtime_environment.cpp"


def test_windows_release_preparation_can_skip_debug_dependencies():
    prepare = PREPARE_PY.read_text(encoding="utf-8")

    assert "'skip-debug'," in prepare
    assert "buildScopes = ('debug', 'release', 'releaseonly')" in prepare
    assert "if 'debug' in scopes and 'skip-debug' in options:" in prepare
    assert "releaseonly:" in prepare
    assert "SET CONFIGURATIONS=-release" in prepare
    assert "win_debug:\n    msbuild -m LzmaLib.sln" in prepare
    assert "win_debug:\n    jom -j%NUMBER_OF_PROCESSORS% build_libs" in prepare


def test_windows_ffmpeg_links_static_dav1d_dependency():
    prepare = PREPARE_PY.read_text(encoding="utf-8")
    cmake = ROOT_CMAKE.read_text(encoding="utf-8")

    assert "--enable-libdav1d" in prepare
    assert "target_link_libraries(external_ffmpeg" in cmake
    assert "dav1d/builddir-$<IF:$<CONFIG:Debug>,debug,release>/src/libdav1d.a" in cmake


def test_windows_telegram_links_qt_network_dns_dependencies():
    telegram_cmake = TELEGRAM_CMAKE.read_text(encoding="utf-8")

    assert "        Dnsapi\n" in telegram_cmake
    assert "/DELAYLOAD:dnsapi.dll" in telegram_cmake


def test_wss_route_toggle_refresh_captures_proxy_box():
    connection_box = CONNECTION_BOX_CPP.read_text(encoding="utf-8")
    route_toggle = connection_box.split("_routeViaWss = addStealthToggle(", 1)[1]
    route_toggle = route_toggle.split("right->add(", 1)[0]

    assert "[this](bool on)" in route_toggle
    assert "refreshRouteViaWss();" in route_toggle


def test_mtproxy_logs_have_release_visible_stream():
    logs_h = LOGS_H.read_text(encoding="utf-8")
    logs_cpp = LOGS_CPP.read_text(encoding="utf-8")
    abstract_connection = ABSTRACT_CONNECTION_CPP.read_text(encoding="utf-8")
    abstract_socket = ABSTRACT_SOCKET_CPP.read_text(encoding="utf-8")
    diagnostics_source = DIAGNOSTICS_CPP.read_text(encoding="utf-8")
    runtime_source = RUNTIME_CPP.read_text(encoding="utf-8")

    assert "void writeMtproxy(const QString &v);" in logs_h
    assert "LogDataMtproxy" in logs_cpp
    assert 'u"DebugLogs/mtproxy"_q' in logs_cpp
    assert "AlwaysWriteLogData(type)" in logs_cpp
    assert "WriteProxyDiagnosticsLine(" in abstract_connection
    assert "WriteProxyDiagnosticsLine(" in abstract_socket
    assert "runtime->diagnostics().reportProxyEvent" in diagnostics_source
    assert "Logs::writeMtproxy(" in runtime_source
    assert "AddProxyDiagnosticsEvent" not in diagnostics_source
    assert "ProxyDiagnosticsEventsValue" not in diagnostics_source
    assert "LoadProxyDiagnosticsTail" not in diagnostics_source


def test_debug_logs_use_one_run_file_with_weekly_retention():
    logs_cpp = LOGS_CPP.read_text(encoding="utf-8")

    assert "RunScopedDebugLogPath(" in logs_cpp
    assert "CleanOldDebugLogs(" in logs_cpp
    assert "kDebugLogRetentionDays = 7" in logs_cpp
    assert "kDebugLogRetentionCheckPeriod = crl::time(24 * 60 * 60 * 1000)" in logs_cpp
    assert "debugLogRunId" in logs_cpp
    assert "debugLogOpened" in logs_cpp
    assert "reopenDebug()" not in logs_cpp
    assert "switchEach = 15" not in logs_cpp
    assert "reopen(LogDataMtproxy, dayIndex, postfix)" not in logs_cpp


def test_mtproxy_progress_errors_and_success_are_reported():
    tcp_connection = TCP_CONNECTION_CPP.read_text(encoding="utf-8")
    control_source = (
        SOURCE_DIR / "mtproto" / "proxy" / "control_plane.cpp"
    ).read_text(encoding="utf-8")

    assert "_socket->progress(" in tcp_connection
    assert "socketProgress(phase);" in tcp_connection
    assert "socketError(errorCode);" in tcp_connection
    assert "void TcpConnection::socketProgress(HandshakePhase phase)" in tcp_connection
    assert "void TcpConnection::socketError(int errorCode)" in tcp_connection
    assert "SocketProxyConnectionError(errorCode)" in tcp_connection
    assert "HandshakePhase::TcpConnected" in tcp_connection
    assert "HandshakePhase::ClientHelloSent" in tcp_connection
    assert "HandshakePhase::ServerHelloOk" in tcp_connection
    assert "HandshakePhase::FirstDataReceived" in tcp_connection
    assert "ProxyDiagnosticsPhase::ClientHelloSent" in tcp_connection
    assert "ProxyDiagnosticsPhase::TelegramCheck" in tcp_connection
    assert "ProxyDiagnosticsPhase::Connected" in tcp_connection
    assert "ProxyConnectionPhase::Handshake" in control_source
    assert "ProxyConnectionPhase::CheckingTelegram" in control_source
    assert "ProxyConnectionPhase::Connected" in control_source


if __name__ == "__main__":
    test_windows_artifact_uses_release_configuration()
    test_windows_ci_prepares_release_dependencies_only()
    test_windows_dependency_caches_save_before_compile()
    test_windows_telegram_build_tree_cache_survives_compile_failures()
    test_windows_sccache_server_is_started_and_cleaned_up()
    test_windows_ffmpeg_links_static_dav1d_dependency()
    test_windows_telegram_links_qt_network_dns_dependencies()
    test_wss_route_toggle_refresh_captures_proxy_box()
    test_mtproxy_logs_have_release_visible_stream()
    test_mtproxy_progress_errors_and_success_are_reported()
