from pathlib import Path


SOURCE_DIR = Path(__file__).resolve().parents[1]
ROOT = SOURCE_DIR.parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "win.yml"
PREPARE_PY = ROOT / "Telegram" / "build" / "prepare" / "prepare.py"
ROOT_CMAKE = ROOT / "CMakeLists.txt"
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


def test_windows_artifact_uses_release_configuration():
    workflow = WORKFLOW.read_text(encoding="utf-8")

    assert "-D CMAKE_CONFIGURATION_TYPES=Release" in workflow
    assert "DESKTOP_APP_ENABLE_LTO=${{" in workflow
    # Self-hosted auto-updates: the fork builds with autoupdate enabled.
    assert "-D DESKTOP_APP_DISABLE_AUTOUPDATE=OFF" in workflow
    assert "cmake --build ..\\out --config Release --target Telegram Packer --parallel" in workflow
    assert "set OUT=%TBUILD%\\%REPO_NAME%\\out\\Release" in workflow
    assert "%TBUILD%\\%REPO_NAME%\\Telegram\\build\\prepare\\win.bat skip-release" not in workflow
    assert "-D DESKTOP_APP_DISABLE_AUTOUPDATE=ON" not in workflow
    assert "move %OUT%\\Updater.exe artifact/" in workflow
    assert "release/Updater-$arch.exe" not in workflow
    assert "-D CMAKE_CONFIGURATION_TYPES=Debug" not in workflow
    assert "cmake --build ..\\out --config Debug" not in workflow
    assert "set OUT=%TBUILD%\\%REPO_NAME%\\out\\Debug" not in workflow


def test_windows_ci_prepares_release_dependencies_only():
    workflow = WORKFLOW.read_text(encoding="utf-8")
    prepare = PREPARE_PY.read_text(encoding="utf-8")

    assert "'skip-debug'," in prepare
    assert "buildScopes = ('debug', 'release', 'releaseonly')" in prepare
    assert "if 'debug' in scopes and 'skip-debug' in options:" in prepare
    assert "releaseonly:" in prepare
    assert "SET CONFIGURATIONS=-release" in prepare
    assert "win_debug:\n    msbuild -m LzmaLib.sln" in prepare
    assert "win_debug:\n    jom -j%NUMBER_OF_PROCESSORS% build_libs" in prepare
    assert "win.bat skip-debug silent" in workflow
    assert "win.bat skip-release" not in workflow


def test_windows_dependency_caches_save_before_compile():
    workflow = WORKFLOW.read_text(encoding="utf-8")

    build_libraries = workflow.index("- name: Libraries.")
    save_third_party = workflow.index("- name: ThirdParty cache (save).")
    save_libraries = workflow.index("- name: Libraries cache (save).")
    save_qt = workflow.index("- name: Qt cache (save).")
    telegram_build = workflow.index("- name: Telegram Desktop build.")

    assert build_libraries < save_third_party < telegram_build
    assert build_libraries < save_libraries < telegram_build
    assert build_libraries < save_qt < telegram_build
    assert workflow.count("steps.build-libs.outcome == 'success'") == 3
    assert workflow.count("continue-on-error: true") >= 3
    assert "steps.cache-third-party.outputs.cache-hit != 'true'" in workflow
    assert "steps.cache-libs.outputs.cache-hit != 'true'" in workflow
    assert "steps.cache-qt.outputs.cache-hit != 'true'" in workflow


def test_windows_telegram_build_tree_cache_survives_compile_failures():
    workflow = WORKFLOW.read_text(encoding="utf-8")

    restore_build_tree = workflow.index("- name: Telegram build cache (restore).")
    normalize_mtimes = workflow.index("- name: Normalize Telegram source mtimes.")
    telegram_build = workflow.index("- name: Telegram Desktop build.")
    cache_metadata = workflow.index("- name: Telegram build cache metadata.")
    save_build_tree = workflow.index("- name: Telegram build cache (save).")
    move_artifact = workflow.index("- name: Move artifact.")

    assert restore_build_tree < normalize_mtimes < telegram_build
    assert telegram_build < cache_metadata < save_build_tree < move_artifact
    assert "TELEGRAM_BUILD_CACHE_VERSION: \"v2\"" in workflow
    assert "TELEGRAM_BUILD_CACHE_SCOPE=" in workflow
    assert "TELEGRAM_BUILD_CACHE_KEY=" in workflow
    assert "TELEGRAM_BUILD_CACHE_RESTORE_KEY=" in workflow
    assert "TELEGRAM_BUILD_CACHE_PROGRESS_KEY=" in workflow
    assert "TELEGRAM_BUILD_CACHE_LOOKUP_KEY=" in workflow
    assert "uses: actions/cache/restore@v5" in workflow
    assert "uses: actions/cache/save@v5" in workflow
    assert "id: cache-telegram-build" in workflow
    assert "${{ env.TBUILD }}\\${{ env.REPO_NAME }}\\out" in workflow
    assert "!${{ env.TBUILD }}\\${{ env.REPO_NAME }}\\out\\Release\\Telegram.exe" in workflow
    assert "steps.build-telegram.outcome == 'failure'" in workflow
    assert "key: ${{ env.TELEGRAM_BUILD_CACHE_LOOKUP_KEY }}" in workflow
    assert (
        "restore-keys: |\n"
        "            ${{ env.TELEGRAM_BUILD_CACHE_RESTORE_KEY }}-progress-\n"
        "            ${{ env.TELEGRAM_BUILD_CACHE_RESTORE_KEY }}\n"
        "            ${{ env.TELEGRAM_BUILD_CACHE_SCOPE }}-"
    ) in workflow
    assert "${{ env.TELEGRAM_BUILD_CACHE_RESTORE_KEY }}-progress-" in workflow
    assert "${{ env.TELEGRAM_BUILD_CACHE_RESTORE_KEY }}" in workflow
    assert "${{ env.TELEGRAM_BUILD_CACHE_SCOPE }}-" in workflow
    assert "env.TELEGRAM_BUILD_CACHE_PROGRESS_KEY" in workflow
    assert "env.TELEGRAM_BUILD_CACHE_RESTORE_KEY" in workflow
    assert "steps.cache-telegram-build.outputs.cache-matched-key != env.TELEGRAM_BUILD_CACHE_RESTORE_KEY" in workflow
    assert "steps.cache-telegram-build.outputs.cache-primary-key" not in workflow
    assert "steps.build-telegram.outcome != 'skipped'" in workflow
    assert "always()" in workflow[save_build_tree:move_artifact]
    assert "steps.cache-telegram-build.outputs.cache-matched-key != ''" in workflow
    assert ".telegram_build_cache_metadata" in workflow
    assert "TELEGRAM_BUILD_CACHE_HIT: ${{ steps.cache-telegram-build.outputs.cache-hit }}" in workflow
    assert "TELEGRAM_BUILD_CACHE_MATCHED_KEY: ${{ steps.cache-telegram-build.outputs.cache-matched-key }}" in workflow
    assert "TELEGRAM_BUILD_CACHE_HIT\") == \"true\"" in workflow
    assert "dc7fc515605489f2486904c1a2d3e60811335b54" in workflow
    assert "97e7512e600590ca2254c7bd523c2b07346b494f8c07d2334e9fff922a2c7e73" in workflow
    assert "e48a776cea3c96cdf4cfbf0bcd71426b2945ba854f733ac6c1774413f89253bb" in workflow
    assert "GITHUB_EVENT_BEFORE" not in workflow
    assert "TELEGRAM_SKIP_CONFIGURE=true" in workflow
    assert "Reusing restored CMake configure." in workflow
    assert "[\"git\", \"fetch\", \"--no-tags\", \"--depth=1\", \"origin\", value]" in workflow
    assert "\"CMakeLists.txt\"" in workflow
    assert "item.endswith(\".cmake\")" in workflow
    assert "mtime: CMake graph changed, configure will run" in workflow
    assert "\"diff\"," in workflow
    assert "\"--name-only\"," in workflow
    assert "os.utime(path, (old_mtime, old_mtime))" in workflow
    assert "follow_symlinks" not in workflow


def test_windows_sccache_server_is_started_and_cleaned_up():
    workflow = WORKFLOW.read_text(encoding="utf-8")

    install_sccache = workflow.index("- name: sccache.")
    start_sccache = workflow.index("- name: Start sccache server.")
    telegram_build = workflow.index("- name: Telegram Desktop build.")
    sccache_stats = workflow.index("- name: sccache stats.")
    stop_sccache = workflow.index("- name: Stop sccache server.")
    move_artifact = workflow.index("- name: Move artifact.")

    assert install_sccache < start_sccache < telegram_build
    assert sccache_stats < stop_sccache < move_artifact
    assert "disable_annotations: \"true\"" in workflow
    assert "SCCACHE_IDLE_TIMEOUT: \"600\"" in workflow
    assert "SCCACHE_SERVER_PORT=$SCCACHE_SERVER_PORT" in workflow
    assert "${SCCACHE_PATH:-sccache} --start-server" in workflow
    assert "${SCCACHE_PATH:-sccache} --zero-stats" in workflow
    assert "${SCCACHE_PATH:-sccache} --stop-server || true" in workflow
    assert "SCCACHE_IDLE_TIMEOUT: \"0\"" not in workflow


def test_windows_ffmpeg_links_static_dav1d_dependency():
    prepare = PREPARE_PY.read_text(encoding="utf-8")
    cmake = ROOT_CMAKE.read_text(encoding="utf-8")

    assert "--enable-libdav1d" in prepare
    assert "target_link_libraries(external_ffmpeg" in cmake
    assert "dav1d/builddir-$<IF:$<CONFIG:Debug>,debug,release>/src/libdav1d.a" in cmake


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
    test_wss_route_toggle_refresh_captures_proxy_box()
    test_mtproxy_logs_have_release_visible_stream()
    test_mtproxy_progress_errors_and_success_are_reported()
