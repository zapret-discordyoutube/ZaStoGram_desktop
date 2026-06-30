from pathlib import Path


SOURCE_DIR = Path(__file__).resolve().parents[1]
ROOT = SOURCE_DIR.parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "win.yml"
PREPARE_PY = ROOT / "Telegram" / "build" / "prepare" / "prepare.py"
LOGS_H = SOURCE_DIR / "logs.h"
LOGS_CPP = SOURCE_DIR / "logs.cpp"
ABSTRACT_CONNECTION_CPP = SOURCE_DIR / "mtproto" / "connection_abstract.cpp"
ABSTRACT_SOCKET_CPP = (
    SOURCE_DIR / "mtproto" / "details" / "mtproto_abstract_socket.cpp"
)
TCP_CONNECTION_CPP = SOURCE_DIR / "mtproto" / "connection_tcp.cpp"


def test_windows_artifact_uses_release_configuration():
    workflow = WORKFLOW.read_text(encoding="utf-8")

    assert "-D CMAKE_CONFIGURATION_TYPES=Release" in workflow
    assert "DESKTOP_APP_ENABLE_LTO=${{" in workflow
    assert "-D DESKTOP_APP_DISABLE_AUTOUPDATE=ON" in workflow
    assert "cmake --build ..\\out --config Release --target Telegram --parallel" in workflow
    assert "set OUT=%TBUILD%\\%REPO_NAME%\\out\\Release" in workflow
    assert "%TBUILD%\\%REPO_NAME%\\Telegram\\build\\prepare\\win.bat skip-release" not in workflow
    assert "-D DESKTOP_APP_DISABLE_AUTOUPDATE=OFF" not in workflow
    assert "move %OUT%\\Updater.exe artifact/" not in workflow
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


def test_mtproxy_logs_have_release_visible_stream():
    logs_h = LOGS_H.read_text(encoding="utf-8")
    logs_cpp = LOGS_CPP.read_text(encoding="utf-8")
    abstract_connection = ABSTRACT_CONNECTION_CPP.read_text(encoding="utf-8")
    abstract_socket = ABSTRACT_SOCKET_CPP.read_text(encoding="utf-8")

    assert "void writeMtproxy(const QString &v);" in logs_h
    assert "LogDataMtproxy" in logs_cpp
    assert 'u"DebugLogs/mtproxy"_q' in logs_cpp
    assert "AlwaysWriteLogData(type)" in logs_cpp
    assert "Logs::writeMtproxy(" in abstract_connection
    assert "Logs::writeMtproxy(" in abstract_socket


def test_mtproxy_progress_errors_and_success_are_reported():
    tcp_connection = TCP_CONNECTION_CPP.read_text(encoding="utf-8")

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
    assert "ProxyConnectionPhase::Handshake" in tcp_connection
    assert "ProxyConnectionPhase::CheckingTelegram" in tcp_connection
    assert "ProxyConnectionPhase::Connected" in tcp_connection


if __name__ == "__main__":
    test_windows_artifact_uses_release_configuration()
    test_windows_ci_prepares_release_dependencies_only()
    test_windows_dependency_caches_save_before_compile()
    test_mtproxy_logs_have_release_visible_stream()
    test_mtproxy_progress_errors_and_success_are_reported()
