from pathlib import Path


SOURCE_DIR = Path(__file__).resolve().parents[1]
ROOT = SOURCE_DIR.parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "win.yml"
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
    assert "cmake --build ..\\out --config Release --parallel" in workflow
    assert "set OUT=%TBUILD%\\%REPO_NAME%\\out\\Release" in workflow
    assert "-D CMAKE_CONFIGURATION_TYPES=Debug" not in workflow
    assert "cmake --build ..\\out --config Debug" not in workflow
    assert "set OUT=%TBUILD%\\%REPO_NAME%\\out\\Debug" not in workflow


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
    test_mtproxy_logs_have_release_visible_stream()
    test_mtproxy_progress_errors_and_success_are_reported()
