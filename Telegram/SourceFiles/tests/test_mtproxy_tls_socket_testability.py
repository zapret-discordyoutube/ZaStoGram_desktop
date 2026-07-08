from pathlib import Path
import re


SOURCE_DIR = Path(__file__).resolve().parents[1]
ROOT = SOURCE_DIR.parents[1]
MTPROXY_DIR = SOURCE_DIR / "mtproto" / "proxy" / "mtproxy"
CMAKE_TESTS = ROOT / "Telegram" / "cmake" / "tests.cmake"
RUNTIME_H = SOURCE_DIR / "mtproto" / "runtime" / "runtime_environment.h"
RUNTIME_CPP = SOURCE_DIR / "mtproto" / "runtime" / "runtime_environment.cpp"
TLS_SOCKET_H = MTPROXY_DIR / "tls_socket.h"
TLS_SOCKET_CPP = MTPROXY_DIR / "tls_socket.cpp"
TLS_SOCKET_HANDSHAKE_CPP = MTPROXY_DIR / "tls_socket_handshake.cpp"
TLS_SOCKET_RECORDS_CPP = MTPROXY_DIR / "tls_socket_records.cpp"
TLS_SOCKET_TRANSPORT_H = MTPROXY_DIR / "tls_socket_transport.h"
TLS_SOCKET_TRANSPORT_CPP = MTPROXY_DIR / "tls_socket_transport.cpp"
TLS_SOCKET_TEST = SOURCE_DIR / "tests" / "test_mtproxy_tls_socket.cpp"


def read(path):
    assert path.exists(), f"missing expected source file: {path}"
    return path.read_text(encoding="utf-8")


def test_tls_socket_has_injectable_transport_instead_of_qtcp_member():
    header = read(TLS_SOCKET_H)
    source = read(TLS_SOCKET_CPP)
    transport_header = read(TLS_SOCKET_TRANSPORT_H)
    transport_source = read(TLS_SOCKET_TRANSPORT_CPP)
    socket_sources = "\n".join(
        read(path)
        for path in (
            TLS_SOCKET_CPP,
            TLS_SOCKET_HANDSHAKE_CPP,
            TLS_SOCKET_RECORDS_CPP,
        ))

    assert "class TlsSocketTransport" in transport_header
    assert "struct TlsSocketTransportCallbacks" in transport_header
    assert "CreateTlsSocketTransport(" in transport_header
    assert "class QTcpSocketTransport final" in transport_source
    assert "QTcpSocket _socket;" in transport_source
    assert '#include "mtproto/proxy/mtproxy/tls_socket_transport.h"' in header
    assert "#include <QtNetwork/QTcpSocket>" not in header
    assert "QTcpSocket _socket;" not in header
    assert "std::unique_ptr<TlsSocketTransport> _transport;" in header
    assert "std::unique_ptr<TlsSocketTransport> transport = nullptr" in header
    assert "CreateTlsSocketTransport()" in source
    assert "setCallbacks({" in source
    assert "_transport->connectToHost(" in socket_sources
    assert "_transport->write(" in socket_sources
    assert "_transport->readAll()" in socket_sources
    assert "_transport->bytesAvailable()" in socket_sources
    assert re.search(r"\b_socket\.", socket_sources) is None


def test_tls_socket_timers_use_runtime_async_gateway():
    runtime_header = read(RUNTIME_H)
    runtime_source = read(RUNTIME_CPP)
    socket_header = read(TLS_SOCKET_H)
    socket_source = read(TLS_SOCKET_CPP)
    socket_sources = "\n".join(
        read(path)
        for path in (
            TLS_SOCKET_CPP,
            TLS_SOCKET_HANDSHAKE_CPP,
            TLS_SOCKET_RECORDS_CPP,
        ))

    assert "class RuntimeTimer final" in runtime_header
    assert "Fn<RuntimeTimer(not_null<QObject*>, Fn<void()>)> makeTimer;" in (
        runtime_header)
    assert ".makeTimer = [](" in runtime_source
    assert "std::make_shared<base::Timer>" in runtime_source
    assert "base::Timer" not in socket_header
    assert "RuntimeTimer _pacingTimer;" in socket_header
    assert "RuntimeTimer _clientHelloTimer;" in socket_header
    assert "RuntimeTimer _clientHelloFragmentTimer;" in socket_header
    assert "runtime->async().makeTimer(" in socket_source
    assert ".setCallback(" not in socket_sources


def test_mtproxy_tls_socket_cpp_smoke_target_is_registered():
    cmake = read(CMAKE_TESTS)
    test = read(TLS_SOCKET_TEST)

    assert "add_executable(test_mtproxy_tls_socket WIN32)" in cmake
    assert "mtproto/proxy/mtproxy/tls_socket_transport.cpp" in cmake
    assert "mtproto/proxy/mtproxy/tls_socket.cpp" in cmake
    assert "tests/test_mtproxy_tls_socket.cpp" in cmake
    assert "test_mtproxy_tls_socket" in cmake
    assert "class ScriptedAsync" in test
    assert "class FakeTlsSocketTransport" in test
    for scenario in (
            "ScenarioSuccessToFirstAppData",
            "ScenarioTimeoutBeforeServerHello",
            "ScenarioTlsAlertAfterClientHello",
            "ScenarioNoAppData",
            "ScenarioReconnectCancelDropsStaleCallbacks"):
        assert scenario in test
