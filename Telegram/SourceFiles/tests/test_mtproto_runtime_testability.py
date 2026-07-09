from pathlib import Path


SOURCE_DIR = Path(__file__).resolve().parents[1]
ROOT = SOURCE_DIR.parents[1]
CMAKE_TESTS = ROOT / "Telegram" / "cmake" / "tests.cmake"
RUNTIME_H = SOURCE_DIR / "mtproto" / "runtime" / "runtime_environment.h"
RUNTIME_CPP = SOURCE_DIR / "mtproto" / "runtime" / "runtime_environment.cpp"
BROKER_CPP = SOURCE_DIR / "mtproto" / "proxy" / "connection_broker.cpp"
OPEN_SCHEDULER_H = (
    SOURCE_DIR / "mtproto" / "proxy" / "mtproxy" / "open_scheduler.h")
OPEN_SCHEDULER_CPP = (
    SOURCE_DIR / "mtproto" / "proxy" / "mtproxy" / "open_scheduler.cpp")
HANDSHAKE_GATE_H = SOURCE_DIR / "mtproto" / "proxy" / "handshake_gate.h"
HANDSHAKE_GATE_CPP = SOURCE_DIR / "mtproto" / "proxy" / "handshake_gate.cpp"
OPEN_SCHEDULER_TEST = SOURCE_DIR / "tests" / "test_mtproxy_open_scheduler.cpp"


def read(path):
    assert path.exists(), f"missing expected source file: {path}"
    return path.read_text(encoding="utf-8")


def test_runtime_environment_exposes_async_gateway():
    header = read(RUNTIME_H)
    source = read(RUNTIME_CPP)

    assert "struct RuntimeAsyncGateway final" in header
    assert "Fn<crl::time()> now;" in header
    assert "Fn<int(int)> randomIndex;" in header
    assert "Fn<void(crl::time, QObject*, Fn<void()>)> singleShot;" in header
    assert "RuntimeAsyncGateway async;" in header
    assert "const RuntimeAsyncGateway &async() const;" in header
    assert "RuntimeAsyncGateway CreateAsyncGateway()" in source
    assert ".async = CreateAsyncGateway()" in source
    assert "crl::now();" in source
    assert "base::RandomIndex(limit);" in source
    assert "QTimer::singleShot(int(delay)" in source


def test_connection_broker_uses_runtime_async_gateway():
    source = read(BROKER_CPP)

    assert "_runtime->async().now()" in source
    assert "_runtime->async().singleShot(" in source
    assert "QTimer::singleShot" not in source
    assert "MtProxy::ReserveOpenSlot(" in source
    assert "IsProxyCheck(state->request.use)" in source
    assert "\t\t\t: MtProxy::ReserveOpenSlot(" in source


def test_open_scheduler_is_injectable_and_has_cpp_smoke_test():
    header = read(OPEN_SCHEDULER_H)
    source = read(OPEN_SCHEDULER_CPP)
    cmake = read(CMAKE_TESTS)
    test = read(OPEN_SCHEDULER_TEST)

    assert "class OpenScheduler final" in header
    assert "explicit OpenScheduler(not_null<RuntimeEnvironment*> runtime);" in header
    assert "ReserveOpenSlot(\n\tnot_null<RuntimeEnvironment*> runtime" in header
    assert "OpenScheduler::ReserveOpenSlot(" in source
    assert "OpenScheduler(runtime)" in source
    assert "runtime->proxyEndpointContextShared()" in source
    assert "_async.now()" in source
    assert "_async.randomIndex(" in source
    assert "test_mtproxy_open_scheduler" in cmake
    assert "tests/test_mtproxy_open_scheduler.cpp" in cmake
    assert "struct FakeAsync" in test
    assert "OpenScheduler(fake.gateway())" in test


def test_handshake_gate_delay_uses_runtime_randomness():
    header = read(HANDSHAKE_GATE_H)
    source = read(HANDSHAKE_GATE_CPP)

    assert "ReserveHandshakeGate(" in header
    assert "ReserveHandshakeGateForProxy(" in header
    assert "not_null<RuntimeEnvironment*> runtime" in header
    assert "runtime->async().randomIndex(" in source
    assert "base::RandomIndex(" not in source
