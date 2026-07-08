from pathlib import Path


SOURCE_DIR = Path(__file__).resolve().parents[1]
ROOT = SOURCE_DIR.parents[1]
CMAKE = ROOT / "Telegram" / "CMakeLists.txt"
MTPROTO_DIR = SOURCE_DIR / "mtproto"
INSTANCE_DIR = MTPROTO_DIR / "instance"
INSTANCE_CPP = INSTANCE_DIR / "mtp_instance.cpp"
INSTANCE_H = INSTANCE_DIR / "mtp_instance.h"
REQUEST_REGISTRY_H = INSTANCE_DIR / "request_registry.h"
REQUEST_REGISTRY_CPP = INSTANCE_DIR / "request_registry.cpp"
SESSION_DELEGATE_H = MTPROTO_DIR / "session" / "session_delegate.h"


def read(path):
    assert path.exists(), f"missing expected source file: {path}"
    return path.read_text(encoding="utf-8")


def function_body(source, signature):
    start = source.index(signature)
    brace = source.index("{", start)
    depth = 0
    for index in range(brace, len(source)):
        char = source[index]
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return source[brace + 1:index]
    raise AssertionError(f"function body not found: {signature}")


def test_request_registry_sources_are_registered():
    cmake = read(CMAKE)

    assert "mtproto/instance/request_registry.cpp" in cmake
    assert "mtproto/instance/request_registry.h" in cmake
    assert read(REQUEST_REGISTRY_H)
    assert read(REQUEST_REGISTRY_CPP)


def test_instance_private_delegates_request_bookkeeping():
    instance = read(INSTANCE_CPP)
    private_body = function_body(instance, "class Instance::Private")

    assert '#include "mtproto/instance/request_registry.h"' in instance
    assert "RequestRegistry _requests;" in private_body

    for moved in (
            "_requestsByDc",
            "_requestByDcLock",
            "_parserMap",
            "_parserMapLock",
            "_requestMap",
            "_requestMapLock",
            "_delayedRequests",
            "_dependentRequests",
            "_dependentRequestsLock",
            "_requestsDelays"):
        assert moved not in private_body

    for kept in (
            "_authExportRequests",
            "_authWaiters",
            "_badGuestDcRequests"):
        assert kept in private_body


def test_request_registry_owns_rpc_state_and_locks():
    header = read(REQUEST_REGISTRY_H)
    source = read(REQUEST_REGISTRY_CPP)

    assert "class RequestRegistry final" in header
    for field in (
            "_requestsByDc",
            "_requestByDcLock",
            "_parserMap",
            "_parserMapLock",
            "_requestMap",
            "_requestMapLock",
            "_dependentRequests",
            "_dependentRequestsLock",
            "_delayedRequests",
            "_requestsDelays"):
        assert field in header

    for method in (
            "storeRequest(",
            "registerRequest(",
            "queryDc(",
            "changeDc(",
            "request(",
            "hasCallback(",
            "takeCallback(",
            "restoreCallback(",
            "unregisterRequest(",
            "prepareDependency(",
            "nextBackoffSeconds(",
            "scheduleDelayed(",
            "takeReadyDelayed(",
            "nextDelayedAt("):
        assert method in header
        assert f"RequestRegistry::{method}" in source


def test_public_instance_and_session_delegate_surfaces_stay_stable():
    instance_header = read(INSTANCE_H)
    delegate = read(SESSION_DELEGATE_H)

    assert "request_registry" not in instance_header
    assert "class RequestRegistry" not in instance_header
    assert "sendSerialized(" in instance_header
    assert "sendProtocolMessage(" in instance_header

    for callback in (
            "hasCallback(mtpRequestId requestId) const",
            "processCallback(const Response &response)",
            "processUpdate(const Response &message)"):
        assert callback in delegate


if __name__ == "__main__":
    test_request_registry_sources_are_registered()
    test_instance_private_delegates_request_bookkeeping()
    test_request_registry_owns_rpc_state_and_locks()
    test_public_instance_and_session_delegate_surfaces_stay_stable()
