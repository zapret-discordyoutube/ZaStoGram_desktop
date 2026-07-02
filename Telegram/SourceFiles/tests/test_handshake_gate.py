from pathlib import Path


SOURCE_DIR = Path(__file__).resolve().parents[1]
ROOT = SOURCE_DIR.parents[1]
CMAKE = ROOT / "Telegram" / "CMakeLists.txt"
PROXY_DIR = SOURCE_DIR / "mtproto" / "proxy"
GATE_H = PROXY_DIR / "handshake_gate.h"
GATE_CPP = PROXY_DIR / "handshake_gate.cpp"
SESSION_H = SOURCE_DIR / "mtproto" / "session_private.h"
SESSION_CPP = SOURCE_DIR / "mtproto" / "session_private.cpp"
PROXY_CHECK_H = PROXY_DIR / "check.h"
PROXY_CHECK_CPP = PROXY_DIR / "check.cpp"
CONNECTION_BOX_H = SOURCE_DIR / "boxes" / "connection_box.h"


def test_gate_module_is_registered():
    cmake = CMAKE.read_text(encoding="utf-8")

    assert GATE_H.exists()
    assert GATE_CPP.exists()
    assert "mtproto/proxy/handshake_gate.cpp" in cmake
    assert "mtproto/proxy/handshake_gate.h" in cmake


def test_gate_lease_api_and_constants():
    header = GATE_H.read_text(encoding="utf-8")
    source = GATE_CPP.read_text(encoding="utf-8")

    assert "class HandshakeGateLease" in header
    assert "HandshakeGateLease(const HandshakeGateLease &other) = delete;" in header
    assert "HandshakeGateLease &operator=(" in header
    assert "[[nodiscard]] crl::time delay() const;" in header
    assert "void release();" in header
    assert "~HandshakeGateLease();" in header
    assert "[[nodiscard]] HandshakeGateLease ReserveHandshakeGate();" in header
    assert "std::atomic<int>" in source
    assert "kHandshakeGateCap = 3" in source
    assert "kHandshakeGateStep = crl::time(200)" in source
    assert "kHandshakeGateMaxDelay = crl::time(2000)" in source
    assert "kHandshakeGateJitterLimit = crl::time(100)" in source
    assert "fetch_add(" in source
    assert "compare_exchange_weak" in source
    assert "_active" in header
    assert "_active = false" in source


def test_session_private_uses_gate_for_proxied_test_connections():
    header = SESSION_H.read_text(encoding="utf-8")
    source = SESSION_CPP.read_text(encoding="utf-8")

    assert '#include "mtproto/proxy/handshake_gate.h"' in header
    assert "HandshakeGateLease handshakeGate;" in header
    assert "const auto proxied = (_options->proxy.type != ProxyData::Type::None);" in source
    assert "auto handshakeGate = proxied" in source
    assert "? ReserveHandshakeGate()" in source
    assert "const auto gateDelay = handshakeGate.delay();" in source
    assert "std::move(handshakeGate)" in source
    assert "const auto startDelay = spacing *" in source
    assert "+ gateDelay;" in source
    assert "i->handshakeGate.release();" in source


def test_remove_connection_releases_before_erasing():
    source = SESSION_CPP.read_text(encoding="utf-8")
    body = body_after(
        source,
        "void SessionPrivate::removeTestConnection")

    assert "i->handshakeGate.release();" in body
    assert body.index("i->handshakeGate.release();") < body.index(
        "_testConnections.erase(")


def test_proxy_check_connection_holds_gate_lease():
    header = PROXY_CHECK_H.read_text(encoding="utf-8")

    assert '#include "mtproto/proxy/handshake_gate.h"' in header
    assert "class ProxyCheckConnection" in header
    assert "#include <memory>" in header
    assert "struct Data" in header
    assert "std::shared_ptr<Data>" in header
    assert "details::ConnectionPointer connection;" in header
    assert "details::HandshakeGateLease handshakeGate;" in header
    assert "details::AbstractConnection *get() const;" in header
    assert "void reset();" in header
    assert "void releaseGate();" in header
    assert "~ProxyCheckConnection();" in header


def test_proxy_check_connection_raii_releases_gate():
    proxy_check = PROXY_CHECK_CPP.read_text(encoding="utf-8")
    destructor_body = body_after(
        proxy_check,
        "ProxyCheckConnection::~ProxyCheckConnection")
    move_assignment_body = body_after(
        proxy_check,
        "ProxyCheckConnection &ProxyCheckConnection::operator=")

    assert "reset();" in destructor_body
    assert "reset();" in move_assignment_body


def test_proxy_check_starts_are_soft_gated():
    proxy_check = PROXY_CHECK_CPP.read_text(encoding="utf-8")
    start_body = body_after(proxy_check, "void StartProxyCheck")

    assert '#include <QtCore/QTimer>' in proxy_check
    assert "const auto proxied = (proxy.type != ProxyData::Type::None);" in start_body
    assert "auto handshakeGate = proxied" in start_body
    assert "? details::ReserveHandshakeGate()" in start_body
    assert "const auto state = checker.state();" in start_body
    assert "const auto gateDelay = state->handshakeGate.delay();" in start_body
    assert "QTimer::singleShot(int(gateDelay), raw, start);" in start_body
    assert "state->handshakeGate.release();" in start_body
    assert "[=, &checker]" not in start_body


def test_proxy_check_release_paths_are_complete():
    proxy_check = PROXY_CHECK_CPP.read_text(encoding="utf-8")
    reset_body = body_after(proxy_check, "void ResetProxyCheckers")
    drop_body = body_after(proxy_check, "void DropProxyChecker")
    start_body = body_after(proxy_check, "void StartProxyCheck")

    assert "v4.releaseGate();" in reset_body
    assert "v6.releaseGate();" in reset_body
    assert "v4.releaseGate();" in drop_body
    assert "v6.releaseGate();" in drop_body
    assert start_body.count("state->handshakeGate.release();") >= 2


def test_proxy_check_call_sites_use_wrapper_type():
    header = CONNECTION_BOX_H.read_text(encoding="utf-8")

    assert "using Checker = MTP::ProxyCheckConnection;" in header
    assert "using Checker = MTP::details::ConnectionPointer;" not in header


def body_after(text: str, signature: str) -> str:
    start = text.index(signature)
    brace = text.index(" {\n", start) + 1
    depth = 0
    for index in range(brace, len(text)):
        char = text[index]
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return text[brace + 1:index]
    raise AssertionError(f"body not found for {signature}")


if __name__ == "__main__":
    test_gate_module_is_registered()
    test_gate_lease_api_and_constants()
    test_session_private_uses_gate_for_proxied_test_connections()
    test_remove_connection_releases_before_erasing()
    test_proxy_check_connection_holds_gate_lease()
    test_proxy_check_connection_raii_releases_gate()
    test_proxy_check_starts_are_soft_gated()
    test_proxy_check_release_paths_are_complete()
    test_proxy_check_call_sites_use_wrapper_type()
