from pathlib import Path
from session_private_sources import read_session_private_sources


SOURCE_DIR = Path(__file__).resolve().parents[1]
ROOT = SOURCE_DIR.parents[1]
CMAKE = ROOT / "Telegram" / "CMakeLists.txt"
PROXY_DIR = SOURCE_DIR / "mtproto" / "proxy"
GATE_H = PROXY_DIR / "handshake_gate.h"
GATE_CPP = PROXY_DIR / "handshake_gate.cpp"
SESSION_H = SOURCE_DIR / "mtproto" / "session" / "private" / "session_private.h"
SESSION_CPP = SOURCE_DIR / "mtproto" / "session" / "private" / "session_private.cpp"
TRANSPORT_H = SOURCE_DIR / "mtproto" / "session" / "private" / "transport.h"
SESSION_PROXY_ADAPTER_CPP = PROXY_DIR / "session_proxy_adapter.cpp"
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
    assert "[[nodiscard]] HandshakeGateLease ReserveHandshakeGate(" in header
    assert "not_null<RuntimeEnvironment*> runtime" in header
    assert "[[nodiscard]] HandshakeGateLease ReserveHandshakeGateForProxy(" in header
    assert "std::atomic<int>" in source
    assert "kHandshakeGateCap = 3" in source
    assert "kHandshakeGateStep = crl::time(200)" in source
    assert "kHandshakeGateMaxDelay = crl::time(2000)" in source
    assert "kHandshakeGateJitterLimit = crl::time(100)" in source
    assert "fetch_add(" in source
    assert "compare_exchange_weak" in source
    assert "_active" in header
    assert "_active = false" in source


def test_session_private_uses_endpoint_health_for_live_mtproxy_attempts():
    header = SESSION_H.read_text(encoding="utf-8")
    transport_header = TRANSPORT_H.read_text(encoding="utf-8")
    adapter = SESSION_PROXY_ADAPTER_CPP.read_text(encoding="utf-8")
    source = read_session_private_sources()

    assert '#include "mtproto/session/private/proxy_port.h"' in header
    assert "not_null<SessionProxyPort*> _proxyPort;" in header
    assert "MtProxy::EndpointAttemptLease mtproxyLease;" in transport_header
    assert "std::vector<SessionProxyTicket> brokerTickets;" in transport_header
    assert "ReserveHandshakeGateForProxy(_sessionState.options->proxy)" not in source
    assert "EndpointHealth::Instance().admit(" not in source
    assert "_proxyPort->requestConnection({" in source
    assert "proxyServices().broker().request(" in adapter
    assert "std::move(start.lease)" in source


def test_remove_connection_releases_before_erasing():
    source = read_session_private_sources()
    body = body_after(
        source,
        "void SessionTransport::removeTestConnection")

    assert "i->mtproxyLease.release();" in body
    assert body.index("i->mtproxyLease.release();") < body.index(
        "_state.testConnections.erase(")


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
    assert "void releaseGate();" not in header
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
    assert "details::ReserveHandshakeGateForProxy(" in start_body
    assert "runtime,\n\t\t\tproxy)" in start_body
    assert "const auto state = checker.state();" in start_body
    assert "const auto gateDelay = state->handshakeGate.delay();" in start_body
    assert "runtime->proxyServices().broker().request({" in start_body
    assert ".notBefore = gateDelay" in start_body
    assert "MtProxy::EndpointUse::ProxyCheck" in start_body
    assert "state->handshakeGate.release();" in start_body
    assert "[=, &checker]" not in start_body


def test_proxy_check_release_paths_are_complete():
    proxy_check = PROXY_CHECK_CPP.read_text(encoding="utf-8")
    reset_method = body_after(proxy_check, "void ProxyCheckConnection::reset")
    reset_body = body_after(proxy_check, "void ResetProxyCheckers")
    drop_body = body_after(proxy_check, "void DropProxyChecker")
    start_body = body_after(proxy_check, "void StartProxyCheck")

    assert "_data->handshakeGate.release();" in reset_method
    assert "_data->connectionTicket.cancel();" in reset_method
    assert "_data->mtproxyLease.release();" in reset_method
    assert "releaseGate();" not in reset_body
    assert "releaseGate();" not in drop_body
    assert start_body.count("state->handshakeGate.release();") >= 2


def test_proxy_check_uses_connection_timeout_contract():
    proxy_check = PROXY_CHECK_CPP.read_text(encoding="utf-8")
    start_body = body_after(proxy_check, "void StartProxyCheck")

    assert "kProxyCheckTimeout" not in proxy_check
    assert "raw->fullConnectTimeout()" in start_body
    assert ".notBefore = gateDelay" in start_body
    assert "QTimer::singleShot(int(raw->fullConnectTimeout()), raw," in start_body
    assert "ProxyConnectionError::Timeout" in start_body
    assert "raw->timedOut();" in start_body
    assert "fail(raw);" in start_body


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
    test_session_private_uses_endpoint_health_for_live_mtproxy_attempts()
    test_remove_connection_releases_before_erasing()
    test_proxy_check_connection_holds_gate_lease()
    test_proxy_check_connection_raii_releases_gate()
    test_proxy_check_starts_are_soft_gated()
    test_proxy_check_release_paths_are_complete()
    test_proxy_check_uses_connection_timeout_contract()
    test_proxy_check_call_sites_use_wrapper_type()
