from pathlib import Path
from session_private_sources import read_session_private_sources


SOURCE_DIR = Path(__file__).resolve().parents[1]
SESSION_TRANSPORT_H = SOURCE_DIR / "mtproto" / "session" / "private" / "transport.h"
TLS_SOCKET_CPP = SOURCE_DIR / "mtproto" / "proxy" / "mtproxy" / "tls_socket.cpp"
CONNECTION_CPP = SOURCE_DIR / "mtproto" / "session" / "private" / "connection.cpp"
TRANSPORT_CPP = SOURCE_DIR / "mtproto" / "session" / "private" / "transport.cpp"
CHECK_CPP = SOURCE_DIR / "mtproto" / "proxy" / "check.cpp"
DIAL_PACER_CPP = SOURCE_DIR / "mtproto" / "proxy" / "dial_pacer.cpp"
TCP_CONNECTION_CPP = SOURCE_DIR / "mtproto" / "transport" / "connection_tcp.cpp"


def test_session_bypasses_endpoint_admission_and_local_cooldown():
    header = SESSION_TRANSPORT_H.read_text(encoding="utf-8")
    source = read_session_private_sources()
    append_body = function_body(
        source,
        "bool SessionTransport::appendTestConnection(")

    assert "_endpointCooldownUntil" not in header
    assert "_endpointCooldownUntil" not in source
    assert "noteTestConnectionFailure" not in header
    assert "noteTestConnectionFailure" not in source
    assert "kEndpointCooldownPenalty" not in source
    assert "MtproxyEndpointCooldown(" not in source
    assert "EndpointHealth::Instance().admit(" not in append_body
    assert "_owner->_proxyPort->requestConnection({" not in append_body
    assert "SessionProxyAdmissionDecision" not in append_body
    assert "ReserveHandshakeGateForProxy" not in append_body
    assert "_owner->_connectionFactory->create(" in append_body
    assert "weak->connectToServer(" in append_body
    assert "admission queue, no health cooldown" in append_body
    # MTProxy may still pace its independent handshakes. The pacer itself
    # must reject other proxy types: WEB connections are logical streams on
    # one carrier and must never inherit MTProxy failure memory or queues.
    assert "ReserveProxyDial(_owner->_runtime, proxy)" in append_body
    pacer = DIAL_PACER_CPP.read_text(encoding="utf-8")
    reserve = function_body(pacer, "ProxyDialLease ReserveProxyDial(")
    assert "proxy.type != ProxyData::Type::Mtproto" in reserve
    assert "setState(-int(admission.retryAfter));" not in append_body


def test_web_proxy_connect_budget_covers_browser_handshake():
    source = TCP_CONNECTION_CPP.read_text(encoding="utf-8")
    timeout = function_body(
        source, "crl::time TcpConnection::fullConnectTimeout() const")
    connect = function_body(
        source, "void TcpConnection::connectToServer(")

    assert "kWebProxyFullConnectionTimeout" in source
    assert "ProxyData::Type::Web" in timeout
    assert "kWebProxyFullConnectionTimeout" in timeout
    assert "const auto proxyProtocol" in connect
    assert "|| (_proxy.type == ProxyData::Type::Web)" in connect
    assert "const auto secret = proxyProtocol" in connect
    assert "if (proxyProtocol)" in connect


def function_body(text: str, signature: str) -> str:
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
    raise AssertionError("body not found")


if __name__ == "__main__":
    test_session_bypasses_endpoint_admission_and_local_cooldown()
    test_web_proxy_connect_budget_covers_browser_handshake()
