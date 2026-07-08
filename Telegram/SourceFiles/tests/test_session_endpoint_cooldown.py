from pathlib import Path
from session_private_sources import read_session_private_sources


SOURCE_DIR = Path(__file__).resolve().parents[1]
SESSION_TRANSPORT_H = SOURCE_DIR / "mtproto" / "session" / "private" / "transport.h"
PROXY_ADAPTER_CPP = SOURCE_DIR / "mtproto" / "proxy" / "session_proxy_adapter.cpp"
TLS_SOCKET_CPP = SOURCE_DIR / "mtproto" / "proxy" / "mtproxy" / "tls_socket.cpp"
TLS_SOCKET_RECORDS_CPP = (
    SOURCE_DIR / "mtproto" / "proxy" / "mtproxy" / "tls_socket_records.cpp")
CONNECTION_BROKER_CPP = SOURCE_DIR / "mtproto" / "proxy" / "connection_broker.cpp"


def test_session_uses_endpoint_health_admission_instead_of_local_cooldown():
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
    assert "_owner->_proxyPort->requestConnection({" in append_body
    assert ".status = [=](SessionProxyAdmissionDecision)" in append_body
    assert "ConnectionBrokerAction::Queued" in CONNECTION_BROKER_CPP.read_text(
        encoding="utf-8")
    assert "ProxyDiagnosticsPhase::AdmissionQueued" in CONNECTION_BROKER_CPP.read_text(
        encoding="utf-8")
    assert "setState(-int(admission.retryAfter));" not in append_body


def test_session_keeps_mtproxy_attempt_lease_until_terminal_outcome():
    header = SESSION_TRANSPORT_H.read_text(encoding="utf-8")
    source = read_session_private_sources()

    assert "SessionProxyLease mtproxyLease;" in header
    assert "std::move(start.lease)" in source
    assert "std::vector<SessionProxyTicket> brokerTickets;" in header
    assert "i->mtproxyLease.release();" in source
    assert "reportConnectionError(" in source
    assert "reportMtproxyFailure(" in (
        PROXY_ADAPTER_CPP.read_text(encoding="utf-8"))
    assert "reportMtproxySuccess(" in (
        TLS_SOCKET_RECORDS_CPP.read_text(encoding="utf-8"))


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
    test_session_uses_endpoint_health_admission_instead_of_local_cooldown()
    test_session_keeps_mtproxy_attempt_lease_until_terminal_outcome()
