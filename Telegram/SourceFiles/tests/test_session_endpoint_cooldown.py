from pathlib import Path
from session_private_sources import read_session_private_sources


SOURCE_DIR = Path(__file__).resolve().parents[1]
SESSION_TRANSPORT_H = SOURCE_DIR / "mtproto" / "session" / "private" / "transport.h"
PROXY_ADAPTER_CPP = SOURCE_DIR / "mtproto" / "proxy" / "session_proxy_adapter.cpp"
TLS_SOCKET_CPP = SOURCE_DIR / "mtproto" / "proxy" / "mtproxy" / "tls_socket.cpp"
TLS_SOCKET_RECORDS_CPP = (
    SOURCE_DIR / "mtproto" / "proxy" / "mtproxy" / "tls_socket_records.cpp")
CONNECTION_BROKER_CPP = SOURCE_DIR / "mtproto" / "proxy" / "connection_broker.cpp"
CONNECTION_CPP = SOURCE_DIR / "mtproto" / "session" / "private" / "connection.cpp"
TRANSPORT_CPP = SOURCE_DIR / "mtproto" / "session" / "private" / "transport.cpp"
CHECK_CPP = SOURCE_DIR / "mtproto" / "proxy" / "check.cpp"
ENDPOINT_HEALTH_LIFECYCLE_CPP = (
    SOURCE_DIR / "mtproto" / "proxy" / "mtproxy" /
    "endpoint_health_lifecycle.cpp")


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
    assert "health cooldown and main-first scout" in append_body
    assert "ConnectionBrokerAction::Queued" in CONNECTION_BROKER_CPP.read_text(
        encoding="utf-8")
    assert "ProxyDiagnosticsPhase::AdmissionQueued" in CONNECTION_BROKER_CPP.read_text(
        encoding="utf-8")
    assert "setState(-int(admission.retryAfter));" not in append_body


def test_session_data_plane_has_no_admission_lease_or_deadline():
    header = SESSION_TRANSPORT_H.read_text(encoding="utf-8")
    source = read_session_private_sources()

    assert "SessionProxyLease" not in header
    assert "SessionProxyTicket" not in header
    assert "brokerQueueDeadlineTimer" not in header
    assert "std::move(start.lease)" not in source
    assert "reclaimMtproxySlot" not in source
    assert "brokerQueueDeadlineFired" not in source
    assert "endpointAdmissionWait" not in source
    assert "reportConnectionError(" not in source
    assert "reportMtproxyFailure(" in (
        PROXY_ADAPTER_CPP.read_text(encoding="utf-8"))
    assert "reportMtproxySuccess(" in (
        TLS_SOCKET_RECORDS_CPP.read_text(encoding="utf-8"))
    connection = CONNECTION_CPP.read_text(encoding="utf-8")
    append = function_body(
        connection, "bool SessionTransport::appendTestConnection(")
    assert "&AbstractConnection::handshakeProgress" not in append
    assert "SessionTransport::onHandshakeProgress(" not in connection
    connected = function_body(
        connection, "void SessionTransport::onConnected(")
    confirmed = function_body(
        connection, "void SessionTransport::confirmBestConnection()")
    assert "reportMtproxyConnectionUsable" not in connected
    assert "reportMtproxyConnectionUsable" not in confirmed
    assert "requestConnection({" not in append
    transport = TRANSPORT_CPP.read_text(encoding="utf-8")
    note_payload = function_body(
        transport, "void SessionTransport::noteMtprotoPayloadReceived()")
    assert "if (firstPayload)" in note_payload
    assert "reportFirstMtprotoPayload(" not in note_payload
    assert "transferDemandGraceFired" not in connection
    assert "kTransferDemandGrace" not in connection
    assert "hasTransferDemand()" not in connection
    classify = function_body(
        connection, "SessionProxyEndpointUse SessionTransport::classifyEndpointUse(")
    assert "SessionProxyEndpointUse::Upload" in classify
    assert "SessionProxyEndpointUse::Media" in classify
    assert "std::vector<TestConnection> testConnections;" in header
    wait_received = function_body(
        connection, "void SessionTransport::waitReceivedFailed()")
    connecting_timeout = function_body(
        connection, "void SessionTransport::connectingTimedOut()")
    on_error = function_body(
        connection, "void SessionTransport::onError(")
    assert "_proxyPort" not in wait_received
    assert "_proxyPort" not in connecting_timeout
    assert "_proxyPort" not in on_error
    assert ".routesExhausted = true," in CHECK_CPP.read_text(encoding="utf-8")


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
    test_session_data_plane_has_no_admission_lease_or_deadline()
