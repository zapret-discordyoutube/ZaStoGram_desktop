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
    assert ".status = [=](SessionProxyAdmissionDecision decision)" in append_body
    assert "_state.endpointAdmissionWaitKey = decision.key;" in append_body
    assert "_state.endpointAdmissionWaitRevision = decision.revision;" in append_body
    assert "_state.endpointAdmissionWaitReason = decision.waitReason;" in append_body
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
    connection = CONNECTION_CPP.read_text(encoding="utf-8")
    adapter = PROXY_ADAPTER_CPP.read_text(encoding="utf-8")
    lease = function_body(
        adapter, "void transportReady() override")
    endpoint_lease = function_body(
        ENDPOINT_HEALTH_LIFECYCLE_CPP.read_text(encoding="utf-8"),
        "void EndpointAttemptLease::transportReady()")
    assert "_lease.transportReady();" in lease
    assert "_lease.release();" not in lease
    assert "_dialSlotArmed" in endpoint_lease
    assert "_relayReadyReported" in endpoint_lease
    assert "_openingTerminalReported" in endpoint_lease
    assert "markRelayReady(" in endpoint_lease
    assert "releaseDialSlot(" not in endpoint_lease
    append = function_body(
        connection, "bool SessionTransport::appendTestConnection(")
    assert "&AbstractConnection::handshakeProgress" not in append
    assert "SessionTransport::onHandshakeProgress(" not in connection
    connected = function_body(
        connection, "void SessionTransport::onConnected(")
    confirmed = function_body(
        connection, "void SessionTransport::confirmBestConnection()")
    assert "transportReady();" not in connected
    assert "transportReady();" not in confirmed
    assert "transportReady();" not in connection
    assert "reportMtproxyConnectionUsable(*i);" in connected
    assert "reportMtproxyConnectionUsable(*i);" in confirmed
    first_payload = function_body(
        adapter,
        "void ProductionSessionProxyPort::reportFirstMtprotoPayload(")
    assert first_payload.index("reportMtproxySuccess(") < first_payload.index(
        "lease->transportReady();")
    transport = TRANSPORT_CPP.read_text(encoding="utf-8")
    note_payload = function_body(
        transport, "void SessionTransport::noteMtprotoPayloadReceived()")
    assert "if (firstPayload)" in note_payload
    assert "reportFirstMtprotoPayload(" in note_payload
    assert "transportReady();" not in note_payload
    destroy = function_body(
        connection, "void SessionTransport::destroyAllConnections(")
    clear = function_body(
        connection, "void SessionTransport::clearTestConnections()")
    remove = function_body(
        connection, "void SessionTransport::removeTestConnection(")
    assert destroy.index("_state.connection.reset();") < destroy.index(
        "_state.mtproxyLease.release();")
    assert clear.index("connection.data.reset();") < clear.index(
        "connection.mtproxyLease.release();")
    assert remove.index("i->data.reset();") < remove.index(
        "i->mtproxyLease.release();")
    grace = function_body(
        connection, "void SessionTransport::transferDemandGraceFired()")
    assert "kTransferDemandGrace = 5 * crl::time(1000)" in connection
    assert "hasTransferDemand()" in grace
    assert "destroyAllConnections(ProxyCloseOrigin::BrokerCancelled);" in grace
    assert "reclaimMtproxySlot(" not in connection
    assert "slotKey()" not in connection
    assert "AdmissionPurpose" not in connection
    classify = function_body(
        connection, "SessionProxyEndpointUse SessionTransport::classifyEndpointUse(")
    assert "SessionProxyEndpointUse::Upload" in classify
    assert "SessionProxyEndpointUse::Media" in classify
    assert "std::vector<TestConnection> testConnections;" in header
    assert destroy.index("_state.connection.reset();") < destroy.index(
        "_state.mtproxyLease.release();")
    deadline = function_body(
        connection, "void SessionTransport::brokerQueueDeadlineFired()")
    assert "_state.endpointAdmissionWaitKey.ticketId" in deadline
    assert "_state.endpointAdmissionWaitRevision" in deadline
    assert "MtProxy::EndpointAdmissionWaitReason::Slot" in deadline
    for reason in ("Capacity", "Closing"):
        assert f"MtProxy::EndpointAdmissionWaitReason::{reason}" not in deadline
    assert "waiting->reevaluate();" in deadline
    assert deadline.index("waiting->reevaluate();") < deadline.index(
        "_timing.brokerQueueDeadlineTimer.callOnce(kBrokerQueueHardDeadline);")
    assert "MtProxy::EndpointAdmissionWaitReason::HealthOrNotBefore" in deadline
    gate_branch = deadline.split(
        "if (exactWait && dialGateWait)", 1)[1].split("if (!exactWait", 1)[0]
    assert "waiting->reevaluate();" in gate_branch
    assert "callOnce(kBrokerQueueHardDeadline);" in gate_branch
    assert "doDisconnect();" not in gate_branch
    assert "resetEndpointAdmissionWait();" not in gate_branch
    assert ".waitStartedAt = _state.endpointAdmissionWaitStartedAt" in connection
    assert "preserveWaitStartedAt" in connection
    assert "_state.endpointAdmissionWaitStartedAt = preserveWaitStartedAt;" in connection
    connection_error = function_body(
        adapter,
        "void ProductionSessionProxyPort::reportConnectionError(")
    receive_timeout = function_body(
        adapter,
        "void ProductionSessionProxyPort::reportReceiveTimeout(")
    connect_timeout = function_body(
        adapter,
        "void ProductionSessionProxyPort::reportConnectTimeout(")
    for terminal in (connection_error, receive_timeout, connect_timeout):
        assert terminal.index("ReportConnectionFailure(") < terminal.index(
            "lease->openingTerminal(")
        assert "IsSessionOpeningTerminal(" in terminal
        assert "true" in terminal.split("lease->openingTerminal(", 1)[1]
    wait_received = function_body(
        connection, "void SessionTransport::waitReceivedFailed()")
    connecting_timeout = function_body(
        connection, "void SessionTransport::connectingTimedOut()")
    on_error = function_body(
        connection, "void SessionTransport::onError(")
    assert "&_state.mtproxyLease" in wait_received
    assert "&connection.mtproxyLease" in connecting_timeout
    assert "&found->mtproxyLease" in on_error
    assert "&_state.mtproxyLease" in on_error
    assert ".routesExhausted = true," in adapter
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
    test_session_uses_endpoint_health_admission_instead_of_local_cooldown()
    test_session_keeps_mtproxy_attempt_lease_until_terminal_outcome()
