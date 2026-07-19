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
CHECK_CPP = SOURCE_DIR / "mtproto" / "proxy" / "check.cpp"


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
    assert "_transportReady" in lease
    assert "endpointAdmissionArbiter().markTransportReady(" in lease
    assert "_lease.release();" not in lease
    assert connection.count("_state.mtproxyLease.transportReady();") == 2
    destroy = function_body(
        connection, "void SessionTransport::destroyAllConnections(")
    reclaim = function_body(
        connection, "void SessionTransport::reclaimMtproxySlot(")
    clear = function_body(
        connection, "void SessionTransport::clearTestConnections()")
    remove = function_body(
        connection, "void SessionTransport::removeTestConnection(")
    assert destroy.index("_state.connection.reset();") < destroy.index(
        "_state.mtproxyLease.release();")
    assert reclaim.index("candidate->data.reset();") < reclaim.index(
        "candidate->mtproxyLease.release();")
    assert reclaim.index("_state.connection.reset();") < reclaim.index(
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
    assert destroy.index("_state.connection.reset();") < destroy.index(
        "_state.mtproxyLease.release();")
    deadline = function_body(
        connection, "void SessionTransport::brokerQueueDeadlineFired()")
    assert "_state.endpointAdmissionWaitKey.ticketId" in deadline
    assert "_state.endpointAdmissionWaitRevision" in deadline
    assert "MtProxy::EndpointAdmissionWaitReason::Slot" in deadline
    assert "MtProxy::EndpointAdmissionWaitReason::ClosingSlot" in deadline
    assert "waiting->reevaluate();" in deadline
    assert deadline.index("waiting->reevaluate();") < deadline.index(
        "_timing.brokerQueueDeadlineTimer.callOnce(kBrokerQueueHardDeadline);")
    assert "MtProxy::EndpointAdmissionWaitReason::HealthOrNotBefore" in deadline
    slot_branch = deadline.split(
        "if (exactWait", 1)[1].split("if (!exactWait", 1)[0]
    assert "doDisconnect();" not in slot_branch
    assert ".waitStartedAt = _state.endpointAdmissionWaitStartedAt" in connection
    assert "preserveWaitStartedAt" in connection
    assert "_state.endpointAdmissionWaitStartedAt = preserveWaitStartedAt;" in connection
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
