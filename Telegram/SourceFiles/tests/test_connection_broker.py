from pathlib import Path


SOURCE_DIR = Path(__file__).resolve().parents[1]
ROOT = SOURCE_DIR.parents[1]
CMAKE = ROOT / "Telegram" / "CMakeLists.txt"
CONTROL_H = SOURCE_DIR / "mtproto" / "proxy" / "control_plane.h"
BROKER_H = SOURCE_DIR / "mtproto" / "proxy" / "connection_broker.h"
BROKER_CPP = SOURCE_DIR / "mtproto" / "proxy" / "connection_broker.cpp"
ENDPOINT_HEALTH_H = SOURCE_DIR / "mtproto" / "proxy" / "mtproxy" / "endpoint_health.h"
SESSION_H = SOURCE_DIR / "mtproto" / "session_private.h"
SESSION_CPP = SOURCE_DIR / "mtproto" / "session_private.cpp"
PROXY_CHECK_H = SOURCE_DIR / "mtproto" / "proxy" / "check.h"
PROXY_CHECK_CPP = SOURCE_DIR / "mtproto" / "proxy" / "check.cpp"


def test_connection_broker_is_registered_owner_seam():
    cmake = CMAKE.read_text(encoding="utf-8")
    header = BROKER_H.read_text(encoding="utf-8")
    source = BROKER_CPP.read_text(encoding="utf-8")

    assert "mtproto/proxy/connection_broker.cpp" in cmake
    assert "mtproto/proxy/connection_broker.h" in cmake
    assert "class ConnectionBroker final" in header
    assert "ConnectionTicket request(ConnectionRequest request);" in header
    assert "void cancel(ConnectionTicketId id);" in header
    assert "enum class ConnectionBrokerAction" in header
    for action in ("StartNow", "Queued", "StartAfter", "Rejected"):
        assert action in header
    assert "struct EndpointQueue" in header
    assert "std::unique_ptr<EndpointQueue> _mainQueue;" in header
    assert "std::unique_ptr<EndpointQueue> _mediaQueue;" in header
    assert "std::unique_ptr<EndpointQueue> _proxyCheckQueue;" in header
    assert '#include "mtproto/proxy/control_plane.h"' in source
    assert "ProxyControlPlane::Admit({" in source
    assert "MtProxy::ReserveOpenSlot(" in source


def test_session_private_queues_admission_without_retry_backoff():
    header = SESSION_H.read_text(encoding="utf-8")
    source = SESSION_CPP.read_text(encoding="utf-8")
    broker = BROKER_CPP.read_text(encoding="utf-8")
    append_body = function_body(
        source,
        "bool SessionPrivate::appendTestConnection(")
    notify_body = function_body(broker, "void ConnectionBroker::notify(")
    report_body = function_body(
        broker,
        "void ConnectionBroker::reportAdmissionEvent(")

    assert '#include "mtproto/proxy/connection_broker.h"' in source
    assert "std::vector<ConnectionTicket> _connectionBrokerTickets;" in header
    assert "ConnectionBroker::Instance().request({" in append_body
    assert "EndpointHealth::Instance().admit(" not in append_body
    assert "EndpointHealth::Instance().admit(" not in broker
    assert "setState(-int(admission.retryAfter));" not in append_body
    assert "ConnectionBrokerAction::Queued" in notify_body
    assert "ConnectionBrokerAction::StartAfter" in notify_body
    assert ".start = [=](ConnectionStart start)" in append_body
    assert "removeConnectionBrokerTicket(start.ticketId);" in append_body
    assert "appendStartedConnection(" in append_body
    assert "ProxyDiagnosticsPhase::AdmissionQueued" in notify_body
    assert "ProxyDiagnosticsPhase::Connecting" not in notify_body
    assert "ProxyDiagnosticsSeverity::Warning" in report_body
    assert ".error = " not in report_body
    assert "mtproxy admission queued" in notify_body
    assert "mtproxy admission queued" not in append_body


def test_session_pending_broker_tickets_keep_connecting_without_timeout_loop():
    header = SESSION_H.read_text(encoding="utf-8")
    source = SESSION_CPP.read_text(encoding="utf-8")
    connect_body = function_body(source, "void SessionPrivate::connectToServer(")
    destroy_body = function_body(source, "void SessionPrivate::destroyAllConnections()")

    assert "void removeConnectionBrokerTicket(ConnectionTicketId id);" in header
    assert "void armWaitForConnectedTimer();" in header
    assert "_testConnections.empty() && _connectionBrokerTickets.empty()" in connect_body
    assert "if (!_testConnections.empty()) {\n\t\tarmWaitForConnectedTimer();" in connect_body
    assert "_connectionBrokerTickets.clear();" in destroy_body
    assert "removeConnectionBrokerTicket(start.ticketId);" in source
    assert "armWaitForConnectedTimer();" in source


def test_session_queued_broker_tickets_have_hard_deadline():
    header = SESSION_H.read_text(encoding="utf-8")
    source = SESSION_CPP.read_text(encoding="utf-8")
    connect_body = function_body(source, "void SessionPrivate::connectToServer(")
    destroy_body = function_body(source, "void SessionPrivate::destroyAllConnections()")
    remove_body = function_body(
        source,
        "void SessionPrivate::removeConnectionBrokerTicket(")
    deadline_body = function_body(
        source,
        "void SessionPrivate::brokerQueueDeadlineFired()")

    # A queued ticket is not a failure and must not churn the retry loop,
    # but it may not hang the session forever either: arm a generous hard
    # deadline while only broker tickets are pending, tear down and retry
    # with fresh options (picking up a rotated proxy) when it fires.
    assert "base::Timer _brokerQueueDeadlineTimer;" in header
    assert "void brokerQueueDeadlineFired();" in header
    assert "kBrokerQueueHardDeadline = 90 * crl::time(1000)" in source
    assert (
        "_brokerQueueDeadlineTimer.callOnce(kBrokerQueueHardDeadline);"
        in connect_body)
    assert "_brokerQueueDeadlineTimer.cancel();" in destroy_body
    assert "_brokerQueueDeadlineTimer.cancel();" in remove_body
    assert "doDisconnect();" in deadline_body
    assert "kProxyReconnectMinTimeout" in deadline_body


def test_broker_drains_every_queue_independently():
    source = BROKER_CPP.read_text(encoding="utf-8")
    header = BROKER_H.read_text(encoding="utf-8")
    drain_body = function_body(source, "void ConnectionBroker::drain()")

    assert "void drainQueue(MtProxy::EndpointUse use);" in header
    assert "for (const auto use : kQueuePriorityOrder)" in drain_body
    assert "drainQueue(use);" in drain_body
    assert "void ConnectionBroker::drainQueue(" in source


def test_broker_claims_front_request_before_admission():
    source = BROKER_CPP.read_text(encoding="utf-8")
    control_header = CONTROL_H.read_text(encoding="utf-8")
    health_header = ENDPOINT_HEALTH_H.read_text(encoding="utf-8")
    request_state = source.split(
        "struct ConnectionBroker::RequestState {", 1)[1].split("};", 1)[0]
    drain_body = function_body(source, "void ConnectionBroker::drainQueue(")
    schedule_body = function_body(source, "void ConnectionBroker::scheduleStart(")

    assert "uint64 proxyGeneration = 0;" in control_header
    assert "uint64 proxyGeneration = 0;" in health_header
    assert "bool admissionInProgress = false;" in request_state
    assert "state->admissionInProgress" in drain_body
    assert drain_body.index("state->admissionInProgress = true;") < (
        drain_body.index("ProxyControlPlane::Admit({"))
    after_admit = drain_body.split("ProxyControlPlane::Admit({", 1)[1]
    assert ".proxyGeneration = state->proxyGeneration" in after_admit
    assert "state->admissionInProgress = false;" in after_admit
    assert "state->startScheduled = true;" in drain_body
    assert "state->startScheduled = true;" not in schedule_body


def test_broker_cancel_releases_admitted_lease_immediately():
    source = BROKER_CPP.read_text(encoding="utf-8")
    cancel_body = function_body(source, "void ConnectionBroker::cancel(")
    generation_cancel_body = function_body(
        source,
        "void ConnectionBroker::cancelByProxyGeneration(")

    assert "void ConnectionBroker::releaseAdmission(" in source
    assert "state->admission->lease.release();" in source
    assert "state->admission.reset();" in source
    assert "releaseAdmission(cancelled);" in cancel_body
    assert "releaseAdmission(state);" in generation_cancel_body


def test_proxy_check_uses_connection_broker_proxy_check_queue():
    header = PROXY_CHECK_H.read_text(encoding="utf-8")
    source = PROXY_CHECK_CPP.read_text(encoding="utf-8")
    start_body = function_body(source, "void StartProxyCheck(")

    assert '#include "mtproto/proxy/connection_broker.h"' in header
    assert "details::ConnectionTicket connectionTicket;" in header
    assert "details::ConnectionBroker::Instance().request({" in start_body
    assert "MtProxy::EndpointUse::ProxyCheck" in start_body
    assert "MtProxy::ReserveOpenSlot(" not in start_body
    assert "state->mtproxyLease = std::move(start.lease);" in start_body


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
    raise AssertionError(f"body not found for {signature}")


def block_after(text: str, marker: str) -> str:
    start = text.index(marker)
    brace = text.index("{", start)
    depth = 0
    for index in range(brace, len(text)):
        char = text[index]
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return text[brace + 1:index]
    raise AssertionError(f"block not found after {marker}")


if __name__ == "__main__":
    test_connection_broker_is_registered_owner_seam()
    test_session_private_queues_admission_without_retry_backoff()
    test_session_pending_broker_tickets_keep_connecting_without_timeout_loop()
    test_session_queued_broker_tickets_have_hard_deadline()
    test_broker_drains_every_queue_independently()
    test_broker_claims_front_request_before_admission()
    test_broker_cancel_releases_admitted_lease_immediately()
    test_proxy_check_uses_connection_broker_proxy_check_queue()
