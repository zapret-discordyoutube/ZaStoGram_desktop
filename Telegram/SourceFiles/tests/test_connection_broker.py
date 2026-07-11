import re
from pathlib import Path
from session_private_sources import read_session_private_sources


SOURCE_DIR = Path(__file__).resolve().parents[1]
ROOT = SOURCE_DIR.parents[1]
CMAKE = ROOT / "Telegram" / "CMakeLists.txt"
CONTROL_H = SOURCE_DIR / "mtproto" / "proxy" / "control_plane.h"
BROKER_H = SOURCE_DIR / "mtproto" / "proxy" / "connection_broker.h"
BROKER_CPP = SOURCE_DIR / "mtproto" / "proxy" / "connection_broker.cpp"
ENDPOINT_HEALTH_H = SOURCE_DIR / "mtproto" / "proxy" / "mtproxy" / "endpoint_health.h"
SESSION_H = SOURCE_DIR / "mtproto" / "session" / "private" / "session_private.h"
SESSION_TRANSPORT_H = SOURCE_DIR / "mtproto" / "session" / "private" / "transport.h"
SESSION_CPP = SOURCE_DIR / "mtproto" / "session" / "private" / "session_private.cpp"
PROXY_CHECK_H = SOURCE_DIR / "mtproto" / "proxy" / "check.h"
PROXY_CHECK_CPP = SOURCE_DIR / "mtproto" / "proxy" / "check.cpp"


def test_connection_broker_is_registered_owner_seam():
    cmake = CMAKE.read_text(encoding="utf-8")
    header = BROKER_H.read_text(encoding="utf-8")
    source = BROKER_CPP.read_text(encoding="utf-8")

    assert "mtproto/proxy/connection_broker.cpp" in cmake
    assert "mtproto/proxy/connection_broker.h" in cmake
    assert "class ConnectionBroker final" in header
    assert "explicit ConnectionBroker(not_null<RuntimeEnvironment*> runtime);" in header
    assert "[[nodiscard]] static ConnectionBroker &Instance();" not in header
    assert "ConnectionTicket request(ConnectionRequest request);" in header
    assert "void cancel(ConnectionTicketId id);" in header
    assert "void cancelByProxyGeneration(uint64 generation);" in header
    assert "enum class ConnectionBrokerAction" in header
    for action in ("StartNow", "Queued", "StartAfter", "Rejected"):
        assert action in header
    assert "struct EndpointQueue" in header
    assert "std::unique_ptr<EndpointQueue> _mainQueue;" in header
    assert "std::unique_ptr<EndpointQueue> _mediaQueue;" in header
    assert "std::unique_ptr<EndpointQueue> _proxyCheckQueue;" in header
    assert '#include "mtproto/proxy/control_plane.h"' in source
    assert "_runtime->proxyServices().control().admit({" in source
    assert "MtProxy::ReserveOpenSlot(" in source


def test_session_private_queues_admission_without_retry_backoff():
    header = SESSION_TRANSPORT_H.read_text(encoding="utf-8")
    source = read_session_private_sources()
    broker = BROKER_CPP.read_text(encoding="utf-8")
    append_body = function_body(
        source,
        "bool SessionTransport::appendTestConnection(")
    notify_body = function_body(broker, "void ConnectionBroker::notify(")
    report_body = function_body(
        broker,
        "void ConnectionBroker::reportAdmissionEvent(")

    assert '#include "mtproto/proxy/connection_broker.h"' not in source
    assert "std::vector<SessionProxyTicket> brokerTickets;" in header
    assert "_owner->_proxyPort->requestConnection({" in append_body
    assert "ConnectionBroker::Instance()" not in source
    assert "EndpointHealth::Instance().admit(" not in append_body
    assert "EndpointHealth::Instance().admit(" not in broker
    assert "setState(-int(admission.retryAfter));" not in append_body
    assert "ConnectionBrokerAction::Queued" in notify_body
    assert "ConnectionBrokerAction::StartAfter" in notify_body
    assert ".start = [=](SessionProxyStart start)" in append_body
    assert "removeConnectionBrokerTicket(start.ticketId);" in append_body
    assert "appendStartedConnection(" in append_body
    assert "ProxyDiagnosticsPhase::AdmissionQueued" in notify_body
    assert "ProxyDiagnosticsPhase::Connecting" not in notify_body
    assert "ProxyDiagnosticsSeverity::Warning" in report_body
    assert ".error = " not in report_body
    assert "mtproxy admission queued" in notify_body
    assert "mtproxy admission queued" not in append_body


def test_session_pending_broker_tickets_keep_connecting_without_timeout_loop():
    header = SESSION_TRANSPORT_H.read_text(encoding="utf-8")
    source = read_session_private_sources()
    connect_body = function_body(source, "void SessionTransport::connectToServer(")
    destroy_body = function_body(
        source,
        "void SessionTransport::destroyAllConnections(ProxyCloseOrigin origin)")

    assert "void removeConnectionBrokerTicket(SessionProxyTicketId id);" in header
    assert "void armWaitForConnectedTimer();" in header
    assert "|| !_state.brokerTickets.empty()" in connect_body
    assert "if (!_state.testConnections.empty()) {\n\t\tarmWaitForConnectedTimer();" in connect_body
    assert "_state.brokerTickets.clear();" in destroy_body
    assert "removeConnectionBrokerTicket(start.ticketId);" in source
    assert "armWaitForConnectedTimer();" in source


def test_session_queued_broker_tickets_have_hard_deadline():
    header = SESSION_TRANSPORT_H.read_text(encoding="utf-8")
    source = read_session_private_sources()
    connect_body = function_body(source, "void SessionTransport::connectToServer(")
    destroy_body = function_body(
        source,
        "void SessionTransport::destroyAllConnections(ProxyCloseOrigin origin)")
    remove_body = function_body(
        source,
        "void SessionTransport::removeConnectionBrokerTicket(")
    deadline_body = function_body(
        source,
        "void SessionTransport::brokerQueueDeadlineFired()")

    # A queued ticket is not a failure and must not churn the retry loop,
    # but it may not hang the session forever either: arm a generous hard
    # deadline while only broker tickets are pending, tear down and retry
    # with fresh options (picking up a rotated proxy) when it fires.
    assert "RuntimeTimer brokerQueueDeadlineTimer;" in header
    assert "void brokerQueueDeadlineFired();" in header
    assert "kBrokerQueueHardDeadline = 90 * crl::time(1000)" in source
    assert (
        "_timing.brokerQueueDeadlineTimer.callOnce(kBrokerQueueHardDeadline);"
        in connect_body)
    assert "_timing.brokerQueueDeadlineTimer.cancel();" in destroy_body
    assert "_timing.brokerQueueDeadlineTimer.cancel();" in remove_body
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
    claim_body = function_body(
        source, "ConnectionBroker::ClaimResult ConnectionBroker::claimFront(")
    verdict_body = function_body(
        source,
        "ConnectionBroker::DrainVerdict ConnectionBroker::computeVerdict(")
    commit_admitted = function_body(
        source, "void ConnectionBroker::commitAdmitted(")
    commit_denied = function_body(
        source, "void ConnectionBroker::commitDenied(")
    schedule_body = function_body(source, "void ConnectionBroker::scheduleStart(")

    assert "uint64 proxyGeneration = 0;" in control_header
    assert "uint64 proxyGeneration = 0;" in health_header
    assert "bool admissionInProgress = false;" in request_state
    # The front request is claimed (admissionInProgress) before the
    # unlocked admission pass, and released in every commit path.
    assert "state->admissionInProgress = true;" in claim_body
    assert drain_body.index("claimFront(use)") < (
        drain_body.index("computeVerdict(state)"))
    assert "_runtime->proxyServices().control().admit({" in verdict_body
    assert ".proxyGeneration = state->proxyGeneration" in verdict_body
    assert "state->admissionInProgress = false;" in commit_admitted
    assert "state->admissionInProgress = false;" in commit_denied
    assert "state->startScheduled = true;" in commit_admitted
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
    assert "state->openSlot.cancel();" in source
    assert "state->openSlot.commit();" in source
    assert "releaseAdmission(cancelled);" in cancel_body
    assert "releaseAdmission(state);" in generation_cancel_body


def test_broker_rechecks_scheduler_after_delayed_open_slot():
    source = BROKER_CPP.read_text(encoding="utf-8")
    drain_body = function_body(source, "void ConnectionBroker::drainQueue(")
    claim_body = function_body(
        source, "ConnectionBroker::ClaimResult ConnectionBroker::claimFront(")
    commit_admitted = function_body(
        source, "void ConnectionBroker::commitAdmitted(")
    request_state = source.split(
        "struct ConnectionBroker::RequestState {", 1)[1].split("};", 1)[0]

    assert "crl::time openRetryAt = 0;" in request_state
    assert "bool openRetryScheduled = false;" in request_state
    assert "if (state->openRetryAt > now)" in claim_body
    assert "if (state->openRetryScheduled)" in claim_body
    assert "result.openRetryAfter = state->openRetryAt - now;" in claim_body
    assert "scheduleOpenRetry(state, claim.openRetryAfter);" in drain_body
    assert "const auto delayedOpen = !IsProxyCheck(state->request.use)" in (
        commit_admitted)
    assert "(openDelay > 0);" in commit_admitted
    assert "state->request.notBefore = 0;" in commit_admitted
    assert "state->openRetryAt = _runtime->async().now()" in commit_admitted
    assert "state->openRetryScheduled = true;" in commit_admitted
    # The immediate-start branch stores the admission/slot into the state;
    # the delayed branch must NOT (a queued front's state->admission is
    # read under _mutex by claimFront/wakeEndpoint, so it is kept in the
    # local `verdict` and released after the unlock instead).
    assert "state->admission = std::move(*verdict.admission);" in (
        commit_admitted)
    assert "state->openSlot = std::move(verdict.openSlot);" in commit_admitted
    assert "verdict.admission->lease.release();" in commit_admitted
    assert "verdict.openSlot.cancel();" in commit_admitted
    assert "scheduleOpenRetry(state, openDelay);" in commit_admitted
    assert "scheduleStart(state, openDelay);" in commit_admitted
    # The locked delayed branch keeps the request queued without storing the
    # admission into the state or scheduling a start.
    delayed_locked = commit_admitted.split(
        "if (delayedOpen) {", 1)[1].split("} else {", 1)[0]
    assert "state->admission = std::move(" not in delayed_locked
    assert "state->startScheduled = true;" not in delayed_locked
    assert "scheduleStart(" not in delayed_locked
    dispatch = commit_admitted.split("if (delayedOpen) {", 2)[2]
    assert dispatch.index("verdict.admission->lease.release();") < (
        dispatch.index("scheduleOpenRetry(state, openDelay);"))
    assert dispatch.index("scheduleOpenRetry(state, openDelay);") < (
        dispatch.index("scheduleStart(state, openDelay);"))

    retry_body = function_body(
        source, "void ConnectionBroker::scheduleOpenRetry(")
    assert "state->openRetryScheduled = false;" in retry_body
    # Cleared under _mutex (wakeEndpoint reads it under the lock).
    assert "QMutexLocker lock(&_mutex);" in retry_body
    assert "if (state->active)" in retry_body
    assert "drain();" in retry_body


def test_broker_wakes_queue_on_admission_slot_release():
    source = BROKER_CPP.read_text(encoding="utf-8")
    header = BROKER_H.read_text(encoding="utf-8")
    constructor = function_body(
        source, "ConnectionBroker::ConnectionBroker(")
    destructor = function_body(source, "ConnectionBroker::~ConnectionBroker(")
    wake_body = function_body(
        source, "void ConnectionBroker::wakeEndpoint(")
    request_state = source.split(
        "struct ConnectionBroker::RequestState {", 1)[1].split("};", 1)[0]

    # The broker subscribes to freed admission slots and unsubscribes
    # (after neutering the guard) before cancelling its own requests.
    assert "struct WakeGuard {" in header
    assert "addAdmissionReleaseListener(" in constructor
    assert "std::weak_ptr<WakeGuard>" in constructor
    assert "broker->wakeEndpoint(key);" in constructor
    assert "_wakeGuard->broker = nullptr;" in destructor
    assert "removeAdmissionReleaseListener(" in destructor
    assert destructor.index("_wakeGuard->broker = nullptr;") < (
        destructor.index("removeAdmissionReleaseListener("))
    assert destructor.index("removeAdmissionReleaseListener(") < (
        destructor.index("cancelByOwnerDestruction();"))

    # The wake never drains synchronously: it only schedules onto the
    # request context, deduped by wakeScheduled.
    assert "QString endpointKey;" in request_state
    assert "bool wakeScheduled = false;" in request_state
    assert "state->endpointKey == endpointKey" in wake_body
    assert "state->wakeScheduled = true;" in wake_body
    assert "_runtime->async().singleShot(0, state->request.context" in (
        wake_body)
    assert "drainQueue(" not in wake_body
    assert wake_body.index("QMutexLocker lock(&_mutex);") < wake_body.index(
        "_runtime->async().singleShot(")


def test_proxy_check_uses_connection_broker_proxy_check_queue():
    header = PROXY_CHECK_H.read_text(encoding="utf-8")
    source = PROXY_CHECK_CPP.read_text(encoding="utf-8")
    start_body = function_body(source, "void StartProxyCheck(")

    assert '#include "mtproto/proxy/connection_broker.h"' in header
    assert "details::ConnectionTicket connectionTicket;" in header
    assert "runtime->proxyServices().broker().request({" in start_body
    assert "ConnectionBroker::Instance()" not in source
    assert "MtProxy::EndpointUse::ProxyCheck" in start_body
    assert "MtProxy::ReserveOpenSlot(" not in start_body
    assert "state->mtproxyLease = std::move(start.lease);" in start_body


def test_proxy_check_connection_request_designators_match_struct_order():
    header = BROKER_H.read_text(encoding="utf-8")
    source = PROXY_CHECK_CPP.read_text(encoding="utf-8")
    fields = struct_fields(header, "struct ConnectionRequest {")
    start_body = function_body(source, "void StartProxyCheck(")
    request = block_after(
        start_body,
        "runtime->proxyServices().broker().request(").split(
        ".start = ", 1)[0]
    designators = [
        match.group(1)
        for match in re.finditer(r"^\s*\.(\w+)\s*=", request, re.MULTILINE)
    ]
    field_indexes = [fields.index(name) for name in designators]

    assert field_indexes == sorted(field_indexes)


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


def struct_fields(text: str, marker: str) -> list[str]:
    body = block_after(text, marker)
    fields = []
    for line in body.splitlines():
        line = line.strip()
        if not line or not line.endswith(";"):
            continue
        declaration = line.split("=", 1)[0].removesuffix(";").strip()
        fields.append(declaration.split()[-1].lstrip("*&"))
    return fields


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
    test_broker_rechecks_scheduler_after_delayed_open_slot()
    test_broker_wakes_queue_on_admission_slot_release()
    test_proxy_check_uses_connection_broker_proxy_check_queue()
    test_proxy_check_connection_request_designators_match_struct_order()
