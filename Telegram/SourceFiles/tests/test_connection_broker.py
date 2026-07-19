import re
from pathlib import Path
from session_private_sources import read_session_private_sources


SOURCE_DIR = Path(__file__).resolve().parents[1]
ROOT = SOURCE_DIR.parents[1]
CMAKE = ROOT / "Telegram" / "CMakeLists.txt"
BROKER_H = SOURCE_DIR / "mtproto" / "proxy" / "connection_broker.h"
BROKER_CPP = SOURCE_DIR / "mtproto" / "proxy" / "connection_broker.cpp"
ARBITER_H = SOURCE_DIR / "mtproto" / "proxy" / "endpoint_admission_arbiter.h"
ARBITER_CPP = SOURCE_DIR / "mtproto" / "proxy" / "endpoint_admission_arbiter.cpp"
SESSION_TRANSPORT_H = SOURCE_DIR / "mtproto" / "session" / "private" / "transport.h"
PROXY_CHECK_H = SOURCE_DIR / "mtproto" / "proxy" / "check.h"
PROXY_CHECK_CPP = SOURCE_DIR / "mtproto" / "proxy" / "check.cpp"


def read(path):
    assert path.exists(), f"missing expected source file: {path}"
    return path.read_text(encoding="utf-8")


def test_connection_broker_is_a_facade_over_the_shared_arbiter():
    cmake = read(CMAKE)
    header = read(BROKER_H)
    source = read(BROKER_CPP)

    for name in (
        "connection_broker.cpp",
        "connection_broker.h",
        "endpoint_admission_arbiter.cpp",
        "endpoint_admission_arbiter.h",
    ):
        assert f"mtproto/proxy/{name}" in cmake
    assert "class ConnectionBroker final" in header
    assert "ConnectionTicket request(ConnectionRequest request);" in header
    assert "void cancel(ConnectionTicketId id);" in header
    assert "void cancelByProxyGeneration(uint64 generation);" in header
    assert "std::atomic<ConnectionTicketId> _lastTicketId = 0;" in header
    assert "const std::shared_ptr<ProxyEndpointContext> _endpointContext;" in header
    assert "EndpointQueue" not in header
    assert "RuntimeTimer" not in header
    assert "ReserveOpenSlot" not in source
    assert "addAdmissionReleaseListener" not in source
    assert "endpointAdmissionArbiter().enqueue(" in source
    assert "endpointAdmissionArbiter().cancel(" in source
    assert "endpointAdmissionArbiter().cancelBeforeGeneration(" in source
    assert "endpointAdmissionArbiter().cancelRuntime(" in source


def test_ticket_cancellation_uses_runtime_and_ticket_identity():
    header = read(BROKER_H)
    source = read(BROKER_CPP)
    cancel = function_body(source, "void ConnectionTicket::cancel()")

    assert "std::weak_ptr<ProxyEndpointContext> _context;" in header
    assert "AdmissionTicketKey _key;" in header
    assert "ConnectionBroker *_broker" not in header
    assert "const auto key = base::take(_key);" in cancel
    assert "const auto revision = base::take(_revision);" in cancel
    assert "context->endpointAdmissionArbiter().cancel(key, revision);" in cancel
    assert "_context.reset();" in cancel


def test_arbiter_owns_one_exact_opening_permit_and_cleanup():
    header = read(ARBITER_H)
    source = read(ARBITER_CPP)
    cancel = function_body(
        source, "void EndpointAdmissionArbiter::Private::cancelTicketLocked(")
    clear_reservation = function_body(
        source,
        "void EndpointAdmissionArbiter::Private::clearTicketReservationLocked(")
    owner_destroyed = function_body(
        source, "void EndpointAdmissionArbiter::Private::ownerDestroyed(")
    missing = function_body(
        source, "void EndpointAdmissionArbiter::Private::deliveryMissing(")
    deliver = function_body(
        source, "void EndpointAdmissionArbiter::Private::deliverGrant(")
    grant_action = function_body(source, "void GrantAction::run()")
    actions = function_body(source, "void Actions::run()")
    permit = block_after(header, "struct EndpointOpeningPermit")

    assert "struct EndpointSchedule" in source
    assert "std::deque<AdmissionTicketKey> order;" in source
    assert "std::map<AdmissionTicketKey, std::unique_ptr<Ticket>> _tickets;" in source
    assert "enum class PriorityClass" in source
    for priority in (
        "ForegroundMain",
        "ForegroundTransfer",
        "UrgentMain",
        "OrdinaryMain",
        "Maintenance",
        "Auxiliary",
        "ProxyCheck",
        "Background",
    ):
        assert priority in source
    for lifecycle in ("Queued", "Scheduled", "Granted", "HandedOff", "Cancelled"):
        assert f"ProxySchedulerLifecycle::{lifecycle}" in source
    assert "struct EndpointOpeningPermit" in header
    assert "OpeningPermitTicketOwner" in header
    assert "using EndpointOpeningPermitOwner = std::variant<" in header
    assert "std::monostate," in header
    assert "OpeningPermitTicketOwner," in header
    assert "ProxyConnectionAttempt>" in header
    assert "EndpointOpeningPermitOwner owner;" in permit
    assert "OpenSlotSchedule openings;" in permit
    assert "QPointer" not in permit
    assert "Fn<" not in permit
    assert "std::map<QString, MtProxy::EndpointOpeningPermit> _permits;" in source
    assert "LiveSlot" not in header
    assert "LiveSlot" not in source
    assert "MtProxy::ReserveOpenSlot(" in source
    assert "MtProxy::CancelOpenSlot(" in clear_reservation
    assert "TicketOwnerMatches(*owner, ticket)" in clear_reservation
    assert "current.owner = std::monostate();" in clear_reservation
    assert "clearTicketReservationLocked(ticket);" in cancel
    assert "actions.removed.push_back(takeTicketLocked(key));" in cancel
    assert "cancelTicketLocked(key, revision, actions);" in owner_destroyed
    assert "drainEndpointLocked(endpointKey, inputs, actions);" in owner_destroyed
    assert "cancelTicketLocked(key, revision, actions);" in missing
    assert "drainEndpointLocked(endpointKey, inputs, actions);" in missing
    assert "if (!openCommitted)" in deliver
    assert "if (!admission)" in deliver
    assert "if (recoveryAdoptionFailed)" in deliver
    assert deliver.count("cancelTicketLocked(key, revision, actions);") >= 3
    assert "admission->lease.abandon();" in deliver
    assert "grant.admission.lease.release();" in grant_action
    assert "QMutexLocker" not in actions
    assert "posts" in actions
    assert "grants" in actions


def test_session_pending_tickets_have_one_hard_deadline():
    header = read(SESSION_TRANSPORT_H)
    source = read_session_private_sources()
    connect = function_body(source, "void SessionTransport::connectToServer(")
    destroy = function_body(
        source,
        "void SessionTransport::destroyAllConnections(ProxyCloseOrigin origin)")
    deadline = function_body(
        source, "void SessionTransport::brokerQueueDeadlineFired()")

    assert "std::vector<SessionProxyTicket> brokerTickets;" in header
    assert "RuntimeTimer brokerQueueDeadlineTimer;" in header
    assert "kBrokerQueueHardDeadline = 90 * crl::time(1000)" in source
    assert "_timing.brokerQueueDeadlineTimer.callOnce(kBrokerQueueHardDeadline);" in connect
    assert "_timing.brokerQueueDeadlineTimer.cancel();" in destroy
    assert "MtProxy::EndpointAdmissionWaitReason::Slot" in deadline
    assert "MtProxy::EndpointAdmissionWaitReason::ClosingSlot" not in deadline
    assert "waiting->reevaluate();" in deadline
    assert deadline.index("waiting->reevaluate();") < deadline.index(
        "_timing.brokerQueueDeadlineTimer.callOnce(kBrokerQueueHardDeadline);")
    slot_branch = deadline.split("if (exactWait", 1)[1].split(
        "if (!exactWait", 1)[0]
    assert "doDisconnect();" not in slot_branch
    assert "MtProxy::EndpointAdmissionWaitReason::HealthOrNotBefore" in deadline
    assert "doDisconnect();" in deadline
    assert "kProxyReconnectMinTimeout" in deadline
    arbiter = read(ARBITER_CPP)
    wake = function_body(
        arbiter, "void EndpointAdmissionArbiter::Private::updateWakeLocked(")
    assert "ticket.scheduledOpenAt" in wake
    assert "ticket.reevaluateAt" in wake
    assert "kLiveQuantum" not in wake
    assert "liveSince" not in wake


def test_proxy_check_uses_the_shared_broker():
    header = read(PROXY_CHECK_H)
    source = read(PROXY_CHECK_CPP)
    start = function_body(source, "void StartProxyCheck(")
    reset = function_body(source, "void ResetProxyCheckState(")
    handshake = block_after(start, "&Connection::handshakeProgress")
    connected = block_after(start, "&Connection::connected")

    assert '#include "mtproto/proxy/connection_broker.h"' in header
    assert "details::ConnectionTicket connectionTicket;" in header
    assert "runtime->proxyServices().broker().request({" in start
    assert "MtProxy::EndpointUse::ProxyCheck" in start
    assert "MtProxy::ReserveOpenSlot(" not in start
    assert ".reclaim =" not in start
    assert "phase >= details::HandshakePhase::ServerHelloOk" in handshake
    assert "state->mtproxyLease.transportReady();" in handshake
    assert handshake.index("state->mtproxyLease.transportReady();") < (
        handshake.index("SetProxyCheckProgress("))
    assert "state->mtproxyLease.transportReady();" in connected
    assert "state->mtproxyLease = std::move(start.lease);" in start
    assert reset.index("state->connection.reset();") < reset.index(
        "state->mtproxyLease.release();")
    assert "mtproxySlot" not in reset
    assert "ConnectionBrokerAction::Rejected" in start


def test_proxy_check_connection_request_designators_match_struct_order():
    header = read(BROKER_H)
    source = read(PROXY_CHECK_CPP)
    fields = struct_fields(header, "struct ConnectionRequest {")
    start = function_body(source, "void StartProxyCheck(")
    request = block_after(
        start,
        "runtime->proxyServices().broker().request(").split(".start = ", 1)[0]
    designators = [
        match.group(1)
        for match in re.finditer(r"^\s*\.(\w+)\s*=", request, re.MULTILINE)
    ]

    assert [fields.index(name) for name in designators] == sorted(
        fields.index(name) for name in designators)


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
    fields = []
    for line in block_after(text, marker).splitlines():
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
    test_connection_broker_is_a_facade_over_the_shared_arbiter()
    test_ticket_cancellation_uses_runtime_and_ticket_identity()
    test_arbiter_owns_one_exact_opening_permit_and_cleanup()
    test_session_pending_tickets_have_one_hard_deadline()
    test_proxy_check_uses_the_shared_broker()
    test_proxy_check_connection_request_designators_match_struct_order()
