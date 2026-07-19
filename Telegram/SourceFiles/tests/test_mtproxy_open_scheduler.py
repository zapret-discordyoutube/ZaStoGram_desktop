from pathlib import Path
from session_private_sources import read_session_private_sources


SOURCE_DIR = Path(__file__).resolve().parents[1]
ROOT = SOURCE_DIR.parents[1]
MTPROXY_DIR = SOURCE_DIR / "mtproto" / "proxy" / "mtproxy"
SCHEDULER_H = MTPROXY_DIR / "open_scheduler.h"
SCHEDULER_CPP = MTPROXY_DIR / "open_scheduler.cpp"
ARBITER_CPP = SOURCE_DIR / "mtproto" / "proxy" / "endpoint_admission_arbiter.cpp"
ARBITER_H = SOURCE_DIR / "mtproto" / "proxy" / "endpoint_admission_arbiter.h"
BROKER_H = SOURCE_DIR / "mtproto" / "proxy" / "connection_broker.h"
BROKER_CPP = SOURCE_DIR / "mtproto" / "proxy" / "connection_broker.cpp"
CHECK_CPP = SOURCE_DIR / "mtproto" / "proxy" / "check.cpp"


def read(path):
    assert path.exists(), f"missing expected source file: {path}"
    return path.read_text(encoding="utf-8")


def test_open_scheduler_and_arbiter_are_registered():
    cmake = read(ROOT / "Telegram" / "CMakeLists.txt")

    for name in (
        "mtproxy/open_scheduler.cpp",
        "mtproxy/open_scheduler.h",
        "endpoint_admission_arbiter.cpp",
        "endpoint_admission_arbiter.h",
    ):
        assert f"mtproto/proxy/{name}" in cmake


def test_scheduler_exposes_only_pure_reservation_reducers():
    header = read(SCHEDULER_H)
    source = read(SCHEDULER_CPP)

    assert "OpenSlotReduction ReserveOpenSlot(" in header
    assert "OpenSlotReduction CancelOpenSlot(" in header
    assert "OpenSlotReduction CommitOpenSlot(" in header
    assert "OpenSlotReflowReduction ReflowOpenSlots(" in header
    assert "const OpenSlotSchedule &schedule" in header
    assert "class OpenSlotReservation" not in header
    assert "QMutexLocker" not in source
    assert "result.schedule.pending.push_back({" in source
    assert "result.schedule.pending.erase(i);" in source
    assert "result.schedule.recent.push_back({" in source
    assert "EndpointContextStorage" not in header


def test_scheduler_uses_pattern_spacing_without_adaptive_feedback():
    source = read(SCHEDULER_CPP)
    spacing = function_body(source, "crl::time OpenConnectionSpacing(")

    for pattern, delay in (
        ("Soft", 1100),
        ("Quiet", 1200),
        ("Strict", 1400),
        ("Browser", 1150),
    ):
        assert f"ProxyConnectionPattern::{pattern}: return crl::time({delay});" in spacing
    assert "kMinimumOpenSpacing = crl::time(500)" in source
    assert "kMaximumOpenJitter = crl::time(125)" in source
    assert "adaptiveSpacing" not in source
    assert "NoteConnectTimeout" not in source
    assert "NoteConnectSuccess" not in source


def test_arbiter_reserves_reflows_and_commits_exact_live_slots():
    header = read(ARBITER_H)
    source = read(ARBITER_CPP)
    reserve = function_body(
        source,
        "bool EndpointAdmissionArbiter::Private::reserveTicketLocked(")
    revalidate = function_body(
        source,
        "void EndpointAdmissionArbiter::Private::revalidateReservationsLocked(")
    grant = function_body(
        source, "void EndpointAdmissionArbiter::Private::deliverGrant(")
    transport_ready = function_body(
        source,
        "void EndpointAdmissionArbiter::Private::markTransportReady(")
    release = function_body(
        source,
        "void EndpointAdmissionArbiter::Private::releaseLiveSlot(")

    assert "kMinimumOpenSpacing = crl::time(500)" in read(SCHEDULER_CPP)
    assert "kOpenSpacingJitter = crl::time(125)" in source
    assert "kEndpointLiveSlotCount = 4" in header
    assert "pool.slots[slotIndex].phase != MtProxy::LiveSlotPhase::Empty" in reserve
    assert "MtProxy::ReserveOpenSlot(" in reserve
    assert "slot.phase = MtProxy::LiveSlotPhase::Reserved;" in reserve
    assert "ticket.slotKey = SlotKey(endpointKey, slotIndex, slot);" in reserve
    assert "MtProxy::ReflowOpenSlots(" in revalidate
    assert "MtProxy::CommitOpenSlot(" in grant
    assert "ProxySchedulerLifecycle::HandedOff" in grant
    assert "slot.phase = MtProxy::LiveSlotPhase::Opening;" in grant
    assert "slot.owner = MtProxy::LiveSlotAttemptOwner{" in grant
    assert "slot.phase != MtProxy::LiveSlotPhase::Opening" in transport_ready
    assert "slot.incarnation != slotKey.incarnation" in transport_ready
    assert "AttemptOwnerMatches(*owner, attempt)" in transport_ready
    assert "slot.phase = MtProxy::LiveSlotPhase::Live;" in transport_ready
    assert "LiveSlotPhase::Empty" not in transport_ready
    assert "slot.incarnation != slotKey.incarnation" in release
    assert "AttemptOwnerMatches" in release
    assert "slot.phase = MtProxy::LiveSlotPhase::Empty;" in release
    assert "successor = closing->pendingSuccessor;" in release
    for deleted in (
        "applyOpeningEventLocked",
        "PressureFailure",
        "EndpointOpenGateStage",
        "kPressureWindow",
        "kRecoveryOpenSpacing",
    ):
        assert deleted not in source


def test_cancelled_ticket_releases_reservation_and_redistributes():
    source = read(ARBITER_CPP)
    cancel_ticket = function_body(
        source,
        "void EndpointAdmissionArbiter::Private::cancelTicketLocked(")
    clear_slot = function_body(
        source,
        "void EndpointAdmissionArbiter::Private::clearTicketSlotLocked(")
    cancel = function_body(
        source, "void EndpointAdmissionArbiter::Private::cancel(")

    assert "clearTicketSlotLocked(ticket);" in cancel_ticket
    assert "MtProxy::CancelOpenSlot(" in clear_slot
    assert "slot.phase = MtProxy::LiveSlotPhase::Empty;" in clear_slot
    assert "closing->pendingSuccessor.reset();" in clear_slot
    assert "actions.removed.push_back(takeTicketLocked(key));" in cancel_ticket
    assert "drainEndpointLocked(endpointKey, inputs, actions);" in cancel
    assert "updateWakeLocked(inputs, actions);" in cancel
    assert cancel.index("actions.run();") > cancel.index(
        "drainEndpointLocked(endpointKey, inputs, actions);")


def test_connection_broker_is_not_a_second_scheduler():
    header = read(BROKER_H)
    source = read(BROKER_CPP)

    assert "EndpointQueue" not in header
    assert "OpenSlotReservation" not in header
    assert "ReserveOpenSlot" not in source
    assert "scheduleOpenRetry" not in source
    assert "endpointAdmissionArbiter().enqueue(" in source
    assert "endpointAdmissionArbiter().cancel(" in source


def test_live_and_probe_connections_enter_through_the_same_broker():
    session = read_session_private_sources()
    append = function_body(session, "bool SessionTransport::appendTestConnection(")
    check = read(CHECK_CPP)
    start = function_body(check, "void StartProxyCheck(")

    assert "_owner->_proxyPort->requestConnection({" in append
    assert "runtime->proxyServices().broker().request({" in start
    assert "MtProxy::EndpointUse::ProxyCheck" in start
    assert "ReserveOpenSlot" not in append
    assert "ReserveOpenSlot" not in start


def test_broker_cancellation_is_runtime_and_generation_scoped():
    header = read(BROKER_H)
    source = read(BROKER_CPP)

    assert "void cancelByProxyGeneration(uint64 generation);" in header
    assert "void cancelByOwnerDestruction();" in header
    assert "cancelBeforeGeneration(" in source
    assert "cancelRuntime(" in source
    assert "MTP::Instance" not in header


def function_body(text, signature):
    start = text.index(signature)
    brace = text.index("{", start)
    depth = 0
    for index in range(brace, len(text)):
        if text[index] == "{":
            depth += 1
        elif text[index] == "}":
            depth -= 1
            if depth == 0:
                return text[brace + 1:index]
    raise AssertionError(f"function body not found: {signature}")


if __name__ == "__main__":
    test_open_scheduler_and_arbiter_are_registered()
    test_scheduler_exposes_only_pure_reservation_reducers()
    test_scheduler_uses_pattern_spacing_without_adaptive_feedback()
    test_arbiter_reserves_reflows_and_commits_exact_live_slots()
    test_cancelled_ticket_releases_reservation_and_redistributes()
    test_connection_broker_is_not_a_second_scheduler()
    test_live_and_probe_connections_enter_through_the_same_broker()
    test_broker_cancellation_is_runtime_and_generation_scoped()
