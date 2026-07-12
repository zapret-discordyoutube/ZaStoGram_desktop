from pathlib import Path
from session_private_sources import read_session_private_sources


SOURCE_DIR = Path(__file__).resolve().parents[1]
ROOT = SOURCE_DIR.parents[1]
MTPROXY_DIR = SOURCE_DIR / "mtproto" / "proxy" / "mtproxy"
SCHEDULER_H = MTPROXY_DIR / "open_scheduler.h"
SCHEDULER_CPP = MTPROXY_DIR / "open_scheduler.cpp"
ARBITER_CPP = SOURCE_DIR / "mtproto" / "proxy" / "endpoint_admission_arbiter.cpp"
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


def test_scheduler_exposes_only_locked_reservation_primitives():
    header = read(SCHEDULER_H)
    source = read(SCHEDULER_CPP)

    assert "OpenSlotAssignment ReserveOpenSlotLocked(" in header
    assert "bool CancelOpenSlotLocked(" in header
    assert "bool CommitOpenSlotLocked(" in header
    assert "ReflowOpenSlotsLocked(" in header
    assert "class OpenSlotReservation" not in header
    assert "QMutexLocker" not in function_body(
        source, "OpenSlotAssignment ReserveOpenSlotLocked(")
    assert "state.pendingOpens.push_back({" in source
    assert "state.pendingOpens.erase(i);" in source
    assert "state.recentOpens.push_back({" in source


def test_scheduler_keeps_pattern_and_adaptive_spacing_separate():
    source = read(SCHEDULER_CPP)
    spacing = function_body(source, "crl::time OpenConnectionSpacing(")

    for pattern, delay in (
        ("Soft", 1100),
        ("Quiet", 1200),
        ("Strict", 1400),
        ("Browser", 1150),
    ):
        assert f"ProxyConnectionPattern::{pattern}: return crl::time({delay});" in spacing
    assert "kAdaptiveSpacingMin = crl::time(500)" in source
    assert "kAdaptiveSpacingMax = crl::time(6000)" in source
    assert "state.adaptiveSpacing * 2" in source
    assert "state.adaptiveSpacing / 2" in source


def test_arbiter_reserves_reflows_and_commits_the_shared_slot():
    source = read(ARBITER_CPP)
    assign = function_body(
        source,
        "void EndpointAdmissionArbiter::Private::assignReservationsLocked(")
    revalidate = function_body(
        source,
        "void EndpointAdmissionArbiter::Private::revalidateReservationsLocked(")
    grant = function_body(
        source, "void EndpointAdmissionArbiter::Private::deliverGrant(")

    assert "kMinimumOpenSpacing = crl::time(500)" in source
    assert "kOpenSpacingJitter = crl::time(125)" in source
    assert "MtProxy::ReserveOpenSlotLocked(" in assign
    assert "openState.adaptiveSpacing" in assign
    assert "MtProxy::ReflowOpenSlotsLocked(" in revalidate
    assert "MtProxy::CommitOpenSlotLocked(" in grant
    assert "ProxySchedulerLifecycle::HandedOff" in grant


def test_cancelled_ticket_releases_reservation_and_redistributes():
    source = read(ARBITER_CPP)
    cancel_ticket = function_body(
        source,
        "void EndpointAdmissionArbiter::Private::cancelTicketLocked(")
    cancel = function_body(
        source, "void EndpointAdmissionArbiter::Private::cancel(")

    assert "MtProxy::CancelOpenSlotLocked(" in cancel_ticket
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
    test_scheduler_exposes_only_locked_reservation_primitives()
    test_scheduler_keeps_pattern_and_adaptive_spacing_separate()
    test_arbiter_reserves_reflows_and_commits_the_shared_slot()
    test_cancelled_ticket_releases_reservation_and_redistributes()
    test_connection_broker_is_not_a_second_scheduler()
    test_live_and_probe_connections_enter_through_the_same_broker()
    test_broker_cancellation_is_runtime_and_generation_scoped()
