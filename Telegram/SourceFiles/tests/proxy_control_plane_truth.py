from dataclasses import dataclass, replace
from pathlib import Path


SOURCE_DIR = Path(__file__).resolve().parents[1]
PROXY_DIR = SOURCE_DIR / "mtproto" / "proxy"
CONTROL_CPP = PROXY_DIR / "control_plane.cpp"
BROKER_CPP = PROXY_DIR / "connection_broker.cpp"
CHECK_CPP = PROXY_DIR / "check.cpp"
CAPABILITIES_CPP = PROXY_DIR / "capabilities.cpp"
ENDPOINT_HEALTH_CPP = PROXY_DIR / "mtproxy" / "endpoint_health.cpp"
ENDPOINT_HEALTH_H = PROXY_DIR / "mtproxy" / "endpoint_health.h"
TLS_SOCKET_CPP = PROXY_DIR / "mtproxy" / "tls_socket.cpp"

NONE = "none"
FAILED = "failed"
CONNECTED = "connected"
CHECKING = "checking"
NO_SERVERHELLO = "client_hello_sent_no_server_hello"
NO_APPDATA = "server_hello_ok_no_appdata"
NO_MTPROTO = "server_hello_ok_no_mtproto_data"
MTP_TIMEOUT_AFTER_DATA = "mtp_receive_timeout_after_data"
HMAC_MISMATCH = "server_hello_hmac_mismatch"
RELAY = "relay"
HANDSHAKE = "handshake"
FAKETLS_APPDATA = "faketls_appdata"


@dataclass(frozen=True)
class Attempt:
    proxy_generation: int = 0
    proxy_epoch: int = 0
    attempt_id: int = 0
    probe: bool = False


@dataclass(frozen=True)
class Status:
    phase: str = NONE
    reason: str = NONE
    error: bool = False
    attempt: Attempt = Attempt()
    terminal_until: int = 0
    success_until: int = 0


@dataclass(frozen=True)
class Fact:
    status: Status = Status()
    success_scope: str = NONE


@dataclass
class EndpointState:
    proxy_generation: int = 0
    proxy_epoch: int = 1
    success_epoch: int = 0
    last_relay_success_at: int = 0
    relay_proven: bool = False


@dataclass
class BrokerRequest:
    active: bool = True
    has_context: bool = True
    admission: bool = False
    admission_lease_active: bool = False
    admission_in_progress: bool = False
    start_scheduled: bool = False


def read(path):
    assert path.exists(), f"missing expected source file: {path}"
    return path.read_text(encoding="utf-8")


def is_terminal_reason(reason):
    return reason != NONE


def is_terminal_failure(status):
    return status.error or is_terminal_reason(status.reason)


def is_success(status):
    return status.phase == CONNECTED


def relay_success_is_fresh(status, now):
    return is_success(status) and status.success_until > now


def is_newer_proxy_epoch(current, update):
    if update.proxy_generation != current.proxy_generation:
        return update.proxy_generation > current.proxy_generation
    return update.proxy_epoch > current.proxy_epoch


def is_newer_attempt(current, update):
    if update.proxy_generation != current.proxy_generation:
        return update.proxy_generation > current.proxy_generation
    if update.proxy_epoch != current.proxy_epoch:
        return update.proxy_epoch > current.proxy_epoch
    return update.attempt_id > current.attempt_id


def is_older_proxy_generation(current, update):
    return (
        current.proxy_generation
        and (not update.proxy_generation
             or update.proxy_generation < current.proxy_generation)
    )


def is_older_attempt(current, update):
    if current.proxy_generation and update.proxy_generation != current.proxy_generation:
        return False
    if current.proxy_epoch and not update.proxy_epoch:
        return True
    if update.proxy_epoch and update.proxy_epoch < current.proxy_epoch:
        return True
    if update.proxy_epoch != current.proxy_epoch:
        return False
    return (
        current.attempt_id
        and update.attempt_id
        and update.attempt_id < current.attempt_id
    )


def is_relay_data_stall(status):
    return status.reason in {
        NO_APPDATA,
        NO_MTPROTO,
        MTP_TIMEOUT_AFTER_DATA,
    }


def normalize_terminal_reason(current, status):
    if status.reason != NO_SERVERHELLO or current.attempt != status.attempt:
        return status
    if current.phase not in {CHECKING, CONNECTED}:
        return status
    return replace(status, reason=NO_APPDATA, error=False)


def apply_selected_status_update(current, update, now):
    if is_older_proxy_generation(current.attempt, update.attempt):
        return current
    if is_older_attempt(current.attempt, update.attempt):
        return current
    if (
        relay_success_is_fresh(current, now)
        and is_terminal_failure(update)
        and not is_newer_proxy_epoch(current.attempt, update.attempt)
    ):
        return current
    if not is_terminal_reason(current.reason):
        return update
    if (
        is_success(update)
        or is_terminal_reason(update.reason)
        or is_newer_attempt(current.attempt, update.attempt)
    ):
        return update
    if current.terminal_until > now:
        return current
    return update


def reduce_status(current, fact, now=1000, fresh_window=15000):
    status = fact.status
    if status.attempt.probe:
        return current
    if is_relay_data_stall(status):
        status = replace(status, error=False)
    if fact.success_scope == RELAY:
        status = replace(
            status,
            phase=CONNECTED,
            success_until=now + fresh_window)
    status = normalize_terminal_reason(current, status)
    if (
        relay_success_is_fresh(current, now)
        and is_terminal_failure(status)
        and not is_newer_proxy_epoch(current.attempt, status.attempt)
    ):
        return current
    return apply_selected_status_update(current, status, now)


def report_epoch_is_stale(report_epoch, state):
    return report_epoch and report_epoch < state.proxy_epoch


def report_success_epoch_is_stale(report_success_epoch, state):
    return state.success_epoch and report_success_epoch < state.success_epoch


def report_generation_is_stale(report_generation, state):
    return report_generation and report_generation < state.proxy_generation


def report_started_before_relay(started_at, state):
    return state.last_relay_success_at and started_at < state.last_relay_success_at


def failure_from_stale_attempt(
        report_generation,
        report_epoch,
        report_success_epoch,
        started_at,
        state):
    return (
        report_generation_is_stale(report_generation, state)
        or
        report_epoch_is_stale(report_epoch, state)
        or
        report_success_epoch_is_stale(report_success_epoch, state)
        or report_started_before_relay(started_at, state)
    )


def success_from_stale_attempt(
        report_generation,
        report_epoch,
        report_success_epoch,
        started_at,
        state):
    return (
        report_generation_is_stale(report_generation, state)
        or
        report_epoch_is_stale(report_epoch, state)
        or
        report_success_epoch_is_stale(report_success_epoch, state)
        or report_started_before_relay(started_at, state)
    )


def relay_success(
        state,
        report_generation,
        report_epoch,
        report_success_epoch,
        started_at,
        now):
    if success_from_stale_attempt(
            report_generation,
            report_epoch,
            report_success_epoch,
            started_at,
            state):
        return False
    state.proxy_generation = max(state.proxy_generation, report_generation)
    state.relay_proven = True
    state.last_relay_success_at = now
    state.success_epoch += 1
    state.proxy_epoch += 1
    return True


def faketls_appdata_success(
        state,
        report_generation,
        report_epoch,
        report_success_epoch,
        started_at,
        now):
    if success_from_stale_attempt(
            report_generation,
            report_epoch,
            report_success_epoch,
            started_at,
            state):
        return False
    state.proxy_generation = max(state.proxy_generation, report_generation)
    return True


def broker_claim_front(state):
    if (
        not state.active
        or not state.has_context
        or state.admission
        or state.admission_in_progress
        or state.start_scheduled
    ):
        return False
    state.admission_in_progress = True
    return True


def broker_complete_start(state):
    state.admission_in_progress = False
    state.start_scheduled = True


def broker_cancel(state):
    state.active = False
    state.admission = False
    state.admission_lease_active = False
    state.admission_in_progress = False


def probe_decision(active_probe_key, snapshot, now=1000, active_window=9000):
    if active_probe_key:
        return "waiting_for_connection_slot"
    if (
        snapshot["healthy"]
        and not snapshot["half_open"]
        and snapshot["relay_proven"]
        and snapshot["last_relay_success_at"]
        and now - snapshot["last_relay_success_at"] < active_window
    ):
        return "connected_by_active_session"
    return "start_probe"


def capability_relay_proven_after_failure(relay_proven, reason, degraded):
    if degraded and reason in {NO_APPDATA, NO_MTPROTO, MTP_TIMEOUT_AFTER_DATA}:
        return False
    return relay_proven


def capability_relay_proven_after_age(relay_proven, proven_at, now, ttl):
    return relay_proven and proven_at and now - proven_at <= ttl


def test_reducer_no_appdata_relay_success_sibling_failure():
    attempt1 = Attempt(proxy_generation=1, proxy_epoch=1, attempt_id=1)
    attempt2 = Attempt(proxy_generation=1, proxy_epoch=1, attempt_id=2)
    current = Status()
    current = reduce_status(current, Fact(Status(
        phase=FAILED,
        reason=NO_APPDATA,
        error=True,
        attempt=attempt1)))
    assert current.reason == NO_APPDATA
    assert not current.error

    current = reduce_status(current, Fact(
        Status(phase=CONNECTED, attempt=attempt2),
        success_scope=RELAY))
    connected = current
    assert connected.phase == CONNECTED
    assert connected.success_until > 1000

    sibling_failure = Fact(Status(
        phase=FAILED,
        reason=NO_SERVERHELLO,
        error=True,
        attempt=attempt1))
    assert reduce_status(current, sibling_failure) == connected


def test_old_generation_and_probe_facts_are_shadowed():
    current = Status(
        phase=CONNECTED,
        attempt=Attempt(proxy_generation=2, proxy_epoch=1, attempt_id=1),
        success_until=16000)
    old_generation_failure = Fact(Status(
        phase=FAILED,
        reason=HMAC_MISMATCH,
        error=True,
        attempt=Attempt(proxy_generation=1, proxy_epoch=99, attempt_id=99)))
    probe_failure = Fact(Status(
        phase=FAILED,
        reason=NO_SERVERHELLO,
        error=True,
        attempt=Attempt(
            proxy_generation=2,
            proxy_epoch=1,
            attempt_id=2,
            probe=True)))
    assert reduce_status(current, old_generation_failure) == current
    assert reduce_status(current, probe_failure) == current


def test_older_progress_fact_cannot_repaint_connected_status():
    current = Status(
        phase=CONNECTED,
        attempt=Attempt(proxy_generation=1, proxy_epoch=2, attempt_id=4),
        success_until=0)
    stale_progress = Fact(Status(
        phase=CHECKING,
        attempt=Attempt(proxy_generation=1, proxy_epoch=2, attempt_id=3)))
    stale_epoch_progress = Fact(Status(
        phase=CHECKING,
        attempt=Attempt(proxy_generation=1, proxy_epoch=1, attempt_id=99)))

    assert reduce_status(current, stale_progress) == current
    assert reduce_status(current, stale_epoch_progress) == current


def test_endpoint_success_epoch_shadows_old_reports():
    state = EndpointState(proxy_generation=3)
    assert relay_success(
        state,
        report_generation=3,
        report_epoch=1,
        report_success_epoch=0,
        started_at=100,
        now=200)
    assert state.proxy_epoch == 2
    assert state.success_epoch == 1
    assert state.relay_proven
    assert failure_from_stale_attempt(
        report_generation=3,
        report_epoch=2,
        report_success_epoch=0,
        started_at=300,
        state=state)
    assert success_from_stale_attempt(
        report_generation=3,
        report_epoch=2,
        report_success_epoch=0,
        started_at=300,
        state=state)
    assert failure_from_stale_attempt(
        report_generation=2,
        report_epoch=2,
        report_success_epoch=1,
        started_at=300,
        state=state)
    assert success_from_stale_attempt(
        report_generation=2,
        report_epoch=2,
        report_success_epoch=1,
        started_at=300,
        state=state)
    assert failure_from_stale_attempt(
        report_generation=3,
        report_epoch=2,
        report_success_epoch=1,
        started_at=100,
        state=state)
    assert not failure_from_stale_attempt(
        report_generation=3,
        report_epoch=2,
        report_success_epoch=1,
        started_at=250,
        state=state)


def test_faketls_appdata_does_not_prove_relay_or_bump_epoch():
    state = EndpointState()
    assert faketls_appdata_success(
        state,
        report_generation=1,
        report_epoch=1,
        report_success_epoch=0,
        started_at=100,
        now=200)
    assert not state.relay_proven
    assert state.proxy_epoch == 1
    assert state.success_epoch == 0
    assert not state.last_relay_success_at

    assert relay_success(
        state,
        report_generation=1,
        report_epoch=1,
        report_success_epoch=0,
        started_at=100,
        now=300)
    assert state.relay_proven
    assert state.proxy_epoch == 2
    assert state.success_epoch == 1
    assert state.last_relay_success_at == 300


def test_probe_waiting_slot_and_relay_proven_gate():
    fresh_not_proven = {
        "healthy": True,
        "half_open": False,
        "relay_proven": False,
        "last_relay_success_at": 500,
    }
    fresh_proven = dict(fresh_not_proven, relay_proven=True)
    assert probe_decision(True, fresh_proven) == "waiting_for_connection_slot"
    assert probe_decision(False, fresh_not_proven) == "start_probe"
    assert probe_decision(False, fresh_proven) == "connected_by_active_session"


def test_broker_claim_prevents_double_admit():
    request = BrokerRequest()
    assert broker_claim_front(request)
    assert request.admission_in_progress
    assert not broker_claim_front(request)
    broker_complete_start(request)
    assert request.start_scheduled
    assert not broker_claim_front(request)


def test_broker_cancel_releases_admitted_lease_before_timer_fires():
    request = BrokerRequest(admission=True, admission_lease_active=True)
    broker_cancel(request)

    assert not request.active
    assert not request.admission
    assert not request.admission_lease_active
    assert not request.admission_in_progress


def test_capability_cache_soft_warning_vs_degraded_relay_failure():
    assert capability_relay_proven_after_failure(
        relay_proven=True,
        reason=NO_APPDATA,
        degraded=False)
    assert not capability_relay_proven_after_failure(
        relay_proven=True,
        reason=NO_APPDATA,
        degraded=True)


def test_capability_cache_relay_proof_ages_out():
    assert capability_relay_proven_after_age(
        relay_proven=True,
        proven_at=100,
        now=200,
        ttl=1000)
    assert not capability_relay_proven_after_age(
        relay_proven=True,
        proven_at=100,
        now=2000,
        ttl=1000)
    assert not capability_relay_proven_after_age(
        relay_proven=False,
        proven_at=100,
        now=200,
        ttl=1000)


def test_source_seams_match_truth_table_contract():
    control = read(CONTROL_CPP)
    broker = read(BROKER_CPP)
    check = read(CHECK_CPP)
    health_header = read(ENDPOINT_HEALTH_H)
    health = read(ENDPOINT_HEALTH_CPP)
    tls_socket = read(TLS_SOCKET_CPP)
    capabilities = read(CAPABILITIES_CPP)

    assert "ProxyControlPlane::Reduce(current, normalized)" in control
    assert "ApplySelectedStatusUpdate(" in control
    assert "IsOlderAttempt(current.attempt, update.attempt)" in control
    assert "fact.status.attempt.probe" in control
    assert "ShadowedByFreshRelaySuccess(current, fact)" in control
    assert "FakeTlsAppData," in health_header
    assert ".scope = MtProxy::SuccessScope::FakeTlsAppData" in tls_socket
    assert "ReportEpochIsStale(report.proxyEpoch, state)" in health
    assert "ReportSuccessEpochIsStale(report.successEpoch, state)" in health
    assert "ReportGenerationIsStale(report.proxyGeneration, state)" in health
    assert "SuccessFromStaleAttempt(report, state)" in health
    assert "uint64 proxyGeneration = 0;" in health_header
    assert "uint64 successEpoch = 0;" in health_header
    assert "uint64 successEpoch() const" in health_header
    assert "++state.proxyEpoch;" in health
    assert "++state.successEpoch;" in health
    assert "snapshot.relayProven" in check
    assert "ProxyCheckStatus::WaitingForConnectionSlot" in check
    assert "bool admissionInProgress = false;" in broker
    assert broker.index("state->admissionInProgress = true;") < (
        broker.index("ProxyControlPlane::Admit({"))
    assert "releaseAdmission(cancelled);" in broker
    assert "noteMtproxyRelayFailure(" in capabilities
    assert "card.relayProven = false;" in capabilities
    assert "relayProvenAt" in capabilities
    assert "FreshMtproxyRelayProof(" in capabilities
    assert "void EndpointHealth::noteRelayStall(" in health
    relay_stall = health.split("void EndpointHealth::noteRelayStall(", 1)[1]
    assert "RelayStallReport report" in relay_stall.split(")", 1)[0]
    assert "FailureFromStaleAttempt(staleReport, state)" in relay_stall
    assert "noteMtproxyRelayFailure(" in relay_stall


def run_all_truth_tables():
    test_reducer_no_appdata_relay_success_sibling_failure()
    test_old_generation_and_probe_facts_are_shadowed()
    test_older_progress_fact_cannot_repaint_connected_status()
    test_endpoint_success_epoch_shadows_old_reports()
    test_faketls_appdata_does_not_prove_relay_or_bump_epoch()
    test_probe_waiting_slot_and_relay_proven_gate()
    test_broker_claim_prevents_double_admit()
    test_broker_cancel_releases_admitted_lease_before_timer_fires()
    test_capability_cache_soft_warning_vs_degraded_relay_failure()
    test_capability_cache_relay_proof_ages_out()
    test_source_seams_match_truth_table_contract()
