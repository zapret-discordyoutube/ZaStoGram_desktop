from copy import deepcopy
from dataclasses import dataclass, field, replace
from pathlib import Path


SOURCE_DIR = Path(__file__).resolve().parents[1]
PROXY_DIR = SOURCE_DIR / "mtproto" / "proxy"
CONTROL_CPP = PROXY_DIR / "control_plane.cpp"
BROKER_CPP = PROXY_DIR / "connection_broker.cpp"
CHECK_CPP = PROXY_DIR / "check.cpp"
CAPABILITIES_CPP = PROXY_DIR / "capabilities.cpp"
ENDPOINT_HEALTH_CPP = PROXY_DIR / "mtproxy" / "endpoint_health.cpp"
ENDPOINT_HEALTH_LIFECYCLE_CPP = (
    PROXY_DIR / "mtproxy" / "endpoint_health_lifecycle.cpp")
ENDPOINT_HEALTH_CAPABILITIES_CPP = (
    PROXY_DIR / "mtproxy" / "endpoint_health_capabilities.cpp")
ENDPOINT_HEALTH_H = PROXY_DIR / "mtproxy" / "endpoint_health.h"
ENDPOINT_HEALTH_POLICY_CPP = PROXY_DIR / "mtproxy" / "endpoint_health_policy.cpp"
ENDPOINT_HEALTH_STATE_H = PROXY_DIR / "mtproxy" / "endpoint_health_state.h"
PROXY_ENDPOINT_CONTEXT_CPP = PROXY_DIR / "proxy_endpoint_context.cpp"
SESSION_PROXY_ADAPTER_CPP = PROXY_DIR / "session_proxy_adapter.cpp"
SESSION_PROXY_PORT_H = SOURCE_DIR / "mtproto" / "session" / "private" / "proxy_port.h"
SESSION_CONNECTION_CPP = (
    SOURCE_DIR / "mtproto" / "session" / "private" / "connection.cpp")
INSTANCE_CPP = SOURCE_DIR / "mtproto" / "instance" / "mtp_instance.cpp"
TLS_SOCKET_CPP = PROXY_DIR / "mtproxy" / "tls_socket.cpp"
TLS_SOCKET_RECORDS_CPP = PROXY_DIR / "mtproxy" / "tls_socket_records.cpp"

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
INSERTED = "Inserted"
ALREADY_PROVEN = "AlreadyProven"
MISSING_ADMISSION = "MissingAdmission"
STALE_GENERATION = "StaleGeneration"
STALE_ATTEMPT = "StaleAttempt"
MISSING_OR_DUPLICATE = "MissingOrDuplicate"
RETIRED_WITH_SURVIVORS = "RetiredWithSurvivors"
RETIRED_FINAL = "RetiredFinal"
PUNISHED_MISSING = "PunishedMissing"
HEALTHY_ACTIVE_CAP = 1
ATTEMPT_HARD_TTL = 120000
ABC_ENDPOINT = "151.247.209.166.sslip.io:45632"


@dataclass(frozen=True)
class Attempt:
    proxy_generation: int = 0
    proxy_epoch: int = 0
    success_epoch: int = 0
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


@dataclass(frozen=True, order=True)
class RelayProofIdentity:
    runtime_id: int = 0
    proxy_generation: int = 0
    attempt_id: int = 0


@dataclass(frozen=True)
class EndpointAttemptState:
    runtime_id: int = 0
    proxy_generation: int = 0
    started_at: int = 0
    admission_active: bool = True


@dataclass(frozen=True)
class RelayProofState:
    proven_at: int = 0


@dataclass(frozen=True)
class RelayReport:
    endpoint: str
    runtime_id: int = 0
    proxy_generation: int = 0
    attempt_id: int = 0
    proxy_epoch: int = 0
    success_epoch: int = 0
    started_at: int = 0


@dataclass
class EndpointState:
    generations: dict = field(default_factory=dict)
    attempt_starts: dict = field(default_factory=dict)
    active: int = 0
    proxy_epoch: int = 1
    success_epoch: int = 0
    relay_proofs: dict = field(default_factory=dict)
    last_success_at: int = 0
    last_relay_success_at: int = 0
    relay_proven: bool = False
    healthy: bool = False
    route_state: str = "unknown"
    route_success_count: int = 0
    route_failure_count: int = 0
    cooldown_until: int = 0
    cooldown_count: int = 0
    rotation_count: int = 0
    capability_success_count: int = 0
    capability_failure_count: int = 0
    relay_capability_failure_count: int = 0
    capability_relay_proven: bool = False
    last_failure: str = NONE


@dataclass
class CanonicalEndpointStore:
    states: dict = field(default_factory=dict)

    def state(self, endpoint):
        return self.states.setdefault(endpoint, EndpointState())


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


def read_endpoint_health_sources():
    return "\n".join(read(path) for path in (
        ENDPOINT_HEALTH_CPP,
        ENDPOINT_HEALTH_LIFECYCLE_CPP,
    ))


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
    if update.proxy_epoch != current.proxy_epoch:
        return update.proxy_epoch > current.proxy_epoch
    return update.success_epoch > current.success_epoch


def is_newer_attempt(current, update):
    if update.proxy_generation != current.proxy_generation:
        return update.proxy_generation > current.proxy_generation
    if update.proxy_epoch != current.proxy_epoch:
        return update.proxy_epoch > current.proxy_epoch
    if update.success_epoch != current.success_epoch:
        return update.success_epoch > current.success_epoch
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
    if current.success_epoch and not update.success_epoch:
        return True
    if update.success_epoch and update.success_epoch < current.success_epoch:
        return True
    if update.success_epoch != current.success_epoch:
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
        and update.attempt != current.attempt
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
        and status.attempt != current.attempt
        and not is_newer_proxy_epoch(current.attempt, status.attempt)
    ):
        return current
    return apply_selected_status_update(current, status, now)


def report_epoch_is_stale(report_epoch, state):
    return report_epoch and report_epoch < state.proxy_epoch


def report_success_epoch_is_stale(report_success_epoch, state):
    return state.success_epoch and report_success_epoch < state.success_epoch


def relay_proof_identity(report):
    return RelayProofIdentity(
        runtime_id=report.runtime_id,
        proxy_generation=report.proxy_generation,
        attempt_id=report.attempt_id)


def runtime_proxy_generation_is_stale(state, runtime_id, proxy_generation):
    return (
        runtime_id in state.generations
        and proxy_generation < state.generations[runtime_id]
    )


def has_endpoint_attempt(state, identity):
    admission = state.attempt_starts.get(identity.attempt_id)
    return (
        admission is not None
        and admission.runtime_id == identity.runtime_id
        and admission.proxy_generation == identity.proxy_generation
    )


def has_relay_proof(state, identity):
    return identity in state.relay_proofs


def active_endpoint_admission_count(state):
    return sum(
        admission.admission_active
        for admission in state.attempt_starts.values())


def synchronize_endpoint_admission_aggregate(state):
    state.active = active_endpoint_admission_count(state)


def release_admission_for_relay_candidate(state, identity):
    admission = state.attempt_starts.get(identity.attempt_id)
    if (
        admission is None
        or admission.runtime_id != identity.runtime_id
        or admission.proxy_generation != identity.proxy_generation
        or not admission.admission_active
    ):
        return False
    state.attempt_starts[identity.attempt_id] = replace(
        admission,
        admission_active=False)
    synchronize_endpoint_admission_aggregate(state)
    return True


def synchronize_relay_proof_aggregate(state):
    state.relay_proofs = {
        identity: proof
        for identity, proof in state.relay_proofs.items()
        if not (
            identity.runtime_id in state.generations
            and identity.proxy_generation
            < state.generations[identity.runtime_id]
        )
    }
    state.relay_proven = bool(state.relay_proofs)
    state.last_relay_success_at = max(
        (proof.proven_at for proof in state.relay_proofs.values()),
        default=0)
    if state.relay_proven:
        state.healthy = True


def apply_runtime_proxy_generation(state, runtime_id, proxy_generation):
    if not runtime_id:
        return
    current = state.generations.get(runtime_id)
    if (
        (current is not None and proxy_generation <= current)
        or (current is None and not proxy_generation)
    ):
        return
    state.generations[runtime_id] = proxy_generation
    state.attempt_starts = {
        attempt_id: admission
        for attempt_id, admission in state.attempt_starts.items()
        if not (
            admission.runtime_id == runtime_id
            and admission.proxy_generation < proxy_generation
        )
    }
    synchronize_endpoint_admission_aggregate(state)
    state.relay_proofs = {
        identity: proof
        for identity, proof in state.relay_proofs.items()
        if not (
            identity.runtime_id == runtime_id
            and identity.proxy_generation < proxy_generation
        )
    }
    synchronize_relay_proof_aggregate(state)


def prune_expired_endpoint_state(state, now):
    state.attempt_starts = {
        attempt_id: admission
        for attempt_id, admission in state.attempt_starts.items()
        if now - admission.started_at <= ATTEMPT_HARD_TTL
    }
    synchronize_endpoint_admission_aggregate(state)


def seed_admission(store, report):
    state = store.state(report.endpoint)
    apply_runtime_proxy_generation(
        state,
        report.runtime_id,
        report.proxy_generation)
    state.attempt_starts[report.attempt_id] = EndpointAttemptState(
        runtime_id=report.runtime_id,
        proxy_generation=report.proxy_generation,
        started_at=report.started_at)
    synchronize_endpoint_admission_aggregate(state)


def public_admit(store, report, now):
    state = store.state(report.endpoint)
    prune_expired_endpoint_state(state, now)
    if runtime_proxy_generation_is_stale(
            state,
            report.runtime_id,
            report.proxy_generation):
        return False
    apply_runtime_proxy_generation(
        state,
        report.runtime_id,
        report.proxy_generation)
    if state.active >= HEALTHY_ACTIVE_CAP:
        return False
    seed_admission(store, report)
    return True


def promote_relay_proof(state, identity, proof):
    if has_relay_proof(state, identity):
        return ALREADY_PROVEN
    if not has_endpoint_attempt(state, identity):
        return MISSING_ADMISSION
    state.relay_proofs[identity] = proof
    del state.attempt_starts[identity.attempt_id]
    synchronize_endpoint_admission_aggregate(state)
    synchronize_relay_proof_aggregate(state)
    return INSERTED


def retire_relay_proof_record(state, identity):
    if identity not in state.relay_proofs:
        return False
    del state.relay_proofs[identity]
    synchronize_relay_proof_aggregate(state)
    return True


def failure_from_stale_attempt(report, state):
    if runtime_proxy_generation_is_stale(
            state,
            report.runtime_id,
            report.proxy_generation):
        return True
    if has_relay_proof(state, relay_proof_identity(report)):
        return False
    return (
        report_epoch_is_stale(report.proxy_epoch, state)
        or report_success_epoch_is_stale(report.success_epoch, state)
        or (
            state.last_relay_success_at
            and report.started_at < state.last_relay_success_at
        )
    )


def success_from_stale_attempt(report, state):
    if runtime_proxy_generation_is_stale(
            state,
            report.runtime_id,
            report.proxy_generation):
        return True
    identity = relay_proof_identity(report)
    if has_endpoint_attempt(state, identity) or has_relay_proof(state, identity):
        return False
    return (
        report_epoch_is_stale(report.proxy_epoch, state)
        or report_success_epoch_is_stale(report.success_epoch, state)
        or (
            state.last_relay_success_at
            and report.started_at < state.last_relay_success_at
        )
    )


def report_relay_success(store, report, now):
    state = store.state(report.endpoint)
    prune_expired_endpoint_state(state, now)
    if runtime_proxy_generation_is_stale(
            state,
            report.runtime_id,
            report.proxy_generation):
        return STALE_GENERATION
    apply_runtime_proxy_generation(
        state,
        report.runtime_id,
        report.proxy_generation)
    if success_from_stale_attempt(report, state):
        return STALE_ATTEMPT
    promotion = promote_relay_proof(
        state,
        relay_proof_identity(report),
        RelayProofState(proven_at=now))
    if promotion != INSERTED:
        return promotion
    state.last_success_at = now
    state.route_state = "good"
    state.route_success_count += 1
    state.success_epoch += 1
    state.proxy_epoch += 1
    state.capability_success_count += 1
    state.capability_relay_proven = True
    state.last_failure = NONE
    state.cooldown_until = 0
    state.healthy = True
    return INSERTED


def faketls_appdata_success(store, report, now):
    state = store.state(report.endpoint)
    prune_expired_endpoint_state(state, now)
    if runtime_proxy_generation_is_stale(
            state,
            report.runtime_id,
            report.proxy_generation):
        return False
    apply_runtime_proxy_generation(
        state,
        report.runtime_id,
        report.proxy_generation)
    if success_from_stale_attempt(report, state):
        return False
    state.last_success_at = now
    return True


def retire_relay_proof(store, report, now):
    state = store.states.get(report.endpoint)
    if state is None:
        return MISSING_OR_DUPLICATE
    prune_expired_endpoint_state(state, now)
    if runtime_proxy_generation_is_stale(
            state,
            report.runtime_id,
            report.proxy_generation):
        return STALE_GENERATION
    apply_runtime_proxy_generation(
        state,
        report.runtime_id,
        report.proxy_generation)
    if not retire_relay_proof_record(state, relay_proof_identity(report)):
        return MISSING_OR_DUPLICATE
    return (
        RETIRED_WITH_SURVIVORS
        if state.relay_proven
        else RETIRED_FINAL
    )


def punish_final_failure(state, reason, now):
    state.route_state = "bad"
    state.route_failure_count += 1
    state.last_failure = reason
    relay_failures = {
        NO_APPDATA,
        NO_MTPROTO,
        MTP_TIMEOUT_AFTER_DATA,
    }
    cooldown_failures = {
        NO_SERVERHELLO,
        NO_APPDATA,
        NO_MTPROTO,
        HMAC_MISMATCH,
    }
    if reason not in relay_failures:
        state.capability_failure_count += 1
    if reason in cooldown_failures:
        state.cooldown_count += 1
        state.cooldown_until = now + 15000
        state.rotation_count += 1
        state.healthy = False
        if reason in relay_failures:
            state.relay_capability_failure_count += 1
            state.capability_relay_proven = False


def report_failure(store, report, reason, now):
    state = store.state(report.endpoint)
    prune_expired_endpoint_state(state, now)
    if runtime_proxy_generation_is_stale(
            state,
            report.runtime_id,
            report.proxy_generation):
        return STALE_GENERATION
    apply_runtime_proxy_generation(
        state,
        report.runtime_id,
        report.proxy_generation)
    if failure_from_stale_attempt(report, state):
        return STALE_ATTEMPT
    retired = retire_relay_proof_record(state, relay_proof_identity(report))
    if state.relay_proven:
        return (
            RETIRED_WITH_SURVIVORS
            if retired
            else MISSING_OR_DUPLICATE
        )
    punish_final_failure(state, reason, now)
    return RETIRED_FINAL if retired else PUNISHED_MISSING


def report_relay_stall(store, report, now):
    result = retire_relay_proof(store, report, now)
    if result == RETIRED_FINAL:
        state = store.states[report.endpoint]
        state.relay_capability_failure_count += 1
        state.capability_relay_proven = False
    return result


def neutral_retire(store, report, now, origin=NONE):
    assert origin in {
        NONE,
        "normal_close",
        "cancel",
        "owner_destruction",
        "proxy_switch",
    }
    return retire_relay_proof(store, report, now)


def healthy_remote_close(store, report, now):
    state = store.states.get(report.endpoint)
    if state is None or not state.healthy:
        return MISSING_OR_DUPLICATE
    return neutral_retire(
        store,
        report,
        now,
        origin="normal_close")


def snapshot_endpoint_state(store, endpoint, now):
    state = store.states.get(endpoint)
    if state is None:
        return None
    prune_expired_endpoint_state(state, now)
    return deepcopy(state)


def apply_proxy_generation(store, runtime_id, proxy_generation, now):
    for state in store.states.values():
        prune_expired_endpoint_state(state, now)
        apply_runtime_proxy_generation(
            state,
            runtime_id,
            proxy_generation)


def unregister_runtime(store, runtime_id):
    for state in store.states.values():
        state.generations.pop(runtime_id, None)
        state.attempt_starts = {
            attempt_id: admission
            for attempt_id, admission in state.attempt_starts.items()
            if admission.runtime_id != runtime_id
        }
        synchronize_endpoint_admission_aggregate(state)
        state.relay_proofs = {
            identity: proof
            for identity, proof in state.relay_proofs.items()
            if identity.runtime_id != runtime_id
        }
        synchronize_relay_proof_aggregate(state)


def punishment_signature(state):
    return (
        state.route_state,
        state.route_success_count,
        state.route_failure_count,
        state.cooldown_until,
        state.cooldown_count,
        state.rotation_count,
        state.capability_success_count,
        state.capability_failure_count,
        state.relay_capability_failure_count,
        state.capability_relay_proven,
    )


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

    same_attempt_stall = Fact(Status(
        phase=FAILED,
        reason=MTP_TIMEOUT_AFTER_DATA,
        error=True,
        attempt=attempt2))
    stalled = reduce_status(current, same_attempt_stall)
    assert stalled != connected
    assert stalled.reason == MTP_TIMEOUT_AFTER_DATA
    assert not stalled.error


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


def test_selected_status_success_epoch_shadows_late_failures():
    current = Status(
        phase=CONNECTED,
        attempt=Attempt(
            proxy_generation=1,
            proxy_epoch=2,
            success_epoch=1,
            attempt_id=4),
        success_until=16000)
    stale_success_epoch_failure = Fact(Status(
        phase=FAILED,
        reason=NO_SERVERHELLO,
        error=True,
        attempt=Attempt(
            proxy_generation=1,
            proxy_epoch=2,
            success_epoch=0,
            attempt_id=99)))
    fresh_success_epoch_progress = Fact(Status(
        phase=CHECKING,
        attempt=Attempt(
            proxy_generation=1,
            proxy_epoch=2,
            success_epoch=2,
            attempt_id=1)))

    assert reduce_status(current, stale_success_epoch_failure) == current
    assert reduce_status(current, fresh_success_epoch_progress) != current


def make_relay_report(
        endpoint=ABC_ENDPOINT,
        runtime_id=2,
        proxy_generation=36,
        attempt_id=168,
        proxy_epoch=1,
        success_epoch=0,
        started_at=100):
    return RelayReport(
        endpoint=endpoint,
        runtime_id=runtime_id,
        proxy_generation=proxy_generation,
        attempt_id=attempt_id,
        proxy_epoch=proxy_epoch,
        success_epoch=success_epoch,
        started_at=started_at)


def test_keyless_release_preserves_exact_promotion_lineage():
    report = make_relay_report()
    unrelated = replace(report, attempt_id=169)
    store = CanonicalEndpointStore()
    assert public_admit(store, report, now=100)
    state = store.state(report.endpoint)
    identity = relay_proof_identity(report)

    assert state.active == HEALTHY_ACTIVE_CAP
    assert release_admission_for_relay_candidate(state, identity)
    assert state.active == 0
    assert set(state.attempt_starts) == {report.attempt_id}
    assert has_endpoint_attempt(state, identity)
    assert not release_admission_for_relay_candidate(
        state,
        relay_proof_identity(unrelated))
    assert report_relay_success(store, unrelated, now=150) == MISSING_ADMISSION
    assert report_relay_success(store, report, now=200) == INSERTED
    assert not state.attempt_starts
    assert set(state.relay_proofs) == {identity}


def test_canonical_endpoint_abc_lifecycle():
    a = make_relay_report(runtime_id=2, attempt_id=168, started_at=100)
    b = make_relay_report(runtime_id=5, attempt_id=169, started_at=110)
    c = make_relay_report(runtime_id=3, attempt_id=170, started_at=120)

    serialized = CanonicalEndpointStore()
    assert public_admit(serialized, a, now=90)
    assert not public_admit(serialized, b, now=90)
    assert serialized.state(ABC_ENDPOINT).active == HEALTHY_ACTIVE_CAP

    store = CanonicalEndpointStore()
    for report in (a, b, c):
        seed_admission(store, report)
    state = store.state(ABC_ENDPOINT)
    assert state.active == 3

    assert report_relay_success(store, a, now=1000) == INSERTED
    assert report_relay_success(store, b, now=1100) == INSERTED
    assert report_relay_success(store, c, now=1200) == INSERTED
    identities = {
        relay_proof_identity(a),
        relay_proof_identity(b),
        relay_proof_identity(c),
    }
    assert set(state.relay_proofs) == identities
    assert state.active == 0
    assert state.proxy_epoch == 4
    assert state.success_epoch == 3
    assert state.relay_proven
    assert state.healthy
    assert state.last_relay_success_at == 1200
    protected = punishment_signature(state)

    assert report_relay_stall(store, a, now=1300) == RETIRED_WITH_SURVIVORS
    assert set(state.relay_proofs) == {
        relay_proof_identity(b),
        relay_proof_identity(c),
    }
    assert state.relay_proven
    assert state.healthy
    assert state.last_relay_success_at == 1200
    assert punishment_signature(state) == protected

    after_first_terminal = deepcopy(state)
    assert report_relay_stall(store, a, now=1400) == MISSING_OR_DUPLICATE
    assert state == after_first_terminal


def test_unowned_current_epoch_success_is_rejected():
    store = CanonicalEndpointStore()
    state = store.state(ABC_ENDPOINT)
    state.generations[2] = 36
    report = make_relay_report(
        attempt_id=999,
        proxy_epoch=state.proxy_epoch,
        success_epoch=state.success_epoch,
        started_at=500)
    before = deepcopy(state)

    assert not success_from_stale_attempt(report, state)
    assert report_relay_success(store, report, now=1000) == MISSING_ADMISSION
    assert state == before


def test_same_tuple_is_namespaced_by_canonical_endpoint():
    first = make_relay_report(endpoint="first.example:443")
    second = replace(first, endpoint="second.example:443")
    store = CanonicalEndpointStore()
    seed_admission(store, first)
    seed_admission(store, second)

    assert report_relay_success(store, first, now=1000) == INSERTED
    assert store.state(first.endpoint).relay_proven
    assert not store.state(second.endpoint).relay_proven
    assert report_relay_success(store, second, now=1100) == INSERTED
    assert set(store.state(first.endpoint).relay_proofs) == {
        relay_proof_identity(first),
    }
    assert set(store.state(second.endpoint).relay_proofs) == {
        relay_proof_identity(second),
    }


def test_duplicate_success_has_no_growth_or_refresh():
    report = make_relay_report()
    store = CanonicalEndpointStore()
    seed_admission(store, report)
    assert report_relay_success(store, report, now=1000) == INSERTED
    state = store.state(report.endpoint)
    before = deepcopy(state)

    assert report_relay_success(store, report, now=2000) == ALREADY_PROVEN
    assert state == before
    assert len(state.relay_proofs) == 1
    assert state.relay_proofs[relay_proof_identity(report)] == RelayProofState(
        proven_at=1000)


def test_sibling_preserving_ordinary_failure():
    a = make_relay_report(runtime_id=2, attempt_id=168, started_at=100)
    b = make_relay_report(runtime_id=5, attempt_id=169, started_at=110)
    store = CanonicalEndpointStore()
    for report in (a, b):
        seed_admission(store, report)
    assert report_relay_success(store, a, now=1000) == INSERTED
    assert report_relay_success(store, b, now=1100) == INSERTED
    state = store.state(ABC_ENDPOINT)
    protected = punishment_signature(state)

    assert report_failure(store, a, HMAC_MISMATCH, now=1200) == (
        RETIRED_WITH_SURVIVORS)
    assert set(state.relay_proofs) == {relay_proof_identity(b)}
    assert state.relay_proven
    assert state.healthy
    assert state.last_relay_success_at == 1100
    assert punishment_signature(state) == protected


def test_healthy_remote_close_retires_exact_proof_once():
    a = make_relay_report(runtime_id=2, attempt_id=168, started_at=100)
    b = make_relay_report(runtime_id=5, attempt_id=169, started_at=110)
    store = CanonicalEndpointStore()
    for report in (a, b):
        seed_admission(store, report)
    assert report_relay_success(store, a, now=1000) == INSERTED
    assert report_relay_success(store, b, now=1100) == INSERTED
    state = store.state(ABC_ENDPOINT)
    protected = punishment_signature(state)

    assert healthy_remote_close(store, a, now=1200) == (
        RETIRED_WITH_SURVIVORS)
    assert set(state.relay_proofs) == {relay_proof_identity(b)}
    assert state.relay_proven
    assert state.healthy
    assert state.last_relay_success_at == 1100
    assert punishment_signature(state) == protected

    after_close = deepcopy(state)
    assert neutral_retire(
        store,
        a,
        now=1300,
        origin="cancel") == MISSING_OR_DUPLICATE
    assert state == after_close


def test_final_proof_real_failure_keeps_existing_punishment():
    report = make_relay_report()
    store = CanonicalEndpointStore()
    seed_admission(store, report)
    assert report_relay_success(store, report, now=1000) == INSERTED
    state = store.state(report.endpoint)
    route_failures = state.route_failure_count
    cooldowns = state.cooldown_count
    rotations = state.rotation_count
    capability_failures = state.relay_capability_failure_count

    assert report_failure(store, report, NO_MTPROTO, now=1200) == RETIRED_FINAL
    assert not state.relay_proofs
    assert not state.relay_proven
    assert not state.last_relay_success_at
    assert not state.healthy
    assert state.route_state == "bad"
    assert state.route_failure_count == route_failures + 1
    assert state.cooldown_count == cooldowns + 1
    assert state.cooldown_until == 16200
    assert state.rotation_count == rotations + 1
    assert state.relay_capability_failure_count == capability_failures + 1
    assert not state.capability_relay_proven


def test_final_stall_only_invalidates_relay_capability():
    report = make_relay_report()
    store = CanonicalEndpointStore()
    seed_admission(store, report)
    assert report_relay_success(store, report, now=1000) == INSERTED
    state = store.state(report.endpoint)
    route_state = state.route_state
    route_failures = state.route_failure_count
    cooldowns = state.cooldown_count
    rotations = state.rotation_count
    capability_failures = state.relay_capability_failure_count

    assert report_relay_stall(store, report, now=1200) == RETIRED_FINAL
    assert not state.relay_proven
    assert not state.last_relay_success_at
    assert state.healthy
    assert state.route_state == route_state
    assert state.route_failure_count == route_failures
    assert state.cooldown_count == cooldowns
    assert state.rotation_count == rotations
    assert state.relay_capability_failure_count == capability_failures + 1
    assert not state.capability_relay_proven


def test_normal_close_cancel_and_owner_destruction_are_neutral():
    for index, origin in enumerate((
            "normal_close",
            "cancel",
            "owner_destruction")):
        report = make_relay_report(
            endpoint=f"neutral-{index}.example:443",
            attempt_id=200 + index)
        store = CanonicalEndpointStore()
        seed_admission(store, report)
        assert report_relay_success(store, report, now=1000) == INSERTED
        state = store.state(report.endpoint)
        protected = punishment_signature(state)

        assert neutral_retire(
            store,
            report,
            now=1200,
            origin=origin) == RETIRED_FINAL
        assert not state.relay_proven
        assert not state.last_relay_success_at
        assert state.healthy
        assert state.capability_relay_proven
        assert punishment_signature(state) == protected


def test_cancellation_after_handled_failure_is_noop():
    report = make_relay_report()
    store = CanonicalEndpointStore()
    seed_admission(store, report)
    assert report_relay_success(store, report, now=1000) == INSERTED
    assert report_failure(store, report, NO_MTPROTO, now=1200) == RETIRED_FINAL
    state = store.state(report.endpoint)
    after_failure = deepcopy(state)

    assert neutral_retire(
        store,
        report,
        now=1300,
        origin="cancel") == MISSING_OR_DUPLICATE
    assert state == after_failure


def test_proxy_switch_generation_cleanup_is_runtime_scoped():
    a = make_relay_report(runtime_id=2, attempt_id=168)
    b = make_relay_report(runtime_id=5, attempt_id=169)
    store = CanonicalEndpointStore()
    for report in (a, b):
        seed_admission(store, report)
    assert report_relay_success(store, a, now=1000) == INSERTED
    assert report_relay_success(store, b, now=1100) == INSERTED
    state = store.state(ABC_ENDPOINT)
    protected = punishment_signature(state)

    apply_proxy_generation(store, runtime_id=2, proxy_generation=37, now=1200)
    assert state.generations[2] == 37
    assert set(state.relay_proofs) == {relay_proof_identity(b)}
    assert state.last_relay_success_at == 1100
    assert state.relay_proven
    assert state.healthy
    assert punishment_signature(state) == protected

    after_switch = deepcopy(state)
    assert report_failure(store, a, HMAC_MISMATCH, now=1300) == STALE_GENERATION
    assert state == after_switch


def test_runtime_unregister_cleanup_is_runtime_scoped():
    a = make_relay_report(runtime_id=2, attempt_id=168)
    b = make_relay_report(runtime_id=5, attempt_id=169)
    pending_a = make_relay_report(runtime_id=2, attempt_id=172, started_at=200)
    pending_b = make_relay_report(runtime_id=5, attempt_id=173, started_at=210)
    store = CanonicalEndpointStore()
    for report in (a, b):
        seed_admission(store, report)
    assert report_relay_success(store, a, now=1000) == INSERTED
    assert report_relay_success(store, b, now=1100) == INSERTED
    seed_admission(store, pending_a)
    seed_admission(store, pending_b)
    state = store.state(ABC_ENDPOINT)

    unregister_runtime(store, runtime_id=2)
    assert 2 not in state.generations
    assert state.generations[5] == 36
    assert set(state.relay_proofs) == {relay_proof_identity(b)}
    assert set(state.attempt_starts) == {pending_b.attempt_id}
    assert state.active == 1
    assert state.relay_proven
    assert state.healthy
    assert state.last_relay_success_at == 1100


def test_inactive_candidates_are_removed_by_generation_and_runtime_cleanup():
    a = make_relay_report(runtime_id=2, attempt_id=172, started_at=100)
    b = make_relay_report(runtime_id=5, attempt_id=173, started_at=110)
    expired = make_relay_report(runtime_id=7, attempt_id=174, started_at=0)
    store = CanonicalEndpointStore()
    for report in (a, b, expired):
        seed_admission(store, report)
        assert release_admission_for_relay_candidate(
            store.state(report.endpoint),
            relay_proof_identity(report))
    state = store.state(ABC_ENDPOINT)
    assert state.active == 0
    assert set(state.attempt_starts) == {
        a.attempt_id,
        b.attempt_id,
        expired.attempt_id,
    }

    apply_proxy_generation(store, runtime_id=2, proxy_generation=37, now=200)
    assert set(state.attempt_starts) == {b.attempt_id, expired.attempt_id}
    assert state.active == 0
    unregister_runtime(store, runtime_id=5)
    assert set(state.attempt_starts) == {expired.attempt_id}
    prune_expired_endpoint_state(state, ATTEMPT_HARD_TTL + 1)
    assert not state.attempt_starts
    assert state.active == 0


def test_live_proof_survives_ten_minutes_and_state_touches():
    a = make_relay_report(runtime_id=2, attempt_id=168, started_at=100)
    b = make_relay_report(runtime_id=5, attempt_id=169, started_at=110)
    touch = make_relay_report(
        runtime_id=7,
        attempt_id=170,
        started_at=601200)
    store = CanonicalEndpointStore()
    for report in (a, b):
        seed_admission(store, report)
    assert report_relay_success(store, a, now=1000) == INSERTED
    assert report_relay_success(store, b, now=1100) == INSERTED
    state = store.state(ABC_ENDPOINT)
    identities = {relay_proof_identity(a), relay_proof_identity(b)}
    late = 601200

    snapshot = snapshot_endpoint_state(store, ABC_ENDPOINT, late)
    assert set(snapshot.relay_proofs) == identities
    assert public_admit(store, touch, now=late)
    prune_expired_endpoint_state(state, late + 1)
    assert set(state.relay_proofs) == identities
    assert state.last_relay_success_at == 1100
    assert report_failure(store, a, HMAC_MISMATCH, now=late + 2) == (
        RETIRED_WITH_SURVIVORS)
    assert set(state.relay_proofs) == {relay_proof_identity(b)}
    assert report_relay_stall(store, b, now=late + 3) == RETIRED_FINAL
    assert not state.relay_proofs
    assert not state.relay_proven
    assert state.healthy


def test_repeated_success_and_terminal_cycles_return_to_empty():
    store = CanonicalEndpointStore()
    count = 128
    for index in range(count):
        report = make_relay_report(
            runtime_id=7,
            attempt_id=1000 + index,
            started_at=100 + index)
        seed_admission(store, report)
        assert report_relay_success(store, report, now=1000 + index) == INSERTED
        assert report_relay_success(
            store,
            report,
            now=2000 + index) == ALREADY_PROVEN
        assert neutral_retire(
            store,
            report,
            now=3000 + index,
            origin="normal_close") == RETIRED_FINAL
        assert neutral_retire(
            store,
            report,
            now=4000 + index,
            origin="cancel") == MISSING_OR_DUPLICATE
        state = store.state(ABC_ENDPOINT)
        assert not state.attempt_starts
        assert not state.relay_proofs
        assert state.active == 0
        assert not state.relay_proven


def test_retained_old_generation_membership_cannot_override_rejection():
    report = make_relay_report()
    store = CanonicalEndpointStore()
    seed_admission(store, report)
    assert report_relay_success(store, report, now=1000) == INSERTED
    state = store.state(report.endpoint)
    state.generations[report.runtime_id] = 37
    assert relay_proof_identity(report) in state.relay_proofs
    assert failure_from_stale_attempt(report, state)
    assert success_from_stale_attempt(report, state)
    before = deepcopy(state)

    assert report_failure(store, report, HMAC_MISMATCH, now=1200) == (
        STALE_GENERATION)
    assert state == before


def test_generation_zero_is_stale_after_generation_36():
    store = CanonicalEndpointStore()
    state = store.state(ABC_ENDPOINT)
    state.generations[2] = 36
    report = make_relay_report(proxy_generation=0)
    before = deepcopy(state)

    assert report_relay_success(store, report, now=1000) == STALE_GENERATION
    assert state == before
    assert neutral_retire(store, report, now=1100) == STALE_GENERATION
    assert state == before


def test_faketls_appdata_does_not_prove_relay_or_bump_epoch():
    report = make_relay_report(proxy_generation=1)
    store = CanonicalEndpointStore()
    assert public_admit(store, report, now=100)
    assert faketls_appdata_success(store, report, now=200)
    state = store.state(report.endpoint)
    identity = relay_proof_identity(report)
    assert not state.relay_proven
    assert not state.relay_proofs
    assert state.proxy_epoch == 1
    assert state.success_epoch == 0
    assert not state.last_relay_success_at
    assert state.last_success_at == 200
    assert set(state.attempt_starts) == {report.attempt_id}
    assert has_endpoint_attempt(state, identity)
    assert state.active == HEALTHY_ACTIVE_CAP

    blocked = replace(report, attempt_id=169, started_at=210)
    assert not public_admit(store, blocked, now=250)
    assert set(state.attempt_starts) == {report.attempt_id}
    assert state.active == HEALTHY_ACTIVE_CAP

    assert report_relay_success(store, report, now=300) == INSERTED
    assert state.relay_proven
    assert set(state.relay_proofs) == {identity}
    assert not state.attempt_starts
    assert state.active == 0
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
    health = read_endpoint_health_sources()
    policy = read(ENDPOINT_HEALTH_POLICY_CPP)
    health_state = read(ENDPOINT_HEALTH_STATE_H)
    endpoint_context = read(PROXY_ENDPOINT_CONTEXT_CPP)
    session_adapter = read(SESSION_PROXY_ADAPTER_CPP)
    session_port = read(SESSION_PROXY_PORT_H)
    session_connection = read(SESSION_CONNECTION_CPP)
    instance = read(INSTANCE_CPP)
    capabilities_bridge = read(ENDPOINT_HEALTH_CAPABILITIES_CPP)
    tls_records = read(TLS_SOCKET_RECORDS_CPP)
    capabilities = read(CAPABILITIES_CPP)

    assert "ProxyControlPlane::Reduce(current, fact)" in control
    assert "NormalizeMtproxyTerminalReason" not in control
    assert "ApplySelectedStatusUpdate(" in control
    assert "IsOlderAttempt(current.attempt, update.attempt)" in control
    assert "IsProxyCheck(fact.status.attempt.use)" in control
    assert "ShadowedByFreshRelaySuccess(current, fact)" in control
    assert "FakeTlsAppData," in health_header
    assert ".scope = MtProxy::SuccessScope::FakeTlsAppData" in tls_records
    assert "ReportEpochIsStale(report.proxyEpoch, state)" in policy
    assert "ReportSuccessEpochIsStale(report.successEpoch, state)" in policy
    assert "report.runtimeId" in policy
    assert "SuccessFromStaleAttempt(report, state)" in health
    assert "uint64 proxyGeneration = 0;" in health_header
    assert "uint64 successEpoch = 0;" in health_header
    assert "struct RelayProofIdentity" in health_state
    assert "std::map<RelayProofIdentity, RelayProofState> relayProofs;" in (
        health_state)
    assert "RelayProofPromotionResult::Inserted" in health_state
    assert "RelayProofPromotionResult::AlreadyProven" in health_state
    assert "RelayProofPromotionResult::MissingAdmission" in health_state
    assert "RuntimeProxyGenerationIsStale" in health_state
    assert "HasEndpointAttempt" in health_state
    assert "HasRelayProof" in health_state
    assert "bool admissionActive = true;" in health_state
    assert "ActiveEndpointAdmissionCount" in health_state
    assert "SynchronizeEndpointAdmissionAggregate" in health_state
    assert "ReleaseAdmissionForRelayCandidate" in health_state
    assert "PromoteRelayProof" in health_state
    assert "RetireRelayProof" in health_state
    assert "RemoveRelayProofsForRuntime" in health_state
    assert "SynchronizeRelayProofAggregate" in health_state
    removed_proof_prune = "PruneExpired" + "RelayProofs"
    removed_expiry_field = "expires" + "At"
    removed_proof_ttl = "kRelayProof" + "HardTtl"
    removed_expiry_factory = "RelayProof" + "ExpiresAt"
    assert removed_proof_prune not in health_state
    assert removed_expiry_field not in health_state
    assert "state.relayProven = !state.relayProofs.empty();" in health_state
    assert "entry.second.provenAt > state.lastRelaySuccessAt" in health_state
    assert "state.healthy = true;" in health_state
    assert "constexpr auto kHealthyActiveCap = 1;" in policy
    assert removed_proof_ttl not in policy
    assert removed_expiry_factory not in policy
    assert removed_expiry_factory not in health
    removed_size_count = "state.attemptStarts." + "size()"
    assert removed_size_count not in health_state
    assert removed_size_count not in policy
    assert "uint64 successEpoch() const" in health_header
    assert "++state.proxyEpoch;" in health
    assert "++state.successEpoch;" in health
    assert "snapshot.relayProven" in check
    assert "ProxyCheckStatus::WaitingForConnectionSlot" in check
    assert "bool admissionInProgress = false;" in broker
    assert broker.index("state->admissionInProgress = true;") < (
        broker.index("_runtime->proxyServices().control().admit({"))
    assert "releaseAdmission(cancelled);" in broker
    assert "noteMtproxyRelayFailure(" in capabilities
    assert "card.relayProven = false;" in capabilities
    assert "relayProvenAt" in capabilities
    assert "FreshMtproxyRelayProof(" in capabilities
    assert "void EndpointHealth::noteRelayStall(" in health
    relay_stall = health.split("void EndpointHealth::noteRelayStall(", 1)[1]
    assert "RelayProofReport report" in relay_stall.split(")", 1)[0]
    assert "RetireRelayProofLocked(state, report, now)" in relay_stall
    assert "RelayProofRetirement::RetiredWithSurvivors" in relay_stall
    assert "NoteCapabilityMtproxyRelayFailure(" in relay_stall
    assert "noteMtproxyRelayFailure(" in capabilities_bridge
    assert "RemoveRelayProofsForRuntime(state, runtimeId);" in endpoint_context
    assert "releaseAdmissionForRelayCandidate(" in endpoint_context
    assert "virtual void releaseAdmissionForRelayCandidate() = 0;" in (
        session_port)
    assert session_connection.count(
        "mtproxyLease.releaseAdmissionForRelayCandidate();") == 2
    assert "retireMtproxyRelayProof(" in session_adapter
    assert "RelayProofReport(attempt)" in session_adapter

    remote_close = session_adapter.split(
        "void ProductionSessionProxyPort::reportConnectionError(", 1)[1].split(
            "void ProductionSessionProxyPort::reportReceiveTimeout(", 1)[0]
    healthy_close = remote_close.index(
        "if (snapshot.healthy && !snapshot.halfOpen && postTerminal) {")
    healthy_retirement = remote_close.index("retireMtproxyRelayProof(")
    healthy_liveness = remote_close.index("ReportProxyLiveness(")
    assert healthy_close < healthy_retirement < healthy_liveness

    retirement = health.split(
        "RelayProofRetirement RetireRelayProofLocked(", 1)[1].split(
            "RelayStallFailureReport", 1)[0]
    assert retirement.index("PruneExpiredEndpointState(state, now);") < (
        retirement.index("RuntimeProxyGenerationIsStale("))
    assert retirement.index("RuntimeProxyGenerationIsStale(") < (
        retirement.index("ApplyProxyGeneration("))
    assert retirement.index("ApplyProxyGeneration(") < (
        retirement.index("RetireRelayProof(state, identity)"))
    assert retirement.index("RetireRelayProof(state, identity)") < (
        retirement.index("state.relayProven"))

    success = health.split("void EndpointHealth::reportSuccess(", 1)[1].split(
        "void EndpointHealth::noteRelayStall(", 1)[0]
    assert success.index("PruneExpiredEndpointState(state, now);") < (
        success.index("RuntimeProxyGenerationIsStale("))
    assert success.index("RuntimeProxyGenerationIsStale(") < (
        success.index("ApplyProxyGeneration("))
    assert success.index("ApplyProxyGeneration(") < (
        success.index("SuccessFromStaleAttempt(report, state)"))
    assert success.index("SuccessFromStaleAttempt(report, state)") < (
        success.index("PromoteRelayProof("))
    assert success.index("PromoteRelayProof(") < (
        success.index("state.lastSuccessAt = now;"))

    failure = health.split("void EndpointHealth::reportFailure(", 1)[1].split(
        "void EndpointHealth::reportSuccess(", 1)[0]
    assert failure.index("PruneExpiredEndpointState(state, now);") < (
        failure.index("RuntimeProxyGenerationIsStale("))
    assert failure.index("RuntimeProxyGenerationIsStale(") < (
        failure.index("ApplyProxyGeneration("))
    assert failure.index("ApplyProxyGeneration(") < (
        failure.index("FailureFromStaleAttempt(report, state)"))
    assert failure.index("FailureFromStaleAttempt(report, state)") < (
        failure.index("RetireRelayProof(state, identity)"))
    assert failure.index("RetireRelayProof(state, identity)") < (
        failure.index("if (state.relayProven)"))
    assert failure.index("if (state.relayProven)") < (
        failure.index("state.endpoint = report.endpoint;"))

    stale_success = policy.split(
        "bool SuccessFromStaleAttempt(", 1)[1].split(
            "void PruneExpiredEndpointState", 1)[0]
    assert stale_success.index("RuntimeProxyGenerationIsStale(") < (
        stale_success.index("HasEndpointAttempt(state, identity)"))
    assert stale_success.index("HasEndpointAttempt(state, identity)") < (
        stale_success.index("ReportEpochIsStale(report.proxyEpoch, state)"))

    stale_failure = policy.split(
        "bool FailureFromStaleAttempt(", 1)[1].split(
            "bool SuccessFromStaleAttempt(", 1)[0]
    assert stale_failure.index("RuntimeProxyGenerationIsStale(") < (
        stale_failure.index("HasRelayProof(state, identity)"))
    assert stale_failure.index("HasRelayProof(state, identity)") < (
        stale_failure.index("ReportEpochIsStale(report.proxyEpoch, state)"))

    migration = instance.split("void Instance::Private::migrateProxy()", 1)[1]
    assert migration.index("++_proxyGeneration;") < (
        migration.index("applyMtproxyProxyGeneration("))
    assert migration.index("applyMtproxyProxyGeneration(") < (
        migration.index("_connectionStatus->setProxyStatus("))


def run_all_truth_tables():
    test_reducer_no_appdata_relay_success_sibling_failure()
    test_old_generation_and_probe_facts_are_shadowed()
    test_older_progress_fact_cannot_repaint_connected_status()
    test_selected_status_success_epoch_shadows_late_failures()
    test_keyless_release_preserves_exact_promotion_lineage()
    test_canonical_endpoint_abc_lifecycle()
    test_unowned_current_epoch_success_is_rejected()
    test_same_tuple_is_namespaced_by_canonical_endpoint()
    test_duplicate_success_has_no_growth_or_refresh()
    test_sibling_preserving_ordinary_failure()
    test_healthy_remote_close_retires_exact_proof_once()
    test_final_proof_real_failure_keeps_existing_punishment()
    test_final_stall_only_invalidates_relay_capability()
    test_normal_close_cancel_and_owner_destruction_are_neutral()
    test_cancellation_after_handled_failure_is_noop()
    test_proxy_switch_generation_cleanup_is_runtime_scoped()
    test_runtime_unregister_cleanup_is_runtime_scoped()
    test_inactive_candidates_are_removed_by_generation_and_runtime_cleanup()
    test_live_proof_survives_ten_minutes_and_state_touches()
    test_repeated_success_and_terminal_cycles_return_to_empty()
    test_retained_old_generation_membership_cannot_override_rejection()
    test_generation_zero_is_stale_after_generation_36()
    test_faketls_appdata_does_not_prove_relay_or_bump_epoch()
    test_probe_waiting_slot_and_relay_proven_gate()
    test_broker_claim_prevents_double_admit()
    test_broker_cancel_releases_admitted_lease_before_timer_fires()
    test_capability_cache_soft_warning_vs_degraded_relay_failure()
    test_capability_cache_relay_proof_ages_out()
    test_source_seams_match_truth_table_contract()
