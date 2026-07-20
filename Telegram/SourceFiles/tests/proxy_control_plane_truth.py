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
ENDPOINT_LIVE_POOL_H = PROXY_DIR / "endpoint_live_pool.h"
ENDPOINT_LIVE_POOL_CPP = PROXY_DIR / "endpoint_live_pool.cpp"
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
TERMINAL_ATTEMPT = "TerminalAttempt"
ATTEMPT_HARD_TTL = 120000
OPENING_PRESSURE_COOLDOWN = 15000
ABC_ENDPOINT = "151.247.209.166.sslip.io:45632"
TCP_TIMEOUT = "tcp_connect_timeout"
CONNECTED_NO_MTPROTO = "connected_no_mtproto_data"
DNS_FAILED = "dns_failed"
CANCELLED = "cancelled"
REMOTE_CLOSED = "remote_closed"
EMPTY = "empty"
RESERVED = "reserved"
OPENING = "opening"
LIVE = "live"
CLOSING = "closing"
SLOT_WAIT = "slot"
CAPACITY_WAIT = "capacity"
CLOSING_WAIT = "closing"
ORDINARY = "ordinary"
RECLAIMED_MAIN_RESUME = "reclaimed_main_resume"
MAIN = "main"
MEDIA = "media"
UPLOAD = "upload"
PROXY_CHECK = "proxy_check"
LIVE_SLOT_COUNT = 4
CAPACITY_PRESSURE_REASONS = {
    TCP_TIMEOUT,
    NO_SERVERHELLO,
    NO_APPDATA,
    NO_MTPROTO,
    CONNECTED_NO_MTPROTO,
}


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
    opening_pressure_reason: str = NONE
    opening_pressure_retry_until: int = 0
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


@dataclass(frozen=True, order=True)
class LiveSlotKey:
    endpoint: str
    index: int
    incarnation: int


@dataclass(frozen=True)
class LiveTicket:
    runtime_id: int
    ticket_id: int
    revision: int
    proxy_generation: int = 1
    purpose: str = ORDINARY


@dataclass
class LiveSlot:
    phase: str = EMPTY
    incarnation: int = 0
    ticket: LiveTicket | None = None
    attempt: RelayProofIdentity | None = None
    use: str = MAIN
    live_since: int = 0


@dataclass(frozen=True)
class CapacityProbe:
    key: LiveSlotKey
    attempt: RelayProofIdentity
    target: int
    baseline: tuple[LiveSlotKey, ...]


@dataclass
class LiveReclaim:
    key: LiveSlotKey
    incumbent: RelayProofIdentity
    successor: LiveTicket | None


@dataclass
class LivePool:
    slots: list[LiveSlot] = field(default_factory=lambda: [
        LiveSlot() for _ in range(LIVE_SLOT_COUNT)
    ])
    opening_ticket: LiveTicket | None = None
    opening_attempt: RelayProofIdentity | None = None
    probe: CapacityProbe | None = None
    reclaim: LiveReclaim | None = None
    proven_lower_bound: int = 0
    learned_limit: int | None = None
    last_incarnation: int = 0


def slot_key(endpoint, index, slot):
    return LiveSlotKey(endpoint, index, slot.incarnation)


def find_live_slot(pool, key):
    if (
        not key.endpoint
        or key.index < 0
        or key.index >= LIVE_SLOT_COUNT
    ):
        return None
    slot = pool.slots[key.index]
    return slot if slot.incarnation == key.incarnation else None


def nonempty_slot_count(pool):
    return sum(slot.phase != EMPTY for slot in pool.slots)


def complete_live_baseline(pool, endpoint):
    return tuple(sorted(
        slot_key(endpoint, index, slot)
        for index, slot in enumerate(pool.slots)
        if slot.phase == LIVE and slot.attempt is not None
    ))


def reset_learning_if_empty(pool):
    if any(slot.phase != EMPTY for slot in pool.slots):
        return
    pool.proven_lower_bound = 0
    pool.learned_limit = None
    pool.probe = None
    pool.reclaim = None


def pool_wait_reason(pool, endpoint, ticket):
    if pool.reclaim:
        return (
            CLOSING_WAIT
            if pool.reclaim.successor == ticket
            else SLOT_WAIT
        )
    if pool.opening_ticket or pool.opening_attempt:
        return SLOT_WAIT
    empty = next((
        index
        for index, slot in enumerate(pool.slots)
        if slot.phase == EMPTY
    ), None)
    if empty is None:
        return SLOT_WAIT
    occupied = nonempty_slot_count(pool)
    proven = max(0, min(pool.proven_lower_bound, LIVE_SLOT_COUNT))
    if occupied < proven or (not proven and not occupied):
        return NONE
    if pool.learned_limit is not None and occupied >= pool.learned_limit:
        return CAPACITY_WAIT
    if pool.probe or proven >= LIVE_SLOT_COUNT:
        return CAPACITY_WAIT
    baseline = complete_live_baseline(pool, endpoint)
    return (
        NONE
        if occupied == proven and len(baseline) == proven
        else CAPACITY_WAIT
    )


def reserve_live_slot(pool, endpoint, ticket):
    wait = pool_wait_reason(pool, endpoint, ticket)
    if wait != NONE:
        return None, wait
    index = next(
        index
        for index, slot in enumerate(pool.slots)
        if slot.phase == EMPTY
    )
    pool.last_incarnation += 1
    slot = pool.slots[index]
    slot.phase = RESERVED
    slot.incarnation = pool.last_incarnation
    slot.ticket = ticket
    slot.attempt = None
    slot.use = MAIN
    slot.live_since = 0
    pool.opening_ticket = ticket
    return slot_key(endpoint, index, slot), NONE


def commit_live_slot(pool, key, ticket, attempt, use=MAIN):
    slot = find_live_slot(pool, key)
    if (
        slot is None
        or slot.phase != RESERVED
        or slot.ticket != ticket
        or pool.opening_ticket != ticket
        or attempt.runtime_id != ticket.runtime_id
        or attempt.proxy_generation != ticket.proxy_generation
    ):
        return False
    occupied_before = nonempty_slot_count(pool) - 1
    baseline = complete_live_baseline(pool, key.endpoint)
    target = pool.proven_lower_bound + 1
    expansion = (
        pool.proven_lower_bound > 0
        and target <= LIVE_SLOT_COUNT
        and occupied_before == pool.proven_lower_bound
        and len(baseline) == pool.proven_lower_bound
        and pool.probe is None
        and (
            pool.learned_limit is None
            or target <= pool.learned_limit
        )
    )
    slot.phase = OPENING
    slot.ticket = None
    slot.attempt = attempt
    slot.use = use
    pool.opening_ticket = None
    pool.opening_attempt = attempt
    if expansion:
        pool.probe = CapacityProbe(key, attempt, target, baseline)
    return True


def mark_live_slot_relay_ready(pool, key, attempt, now):
    slot = find_live_slot(pool, key)
    if (
        slot is None
        or slot.phase != OPENING
        or slot.attempt != attempt
        or pool.opening_attempt != attempt
    ):
        return False
    probe_matches = (
        pool.probe is not None
        and pool.probe.key == key
        and pool.probe.attempt == attempt
    )
    stable_probe = (
        probe_matches
        and pool.probe.target == pool.proven_lower_bound + 1
        and pool.probe.baseline
        == complete_live_baseline(pool, key.endpoint)
    )
    bootstrap = (
        pool.proven_lower_bound == 0
        and not complete_live_baseline(pool, key.endpoint)
    )
    slot.phase = LIVE
    slot.live_since = now
    pool.opening_attempt = None
    if stable_probe:
        pool.proven_lower_bound = pool.probe.target
    elif bootstrap:
        pool.proven_lower_bound = 1
    if probe_matches:
        pool.probe = None
    return True


def mark_live_slot_capacity_terminal(
        pool,
        key,
        attempt,
        reason,
        final_endpoint_terminal):
    if not final_endpoint_terminal or reason not in CAPACITY_PRESSURE_REASONS:
        return False
    slot = find_live_slot(pool, key)
    if (
        slot is None
        or slot.phase != OPENING
        or slot.attempt != attempt
        or pool.opening_attempt != attempt
    ):
        return False
    probe_matches = (
        pool.probe is not None
        and pool.probe.key == key
        and pool.probe.attempt == attempt
    )
    stable_probe = (
        probe_matches
        and pool.probe.target == pool.proven_lower_bound + 1
        and len(pool.probe.baseline) == pool.proven_lower_bound
        and bool(pool.probe.baseline)
        and pool.probe.baseline
        == complete_live_baseline(pool, key.endpoint)
    )
    if stable_probe:
        pool.learned_limit = len(pool.probe.baseline)
    if probe_matches:
        pool.probe = None
    slot.phase = CLOSING
    return True


def begin_live_slot_close(
        pool,
        key,
        attempt,
        successor=None,
        resume_purpose=None):
    slot = find_live_slot(pool, key)
    if (
        slot is None
        or slot.phase not in {OPENING, LIVE}
        or slot.attempt != attempt
        or (resume_purpose is not None and pool.reclaim is not None)
        or (successor is not None and resume_purpose is None)
    ):
        return None
    slot.phase = CLOSING
    if (
        pool.probe is not None
        and pool.probe.key == key
        and pool.probe.attempt == attempt
    ):
        pool.probe = None
    if resume_purpose is not None:
        pool.reclaim = LiveReclaim(key, attempt, successor)
    return (key, attempt, resume_purpose)


def capacity_saturated(pool, endpoint):
    if all(slot.phase != EMPTY for slot in pool.slots):
        return True
    occupied = nonempty_slot_count(pool)
    proven = max(0, min(pool.proven_lower_bound, LIVE_SLOT_COUNT))
    if occupied < proven or (not proven and not occupied):
        return False
    if pool.learned_limit is not None and occupied >= pool.learned_limit:
        return True
    if proven >= LIVE_SLOT_COUNT:
        return True
    baseline = complete_live_baseline(pool, endpoint)
    return occupied != proven or len(baseline) != proven


def select_foreground_transfer_reclaim(
        pool,
        endpoint,
        successor,
        foreground_runtime_id):
    if pool.reclaim or any(slot.phase == CLOSING for slot in pool.slots):
        return None, CLOSING_WAIT
    if pool.opening_ticket or pool.opening_attempt:
        return None, SLOT_WAIT
    if not capacity_saturated(pool, endpoint):
        return None, SLOT_WAIT
    candidates = [
        (index, slot)
        for index, slot in enumerate(pool.slots)
        if slot.phase in {OPENING, LIVE} and slot.attempt is not None
    ]
    victim = next((
        item for item in candidates
        if item[1].use in {MEDIA, UPLOAD}
        and item[1].attempt.runtime_id != foreground_runtime_id
    ), None)
    if victim is None:
        victim = next((
            item for item in candidates
            if item[1].use == MAIN
            and item[1].attempt.runtime_id != foreground_runtime_id
        ), None)
    if victim is None:
        return None, CAPACITY_WAIT
    index, slot = victim
    purpose = (
        ORDINARY
        if slot.use in {MEDIA, UPLOAD}
        else RECLAIMED_MAIN_RESUME
    )
    return begin_live_slot_close(
        pool,
        slot_key(endpoint, index, slot),
        slot.attempt,
        successor,
        purpose), CLOSING_WAIT


def cancel_live_slot_successor(pool, ticket):
    if pool.reclaim is None or pool.reclaim.successor != ticket:
        return False
    pool.reclaim.successor = None
    return True


def release_live_slot(pool, key, attempt):
    slot = find_live_slot(pool, key)
    if (
        slot is None
        or slot.phase not in {OPENING, LIVE, CLOSING}
        or slot.attempt != attempt
    ):
        return False, None
    if pool.opening_attempt == attempt:
        pool.opening_attempt = None
    if (
        pool.probe is not None
        and pool.probe.key == key
        and pool.probe.attempt == attempt
    ):
        pool.probe = None
    successor = None
    if (
        pool.reclaim is not None
        and pool.reclaim.key == key
        and pool.reclaim.incumbent == attempt
    ):
        successor = pool.reclaim.successor
        pool.reclaim = None
    slot.phase = CLOSING
    slot.phase = EMPTY
    slot.ticket = None
    slot.attempt = None
    slot.use = MAIN
    slot.live_since = 0
    reset_learning_if_empty(pool)
    return True, successor


def close_slots_before_generation(
        pool,
        endpoint,
        runtime_id,
        proxy_generation,
        cancelled_tickets=()):
    if pool.opening_ticket in cancelled_tickets:
        slot = next(
            slot for slot in pool.slots
            if slot.phase == RESERVED and slot.ticket == pool.opening_ticket
        )
        slot.phase = EMPTY
        slot.ticket = None
        pool.opening_ticket = None
    if pool.reclaim and pool.reclaim.successor in cancelled_tickets:
        pool.reclaim.successor = None
    actions = []
    for index, slot in enumerate(pool.slots):
        if (
            slot.phase in {OPENING, LIVE}
            and slot.attempt is not None
            and slot.attempt.runtime_id == runtime_id
            and slot.attempt.proxy_generation < proxy_generation
        ):
            key = slot_key(endpoint, index, slot)
            slot.phase = CLOSING
            if pool.probe and pool.probe.key == key:
                pool.probe = None
            actions.append((key, slot.attempt, None))
    if (
        pool.reclaim
        and pool.reclaim.incumbent.runtime_id == runtime_id
        and pool.reclaim.incumbent.proxy_generation < proxy_generation
    ):
        pool.reclaim = None
    reset_learning_if_empty(pool)
    return actions


def close_runtime_live_slots(pool, endpoint, runtime_id):
    cancelled = tuple(
        slot.ticket
        for slot in pool.slots
        if slot.phase == RESERVED
        and slot.ticket is not None
        and slot.ticket.runtime_id == runtime_id
    )
    return close_slots_before_generation(
        pool,
        endpoint,
        runtime_id,
        2 ** 63,
        cancelled)


def select_background_main_rotation(
        pool,
        endpoint,
        successor,
        foreground_runtime_id,
        now,
        foreground_transfer_waiting=False,
        foreground_transfer_active=False):
    if (
        successor.runtime_id == foreground_runtime_id
        or foreground_transfer_waiting
        or foreground_transfer_active
        or pool.opening_ticket
        or pool.opening_attempt
        or pool.reclaim
        or any(slot.phase == CLOSING for slot in pool.slots)
    ):
        return None
    candidates = [
        (index, slot)
        for index, slot in enumerate(pool.slots)
        if slot.phase == LIVE
        and slot.attempt is not None
        and slot.use == MAIN
        and slot.attempt.runtime_id != foreground_runtime_id
        and slot.attempt.runtime_id != successor.runtime_id
        and slot.live_since + 60000 <= now
    ]
    if not candidates:
        return None
    index, slot = min(candidates, key=lambda item: item[1].live_since)
    return begin_live_slot_close(
        pool,
        slot_key(endpoint, index, slot),
        slot.attempt,
        resume_purpose=RECLAIMED_MAIN_RESUME)


def admission_priority(ticket, use, foreground, has_main_proof, age):
    if ticket.purpose == RECLAIMED_MAIN_RESUME:
        return 8
    if use == MAIN:
        return 0 if foreground else (3 if has_main_proof else 2)
    if foreground and use in {MEDIA, UPLOAD} and has_main_proof:
        return 1
    base = 4 if use == "maintenance" else 7
    return max(3, base - age // 15000)


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


def promote_relay_proof(state, identity, proof):
    if has_relay_proof(state, identity):
        return ALREADY_PROVEN
    if not has_endpoint_attempt(state, identity):
        return MISSING_ADMISSION
    state.relay_proofs[identity] = proof
    del state.attempt_starts[identity.attempt_id]
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
    identity = relay_proof_identity(report)
    owned_attempt = has_endpoint_attempt(state, identity)
    retired = retire_relay_proof_record(state, identity)
    if not owned_attempt and not retired:
        return MISSING_OR_DUPLICATE
    if owned_attempt:
        del state.attempt_starts[report.attempt_id]
        if reason == NO_SERVERHELLO:
            retry_until = now + OPENING_PRESSURE_COOLDOWN
            if retry_until > state.opening_pressure_retry_until:
                state.opening_pressure_reason = reason
                state.opening_pressure_retry_until = retry_until
    if state.relay_proven:
        return (
            RETIRED_WITH_SURVIVORS
            if retired
            else TERMINAL_ATTEMPT
        )
    punish_final_failure(state, reason, now)
    return RETIRED_FINAL if retired else TERMINAL_ATTEMPT


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


def live_ticket(
        ticket_id,
        runtime_id,
        proxy_generation=1,
        purpose=ORDINARY):
    return LiveTicket(
        runtime_id=runtime_id,
        ticket_id=ticket_id,
        revision=ticket_id + 100,
        proxy_generation=proxy_generation,
        purpose=purpose)


def live_attempt(ticket, attempt_id):
    return RelayProofIdentity(
        runtime_id=ticket.runtime_id,
        proxy_generation=ticket.proxy_generation,
        attempt_id=attempt_id)


def open_pool_attempt(
        pool,
        ticket,
        attempt_id,
        use=MAIN,
        endpoint=ABC_ENDPOINT):
    key, wait = reserve_live_slot(pool, endpoint, ticket)
    assert wait == NONE
    assert key is not None
    attempt = live_attempt(ticket, attempt_id)
    assert commit_live_slot(pool, key, ticket, attempt, use)
    return key, attempt


def add_live_pool_attempt(
        pool,
        ticket,
        attempt_id,
        use=MAIN,
        now=1000,
        endpoint=ABC_ENDPOINT):
    key, attempt = open_pool_attempt(
        pool,
        ticket,
        attempt_id,
        use,
        endpoint)
    assert mark_live_slot_relay_ready(pool, key, attempt, now)
    return key, attempt


def one_live_plus_probe():
    pool = LivePool()
    first = live_ticket(1, 10)
    first_key, first_attempt = add_live_pool_attempt(
        pool,
        first,
        101,
        now=100)
    second = live_ticket(2, 20)
    second_key, second_attempt = open_pool_attempt(
        pool,
        second,
        102)
    assert pool.probe == CapacityProbe(
        second_key,
        second_attempt,
        2,
        (first_key,))
    return pool, first_key, first_attempt, second_key, second_attempt


def test_live_pool_bootstrap_and_sequential_expansion():
    pool = LivePool()
    live = []
    for index in range(LIVE_SLOT_COUNT):
        ticket = live_ticket(index + 1, index + 10)
        key, attempt = open_pool_attempt(pool, ticket, index + 100)
        if index == 0:
            assert pool.probe is None
        else:
            assert pool.probe is not None
            assert pool.probe.target == index + 1
            assert pool.probe.baseline == tuple(key for key, _ in live)
        blocked = live_ticket(index + 20, index + 30)
        assert reserve_live_slot(pool, ABC_ENDPOINT, blocked) == (
            None,
            SLOT_WAIT)
        assert mark_live_slot_relay_ready(
            pool,
            key,
            attempt,
            1000 + index)
        assert pool.proven_lower_bound == index + 1
        assert pool.opening_attempt is None
        assert pool.probe is None
        live.append((key, attempt))

    assert len(pool.slots) == LIVE_SLOT_COUNT
    assert all(slot.phase == LIVE for slot in pool.slots)
    assert reserve_live_slot(
        pool,
        ABC_ENDPOINT,
        live_ticket(99, 99)) == (None, SLOT_WAIT)


def test_capacity_learning_accepts_only_exact_stable_frontier_evidence():
    for reason in sorted(CAPACITY_PRESSURE_REASONS):
        pool, _, _, key, attempt = one_live_plus_probe()
        assert mark_live_slot_capacity_terminal(
            pool,
            key,
            attempt,
            reason,
            True)
        assert pool.slots[key.index].phase == CLOSING
        assert pool.learned_limit == 1
        assert pool.opening_attempt == attempt

    pool, _, _, key, attempt = one_live_plus_probe()
    assert not mark_live_slot_capacity_terminal(
        pool,
        key,
        attempt,
        TCP_TIMEOUT,
        False)
    assert pool.learned_limit is None
    assert pool.slots[key.index].phase == OPENING

    for reason in (DNS_FAILED, CANCELLED, REMOTE_CLOSED, HMAC_MISMATCH):
        pool, _, _, key, attempt = one_live_plus_probe()
        assert not mark_live_slot_capacity_terminal(
            pool,
            key,
            attempt,
            reason,
            True)
        assert pool.learned_limit is None

    pool, _, _, key, attempt = one_live_plus_probe()
    stale_key = replace(key, incarnation=key.incarnation + 1)
    stale_attempt = replace(attempt, attempt_id=attempt.attempt_id + 1)
    assert not mark_live_slot_capacity_terminal(
        pool,
        stale_key,
        attempt,
        TCP_TIMEOUT,
        True)
    assert not mark_live_slot_capacity_terminal(
        pool,
        key,
        stale_attempt,
        TCP_TIMEOUT,
        True)
    assert pool.learned_limit is None

    pool, baseline_key, baseline_attempt, key, attempt = one_live_plus_probe()
    assert begin_live_slot_close(pool, baseline_key, baseline_attempt)
    assert mark_live_slot_capacity_terminal(
        pool,
        key,
        attempt,
        TCP_TIMEOUT,
        True)
    assert pool.learned_limit is None

    pool = LivePool()
    key, attempt = open_pool_attempt(pool, live_ticket(1, 1), 1)
    assert pool.probe is None
    assert mark_live_slot_capacity_terminal(
        pool,
        key,
        attempt,
        TCP_TIMEOUT,
        True)
    assert pool.learned_limit is None
    assert not mark_live_slot_capacity_terminal(
        pool,
        key,
        attempt,
        TCP_TIMEOUT,
        True)

    pool, _, _, key, attempt = one_live_plus_probe()
    pool.probe = None
    assert mark_live_slot_capacity_terminal(
        pool,
        key,
        attempt,
        TCP_TIMEOUT,
        True)
    assert pool.learned_limit is None

    pool, _, _, key, attempt = one_live_plus_probe()
    cleanup = close_slots_before_generation(
        pool,
        ABC_ENDPOINT,
        attempt.runtime_id,
        attempt.proxy_generation + 1)
    assert cleanup == [(key, attempt, None)]
    assert not mark_live_slot_capacity_terminal(
        pool,
        key,
        attempt,
        TCP_TIMEOUT,
        True)
    assert pool.learned_limit is None


def test_learned_cap_and_reclaim_are_serialized_until_exact_release():
    pool, _, _, probe_key, probe_attempt = one_live_plus_probe()
    assert mark_live_slot_capacity_terminal(
        pool,
        probe_key,
        probe_attempt,
        TCP_TIMEOUT,
        True)
    assert release_live_slot(pool, probe_key, probe_attempt) == (True, None)
    assert pool.learned_limit == 1
    successor = live_ticket(3, 30)
    assert reserve_live_slot(pool, ABC_ENDPOINT, successor) == (
        None,
        CAPACITY_WAIT)

    incumbent_key = next(
        slot_key(ABC_ENDPOINT, index, slot)
        for index, slot in enumerate(pool.slots)
        if slot.phase == LIVE)
    incumbent = pool.slots[incumbent_key.index].attempt
    action, wait = select_foreground_transfer_reclaim(
        pool,
        ABC_ENDPOINT,
        successor,
        foreground_runtime_id=successor.runtime_id)
    assert wait == CLOSING_WAIT
    assert action == (
        incumbent_key,
        incumbent,
        RECLAIMED_MAIN_RESUME)
    assert pool.reclaim == LiveReclaim(
        incumbent_key,
        incumbent,
        successor)
    assert reserve_live_slot(pool, ABC_ENDPOINT, successor) == (
        None,
        CLOSING_WAIT)
    second_action, second_wait = select_foreground_transfer_reclaim(
        pool,
        ABC_ENDPOINT,
        live_ticket(4, 30),
        foreground_runtime_id=30)
    assert second_action is None
    assert second_wait == CLOSING_WAIT
    assert cancel_live_slot_successor(pool, successor)
    assert pool.reclaim.successor is None
    assert pool.slots[incumbent_key.index].phase == CLOSING
    assert release_live_slot(pool, incumbent_key, incumbent) == (True, None)
    assert pool.proven_lower_bound == 0
    assert pool.learned_limit is None
    old_incarnation = incumbent_key.incarnation
    new_key, _ = reserve_live_slot(pool, ABC_ENDPOINT, live_ticket(5, 50))
    assert new_key.incarnation > old_incarnation

    pinned_pool, _, _, probe_key, probe_attempt = one_live_plus_probe()
    assert mark_live_slot_capacity_terminal(
        pinned_pool,
        probe_key,
        probe_attempt,
        TCP_TIMEOUT,
        True)
    assert release_live_slot(
        pinned_pool,
        probe_key,
        probe_attempt) == (True, None)
    incumbent_key = next(
        slot_key(ABC_ENDPOINT, index, slot)
        for index, slot in enumerate(pinned_pool.slots)
        if slot.phase == LIVE)
    incumbent = pinned_pool.slots[incumbent_key.index].attempt
    successor = live_ticket(6, 60)
    action, _ = select_foreground_transfer_reclaim(
        pinned_pool,
        ABC_ENDPOINT,
        successor,
        foreground_runtime_id=60)
    assert action is not None
    assert release_live_slot(
        pinned_pool,
        incumbent_key,
        incumbent) == (True, successor)


def test_reclaim_victim_order_and_foreground_main_protection():
    pool = LivePool()
    main_key, main_attempt = add_live_pool_attempt(
        pool,
        live_ticket(1, 10),
        101,
        MAIN)
    transfer_key, transfer_attempt = add_live_pool_attempt(
        pool,
        live_ticket(2, 20),
        102,
        MEDIA)
    pool.learned_limit = 2
    successor = live_ticket(3, 30)
    action, wait = select_foreground_transfer_reclaim(
        pool,
        ABC_ENDPOINT,
        successor,
        foreground_runtime_id=30)
    assert wait == CLOSING_WAIT
    assert action == (transfer_key, transfer_attempt, ORDINARY)
    assert pool.slots[main_key.index].phase == LIVE

    protected = LivePool()
    key, attempt = add_live_pool_attempt(
        protected,
        live_ticket(4, 40),
        104,
        MAIN)
    protected.learned_limit = 1
    action, wait = select_foreground_transfer_reclaim(
        protected,
        ABC_ENDPOINT,
        live_ticket(5, 40),
        foreground_runtime_id=40)
    assert action is None
    assert wait == CAPACITY_WAIT
    assert protected.slots[key.index].phase == LIVE
    assert protected.slots[key.index].attempt == attempt


def test_cleanup_is_no_resume_closing_and_late_events_are_incarnation_safe():
    pool = LivePool()
    old_key, old_attempt = add_live_pool_attempt(
        pool,
        live_ticket(1, 10, proxy_generation=1),
        101,
        now=100)
    survivor_key, survivor_attempt = add_live_pool_attempt(
        pool,
        live_ticket(2, 20, proxy_generation=1),
        102,
        now=200)
    pool.learned_limit = 2
    last_incarnation = pool.last_incarnation
    actions = close_slots_before_generation(
        pool,
        ABC_ENDPOINT,
        runtime_id=10,
        proxy_generation=2)
    assert actions == [(old_key, old_attempt, None)]
    assert pool.slots[old_key.index].phase == CLOSING
    assert pool.slots[survivor_key.index].phase == LIVE
    assert pool.proven_lower_bound == 2
    assert pool.learned_limit == 2
    assert not mark_live_slot_relay_ready(pool, old_key, old_attempt, 300)
    assert not mark_live_slot_capacity_terminal(
        pool,
        old_key,
        old_attempt,
        TCP_TIMEOUT,
        True)
    assert release_live_slot(
        pool,
        replace(old_key, incarnation=old_key.incarnation + 1),
        old_attempt) == (False, None)
    assert release_live_slot(
        pool,
        old_key,
        replace(old_attempt, attempt_id=999)) == (False, None)
    assert release_live_slot(pool, old_key, old_attempt) == (True, None)
    assert pool.proven_lower_bound == 2
    assert pool.learned_limit == 2
    assert pool.last_incarnation == last_incarnation

    runtime_actions = close_runtime_live_slots(
        pool,
        ABC_ENDPOINT,
        survivor_attempt.runtime_id)
    assert runtime_actions == [(survivor_key, survivor_attempt, None)]
    assert pool.slots[survivor_key.index].phase == CLOSING
    assert release_live_slot(
        pool,
        survivor_key,
        survivor_attempt) == (True, None)
    assert pool.proven_lower_bound == 0
    assert pool.learned_limit is None
    assert pool.last_incarnation == last_incarnation


def test_reclaimed_resume_stays_lowest_and_rotation_is_background_main_only():
    resumed = live_ticket(
        1,
        10,
        purpose=RECLAIMED_MAIN_RESUME)
    for age in (0, 15000, 60000, 600000):
        assert admission_priority(
            resumed,
            MAIN,
            foreground=True,
            has_main_proof=False,
            age=age) == 8
    ordinary = live_ticket(2, 20)
    assert admission_priority(
        ordinary,
        MAIN,
        foreground=False,
        has_main_proof=True,
        age=0) < 8

    pool = LivePool()
    oldest_key, oldest_attempt = add_live_pool_attempt(
        pool,
        live_ticket(3, 30),
        103,
        MAIN,
        now=10)
    newer_key, _ = add_live_pool_attempt(
        pool,
        live_ticket(4, 40),
        104,
        MAIN,
        now=100)
    successor = live_ticket(5, 50)
    action = select_background_main_rotation(
        pool,
        ABC_ENDPOINT,
        successor,
        foreground_runtime_id=99,
        now=60100)
    assert action == (
        oldest_key,
        oldest_attempt,
        RECLAIMED_MAIN_RESUME)
    assert pool.slots[newer_key.index].phase == LIVE

    blocked = LivePool()
    add_live_pool_attempt(
        blocked,
        live_ticket(6, 60),
        106,
        MAIN,
        now=0)
    assert select_background_main_rotation(
        blocked,
        ABC_ENDPOINT,
        live_ticket(7, 70),
        foreground_runtime_id=99,
        now=60000,
        foreground_transfer_waiting=True) is None

    transfer_only = LivePool()
    add_live_pool_attempt(
        transfer_only,
        live_ticket(8, 80),
        108,
        MEDIA,
        now=0)
    assert select_background_main_rotation(
        transfer_only,
        ABC_ENDPOINT,
        live_ticket(9, 90),
        foreground_runtime_id=99,
        now=60000) is None


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


def test_health_promotion_preserves_exact_admission_lineage():
    report = make_relay_report()
    unrelated = replace(report, attempt_id=169)
    store = CanonicalEndpointStore()
    seed_admission(store, report)
    state = store.state(report.endpoint)
    identity = relay_proof_identity(report)

    assert set(state.attempt_starts) == {report.attempt_id}
    assert has_endpoint_attempt(state, identity)
    assert report_relay_success(store, unrelated, now=150) == MISSING_ADMISSION
    assert report_relay_success(store, report, now=200) == INSERTED
    assert not state.attempt_starts
    assert set(state.relay_proofs) == {identity}


def test_canonical_endpoint_abc_lifecycle():
    a = make_relay_report(runtime_id=2, attempt_id=168, started_at=100)
    b = make_relay_report(runtime_id=5, attempt_id=169, started_at=110)
    c = make_relay_report(runtime_id=3, attempt_id=170, started_at=120)

    serialized = CanonicalEndpointStore()
    seed_admission(serialized, a)
    serialized_state = serialized.state(ABC_ENDPOINT)
    pool = LivePool()
    a_ticket = live_ticket(
        1,
        a.runtime_id,
        proxy_generation=a.proxy_generation)
    a_key, a_attempt = open_pool_attempt(pool, a_ticket, a.attempt_id)
    assert reserve_live_slot(
        pool,
        ABC_ENDPOINT,
        live_ticket(2, b.runtime_id, b.proxy_generation)) == (
            None,
            SLOT_WAIT)
    assert report_failure(serialized, a, NO_SERVERHELLO, now=100) == (
        TERMINAL_ATTEMPT)
    assert serialized_state.opening_pressure_reason == NO_SERVERHELLO
    assert serialized_state.opening_pressure_retry_until == 15100
    assert mark_live_slot_capacity_terminal(
        pool,
        a_key,
        a_attempt,
        NO_SERVERHELLO,
        True)
    assert release_live_slot(pool, a_key, a_attempt) == (True, None)
    b_key, wait = reserve_live_slot(
        pool,
        ABC_ENDPOINT,
        live_ticket(2, b.runtime_id, b.proxy_generation))
    assert wait == NONE
    assert b_key is not None

    store = CanonicalEndpointStore()
    for report in (a, b, c):
        seed_admission(store, report)
    state = store.state(ABC_ENDPOINT)
    assert len(state.attempt_starts) == 3

    assert report_relay_success(store, a, now=1000) == INSERTED
    assert report_relay_success(store, b, now=1100) == INSERTED
    assert report_relay_success(store, c, now=1200) == INSERTED
    identities = {
        relay_proof_identity(a),
        relay_proof_identity(b),
        relay_proof_identity(c),
    }
    assert set(state.relay_proofs) == identities
    assert not state.attempt_starts
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
    assert len(state.attempt_starts) == 1
    assert state.relay_proven
    assert state.healthy
    assert state.last_relay_success_at == 1100


def test_unresolved_attempts_are_removed_by_generation_and_runtime_cleanup():
    a = make_relay_report(runtime_id=2, attempt_id=172, started_at=100)
    b = make_relay_report(runtime_id=5, attempt_id=173, started_at=110)
    expired = make_relay_report(runtime_id=7, attempt_id=174, started_at=0)
    store = CanonicalEndpointStore()
    for report in (a, b, expired):
        seed_admission(store, report)
    state = store.state(ABC_ENDPOINT)
    assert set(state.attempt_starts) == {
        a.attempt_id,
        b.attempt_id,
        expired.attempt_id,
    }

    apply_proxy_generation(store, runtime_id=2, proxy_generation=37, now=200)
    assert set(state.attempt_starts) == {b.attempt_id, expired.attempt_id}
    unregister_runtime(store, runtime_id=5)
    assert set(state.attempt_starts) == {expired.attempt_id}
    prune_expired_endpoint_state(state, ATTEMPT_HARD_TTL + 1)
    assert not state.attempt_starts


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
    seed_admission(store, touch)
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
    seed_admission(store, report)
    state = store.state(report.endpoint)
    identity = relay_proof_identity(report)
    pool = LivePool()
    ticket = live_ticket(
        1,
        report.runtime_id,
        proxy_generation=report.proxy_generation)
    key, attempt = open_pool_attempt(pool, ticket, report.attempt_id)
    assert faketls_appdata_success(store, report, now=200)
    assert not state.relay_proven
    assert not state.relay_proofs
    assert state.proxy_epoch == 1
    assert state.success_epoch == 0
    assert not state.last_relay_success_at
    assert state.last_success_at == 200
    assert set(state.attempt_starts) == {report.attempt_id}
    assert has_endpoint_attempt(state, identity)
    assert pool.slots[key.index].phase == OPENING
    assert pool.opening_attempt == attempt

    blocked = replace(report, attempt_id=169, started_at=210)
    blocked_ticket = live_ticket(
        2,
        blocked.runtime_id,
        proxy_generation=blocked.proxy_generation)
    assert reserve_live_slot(pool, ABC_ENDPOINT, blocked_ticket) == (
        None,
        SLOT_WAIT)
    assert set(state.attempt_starts) == {report.attempt_id}

    assert report_relay_success(store, report, now=300) == INSERTED
    assert mark_live_slot_relay_ready(pool, key, attempt, 300)
    seed_admission(store, blocked)
    blocked_key, wait = reserve_live_slot(
        pool,
        ABC_ENDPOINT,
        blocked_ticket)
    assert wait == NONE
    assert blocked_key is not None
    assert state.relay_proven
    assert set(state.relay_proofs) == {identity}
    assert set(state.attempt_starts) == {blocked.attempt_id}
    assert pool.opening_ticket == blocked_ticket
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
    arbiter_header = read(PROXY_DIR / "endpoint_admission_arbiter.h")
    arbiter = read(PROXY_DIR / "endpoint_admission_arbiter.cpp")
    live_pool_header = read(ENDPOINT_LIVE_POOL_H)
    live_pool = read(ENDPOINT_LIVE_POOL_CPP)
    check = read(CHECK_CPP)
    health_header = read(ENDPOINT_HEALTH_H)
    health = read_endpoint_health_sources()
    policy = read(ENDPOINT_HEALTH_POLICY_CPP)
    health_state = read(ENDPOINT_HEALTH_STATE_H)
    endpoint_context = read(PROXY_ENDPOINT_CONTEXT_CPP)
    session_adapter = read(SESSION_PROXY_ADAPTER_CPP)
    session_proxy_port = read(SESSION_PROXY_PORT_H)
    instance = read(INSTANCE_CPP)
    tls_records = read(TLS_SOCKET_RECORDS_CPP)
    capabilities = read(CAPABILITIES_CPP)

    assert "ProxyControlPlane::Reduce(current, fact)" in control
    assert "IsOlderAttempt(current.attempt, update.attempt)" in control
    assert "IsProxyCheck(fact.status.attempt.use)" in control
    assert "mtproxyEndpointView(" in control
    assert "view.mainProof.strength" in control
    assert "view.canonicalVerdict" in control
    assert "FakeTlsAppData," in health_header
    assert ".scope = MtProxy::SuccessScope::FakeTlsAppData" in tls_records
    assert "RuntimeGenerationIsCurrent(state, runtimeGeneration)" in policy
    assert "attempt->second.terminalVerdict.has_value()" in policy
    assert "SuccessFromStaleAttempt(report, state)" in health
    assert "FailureFromStaleAttempt(report, state)" in health
    assert "struct EndpointVerdict" in health_header
    assert "struct MainRelayProofView" in health_header
    assert "struct ProxyEndpointView" in health_header
    assert "struct RelayProofIdentity" in health_state
    assert "std::map<RelayProofIdentity, RelayProofState> relayProofs;" in health_state
    assert "std::map<RuntimeGenerationKey, EndpointVerdict> canonicalVerdicts;" in health_state
    assert "RecordCurrentTerminalEvidence" in health_state
    assert "CurrentMainRelayProof" in health_state
    assert "HasCurrentMainRelayProof" in health_state
    assert "RelayProofPromotionResult::Inserted" in health_state
    assert "RelayProofPromotionResult::AlreadyProven" in health_state
    assert "RelayProofPromotionResult::MissingAdmission" in health_state
    assert "state.relayProven = !state.relayProofs.empty();" in health_state
    assert "EndpointQueue" not in broker
    assert "endpointAdmissionArbiter().enqueue(" in broker
    assert "std::map<AdmissionTicketKey, std::unique_ptr<Ticket>> _tickets;" in arbiter
    assert "ProxySchedulerLifecycle::HandedOff" in arbiter
    assert "cancelBeforeGeneration(" in arbiter
    assert "inline constexpr auto kEndpointLiveSlotCount = 4;" in live_pool_header
    assert "struct EndpointLivePool" in live_pool_header
    assert "std::optional<EndpointOpeningOwner> opening;" in live_pool_header
    assert "std::optional<CapacityProbe> capacityProbe;" in live_pool_header
    assert "std::optional<EndpointReclaim> reclaim;" in live_pool_header
    assert "std::map<QString, MtProxy::EndpointLivePool> _pools;" in arbiter
    assert "std::map<MtProxy::LiveSlotKey, PhysicalSlotBinding> _slotBindings;" in (
        arbiter)
    assert "EndpointOpeningPermit" not in arbiter_header
    assert "_permits" not in arbiter
    for reason in ("None", "Slot", "Capacity", "Closing", "HealthOrNotBefore"):
        assert f"{reason}," in arbiter_header
    assert "MtProxy::CancelLiveSlotReservation(" in arbiter
    assert "MtProxy::CancelLiveSlotSuccessor(" in arbiter
    assert "MtProxy::CommitLiveSlotOpening(" in arbiter
    assert "MtProxy::MarkLiveSlotRelayReady(" in arbiter
    assert "MtProxy::MarkLiveSlotCapacityTerminal(" in arbiter
    assert "MtProxy::ReleaseLiveSlot(" in arbiter
    assert "OpeningRetryBoundaryFor(state)" not in arbiter
    assert "openingPressure" not in arbiter
    assert "slot->phase = LiveSlotPhase::Closing;" in live_pool
    assert "slot->phase = LiveSlotPhase::Empty;" in live_pool
    assert "AttemptOwnerMatches(*owner, request.attempt)" in live_pool
    assert "request.finalEndpointTerminal" in live_pool
    for reason in (
            "TcpConnectTimeout",
            "ClientHelloSentNoServerHello",
            "ServerHelloOkNoAppData",
            "ServerHelloOkNoMtprotoData",
            "ConnectedNoMtprotoData"):
        assert f"case FailureReason::{reason}:" in live_pool
    assert "struct EndpointOpeningPressure" in health_state
    assert "EndpointOpeningPressure openingPressure;" in health_state
    assert "return state.openingPressure;" in policy
    assert "ProxyCheckStatus::WaitingForConnectionSlot" in check
    assert "control.mtproxyEndpointView(endpoint)" in check
    assert "noteMtproxyRelayFailure(" in capabilities
    assert "card.relayProven = false;" in capabilities
    assert "relayProvenAt" in capabilities
    assert "void ProxyEndpointContext::transportReady(" not in endpoint_context
    assert "EndpointOpeningEvent" not in health
    assert "endpointAdmissionArbiter().openingEvent(" not in health
    assert "bindLiveSlot" not in broker
    assert "slotKey" not in broker
    assert "MtProxy::AdmissionPurpose purpose" in read(
        PROXY_DIR / "connection_broker.h")
    assert ".reclaim = std::move(request.reclaim)" in broker
    assert "void transportReady() override" in session_adapter
    assert "_lease.transportReady();" in session_adapter
    assert "void capacityTerminal(" in session_adapter
    assert "_lease.capacityTerminal(reason, finalEndpointTerminal);" in (
        session_adapter)
    assert "markTransportReady" not in session_adapter
    assert "virtual void transportReady() = 0;" in session_proxy_port
    assert "virtual MtProxy::LiveSlotKey slotKey() const = 0;" in (
        session_proxy_port)
    assert "std::optional<MtProxy::AdmissionPurpose>)> reclaim;" in (
        session_proxy_port)
    assert "AdmissionPurpose::ReclaimedMainResume" in arbiter
    priority = arbiter.split(
        "PriorityClass EndpointAdmissionArbiter::Private::priorityForLocked(",
        1)[1].split(
            "Ticket *EndpointAdmissionArbiter::Private::selectLocked(",
            1)[0]
    assert priority.index("AdmissionPurpose::ReclaimedMainResume") < (
        priority.index("const auto age ="))
    assert "retireMtproxyRelayProof(" in session_adapter
    assert "view.mainProof.strength" in session_adapter

    success = health.split("void EndpointHealth::reportSuccess(", 1)[1]
    assert success.index("SuccessFromStaleAttempt(report, state)") < (
        success.index("PromoteRelayProof("))
    assert "if (report.use == EndpointUse::Main)" in success
    assert "PruneEndpointOutcomesAfterSuccess(" in success

    failure = health.split("void EndpointHealth::reportFailure(", 1)[1].split(
        "void EndpointHealth::reportSuccess(", 1)[0]
    assert failure.index("RecordTerminalAttemptLocked(") < (
        failure.index("state.lastFailure = report.reason;"))
    pressure = failure.split(
        "if (terminal->finalAttemptTerminal", 1)[1].split(
            "const auto runtimeGeneration", 1)[0]
    assert "FailureReason::ClientHelloSentNoServerHello" in pressure
    assert "state.openingPressure = {" in pressure
    assert "report.use" in failure
    assert "EndpointUse::Main" in failure
    assert "!HasCurrentMainRelayProof(" in failure
    assert "SetCurrentCanonicalVerdict(" in failure

    migration = instance.split(
        "void Instance::Private::migrateProxy(bool manual)", 1)[1]
    assert migration.index("++_proxyGeneration;") < (
        migration.index("applyMtproxyProxyGeneration("))
    assert migration.index("applyMtproxyProxyGeneration(") < (
        migration.index("_connectionStatus->setProxyStatus("))

def run_all_truth_tables():
    test_live_pool_bootstrap_and_sequential_expansion()
    test_capacity_learning_accepts_only_exact_stable_frontier_evidence()
    test_learned_cap_and_reclaim_are_serialized_until_exact_release()
    test_reclaim_victim_order_and_foreground_main_protection()
    test_cleanup_is_no_resume_closing_and_late_events_are_incarnation_safe()
    test_reclaimed_resume_stays_lowest_and_rotation_is_background_main_only()
    test_reducer_no_appdata_relay_success_sibling_failure()
    test_old_generation_and_probe_facts_are_shadowed()
    test_older_progress_fact_cannot_repaint_connected_status()
    test_selected_status_success_epoch_shadows_late_failures()
    test_health_promotion_preserves_exact_admission_lineage()
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
    test_unresolved_attempts_are_removed_by_generation_and_runtime_cleanup()
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
