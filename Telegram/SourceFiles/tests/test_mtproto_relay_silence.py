from pathlib import Path
from session_private_sources import read_session_private_sources


SOURCE_DIR = Path(__file__).resolve().parents[1]
MTPROXY_DIR = SOURCE_DIR / "mtproto" / "proxy" / "mtproxy"
ENDPOINT_IDENTITY_H = MTPROXY_DIR / "endpoint_identity.h"
ENDPOINT_IDENTITY_CPP = MTPROXY_DIR / "endpoint_identity.cpp"
RUNTIME_PROXY_ENDPOINT_H = (
    SOURCE_DIR / "mtproto" / "runtime" / "proxy_endpoint.h")
ENDPOINT_HEALTH_H = MTPROXY_DIR / "endpoint_health.h"
ENDPOINT_HEALTH_CPP = MTPROXY_DIR / "endpoint_health.cpp"
ENDPOINT_HEALTH_LIFECYCLE_CPP = MTPROXY_DIR / "endpoint_health_lifecycle.cpp"
ENDPOINT_HEALTH_POLICY_CPP = MTPROXY_DIR / "endpoint_health_policy.cpp"
ENDPOINT_HEALTH_STATE_H = MTPROXY_DIR / "endpoint_health_state.h"
TLS_SOCKET_CPP = MTPROXY_DIR / "tls_socket.cpp"
TLS_SOCKET_RECORDS_CPP = MTPROXY_DIR / "tls_socket_records.cpp"
STATUS_H = SOURCE_DIR / "mtproto" / "proxy" / "status.h"
STATUS_CPP = SOURCE_DIR / "mtproto" / "proxy" / "status.cpp"
LIVE_POOL_H = SOURCE_DIR / "mtproto" / "proxy" / "endpoint_live_pool.h"
LIVE_POOL_CPP = SOURCE_DIR / "mtproto" / "proxy" / "endpoint_live_pool.cpp"
DIAGNOSTICS_CPP = SOURCE_DIR / "mtproto" / "proxy" / "diagnostics.cpp"
PROXY_ADAPTER_CPP = SOURCE_DIR / "mtproto" / "proxy" / "session_proxy_adapter.cpp"
SESSION_CPP = SOURCE_DIR / "mtproto" / "session" / "private" / "session_private.cpp"
SESSION_H = SOURCE_DIR / "mtproto" / "session" / "private" / "session_private.h"
CONNECTION_CPP = SOURCE_DIR / "mtproto" / "session" / "private" / "connection.cpp"
RECEIVE_CPP = SOURCE_DIR / "mtproto" / "session" / "private" / "receive.cpp"
TRANSPORT_H = SOURCE_DIR / "mtproto" / "session" / "private" / "transport.h"


def read(path):
    assert path.exists(), f"missing expected source file: {path}"
    return path.read_text(encoding="utf-8")


def read_endpoint_health_sources():
    return "\n".join(read(path) for path in (
        ENDPOINT_HEALTH_CPP,
        ENDPOINT_HEALTH_LIFECYCLE_CPP,
    ))


def function_body(source, signature):
    start = source.index(signature)
    brace = source.index("{", start)
    depth = 0
    for i in range(brace, len(source)):
        if source[i] == "{":
            depth += 1
        elif source[i] == "}":
            depth -= 1
            if depth == 0:
                return source[brace:i + 1]
    raise AssertionError(f"function body not found: {signature}")


def test_relay_silence_reason_is_wired_through_all_mappings():
    endpoint_h = read(RUNTIME_PROXY_ENDPOINT_H)
    identity = read(ENDPOINT_IDENTITY_CPP)
    status_h = read(STATUS_H)
    status_cpp = read(STATUS_CPP)
    diagnostics = read(DIAGNOSTICS_CPP)

    assert "ConnectedNoMtprotoData," in endpoint_h
    assert "ConnectedNoMtprotoData," in status_h

    legacy = function_body(identity, "QString ToLegacyDiagnostic(")
    assert "connected_no_mtproto_data" in legacy

    terminal = function_body(
        identity, "ProxyMtproxyTerminalReason ToProxyMtproxyTerminalReason(")
    assert ("return ProxyMtproxyTerminalReason::ConnectedNoMtprotoData;"
        in terminal)

    reason_text = function_body(
        diagnostics, "QString MtproxyReasonText(")
    assert "connected_no_mtproto_data" in reason_text

    kind = function_body(
        status_cpp, "ProxyConnectionStatusKind ProxyConnectionStatusKindFor(")
    assert "case ProxyMtproxyTerminalReason::ConnectedNoMtprotoData:" in kind


def test_relay_silence_cools_down_without_recipe_or_tls_churn():
    policy = read(ENDPOINT_HEALTH_POLICY_CPP)
    traits = function_body(policy, "FailureTraits TraitsFor(")
    ladder = function_body(policy, "crl::time CooldownFor(")

    # No MTProto payload after a successful handshake means the handshake
    # fingerprint is fine - mutating it or rotating TLS profiles cannot
    # help, only a growing cooldown (and rotation to another proxy) can.
    row = traits.split(
        "case FailureReason::ConnectedNoMtprotoData:", 1,
    )[1].split("case FailureReason::", 1)[0]
    assert ".needsCooldown = true" in row
    assert ".escalatesRecipe = true" not in row
    assert ".rotatesTls = true" not in row
    assert ".routeOnly = true" not in row
    assert "FailureReason::ConnectedNoMtprotoData" in ladder
    assert "kSecondCooldown" in ladder.split(
        "FailureReason::ConnectedNoMtprotoData")[1].split("}")[0]


def test_failure_reports_collapse_echoes_within_active_cooldown():
    health = read(ENDPOINT_HEALTH_CPP)
    failure = function_body(health, "void EndpointHealth::reportFailure(")
    terminal = function_body(health, "RecordTerminalAttemptLocked(")

    assert "attempt->second.terminalVerdict" in terminal
    assert "return std::nullopt;" in terminal
    assert "attempt.terminalVerdict = verdict;" in terminal
    record = failure.index("RecordTerminalAttemptLocked(")
    rejected = failure.index("if (!terminal) {")
    assert record < rejected < failure.index("state.lastFailure = report.reason;")
    assert rejected < failure.index("++state.consecutiveFailures;")
    assert rejected < failure.index("++state.recipeLevel;")


def test_handshake_success_does_not_clear_relay_silence_cooldown():
    header = read(ENDPOINT_HEALTH_H)
    health = read(ENDPOINT_HEALTH_CPP)
    records = read(TLS_SOCKET_RECORDS_CPP)
    success = function_body(health, "void EndpointHealth::reportSuccess(")

    assert "enum class SuccessScope {" in header
    assert "SuccessScope scope = SuccessScope::Handshake;" in header

    skip = success.index("if (report.scope != SuccessScope::Relay) {")
    assert skip < success.index("state.lastFailure = FailureReason::None;")
    assert skip < success.index("state.terminalUntil = 0;")
    assert skip < success.index("state.consecutiveFailures = 0;")
    assert skip < success.index("state.recipeLevel = 0;")
    assert "NoteConnectSuccess(" not in success
    assert skip < success.index("PromoteRelayProof(")
    assert "endpointAdmissionArbiter().openingEvent(" not in success
    assert "RelayReady{" not in success
    assert "SuccessScope::FakeTlsAppData" in records
    assert "SuccessScope::Relay" not in function_body(
        records,
        "bool TlsSocket::checkNextPacket()")


def test_session_reports_silence_and_recovers_temporary_key():
    session = read_session_private_sources()
    connection = read(CONNECTION_CPP)
    header = read(TRANSPORT_H)
    wait_received = function_body(
        session, "void SessionTransport::waitReceivedFailed(")
    destroy_all = function_body(
        session, "void SessionTransport::destroyAllConnections(")
    connected = function_body(session, "void SessionTransport::onConnected(")
    append = function_body(
        session, "bool SessionTransport::appendTestConnection(")
    confirm = function_body(
        session,
        "void SessionTransport::confirmBestConnection()")

    assert "bool mtprotoDataReceived = false;" in header
    assert "int mtprotoSilentTimeouts = 0;" in header
    assert "_state.mtprotoDataReceived = false;" in destroy_all
    assert "canProveMtproxyRelay" not in session
    assert "&AbstractConnection::handshakeProgress" not in append
    assert "SessionTransport::onHandshakeProgress(" not in session
    assert (
        '#include "mtproto/transport/details/mtproto_abstract_socket.h"'
        in connection)
    assert "transportReady();" not in connected
    assert "reportMtproxyConnectionUsable" not in connected
    assert "transportReady();" not in confirm
    assert "reportMtproxyConnectionUsable" not in confirm
    assert "transportReady();" not in connection

    # A connection that connects (even passing the plaintext fake-pq
    # check) but never delivers an MTProto payload reports relay silence,
    # and repeated silence is treated like an explicit -404: the server
    # may drop packets of a discarded temporary key without answering.
    assert "kSilentTimeoutsToAssumeKeyDestroyed" in session
    adapter = read(PROXY_ADAPTER_CPP)
    report_timeout = function_body(
        adapter,
        "void ProductionSessionProxyPort::reportReceiveTimeout(")
    assert ("ProxyMtproxyTerminalReason::ServerHelloOkNoMtprotoData"
        in report_timeout)
    assert "MtProxy::FromProxyMtproxyTerminalReason(reason)" in report_timeout
    assert "FromProxyMtprotoTerminalReason" not in adapter
    assert ("ProxyMtproxyTerminalReason::ServerHelloOkNoMtprotoData"
        in report_timeout)
    assert "return _owner->destroyTemporaryKey();" in wait_received

    # Only a handled MTProto message resets the per-session silence counter.
    # Ordinary sessions do not feed endpoint health, because that would bring
    # the shared cooldown and admission policy back into the data plane.
    transport = read(
        SOURCE_DIR / "mtproto" / "session" / "private" / "transport.cpp")
    note_payload = function_body(
        transport,
        "void SessionTransport::noteMtprotoPayloadReceived()")
    assert "_state.mtprotoSilentTimeouts = 0;" in note_payload
    assert "_proxyPort" not in note_payload
    assert "markProxyMtprotoPayloadReceived();" in note_payload


def test_full_concurrency_uses_typed_transfer_admission():
    state_source = read(ENDPOINT_HEALTH_STATE_H)
    health = read(ENDPOINT_HEALTH_CPP)
    live_pool_header = read(LIVE_POOL_H)
    live_pool = read(LIVE_POOL_CPP)
    arbiter = read(SOURCE_DIR / "mtproto" / "proxy" /
        "endpoint_admission_arbiter.cpp")
    eligible = function_body(
        arbiter,
        "auto EndpointAdmissionArbiter::Private::transferAdmissionBasisLocked(")
    reserve = function_body(
        arbiter,
        "auto EndpointAdmissionArbiter::Private::reserveTicketLocked(")
    assign = function_body(
        arbiter,
        "void EndpointAdmissionArbiter::Private::assignReservationsLocked(")
    success = function_body(health, "void EndpointHealth::reportSuccess(")
    failure = function_body(health, "void EndpointHealth::reportFailure(")

    continuation = eligible.index("DemandTransferContinuationMatches(")
    proof = eligible.index("MtProxy::HasCurrentMainRelayProof(state")
    assert continuation < proof
    assert "DemandTransferContinuationStage::Released" in eligible
    assert "TransferAdmissionBasis::ReleasedContinuation" in eligible
    assert "TransferAdmissionBasis::MainRelayProof" in eligible
    assert "TransferAdmissionBasis::None" in eligible
    stages = live_pool_header.split(
        "enum class DemandTransferContinuationStage", 1)[1].split("};", 1)[0]
    assert stages.index("Requested") < stages.index("AwaitingRelease") < (
        stages.index("Released"))
    authorization = function_body(
        live_pool,
        "auto AuthorizeLiveSlotReclaim(")
    assert "EndpointReclaimStage::Requested" in authorization
    assert "EndpointReclaimStage::Authorized" in authorization
    assert "DemandTransferContinuationStage::AwaitingRelease" in authorization
    assert "request.attempt.runtimeId != request.foregroundRuntimeId" in (
        authorization)
    assert "slot->phase = LiveSlotPhase::Live;" in authorization
    assert "ticket.key.runtimeId" in eligible
    assert "ticket.proxyGeneration" in eligible
    assert "if (!IsTransfer(ticket.use))" in eligible
    assert "urgentWaiters" not in eligible
    assert "baseEligibleLocked" not in arbiter
    assert "mainRelayProven" not in arbiter
    assert "transferAdmissionBasisLocked(" in reserve
    assert "AdmissionBasisAllowsTicket(" in reserve
    assert ".transferAdmissionBasis = transferAdmissionBasis" in reserve
    assert "MtProxy::ReserveLiveSlot(" in reserve
    released = assign.split("auto releasedSuccessor", 1)[1].split(
        "auto eligible", 1)[0]
    assert "DemandTransferContinuationStage::Released" in released
    assert "ticketCurrentLocked(*ticket, state)" in released
    assert "boundary.at <= inputs.now" in released
    assert "MtProxy::CancelLiveSlotSuccessor(" in released
    assert "std::remove_if(" in released
    assert "DemandTransferContinuationMatches(" in released
    assert "const auto selected = foregroundOverride" in assign
    candidate = function_body(
        arbiter,
        "EndpointAdmissionArbiter::Private::mainReplacementCandidateLocked(")
    assert candidate.index("ForegroundRecovery") < candidate.index(
        "DemandBootstrap") < candidate.index("BackgroundDuty")
    assert "TransferAdmissionBasis::None" in candidate
    assert "CurrentMainRelayProof(" in state_source
    assert "proof.use != EndpointUse::Main" in state_source
    assert "SuccessFromStaleAttempt(report, state)" in success
    assert "PromoteRelayProof(" in success
    assert "if (report.use == EndpointUse::Main)" in success
    assert "PruneEndpointOutcomesAfterSuccess(" in success
    assert "HasCurrentMainRelayProof(" in failure
    assert "SetCurrentCanonicalVerdict(" in failure

def test_established_idle_close_is_not_a_health_failure():
    tls_socket = read(TLS_SOCKET_CPP)
    session = read_session_private_sources()
    adapter = read(PROXY_ADAPTER_CPP)
    handle_error = function_body(
        tls_socket, "void TlsSocket::handleError(int errorCode)")
    finish_terminal = function_body(
        tls_socket, "bool TlsSocket::finishTerminal(")
    disconnected = function_body(
        session,
        "void SessionTransport::onDisconnected(")
    destroy = function_body(
        session,
        "void SessionTransport::destroyAllConnections(")
    cancelled = function_body(
        adapter,
        "void ProductionSessionProxyPort::reportAttemptCancelled(")
    connection_error = function_body(
        adapter,
        "void ProductionSessionProxyPort::reportConnectionError(")
    on_error = function_body(
        session,
        "void SessionTransport::onError(")

    # Proxies close idle established connections routinely; only a close
    # shortly after the handshake may count against endpoint health.
    assert "kEstablishedIdleCloseAge" in tls_socket
    assert "benignIdleClose" in finish_terminal
    assert "_firstAppDataAt" in finish_terminal
    assert finish_terminal.index("benignIdleClose") < finish_terminal.index(
        "clearSyntheticPskOnFailure(reason)")
    assert "destroyAllConnections();" in disconnected
    assert "reportAttemptCancelled(" not in destroy
    assert "mtproxyLease" not in destroy
    assert "reportConnectionError(" not in on_error
    assert "removeTestConnection(connection);" in on_error
    assert "ReportConnectionFailure(attempt, reason, failure, lease);" in (
        connection_error)
    assert "openingPressure" not in cancelled
    assert "openingPressure" not in connection_error
    assert "retireMtproxyRelayProof(" in cancelled
    assert "RelayProofReport(attempt)" in cancelled
    assert cancelled.index("retireMtproxyRelayProof(") < cancelled.index(
        "ReportProxyAttemptSummary(")
    healthy = connection_error.index(
        "const auto postTerminal = !ClaimAttemptTerminal(attempt);")
    retirement = connection_error.index("retireMtproxyRelayProof(")
    liveness = connection_error.index("ReportProxyLiveness(")
    assert healthy < retirement < liveness
    assert "ignoreHealthyRemoteClosed" in connection_error
    assert "failure.livenessReported" in connection_error
    assert "RelayProofReport(attempt)" in connection_error


if __name__ == "__main__":
    test_relay_silence_reason_is_wired_through_all_mappings()
    test_relay_silence_cools_down_without_recipe_or_tls_churn()
    test_failure_reports_collapse_echoes_within_active_cooldown()
    test_handshake_success_does_not_clear_relay_silence_cooldown()
    test_session_reports_silence_and_recovers_temporary_key()
    test_full_concurrency_uses_typed_transfer_admission()
    test_established_idle_close_is_not_a_health_failure()
