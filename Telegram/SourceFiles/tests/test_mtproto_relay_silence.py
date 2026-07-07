from pathlib import Path
from session_private_sources import read_session_private_sources


SOURCE_DIR = Path(__file__).resolve().parents[1]
MTPROXY_DIR = SOURCE_DIR / "mtproto" / "proxy" / "mtproxy"
ENDPOINT_IDENTITY_H = MTPROXY_DIR / "endpoint_identity.h"
ENDPOINT_IDENTITY_CPP = MTPROXY_DIR / "endpoint_identity.cpp"
ENDPOINT_HEALTH_H = MTPROXY_DIR / "endpoint_health.h"
ENDPOINT_HEALTH_CPP = MTPROXY_DIR / "endpoint_health.cpp"
ENDPOINT_HEALTH_POLICY_CPP = MTPROXY_DIR / "endpoint_health_policy.cpp"
TLS_SOCKET_CPP = MTPROXY_DIR / "tls_socket.cpp"
STATUS_H = SOURCE_DIR / "mtproto" / "proxy" / "status.h"
STATUS_CPP = SOURCE_DIR / "mtproto" / "proxy" / "status.cpp"
DIAGNOSTICS_CPP = SOURCE_DIR / "mtproto" / "proxy" / "diagnostics.cpp"
SESSION_CPP = SOURCE_DIR / "mtproto" / "session" / "private" / "session_private.cpp"
SESSION_H = SOURCE_DIR / "mtproto" / "session" / "private" / "session_private.h"


def read(path):
    assert path.exists(), f"missing expected source file: {path}"
    return path.read_text(encoding="utf-8")


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
    identity_h = read(ENDPOINT_IDENTITY_H)
    identity = read(ENDPOINT_IDENTITY_CPP)
    status_h = read(STATUS_H)
    status_cpp = read(STATUS_CPP)
    diagnostics = read(DIAGNOSTICS_CPP)

    assert "ConnectedNoMtprotoData," in identity_h
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
    cooldown_body = function_body(policy, "bool FailureNeedsCooldown(")
    recipe_body = function_body(policy, "bool FailureNeedsRecipeEscalation(")
    rotation_body = function_body(policy, "bool FailureNeedsTlsRotation(")
    route_only_body = function_body(policy, "bool FailureIsRouteOnly(")
    ladder = function_body(policy, "crl::time CooldownFor(")

    # No MTProto payload after a successful handshake means the handshake
    # fingerprint is fine - mutating it or rotating TLS profiles cannot
    # help, only a growing cooldown (and rotation to another proxy) can.
    after_case = cooldown_body.split(
        "case FailureReason::ConnectedNoMtprotoData:")[1]
    assert after_case.split("return")[1].strip().startswith("true;")
    assert "return false;" in recipe_body.split(
        "case FailureReason::ConnectedNoMtprotoData:")[1]
    assert "return false;" in rotation_body.split(
        "case FailureReason::ConnectedNoMtprotoData:")[1]
    assert "return false;" in route_only_body.split(
        "case FailureReason::ConnectedNoMtprotoData:")[1]
    assert "FailureReason::ConnectedNoMtprotoData" in ladder
    assert "kSecondCooldown" in ladder.split(
        "FailureReason::ConnectedNoMtprotoData")[1].split("}")[0]


def test_failure_reports_collapse_echoes_within_active_cooldown():
    health = read(ENDPOINT_HEALTH_CPP)
    failure = function_body(health, "void EndpointHealth::reportFailure(")

    # Several sockets dying in one storm must produce one strike, not
    # ratchet consecutiveFailures and the stealth recipe once per socket
    # (observed: recipe level 1->4 within a second).
    guard = failure.index("if (state.terminalUntil > now) {")
    assert guard < failure.index("state.lastFailure = report.reason;")
    assert guard < failure.index("++state.consecutiveFailures;")
    assert guard < failure.index("++state.recipeLevel;")


def test_handshake_success_does_not_clear_relay_silence_cooldown():
    header = read(ENDPOINT_HEALTH_H)
    health = read(ENDPOINT_HEALTH_CPP)
    success = function_body(health, "void EndpointHealth::reportSuccess(")

    assert "enum class SuccessScope {" in header
    assert "SuccessScope scope = SuccessScope::Handshake;" in header

    # On a dead relay every reconnect handshakes fine; only an actually
    # received MTProto payload may repaint the endpoint green.
    assert "SuccessScope::Handshake" in success
    assert "FailureReason::ConnectedNoMtprotoData" in success
    skip = success.index("state.lastFailure == FailureReason::ConnectedNoMtprotoData")
    assert skip < success.index("state.lastFailure = FailureReason::None;")
    assert skip < success.index("state.terminalUntil = 0;")
    assert skip < success.index("state.consecutiveFailures = 0;")


def test_session_reports_silence_and_recovers_temporary_key():
    session = read_session_private_sources()
    header = read(SESSION_H)
    wait_received = function_body(
        session, "void SessionPrivate::waitReceivedFailed(")
    destroy_all = function_body(
        session, "void SessionPrivate::destroyAllConnections(")

    assert "bool mtprotoDataReceived = false;" in header
    assert "int mtprotoSilentTimeouts = 0;" in header
    assert "_connectionState.mtprotoDataReceived = false;" in destroy_all

    # A connection that connects (even passing the plaintext fake-pq
    # check) but never delivers an MTProto payload reports relay silence,
    # and repeated silence is treated like an explicit -404: the server
    # may drop packets of a discarded temporary key without answering.
    assert "kSilentTimeoutsToAssumeKeyDestroyed" in session
    assert ("MtProxy::FailureReason::ServerHelloOkNoMtprotoData"
        in wait_received)
    assert ("ProxyMtproxyTerminalReason::ServerHelloOkNoMtprotoData"
        in wait_received)
    assert "return destroyTemporaryKey();" in wait_received

    # Only a handled MTProto message counts as relay proof; it resets the
    # silence counter and reports relay-scope success.
    assert "SuccessScope::Relay" in session
    assert session.index("_timing.retryTimeout = 1;") < session.index(
        "SuccessScope::Relay")


def test_full_concurrency_needs_relay_proof_not_just_handshakes():
    health = read(ENDPOINT_HEALTH_CPP)
    header = read(ENDPOINT_HEALTH_H)
    policy_source = read(ENDPOINT_HEALTH_POLICY_CPP)
    session = read_session_private_sources()
    policy = function_body(
        policy_source, "EndpointConcurrencyPolicy EndpointConcurrencyPolicyFor(")
    success = function_body(health, "void EndpointHealth::reportSuccess(")
    failure = function_body(health, "void EndpointHealth::reportFailure(")
    stall = function_body(health, "void EndpointHealth::noteRelayStall(")
    wait_received = function_body(
        session, "void SessionPrivate::waitReceivedFailed(")

    assert "state.relayProven" in policy
    assert "!state.relayProven || !state.lastRelaySuccessAt" in policy
    assert "use != EndpointUse::Main" in policy
    assert "policy.useAllowed = false;" in policy
    assert "const auto relayAge = now - state.lastRelaySuccessAt;" in policy
    assert "kFreshRelayActiveCap" in policy
    assert "kWarmRelayActiveCap" in policy
    assert "kStableRelayActiveCap" in policy
    assert "state.relayProven = true;" in success
    assert success.index("SuccessScope::Relay") < success.index(
        "state.relayProven = true;")
    assert "state.relayProven = false;" in failure

    # A mid-session silence of an established connection clears the proof
    # without any cooldown - reconnects stay allowed, just as scouts.
    assert "struct RelayStallReport" in header
    assert "void noteRelayStall(RelayStallReport report)" in header
    assert "relayProven = false;" in stall
    assert "FailureFromStaleAttempt(staleReport, state)" in stall
    assert "terminalUntil" not in stall
    assert "ProxyControlPlane::NoteMtproxyRelayStall(" in wait_received
    assert ".proxyGeneration = _connectionState.mtproxyAttempt.proxyGeneration" in (
        wait_received)
    assert ".attemptId = _connectionState.mtproxyAttempt.attemptId" in wait_received
    assert ".proxyEpoch = _connectionState.mtproxyAttempt.proxyEpoch" in wait_received
    assert ".attemptStartedAt = _connectionState.mtproxyAttemptStartedAt" in (
        wait_received)


def test_established_idle_close_is_not_a_health_failure():
    tls_socket = read(TLS_SOCKET_CPP)
    handle_error = function_body(
        tls_socket, "void TlsSocket::handleError(int errorCode)")

    # Proxies close idle established connections routinely; only a close
    # shortly after the handshake may count against endpoint health.
    assert "kEstablishedIdleCloseAge" in tls_socket
    assert "benignIdleClose" in handle_error
    assert "_firstAppDataAt" in handle_error
    assert handle_error.index("benignIdleClose") < handle_error.index(
        "ReportMtproxyFailure({")
