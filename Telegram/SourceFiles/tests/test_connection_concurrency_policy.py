from pathlib import Path


SOURCE_DIR = Path(__file__).resolve().parents[1]
ENDPOINT_HEALTH_H = (
    SOURCE_DIR / "mtproto" / "proxy" / "mtproxy" / "endpoint_health.h")
ENDPOINT_HEALTH_CPP = (
    SOURCE_DIR / "mtproto" / "proxy" / "mtproxy" / "endpoint_health.cpp")
ENDPOINT_HEALTH_POLICY_CPP = (
    SOURCE_DIR / "mtproto" / "proxy" / "mtproxy" / "endpoint_health_policy.cpp")
ENDPOINT_HEALTH_STATE_H = (
    SOURCE_DIR / "mtproto" / "proxy" / "mtproxy" / "endpoint_health_state.h")
CONNECTION_BROKER_H = SOURCE_DIR / "mtproto" / "proxy" / "connection_broker.h"
CONNECTION_BROKER_CPP = SOURCE_DIR / "mtproto" / "proxy" / "connection_broker.cpp"


def read(path):
    assert path.exists(), f"missing expected source file: {path}"
    return path.read_text(encoding="utf-8")


def body_after(text: str, signature: str) -> str:
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


def test_endpoint_health_has_named_concurrency_policy():
    header = read(ENDPOINT_HEALTH_H)
    policy = read(ENDPOINT_HEALTH_POLICY_CPP)
    state = read(ENDPOINT_HEALTH_STATE_H)

    assert "struct EndpointConcurrencyPolicy" in state
    assert "kColdActiveCap = 1" in policy
    assert "kUnknownActiveCap = kColdActiveCap" in policy
    assert "kDpiFailureActiveCap = 1" in policy
    assert "kHealthyActiveCap = 1" in policy
    assert "kFastHealthyActiveCap = 2" in policy
    assert "kHealthyHandshakeSpacing = crl::time(500)" in policy
    assert "bool useAllowed = true;" in state
    assert "nextHandshakeAt" in state
    assert "EndpointConcurrencyPolicyFor(" in policy
    assert "SkipCooldown" in header


def test_cold_endpoint_admits_only_main_scout_until_relay_proof():
    source = read(ENDPOINT_HEALTH_CPP)
    policy_source = read(ENDPOINT_HEALTH_POLICY_CPP)
    admit = body_after(source, "Admission EndpointHealth::admit(")
    policy = body_after(
        policy_source,
        "EndpointConcurrencyPolicy EndpointConcurrencyPolicyFor(")

    assert "EndpointUse use" in policy_source
    assert "crl::time now" in policy_source
    assert "const auto policy = EndpointConcurrencyPolicyFor(" in admit
    assert "request.use," in admit
    assert "!policy.useAllowed" in admit
    assert "auto denialAllowsRotation = true;" in admit
    assert "denialAllowsRotation = false;" in admit
    assert "if (!denialAllowsRotation) {" in admit
    assert "use != EndpointUse::Main" in policy
    assert "policy.useAllowed = false;" in policy
    assert "policy.activeCap = kUnknownActiveCap;" in policy
    assert "policy.activeCap = kDpiFailureActiveCap;" in policy


def test_relay_proof_keeps_handshakes_serialized():
    source = read(ENDPOINT_HEALTH_CPP)
    state_source = read(ENDPOINT_HEALTH_STATE_H)
    policy = body_after(
        read(ENDPOINT_HEALTH_POLICY_CPP),
        "EndpointConcurrencyPolicy EndpointConcurrencyPolicyFor(")
    success = body_after(source, "void EndpointHealth::reportSuccess(")
    promotion = body_after(
        state_source,
        "RelayProofPromotionResult PromoteRelayProof(")
    aggregate = body_after(
        state_source,
        "void SynchronizeRelayProofAggregate(")

    assert "const auto promotion = PromoteRelayProof(" in success
    assert "RelayProofPromotionResult::Inserted" in success
    assert "RelayProofPromotionResult::AlreadyProven" in success
    assert "RelayProofPromotionResult::MissingAdmission" in success
    assert "SynchronizeRelayProofAggregate(state);" in promotion
    assert "state.relayProven = !state.relayProofs.empty();" in aggregate
    assert "entry.second.provenAt > state.lastRelaySuccessAt" in aggregate
    assert "policy.activeCap = fastWarmup" in policy
    assert "? kFastHealthyActiveCap" in policy
    assert ": kHealthyActiveCap;" in policy
    assert "policy.handshakeSpacing = kHealthyHandshakeSpacing;" in policy
    assert "kFreshRelayActiveCap" not in policy
    assert "kStableRelayActiveCap" not in policy


def test_unknown_and_dpi_endpoints_queue_instead_of_skip_or_fail():
    source = read(ENDPOINT_HEALTH_CPP)
    admit = body_after(source, "Admission EndpointHealth::admit(")

    assert "const auto policy = EndpointConcurrencyPolicyFor(" in admit
    assert "state.active >= policy.activeCap" in admit
    assert "AdmissionAction::StartAfter" in admit
    assert "AdmissionAction::SkipCooldown" not in admit
    assert "result.retryAfter = policy.retryAfter;" in admit
    assert "result.retryAfter = state.nextHandshakeAt - now;" in admit
    assert "state.nextHandshakeAt = now + policy.handshakeSpacing;" in admit


def test_dpi_like_failures_keep_strict_cap_and_recipe_escalation():
    source = read(ENDPOINT_HEALTH_POLICY_CPP)
    policy = body_after(source, "EndpointConcurrencyPolicy EndpointConcurrencyPolicyFor(")
    traits = body_after(source, "FailureTraits TraitsFor(")

    for reason in (
        "ClientHelloSentNoServerHello",
        "TlsAlertAfterClientHello",
        "ServerHelloHmacMismatch",
    ):
        row = traits.split(
            f"case FailureReason::{reason}:", 1,
        )[1].split("case FailureReason::", 1)[0]
        assert ".escalatesRecipe = true" in row
    no_appdata_row = traits.split(
        "case FailureReason::ServerHelloOkNoAppData:", 1,
    )[1].split("case FailureReason::", 1)[0]
    assert ".escalatesRecipe = true" not in no_appdata_row
    assert "FailureNeedsRecipeEscalation(state.lastFailure)" in policy
    assert "kDpiFailureActiveCap" in policy
    assert "policy.recipeEscalationAllowed = true;" in policy


def test_tcp_route_failures_rotate_routes_without_canonical_cooldown():
    policy = read(ENDPOINT_HEALTH_POLICY_CPP)
    source = read(ENDPOINT_HEALTH_CPP)
    traits = body_after(policy, "FailureTraits TraitsFor(")
    failure = body_after(source, "void EndpointHealth::reportFailure(")

    for route_reason in ("TcpConnectTimeout", "TcpConnectedNoClientHelloWrite"):
        route_row = traits.split(
            f"case FailureReason::{route_reason}:", 1,
        )[1].split("case FailureReason::", 1)[0]
        assert ".routeOnly = true" in route_row
    assert (
        "NoteRouteFailure(storage, state, report.endpoint.route, report.reason);"
    ) in failure
    # Route-only failures skip canonical degradation while other routes
    # remain, but degrade the canonical once every route has been tried.
    assert ("if (FailureIsRouteOnly(report.reason)"
        " && !report.routesExhausted)") in failure
    route_only_tail = failure.split("if (FailureIsRouteOnly(report.reason)")[1]
    assert route_only_tail.index("return;") < route_only_tail.index(
        "state.lastFailure = report.reason;")


def test_fast_warmup_read_before_lock_and_only_for_healthy_row():
    source = read(ENDPOINT_HEALTH_CPP)
    policy_source = read(ENDPOINT_HEALTH_POLICY_CPP)
    admit = body_after(source, "Admission EndpointHealth::admit(")
    failure = body_after(source, "void EndpointHealth::reportFailure(")
    policy = body_after(
        policy_source,
        "EndpointConcurrencyPolicy EndpointConcurrencyPolicyFor(")

    # The getter reaches into application settings, so it must run before
    # the storage mutex is taken.
    for body in (admit, failure):
        assert body.index("FastWarmupEnabled(_runtime)") < body.index(
            "QMutexLocker lock(&storage.mutex);")
    # Only the proven-and-healthy row may run two concurrent handshakes;
    # cold, unproven and DPI-degraded rows keep the single careful probe.
    assert policy.count("kFastHealthyActiveCap") == 1
    assert "policy.activeCap = fastWarmup" in policy


def test_connection_broker_has_four_priority_queues():
    header = read(CONNECTION_BROKER_H)
    source = read(CONNECTION_BROKER_CPP)
    queue_for = body_after(source, "ConnectionBroker::EndpointQueue &ConnectionBroker::queueFor(")

    assert "std::unique_ptr<EndpointQueue> _uploadQueue;" in header
    assert "kQueuePriorityOrder" in source
    assert "MtProxy::EndpointUse::Main" in source
    assert "MtProxy::EndpointUse::ProxyCheck" in source
    assert "MtProxy::EndpointUse::Media" in source
    assert "MtProxy::EndpointUse::Upload" in source
    assert "return *_uploadQueue;" in queue_for
    assert "return *_mediaQueue;" in queue_for
    assert "case MtProxy::EndpointUse::Upload:" in queue_for


def test_connection_broker_drains_by_priority_not_request_queue_only():
    source = read(CONNECTION_BROKER_CPP)

    assert "void ConnectionBroker::drain()" in source
    assert "void ConnectionBroker::drain(MtProxy::EndpointUse use)" not in source
    assert "for (const auto use : kQueuePriorityOrder)" in source
    assert "drainQueue(use);" in source
    assert "void ConnectionBroker::drainQueue(MtProxy::EndpointUse use)" in source
    assert "drain();" in source
    assert "drain(request.use);" not in source
    assert "drainQueue(request.use);" not in source


if __name__ == "__main__":
    test_endpoint_health_has_named_concurrency_policy()
    test_cold_endpoint_admits_only_main_scout_until_relay_proof()
    test_relay_proof_keeps_handshakes_serialized()
    test_unknown_and_dpi_endpoints_queue_instead_of_skip_or_fail()
    test_dpi_like_failures_keep_strict_cap_and_recipe_escalation()
    test_tcp_route_failures_rotate_routes_without_canonical_cooldown()
    test_fast_warmup_read_before_lock_and_only_for_healthy_row()
    test_connection_broker_has_four_priority_queues()
    test_connection_broker_drains_by_priority_not_request_queue_only()
