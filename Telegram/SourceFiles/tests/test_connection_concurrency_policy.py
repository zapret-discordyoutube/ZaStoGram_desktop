from pathlib import Path


SOURCE_DIR = Path(__file__).resolve().parents[1]
ENDPOINT_HEALTH_H = (
    SOURCE_DIR / "mtproto" / "proxy" / "mtproxy" / "endpoint_health.h")
ENDPOINT_HEALTH_CPP = (
    SOURCE_DIR / "mtproto" / "proxy" / "mtproxy" / "endpoint_health.cpp")
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
    source = read(ENDPOINT_HEALTH_CPP)

    assert "struct EndpointConcurrencyPolicy" in source
    assert "kUnknownActiveCap = kColdActiveCap" in source
    assert "kDpiFailureActiveCap = 1" in source
    assert "kHealthyActiveCap = 8" in source
    assert "kHealthyHandshakeSpacing = crl::time(50)" in source
    assert "nextHandshakeAt" in source
    assert "EndpointConcurrencyPolicyFor(" in source
    assert "SkipCooldown" in header


def test_unknown_and_dpi_endpoints_queue_instead_of_skip_or_fail():
    source = read(ENDPOINT_HEALTH_CPP)
    admit = body_after(source, "Admission EndpointHealth::admit(")

    assert "const auto policy = EndpointConcurrencyPolicyFor(state);" in admit
    assert "state.active >= policy.activeCap" in admit
    assert "AdmissionAction::StartAfter" in admit
    assert "AdmissionAction::SkipCooldown" not in admit
    assert "result.retryAfter = policy.retryAfter;" in admit
    assert "result.retryAfter = state.nextHandshakeAt - now;" in admit
    assert "state.nextHandshakeAt = now + policy.handshakeSpacing;" in admit


def test_dpi_like_failures_keep_strict_cap_and_recipe_escalation():
    source = read(ENDPOINT_HEALTH_CPP)
    policy = body_after(source, "EndpointConcurrencyPolicy EndpointConcurrencyPolicyFor(")
    escalation = body_after(source, "bool FailureNeedsRecipeEscalation(")

    for reason in (
        "ClientHelloSentNoServerHello",
        "TlsAlertAfterClientHello",
        "ServerHelloHmacMismatch",
        "ServerHelloOkNoAppData",
    ):
        assert f"FailureReason::{reason}" in escalation
    assert "FailureNeedsRecipeEscalation(state.lastFailure)" in policy
    assert "kDpiFailureActiveCap" in policy
    assert "policy.recipeEscalationAllowed = true;" in policy


def test_tcp_route_failures_rotate_routes_without_canonical_cooldown():
    source = read(ENDPOINT_HEALTH_CPP)
    route_only = body_after(source, "bool FailureIsRouteOnly(")
    failure = body_after(source, "void EndpointHealth::reportFailure(")

    assert "FailureReason::TcpConnectTimeout" in route_only
    assert "FailureReason::TcpConnectedNoClientHelloWrite" in route_only
    assert "NoteRouteFailure(state, report.endpoint.route, report.reason);" in failure
    # Route-only failures skip canonical degradation while other routes
    # remain, but degrade the canonical once every route has been tried.
    assert ("if (FailureIsRouteOnly(report.reason)"
        " && !report.routesExhausted)") in failure
    route_only_tail = failure.split("if (FailureIsRouteOnly(report.reason)")[1]
    assert route_only_tail.index("return;") < route_only_tail.index(
        "state.lastFailure = report.reason;")


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
    test_unknown_and_dpi_endpoints_queue_instead_of_skip_or_fail()
    test_dpi_like_failures_keep_strict_cap_and_recipe_escalation()
    test_tcp_route_failures_rotate_routes_without_canonical_cooldown()
    test_connection_broker_has_four_priority_queues()
    test_connection_broker_drains_by_priority_not_request_queue_only()
