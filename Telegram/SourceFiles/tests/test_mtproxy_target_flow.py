from pathlib import Path
from session_private_sources import read_session_private_sources


SOURCE_DIR = Path(__file__).resolve().parents[1]
PROXY_DIR = SOURCE_DIR / "mtproto" / "proxy"
MTPROXY_DIR = PROXY_DIR / "mtproxy"

SESSION_CPP = SOURCE_DIR / "mtproto" / "session" / "session.cpp"
SESSION_PRIVATE_CPP = SOURCE_DIR / "mtproto" / "session" / "private" / "session_private.cpp"
ABSTRACT_CONNECTION_CPP = SOURCE_DIR / "mtproto" / "transport" / "connection_abstract.cpp"
TRANSPORT_POLICY_CPP = PROXY_DIR / "transport_policy.cpp"
RESOLVING_CPP = PROXY_DIR / "resolving_connection.cpp"
CONNECTION_BROKER_CPP = PROXY_DIR / "connection_broker.cpp"
ENDPOINT_HEALTH_CPP = MTPROXY_DIR / "endpoint_health.cpp"
ENDPOINT_HEALTH_STATE_H = MTPROXY_DIR / "endpoint_health_state.h"
ENDPOINT_HEALTH_CAPABILITIES_CPP = MTPROXY_DIR / "endpoint_health_capabilities.cpp"
ENDPOINT_HEALTH_POLICY_CPP = MTPROXY_DIR / "endpoint_health_policy.cpp"
ADAPTIVE_POLICY_CPP = MTPROXY_DIR / "adaptive_policy.cpp"
TLS_SOCKET_CPP = MTPROXY_DIR / "tls_socket.cpp"
TLS_SOCKET_HANDSHAKE_CPP = MTPROXY_DIR / "tls_socket_handshake.cpp"
TLS_SOCKET_RECORDS_CPP = MTPROXY_DIR / "tls_socket_records.cpp"
STATUS_CPP = PROXY_DIR / "status.cpp"
WINDOW_CONNECTING_CPP = SOURCE_DIR / "window" / "window_connecting_widget.cpp"


def read(path):
    assert path.exists(), f"missing expected source file: {path}"
    return path.read_text(encoding="utf-8")


def compact(text):
    return " ".join(text.split())


def function_body(text: str, signature: str) -> str:
    start = text.index(signature)
    brace = text.index("{", start)
    depth = 0
    for index in range(brace, len(text)):
        char = text[index]
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return text[brace:index + 1]
    raise AssertionError(f"body not found for {signature}")


def test_user_proxy_selection_uses_capability_then_strict_mtproxy_plan():
    session = read(SESSION_CPP)
    policy = read(TRANSPORT_POLICY_CPP)
    refresh = function_body(session, "void Session::refreshOptions(")
    effective = function_body(policy, "ProxyStealthOptions EffectiveProxyStealthOptions(")
    mtproxy_branch = effective.split(
        "proxy.type == ProxyData::Type::Mtproto) {", 1)[1].split(
        "if (settings == ProxyData::Settings::Enabled", 1)[0]

    assert "EffectiveProxyStealthOptions(" in refresh
    assert "runtime->proxyServices().capabilities().lookup(proxy)" in (
        mtproxy_branch)
    assert mtproxy_branch.index("result.transport = ProxyTransport::Tcp;") < (
        mtproxy_branch.index(
            "runtime->proxyServices().capabilities().lookup(proxy)"))
    assert "BoringMtproxyStealthOptions(std::move(result))" in mtproxy_branch
    assert "ProxyTlsProfile::ChromeModern" in policy
    assert "capability.lastGoodProfile" in mtproxy_branch
    assert mtproxy_branch.index("capability.lastGoodProfile") < (
        mtproxy_branch.index("BoringMtproxyStealthOptions(std::move(result))"))
    assert "ProxyTransport::Wss" not in mtproxy_branch
    assert "ApplyProxyStealthLevel(" not in mtproxy_branch
    assert "syntheticPskAllowed" not in mtproxy_branch
    assert "fragmentationAllowed" not in mtproxy_branch


def test_canonical_endpoint_is_built_before_broker_and_not_admitted_in_session():
    session = read_session_private_sources()
    adapter = (PROXY_DIR / "session_proxy_adapter.cpp").read_text(
        encoding="utf-8")
    append = function_body(session, "bool SessionTransport::appendTestConnection(")
    broker_request = function_body(adapter, "ConnectionRequest ToBrokerRequest(")
    mtproxy_part = append.split("if (mtproxy) {", 1)[1]

    assert "MtProxy::EndpointIdFromProxy(" not in append
    assert "MtProxy::EndpointIdFromProxy(" in broker_request
    assert ".address = ip" in mtproxy_part
    assert ".port = port" in mtproxy_part
    assert ".endpoint = std::move(endpoint)" in broker_request
    assert ".proxy = proxy" in mtproxy_part
    assert ".stealth = stealth" in mtproxy_part
    assert ".start = [=](SessionProxyStart start)" in mtproxy_part
    assert "appendStartedConnection(" in mtproxy_part
    assert "EndpointHealth::Instance().admit(" not in append
    assert "setState(-int(" not in append
    assert "mtproxy admission delayed" not in append


def test_dns_singleflight_precedes_route_open_and_route_racing_is_bounded():
    abstract = read(ABSTRACT_CONNECTION_CPP)
    resolving = read(RESOLVING_CPP)
    connect = function_body(
        resolving,
        "void ResolvingConnection::connectToServer(")
    start_resolving = function_body(
        resolving,
        "void ResolvingConnection::startResolving()")
    route_order = function_body(
        resolving,
        "std::vector<int> ResolvingConnection::routeOrder(")
    add_route = function_body(
        resolving,
        "void ResolvingConnection::addRouteAttempt(")

    assert "proxy.tryCustomResolve()" in abstract
    assert "ConnectionPointer::New<ResolvingConnection>" in abstract
    assert connect.index("_mtproxyAttempt = context.mtproxyAttempt;") < (
        connect.index("startResolving();"))
    assert "_runtime->proxyServices().dnsResolver().request(" in start_resolving
    assert "domainResolved(" in start_resolving
    assert "_runtime->proxyServices().capabilities().lookup(_proxy)" in (
        route_order)
    assert route_order.index("capability.goodRoutes") < (
        route_order.index("for (auto index = 0; index != int(_proxy.resolvedIPs.size())"))
    assert "MtProxy::RouteEndpointFromAddress(" in route_order
    assert "MtProxy::RouteKey(route)" in route_order
    assert "attempt.child = _child->clone(ToDirectIpProxy(_proxy, ipIndex));" in add_route
    assert add_route.index("ToDirectIpProxy(_proxy, ipIndex)") < (
        add_route.index("stored.child->connectToServer("))
    assert "kRouteRaceDelay = crl::time(300)" in resolving
    assert "kMaxParallelRouteAttempts = 2" in resolving
    assert "activeRouteAttempts() >= kMaxParallelRouteAttempts" in resolving


def test_arbiter_queues_by_priority_and_broker_logs_non_failure_progress():
    broker = read(CONNECTION_BROKER_CPP)
    arbiter = read(PROXY_DIR / "endpoint_admission_arbiter.cpp")
    decision = function_body(
        broker, "ConnectionBrokerDecision DecisionFromUpdate(")
    event = function_body(broker, "void ReportAdmissionEvent(")

    for priority in ("UrgentMain", "OrdinaryMain", "ProxyCheck", "Background"):
        assert priority in arbiter
    assert "kAgingStep = crl::time(15 * 1000)" in arbiter
    assert "runtimes.upper_bound(last)" in arbiter
    assert "other->sequence < ticket->sequence" in arbiter
    assert "ConnectionBrokerAction::Queued" in decision
    assert "ConnectionBrokerAction::StartAfter" in decision
    assert "ProxyDiagnosticsPhase::AdmissionQueued" in broker
    assert "ProxyDiagnosticsPhase::Failed" not in broker
    for field in (
        ".canonical = CanonicalText(diagnostics.endpoint)",
        ".route = RouteText(diagnostics.endpoint)",
        ".proxyKeyHash = EndpointHash(diagnostics.endpoint)",
        ".configuredProfile = ProxyDiagnosticsTlsProfileName(",
        ".effectiveProfile = (admission && admission->plan.admitted)",
        ".recipeLevel = (admission && admission->plan.admitted)",
        ".queueMs = enqueuedAt",
    ):
        assert field in event
    assert ".profile =" not in event

def test_route_failure_stays_local_until_main_canonical_exhaustion():
    health = read(ENDPOINT_HEALTH_CPP)
    policy = read(ENDPOINT_HEALTH_POLICY_CPP)
    state_source = read(ENDPOINT_HEALTH_STATE_H)
    failure = function_body(health, "void EndpointHealth::reportFailure(")
    success = function_body(health, "void EndpointHealth::reportSuccess(")
    promotion = function_body(
        state_source, "RelayProofPromotionResult PromoteRelayProof(")

    assert "NoteRouteFailure(" in failure
    assert "const auto routeOnly = FailureIsRouteOnly(report.reason)" in failure
    assert "&& !report.routesExhausted" in failure
    assert "const auto alternateRoute" in failure
    assert "HasHealthyRoute(storage, state)" in failure
    assert "const auto canonicalEligible" in failure
    assert "report.use" in failure
    assert "EndpointUse::Main" in failure
    assert "!routeOnly" in failure
    assert "!alternateRoute" in failure
    assert "!HasCurrentMainRelayProof(" in failure
    assert "SetCurrentCanonicalVerdict(" in failure
    assert "report.routesExhausted" in failure
    assert "const auto needsCooldown = FailureNeedsCooldown(" in failure
    assert "report.reason) || report.routesExhausted;" in compact(failure)
    assert "kThrottledRetryCooldown" in policy
    assert "FailureNeedsRecipeEscalation(" in failure

    relay_guard = success.index("if (report.scope != SuccessScope::Relay)")
    promotion_at = success.index("PromoteRelayProof(")
    assert relay_guard < promotion_at
    assert "SuccessFromStaleAttempt(report, state)" in success
    assert "NoteRouteSuccess(storage, state, report.endpoint.route);" in success
    assert "state.recipeLevel = 0;" in success
    assert "state.lastFailure = FailureReason::None;" in success
    assert "state.healthy = true;" in success
    assert "NoteCapabilityMtproxySuccess(" in success
    assert "state.relayProofs.emplace(identity, proof);" in promotion

def test_safe_attempt_plan_escalates_before_any_wss_fallback():
    health = read(ENDPOINT_HEALTH_CPP)
    health_policy = read(ENDPOINT_HEALTH_POLICY_CPP)
    tls_socket = read(SOURCE_DIR / "mtproto" / "proxy" / "mtproxy" /
        "tls_socket.cpp")
    policy = read(TRANSPORT_POLICY_CPP)
    status = read(STATUS_CPP)
    attempt_plan = function_body(
        health_policy,
        "MtProxyAttemptPlan BuildAttemptPlan(")
    wss_allowed = function_body(policy, "bool ProxyWssAllowed(")
    wss_recommend = function_body(policy, "bool WssNeedsProxyRecommendation(")

    assert "state.recipeLevel < 2" in health
    assert "FailureNeedsRecipeEscalation(report.reason)" in health
    assert "ProxyTlsProfile::ChromeModern" in attempt_plan
    assert "ProxyConnectionPattern::Soft" in attempt_plan
    assert "ProxyClientHelloFragmentation::Soft" in attempt_plan
    assert "plan.stealth.syntheticPsk = false;" in attempt_plan
    assert "NormalizeAttemptPlan" in tls_socket
    assert "proxy.type != ProxyData::Type::Socks5" in wss_allowed
    assert "!runtime->proxyServices().capabilities().wssAllowed(proxy)" in (
        wss_allowed)
    assert "proxy.type == ProxyData::Type::None" in wss_recommend
    assert "ProxyConnectionStatusTone::ErrorDns" in status
    assert "ProxyConnectionStatusTone::ErrorTimeout" in status
    assert "ProxyConnectionStatusTone::ErrorHandshake" in status
    assert "ProxyConnectionStatusTone::ErrorData" in status


def test_logs_and_left_proxy_shield_expose_target_flow_state():
    resolving = read(RESOLVING_CPP)
    tls_handshake = read(TLS_SOCKET_HANDSHAKE_CPP)
    window = read(WINDOW_CONNECTING_CPP)
    route_event = function_body(resolving, "void ReportRouteEvent(")

    assert "MtProxy::ToLegacyDiagnostic(reason)" in route_event
    assert 'u"tcp_not_connected"_q' in route_event
    assert "ProxyDiagnosticsPhase::RouteSelected" in resolving
    assert "ProxyDiagnosticsPhase::RouteFailed" in resolving
    assert "ProxyDiagnosticsPhase::ClientHelloSent" in tls_handshake
    assert "reportTransportEvent(" in tls_handshake
    assert "_proxyIcon->moveToLeft(xShift, yShift);" in window
    assert "const auto progressVisible = visible && !_currentLayout.proxyEnabled;" in window
    assert "_proxyIcon->setVisible(_currentLayout.proxyEnabled);" in window
    assert "_cacheErrorDns" in window
    assert "_cacheErrorTimeout" in window
    assert "_cacheErrorHandshake" in window
    assert "_cacheErrorData" in window


def test_first_app_data_reported_once_per_tls_socket():
    tls = read(TLS_SOCKET_RECORDS_CPP)
    body = function_body(tls, "bool TlsSocket::checkNextPacket(")

    # FirstDataReceived progress and the health success report must fire
    # once per socket, not on every incoming TLS record: repeated reports
    # knock the proxy status from Connected back to CheckingTelegram.
    guard = body.index("if (!_firstAppDataReceived) {")
    assert guard < body.index("_firstAppDataReceived = true;")
    assert guard < body.index("connectionProgress(_phase);")
    assert guard < body.index("reportMtproxySuccess({")


def test_route_timeouts_and_exhaustion_reach_endpoint_health():
    resolving = read(RESOLVING_CPP)
    timeout = function_body(
        resolving,
        "void ResolvingConnection::handleRouteAttemptTimeout(")
    error = function_body(
        resolving,
        "void ResolvingConnection::handleError(")

    assert "child->timedOut();" in timeout
    assert timeout.index("child->timedOut();") < timeout.index(
        "_routeAttempts.erase(victim);")
    assert "TypedRouteFailure(" in timeout
    assert "MergeExhaustedFailure(_lastFailure, failure);" in timeout
    assert "MergeExhaustedFailure(_lastFailure, failure);" in error
    assert "routesExhausted" not in resolving
    adapter = read(PROXY_DIR / "session_proxy_adapter.cpp")
    check = read(PROXY_DIR / "check.cpp")
    assert ".routesExhausted = true," in adapter
    assert ".routesExhausted = true," in check


def test_resolving_connection_forwards_timeout_to_route_attempts():
    resolving = read(RESOLVING_CPP)
    timed_out = function_body(
        resolving,
        "void ResolvingConnection::timedOut(")

    # The owner times out on the ResolvingConnection wrapper; without
    # forwarding, the TlsSocket doing the actual connect never reports
    # its failure to EndpointHealth and domain proxies never degrade.
    assert "attempt.child->timedOut();" in timed_out
    assert "_child->timedOut();" in timed_out


def test_proxied_connects_get_their_full_time_budget():
    session = read_session_private_sources()
    resolving = read(RESOLVING_CPP)
    health = read(ENDPOINT_HEALTH_CPP)
    arm = function_body(
        session,
        "void SessionTransport::armWaitForConnectedTimer(")
    refresh = function_body(
        resolving,
        "void ResolvingConnection::refreshAttemptTimeout(")
    failure = function_body(health, "void EndpointHealth::reportFailure(")
    success = function_body(health, "void EndpointHealth::reportSuccess(")

    # The session must not kill a proxied connect before its own route
    # budget elapses - every premature kill burns a FakeTLS handshake
    # and reconnects, which is what gets proxies throttled.
    assert "_sessionState.options->proxy.type != ProxyData::Type::None" in arm
    assert "fullConnectTimeout()" in arm
    assert "accumulate_max(_timing.waitForConnected, minWait);" in arm
    assert "routePhaseBudget(phase)" in refresh
    budget = function_body(
        resolving,
        "crl::time ResolvingConnection::routePhaseBudget(")
    assert "HandshakePhase::ClientHelloSent" in budget
    assert "return 0;" in budget
    assert "HandshakePhase::ServerHelloOk" in budget
    assert "HandshakePhase::FirstDataReceived" in budget
    assert "kOnlyRouteAttemptTimeout" in budget
    assert "_nextRoutePosition >= int(_routeOrder.size())" in budget
    assert "NoteConnectTimeout(" not in failure
    assert "NoteConnectSuccess(" not in success
    assert success.index(
        "if (report.scope != SuccessScope::Relay) {") < success.index(
            "relayReady = RelayReady{")


def test_stealth_option_changes_restart_proxy_connections():
    app = read(SOURCE_DIR / "core" / "application.cpp")
    box = read(SOURCE_DIR / "boxes" / "connection_box.cpp")
    apply_body = function_body(
        app,
        "void Application::applyProxyStealthOptions(")
    restart_body = function_body(
        app,
        "void Application::restartProxyConnections(")

    # Sessions read stealth options only when (re)connecting: writing
    # the setting without restarting MTP leaves e.g. a WSS transport
    # switch inert until something else (like toggling IPv6) restarts
    # connections.
    assert "setProxyStealthOptions(options);" in apply_body
    assert "_proxyRestartTimer" in apply_body
    assert "_proxyChanges.fire" in restart_body
    assert "Core::App().settings().setProxyStealthOptions(" not in box
    assert "Core::App().applyProxyStealthOptions(o);" in box
    assert "Core::App().restartProxyConnections();" in box


if __name__ == "__main__":
    test_user_proxy_selection_uses_capability_then_strict_mtproxy_plan()
    test_canonical_endpoint_is_built_before_broker_and_not_admitted_in_session()
    test_dns_singleflight_precedes_route_open_and_route_racing_is_bounded()
    test_arbiter_queues_by_priority_and_broker_logs_non_failure_progress()
    test_route_failure_stays_local_until_main_canonical_exhaustion()
    test_safe_attempt_plan_escalates_before_any_wss_fallback()
    test_logs_and_left_proxy_shield_expose_target_flow_state()
    test_first_app_data_reported_once_per_tls_socket()
    test_route_timeouts_and_exhaustion_reach_endpoint_health()
    test_resolving_connection_forwards_timeout_to_route_attempts()
    test_proxied_connects_get_their_full_time_budget()
    test_stealth_option_changes_restart_proxy_connections()
