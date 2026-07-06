from pathlib import Path


SOURCE_DIR = Path(__file__).resolve().parents[1]
PROXY_DIR = SOURCE_DIR / "mtproto" / "proxy"
MTPROXY_DIR = PROXY_DIR / "mtproxy"

SESSION_CPP = SOURCE_DIR / "mtproto" / "session.cpp"
SESSION_PRIVATE_CPP = SOURCE_DIR / "mtproto" / "session_private.cpp"
ABSTRACT_CONNECTION_CPP = SOURCE_DIR / "mtproto" / "connection_abstract.cpp"
TRANSPORT_POLICY_CPP = PROXY_DIR / "transport_policy.cpp"
RESOLVING_CPP = PROXY_DIR / "resolving_connection.cpp"
CONNECTION_BROKER_CPP = PROXY_DIR / "connection_broker.cpp"
ENDPOINT_HEALTH_CPP = MTPROXY_DIR / "endpoint_health.cpp"
ADAPTIVE_POLICY_CPP = MTPROXY_DIR / "adaptive_policy.cpp"
TLS_SOCKET_CPP = MTPROXY_DIR / "tls_socket.cpp"
STATUS_CPP = PROXY_DIR / "status.cpp"
WINDOW_CONNECTING_CPP = SOURCE_DIR / "window" / "window_connecting_widget.cpp"


def read(path):
    assert path.exists(), f"missing expected source file: {path}"
    return path.read_text(encoding="utf-8")


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
    assert "ProxyCapabilityCache::Instance().lookup(proxy)" in mtproxy_branch
    assert mtproxy_branch.index("result.transport = ProxyTransport::Tcp;") < (
        mtproxy_branch.index("ProxyCapabilityCache::Instance().lookup(proxy)"))
    assert "CompatStrictProxyStealthOptions(std::move(result))" in mtproxy_branch
    assert mtproxy_branch.index("CompatStrictProxyStealthOptions(") < (
        mtproxy_branch.index("result.tlsProfile = capability.lastGoodProfile;"))
    assert "ProxyTransport::Wss" not in mtproxy_branch
    assert "ApplyProxyStealthLevel(" not in mtproxy_branch
    assert "syntheticPskAllowed" not in mtproxy_branch
    assert "fragmentationAllowed" not in mtproxy_branch


def test_canonical_endpoint_is_built_before_broker_and_not_admitted_in_session():
    session = read(SESSION_PRIVATE_CPP)
    append = function_body(session, "bool SessionPrivate::appendTestConnection(")
    mtproxy_part = append.split("if (mtproxy) {", 1)[1]

    assert "MtProxy::EndpointIdFromProxy(" in append
    assert append.index("MtProxy::EndpointIdFromProxy(") < (
        append.index("ConnectionBroker::Instance().request({"))
    assert ".endpoint = mtproxyEndpoint" in mtproxy_part
    assert ".proxy = proxy" in mtproxy_part
    assert ".stealth = stealth" in mtproxy_part
    assert ".start = [=](ConnectionStart start)" in mtproxy_part
    assert "appendStartedConnection(" in mtproxy_part
    assert "EndpointHealth::Instance().admit(" not in append
    assert "setState(-int(" not in append
    assert "mtproxy admission delayed" not in append


def test_dns_singleflight_precedes_route_open_and_route_racing_is_bounded():
    abstract = read(ABSTRACT_CONNECTION_CPP)
    resolving = read(RESOLVING_CPP)
    constructor = resolving.split("ResolvingConnection::ResolvingConnection(")[1]
    constructor = constructor.split("\n}\n", 1)[0]
    route_order = function_body(
        resolving,
        "std::vector<int> ResolvingConnection::routeOrder(")
    add_route = function_body(
        resolving,
        "void ResolvingConnection::addRouteAttempt(")

    assert "proxy.tryCustomResolve()" in abstract
    assert "ConnectionPointer::New<ResolvingConnection>" in abstract
    assert "DnsResolverCache::Instance().request(" in constructor
    assert "domainResolved(" in constructor
    assert "ProxyCapabilityCache::Instance().lookup(_proxy)" in route_order
    assert route_order.index("capability.goodRoutes") < (
        route_order.index("for (auto index = 0; index != int(_proxy.resolvedIPs.size())"))
    assert "MtProxy::RouteEndpointFromAddress(" in route_order
    assert "MtProxy::RouteKey(route)" in route_order
    assert "attempt.child = _child->clone(ToDirectIpProxy(_proxy, ipIndex));" in add_route
    assert add_route.index("ToDirectIpProxy(_proxy, ipIndex)") < (
        add_route.index("attempt.child->connectToServer("))
    assert "kRouteRaceDelay = crl::time(300)" in resolving
    assert "kMaxParallelRouteAttempts = 2" in resolving
    assert "activeRouteAttempts() >= kMaxParallelRouteAttempts" in resolving


def test_broker_queues_by_priority_and_logs_queue_as_non_failure():
    broker = read(CONNECTION_BROKER_CPP)
    drain = function_body(broker, "void ConnectionBroker::drain()")
    drain_queue = function_body(broker, "void ConnectionBroker::drainQueue(")
    notify = function_body(broker, "void ConnectionBroker::notify(")
    event = function_body(
        broker,
        "void ConnectionBroker::reportAdmissionEvent(")

    assert "MtProxy::EndpointUse::Main" in broker
    assert "MtProxy::EndpointUse::ProxyCheck" in broker
    assert "MtProxy::EndpointUse::Media" in broker
    assert "MtProxy::EndpointUse::Upload" in broker
    # Every queue is drained on each pass: a Main request waiting out a
    # cooldown must not starve Media/Upload queues (head-of-line blocking).
    assert "for (const auto use : kQueuePriorityOrder)" in drain
    assert "drainQueue(use);" in drain
    assert "MtProxy::EndpointHealth::Instance().admit({" in drain_queue
    assert "MtProxy::ReserveOpenSlot(" in drain_queue
    assert "ConnectionBrokerAction::Queued" in notify
    assert "ConnectionBrokerAction::StartAfter" in notify
    assert "ProxyDiagnosticsPhase::AdmissionQueued" in notify
    assert "ProxyDiagnosticsPhase::Failed" not in notify
    for field in (
        ".canonical = CanonicalText(state->request.endpoint)",
        ".route = RouteText(state->request.endpoint)",
        ".proxyKeyHash = EndpointHash(state->request.endpoint)",
        ".profile = ProxyDiagnosticsTlsProfileName(profile)",
        ".recipeLevel = int(state->request.stealth.level)",
        ".queueMs = state->createdAt",
    ):
        assert field in event


def test_route_failure_stays_route_level_and_success_recovers_canonical():
    health = read(ENDPOINT_HEALTH_CPP)
    failure = function_body(health, "void EndpointHealth::reportFailure(")
    success = function_body(health, "void EndpointHealth::reportSuccess(")

    assert "NoteRouteFailure(state, report.endpoint.route, report.reason);" in failure
    assert failure.index("NoteRouteFailure(") < (
        failure.index("FailureIsRouteOnly(report.reason)"))
    assert ("if (FailureIsRouteOnly(report.reason)"
        " && !report.routesExhausted)") in failure
    assert "HasHealthyRoute(state)" in failure
    assert "!report.routesExhausted" in failure
    assert failure.index("HasHealthyRoute(state)") < (
        failure.index("state.lastFailure = report.reason;"))
    # With every route tried and failed the canonical endpoint must
    # degrade: cooldown applied and rotation allowed.
    assert "const auto needsCooldown = FailureNeedsCooldown(report.reason)" in failure
    assert "|| report.routesExhausted;" in failure
    assert ".rotationAllowed = needsCooldown," in failure
    assert "ProxyCapabilityCache::Instance().noteMtproxySuccess(" in success
    assert "CapabilityProxyKey(report.endpoint.canonical)" in success
    assert "RouteKey(report.endpoint.route)" in success
    assert "NoteRouteSuccess(state, report.endpoint.route);" in success
    assert "state.lastFailure = FailureReason::None;" in success
    assert "state.recipeLevel = 0;" in success
    assert "state.healthy = true;" in success


def test_stealth_escalates_after_phase_failures_before_any_wss_fallback():
    health = read(ENDPOINT_HEALTH_CPP)
    adaptive = read(ADAPTIVE_POLICY_CPP)
    tls = read(TLS_SOCKET_CPP)
    policy = read(TRANSPORT_POLICY_CPP)
    status = read(STATUS_CPP)
    recipe = function_body(adaptive, "AdaptiveRecipeResult ApplyAdaptiveRecipe(")
    wss_allowed = function_body(policy, "bool ProxyWssAllowed(")
    wss_recommend = function_body(policy, "bool WssNeedsProxyRecommendation(")

    assert "FailureNeedsTlsRotation(report.reason)" in health
    assert "FailureNeedsRecipeEscalation(state.lastFailure)" in health
    assert "MtProxy::EndpointHealth::Instance().snapshot(" in tls
    assert "ApplyAdaptiveRecipe(input)" in tls
    assert "FailureNeedsRecipe(input.lastDiagnostic)" in recipe
    assert recipe.index("FailureNeedsRecipe(input.lastDiagnostic)") < (
        recipe.index("ApplyProxyStealthLevel("))
    assert 'input.lastDiagnostic == u"server_hello_ok_no_appdata"_q' in recipe
    assert recipe.index('input.lastDiagnostic == u"server_hello_ok_no_appdata"_q') < (
        recipe.index("CompatibilityTlsProfile("))
    assert "proxy.type != ProxyData::Type::Socks5" in wss_allowed
    assert "!ProxyCapabilityCache::Instance().wssAllowed(proxy)" in wss_allowed
    assert "proxy.type == ProxyData::Type::None" in wss_recommend
    assert "ProxyConnectionStatusTone::ErrorDns" in status
    assert "ProxyConnectionStatusTone::ErrorTimeout" in status
    assert "ProxyConnectionStatusTone::ErrorHandshake" in status
    assert "ProxyConnectionStatusTone::ErrorData" in status


def test_logs_and_left_proxy_shield_expose_target_flow_state():
    resolving = read(RESOLVING_CPP)
    tls = read(TLS_SOCKET_CPP)
    window = read(WINDOW_CONNECTING_CPP)
    route_event = function_body(resolving, "void ReportRouteEvent(")

    assert "MtProxy::ToLegacyDiagnostic(reason)" in route_event
    assert 'u"tcp_not_connected"_q' in route_event
    assert "ProxyDiagnosticsPhase::RouteSelected" in resolving
    assert "ProxyDiagnosticsPhase::RouteFailed" in resolving
    assert "ProxyDiagnosticsPhase::StealthRecipeApplied" in tls
    assert ".phaseAtFailure = input.lastDiagnostic.isEmpty()" in tls
    assert "_proxyIcon->moveToLeft(xShift, yShift);" in window
    assert "const auto progressVisible = visible && !_currentLayout.proxyEnabled;" in window
    assert "_proxyIcon->setVisible(_currentLayout.proxyEnabled);" in window
    assert "_cacheErrorDns" in window
    assert "_cacheErrorTimeout" in window
    assert "_cacheErrorHandshake" in window
    assert "_cacheErrorData" in window


if __name__ == "__main__":
    test_user_proxy_selection_uses_capability_then_strict_mtproxy_plan()
    test_canonical_endpoint_is_built_before_broker_and_not_admitted_in_session()
    test_dns_singleflight_precedes_route_open_and_route_racing_is_bounded()
    test_broker_queues_by_priority_and_logs_queue_as_non_failure()
    test_route_failure_stays_route_level_and_success_recovers_canonical()
    test_stealth_escalates_after_phase_failures_before_any_wss_fallback()
    test_logs_and_left_proxy_shield_expose_target_flow_state()


def test_first_app_data_reported_once_per_tls_socket():
    tls = read(TLS_SOCKET_CPP)
    body = function_body(tls, "bool TlsSocket::checkNextPacket(")

    # FirstDataReceived progress and the health success report must fire
    # once per socket, not on every incoming TLS record: repeated reports
    # knock the proxy status from Connected back to CheckingTelegram.
    guard = body.index("if (!_firstAppDataReceived) {")
    assert guard < body.index("_firstAppDataReceived = true;")
    assert guard < body.index("connectionProgress(_phase);")
    assert guard < body.index("reportSuccess({")


def test_route_timeouts_and_exhaustion_reach_endpoint_health():
    resolving = read(RESOLVING_CPP)
    timeout = function_body(
        resolving,
        "void ResolvingConnection::handleRouteAttemptTimeout(")
    error = function_body(
        resolving,
        "void ResolvingConnection::handleError(")
    exhausted = function_body(resolving, "void ReportAllRoutesFailed(")

    # A route attempt killed by our own timeout produces no socket error,
    # so its failure must be reported to EndpointHealth explicitly.
    assert "ReportRouteFailureToHealth(" in timeout
    # Once the last route fails the canonical endpoint must degrade so a
    # fully blackholed proxy gets a cooldown and can trigger rotation.
    assert "ReportAllRoutesFailed(" in timeout
    assert "ReportAllRoutesFailed(_proxy, reason);" in error
    # An error on an established connection is not route exhaustion.
    assert "if (!_connected) {" in error
    assert ".routesExhausted = true," in exhausted


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
