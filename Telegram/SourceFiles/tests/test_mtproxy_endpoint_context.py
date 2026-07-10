from pathlib import Path


SOURCE_DIR = Path(__file__).resolve().parents[1]
ROOT = SOURCE_DIR.parent.parent


def read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def test_domain_injects_one_shared_endpoint_context_into_all_account_runtimes():
    domain_h = read(SOURCE_DIR / "main" / "main_domain.h")
    domain_cpp = read(SOURCE_DIR / "main" / "main_domain.cpp")
    account = read(SOURCE_DIR / "main" / "main_account.cpp")
    runtime = read(SOURCE_DIR / "mtproto" / "runtime" / "runtime_environment.cpp")

    assert "std::shared_ptr<MTP::ProxyEndpointContext>" in domain_h
    assert "MTP::CreateProxyEndpointContext()" in domain_cpp
    assert account.count("domain().proxyEndpointContext()") == 2
    assert "_proxyEndpointContext->registerRuntime()" in runtime
    assert "_proxyEndpointContext->unregisterRuntime(_proxyRuntimeId)" in runtime


def test_shared_state_namespaces_generations_and_uses_lifetime_safe_leases():
    state = read(SOURCE_DIR / "mtproto" / "proxy" / "mtproxy" /
        "endpoint_health_state.h")
    policy = read(SOURCE_DIR / "mtproto" / "proxy" / "mtproxy" /
        "endpoint_health_policy.cpp")
    health_h = read(SOURCE_DIR / "mtproto" / "proxy" / "mtproxy" /
        "endpoint_health.h")
    health = read(SOURCE_DIR / "mtproto" / "proxy" / "mtproxy" /
        "endpoint_health.cpp")

    assert "std::map<ProxyRuntimeId, uint64> generations;" in state
    assert "ProxyRuntimeId runtimeId" in policy
    assert "i->second.runtimeId == runtimeId" in state
    assert "ApplyRuntimeProxyGeneration(state, runtimeId, proxyGeneration)" in policy
    assert "std::shared_ptr<ProxyEndpointContext> _context;" in health_h
    assert "_context->releaseEndpointAttempt(_key, _attemptId)" in health
    assert "EndpointHealth *_owner" not in health_h


def test_open_scheduler_state_is_owned_by_shared_context():
    scheduler = read(SOURCE_DIR / "mtproto" / "proxy" / "mtproxy" /
        "open_scheduler.cpp")
    storage = read(SOURCE_DIR / "mtproto" / "proxy" /
        "proxy_endpoint_context_p.h")

    assert "std::map<QString, OpenState> openStates;" in storage
    assert "storage.openStates[key]" in scheduler
    assert "OpenStatesMutex" not in scheduler
    assert "DefaultOpenScheduler" not in scheduler


def test_admission_freezes_bounded_safe_faketls_plan():
    policy = read(SOURCE_DIR / "mtproto" / "proxy" / "mtproxy" /
        "endpoint_health_policy.cpp")
    handshake = read(SOURCE_DIR / "mtproto" / "proxy" / "mtproxy" /
        "tls_socket_handshake.cpp")
    tcp = read(SOURCE_DIR / "mtproto" / "transport" / "connection_tcp.cpp")

    assert "std::clamp(recipeLevel, 0, 2)" in policy
    assert "ProxyTlsProfile::ChromeModern" in policy
    assert "ProxyConnectionPattern::Soft" in policy
    assert "ProxyClientHelloFragmentation::Soft" in policy
    assert "plan.stealth.syntheticPsk = false;" in policy
    assert "_mtproxyPlan = context.mtproxyPlan;" in tcp
    assert "applyAdaptiveRecipe" not in handshake
    assert "mtproxyEndpointSnapshot(" not in handshake


def test_partial_success_preserves_recipe_until_relay_proof():
    health = read(SOURCE_DIR / "mtproto" / "proxy" / "mtproxy" /
        "endpoint_health.cpp")
    success = health.split("void EndpointHealth::reportSuccess(", 1)[1].split(
        "void EndpointHealth::noteRelayStall(", 1)[0]

    relay_guard = success.index(
        "if (report.scope != SuccessScope::Relay) {")
    assert relay_guard < success.index("state.recipeLevel = 0;")
    assert relay_guard < success.index("NoteRouteSuccess(")
    assert relay_guard < success.index("state.lastFailure = FailureReason::None;")
    assert relay_guard < success.index(
        "NoteConnectSuccess(_runtime, report.endpoint);")
    assert success.count("state.recipeLevel = 0;") == 1
    assert success.count("NoteConnectSuccess(_runtime, report.endpoint);") == 1


def test_probe_use_and_transport_failure_are_propagated_without_reclassification():
    types = read(SOURCE_DIR / "mtproto" / "runtime" /
        "connection_status_types.h")
    port = read(SOURCE_DIR / "mtproto" / "session" / "private" /
        "proxy_port.h")
    check = read(SOURCE_DIR / "mtproto" / "proxy" / "check.cpp")
    tls = read(SOURCE_DIR / "mtproto" / "proxy" / "mtproxy" /
        "tls_socket.cpp")
    session = read(SOURCE_DIR / "mtproto" / "proxy" /
        "session_proxy_adapter.cpp")
    transport = read(SOURCE_DIR / "mtproto" / "session" / "private" /
        "transport.cpp")

    assert "enum class ProxyConnectionUse" in types
    assert "using SessionProxyEndpointUse = ProxyConnectionUse;" in port
    assert "ProxyTransportFailure" in types
    assert "state->mtproxyAttempt = start.attempt" in check
    assert ".mtproxyAttempt = state->mtproxyAttempt" in check
    assert "_endpointUse = _mtproxyAttempt.use;" in tls
    assert "IsProxyCheck(_endpointUse)" in tls
    assert "FromProxyMtproxyTerminalReason(failure.reason)" in session
    assert "_phase == HandshakePhase::FirstDataReceived" in tls
    assert "ServerHelloOkNoMtprotoData" in tls
    assert "_clientHelloAcceptedBytes > 0" in tls
    assert "TcpConnectedNoClientHelloWrite" in tls
    assert "_mtprotoPayloadReceived" in tls
    assert "markProxyMtprotoPayloadReceived()" in transport
    resolving = read(SOURCE_DIR / "mtproto" / "proxy" /
        "resolving_connection.cpp")
    connect = resolving.split("void ResolvingConnection::connectToServer(", 1)[1]
    assert connect.index("_mtproxyAttempt = context.mtproxyAttempt;") < (
        connect.index("startResolving();"))


def test_proxy_check_does_not_mutate_working_health_or_pacing():
    health = read(SOURCE_DIR / "mtproto" / "proxy" / "mtproxy" /
        "endpoint_health.cpp")
    broker = read(SOURCE_DIR / "mtproto" / "proxy" /
        "connection_broker.cpp")
    resolving = read(SOURCE_DIR / "mtproto" / "proxy" /
        "resolving_connection.cpp")
    admit = health.split("Admission EndpointHealth::admit(", 1)[1].split(
        "void EndpointHealth::reportFailure(", 1)[0]

    probe = admit.index("if (IsProxyCheck(request.use))")
    assert probe < admit.index("ApplyProxyGeneration(")
    assert probe < admit.index("PruneExpiredAttempts(")
    assert probe < admit.index("EndpointConcurrencyPolicyFor(")
    assert "IsProxyCheck(state->request.use)" in broker
    assert broker.index("IsProxyCheck(state->request.use)") < broker.index(
        "MtProxy::ReserveOpenSlot(")
    assert "_ipIndex >= 0 && !IsProxyCheck(_mtproxyAttempt.use)" in resolving


def test_connection_use_is_not_inferred_from_file_buffer_policy():
    session = read(SOURCE_DIR / "mtproto" / "session" / "private" /
        "connection.cpp")
    use_block = session.split("const auto mtproxyUse =", 1)[1].split(
        ";", 1)[0]

    assert "protocolForFiles" not in use_block
    assert "isUploadDcId(_owner->_shiftedDcId)" in use_block
    assert "isMediaClusterDcId(_owner->_shiftedDcId)" in use_block


def test_receive_timeout_preserves_the_lowest_typed_transport_verdict():
    adapter = read(SOURCE_DIR / "mtproto" / "proxy" /
        "session_proxy_adapter.cpp")
    body = adapter.split(
        "void ProductionSessionProxyPort::reportReceiveTimeout(", 1)[1]
    body = body.split(
        "void ProductionSessionProxyPort::reportConnectTimeout(", 1)[0]

    assert "const auto typed = attempt.transport.reason;" in body
    assert "ProxyMtproxyTerminalReason::ConnectedNoMtprotoData" in body
    assert "ProxyMtproxyTerminalReason::ServerHelloOkNoMtprotoData" in body
    assert "MtProxy::FromProxyMtproxyTerminalReason(reason)" in body
    assert "FromProxyMtprotoTerminalReason" not in adapter


def test_trace_schema_omits_unknowns_and_finalizes_once():
    diagnostics_h = read(SOURCE_DIR / "mtproto" / "proxy" / "diagnostics.h")
    diagnostics = read(SOURCE_DIR / "mtproto" / "proxy" / "diagnostics.cpp")
    context = read(SOURCE_DIR / "mtproto" / "proxy" /
        "proxy_endpoint_context.cpp")

    assert "std::optional<int> recipeLevel;" in diagnostics_h
    assert "std::optional<bool> pskOffered;" in diagnostics_h
    assert "std::optional<crl::time> queueMs;" in diagnostics_h
    assert "std::optional<int> clientHelloFragmentSplit;" in diagnostics_h
    assert "std::optional<crl::time> clientHelloFragmentDelayMs;" in (
        diagnostics_h)
    assert "if (safe.recipeLevel)" in diagnostics
    assert "if (safe.pskOffered)" in diagnostics
    assert 'u"phase_at_failure=none"_q' not in diagnostics
    assert 'u"attempt=%1/%2"_q' not in diagnostics
    assert 'u"endpoint_attempt=%1"_q' in diagnostics
    assert 'u"use=%1"_q' in diagnostics
    assert 'u"outcome=cancelled"_q' in diagnostics
    assert 'u"outcome=failure"_q' in diagnostics
    assert 'u"outcome=success"_q' in diagnostics
    assert "finishTrace(report.attempt.traceId)" in diagnostics
    assert "trace_schema=%1" in diagnostics
    assert "report.attempt.traceId && !report.traceSchema" in diagnostics
    assert "activeTraces.erase(traceId) > 0" in context
    assert "traceActive(ProxyTraceId traceId) const" in context
    assert "ProxyDiagnosticsPhase::Liveness" in read(
        SOURCE_DIR / "mtproto" / "proxy" / "mtproxy" / "tls_socket.cpp")
    assert "!livenessReported" in read(
        SOURCE_DIR / "mtproto" / "proxy" / "session_proxy_adapter.cpp")


def test_owner_destruction_finalizes_pending_and_started_traces():
    broker = read(SOURCE_DIR / "mtproto" / "proxy" /
        "connection_broker.cpp")
    runtime = read(SOURCE_DIR / "mtproto" / "runtime" /
        "runtime_environment.cpp")
    check = read(SOURCE_DIR / "mtproto" / "proxy" / "check.cpp")
    connection = read(SOURCE_DIR / "mtproto" / "session" / "private" /
        "connection.cpp")
    adapter = read(SOURCE_DIR / "mtproto" / "proxy" /
        "session_proxy_adapter.cpp")

    assert "cancelByOwnerDestruction()" in broker
    assert "ProxyCloseOrigin::OwnerDestroyed" in broker
    assert "activeTracesForRuntime(" in runtime
    assert "_proxyRuntimeId);" in runtime
    assert "ProxyCloseOrigin::OwnerDestroyed" in runtime
    assert "proxy_check_owner_destroyed" in check
    assert "ProxyCloseOrigin::OwnerDestroyed" in check
    assert "reportAttemptCancelled(" in connection
    assert "destroyAllConnections(ProxyCloseOrigin::ProxySwitch)" in connection
    assert "proxy_attempt_cancelled_by_owner_destruction" in adapter


def test_host_coordinator_test_is_registered_without_requiring_build_here():
    cmake = read(SOURCE_DIR.parent / "cmake" / "tests.cmake")
    test = read(SOURCE_DIR / "tests" / "test_mtproxy_endpoint_context.cpp")

    assert "add_executable(test_mtproxy_endpoint_context" in cmake
    assert "tests/test_mtproxy_endpoint_context.cpp" in cmake
    assert cmake.count("mtproto/proxy/proxy_endpoint_context.cpp") >= 3
    assert "runtime generation isolation failed" in test
    assert "trace finalization is not exactly once" in test
    assert "runtime traces survived unregister" in test


def test_tls_host_test_covers_partial_write_and_response_classes():
    test = read(SOURCE_DIR / "tests" / "test_mtproxy_tls_socket.cpp")
    utils = read(SOURCE_DIR / "mtproto" / "proxy" / "mtproxy" /
        "tls_socket_utils.h")

    assert "ScenarioPartialClientHelloWrite" in test
    assert "ScenarioResponseClassification" in test
    assert "partial_tls_header" in utils
    assert "partial_tls_record" in utils
    assert "tls_alert" in utils
    assert "http_like" in utils
