from pathlib import Path


SOURCE_DIR = Path(__file__).resolve().parents[1]
ROOT = SOURCE_DIR.parent.parent


def read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def read_endpoint_health_sources() -> str:
    directory = SOURCE_DIR / "mtproto" / "proxy" / "mtproxy"
    return "\n".join(read(directory / name) for name in (
        "endpoint_health.cpp",
        "endpoint_health_lifecycle.cpp",
    ))


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
    assert "_context->releaseAdmissionForRelayCandidate(" in health
    assert "void releaseAdmissionForRelayCandidate();" in health_h
    assert "EndpointHealth *_owner" not in health_h


def test_relay_registry_contract_matches_the_executable_lifecycle_model():
    state = read(SOURCE_DIR / "mtproto" / "proxy" / "mtproxy" /
        "endpoint_health_state.h")
    storage = read(SOURCE_DIR / "mtproto" / "proxy" /
        "proxy_endpoint_context_p.h")
    truth = read(SOURCE_DIR / "tests" / "proxy_control_plane_truth.py")
    identity = state.split("struct RelayProofIdentity {", 1)[1].split(
        "};", 1)[0]

    assert "ProxyRuntimeId runtimeId = 0;" in identity
    assert "uint64 proxyGeneration = 0;" in identity
    assert "uint64 attemptId = 0;" in identity
    assert "EndpointId" not in identity
    assert "QString" not in identity
    assert "std::map<QString, EndpointState> states;" in storage
    assert "std::map<RelayProofIdentity, RelayProofState> relayProofs;" in state
    assert "bool admissionActive = true;" in state
    assert "enum class RelayProofPromotionResult" in state
    assert "Inserted," in state
    assert "AlreadyProven," in state
    assert "MissingAdmission," in state
    for helper in (
            "RuntimeProxyGenerationIsStale",
            "HasEndpointAttempt",
            "HasRelayProof",
            "ActiveEndpointAdmissionCount",
            "SynchronizeEndpointAdmissionAggregate",
            "ReleaseAdmissionForRelayCandidate",
            "PromoteRelayProof",
            "RetireRelayProof",
            "RemoveRelayProofsForRuntime",
            "SynchronizeRelayProofAggregate"):
        assert helper in state
    removed_expiry_field = "expires" + "At"
    removed_proof_prune = "PruneExpired" + "RelayProofs"
    assert removed_expiry_field not in state
    assert removed_proof_prune not in state
    assert 'INSERTED = "Inserted"' in truth
    assert 'ALREADY_PROVEN = "AlreadyProven"' in truth
    assert 'MISSING_ADMISSION = "MissingAdmission"' in truth
    assert "class CanonicalEndpointStore:" in truth
    assert "def test_canonical_endpoint_abc_lifecycle():" in truth
    assert "def test_keyless_release_preserves_exact_promotion_lineage():" in (
        truth)
    assert "test_canonical_endpoint_abc_lifecycle()" in truth.split(
        "def run_all_truth_tables():", 1)[1]


def test_promotion_precedes_admission_release_and_unregister_owns_cleanup():
    state = read(SOURCE_DIR / "mtproto" / "proxy" / "mtproxy" /
        "endpoint_health_state.h")
    health = read_endpoint_health_sources()
    context = read(SOURCE_DIR / "mtproto" / "proxy" /
        "proxy_endpoint_context.cpp")
    promotion = state.split(
        "RelayProofPromotionResult PromoteRelayProof(", 1)[1].split(
            "[[nodiscard]] inline bool RetireRelayProof", 1)[0]
    success = health.split("void EndpointHealth::reportSuccess(", 1)[1].split(
        "void EndpointHealth::noteRelayStall(", 1)[0]
    unregister = context.split(
        "void ProxyEndpointContext::unregisterRuntime(", 1)[1].split(
            "ProxyTraceId ProxyEndpointContext::nextTraceId", 1)[0]

    assert promotion.index("state.relayProofs.emplace(identity, proof);") < (
        promotion.index("state.attemptStarts.erase(identity.attemptId);"))
    release_guard = success.index("const auto releaseLease = gsl::finally")
    lock_scope = success.index("auto &storage = _context->storage();")
    promote = success.index("const auto promotion = PromoteRelayProof(")
    lock_end = success.index("\n\t}\n\tNoteConnectSuccess(")
    assert release_guard < lock_scope < promote < lock_end
    assert "report.lease->release();" in success[release_guard:lock_scope]
    assert "state.generations.erase(runtimeId);" in unregister
    assert "i->second.runtimeId == runtimeId" in unregister
    assert "RemoveRelayProofsForRuntime(state, runtimeId);" in unregister


def test_keyless_release_frees_only_the_active_slot_and_keeps_lineage():
    state = read(SOURCE_DIR / "mtproto" / "proxy" / "mtproxy" /
        "endpoint_health_state.h")
    connection = read(SOURCE_DIR / "mtproto" / "session" / "private" /
        "connection.cpp")
    context = read(SOURCE_DIR / "mtproto" / "proxy" /
        "proxy_endpoint_context.cpp")
    release = state.split(
        "bool ReleaseAdmissionForRelayCandidate(", 1)[1].split(
            "void SynchronizeRelayProofAggregate", 1)[0]
    promotion = state.split(
        "RelayProofPromotionResult PromoteRelayProof(", 1)[1].split(
            "[[nodiscard]] inline bool RetireRelayProof", 1)[0]

    assert "i->second.admissionActive = false;" in release
    assert "state.attemptStarts.erase" not in release
    assert "SynchronizeEndpointAdmissionAggregate(state);" in release
    assert "HasEndpointAttempt(state, identity)" in promotion
    assert connection.count(
        "i->mtproxyLease.releaseAdmissionForRelayCandidate();") == 2
    assert "details::MtProxy::ReleaseAdmissionForRelayCandidate(" in context


def test_admission_release_listeners_fire_after_storage_unlock():
    context = read(SOURCE_DIR / "mtproto" / "proxy" /
        "proxy_endpoint_context.cpp")
    header = read(SOURCE_DIR / "mtproto" / "proxy" /
        "proxy_endpoint_context.h")
    storage = read(SOURCE_DIR / "mtproto" / "proxy" /
        "proxy_endpoint_context_p.h")

    assert "addAdmissionReleaseListener(" in header
    assert "removeAdmissionReleaseListener(" in header
    assert "admissionReleaseListeners;" in storage

    # Listeners are snapshotted under the storage mutex and invoked only
    # after it unlocks: calling under the lock would invert the broker's
    # request() lock order (broker mutex -> storage mutex) and deadlock.
    for signature in (
        "void ProxyEndpointContext::releaseEndpointAttempt(",
        "void ProxyEndpointContext::releaseAdmissionForRelayCandidate(",
    ):
        body = context.split(signature, 1)[1].split("\n}\n", 1)[0]
        assert "CollectAdmissionReleaseListeners(*_storage);" in body
        locked = body.split("QMutexLocker lock(&_storage->mutex);", 1)[1]
        locked_scope = locked.split("\n\t}\n", 1)[0]
        assert "(*listener)(key);" not in locked_scope
        after_lock = locked.split("\n\t}\n", 1)[1]
        assert "(*listener)(key);" in after_lock

    # Only an actual slot release fires the listeners.
    release = context.split(
        "void ProxyEndpointContext::releaseEndpointAttempt(", 1)[1]
    assert "i->second.active < wasActive" in release


def test_endpoint_admissible_wake_on_recovery_and_selection():
    context = read(SOURCE_DIR / "mtproto" / "proxy" /
        "proxy_endpoint_context.cpp")
    header = read(SOURCE_DIR / "mtproto" / "proxy" /
        "proxy_endpoint_context.h")
    health = read(SOURCE_DIR / "mtproto" / "proxy" / "mtproxy" /
        "endpoint_health.cpp")
    lifecycle = read(SOURCE_DIR / "mtproto" / "proxy" / "mtproxy" /
        "endpoint_health_lifecycle.cpp")

    # A relay success or manual selection that clears the cooldown/penalty
    # early must wake the broker so requests queued behind the (now stale)
    # cooldown drain at once, not one per ~1s poll. Same listener channel,
    # same fire-after-unlock discipline.
    assert "void notifyEndpointAdmissible(const QString &key);" in header
    notify = context.split(
        "void ProxyEndpointContext::notifyEndpointAdmissible(", 1)[1].split(
            "\n}\n", 1)[0]
    assert "CollectAdmissionReleaseListeners(*_storage);" in notify
    after_lock = notify.split(
        "QMutexLocker lock(&_storage->mutex);", 1)[1].split("\n\t}\n", 1)[1]
    assert "(*listener)(key);" in after_lock

    success = health.split(
        "void EndpointHealth::reportSuccess(", 1)[1].split(
            "void EndpointHealth::noteRelayStall(", 1)[0]
    assert "becameAdmissible = wasDegraded;" in success
    assert "_context->notifyEndpointAdmissible(key);" in success
    assert success.index("state.terminalUntil = 0;") < success.index(
        "_context->notifyEndpointAdmissible(key);")

    selected = lifecycle.split(
        "void EndpointHealth::noteEndpointSelected(", 1)[1].split(
            "void EndpointHealth::applyProxyGeneration(", 1)[0]
    assert "_context->notifyEndpointAdmissible(key);" in selected


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
    health = read_endpoint_health_sources()
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
    assert probe < admit.index("PruneExpiredEndpointState(")
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
    assert "ScenarioRelayProofLifecycle" in test
    assert "ScenarioInactiveAdmissionPromotion" in test
    assert "ScenarioCanonicalEndpointIsolation" in test
    assert "ScenarioGenerationRejectionBeforeMembership" in test
    assert "ScenarioPerRuntimeGenerationPruning" in test
    assert "ScenarioRuntimeUnregisterPruning" in test
    assert "ScenarioRelayProofLifetimeAndBoundedness" in test
    assert "A/B/C relay proof promotion failed" in test
    assert "exact A retirement did not preserve B/C aggregate" in test
    assert "canonical outer key isolation failed" in test
    assert "stale generation overrode proof membership rejection" in test
    assert "inactive admission did not preserve exact promotion lineage" in test
    assert "live relay proof did not survive state touches" in test
    assert "repeated success and terminal cycle leaked state" in test
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


if __name__ == "__main__":
    test_domain_injects_one_shared_endpoint_context_into_all_account_runtimes()
    test_shared_state_namespaces_generations_and_uses_lifetime_safe_leases()
    test_relay_registry_contract_matches_the_executable_lifecycle_model()
    test_promotion_precedes_admission_release_and_unregister_owns_cleanup()
    test_keyless_release_frees_only_the_active_slot_and_keeps_lineage()
    test_admission_release_listeners_fire_after_storage_unlock()
    test_endpoint_admissible_wake_on_recovery_and_selection()
    test_open_scheduler_state_is_owned_by_shared_context()
    test_admission_freezes_bounded_safe_faketls_plan()
    test_partial_success_preserves_recipe_until_relay_proof()
    test_probe_use_and_transport_failure_are_propagated_without_reclassification()
    test_proxy_check_does_not_mutate_working_health_or_pacing()
    test_connection_use_is_not_inferred_from_file_buffer_policy()
    test_receive_timeout_preserves_the_lowest_typed_transport_verdict()
    test_trace_schema_omits_unknowns_and_finalizes_once()
    test_owner_destruction_finalizes_pending_and_started_traces()
    test_host_coordinator_test_is_registered_without_requiring_build_here()
    test_tls_host_test_covers_partial_write_and_response_classes()
