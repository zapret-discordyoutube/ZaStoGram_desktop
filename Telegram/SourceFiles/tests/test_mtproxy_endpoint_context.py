from pathlib import Path


SOURCE_DIR = Path(__file__).resolve().parents[1]
PROXY_DIR = SOURCE_DIR / "mtproto" / "proxy"
MTPROXY_DIR = PROXY_DIR / "mtproxy"
CONTEXT_H = PROXY_DIR / "proxy_endpoint_context.h"
CONTEXT_CPP = PROXY_DIR / "proxy_endpoint_context.cpp"
STORAGE_H = PROXY_DIR / "proxy_endpoint_context_p.h"
ARBITER_H = PROXY_DIR / "endpoint_admission_arbiter.h"
ARBITER_CPP = PROXY_DIR / "endpoint_admission_arbiter.cpp"
HEALTH_H = MTPROXY_DIR / "endpoint_health.h"
HEALTH_CPP = MTPROXY_DIR / "endpoint_health.cpp"
HEALTH_LIFECYCLE_CPP = MTPROXY_DIR / "endpoint_health_lifecycle.cpp"
STATE_H = MTPROXY_DIR / "endpoint_health_state.h"
POLICY_CPP = MTPROXY_DIR / "endpoint_health_policy.cpp"


def read(path):
    assert path.exists(), f"missing expected source file: {path}"
    return path.read_text(encoding="utf-8")


def test_domain_injects_one_shared_endpoint_context_into_all_runtimes():
    domain_h = read(SOURCE_DIR / "main" / "main_domain.h")
    domain_cpp = read(SOURCE_DIR / "main" / "main_domain.cpp")
    account = read(SOURCE_DIR / "main" / "main_account.cpp")
    runtime = read(SOURCE_DIR / "mtproto" / "runtime" / "runtime_environment.cpp")

    assert "std::shared_ptr<MTP::ProxyEndpointContext>" in domain_h
    assert "MTP::CreateProxyEndpointContext()" in domain_cpp
    assert account.count("domain().proxyEndpointContext()") == 2
    assert "_proxyEndpointContext->registerRuntime()" in runtime
    assert "endpointAdmissionArbiter().bindRuntime(" in runtime
    assert "_proxyEndpointContext->unregisterRuntime(_proxyRuntimeId)" in runtime


def test_shared_context_owns_storage_and_one_admission_arbiter():
    header = read(CONTEXT_H)
    source = read(CONTEXT_CPP)
    storage = read(STORAGE_H)

    assert "const std::unique_ptr<details::MtProxy::EndpointContextStorage> _storage;" in header
    assert "const std::unique_ptr<details::EndpointAdmissionArbiter> _arbiter;" in header
    assert "std::make_unique<details::MtProxy::EndpointContextStorage>()" in source
    assert "std::make_unique<details::EndpointAdmissionArbiter>(*_storage)" in source
    assert "std::map<QString, EndpointState> states;" in storage
    assert "openStates" not in storage
    arbiter_header = read(ARBITER_H)
    arbiter = read(ARBITER_CPP)
    assert "struct EndpointOpeningPermit" in arbiter_header
    assert "EndpointOpeningPermitOwner owner;" in arbiter_header
    assert "std::map<QString, MtProxy::EndpointOpeningPermit> _permits;" in arbiter
    assert "LiveSlot" not in arbiter_header
    assert "LiveSlot" not in arbiter
    assert "std::set<ProxyRuntimeId> runtimes;" in storage
    assert "admissionReleaseListeners" not in storage


def test_runtime_unregister_cancels_tickets_and_prunes_generation_state():
    context = function_body(
        read(CONTEXT_CPP), "void ProxyEndpointContext::unregisterRuntime(")
    arbiter = function_body(
        read(ARBITER_CPP),
        "void EndpointAdmissionArbiter::Private::unregisterRuntime(")
    release_permits = function_body(
        read(ARBITER_CPP),
        "void EndpointAdmissionArbiter::Private::releaseMatchingPermitsLocked(")

    assert "_arbiter->unregisterRuntime(runtimeId);" in context
    assert "_storage.runtimes.erase(runtimeId);" in arbiter
    assert "InvalidateRuntimeDispatch(dispatch->second);" in arbiter
    assert "cancelTicketLocked(key, 0, actions);" in arbiter
    assert "releaseMatchingPermitsLocked(" in arbiter
    assert "permit.owner = std::monostate();" in release_permits
    assert "state.generations.erase(runtimeId);" in arbiter
    assert "i->second.runtimeId == runtimeId" in arbiter
    assert "MtProxy::RemoveRelayProofsForRuntime(state, runtimeId);" in arbiter
    assert "drainEndpointLocked(endpointKey, inputs, actions);" in arbiter
    assert arbiter.rindex("actions.run();") > arbiter.rindex(
        "updateWakeLocked(inputs, actions);")


def test_runtime_cancel_retires_exact_opening_before_permit_reuse():
    source = read(ARBITER_CPP)
    retire = function_body(
        source,
        "void EndpointAdmissionArbiter::Private::retireOpeningAttemptLocked(")
    cancel = function_body(
        source, "void EndpointAdmissionArbiter::Private::cancelRuntime(")

    assert "attemptStarts.find(owner.attemptId)" in retire
    assert "AttemptOwnerMatches(owner, exact)" in retire
    assert "FinishMainRecoveryByReplacementAttemptLocked(" in retire
    assert "std::move(opening->second.ownerDestroyed)" in retire
    assert "attemptStarts.erase(opening);" in retire
    assert "activeTraces.erase" not in retire
    assert "liveLanes" not in retire
    assert "std::get_if<ProxyConnectionAttempt>(" in cancel
    retirement = cancel.index("retireOpeningAttemptLocked(endpointKey, *owner, actions);")
    release = cancel.index("permit.owner = std::monostate();", retirement)
    drain = cancel.index("drainEndpointLocked(endpointKey, inputs, actions);", release)
    assert retirement < release < drain


def test_ticket_callbacks_are_invalidated_and_delivered_after_unlock():
    source = read(ARBITER_CPP)
    post = function_body(source, "void PostAction::run()")
    actions = function_body(source, "void Actions::run()")
    cancel = function_body(
        source, "void EndpointAdmissionArbiter::Private::cancel(")
    missing = function_body(
        source, "void EndpointAdmissionArbiter::Private::deliveryMissing(")
    grant = function_body(source, "void GrantAction::run()")

    assert "registrationLive->load(std::memory_order_acquire)" in post
    assert "guardedTarget" in post
    assert "QMutexLocker" not in actions
    assert "post.run();" in actions
    assert "grant.run();" in actions
    assert cancel.index("QMutexLocker lock(&_storage.mutex);") < cancel.index("actions.run();")
    assert cancel.index("actions.run();") > cancel.rindex("}")
    assert "cancelTicketLocked(key, revision, actions);" in missing
    assert "drainEndpointLocked(endpointKey, inputs, actions);" in missing
    assert "grant.admission.lease.release();" in grant


def test_moved_lease_separates_health_retirement_from_exact_permit_release():
    context = read(CONTEXT_CPP)
    lifecycle = read(HEALTH_LIFECYCLE_CPP)
    arbiter = read(ARBITER_CPP)
    health_header = read(HEALTH_H)
    cancel = function_body(
        context, "void ProxyEndpointContext::cancelEndpointAttempt(")
    release = function_body(lifecycle, "void EndpointAttemptLease::release()")
    grant = function_body(
        arbiter, "void EndpointAdmissionArbiter::Private::deliverGrant(")
    ready = function_body(
        lifecycle, "void EndpointAttemptLease::transportReady()")

    assert "QMutexLocker lock(&_storage->mutex);" in cancel
    assert "AttemptIdentity(owner.attemptId, attemptState) == owner" in cancel
    assert "_context->cancelEndpointAttempt(_key, _attempt);" in release
    assert "endpointAdmissionArbiter().releaseOpeningPermit(" in release
    assert release.index("cancelEndpointAttempt(") < release.index(
        "releaseOpeningPermit(")
    assert "base::take(_openingPermitHeld)" in ready
    assert "cancelEndpointAttempt(" not in ready
    assert "releaseOpeningPermit(" in ready
    assert ", _openingPermitHeld(base::take(other._openingPermitHeld))" in lifecycle
    assert "_openingPermitHeld = base::take(other._openingPermitHeld);" in lifecycle
    assert "permit->second.owner = attempt;" in grant
    assert "admission->lease.armOpeningPermit(attempt);" in grant
    assert grant.index("admission->lease.armOpeningPermit(attempt);") < grant.index(
        "actions.grants.push_back({")
    assert "LiveSlot" not in health_header
    assert "slotKey" not in health_header
    assert "SynchronizeEndpointAdmissionAggregate" not in context
    assert "EndpointOpeningEvent" not in lifecycle


def test_composed_view_is_generation_scoped_and_main_only():
    header = read(HEALTH_H)
    source = read(CONTEXT_CPP)
    compose = function_body(source, "ComposeEndpointViewLocked(")

    assert "struct ProxyEndpointView" in header
    assert "RuntimeGenerationKey runtimeGeneration;" in header
    assert "MainRelayProofView mainProof;" in header
    assert "std::optional<EndpointVerdict> canonicalVerdict;" in header
    assert "generation->second != runtimeGeneration.proxyGeneration" in compose
    assert "result.mainProof = MtProxy::CurrentMainRelayProof(" in compose
    assert "state.canonicalVerdicts.find(" in compose
    assert "SelectMainAttempt(" in compose
    assert "arbiter.composeEndpointViewLocked(" in compose
    assert "EndpointEvent" not in header
    assert "Snapshot" not in header


def test_generation_change_cancels_only_older_tickets():
    source = read(ARBITER_CPP)
    cancel = function_body(
        source,
        "void EndpointAdmissionArbiter::Private::cancelBeforeGeneration(")

    assert "MtProxy::ApplyRuntimeProxyGeneration(" in cancel
    assert "ticket->proxyGeneration < proxyGeneration" in cancel
    assert "postGenerationCancelledStatusLocked(" in cancel
    assert "cancelTicketLocked(key, 0, actions);" in cancel
    assert "releaseMatchingPermitsLocked(" in cancel
    assert "attempt.proxyGeneration < proxyGeneration" in cancel
    assert "drainEndpointLocked(endpointKey, inputs, actions);" in cancel
    assert cancel.rindex("actions.run();") > cancel.rindex(
        "updateWakeLocked(inputs, actions);")


def test_admission_freezes_a_bounded_faketls_plan():
    policy = read(POLICY_CPP)
    health = read(HEALTH_CPP)
    handshake = read(MTPROXY_DIR / "tls_socket_handshake.cpp")
    tcp = read(SOURCE_DIR / "mtproto" / "transport" / "connection_tcp.cpp")

    assert "std::clamp(recipeLevel, 0, 2)" in policy
    assert "ProxyTlsProfile::ChromeModern" in policy
    assert "ProxyConnectionPattern::Soft" in policy
    assert "ProxyClientHelloFragmentation::Soft" in policy
    assert "plan.stealth.syntheticPsk = false;" in policy
    assert "BeginScheduledAttemptLocked(" in health
    assert "_mtproxyPlan = context.mtproxyPlan;" in tcp
    assert "applyAdaptiveRecipe" not in handshake
    assert "mtproxyEndpointSnapshot(" not in handshake


def test_relay_promotion_and_terminal_outcome_preserve_exact_lineage():
    state = read(STATE_H)
    health = read(HEALTH_CPP)
    promotion = block_between(
        state,
        "RelayProofPromotionResult PromoteRelayProof(",
        "[[nodiscard]] inline bool RetireRelayProof")
    terminal = function_body(health, "RecordTerminalAttemptLocked(")

    assert "state.relayProofs.emplace(identity, proof);" in promotion
    assert promotion.index("state.relayProofs.emplace(identity, proof);") < promotion.index(
        "state.attemptStarts.erase(identity.attemptId);")
    assert "FailureFromStaleAttempt(report, state)" in terminal
    assert "attempt->second.terminalVerdict" in terminal
    assert "RecordCurrentTerminalEvidence(" in terminal
    assert "ticketKey = result.attempt.ticketKey" in terminal


def test_trace_identity_is_runtime_scoped_and_finalized_once():
    context_h = read(CONTEXT_H)
    context = read(CONTEXT_CPP)
    storage = read(STORAGE_H)
    diagnostics = read(PROXY_DIR / "diagnostics.cpp")

    assert "std::map<ProxyTraceId, ProxyConnectionAttempt> activeTraces;" in storage
    assert "activeTracesForRuntime(" in context_h
    assert "attempt.runtimeId == runtimeId" in context
    assert "activeTraces.erase(traceId) > 0" in context
    assert "finishTrace(report.attempt.traceId)" in diagnostics


def function_body(text, signature):
    start = text.index(signature)
    brace = text.index("{", start)
    depth = 0
    for index in range(brace, len(text)):
        if text[index] == "{":
            depth += 1
        elif text[index] == "}":
            depth -= 1
            if depth == 0:
                return text[brace + 1:index]
    raise AssertionError(f"function body not found: {signature}")


def block_between(text, start, end):
    return text.split(start, 1)[1].split(end, 1)[0]


if __name__ == "__main__":
    test_domain_injects_one_shared_endpoint_context_into_all_runtimes()
    test_shared_context_owns_storage_and_one_admission_arbiter()
    test_runtime_unregister_cancels_tickets_and_prunes_generation_state()
    test_runtime_cancel_retires_exact_opening_before_permit_reuse()
    test_ticket_callbacks_are_invalidated_and_delivered_after_unlock()
    test_moved_lease_separates_health_retirement_from_exact_permit_release()
    test_composed_view_is_generation_scoped_and_main_only()
    test_generation_change_cancels_only_older_tickets()
    test_admission_freezes_a_bounded_faketls_plan()
    test_relay_promotion_and_terminal_outcome_preserve_exact_lineage()
    test_trace_identity_is_runtime_scoped_and_finalized_once()
