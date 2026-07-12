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
    assert "std::map<QString, OpenState> openStates;" in storage
    assert "std::set<ProxyRuntimeId> runtimes;" in storage
    assert "admissionReleaseListeners" not in storage


def test_runtime_unregister_cancels_tickets_and_prunes_generation_state():
    context = function_body(
        read(CONTEXT_CPP), "void ProxyEndpointContext::unregisterRuntime(")
    arbiter = function_body(
        read(ARBITER_CPP),
        "void EndpointAdmissionArbiter::Private::unregisterRuntime(")

    assert "_arbiter->unregisterRuntime(runtimeId);" in context
    assert "_storage.runtimes.erase(runtimeId);" in arbiter
    assert "InvalidateRuntimeDispatch(dispatch->second);" in arbiter
    assert "cancelTicketLocked(key, 0, actions);" in arbiter
    assert "state.generations.erase(runtimeId);" in arbiter
    assert "i->second.runtimeId == runtimeId" in arbiter
    assert "MtProxy::RemoveRelayProofsForRuntime(state, runtimeId);" in arbiter
    assert arbiter.index("actions.run();") < arbiter.index("drainEndpoint(endpointKey);")


def test_ticket_callbacks_are_invalidated_and_delivered_after_unlock():
    source = read(ARBITER_CPP)
    post = function_body(source, "void PostAction::run()")
    actions = function_body(source, "void Actions::run()")
    cancel = function_body(
        source, "void EndpointAdmissionArbiter::Private::cancel(")

    assert "registrationLive->load(std::memory_order_acquire)" in post
    assert "guardedTarget" in post
    assert "QMutexLocker" not in actions
    assert "post.run();" in actions
    assert "grant.run();" in actions
    assert cancel.index("QMutexLocker lock(&_storage.mutex);") < cancel.index("actions.run();")
    assert cancel.index("actions.run();") > cancel.rindex("}")


def test_release_frees_capacity_then_drains_outside_the_mutex():
    source = read(CONTEXT_CPP)
    release = function_body(
        source, "void ProxyEndpointContext::releaseEndpointAttempt(")
    candidate = function_body(
        source,
        "void ProxyEndpointContext::releaseAdmissionForRelayCandidate(")

    for body in (release, candidate):
        assert "QMutexLocker lock(&_storage->mutex);" in body
        assert "_arbiter->drainEndpoint(key);" in body
        assert body.rindex("_arbiter->drainEndpoint(key);") > body.index("\n\t}")
        assert "notifyEndpointViewChanged(" in body
    assert "SynchronizeEndpointAdmissionAggregate(i->second);" in release
    assert "ReleaseAdmissionForRelayCandidate(" in candidate


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
    for lifecycle in ("Queued", "Scheduled", "Granted"):
        assert f"ProxySchedulerLifecycle::{lifecycle}" in cancel
    assert "cancelTicketLocked(key, 0, actions);" in cancel
    assert cancel.index("actions.run();") < cancel.index("drainEndpoint(endpointKey);")


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
    test_ticket_callbacks_are_invalidated_and_delivered_after_unlock()
    test_release_frees_capacity_then_drains_outside_the_mutex()
    test_composed_view_is_generation_scoped_and_main_only()
    test_generation_change_cancels_only_older_tickets()
    test_admission_freezes_a_bounded_faketls_plan()
    test_relay_promotion_and_terminal_outcome_preserve_exact_lineage()
    test_trace_identity_is_runtime_scoped_and_finalized_once()
