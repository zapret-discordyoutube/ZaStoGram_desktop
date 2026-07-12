from pathlib import Path


SOURCE_DIR = Path(__file__).resolve().parents[1]
ROTATION_H = SOURCE_DIR / "core" / "proxy_rotation_manager.h"
ROTATION_CPP = SOURCE_DIR / "core" / "proxy_rotation_manager.cpp"


def read(path):
    assert path.exists(), f"missing expected source file: {path}"
    return path.read_text(encoding="utf-8")


def test_rotation_subscribes_to_composed_endpoint_views():
    source = read(ROTATION_CPP)
    subscribe = function_body(
        source, "void ProxyRotationManager::subscribeEndpointViews()")
    handler = function_body(
        source, "void ProxyRotationManager::handleEndpointViewChanged(")

    assert "mtproxyEndpointViewChanges(" in subscribe
    assert "ProxyEndpointView view" in subscribe
    assert "view.runtimeGeneration.runtimeId" in handler
    assert "_endpointViewRuntime->proxyRuntimeId()" in handler
    assert "isSelectedProxyEndpoint(view.endpoint)" in handler
    assert handler.index("isSelectedProxyEndpoint(view.endpoint)") < handler.index(
        "recoveryObservedAt(view)")


def test_only_current_main_terminal_without_proof_requests_recovery():
    source = read(ROTATION_CPP)
    evidence = function_body(
        source, "bool ProxyRotationManager::canonicalRecoveryEvidence(")

    assert "view.canonicalVerdict" in evidence
    assert "view.mainProof.strength" in evidence
    assert "MainRelayProofStrength::None" in evidence
    assert "verdict.runtimeGeneration == view.runtimeGeneration" in evidence
    assert "attempt.runtimeId == view.runtimeGeneration.runtimeId" in evidence
    assert "attempt.proxyGeneration" in evidence
    assert "attempt.use == MTP::ProxyConnectionUse::Main" in evidence


def test_main_admission_progress_can_hold_the_recovery_window_open():
    source = read(ROTATION_CPP)
    observed = function_body(
        source, "crl::time ProxyRotationManager::recoveryObservedAt(")

    assert "view.mainProof.strength" in observed
    assert "view.admissionPhase != MTP::ProxyAdmissionPhase::Idle" in observed
    assert "attempt.runtimeId == view.runtimeGeneration.runtimeId" in observed
    assert "attempt.proxyGeneration" in observed
    assert "attempt.use == MTP::ProxyConnectionUse::Main" in observed
    assert "view.enqueuedAt" in observed
    assert "view.attemptStartedAt" in observed
    assert "view.phaseStartedAt" in observed


def test_selected_endpoint_match_uses_canonical_identity():
    body = function_body(
        read(ROTATION_CPP),
        "bool ProxyRotationManager::isSelectedProxyEndpoint(")

    assert "settings.isEnabled()" in body
    assert "EndpointIdFromProxy(" in body
    assert "EndpointKey(selected)" in body
    assert "!key.isEmpty()" in body


def test_switch_grace_is_scoped_to_selection_generation_and_main_success():
    source = read(ROTATION_CPP)
    header = read(ROTATION_H)
    reevaluate = function_body(source, "void ProxyRotationManager::reevaluate()")
    success = function_body(
        source, "void ProxyRotationManager::recordGraceMainSuccess(")
    switch = function_body(
        source, "bool ProxyRotationManager::switchToAvailable(")

    assert "kAfterSwitchGracePeriod = 15 * crl::time(1000)" in source
    assert "crl::time _lastSwitchAt = 0;" in header
    assert "view->runtimeGeneration" in reevaluate
    assert "_pendingGraceEvaluation->runtimeGeneration" in reevaluate
    assert "_pendingGraceEvaluation.reset();" in reevaluate
    assert "_graceTimer.cancel();" in reevaluate
    assert "view.mainProof.strength" in success
    assert "MainRelayProofStrength::None" in success
    assert "view.mainProof.provenAt" in success
    assert "view.mainProof.lastPayloadAt" in success
    assert "_lastSwitchAt = crl::now();" in switch
    assert "_healthRotationRequestedUntil = 0;" in switch


def test_candidate_preference_uses_the_same_composed_view():
    source = read(ROTATION_CPP)
    candidate = function_body(
        source, "bool ProxyRotationManager::proxyCandidatePreferred(")
    gate = function_body(
        source, "bool ProxyRotationManager::shouldSwitchToAvailable(")

    assert "mtproxyEndpointView(endpoint)" in candidate
    assert "view.retryUntil <= crl::now()" in candidate
    assert "shouldObserve()" in gate
    assert "hasActiveHealthRotationRequest()" in gate
    assert "selectedProxyNeedsRecovery()" in gate


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


if __name__ == "__main__":
    test_rotation_subscribes_to_composed_endpoint_views()
    test_only_current_main_terminal_without_proof_requests_recovery()
    test_main_admission_progress_can_hold_the_recovery_window_open()
    test_selected_endpoint_match_uses_canonical_identity()
    test_switch_grace_is_scoped_to_selection_generation_and_main_success()
    test_candidate_preference_uses_the_same_composed_view()
