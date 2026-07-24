from pathlib import Path
from session_private_sources import read_session_private_sources


SOURCE_DIR = Path(__file__).resolve().parents[1]
MTPROXY_DIR = SOURCE_DIR / "mtproto" / "proxy" / "mtproxy"
ADAPTIVE_POLICY_CPP = MTPROXY_DIR / "adaptive_policy.cpp"
ENDPOINT_HEALTH_CPP = MTPROXY_DIR / "endpoint_health.cpp"
TLS_SOCKET_CPP = MTPROXY_DIR / "tls_socket.cpp"
TLS_SOCKET_HANDSHAKE_CPP = MTPROXY_DIR / "tls_socket_handshake.cpp"
SESSION_PRIVATE_CPP = SOURCE_DIR / "mtproto" / "session" / "private" / "session_private.cpp"


def test_auto_rotate_profile_is_not_used_by_automatic_endpoint_recovery():
    source = ADAPTIVE_POLICY_CPP.read_text(encoding="utf-8")
    endpoint_health = ENDPOINT_HEALTH_CPP.read_text(encoding="utf-8")
    rotate_body = function_body(
        source,
        "ProxyTlsProfile RotateTlsProfileOnFailure(")

    assert "kAutoRotateFailureThreshold" in source
    assert "kAutoRotateMinDwell" in source
    assert "state.profileFailures < kAutoRotateFailureThreshold" in rotate_body
    assert "now - state.profileChangedAt < kAutoRotateMinDwell" in rotate_body
    assert "RotateTlsProfileOnFailure(" not in endpoint_health
    assert "BuildAttemptPlan(request, state.recipeLevel)" in endpoint_health
    assert "ProxyTlsProfile::ChromeModern" in (
        MTPROXY_DIR / "endpoint_health_policy.cpp").read_text(encoding="utf-8")


def test_adaptive_policy_does_not_enable_pacing_as_a_recovery_recipe():
    source = ADAPTIVE_POLICY_CPP.read_text(encoding="utf-8")
    recipe_body = function_body(
        source,
        "AdaptiveRecipeResult ApplyAdaptiveRecipe(")

    assert "ProxyStealthLevelForRecipeLevel(" in source
    assert "ApplyProxyStealthLevel(" in recipe_body
    assert "ProxyStealthLevel::Experimental" not in function_body(
        source,
        "ProxyStealthLevel ProxyStealthLevelForRecipeLevel(")


def test_adaptive_recipe_ladder_keeps_experimental_flags_manual():
    source = ADAPTIVE_POLICY_CPP.read_text(encoding="utf-8")
    data = (SOURCE_DIR / "mtproto" / "proxy" / "data.cpp").read_text(
        encoding="utf-8")
    box = (SOURCE_DIR / "boxes" / "connection_box.cpp").read_text(
        encoding="utf-8")
    recipe_body = function_body(
        source,
        "AdaptiveRecipeResult ApplyAdaptiveRecipe(")
    level_body = function_body(
        source,
        "ProxyStealthLevel ProxyStealthLevelForRecipeLevel(")
    apply_level = function_body(
        data,
        "ProxyStealthOptions ApplyProxyStealthLevel(")

    assert "recipeLevel <= 0" in level_body
    assert "ProxyStealthLevel::CompatStrict" in level_body
    assert "ProxyStealthLevel::CompatModern" in level_body
    assert "ProxyStealthLevel::DpiAdaptiveHandshake" in level_body
    assert "ProxyStealthLevel::DpiAdaptiveData" in level_body
    assert "ProxyStealthLevel::Experimental" not in level_body
    assert "result.syntheticPsk = false;" in apply_level
    assert "result.clientHelloFragmentation = ProxyClientHelloFragmentation::Off;" in (
        apply_level)
    assert "case ProxyStealthLevel::Experimental:" in apply_level
    assert "ApplyProxyStealthLevel(input.stealth, level)" in recipe_body
    assert "Synthetic PSK tickets (experimental)" in box
    assert "Experimental MTProxy handshake" in box
    assert "Data-phase shaping" in box


def test_post_handshake_failure_does_not_rotate_client_hello_profile():
    header = (MTPROXY_DIR / "adaptive_policy.h").read_text(encoding="utf-8")
    source = ADAPTIVE_POLICY_CPP.read_text(encoding="utf-8")
    endpoint_health = ENDPOINT_HEALTH_CPP.read_text(encoding="utf-8")
    rotation_body = function_body(
        source,
        "ProxyTlsProfile RotateTlsProfileOnFailure(")
    predicate_body = function_body(
        source,
        "bool FailureNeedsTlsProfileRotation(")
    report_failure = function_body(
        endpoint_health,
        "void EndpointHealth::reportFailure(")

    assert "FailureNeedsTlsProfileRotation(" in header
    assert "FailureNeedsTlsProfileRotation(diagnostic)" in rotation_body
    assert 'u"server_hello_ok_no_appdata"_q' not in predicate_body
    assert "RotateTlsProfileOnFailure(" not in report_failure


def test_immutable_admission_profile_is_used_for_client_hello():
    source = TLS_SOCKET_HANDSHAKE_CPP.read_text(encoding="utf-8")
    header = (MTPROXY_DIR / "tls_socket.h").read_text(encoding="utf-8")
    send_body = function_body(source, "void TlsSocket::sendClientHello()")

    assert "MtProxyAttemptPlan _mtproxyPlan;" in header
    assert "ProxyTlsProfile _preparedTlsProfile" not in header
    assert "applyAdaptiveRecipe" not in source
    assert "const auto profile = effectiveTlsProfile();" in send_body


def test_mtproxy_admission_is_confined_to_explicit_proxy_checks():
    source = read_session_private_sources()
    broker = (SOURCE_DIR / "mtproto" / "proxy" / "connection_broker.cpp").read_text(
        encoding="utf-8")
    append_body = function_body(
        source,
        "bool SessionTransport::appendTestConnection(")

    assert "_owner->_proxyPort->requestConnection({" not in append_body
    assert "SessionProxyAdmissionDecision" not in append_body
    assert "ReserveHandshakeGateForProxy" not in append_body
    assert "_owner->_connectionFactory->create(" in append_body
    assert "weak->connectToServer(" in append_body
    decision = function_body(
        broker,
        "ConnectionBrokerDecision DecisionFromUpdate(")
    report = function_body(broker, "void ReportAdmissionEvent(")
    assert "ConnectionBrokerAction::Queued" in decision
    assert "ConnectionBrokerAction::StartAfter" in decision
    assert "ProxyDiagnosticsPhase::AdmissionQueued" in broker
    assert "ProxyDiagnosticsPhase::Connecting" not in broker
    assert "ProxyDiagnosticsSeverity::Warning" in broker
    assert ".error = " not in report
    assert "mtproxy admission queued" in broker
    assert "setState(-int(admission.retryAfter));" not in append_body


def test_adaptive_recipe_ignores_non_recipe_diagnostic_with_stale_level():
    source = ADAPTIVE_POLICY_CPP.read_text(encoding="utf-8")
    recipe_body = function_body(
        source,
        "AdaptiveRecipeResult ApplyAdaptiveRecipe(")
    guard = (
        "if (!FailureNeedsRecipe(input.lastDiagnostic)) {\n"
        "\t\treturn result;\n"
        "\t}")

    assert guard in recipe_body
    assert recipe_body.index(guard) < recipe_body.index(
        "ApplyProxyStealthLevel(")


def function_body(text: str, signature: str) -> str:
    start = text.index(signature)
    brace = text.index(" {\n", start) + 1
    return body_from_brace(text, brace)


def block_after(text: str, marker: str) -> str:
    start = text.index(marker)
    brace = text.index("{", start)
    return body_from_brace(text, brace)


def body_from_brace(text: str, brace: int) -> str:
    depth = 0
    for index in range(brace, len(text)):
        char = text[index]
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return text[brace + 1:index]
    raise AssertionError("body not found")


if __name__ == "__main__":
    test_auto_rotate_profile_is_not_used_by_automatic_endpoint_recovery()
    test_adaptive_policy_does_not_enable_pacing_as_a_recovery_recipe()
    test_adaptive_recipe_ladder_keeps_experimental_flags_manual()
    test_post_handshake_failure_does_not_rotate_client_hello_profile()
    test_immutable_admission_profile_is_used_for_client_hello()
    test_mtproxy_admission_is_confined_to_explicit_proxy_checks()
    test_adaptive_recipe_ignores_non_recipe_diagnostic_with_stale_level()
