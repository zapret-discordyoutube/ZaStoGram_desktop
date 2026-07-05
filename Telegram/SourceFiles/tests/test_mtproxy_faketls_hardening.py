from pathlib import Path


SOURCE_DIR = Path(__file__).resolve().parents[1]
MTPROXY_DIR = SOURCE_DIR / "mtproto" / "proxy" / "mtproxy"
ADAPTIVE_POLICY_CPP = MTPROXY_DIR / "adaptive_policy.cpp"
ENDPOINT_HEALTH_CPP = MTPROXY_DIR / "endpoint_health.cpp"
TLS_SOCKET_CPP = MTPROXY_DIR / "tls_socket.cpp"
SESSION_PRIVATE_CPP = SOURCE_DIR / "mtproto" / "session_private.cpp"


def test_auto_rotate_profile_changes_are_hysteresis_gated():
    source = ADAPTIVE_POLICY_CPP.read_text(encoding="utf-8")
    endpoint_health = ENDPOINT_HEALTH_CPP.read_text(encoding="utf-8")
    rotate_body = function_body(
        source,
        "ProxyTlsProfile RotateTlsProfileOnFailure(")

    assert "kAutoRotateFailureThreshold" in source
    assert "kAutoRotateMinDwell" in source
    assert "state.profileFailures < kAutoRotateFailureThreshold" in rotate_body
    assert "now - state.profileChangedAt < kAutoRotateMinDwell" in rotate_body
    assert "RotateTlsProfileOnFailure(" in endpoint_health


def test_adaptive_policy_does_not_enable_pacing_as_a_recovery_recipe():
    source = ADAPTIVE_POLICY_CPP.read_text(encoding="utf-8")
    post_handshake = block_after(
        source,
        'if (input.lastDiagnostic == u"post_handshake_no_appdata"_q) {')

    assert "ProxyTiming::Gentle" not in post_handshake
    assert "stealth.timing =" not in post_handshake


def test_post_handshake_recipe_keeps_first_retry_close_to_configured_shape():
    source = ADAPTIVE_POLICY_CPP.read_text(encoding="utf-8")
    post_handshake = block_after(
        source,
        'if (input.lastDiagnostic == u"post_handshake_no_appdata"_q) {')

    record_index = post_handshake.index(
        "stealth.recordSizing = ProxyRecordSizing::Conservative;")
    startup_index = post_handshake.index(
        "stealth.startupCover = ProxyStartupCover::Soft;")
    quiet_index = post_handshake.index(
        "stealth.connectionPattern = ProxyConnectionPattern::Quiet;")

    assert post_handshake.rfind("input.recipeLevel >= 2", 0, record_index) >= 0
    assert post_handshake.rfind("input.recipeLevel >= 3", 0, startup_index) >= 0
    assert post_handshake.rfind("input.recipeLevel >= 4", 0, quiet_index) >= 0


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
    assert 'u"post_handshake_no_appdata"_q' not in predicate_body
    assert "RotateTlsProfileOnFailure(" in report_failure


def test_prepared_adaptive_profile_is_used_for_client_hello():
    source = TLS_SOCKET_CPP.read_text(encoding="utf-8")
    header = (MTPROXY_DIR / "tls_socket.h").read_text(encoding="utf-8")
    recipe_body = function_body(source, "void TlsSocket::applyAdaptiveRecipe()")
    send_body = function_body(source, "void TlsSocket::sendClientHello()")
    disconnect_body = function_body(source, "void TlsSocket::plainDisconnected()")

    assert "ProxyTlsProfile _preparedTlsProfile" in header
    assert "bool _usePreparedTlsProfile = false;" in header
    assert "_preparedTlsProfile = recipe.stealth.tlsProfile;" in recipe_body
    assert "_usePreparedTlsProfile = true;" in recipe_body
    assert "? _preparedTlsProfile" in send_body
    assert ": effectiveTlsProfile()" in send_body
    assert "_usePreparedTlsProfile = false;" in send_body
    assert "_usePreparedTlsProfile = false;" in disconnect_body


def test_mtproxy_admission_delays_are_logged_before_skipping_start():
    source = SESSION_PRIVATE_CPP.read_text(encoding="utf-8")
    append_body = function_body(
        source,
        "bool SessionPrivate::appendTestConnection(")
    blocked_branch = block_after(
        append_body,
        "if (admission.action != MtProxy::AdmissionAction::StartNow) {")

    assert "ReportProxyEvent(" in blocked_branch
    assert "ProxyDiagnosticsPhase::Failed" in blocked_branch
    assert "admission.blockedBy" in blocked_branch
    assert "mtproxy admission delayed" in blocked_branch


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
        "if (input.recipeLevel >= 1")


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
    test_auto_rotate_profile_changes_are_hysteresis_gated()
    test_adaptive_policy_does_not_enable_pacing_as_a_recovery_recipe()
    test_post_handshake_recipe_keeps_first_retry_close_to_configured_shape()
    test_post_handshake_failure_does_not_rotate_client_hello_profile()
    test_prepared_adaptive_profile_is_used_for_client_hello()
    test_mtproxy_admission_delays_are_logged_before_skipping_start()
    test_adaptive_recipe_ignores_non_recipe_diagnostic_with_stale_level()
