from pathlib import Path


SOURCE_DIR = Path(__file__).resolve().parents[1]
MTPROXY_DIR = SOURCE_DIR / "mtproto" / "proxy" / "mtproxy"
ADAPTIVE_POLICY_CPP = MTPROXY_DIR / "adaptive_policy.cpp"
ENDPOINT_HEALTH_CPP = MTPROXY_DIR / "endpoint_health.cpp"
TLS_SOCKET_CPP = MTPROXY_DIR / "tls_socket.cpp"


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
    test_prepared_adaptive_profile_is_used_for_client_hello()
