from pathlib import Path
from session_private_sources import read_session_private_sources


SOURCE_DIR = Path(__file__).resolve().parents[1]
PROXY_DIR = SOURCE_DIR / "mtproto" / "proxy"
MTPROXY_DIR = PROXY_DIR / "mtproxy"
DIAGNOSTICS_H = PROXY_DIR / "diagnostics.h"
DIAGNOSTICS_CPP = PROXY_DIR / "diagnostics.cpp"
RESOLVING_CPP = PROXY_DIR / "resolving_connection.cpp"
TLS_SOCKET_CPP = MTPROXY_DIR / "tls_socket.cpp"
TLS_SOCKET_HANDSHAKE_CPP = MTPROXY_DIR / "tls_socket_handshake.cpp"
TRANSPORT_POLICY_CPP = PROXY_DIR / "transport_policy.cpp"
SESSION_CPP = SOURCE_DIR / "mtproto" / "session" / "private" / "session_private.cpp"


def read(path):
    assert path.exists(), f"missing expected source file: {path}"
    return path.read_text(encoding="utf-8")


def function_body(text: str, signature: str) -> str:
    start = text.index(signature)
    brace = text.index(" {\n", start) + 1
    depth = 0
    for index in range(brace, len(text)):
        char = text[index]
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return text[brace + 1:index]
    raise AssertionError(f"body not found for {signature}")


def test_diagnostics_declares_structured_proxy_events_and_context():
    header = read(DIAGNOSTICS_H)
    source = read(DIAGNOSTICS_CPP)

    for event in (
        "AdmissionQueued",
        "AdmissionStarted",
        "AdmissionCancelled",
        "RouteSelected",
        "RouteFailed",
        "CanonicalDegraded",
        "CanonicalRecovered",
        "StealthRecipeApplied",
        "TransportFallbackApplied",
    ):
        assert f"ProxyDiagnosticsPhase::{event}" in source
        assert event in header

    for text in (
        "admission_queued",
        "admission_started",
        "admission_cancelled",
        "route_selected",
        "route_failed",
        "canonical_degraded",
        "canonical_recovered",
        "stealth_recipe_applied",
        "transport_fallback_applied",
    ):
        assert f'u"{text}"_q' in source

    for field in (
        "QString canonical",
        "QString route",
        "QString proxyKeyHash",
        "QString profile",
        "std::optional<int> recipeLevel",
        "std::optional<bool> pskOffered",
        "std::optional<bool> fragmentedClientHello",
        "QString phaseAtFailure",
        "std::optional<crl::time> queueMs",
    ):
        assert field in header

    for token in (
        "canonical=%1",
        "route=%1",
        "proxy_key_hash=%1",
        "profile=%1",
        "recipe_level=%1",
        "psk_offered=%1",
        "fragmented_ch=%1",
        "phase_at_failure=%1",
        "queue_ms=%1",
    ):
        assert token in source

    assert "ProxyKeyHash(" in source
    assert "QCryptographicHash::Sha256" in source
