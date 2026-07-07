from pathlib import Path
from session_private_sources import read_session_private_sources


SOURCE_DIR = Path(__file__).resolve().parents[1]
PROXY_DIR = SOURCE_DIR / "mtproto" / "proxy"
MTPROXY_DIR = PROXY_DIR / "mtproxy"
DIAGNOSTICS_H = PROXY_DIR / "diagnostics.h"
DIAGNOSTICS_CPP = PROXY_DIR / "diagnostics.cpp"
CONNECTION_BROKER_CPP = PROXY_DIR / "connection_broker.cpp"
RESOLVING_CPP = PROXY_DIR / "resolving_connection.cpp"
ENDPOINT_HEALTH_CPP = MTPROXY_DIR / "endpoint_health.cpp"
TLS_SOCKET_CPP = MTPROXY_DIR / "tls_socket.cpp"
TRANSPORT_POLICY_CPP = PROXY_DIR / "transport_policy.cpp"
SESSION_CPP = SOURCE_DIR / "mtproto" / "session_private.cpp"


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
        "int recipeLevel",
        "bool pskOffered",
        "bool fragmentedClientHello",
        "QString phaseAtFailure",
        "crl::time queueMs",
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


def test_admission_queue_and_start_are_logged_not_failed():
    broker = read(CONNECTION_BROKER_CPP)
    session = read_session_private_sources()

    assert "ProxyDiagnosticsPhase::AdmissionQueued" in broker
    assert "ProxyDiagnosticsPhase::AdmissionStarted" in broker
    assert "ProxyDiagnosticsPhase::AdmissionCancelled" in broker
    assert "queueMs =" in broker
    assert "request.runtime" in broker
    assert "request.instance" not in broker

    append_body = function_body(session, "bool SessionPrivate::appendTestConnection(")
    status_body = append_body.split(".status = [=](ConnectionBrokerDecision")[1]
    assert "ProxyDiagnosticsPhase::Connecting" not in status_body
    assert "mtproxy admission queued" not in status_body
    assert "ProxyDiagnosticsPhase::Failed" not in status_body


def test_route_canonical_recipe_and_fallback_events_are_emitted():
    resolving = read(RESOLVING_CPP)
    endpoint_health = read(ENDPOINT_HEALTH_CPP)
    tls_socket = read(TLS_SOCKET_CPP)
    transport_policy = read(TRANSPORT_POLICY_CPP)

    assert "ProxyDiagnosticsPhase::RouteSelected" in resolving
    assert "ProxyDiagnosticsPhase::RouteFailed" in resolving
    assert ".phaseAtFailure =" in resolving
    assert "tcp_not_connected" in resolving
    assert "MtProxy::RouteKey(" in resolving

    assert "ProxyDiagnosticsPhase::CanonicalDegraded" in endpoint_health
    assert "ProxyDiagnosticsPhase::CanonicalRecovered" in endpoint_health
    assert "WriteProxyDiagnosticsLine(" in endpoint_health

    assert "ProxyDiagnosticsPhase::StealthRecipeApplied" in tls_socket
    assert ".pskOffered = _syntheticPskOffered" in tls_socket
    assert ".fragmentedClientHello = _clientHelloFragmented" in tls_socket
    assert "HandshakePhaseText(" in tls_socket

    assert "ProxyDiagnosticsPhase::TransportFallbackApplied" in transport_policy
    assert "transportFallbackLogged" in transport_policy


if __name__ == "__main__":
    test_diagnostics_declares_structured_proxy_events_and_context()
    test_admission_queue_and_start_are_logged_not_failed()
    test_route_canonical_recipe_and_fallback_events_are_emitted()
