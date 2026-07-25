from pathlib import Path
from session_private_sources import read_session_private_sources


SOURCE_DIR = Path(__file__).resolve().parents[1]
ROOT = SOURCE_DIR.parents[1]
PROXY_DIR = SOURCE_DIR / "mtproto" / "proxy"
CONTROL_H = PROXY_DIR / "control_plane.h"
CONTROL_CPP = PROXY_DIR / "control_plane.cpp"
TLS_CPP = PROXY_DIR / "mtproxy" / "tls_socket.cpp"
RESOLVING_CPP = PROXY_DIR / "resolving_connection.cpp"


def read(path):
    assert path.exists(), f"missing expected source file: {path}"
    return path.read_text(encoding="utf-8")


def test_raw_reducer_rejects_probe_and_stale_generation_facts():
    source = read(CONTROL_CPP)
    reduce = function_body(
        source, "ProxyConnectionStatus ProxyControlPlane::Reduce(")
    update = function_body(source, "ProxyConnectionStatus ApplySelectedStatusUpdate(")

    assert "IsProxyCheck(fact.status.attempt.use)" in reduce
    assert "return current;" in reduce.split(
        "IsProxyCheck(fact.status.attempt.use)", 1)[1].split("}", 1)[0]
    assert "IsOlderProxyGeneration(current.attempt, update.attempt)" in update
    assert "IsOlderAttempt(current.attempt, update.attempt)" in update
    assert "NonMtproxyRelaySuccessIsFresh(current)" in update
    assert "kNonMtproxyFreshRelaySuccessWindow" in source


def test_tls_socket_owns_serverhello_timeout_and_one_terminal_path():
    source = read(TLS_CPP)
    timeout = function_body(source, "void TlsSocket::handleServerHelloTimeout()")
    terminal = function_body(source, "bool TlsSocket::finishTerminal(")

    assert "_serverHelloDeadline" in timeout
    assert "_serverHelloDeadline - now" in timeout
    assert "finishTerminal(" in timeout
    assert "if (_terminal)" in terminal
    assert "_terminal = true;" in terminal
    assert "_serverHelloTimer.cancel();" in terminal
    assert "_terminalFailure = collectTransportFailure();" in terminal
    assert "reportTransportEvent(" in terminal


def test_resolving_wrapper_keeps_typed_route_and_full_cycle_boundaries():
    source = read(RESOLVING_CPP)
    budget = function_body(
        source, "crl::time ResolvingConnection::fullConnectTimeout() const")

    assert "TypedRouteFailure(" in source
    assert "MergeExhaustedFailure(" in source
    assert "_mtproxyPlan.serverHelloTimeout" in budget
    assert "kRouteAttemptTimeout" in budget
    assert "kOnlyRouteAttemptTimeout" in budget
    assert "kFullConnectTimeoutSafetyMargin" in budget


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
    test_raw_reducer_rejects_probe_and_stale_generation_facts()
    test_tls_socket_owns_serverhello_timeout_and_one_terminal_path()
    test_resolving_wrapper_keeps_typed_route_and_full_cycle_boundaries()
