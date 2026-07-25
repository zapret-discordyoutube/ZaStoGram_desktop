from pathlib import Path


SOURCE_DIR = Path(__file__).resolve().parents[1]
CHECK_H = SOURCE_DIR / "mtproto" / "proxy" / "check.h"
CHECK_CPP = SOURCE_DIR / "mtproto" / "proxy" / "check.cpp"
CONTROL_CPP = SOURCE_DIR / "mtproto" / "proxy" / "control_plane.cpp"
CONNECTION_BOX_CPP = SOURCE_DIR / "boxes" / "connection_box.cpp"
CONNECTION_BOX_H = SOURCE_DIR / "boxes" / "connection_box.h"
STATUS_TYPES_H = SOURCE_DIR / "mtproto" / "runtime" / "connection_status_types.h"
LANG = SOURCE_DIR.parent / "Resources" / "langs" / "lang.strings"


def read(path):
    assert path.exists(), f"missing expected source file: {path}"
    return path.read_text(encoding="utf-8")


def test_proxy_check_has_a_dedicated_progress_model():
    header = read(CHECK_H)
    source = read(CHECK_CPP)

    assert "enum class ProxyCheckStatus" in header
    for status in (
        "WaitingForConnectionSlot",
        "Resolving",
        "TcpConnected",
        "ClientHelloSent",
        "ServerHelloOk",
        "FirstTlsAppData",
        "FirstMtprotoPayload",
        "ConnectedByActiveSession",
    ):
        assert status in header
    assert "Fn<void(ProxyCheckStatus status)> progress" in header
    assert "ProxyCheckStatus progressStatus" in header
    assert "void SetProxyCheckProgress(" in source
    assert "state->progress = progress;" in source


def test_paced_and_rejected_probe_outcomes_are_distinct():
    start = function_body(read(CHECK_CPP), "void StartProxyCheck(")

    # A probe that has to wait for its pacing slot reports "waiting",
    # a probe the health layer refuses to register fails outright.
    assert "state->dial.delay()" in start
    assert "ProxyCheckStatus::WaitingForConnectionSlot" in start
    assert "MtProxy::MakeAttemptPlan(checkStealth)" in start


def test_proxy_check_reports_progressive_transport_phases():
    source = read(CHECK_CPP)
    start = function_body(source, "void StartProxyCheck(")
    phase_map = function_body(
        source, "ProxyCheckStatus ProxyCheckStatusForHandshake(")

    assert "&Connection::handshakeProgress" in start
    for status in (
        "ProxyCheckStatus::TcpConnected",
        "ProxyCheckStatus::ClientHelloSent",
        "ProxyCheckStatus::ServerHelloOk",
        "ProxyCheckStatus::FirstTlsAppData",
    ):
        assert status in phase_map
    assert "const auto phase = raw->handshakePhase();" in start
    assert "ProxyCheckStatusForHandshake(phase)" in start
    handshake = function_body(
        start, "raw->connect(raw, &Connection::handshakeProgress")
    assert "transportReady();" not in handshake
    assert "ProxyCheckStatus::FirstMtprotoPayload" in start
    connected = function_body(
        start, "raw->connect(raw, &Connection::connected")
    assert "ClaimProxyCheckTerminal(" in connected


def test_probe_timeout_starts_after_handoff_and_uses_network_budget():
    source = read(CHECK_CPP)
    header = read(CHECK_H)
    start = function_body(source, "void StartProxyCheck(")

    assert "ProxyStealthOptions mtproxyStealth;" in header
    assert "ProxyTlsProfile mtproxySentProfile" in header
    assert "state->mtproxyAttempt = {" in start
    assert "state->mtproxyPlan = MtProxy::MakeAttemptPlan(" in start
    assert "state->networkStarted = true;" in start
    assert "QTimer::singleShot(int(raw->fullConnectTimeout()), raw" in start
    assert start.index("state->networkStarted = true;") < start.index(
        "QTimer::singleShot(int(raw->fullConnectTimeout()), raw")
    timeout = start.split(
        "QTimer::singleShot(int(raw->fullConnectTimeout()), raw", 1)[1]
    assert "ProxyConnectionError::Timeout" in timeout


def test_probe_facts_do_not_publish_selected_main_status():
    status = read(STATUS_TYPES_H)
    control = read(CONTROL_CPP)
    reduce = function_body(
        control, "ProxyConnectionStatus ProxyControlPlane::Reduce(")

    assert "ProxyConnectionUse use = ProxyConnectionUse::Main;" in status
    assert "IsProxyCheck(fact.status.attempt.use)" in reduce
    assert "return current;" in reduce.split(
        "IsProxyCheck(fact.status.attempt.use)", 1)[1].split("}", 1)[0]


def test_probe_terminal_callbacks_reset_before_exact_lease_release():
    source = read(CHECK_CPP)
    start = function_body(source, "void StartProxyCheck(")
    finish = function_body(start, "const auto finishWithFail = [=](")
    terminal = function_body(
        finish, "if (!MtProxy::EndpointEmpty(state->mtproxyEndpoint))")
    reset = function_body(source, "void ResetProxyCheckState(")
    connected = function_body(
        start, "raw->connect(raw, &Connection::connected")

    assert "ClaimProxyCheckTerminal(runtime, state)" in terminal
    assert "state->mtproxyLease.release();" not in finish
    assert finish.index("fail(raw);") < finish.index(
        "if (state->connection.get() == raw)")
    assert finish.index("if (state->connection.get() == raw)") < finish.index(
        "ResetProxyCheckState(")
    assert connected.index("done(raw, ping);") < connected.index(
        "if (state->connection.get() == raw)")
    assert connected.index("if (state->connection.get() == raw)") < (
        connected.index("ResetProxyCheckState("))
    assert "state->dial.release();" in reset


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
    test_proxy_check_has_a_dedicated_progress_model()
    test_paced_and_rejected_probe_outcomes_are_distinct()
    test_proxy_check_reports_progressive_transport_phases()
    test_probe_timeout_starts_after_handoff_and_uses_network_budget()
    test_probe_facts_do_not_publish_selected_main_status()
    test_probe_terminal_callbacks_reset_before_exact_lease_release()
