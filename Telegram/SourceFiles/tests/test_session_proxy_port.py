from pathlib import Path
from session_private_sources import read_session_private_sources


SOURCE_DIR = Path(__file__).resolve().parents[1]
ROOT = SOURCE_DIR.parents[1]
CMAKE = ROOT / "Telegram" / "CMakeLists.txt"
MTPROTO_DIR = SOURCE_DIR / "mtproto"
SESSION_PRIVATE_DIR = MTPROTO_DIR / "session" / "private"
PROXY_DIR = MTPROTO_DIR / "proxy"

PROXY_PORT_H = SESSION_PRIVATE_DIR / "proxy_port.h"
PROXY_PORT_CPP = SESSION_PRIVATE_DIR / "proxy_port.cpp"
PROXY_ADAPTER_H = PROXY_DIR / "session_proxy_adapter.h"
PROXY_ADAPTER_CPP = PROXY_DIR / "session_proxy_adapter.cpp"


SESSION_PRIVATE_BANNED_TOKENS = (
    '#include "mtproto/proxy/connection_broker.h"',
    '#include "mtproto/proxy/control_plane.h"',
    "ConnectionBroker::Instance()",
    "ProxyControlPlane::",
    "ReportProxyEvent(",
    "WriteProxyDiagnosticsLine(",
)


def read(path):
    assert path.exists(), f"missing expected source file: {path}"
    return path.read_text(encoding="utf-8")


def function_body(source, signature):
    start = source.index(signature)
    brace = source.index("{", start)
    depth = 0
    for index in range(brace, len(source)):
        if source[index] == "{":
            depth += 1
        elif source[index] == "}":
            depth -= 1
            if depth == 0:
                return source[brace:index + 1]
    raise AssertionError(f"function body not found: {signature}")


def test_session_proxy_port_files_are_registered():
    cmake = read(CMAKE)

    for path in (
            PROXY_PORT_H,
            PROXY_PORT_CPP,
            PROXY_ADAPTER_H,
            PROXY_ADAPTER_CPP):
        relative = path.relative_to(SOURCE_DIR).as_posix()
        assert relative in cmake


def test_session_private_uses_only_proxy_port_for_proxy_globals():
    session_sources = read_session_private_sources()
    port_header = read(PROXY_PORT_H)

    assert "class SessionProxyPort" in port_header
    assert "DefaultSessionProxyPort()" in port_header
    assert "requestConnection(" in port_header
    assert "reportConnected(" in port_header
    assert "reportFirstMtprotoPayload(" in port_header
    first_payload = port_header.split("reportFirstMtprotoPayload(", 1)[1]
    assert "SessionProxyLease *lease" in first_payload.split(") = 0;", 1)[0]
    assert "reportConnectionError(" in port_header
    assert "reportReceiveTimeout(" in port_header
    assert "reportConnectTimeout(" in port_header
    assert "reportAttemptCancelled(" in port_header
    assert "virtual void transportReady() = 0;" in port_header
    assert "void transportReady();" in port_header
    assert "virtual void openingTerminal(" in port_header
    assert "void openingTerminal(" in port_header
    assert "slotKey()" not in port_header
    assert "struct SessionProxyStart" in port_header
    assert "struct SessionProxyRequest" in port_header
    lease = port_header.split("class SessionProxyLease final", 1)[1].split(
        "struct SessionProxyAttempt", 1)[0]
    start = port_header.split("struct SessionProxyStart", 1)[1].split(
        "struct SessionProxyRequest", 1)[0]
    request = port_header.split("struct SessionProxyRequest", 1)[1].split(
        "class SessionProxyTicket", 1)[0]
    assert "SessionProxyLease(const SessionProxyLease &other) = delete;" in lease
    assert "DialSlotKey" not in lease
    assert "DialSlotKey" not in start
    assert "slotKey" not in start
    assert "AdmissionPurpose" not in request
    assert "reclaim" not in request
    assert "DialSlotKey" not in request
    receive_timeout = port_header.split("reportReceiveTimeout(", 1)[1].split(
        ") = 0;", 1)[0]
    connect_timeout = port_header.split("reportConnectTimeout(", 1)[1].split(
        ") = 0;", 1)[0]
    assert "SessionProxyLease *lease" in receive_timeout
    assert "SessionProxyLease *lease" in connect_timeout
    assert "logEvent(" in port_header
    assert "releaseAdmissionForRelayCandidate" not in port_header
    assert "retireMtproxyRelayProof" not in port_header
    assert "RelayProofReport" not in port_header
    assert "applyMtproxyProxyGeneration" not in port_header

    for token in SESSION_PRIVATE_BANNED_TOKENS:
        assert token not in session_sources

    assert "SessionProxyPort" in session_sources
    assert "_proxyPort->" in session_sources
    assert "retireMtproxyRelayProof" not in session_sources
    assert "applyMtproxyProxyGeneration" not in session_sources


def test_proxy_adapter_is_the_only_session_proxy_global_caller():
    adapter_h = read(PROXY_ADAPTER_H)
    adapter_cpp = read(PROXY_ADAPTER_CPP)
    relay_report = function_body(
        adapter_cpp,
        "MtProxy::RelayProofReport RelayProofReport(")
    cancelled = function_body(
        adapter_cpp,
        "void ProductionSessionProxyPort::reportAttemptCancelled(")
    stalled = function_body(
        adapter_cpp,
        "void ProductionSessionProxyPort::reportRelayStall(")
    connection_error = function_body(
        adapter_cpp,
        "void ProductionSessionProxyPort::reportConnectionError(")
    receive_timeout = function_body(
        adapter_cpp,
        "void ProductionSessionProxyPort::reportReceiveTimeout(")
    connect_timeout = function_body(
        adapter_cpp,
        "void ProductionSessionProxyPort::reportConnectTimeout(")
    generation_cancel = function_body(
        adapter_cpp,
        "void ProductionSessionProxyPort::cancelByProxyGeneration(")
    ready = function_body(adapter_cpp, "void transportReady() override")
    terminal = function_body(adapter_cpp, "void openingTerminal(")
    broker_request = function_body(
        adapter_cpp, "ConnectionRequest ToBrokerRequest(")

    assert '#include "mtproto/session/private/proxy_port.h"' not in adapter_h
    assert "public SessionProxyPort" not in adapter_h
    assert '#include "mtproto/session/private/proxy_port.h"' in adapter_cpp
    assert "class ProductionSessionProxyPort final" in adapter_cpp
    assert "releaseAdmissionForRelayCandidate" not in adapter_cpp
    assert "DefaultSessionProxyPort()" in adapter_cpp
    assert "proxyServices().broker().request(" in adapter_cpp
    assert "proxyServices().broker().cancelByProxyGeneration(" in adapter_cpp
    assert "proxyServices().control().reportMtproxySuccess(" in adapter_cpp
    assert "proxyServices().control().reportMtproxyFailure(" in adapter_cpp
    assert "proxyServices().control().noteMtproxyRelayStall(" in adapter_cpp
    assert "proxyServices().control().retireMtproxyRelayProof(" in adapter_cpp
    assert ").mtproxyEndpointSnapshot(endpoint)" in adapter_cpp
    assert "ReportProxyEvent(" in adapter_cpp
    assert "WriteProxyDiagnosticsLine(" in adapter_cpp
    assert "_lease.transportReady();" in ready
    assert "_lease.release();" not in ready
    assert "_lease.openingTerminal(reason, finalEndpointTerminal);" in terminal
    assert ".lease = SessionProxyLease(" in broker_request
    assert "std::move(value.lease)" in broker_request
    assert ".purpose = request.purpose" not in broker_request
    assert ".reclaim = std::move(request.reclaim)" not in broker_request
    assert ".slotKey =" not in broker_request
    assert "start.slotKey" not in broker_request
    assert "value.slotKey" not in broker_request

    for field in (
            ".endpoint = attempt.endpoint",
            ".use = attempt.use",
            ".runtimeId = attempt.attempt.runtimeId",
            ".proxyGeneration = attempt.attempt.proxyGeneration",
            ".attemptId = attempt.attempt.attemptId",
            ".proxyEpoch = attempt.attempt.proxyEpoch",
            ".successEpoch = attempt.attempt.successEpoch",
            ".attemptStartedAt = attempt.attemptStartedAt"):
        assert field in relay_report
    assert "RelayProofReport(attempt)" in cancelled
    assert "RelayProofReport(attempt)" in stalled
    assert "RelayProofReport(attempt)" in connection_error
    assert adapter_cpp.count("RelayProofReport(attempt)") == 3
    assert cancelled.index("retireMtproxyRelayProof(") < cancelled.index(
        "ReportProxyAttemptSummary(")
    assert "noteMtproxyRelayStall(" in stalled
    healthy = connection_error.index(
        "if (snapshot.healthy && !snapshot.halfOpen && postTerminal) {")
    retirement = connection_error.index("retireMtproxyRelayProof(")
    liveness = connection_error.index("ReportProxyLiveness(")
    assert healthy < retirement < liveness
    for body in (connection_error, receive_timeout, connect_timeout):
        assert "IsSessionOpeningTerminal(" in body
        assert body.index("ReportConnectionFailure(") < body.index(
            "lease->openingTerminal(")
        assert "true" in body.split("lease->openingTerminal(", 1)[1]

    assert "proxyServices().broker().cancelByProxyGeneration(" in (
        generation_cancel)
    assert "proxyServices().control()" not in generation_cancel
    assert "applyMtproxyProxyGeneration" not in generation_cancel


if __name__ == "__main__":
    test_session_proxy_port_files_are_registered()
    test_session_private_uses_only_proxy_port_for_proxy_globals()
    test_proxy_adapter_is_the_only_session_proxy_global_caller()
