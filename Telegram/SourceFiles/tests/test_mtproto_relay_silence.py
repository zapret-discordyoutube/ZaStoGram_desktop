from pathlib import Path
from session_private_sources import read_session_private_sources


SOURCE_DIR = Path(__file__).resolve().parents[1]
MTPROXY_DIR = SOURCE_DIR / "mtproto" / "proxy" / "mtproxy"
ENDPOINT_IDENTITY_H = MTPROXY_DIR / "endpoint_identity.h"
ENDPOINT_IDENTITY_CPP = MTPROXY_DIR / "endpoint_identity.cpp"
RUNTIME_PROXY_ENDPOINT_H = (
    SOURCE_DIR / "mtproto" / "runtime" / "proxy_endpoint.h")
TLS_SOCKET_CPP = MTPROXY_DIR / "tls_socket.cpp"
TLS_SOCKET_RECORDS_CPP = MTPROXY_DIR / "tls_socket_records.cpp"
STATUS_H = SOURCE_DIR / "mtproto" / "proxy" / "status.h"
STATUS_CPP = SOURCE_DIR / "mtproto" / "proxy" / "status.cpp"
DIAGNOSTICS_CPP = SOURCE_DIR / "mtproto" / "proxy" / "diagnostics.cpp"
SESSION_CPP = SOURCE_DIR / "mtproto" / "session" / "private" / "session_private.cpp"
SESSION_H = SOURCE_DIR / "mtproto" / "session" / "private" / "session_private.h"
CONNECTION_CPP = SOURCE_DIR / "mtproto" / "session" / "private" / "connection.cpp"
RECEIVE_CPP = SOURCE_DIR / "mtproto" / "session" / "private" / "receive.cpp"
TRANSPORT_H = SOURCE_DIR / "mtproto" / "session" / "private" / "transport.h"


def read(path):
    assert path.exists(), f"missing expected source file: {path}"
    return path.read_text(encoding="utf-8")


def read_endpoint_health_sources():
    return "\n".join(read(path) for path in (
        ENDPOINT_HEALTH_CPP,
        ENDPOINT_HEALTH_LIFECYCLE_CPP,
    ))


def function_body(source, signature):
    start = source.index(signature)
    brace = source.index("{", start)
    depth = 0
    for i in range(brace, len(source)):
        if source[i] == "{":
            depth += 1
        elif source[i] == "}":
            depth -= 1
            if depth == 0:
                return source[brace:i + 1]
    raise AssertionError(f"function body not found: {signature}")


def test_relay_silence_reason_is_wired_through_all_mappings():
    endpoint_h = read(RUNTIME_PROXY_ENDPOINT_H)
    identity = read(ENDPOINT_IDENTITY_CPP)
    status_h = read(STATUS_H)
    status_cpp = read(STATUS_CPP)
    diagnostics = read(DIAGNOSTICS_CPP)

    assert "ConnectedNoMtprotoData," in endpoint_h
    assert "ConnectedNoMtprotoData," in status_h

    legacy = function_body(identity, "QString ToLegacyDiagnostic(")
    assert "connected_no_mtproto_data" in legacy

    terminal = function_body(
        identity, "ProxyMtproxyTerminalReason ToProxyMtproxyTerminalReason(")
    assert ("return ProxyMtproxyTerminalReason::ConnectedNoMtprotoData;"
        in terminal)

    reason_text = function_body(
        diagnostics, "QString MtproxyReasonText(")
    assert "connected_no_mtproto_data" in reason_text

    kind = function_body(
        status_cpp, "ProxyConnectionStatusKind ProxyConnectionStatusKindFor(")
    assert "case ProxyMtproxyTerminalReason::ConnectedNoMtprotoData:" in kind


def test_session_reports_silence_and_recovers_temporary_key():
    session = read_session_private_sources()
    connection = read(CONNECTION_CPP)
    header = read(TRANSPORT_H)
    wait_received = function_body(
        session, "void SessionTransport::waitReceivedFailed(")
    destroy_all = function_body(
        session, "void SessionTransport::destroyAllConnections(")
    connected = function_body(session, "void SessionTransport::onConnected(")
    append = function_body(
        session, "bool SessionTransport::appendTestConnection(")
    confirm = function_body(
        session,
        "void SessionTransport::confirmBestConnection()")

    assert "bool mtprotoDataReceived = false;" in header
    assert "int mtprotoSilentTimeouts = 0;" in header
    assert "_state.mtprotoDataReceived = false;" in destroy_all
    assert "canProveMtproxyRelay" not in session
    assert "&AbstractConnection::handshakeProgress" not in append
    assert "SessionTransport::onHandshakeProgress(" not in session
    assert (
        '#include "mtproto/transport/details/mtproto_abstract_socket.h"'
        in connection)
    assert "transportReady();" not in connected
    assert "reportMtproxyConnectionUsable" not in connected
    assert "transportReady();" not in confirm
    assert "reportMtproxyConnectionUsable" not in confirm
    assert "transportReady();" not in connection

    # A connection that connects (even passing the plaintext fake-pq
    # check) but never delivers an MTProto payload reports relay silence,
    # and repeated silence is treated like an explicit -404: the server
    # may drop packets of a discarded temporary key without answering.
    assert "kSilentTimeoutsToAssumeKeyDestroyed" in session
    assert "return _owner->destroyTemporaryKey();" in wait_received

    # Only a handled MTProto message resets the per-session silence counter.
    # Ordinary sessions do not feed endpoint health, because that would bring
    # the shared cooldown and admission policy back into the data plane.
    transport = read(
        SOURCE_DIR / "mtproto" / "session" / "private" / "transport.cpp")
    note_payload = function_body(
        transport,
        "void SessionTransport::noteMtprotoPayloadReceived()")
    assert "_state.mtprotoSilentTimeouts = 0;" in note_payload
    assert "_proxyPort" not in note_payload
    assert "markProxyMtprotoPayloadReceived();" in note_payload


def test_established_idle_close_is_not_a_health_failure():
    tls_socket = read(TLS_SOCKET_CPP)
    session = read_session_private_sources()
    handle_error = function_body(
        tls_socket, "void TlsSocket::handleError(int errorCode)")
    finish_terminal = function_body(
        tls_socket, "bool TlsSocket::finishTerminal(")
    disconnected = function_body(
        session,
        "void SessionTransport::onDisconnected(")
    destroy = function_body(
        session,
        "void SessionTransport::destroyAllConnections(")
    on_error = function_body(
        session,
        "void SessionTransport::onError(")

    # Proxies close idle established connections routinely; only a close
    # shortly after the handshake may count against endpoint health.
    assert "kEstablishedIdleCloseAge" in tls_socket
    assert "benignIdleClose" in finish_terminal
    assert "_firstAppDataAt" in finish_terminal
    assert finish_terminal.index("benignIdleClose") < finish_terminal.index(
        "clearSyntheticPskOnFailure(reason)")
    assert "destroyAllConnections();" in disconnected
    assert "reportAttemptCancelled(" not in destroy
    assert "mtproxyLease" not in destroy
    assert "reportConnectionError(" not in on_error
    assert "removeTestConnection(connection);" in on_error


if __name__ == "__main__":
    test_relay_silence_reason_is_wired_through_all_mappings()
    test_session_reports_silence_and_recovers_temporary_key()
    test_established_idle_close_is_not_a_health_failure()
