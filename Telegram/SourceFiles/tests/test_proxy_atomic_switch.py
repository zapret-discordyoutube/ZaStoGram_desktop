from pathlib import Path
from session_private_sources import read_session_private_sources


SOURCE_DIR = Path(__file__).resolve().parents[1]
APPLICATION_CPP = SOURCE_DIR / "core" / "application.cpp"
MAIN_ACCOUNT_CPP = SOURCE_DIR / "main" / "main_account.cpp"
INSTANCE_H = SOURCE_DIR / "mtproto" / "instance" / "mtp_instance.h"
INSTANCE_CPP = SOURCE_DIR / "mtproto" / "instance" / "mtp_instance.cpp"
SESSION_H = SOURCE_DIR / "mtproto" / "session" / "session.h"
SESSION_CPP = SOURCE_DIR / "mtproto" / "session" / "session.cpp"
SESSION_TRANSPORT_H = SOURCE_DIR / "mtproto" / "session" / "private" / "transport.h"
SESSION_TRANSPORT_CPP = SOURCE_DIR / "mtproto" / "session" / "private" / "transport.cpp"
SESSION_PRIVATE_CPP = SOURCE_DIR / "mtproto" / "session" / "private" / "session_private.cpp"
STATUS_H = SOURCE_DIR / "mtproto" / "proxy" / "status.h"
STATUS_CPP = SOURCE_DIR / "mtproto" / "proxy" / "status.cpp"
STATUS_TYPES_H = SOURCE_DIR / "mtproto" / "runtime" / "connection_status_types.h"
CONTROL_CPP = SOURCE_DIR / "mtproto" / "proxy" / "control_plane.cpp"
DIAGNOSTICS_CPP = SOURCE_DIR / "mtproto" / "proxy" / "diagnostics.cpp"


def read(path):
    assert path.exists(), f"missing expected source file: {path}"
    return path.read_text(encoding="utf-8")


def function_body(text, signature):
    start = text.index(signature)
    brace = text.index("{", start)
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


def test_reapplying_selected_proxy_keeps_live_connections():
    application = read(APPLICATION_CPP)
    apply_proxy = function_body(application, "void Application::setCurrentProxy(")
    explicit_restart = function_body(
        application,
        "void Application::restartProxyConnections(")

    assert "if (was != now) {" in apply_proxy
    assert apply_proxy.index("if (was != now) {") < apply_proxy.index(
        "_proxyChanges.fire({ was, now, manual });")
    # A blanket restart is not a user selection, so it must not carry the
    # manual flag that resets a proxy's cooldown penalty.
    assert "_proxyChanges.fire({ current, current, false });" in (
        explicit_restart)


def test_session_proxy_switch_reconnects_every_lane_immediately():
    header = read(SESSION_TRANSPORT_H)
    source = read_session_private_sources()
    switch_body = function_body(source, "void SessionTransport::migrateProxy(")
    append_body = function_body(source, "bool SessionTransport::appendTestConnection(")
    connect_body = function_body(
        source, "void SessionTransport::connectToServer(bool afterConfig)")
    received_body = function_body(source, "void SessionMessageHandler::handleReceived()")
    payload_body = function_body(source, "void SessionTransport::noteMtprotoPayloadReceived()")
    disconnected_body = function_body(source, "void SessionTransport::onDisconnected(")
    error_body = function_body(source, "void SessionTransport::onError(")

    assert "void migrateProxy(uint64 generation);" in header
    assert "releaseProxyMigration" not in header
    assert "uint64 proxyGeneration = 0;" in header
    assert "proxyMigrationSuspended" not in header
    assert "proxyMigrationScout" not in header
    assert "destroyAllConnections(ProxyCloseOrigin::ProxySwitch);" in switch_body
    assert "_timing.retryTimer.cancel();" in switch_body
    assert "proxy_route_changed" in switch_body
    assert "suspended_by_proxy_switch" not in switch_body
    assert "connectToServer();" in switch_body
    assert "ProxyControlPlane::ReportMtproxyFailure" not in switch_body
    assert "restart();" not in switch_body
    assert "setState(-_timing.retryTimeout)" not in switch_body
    assert "proxyMigrationSuspended" not in connect_body
    assert "_owner->_proxyPort->requestConnection({" not in append_body
    assert "ReserveHandshakeGateForProxy" not in append_body
    assert ".proxyGeneration = _state.proxyGeneration" in append_body
    assert "_owner->_transport.noteMtprotoPayloadReceived();" in received_body
    assert "_owner->_transport._state" not in received_body
    assert "proxyMigrationScout" not in payload_body
    assert "proxyMigrationSucceeded" not in payload_body
    assert "found == end(_state.testConnections)" in disconnected_body
    assert "_state.connection.get() != connection.get()" in disconnected_body
    assert disconnected_body.index("_state.connection.get() != connection.get()") < (
        disconnected_body.index("restart();"))
    assert "found == end(_state.testConnections)" in error_body
    assert "_state.connection.get() != connection.get()" in error_body
    assert error_body.index("_state.connection.get() != connection.get()") < (
        error_body.index("handleError(errorCode);"))


def test_new_sessions_inherit_current_proxy_generation():
    instance = read(INSTANCE_CPP)
    session_header = read(SESSION_H)
    session = read(SESSION_CPP)
    transport_header = read(SESSION_TRANSPORT_H)
    transport = read(SESSION_TRANSPORT_CPP)
    private = read(SESSION_PRIVATE_CPP)
    start_session = function_body(
        instance,
        "not_null<Session*> Instance::Private::startSession(")
    start = function_body(session, "void Session::start()")
    transport_constructor = function_body(
        transport,
        "SessionTransport::SessionTransport(")

    assert "uint64 proxyGeneration" in session_header
    assert "proxyMigrationScout" not in session_header
    assert "proxyMigrationSuspended" not in session_header
    assert "_proxyGeneration);" in start
    assert "proxyGeneration" in private
    assert "proxyMigrationScout" not in private
    assert "proxyMigrationSuspended" not in private
    assert "uint64 proxyGeneration" in transport_header
    assert "_state.proxyGeneration = proxyGeneration;" in transport_constructor
    assert "_proxyGeneration)" in start_session
    assert "&& !_mainSession" not in start_session
    assert "shiftedDcId == mainDcId()" not in start_session
    assert "result->migrateProxy(" not in start_session


def test_status_reducer_shadows_old_proxy_generation_facts():
    status_h = read(STATUS_H)
    status_types_h = read(STATUS_TYPES_H)
    status = read(STATUS_CPP)
    control = read(CONTROL_CPP)
    diagnostics = read(DIAGNOSTICS_CPP)

    assert '#include "mtproto/runtime/connection_status_types.h"' in status_h
    assert "uint64 proxyGeneration = 0;" in status_types_h
    assert "proxyGeneration == other.proxyGeneration" in status_types_h
    assert "update.proxyGeneration != current.proxyGeneration" in control
    assert "update.proxyGeneration > current.proxyGeneration" in control
    assert "!update.proxyGeneration" in control
    assert "update.proxyGeneration < current.proxyGeneration" in control
    assert "ApplyProxyConnectionStatusUpdate(" not in status
    assert "generation=%1" in diagnostics
