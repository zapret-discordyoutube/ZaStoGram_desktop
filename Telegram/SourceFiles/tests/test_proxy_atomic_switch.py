from pathlib import Path


SOURCE_DIR = Path(__file__).resolve().parents[1]
MAIN_ACCOUNT_CPP = SOURCE_DIR / "main" / "main_account.cpp"
INSTANCE_H = SOURCE_DIR / "mtproto" / "mtp_instance.h"
INSTANCE_CPP = SOURCE_DIR / "mtproto" / "mtp_instance.cpp"
SESSION_H = SOURCE_DIR / "mtproto" / "session.h"
SESSION_CPP = SOURCE_DIR / "mtproto" / "session.cpp"
SESSION_PRIVATE_H = SOURCE_DIR / "mtproto" / "session_private.h"
SESSION_PRIVATE_CPP = SOURCE_DIR / "mtproto" / "session_private.cpp"
BROKER_H = SOURCE_DIR / "mtproto" / "proxy" / "connection_broker.h"
BROKER_CPP = SOURCE_DIR / "mtproto" / "proxy" / "connection_broker.cpp"
STATUS_H = SOURCE_DIR / "mtproto" / "proxy" / "status.h"
STATUS_CPP = SOURCE_DIR / "mtproto" / "proxy" / "status.cpp"
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


def test_proxy_switch_uses_atomic_migration_not_global_restart():
    account = read(MAIN_ACCOUNT_CPP)
    instance_h = read(INSTANCE_H)
    instance = read(INSTANCE_CPP)
    session_h = read(SESSION_H)
    session = read(SESSION_CPP)

    watcher = function_body(account, "void Account::watchProxyChanges()")
    assert "void migrateProxy();" in instance_h
    assert "void Instance::Private::migrateProxy()" in instance
    assert "void Instance::migrateProxy()" in instance
    assert "void migrateProxy(uint64 generation, bool scout);" in session_h
    assert "void Session::migrateProxy(" in session
    migrate = function_body(instance, "void Instance::Private::migrateProxy()")
    assert "_mtp->migrateProxy();" in watcher
    assert "_mtp->restart();" not in watcher
    assert "_mtp->reInitConnection(_mtp->mainDcId());" not in watcher
    assert "++_proxyGeneration;" in migrate
    assert "_proxyMigrationActive = true;" in migrate
    assert "ConnectionBroker::Instance().cancelByProxyGeneration(" in migrate
    assert "session->migrateProxy(" in migrate
    assert "session.get() == _mainSession" in migrate
    assert "session->restart();" not in migrate


def test_session_proxy_switch_suspends_old_generation_silently():
    header = read(SESSION_PRIVATE_H)
    source = read(SESSION_PRIVATE_CPP)
    switch_body = function_body(source, "void SessionPrivate::migrateProxy(")
    release_body = function_body(source, "void SessionPrivate::releaseProxyMigration(")
    append_body = function_body(source, "bool SessionPrivate::appendTestConnection(")
    connect_body = function_body(source, "void SessionPrivate::connectToServer(")
    received_body = function_body(source, "void SessionPrivate::handleReceived()")
    disconnected_body = function_body(source, "void SessionPrivate::onDisconnected(")
    error_body = function_body(source, "void SessionPrivate::onError(")

    assert "void migrateProxy(uint64 generation, bool scout);" in header
    assert "void releaseProxyMigration(uint64 generation);" in header
    assert "uint64 _proxyGeneration = 0;" in header
    assert "bool _proxyMigrationSuspended = false;" in header
    assert "bool _proxyMigrationScout = false;" in header
    assert "destroyAllConnections();" in switch_body
    assert "_retryTimer.cancel();" in switch_body
    assert "suspended_by_proxy_switch" in switch_body
    assert "if (!scout) {" in switch_body
    assert "connectToServer();" in switch_body
    assert "ProxyControlPlane::ReportMtproxyFailure" not in switch_body
    assert "restart();" not in switch_body
    assert "setState(-_retryTimeout)" not in switch_body
    assert "if (_proxyMigrationSuspended) {" in connect_body
    assert "_proxyMigrationScout" in append_body
    assert "_connectionBrokerTickets.empty()" in append_body
    assert ".proxyGeneration = _proxyGeneration" in append_body
    assert "_instance->proxyMigrationSucceeded(_proxyGeneration);" in received_body
    assert "_proxyMigrationScout = false;" in received_body
    assert "_proxyMigrationSuspended = false;" in release_body
    assert "connectToServer();" in release_body
    assert "found == end(_testConnections)" in disconnected_body
    assert "_connection.get() != connection.get()" in disconnected_body
    assert disconnected_body.index("_connection.get() != connection.get()") < (
        disconnected_body.index("restart();"))
    assert "found == end(_testConnections)" in error_body
    assert "_connection.get() != connection.get()" in error_body
    assert error_body.index("_connection.get() != connection.get()") < (
        error_body.index("handleError(errorCode);"))


def test_broker_cancels_old_proxy_generation_tickets():
    header = read(BROKER_H)
    source = read(BROKER_CPP)
    request_state = source.split("struct ConnectionBroker::RequestState {", 1)[1].split("};", 1)[0]
    cancel_body = function_body(source, "void ConnectionBroker::cancelByProxyGeneration(")
    start_body = function_body(source, "void ConnectionBroker::start(")

    assert "uint64 proxyGeneration = 0;" in header
    assert "void cancelByProxyGeneration(" in header
    assert "uint64 proxyGeneration = 0;" in request_state
    assert "state->proxyGeneration = state->request.proxyGeneration;" in source
    assert "state->request.instance == instance" in cancel_body
    assert "state->proxyGeneration < generation" in cancel_body
    assert "state->active = false;" in cancel_body
    assert "AdmissionCancelled" in cancel_body
    assert "start.proxyGeneration = state->proxyGeneration;" in start_body


def test_status_reducer_shadows_old_proxy_generation_facts():
    status_h = read(STATUS_H)
    status = read(STATUS_CPP)
    diagnostics = read(DIAGNOSTICS_CPP)

    assert "uint64 proxyGeneration = 0;" in status_h
    assert "proxyGeneration == other.proxyGeneration" in status_h
    assert "update.proxyGeneration != current.proxyGeneration" in status
    assert "update.proxyGeneration > current.proxyGeneration" in status
    assert "!update.proxyGeneration" in status
    assert "update.proxyGeneration < current.proxyGeneration" in status
    assert "generation=%1" in diagnostics


if __name__ == "__main__":
    test_proxy_switch_uses_atomic_migration_not_global_restart()
    test_session_proxy_switch_suspends_old_generation_silently()
    test_broker_cancels_old_proxy_generation_tickets()
    test_status_reducer_shadows_old_proxy_generation_facts()
