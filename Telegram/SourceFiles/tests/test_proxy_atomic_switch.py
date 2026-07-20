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
BROKER_H = SOURCE_DIR / "mtproto" / "proxy" / "connection_broker.h"
BROKER_CPP = SOURCE_DIR / "mtproto" / "proxy" / "connection_broker.cpp"
ARBITER_CPP = SOURCE_DIR / "mtproto" / "proxy" / "endpoint_admission_arbiter.cpp"
LIVE_POOL_CPP = SOURCE_DIR / "mtproto" / "proxy" / "endpoint_live_pool.cpp"
STATUS_H = SOURCE_DIR / "mtproto" / "proxy" / "status.h"
STATUS_CPP = SOURCE_DIR / "mtproto" / "proxy" / "status.cpp"
STATUS_TYPES_H = SOURCE_DIR / "mtproto" / "runtime" / "connection_status_types.h"
CONTROL_CPP = SOURCE_DIR / "mtproto" / "proxy" / "control_plane.cpp"
DIAGNOSTICS_CPP = SOURCE_DIR / "mtproto" / "proxy" / "diagnostics.cpp"
PROXY_ADAPTER_CPP = SOURCE_DIR / "mtproto" / "proxy" / "session_proxy_adapter.cpp"
ENDPOINT_HEALTH_LIFECYCLE_CPP = (
    SOURCE_DIR / "mtproto" / "proxy" / "mtproxy" /
    "endpoint_health_lifecycle.cpp")
ENDPOINT_HEALTH_STATE_H = (
    SOURCE_DIR / "mtproto" / "proxy" / "mtproxy" / "endpoint_health_state.h")


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
    control = read(CONTROL_CPP)
    adapter = read(PROXY_ADAPTER_CPP)
    health_lifecycle = read(ENDPOINT_HEALTH_LIFECYCLE_CPP)
    health_state = read(ENDPOINT_HEALTH_STATE_H)
    session_h = read(SESSION_H)
    session = read(SESSION_CPP)

    watcher = function_body(account, "void Account::watchProxyChanges()")
    assert "void migrateProxy(bool manual = true);" in instance_h
    assert "void Instance::Private::migrateProxy(bool manual)" in instance
    assert "void Instance::migrateProxy(bool manual)" in instance
    assert "void migrateProxy(uint64 generation, bool scout);" in session_h
    assert "void Session::migrateProxy(" in session
    migrate = function_body(instance, "void Instance::Private::migrateProxy(bool manual)")
    assert "_mtp->migrateProxy(change.manual);" in watcher
    assert "_mtp->restart();" not in watcher
    assert "_mtp->reInitConnection(_mtp->mainDcId());" not in watcher
    assert "++_proxyGeneration;" in migrate
    assert "_proxyMigrationActive = true;" in migrate
    assert "_runtime->proxyServices().broker().cancelByProxyGeneration(" in migrate
    assert "session->migrateProxy(" in migrate
    assert "session.get() == _mainSession" in migrate
    assert "session->restart();" not in migrate
    generation_cleanup = migrate.index(
        "_runtime->proxyServices().control().applyMtproxyProxyGeneration(")
    generation_increment = migrate.index("++_proxyGeneration;")
    status_publication = migrate.index("_connectionStatus->setProxyStatus({")
    broker_cancellation = migrate.index(
        "_runtime->proxyServices().broker().cancelByProxyGeneration(")
    session_migration = migrate.index("session->migrateProxy(")
    assert generation_increment < generation_cleanup < status_publication
    assert generation_cleanup < broker_cancellation < session_migration
    assert migrate.count("applyMtproxyProxyGeneration(") == 1
    assert "applyMtproxyProxyGeneration(" not in adapter

    apply_generation = function_body(
        health_lifecycle,
        "void EndpointHealth::applyProxyGeneration(")
    runtime_generation = function_body(
        health_state,
        "void ApplyRuntimeProxyGeneration(")
    control_forwarder = function_body(
        control,
        "void ProxyControlPlane::applyMtproxyProxyGeneration(")
    assert "endpointAdmissionArbiter().cancelBeforeGeneration(" in (
        apply_generation)
    assert "_runtimeId" in apply_generation
    assert "_endpointHealth->applyProxyGeneration(proxyGeneration);" in (
        control_forwarder)
    assert "i->first.runtimeId == runtimeId" in runtime_generation
    assert "i->first.proxyGeneration < proxyGeneration" in runtime_generation
    assert "SynchronizeRelayProofAggregate(state);" in runtime_generation
    succeeded = function_body(
        instance,
        "void Instance::Private::proxyMigrationSucceeded(")
    assert "session->releaseProxyMigration(generation);" in succeeded
    assert "session.get() != _mainSession" not in succeeded


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


def test_session_proxy_switch_suspends_old_generation_silently():
    header = read(SESSION_TRANSPORT_H)
    source = read_session_private_sources()
    switch_body = function_body(source, "void SessionTransport::migrateProxy(")
    release_body = function_body(source, "void SessionTransport::releaseProxyMigration(")
    append_body = function_body(source, "bool SessionTransport::appendTestConnection(")
    connect_body = function_body(
        source,
        "void SessionTransport::connectToServer(\n"
        "\t\tbool afterConfig,\n"
        "\t\tMtProxy::AdmissionPurpose purpose)")
    received_body = function_body(source, "void SessionMessageHandler::handleReceived()")
    payload_body = function_body(source, "void SessionTransport::noteMtprotoPayloadReceived()")
    disconnected_body = function_body(source, "void SessionTransport::onDisconnected(")
    error_body = function_body(source, "void SessionTransport::onError(")

    assert "void migrateProxy(uint64 generation, bool scout);" in header
    assert "void releaseProxyMigration(uint64 generation);" in header
    assert "uint64 proxyGeneration = 0;" in header
    assert "bool proxyMigrationSuspended = false;" in header
    assert "bool proxyMigrationScout = false;" in header
    assert "destroyAllConnections(ProxyCloseOrigin::ProxySwitch);" in switch_body
    assert "_timing.retryTimer.cancel();" in switch_body
    assert "suspended_by_proxy_switch" in switch_body
    assert "if (!scout) {" in switch_body
    assert "connectToServer();" in switch_body
    assert "ProxyControlPlane::ReportMtproxyFailure" not in switch_body
    assert "restart();" not in switch_body
    assert "setState(-_timing.retryTimeout)" not in switch_body
    assert "if (_state.proxyMigrationSuspended) {" in connect_body
    assert "_state.proxyMigrationScout" in append_body
    assert "_state.brokerTickets.empty()" in append_body
    assert ".proxyGeneration = _state.proxyGeneration" in append_body
    assert "_owner->_transport.noteMtprotoPayloadReceived();" in received_body
    assert "_owner->_transport._state" not in received_body
    assert "_state.proxyMigrationScout = false;" in payload_body
    assert "const auto generation = _state.proxyGeneration;" in payload_body
    assert "InvokeQueued(_owner->_instance, [" in payload_body
    assert "delegate->proxyMigrationSucceeded(generation);" in payload_body
    assert "_state.proxyMigrationSuspended = false;" in release_body
    assert "connectToServer();" in release_body
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
    assert "bool proxyMigrationScout" in session_header
    assert "bool proxyMigrationSuspended" in session_header
    assert "_proxyGeneration," in start
    assert "_proxyMigrationScout," in start
    assert "_proxyMigrationSuspended" in start
    assert "proxyGeneration" in private
    assert "proxyMigrationScout" in private
    assert "proxyMigrationSuspended" in private
    assert "uint64 proxyGeneration" in transport_header
    assert "_state.proxyGeneration = proxyGeneration;" in transport_constructor
    assert "_state.proxyMigrationScout = proxyMigrationScout;" in (
        transport_constructor)
    assert "_state.proxyMigrationSuspended = proxyMigrationSuspended;" in (
        transport_constructor)
    assert "_proxyGeneration," in start_session
    assert "proxyMigrationScout," in start_session
    assert "proxyMigrationSuspended" in start_session
    assert "&& !_mainSession" not in start_session
    assert "shiftedDcId == mainDcId()" in start_session
    assert "result->migrateProxy(" not in start_session


def test_broker_cancels_old_proxy_generation_tickets():
    header = read(BROKER_H)
    source = read(BROKER_CPP)
    arbiter = read(ARBITER_CPP)
    cancel_body = function_body(source, "void ConnectionBroker::cancelByProxyGeneration(")
    generation_cancel = function_body(
        arbiter,
        "void EndpointAdmissionArbiter::Private::cancelBeforeGeneration(")
    pool_cleanup = function_body(
        read(LIVE_POOL_CPP),
        "LiveSlotsCloseReduction CloseLiveSlotsBeforeGeneration(")
    close_matching = function_body(
        read(LIVE_POOL_CPP), "LiveSlotsCloseReduction CloseMatchingSlots(")
    lease_release = function_body(
        read(ENDPOINT_HEALTH_LIFECYCLE_CPP),
        "void EndpointAttemptLease::release()")

    assert "uint64 proxyGeneration = 0;" in header
    assert "void cancelByProxyGeneration(" in header
    assert "cancelBeforeGeneration(" in cancel_body
    assert "_runtime->proxyRuntimeId()" in cancel_body
    assert "ticket->proxyGeneration < proxyGeneration" in generation_cancel
    assert "postGenerationCancelledStatusLocked(" in generation_cancel
    assert "cancelTicketLocked(key, 0, actions);" in generation_cancel
    assert "MtProxy::ApplyRuntimeProxyGeneration(" in generation_cancel
    assert "closeSlotsBeforeGenerationLocked(" in generation_cancel
    assert "attempt.proxyGeneration < request.proxyGeneration" in pool_cleanup
    assert generation_cancel.index(
        "MtProxy::ApplyRuntimeProxyGeneration("
    ) < generation_cancel.index("closeSlotsBeforeGenerationLocked(")
    assert "slot.phase = LiveSlotPhase::Closing;" in close_matching
    assert ".resumePurpose = std::nullopt" in close_matching
    assert "ReleaseLiveSlot(" not in pool_cleanup
    assert "endpointAdmissionArbiter().releaseLiveSlot(" in lease_release
    assert lease_release.index("cancelEndpointAttempt(") < lease_release.index(
        "releaseLiveSlot(")
    assert "ProxySchedulerLifecycle::Cancelled" in arbiter
    assert ".proxyGeneration = grant.proxyGeneration" in source


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


def test_manual_selection_uses_normal_generation_migration_without_scout():
    instance = read(INSTANCE_CPP)
    lifecycle = read(SOURCE_DIR / "mtproto" / "proxy" / "mtproxy" /
        "endpoint_health_lifecycle.cpp")
    control = read(CONTROL_CPP)
    arbiter = read(ARBITER_CPP)
    migrate = function_body(instance, "void Instance::Private::migrateProxy(bool manual)")
    selected = function_body(
        control, "void ProxyControlPlane::noteMtproxyEndpointSelected(")

    assert "noteMtproxyEndpointSelected(" in migrate
    assert "selected.type == ProxyData::Type::Mtproto" in migrate
    assert "void migrateProxy(bool manual)" in instance
    assert "manual && selected" in migrate
    assert migrate.index("applyMtproxyProxyGeneration(") < migrate.index(
        "noteMtproxyEndpointSelected(")
    assert migrate.index("noteMtproxyEndpointSelected(") < migrate.index(
        "cancelByProxyGeneration(")
    assert "_selectedMtproxyEndpoint = endpoint;" in selected
    assert "notifyEndpointViewChanged(endpoint);" in selected
    for deleted in (
        "requestImmediateScout",
        "immediateScoutRequest",
        "EndpointOpenGateStage",
        "pressureWindow",
        "backoffRung",
    ):
        assert deleted not in lifecycle
        assert deleted not in arbiter


if __name__ == "__main__":
    test_manual_selection_uses_normal_generation_migration_without_scout()
    test_proxy_switch_uses_atomic_migration_not_global_restart()
    test_reapplying_selected_proxy_keeps_live_connections()
    test_session_proxy_switch_suspends_old_generation_silently()
    test_new_sessions_inherit_current_proxy_generation()
    test_broker_cancels_old_proxy_generation_tickets()
    test_status_reducer_shadows_old_proxy_generation_facts()
