from pathlib import Path
from session_private_sources import read_session_private_sources


SOURCE_DIR = Path(__file__).resolve().parents[1]
ROOT = SOURCE_DIR.parents[1]
CMAKE = ROOT / "Telegram" / "CMakeLists.txt"
MTPROTO_DIR = SOURCE_DIR / "mtproto"
PROXY_DIR = MTPROTO_DIR / "proxy"
PROXY_SERVICES_H = PROXY_DIR / "proxy_services.h"
PROXY_SERVICES_CPP = PROXY_DIR / "proxy_services.cpp"
SESSION_PROXY_ADAPTER_CPP = PROXY_DIR / "session_proxy_adapter.cpp"
RUNTIME_H = MTPROTO_DIR / "runtime" / "runtime_environment.h"
RUNTIME_CPP = MTPROTO_DIR / "runtime" / "runtime_environment.cpp"
CONNECTION_STATUS_H = MTPROTO_DIR / "runtime" / "connection_status.h"
CONNECTION_STATUS_CPP = MTPROTO_DIR / "runtime" / "connection_status.cpp"
DIAGNOSTICS_H = PROXY_DIR / "diagnostics.h"
DIAGNOSTICS_CPP = PROXY_DIR / "diagnostics.cpp"
CONTROL_H = PROXY_DIR / "control_plane.h"
CONTROL_CPP = PROXY_DIR / "control_plane.cpp"
BROKER_H = PROXY_DIR / "connection_broker.h"
DNS_H = PROXY_DIR / "dns_resolver_cache.h"
CHECK_H = PROXY_DIR / "check.h"
ABSTRACT_CONNECTION_H = MTPROTO_DIR / "transport" / "connection_abstract.h"
ABSTRACT_CONNECTION_CPP = MTPROTO_DIR / "transport" / "connection_abstract.cpp"
INSTANCE_CPP = MTPROTO_DIR / "instance" / "mtp_instance.cpp"
INSTANCE_H = MTPROTO_DIR / "instance" / "mtp_instance.h"
RPC_ERROR_H = MTPROTO_DIR / "instance" / "rpc_error_handler.h"
RPC_ERROR_CPP = MTPROTO_DIR / "instance" / "rpc_error_handler.cpp"
SENDER_CPP = MTPROTO_DIR / "instance" / "sender.cpp"
SENDER_H = MTPROTO_DIR / "instance" / "sender.h"
SESSION_CPP = MTPROTO_DIR / "session" / "session.cpp"
SESSION_H = MTPROTO_DIR / "session" / "session.h"
SESSION_DELEGATE_H = MTPROTO_DIR / "session" / "session_delegate.h"
SESSION_PRIVATE_CPP = MTPROTO_DIR / "session" / "private" / "session_private.cpp"
SESSION_PRIVATE_H = MTPROTO_DIR / "session" / "private" / "session_private.h"


def read(path):
    assert path.exists(), f"missing expected source file: {path}"
    return path.read_text(encoding="utf-8")


def function_body(source, signature):
    start = source.index(signature)
    brace = source.index("{", start)
    depth = 0
    for index in range(brace, len(source)):
        char = source[index]
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return source[brace + 1:index]
    raise AssertionError(f"function body not found: {signature}")


def mtproto_sources():
    for path in (
            list(PROXY_DIR.rglob("*.h"))
            + list(PROXY_DIR.rglob("*.cpp"))
            + [
                MTPROTO_DIR / "transport" / "connection_abstract.h",
                MTPROTO_DIR / "transport" / "connection_abstract.cpp",
                MTPROTO_DIR / "transport" / "connection_tcp.h",
                MTPROTO_DIR / "transport" / "connection_tcp.cpp",
                MTPROTO_DIR / "transport" / "connection_http.h",
                MTPROTO_DIR / "transport" / "connection_http.cpp",
                MTPROTO_DIR / "transport" / "mtproto_abstract_socket.h",
                MTPROTO_DIR / "transport" / "mtproto_abstract_socket.cpp",
            ]):
        if path.exists():
            yield path


def test_runtime_environment_is_the_app_gateway():
    cmake = read(CMAKE)
    header = read(RUNTIME_H)
    source = read(RUNTIME_CPP)
    services_header = read(PROXY_SERVICES_H)
    status_header = read(CONNECTION_STATUS_H)
    status_source = read(CONNECTION_STATUS_CPP)
    instance = read(INSTANCE_CPP)

    assert "mtproto/runtime/runtime_environment.cpp" in cmake
    assert "mtproto/runtime/runtime_environment.h" in cmake
    assert "mtproto/runtime/connection_status.cpp" in cmake
    assert "mtproto/runtime/connection_status.h" in cmake
    assert "mtproto/proxy/proxy_services.cpp" in cmake
    assert "mtproto/proxy/proxy_services.h" in cmake
    assert "struct RuntimeProxySettings" in header
    assert "struct RuntimeDeviceSettings" in header
    assert "struct RuntimeLanguageGateway" in header
    assert "struct RuntimeStorageGateway" in header
    assert "struct RuntimeAppGateway" in header
    assert "struct RuntimeDiagnosticsGateway" in header
    assert "struct RuntimeInstanceServices" in header
    assert "struct RuntimeProxyResolver" in header
    assert "class RuntimeEnvironment final" in header
    assert "class ProxyServices;" in header
    assert "[[nodiscard]] ProxyServices &proxyServices() const;" in header
    assert "class ProxyServices final" in services_header
    assert "ProxyControlPlane &control();" in services_header
    assert "details::ConnectionBroker &broker();" in services_header
    assert "details::DnsResolverCache &dnsResolver();" in services_header
    assert "void bindInstance(RuntimeInstanceServices services);" in header
    assert "void unbindInstance(ConnectionStatus *status);" in header
    assert "RuntimeEnvironmentDescriptor" in header
    assert "DefaultRuntimeEnvironment()" in header
    assert "DefaultRuntimeEnvironment()" in source
    assert "class ConnectionStatus final" in status_header
    assert "ConnectionStatus::setProxyStatus(" in status_source
    assert "fields.runtimeEnvironment" in instance


def test_runtime_environment_has_no_public_mutable_service_locator_fields():
    header = read(RUNTIME_H)
    source = read(RUNTIME_CPP)
    instance = read(INSTANCE_CPP)

    runtime_body = function_body(header, "class RuntimeEnvironment final")

    assert "public:\n\tRuntimeProxySettings proxy;" not in header
    assert "ConnectionStatus *connectionStatus = nullptr" not in runtime_body
    assert "Fn<" not in runtime_body
    assert "runtime->connectionStatus =" not in instance
    assert "runtime->mainDcId =" not in instance
    assert "runtime->dcOptionsLookup =" not in instance
    assert "runtime->resolveProxyDomain =" not in instance
    assert "runtime->setGoodProxyDomain =" not in instance
    assert "runtime->proxyDomainResolved =" not in instance
    assert "runtime->syncHttpUnixtime =" not in instance
    assert "InstallDefaultHandlers" not in source


def test_lower_mtproto_layers_do_not_include_app_facade():
    banned_tokens = (
        '#include "mtproto/instance/mtp_instance.h"',
        '#include "core/',
        '#include "main/',
        '#include "settings.h"',
        "Core::App(",
        "Core::App().",
        "Local::",
        "Lang::",
        "Logs::writeMtproxy",
    )
    allowed = {
        RUNTIME_CPP,
        RUNTIME_H,
    }

    for path in mtproto_sources():
        if path in allowed:
            continue
        text = read(path)
        for token in banned_tokens:
            assert token not in text, (
                f"{path.relative_to(ROOT)} still depends on app layer via "
                f"{token}")


def test_proxy_reporting_and_control_plane_do_not_accept_instance():
    diagnostics_h = read(DIAGNOSTICS_H)
    diagnostics_cpp = read(DIAGNOSTICS_CPP)
    control_h = read(CONTROL_H)
    control_cpp = read(CONTROL_CPP)
    runtime_cpp = read(RUNTIME_CPP)

    assert "void ReportProxyEvent(ProxyEventReport report);" not in diagnostics_h
    assert "not_null<Instance*>" not in diagnostics_h
    assert "not_null<Instance*>" not in diagnostics_cpp
    assert "class Instance;" not in diagnostics_h
    assert "not_null<RuntimeEnvironment*> runtime" in diagnostics_h
    assert "runtime->diagnostics().reportProxyEvent" in diagnostics_cpp
    assert "proxyServices().control().submitFact(report)" in runtime_cpp
    assert "void submitFact(const ProxyEventReport &report);" in control_h
    assert "not_null<Instance*>" not in control_h
    assert "not_null<Instance*>" not in control_cpp
    assert "_runtime->instance().connectionStatus->setProxyStatus" in control_cpp


def test_instance_and_session_use_runtime_gateway_for_app_facade():
    runtime = read(RUNTIME_CPP)
    instance_h = read(INSTANCE_H)
    checked_sources = (
        INSTANCE_CPP,
        SESSION_CPP,
        SESSION_PRIVATE_CPP,
    )
    banned_tokens = (
        '#include "core/application.h"',
        '#include "core/core_settings.h"',
        '#include "main/',
        '#include "storage/localstorage.h"',
        '#include "lang/',
        "Core::App(",
        "Core::App().",
        "Local::",
        "Lang::",
    )

    assert "Core::App().settings().proxy()" in runtime
    assert "Lang::CurrentCloudManager()" in runtime
    assert "Local::writeSettings()" in runtime
    assert "ConnectionStatus &connectionStatus() const;" in instance_h
    for removed in (
            "proxyConnectionStatus",
            "connectionNoticeValue",
            "setConnectionNotice",
            "pingTimeValue",
            "setSessionPingTime"):
        assert removed not in instance_h

    for path in checked_sources:
        text = read(path)
        for token in banned_tokens:
            assert token not in text, (
                f"{path.relative_to(ROOT)} still depends on app layer via "
                f"{token}")


def test_on_error_default_is_split_into_helpers():
    cmake = read(CMAKE)
    instance = read(INSTANCE_CPP)
    rpc_h = read(RPC_ERROR_H)
    rpc_cpp = read(RPC_ERROR_CPP)
    body = function_body(
        instance,
        "bool Instance::Private::onErrorDefault(")

    assert "mtproto/instance/rpc_error_handler.cpp" in cmake
    assert "mtproto/instance/rpc_error_handler.h" in cmake
    assert "struct DefaultRpcErrorAction" in rpc_h
    assert "DefaultRpcErrorAction ClassifyDefaultRpcError(" in rpc_h
    assert "QRegularExpression" not in instance
    assert "QRegularExpression" in rpc_cpp
    assert "ClassifyDefaultRpcError(" in body
    assert len(body.splitlines()) <= 45
    for helper in (
            "handleMigrationError(",
            "handleMsgWaitError(",
            "handleRetryError(",
            "handleUnauthorizedError(",
            "handleConnectionInitError("):
        assert helper in body


def test_session_callbacks_are_hidden_behind_delegate():
    cmake = read(CMAKE)
    instance = read(INSTANCE_CPP)
    instance_h = read(INSTANCE_H)
    session_h = read(SESSION_H)
    session = read(SESSION_CPP)
    session_private_h = read(SESSION_PRIVATE_H)
    session_private = read_session_private_sources()
    delegate = read(SESSION_DELEGATE_H)
    public_instance = function_body(instance_h, "class Instance : public QObject")

    assert "mtproto/session/session_delegate.h" in cmake
    assert "class SessionDelegate" in delegate
    assert "public details::SessionDelegate" in instance
    assert "not_null<SessionDelegate*> delegate" in session_h
    assert "const not_null<SessionDelegate*> _delegate;" in session_h
    assert "const not_null<SessionDelegate*> _delegate;" in session_private_h
    assert "std::make_unique<Session>(_instance, this" in instance
    assert "new SessionPrivate(\n\t\t_instance,\n\t\t_delegate," in session

    for hidden in (
            "resolveProxyDomain(",
            "setGoodProxyDomain(",
            "systemLangCode(",
            "cloudLangCode(",
            "langPackName(",
            "dcPersistentKeyChanged(",
            "dcTemporaryKeyChanged(",
            "proxyMigrationSucceeded(",
            "onStateChange(",
            "onSessionReset(",
            "hasCallback(",
            "processCallback(",
            "processUpdate(",
            "rpcErrorOccured(",
            "keyWasPossiblyDestroyed(",
            "keyDestroyedOnServer(",
            "badConfigurationError(",
            "restartedByTimeout("):
        assert hidden not in public_instance

    assert "_instance->" not in session
    assert "_instance->" not in session_private
    assert "delegate->processCallback(" in session
    assert "_delegate->hasCallback(" in session_private


def test_runtime_context_replaces_instance_in_proxy_entrypoints():
    broker_h = read(BROKER_H)
    dns_h = read(DNS_H)
    check_h = read(CHECK_H)
    session = read_session_private_sources()
    adapter = read(SESSION_PROXY_ADAPTER_CPP)

    assert "RuntimeEnvironment *runtime = nullptr;" not in broker_h
    assert "explicit ConnectionBroker(not_null<RuntimeEnvironment*> runtime);" in (
        broker_h)
    assert "cancelByProxyGeneration(RuntimeEnvironment *runtime" not in broker_h
    assert "void cancelByProxyGeneration(uint64 generation);" in broker_h
    assert "void request(\n\t\tQObject *receiver" in dns_h
    assert "void StartProxyCheck(\n\tnot_null<RuntimeEnvironment*> runtime" in check_h
    assert "_connectionFactory->create(\n\t\t\t\t_owner->_runtime" in session
    assert "SessionProxyPort" in session
    assert "proxyServices().broker().request(" in adapter
    assert "proxyServices().control().reportMtproxySuccess(" in adapter
    assert "ConnectionBroker::Instance()" not in session
    assert "DnsResolverCache::Instance()" not in session
    assert ".instance = _instance" not in session


def test_transport_session_leaks_use_neutral_metadata():
    abstract_h = read(ABSTRACT_CONNECTION_H)
    abstract_cpp = read(ABSTRACT_CONNECTION_CPP)
    session = read_session_private_sources()

    assert "enum class TransportServiceRequest" in abstract_h
    assert "HttpWait" in abstract_h
    assert "serviceRequestNeeded(" in abstract_h
    assert "usingHttpWait" not in abstract_h
    assert "needHttpWait" not in abstract_h
    assert "setSentEncryptedWithKeyId" not in abstract_h
    assert "sentEncryptedWithKeyId" not in abstract_h
    assert "struct SendDataContext" in abstract_h
    assert "uint64 keyId = 0;" in abstract_h
    assert "sendData(mtpBuffer &&buffer, SendDataContext context)" in abstract_h
    assert "struct ConnectionStartContext" in abstract_h
    assert "ProxyConnectionAttempt mtproxyAttempt;" in abstract_h
    assert "ConnectionStartContext context = {}" in abstract_h
    assert "setMtproxyAttempt" not in abstract_h
    assert "setMtproxyAttempt" not in abstract_cpp
    assert "setMtproxyAttempt(" not in session
    assert "TransportServiceRequest::HttpWait" in session
    assert ".keyId = _sessionState.keyId" in session
    assert "usingHttpWait" not in session
    assert "needHttpWait" not in session
    assert "sentEncryptedWithKeyId" not in abstract_cpp


def test_sender_header_does_not_pull_instance_facade():
    cmake = read(CMAKE)
    instance_h = read(INSTANCE_H)
    sender_h = read(SENDER_H)
    sender_cpp = read(SENDER_CPP)

    assert "mtproto/instance/sender.cpp" in cmake
    assert '#include "mtproto/instance/mtp_instance.h"' not in sender_h
    assert '#include "mtproto/proxy/data.h"' not in instance_h
    assert "class Instance;" in sender_h
    assert "Sender::sendSerializedRequest(" in sender_cpp
    assert '#include "mtproto/instance/mtp_instance.h"' in sender_cpp


if __name__ == "__main__":
    test_runtime_environment_is_the_app_gateway()
    test_runtime_environment_has_no_public_mutable_service_locator_fields()
    test_lower_mtproto_layers_do_not_include_app_facade()
    test_proxy_reporting_and_control_plane_do_not_accept_instance()
    test_instance_and_session_use_runtime_gateway_for_app_facade()
    test_on_error_default_is_split_into_helpers()
    test_session_callbacks_are_hidden_behind_delegate()
    test_runtime_context_replaces_instance_in_proxy_entrypoints()
    test_transport_session_leaks_use_neutral_metadata()
    test_sender_header_does_not_pull_instance_facade()
