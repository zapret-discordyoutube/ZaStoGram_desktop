from pathlib import Path
from session_private_sources import read_session_private_sources


SOURCE_DIR = Path(__file__).resolve().parents[1]
ROOT = SOURCE_DIR.parents[1]
CMAKE = ROOT / "Telegram" / "CMakeLists.txt"
MTPROTO_DIR = SOURCE_DIR / "mtproto"
PROXY_DIR = MTPROTO_DIR / "proxy"
RUNTIME_H = MTPROTO_DIR / "runtime_environment.h"
RUNTIME_CPP = MTPROTO_DIR / "runtime_environment.cpp"
DIAGNOSTICS_H = PROXY_DIR / "diagnostics.h"
DIAGNOSTICS_CPP = PROXY_DIR / "diagnostics.cpp"
CONTROL_H = PROXY_DIR / "control_plane.h"
CONTROL_CPP = PROXY_DIR / "control_plane.cpp"
BROKER_H = PROXY_DIR / "connection_broker.h"
DNS_H = PROXY_DIR / "dns_resolver_cache.h"
CHECK_H = PROXY_DIR / "check.h"
ABSTRACT_CONNECTION_H = MTPROTO_DIR / "transport" / "connection_abstract.h"
ABSTRACT_CONNECTION_CPP = MTPROTO_DIR / "transport" / "connection_abstract.cpp"
SESSION_CPP = MTPROTO_DIR / "session" / "private.cpp"
INSTANCE_CPP = MTPROTO_DIR / "mtp_instance.cpp"


def read(path):
    assert path.exists(), f"missing expected source file: {path}"
    return path.read_text(encoding="utf-8")


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
    instance = read(INSTANCE_CPP)

    assert "mtproto/runtime/runtime_environment.cpp" in cmake
    assert "mtproto/runtime/runtime_environment.h" in cmake
    assert "struct RuntimeEnvironment" in header
    assert "Fn<void(ProxyDiagnosticsEvent)> writeProxyDiagnosticsLine" in header
    assert "Fn<void(ProxyEventReport)> reportProxyEvent" in header
    assert "Fn<ProxyConnectionStatus()> proxyConnectionStatus" in header
    assert "Fn<void(QString, QStringList, qint64)> proxyDomainResolved" in header
    assert "DefaultRuntimeEnvironment()" in header
    assert "DefaultRuntimeEnvironment()" in source
    assert "fields.runtimeEnvironment" in instance


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
        MTPROTO_DIR / "runtime_environment.cpp",
        MTPROTO_DIR / "runtime_environment.h",
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

    assert "void ReportProxyEvent(ProxyEventReport report);" in diagnostics_h
    assert "not_null<Instance*>" not in diagnostics_h
    assert "not_null<Instance*>" not in diagnostics_cpp
    assert "class Instance;" not in diagnostics_h
    assert "not_null<RuntimeEnvironment*> runtime" in diagnostics_h
    assert "runtime->reportProxyEvent" in diagnostics_cpp
    assert "ProxyControlPlane::SubmitFact(runtime, report)" in runtime_cpp
    assert "SubmitFact(\n\t\tnot_null<RuntimeEnvironment*> runtime" in control_h
    assert "not_null<Instance*>" not in control_h
    assert "not_null<Instance*>" not in control_cpp
    assert "runtime->setProxyConnectionStatus" in control_cpp


def test_runtime_context_replaces_instance_in_proxy_entrypoints():
    broker_h = read(BROKER_H)
    dns_h = read(DNS_H)
    check_h = read(CHECK_H)
    session = read_session_private_sources()

    assert "RuntimeEnvironment *runtime = nullptr;" in broker_h
    assert "cancelByProxyGeneration(RuntimeEnvironment *runtime" in broker_h
    assert "void request(\n\t\tRuntimeEnvironment *runtime" in dns_h
    assert "void StartProxyCheck(\n\tnot_null<RuntimeEnvironment*> runtime" in check_h
    assert ".runtime = _runtime" in session
    assert "AbstractConnection::Create(\n\t\t\t\t_runtime" in session
    assert "ConnectionBroker::Instance().request({" in session
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
    assert "TransportServiceRequest::HttpWait" in session
    assert ".keyId = _sessionState.keyId" in session
    assert "usingHttpWait" not in session
    assert "needHttpWait" not in session
    assert "sentEncryptedWithKeyId" not in abstract_cpp


if __name__ == "__main__":
    test_runtime_environment_is_the_app_gateway()
    test_lower_mtproto_layers_do_not_include_app_facade()
    test_proxy_reporting_and_control_plane_do_not_accept_instance()
    test_runtime_context_replaces_instance_in_proxy_entrypoints()
    test_transport_session_leaks_use_neutral_metadata()
