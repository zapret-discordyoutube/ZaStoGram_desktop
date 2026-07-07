from pathlib import Path
from session_private_sources import read_session_private_sources


SOURCE_DIR = Path(__file__).resolve().parents[1]
ROOT_DIR = SOURCE_DIR.parents[1]
MTPROXY_DIR = SOURCE_DIR / "mtproto" / "proxy" / "mtproxy"
POLICY_H = MTPROXY_DIR / "policy.h"
POLICY_CPP = MTPROXY_DIR / "policy.cpp"
ENDPOINT_HEALTH_H = MTPROXY_DIR / "endpoint_health.h"
ENDPOINT_HEALTH_CPP = MTPROXY_DIR / "endpoint_health.cpp"
SESSION_CPP = SOURCE_DIR / "mtproto" / "session_private.cpp"
CONNECTION_BROKER_CPP = SOURCE_DIR / "mtproto" / "proxy" / "connection_broker.cpp"
TLS_SOCKET_CPP = MTPROXY_DIR / "tls_socket.cpp"
CMAKE = ROOT_DIR / "Telegram" / "CMakeLists.txt"
TD_MTPROTO_CMAKE = ROOT_DIR / "Telegram" / "cmake" / "td_mtproto.cmake"


def test_legacy_mtproxy_policy_module_is_removed():
    session = read_session_private_sources()
    tls_socket = TLS_SOCKET_CPP.read_text(encoding="utf-8")
    endpoint_header = ENDPOINT_HEALTH_H.read_text(encoding="utf-8")
    endpoint_source = ENDPOINT_HEALTH_CPP.read_text(encoding="utf-8")
    broker = CONNECTION_BROKER_CPP.read_text(encoding="utf-8")
    cmake = CMAKE.read_text(encoding="utf-8")

    assert not POLICY_H.exists()
    assert not POLICY_CPP.exists()
    assert "mtproto/proxy/mtproxy/policy.h" not in cmake
    assert "mtproto/proxy/mtproxy/policy.cpp" not in cmake
    assert '#include "mtproto/proxy/mtproxy/policy.h"' not in session
    assert '#include "mtproto/proxy/mtproxy/policy.h"' not in tls_socket
    assert "MtproxyConnectionSpacing(" not in endpoint_header
    assert "MtproxyConnectionSpacing(" not in endpoint_source
    assert "ConnectionSpacing(" in endpoint_header
    assert "ConnectionSpacing(" in endpoint_source
    assert "ProxyPatternSpacing(" not in session
    assert "CooldownMsForEndpoint(" not in session
    assert "MtProxy::ConnectionSpacing(" not in session
    assert "MtProxy::ReserveOpenSlot(" in broker
    assert "MtProxy::ConnectionSpacing(" in tls_socket
    assert "MtproxyEndpointCooldown(" not in session


def test_tls_socket_reports_endpoint_state_through_endpoint_health():
    endpoint_header = ENDPOINT_HEALTH_H.read_text(encoding="utf-8")
    endpoint_source = ENDPOINT_HEALTH_CPP.read_text(encoding="utf-8")
    tls_socket = TLS_SOCKET_CPP.read_text(encoding="utf-8")

    assert "class EndpointHealth" in endpoint_header
    assert "recipeLevel" in endpoint_header
    assert "lastDiagnostic" in endpoint_header
    assert "RotateTlsProfileOnFailure(" in endpoint_source
    assert "CooldownMsForEndpoint(" not in tls_socket
    assert '#include "mtproto/proxy/mtproxy/endpoint_health.h"' in (
        MTPROXY_DIR / "tls_socket.h").read_text(encoding="utf-8")
    assert "ProxyControlPlane::ReportMtproxyFailure(" in tls_socket
    assert "ProxyControlPlane::ReportMtproxySuccess(" in tls_socket
    assert "MtproxyNoteEndpointFailure(" not in tls_socket
    assert "MtproxyNoteEndpointSuccess(" not in tls_socket
    assert "MtproxyRotateTlsProfileOnFailure(" not in tls_socket


def test_proxy_module_sources_are_registered_for_build():
    cmake = CMAKE.read_text(encoding="utf-8")

    for path in (
        "mtproto/proxy/data.cpp",
        "mtproto/proxy/data.h",
        "mtproto/proxy/connection_broker.cpp",
        "mtproto/proxy/connection_broker.h",
        "mtproto/proxy/status.h",
        "mtproto/proxy/mtproxy/adaptive_policy.cpp",
        "mtproto/proxy/mtproxy/adaptive_policy.h",
        "mtproto/proxy/mtproxy/client_hello_builder.cpp",
        "mtproto/proxy/mtproxy/client_hello_builder.h",
        "mtproto/proxy/mtproxy/client_hello_facts.cpp",
        "mtproto/proxy/mtproxy/client_hello_facts.h",
        "mtproto/proxy/mtproxy/client_hello_profile.cpp",
        "mtproto/proxy/mtproxy/client_hello_profile.h",
        "mtproto/proxy/mtproxy/endpoint_health.cpp",
        "mtproto/proxy/mtproxy/endpoint_health.h",
        "mtproto/proxy/mtproxy/endpoint_identity.cpp",
        "mtproto/proxy/mtproxy/endpoint_identity.h",
        "mtproto/proxy/mtproxy/tls_socket.cpp",
        "mtproto/proxy/mtproxy/tls_socket.h",
        "mtproto/proxy/wss/socket.cpp",
        "mtproto/proxy/wss/socket.h",
    ):
        assert path in cmake


def test_td_mtproto_source_list_only_references_existing_files():
    cmake = TD_MTPROTO_CMAKE.read_text(encoding="utf-8")

    for line in cmake.splitlines():
        path = line.strip()
        if not path.startswith("mtproto/") or not path.endswith((".cpp", ".h")):
            continue
        assert (SOURCE_DIR / path).exists(), path


if __name__ == "__main__":
    test_legacy_mtproxy_policy_module_is_removed()
    test_tls_socket_reports_endpoint_state_through_endpoint_health()
    test_proxy_module_sources_are_registered_for_build()
    test_td_mtproto_source_list_only_references_existing_files()
