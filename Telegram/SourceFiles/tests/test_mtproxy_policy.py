from pathlib import Path
from session_private_sources import read_session_private_sources


SOURCE_DIR = Path(__file__).resolve().parents[1]
ROOT_DIR = SOURCE_DIR.parents[1]
PROXY_DIR = SOURCE_DIR / "mtproto" / "proxy"
MTPROXY_DIR = SOURCE_DIR / "mtproto" / "proxy" / "mtproxy"
POLICY_H = MTPROXY_DIR / "policy.h"
POLICY_CPP = MTPROXY_DIR / "policy.cpp"
ENDPOINT_HEALTH_H = MTPROXY_DIR / "endpoint_health.h"
ENDPOINT_HEALTH_CPP = MTPROXY_DIR / "endpoint_health.cpp"
SESSION_CPP = SOURCE_DIR / "mtproto" / "session" / "private" / "session_private.cpp"
CONNECTION_BROKER_CPP = SOURCE_DIR / "mtproto" / "proxy" / "connection_broker.cpp"
ENDPOINT_ARBITER_CPP = SOURCE_DIR / "mtproto" / "proxy" / "endpoint_admission_arbiter.cpp"
TLS_SOCKET_CPP = MTPROXY_DIR / "tls_socket.cpp"
CLIENT_HELLO_RULES_CPP = MTPROXY_DIR / "client_hello_rules.cpp"
CLIENT_HELLO_FRAGMENTATION_CPP = MTPROXY_DIR / "client_hello_fragmentation.cpp"
ENDPOINT_HEALTH_CAPABILITIES_CPP = MTPROXY_DIR / "endpoint_health_capabilities.cpp"
ENDPOINT_HEALTH_CAPABILITIES_H = MTPROXY_DIR / "endpoint_health_capabilities.h"
ENDPOINT_HEALTH_DIAGNOSTICS_CPP = MTPROXY_DIR / "endpoint_health_diagnostics.cpp"
ENDPOINT_HEALTH_DIAGNOSTICS_H = MTPROXY_DIR / "endpoint_health_diagnostics.h"
ENDPOINT_HEALTH_POLICY_CPP = MTPROXY_DIR / "endpoint_health_policy.cpp"
ENDPOINT_HEALTH_POLICY_H = MTPROXY_DIR / "endpoint_health_policy.h"
ENDPOINT_HEALTH_STATE_H = MTPROXY_DIR / "endpoint_health_state.h"
TLS_SOCKET_HANDSHAKE_CPP = MTPROXY_DIR / "tls_socket_handshake.cpp"
TLS_SOCKET_PSK_CPP = MTPROXY_DIR / "tls_socket_psk.cpp"
TLS_SOCKET_PSK_H = MTPROXY_DIR / "tls_socket_psk.h"
TLS_SOCKET_RECORDS_CPP = MTPROXY_DIR / "tls_socket_records.cpp"
TLS_SOCKET_UTILS_H = MTPROXY_DIR / "tls_socket_utils.h"
CMAKE = ROOT_DIR / "Telegram" / "CMakeLists.txt"
TD_MTPROTO_CMAKE = ROOT_DIR / "Telegram" / "cmake" / "td_mtproto.cmake"


def test_legacy_mtproxy_policy_module_is_removed():
    session = read_session_private_sources()
    tls_socket = TLS_SOCKET_CPP.read_text(encoding="utf-8")
    tls_handshake = TLS_SOCKET_HANDSHAKE_CPP.read_text(encoding="utf-8")
    endpoint_header = ENDPOINT_HEALTH_H.read_text(encoding="utf-8")
    endpoint_source = ENDPOINT_HEALTH_CPP.read_text(encoding="utf-8")
    endpoint_policy = ENDPOINT_HEALTH_POLICY_CPP.read_text(encoding="utf-8")
    broker = CONNECTION_BROKER_CPP.read_text(encoding="utf-8")
    arbiter = ENDPOINT_ARBITER_CPP.read_text(encoding="utf-8")
    cmake = CMAKE.read_text(encoding="utf-8")

    assert not POLICY_H.exists()
    assert not POLICY_CPP.exists()
    assert "mtproto/proxy/mtproxy/policy.h" not in cmake
    assert "mtproto/proxy/mtproxy/policy.cpp" not in cmake
    assert '#include "mtproto/proxy/mtproxy/policy.h"' not in session
    assert '#include "mtproto/proxy/mtproxy/policy.h"' not in tls_socket
    assert "MtproxyConnectionSpacing(" not in endpoint_header
    assert "MtproxyConnectionSpacing(" not in endpoint_source
    assert "MtproxyConnectionSpacing(" not in endpoint_policy
    assert "ConnectionSpacing(" in endpoint_header
    assert "ConnectionSpacing(" in endpoint_policy
    assert "ProxyPatternSpacing(" not in session
    assert "CooldownMsForEndpoint(" not in session
    assert "MtProxy::ConnectionSpacing(" not in session
    assert "ReserveOpenSlot" not in broker
    assert "MtProxy::ReserveOpenSlot(" in arbiter
    assert "MtProxy::ReflowOpenSlots(" in arbiter
    assert "MtProxy::CommitOpenSlot(" in arbiter
    assert "adaptiveSpacing" not in arbiter
    assert "NoteConnectTimeout" not in arbiter
    assert "NoteConnectSuccess" not in arbiter
    assert "MtProxy::ConnectionSpacing(" in tls_handshake
    assert "MtproxyEndpointCooldown(" not in session
    proxy_sources = "\n".join(
        path.read_text(encoding="utf-8")
        for path in PROXY_DIR.rglob("*")
        if path.suffix in (".cpp", ".h"))
    for old_seam in (
        "opening.bootstrap",
        "opening.expansion",
        "nextHandshakeAt",
        "admissionActive",
        "adaptiveSpacing",
        "NoteConnectTimeout",
        "NoteConnectSuccess",
        "EndpointConcurrencyPolicy",
        "EvaluateEndpointAdmission",
        "ReserveOpenSlotLocked",
        "CancelOpenSlotLocked",
        "CommitOpenSlotLocked",
        "ReflowOpenSlotsLocked",
        "SynchronizeEndpointAdmissionAggregate",
        "ReleaseAdmissionForRelayCandidate",
    ):
        assert old_seam not in proxy_sources


def test_tls_socket_reports_endpoint_state_through_endpoint_health():
    endpoint_header = ENDPOINT_HEALTH_H.read_text(encoding="utf-8")
    endpoint_source = ENDPOINT_HEALTH_CPP.read_text(encoding="utf-8")
    tls_sources = "\n".join(
        path.read_text(encoding="utf-8")
        for path in (
            TLS_SOCKET_CPP,
            TLS_SOCKET_HANDSHAKE_CPP,
            TLS_SOCKET_RECORDS_CPP,
        ))

    assert "class EndpointHealth" in endpoint_header
    endpoint_state = ENDPOINT_HEALTH_STATE_H.read_text(encoding="utf-8")
    assert "recipeLevel" in endpoint_state
    assert "lastDiagnostic" in endpoint_state
    assert "RotateTlsProfileOnFailure(" not in endpoint_source
    assert "BuildAttemptPlan(request, state.recipeLevel)" in endpoint_source
    assert "ProxyTlsProfile::ChromeModern" in ENDPOINT_HEALTH_POLICY_CPP.read_text(
        encoding="utf-8")
    assert "CooldownMsForEndpoint(" not in tls_sources
    tls_header = (MTPROXY_DIR / "tls_socket.h").read_text(encoding="utf-8")
    assert '#include "mtproto/proxy/mtproxy/endpoint_identity.h"' in tls_header
    assert "MtProxyAttemptPlan _mtproxyPlan;" in tls_header
    assert "reportTransportEvent(" in tls_sources
    assert "collectTransportFailure()" in tls_sources
    assert "reportMtproxySuccess(" in tls_sources
    assert "MtproxyNoteEndpointFailure(" not in tls_sources
    assert "MtproxyNoteEndpointSuccess(" not in tls_sources
    assert "MtproxyRotateTlsProfileOnFailure(" not in tls_sources


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
        "mtproto/proxy/mtproxy/client_hello_fragmentation.cpp",
        "mtproto/proxy/mtproxy/client_hello_facts.cpp",
        "mtproto/proxy/mtproxy/client_hello_facts.h",
        "mtproto/proxy/mtproxy/client_hello_profile.cpp",
        "mtproto/proxy/mtproxy/client_hello_profile.h",
        "mtproto/proxy/mtproxy/client_hello_rules.cpp",
        "mtproto/proxy/mtproxy/endpoint_health_capabilities.cpp",
        "mtproto/proxy/mtproxy/endpoint_health_capabilities.h",
        "mtproto/proxy/mtproxy/endpoint_health.cpp",
        "mtproto/proxy/mtproxy/endpoint_health.h",
        "mtproto/proxy/mtproxy/endpoint_health_diagnostics.cpp",
        "mtproto/proxy/mtproxy/endpoint_health_diagnostics.h",
        "mtproto/proxy/mtproxy/endpoint_health_policy.cpp",
        "mtproto/proxy/mtproxy/endpoint_health_policy.h",
        "mtproto/proxy/mtproxy/endpoint_health_state.h",
        "mtproto/proxy/mtproxy/endpoint_identity.cpp",
        "mtproto/proxy/mtproxy/endpoint_identity.h",
        "mtproto/proxy/mtproxy/tls_socket.cpp",
        "mtproto/proxy/mtproxy/tls_socket.h",
        "mtproto/proxy/mtproxy/tls_socket_handshake.cpp",
        "mtproto/proxy/mtproxy/tls_socket_psk.cpp",
        "mtproto/proxy/mtproxy/tls_socket_psk.h",
        "mtproto/proxy/mtproxy/tls_socket_records.cpp",
        "mtproto/proxy/mtproxy/tls_socket_utils.h",
        "mtproto/proxy/wss/socket.cpp",
        "mtproto/proxy/wss/socket.h",
    ):
        assert path in cmake


def test_mtproxy_transport_hotspots_are_split_by_role():
    limits = {
        TLS_SOCKET_CPP: 420,
        ENDPOINT_HEALTH_CPP: 820,
        MTPROXY_DIR / "client_hello_builder.cpp": 560,
        CLIENT_HELLO_RULES_CPP: 720,
    }

    for path, limit in limits.items():
        assert path.exists(), path
        lines = path.read_text(encoding="utf-8").splitlines()
        assert len(lines) <= limit, f"{path.relative_to(ROOT_DIR)} has {len(lines)} lines"

    tls_socket = TLS_SOCKET_CPP.read_text(encoding="utf-8")
    endpoint_health = ENDPOINT_HEALTH_CPP.read_text(encoding="utf-8")

    assert "SyntheticPskCache" not in tls_socket
    assert "ClientHelloSniHostRange(" not in (
        MTPROXY_DIR / "client_hello_builder.cpp").read_text(encoding="utf-8")
    assert "ProxyCapabilityCache::Instance()" not in endpoint_health
    assert "QMutex StatesMutex" not in ENDPOINT_HEALTH_POLICY_CPP.read_text(
        encoding="utf-8")


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
    test_mtproxy_transport_hotspots_are_split_by_role()
    test_td_mtproto_source_list_only_references_existing_files()
