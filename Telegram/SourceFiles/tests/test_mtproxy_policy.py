from pathlib import Path


SOURCE_DIR = Path(__file__).resolve().parents[1]
ROOT_DIR = SOURCE_DIR.parents[1]
MTPROXY_DIR = SOURCE_DIR / "mtproto" / "proxy" / "mtproxy"
POLICY_H = MTPROXY_DIR / "policy.h"
POLICY_CPP = MTPROXY_DIR / "policy.cpp"
SESSION_CPP = SOURCE_DIR / "mtproto" / "session_private.cpp"
TLS_SOCKET_CPP = MTPROXY_DIR / "tls_socket.cpp"
CMAKE = ROOT_DIR / "Telegram" / "CMakeLists.txt"
TD_MTPROTO_CMAKE = ROOT_DIR / "Telegram" / "cmake" / "td_mtproto.cmake"


def test_session_uses_mtproxy_policy_for_spacing_and_cooldown():
    header = POLICY_H.read_text(encoding="utf-8")
    source = POLICY_CPP.read_text(encoding="utf-8")
    session = SESSION_CPP.read_text(encoding="utf-8")

    assert "MtproxyConnectionSpacing(" in header
    assert "MtproxyConnectionSpacing(" in source
    assert "MtproxyEndpointCooldown(" in header
    assert "MtproxyEndpointCooldown(" in source
    assert "ProxyPatternSpacing(" not in session
    assert "CooldownMsForEndpoint(" not in session
    assert '#include "mtproto/proxy/mtproxy/policy.h"' in session
    assert "MtproxyConnectionSpacing(" in session
    assert "MtproxyEndpointCooldown(" in session


def test_tls_socket_reports_endpoint_state_through_mtproxy_policy():
    header = POLICY_H.read_text(encoding="utf-8")
    source = POLICY_CPP.read_text(encoding="utf-8")
    tls_socket = TLS_SOCKET_CPP.read_text(encoding="utf-8")

    assert "MtproxyNoteEndpointFailure(" in header
    assert "MtproxyNoteEndpointFailure(" in source
    assert "MtproxyNoteEndpointSuccess(" in header
    assert "MtproxyNoteEndpointSuccess(" in source
    assert "MtproxyRotateTlsProfileOnFailure(" in header
    assert "MtproxyRotateTlsProfileOnFailure(" in source
    assert "CooldownMsForEndpoint(" not in tls_socket
    assert '#include "mtproto/proxy/mtproxy/policy.h"' in tls_socket
    assert "MtproxyNoteEndpointFailure(" in tls_socket
    assert "MtproxyNoteEndpointSuccess(" in tls_socket
    assert "MtproxyRotateTlsProfileOnFailure(" in tls_socket


def test_proxy_module_sources_are_registered_for_build():
    cmake = CMAKE.read_text(encoding="utf-8")

    for path in (
        "mtproto/proxy/data.cpp",
        "mtproto/proxy/data.h",
        "mtproto/proxy/status.h",
        "mtproto/proxy/mtproxy/adaptive_policy.cpp",
        "mtproto/proxy/mtproxy/adaptive_policy.h",
        "mtproto/proxy/mtproxy/policy.cpp",
        "mtproto/proxy/mtproxy/policy.h",
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
    test_session_uses_mtproxy_policy_for_spacing_and_cooldown()
    test_tls_socket_reports_endpoint_state_through_mtproxy_policy()
    test_proxy_module_sources_are_registered_for_build()
    test_td_mtproto_source_list_only_references_existing_files()
