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
    '#include "mtproto/proxy/diagnostics.h"',
    "ConnectionBroker::Instance()",
    "ProxyControlPlane::",
    "ReportProxyEvent(",
    "WriteProxyDiagnosticsLine(",
)


def read(path):
    assert path.exists(), f"missing expected source file: {path}"
    return path.read_text(encoding="utf-8")


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
    assert "reportConnectionError(" in port_header
    assert "reportReceiveTimeout(" in port_header
    assert "reportConnectTimeout(" in port_header
    assert "logEvent(" in port_header

    for token in SESSION_PRIVATE_BANNED_TOKENS:
        assert token not in session_sources

    assert "SessionProxyPort" in session_sources
    assert "_proxyPort->" in session_sources


def test_proxy_adapter_is_the_only_session_proxy_global_caller():
	adapter_h = read(PROXY_ADAPTER_H)
	adapter_cpp = read(PROXY_ADAPTER_CPP)

	assert '#include "mtproto/session/private/proxy_port.h"' not in adapter_h
	assert "public SessionProxyPort" not in adapter_h
	assert '#include "mtproto/session/private/proxy_port.h"' in adapter_cpp
	assert "class ProductionSessionProxyPort final" in adapter_cpp
	assert "DefaultSessionProxyPort()" in adapter_cpp
	assert "proxyServices().broker().request(" in adapter_cpp
	assert "proxyServices().broker().cancelByProxyGeneration(" in adapter_cpp
	assert "proxyServices().control().reportMtproxySuccess(" in adapter_cpp
	assert "proxyServices().control().reportMtproxyFailure(" in adapter_cpp
	assert "proxyServices().control().noteMtproxyRelayStall(" in adapter_cpp
	assert ").mtproxyEndpointSnapshot(endpoint)" in adapter_cpp
	assert "ReportProxyEvent(" in adapter_cpp
	assert "WriteProxyDiagnosticsLine(" in adapter_cpp
