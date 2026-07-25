from pathlib import Path
from session_private_sources import read_session_private_sources


SOURCE_DIR = Path(__file__).resolve().parents[1]
PROXY_DIR = SOURCE_DIR / "mtproto" / "proxy"
MTPROXY_DIR = PROXY_DIR / "mtproxy"
TRANSPORT_POLICY_CPP = PROXY_DIR / "transport_policy.cpp"
DATA_CPP = PROXY_DIR / "data.cpp"
SESSION_CPP = SOURCE_DIR / "mtproto" / "session" / "private" / "session_private.cpp"
TLS_SOCKET_CPP = MTPROXY_DIR / "tls_socket.cpp"
TLS_SOCKET_RECORDS_CPP = MTPROXY_DIR / "tls_socket_records.cpp"


def read(path):
    assert path.exists(), f"missing expected source file: {path}"
    return path.read_text(encoding="utf-8")


def function_body(text: str, signature: str) -> str:
    start = text.index(signature)
    brace = text.index(" {\n", start) + 1
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


def test_mtproxy_effective_policy_is_always_conservative_tcp():
    policy = read(TRANSPORT_POLICY_CPP)
    data = read(DATA_CPP)
    effective = function_body(policy, "ProxyStealthOptions EffectiveProxyStealthOptions(")
    strict = function_body(data, "ProxyStealthOptions CompatStrictProxyStealthOptions(")
    mtproxy_branch = effective.split(
        "proxy.type == ProxyData::Type::Mtproto) {", 1)[1].split(
        "if (settings == ProxyData::Settings::Enabled", 1)[0]

    assert "result.transport = ProxyTransport::Tcp;" in mtproxy_branch
    assert "BoringMtproxyStealthOptions(std::move(result))" in mtproxy_branch
    assert "result.level == ProxyStealthLevel::Experimental" not in mtproxy_branch
    assert "ApplyProxyStealthLevel(" not in mtproxy_branch
    assert "capability.syntheticPskAllowed" not in mtproxy_branch
    assert "capability.fragmentationAllowed" not in mtproxy_branch

    for contract in (
        "result.transport = ProxyTransport::Tcp;",
        "result.clientHelloFragmentation = ProxyClientHelloFragmentation::Off;",
        "result.recordSizing = ProxyRecordSizing::Off;",
        "result.timing = ProxyTiming::Off;",
        "result.startupCover = ProxyStartupCover::Off;",
        "result.syntheticPsk = false;",
        "result.connectionPattern = ProxyConnectionPattern::Off;",
    ):
        assert contract in strict


def test_localhost_and_wss_remote_closed_disable_wss_by_proxy_key():
    policy = read(TRANSPORT_POLICY_CPP)
    allowed = function_body(policy, "bool ProxyWssAllowed(")
    note = function_body(policy, "void NoteProxyWssRemoteClosed(")

    assert "proxy.type != ProxyData::Type::Socks5" in allowed
    assert "IsLocalProxyEndpoint(proxy)" in allowed
    assert "!runtime->proxyServices().capabilities().wssAllowed(proxy)" in (
        allowed)
    assert "kWssRemoteClosedTtl = crl::time(30 * 60 * 1000)" in policy
    assert "noteWssRemoteClosed(" in note
    assert "kWssRemoteClosedTtl" in note
