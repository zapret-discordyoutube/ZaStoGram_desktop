from pathlib import Path
from session_private_sources import read_session_private_sources


SOURCE_DIR = Path(__file__).resolve().parents[1]
PROXY_DIR = SOURCE_DIR / "mtproto" / "proxy"
MTPROXY_DIR = PROXY_DIR / "mtproxy"
TRANSPORT_POLICY_CPP = PROXY_DIR / "transport_policy.cpp"
DATA_CPP = PROXY_DIR / "data.cpp"
SESSION_CPP = SOURCE_DIR / "mtproto" / "session" / "private" / "session_private.cpp"
CONNECTION_BROKER_CPP = PROXY_DIR / "connection_broker.cpp"
ENDPOINT_HEALTH_CPP = MTPROXY_DIR / "endpoint_health.cpp"
TLS_SOCKET_CPP = MTPROXY_DIR / "tls_socket.cpp"


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


def test_mtproxy_default_hotfix_ignores_autorotate_and_adaptive_recipe():
    policy = read(TRANSPORT_POLICY_CPP)
    adaptive = read(MTPROXY_DIR / "adaptive_policy.cpp")
    effective = function_body(policy, "ProxyStealthOptions EffectiveProxyStealthOptions(")
    recipe = function_body(adaptive, "AdaptiveRecipeResult ApplyAdaptiveRecipe(")
    mtproxy_branch = effective.split(
        "proxy.type == ProxyData::Type::Mtproto) {", 1)[1].split(
        "if (settings == ProxyData::Settings::Enabled", 1)[0]

    assert "BoringMtproxyStealthOptions(" in policy
    assert "ProxyTlsProfile::ChromeModern" in policy
    assert "result.tlsProfile = profile;" in policy
    assert "BoringMtproxyStealthOptions(std::move(result))" in mtproxy_branch
    assert "ProxyTlsProfile::AutoRotate" not in mtproxy_branch
    assert "ResolveEffectiveTlsProfile(" not in mtproxy_branch
    assert "input.stealth.level == ProxyStealthLevel::CompatStrict" in recipe
    assert recipe.index(
        "input.stealth.level == ProxyStealthLevel::CompatStrict") < (
            recipe.index("ApplyProxyStealthLevel("))


def test_admission_delay_is_queued_not_failed_or_backoff():
    session = read_session_private_sources()
    broker = read(CONNECTION_BROKER_CPP)
    append = function_body(session, "bool SessionPrivate::appendTestConnection(")
    notify = function_body(broker, "void ConnectionBroker::notify(")

    assert "ProxyDiagnosticsPhase::AdmissionQueued" in broker
    assert "ConnectionBrokerAction::Queued" in notify
    assert "ConnectionBrokerAction::StartAfter" in notify
    assert "ProxyDiagnosticsPhase::Failed" not in notify
    assert "setState(-int(admission.retryAfter));" not in append
    assert "mtproxy admission delayed" not in append


def test_route_success_updates_canonical_capability_and_health():
    health = read(ENDPOINT_HEALTH_CPP)
    tls = read(TLS_SOCKET_CPP)
    success = function_body(health, "void EndpointHealth::reportSuccess(")
    packet = function_body(tls, "bool TlsSocket::checkNextPacket()")

    assert "ProxyCapabilityCache::Instance().noteMtproxySuccess(" in success
    assert "CapabilityProxyKey(report.endpoint.canonical)" in success
    assert "RouteKey(report.endpoint.route)" in success
    assert "state.lastFailure = FailureReason::None;" in success
    assert "state.healthy = true;" in success
    assert "ProxyControlPlane::ReportMtproxySuccess({" in packet


def test_localhost_and_wss_remote_closed_disable_wss_by_proxy_key():
    policy = read(TRANSPORT_POLICY_CPP)
    allowed = function_body(policy, "bool ProxyWssAllowed(")
    note = function_body(policy, "void NoteProxyWssRemoteClosed(")

    assert "proxy.type != ProxyData::Type::Socks5" in allowed
    assert "IsLocalProxyEndpoint(proxy)" in allowed
    assert "!ProxyCapabilityCache::Instance().wssAllowed(proxy)" in allowed
    assert "kWssRemoteClosedTtl = crl::time(30 * 60 * 1000)" in policy
    assert "noteWssRemoteClosed(" in note
    assert "kWssRemoteClosedTtl" in note


def test_pre_clienthello_timeouts_do_not_rotate_or_escalate_recipes():
    health = read(ENDPOINT_HEALTH_CPP)
    cooldown = function_body(health, "bool FailureNeedsCooldown(")
    recipe = function_body(health, "bool FailureNeedsRecipeEscalation(")
    rotation = function_body(health, "bool FailureNeedsTlsRotation(")
    route_only = function_body(health, "bool FailureIsRouteOnly(")

    for reason in ("TcpConnectTimeout", "TcpConnectedNoClientHelloWrite"):
        assert f"case FailureReason::{reason}:" in recipe
        assert "return false;" in recipe.split(f"case FailureReason::{reason}:")[1]
        assert f"case FailureReason::{reason}:" in rotation
        assert "return false;" in rotation.split(f"case FailureReason::{reason}:")[1]
        assert f"case FailureReason::{reason}:" in cooldown
        assert "return false;" in cooldown.split(f"case FailureReason::{reason}:")[1]
        assert f"case FailureReason::{reason}:" in route_only
        assert "return true;" in route_only.split(f"case FailureReason::{reason}:")[1]


if __name__ == "__main__":
    test_mtproxy_effective_policy_is_always_conservative_tcp()
    test_mtproxy_default_hotfix_ignores_autorotate_and_adaptive_recipe()
    test_admission_delay_is_queued_not_failed_or_backoff()
    test_route_success_updates_canonical_capability_and_health()
    test_localhost_and_wss_remote_closed_disable_wss_by_proxy_key()
    test_pre_clienthello_timeouts_do_not_rotate_or_escalate_recipes()
