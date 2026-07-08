from pathlib import Path
from session_private_sources import read_session_private_sources


SOURCE_DIR = Path(__file__).resolve().parents[1]
PROXY_DATA_H = SOURCE_DIR / "mtproto" / "proxy" / "data.h"
RUNTIME_PROXY_DATA_H = SOURCE_DIR / "mtproto" / "runtime" / "proxy_data.h"
PROXY_DATA_CPP = SOURCE_DIR / "mtproto" / "proxy" / "data.cpp"
WSS_SOCKET_H = SOURCE_DIR / "mtproto" / "proxy" / "wss" / "socket.h"
WSS_SOCKET_CPP = SOURCE_DIR / "mtproto" / "proxy" / "wss" / "socket.cpp"
CORE_SETTINGS_CPP = SOURCE_DIR / "core" / "core_settings.cpp"
CONNECTION_BOX_CPP = SOURCE_DIR / "boxes" / "connection_box.cpp"
CORE_SETTINGS_PROXY_CPP = SOURCE_DIR / "core" / "core_settings_proxy.cpp"
APPLICATION_CPP = SOURCE_DIR / "core" / "application.cpp"
PROXY_CHECK_H = SOURCE_DIR / "mtproto" / "proxy" / "check.h"
PROXY_CHECK_CPP = SOURCE_DIR / "mtproto" / "proxy" / "check.cpp"
PROXY_ROTATION_MANAGER_CPP = SOURCE_DIR / "core" / "proxy_rotation_manager.cpp"
TRANSPORT_POLICY_H = SOURCE_DIR / "mtproto" / "proxy" / "transport_policy.h"
TRANSPORT_POLICY_CPP = SOURCE_DIR / "mtproto" / "proxy" / "transport_policy.cpp"
SESSION_CPP = SOURCE_DIR / "mtproto" / "session" / "session.cpp"
SESSION_PRIVATE_CPP = SOURCE_DIR / "mtproto" / "session" / "private" / "session_private.cpp"
CONNECTION_TCP_CPP = SOURCE_DIR / "mtproto" / "transport" / "connection_tcp.cpp"
CMAKE_LISTS = SOURCE_DIR.parent / "CMakeLists.txt"


def test_wss_transport_is_the_stealth_default():
    header = RUNTIME_PROXY_DATA_H.read_text(encoding="utf-8")

    assert "ProxyTransport transport = ProxyTransport::Wss;" in header


def test_wss_transport_lives_in_proxy_module():
    header = WSS_SOCKET_H.read_text(encoding="utf-8")
    source = WSS_SOCKET_CPP.read_text(encoding="utf-8")

    assert "struct WssRoute" in header
    assert "class WssSocket final" in header
    assert '#include "mtproto/proxy/wss/socket.h"' in source


def test_wss_keeps_tls_peer_verification_enabled():
    header = WSS_SOCKET_H.read_text(encoding="utf-8")
    source = WSS_SOCKET_CPP.read_text(encoding="utf-8")

    assert "VerifyNone" not in source
    assert "QSslSocket::VerifyPeer" in source
    assert "_socket.setPeerVerifyName(_route.domain);" in source
    assert "connectToRelayHost(" in source
    assert "void connectToRelayHost();" in header


def test_persisted_transport_falls_back_to_wss():
    source = CORE_SETTINGS_CPP.read_text(encoding="utf-8")

    assert 'read(\n\t\t"mtproxy/transport",' in source
    assert "int(MTP::ProxyTransport::Wss)))" in source


def test_route_via_wss_toggle_uses_transport_setting():
    source = CONNECTION_BOX_CPP.read_text(encoding="utf-8")

    assert 'u"Route via WSS (web, DC2/DC4 only)"_q' in source
    assert "(saved.transport == MTP::ProxyTransport::Wss)" in source
    assert "? MTP::ProxyTransport::Wss" in source
    assert ": MTP::ProxyTransport::Tcp" in source


def test_default_local_proxy_port_matches_documented_telegram_proxy():
    source = CORE_SETTINGS_PROXY_CPP.read_text(encoding="utf-8")

    assert '#include "base/random.h"' not in source
    assert "kDefaultProxyPort = 1353" in source
    assert "GenerateDefaultProxyPort()" not in source
    assert "def.port = kDefaultProxyPort;" in source


def test_wss_transport_policy_is_the_single_effective_entrypoint():
    header = TRANSPORT_POLICY_H.read_text(encoding="utf-8")
    source = TRANSPORT_POLICY_CPP.read_text(encoding="utf-8")
    cmake = CMAKE_LISTS.read_text(encoding="utf-8")

    assert '#include "mtproto/proxy/data.h"' in header
    assert "[[nodiscard]] bool ProxyWssAllowed(" in header
    assert "void NoteProxyWssRemoteClosed(" in header
    assert "[[nodiscard]] ProxyTransport EffectiveProxyTransport(" in header
    assert "[[nodiscard]] ProxyStealthOptions EffectiveProxyStealthOptions(" in header
    assert "proxy.type == ProxyData::Type::None" in source
    assert "proxy.type != ProxyData::Type::Socks5" in source
    assert "proxy.type == ProxyData::Type::Mtproto" in source
    assert "proxy.type != ProxyData::Type::Mtproto" not in source
    assert "settings != ProxyData::Settings::Enabled" in source
    assert "result.transport = EffectiveProxyTransport(" in source
    assert "CompatStrictProxyStealthOptions(" in source
    assert "mtproto/proxy/transport_policy.cpp" in cmake
    assert "mtproto/proxy/transport_policy.h" in cmake


def test_wss_policy_allows_only_direct_or_nonlocal_socks_until_forbidden():
    source = TRANSPORT_POLICY_CPP.read_text(encoding="utf-8")
    allowed_body = function_body(source, "bool ProxyWssAllowed(")

    assert "settings != ProxyData::Settings::Enabled" in allowed_body
    assert "proxy.type == ProxyData::Type::None" in allowed_body
    assert "proxy.type != ProxyData::Type::Socks5" in allowed_body
    assert "IsLocalProxyEndpoint(proxy)" in allowed_body
    assert "runtime->proxyServices().capabilities().wssAllowed(proxy)" in (
        allowed_body)
    assert "ProxyWssForbidden(proxy)" not in allowed_body
    assert "ProxyData::Type::Http" not in allowed_body


def test_compat_strict_disables_stealth_for_mtproxy_and_local_tunnels():
    header = RUNTIME_PROXY_DATA_H.read_text(encoding="utf-8")
    proxy_header = PROXY_DATA_H.read_text(encoding="utf-8")
    data = PROXY_DATA_CPP.read_text(encoding="utf-8")
    source = TRANSPORT_POLICY_CPP.read_text(encoding="utf-8")
    strict_body = function_body(
        data,
        "ProxyStealthOptions CompatStrictProxyStealthOptions(")
    level_body = function_body(
        data,
        "ProxyStealthOptions ApplyProxyStealthLevel(")
    effective_body = function_body(
        source,
        "ProxyStealthOptions EffectiveProxyStealthOptions(")

    assert "enum class ProxyStealthLevel" in header
    assert "CompatStrict" in header
    assert "CompatModern" in header
    assert "DpiAdaptiveHandshake" in header
    assert "DpiAdaptiveData" in header
    assert "Experimental" in header
    assert "ProxyStealthLevel level" in header
    assert "bool syntheticPsk = false;" in header
    assert "ApplyProxyStealthLevel(" in proxy_header
    assert "CompatStrictProxyStealthOptions(" in proxy_header
    assert "result.transport = ProxyTransport::Tcp;" in strict_body
    assert (
        "result.clientHelloFragmentation = "
        "ProxyClientHelloFragmentation::Off;" in strict_body)
    assert "result.recordSizing = ProxyRecordSizing::Off;" in strict_body
    assert "result.timing = ProxyTiming::Off;" in strict_body
    assert "result.startupCover = ProxyStartupCover::Off;" in strict_body
    assert "result.syntheticPsk = false;" in strict_body
    assert "result.connectionPattern = ProxyConnectionPattern::Off;" in strict_body
    assert "result.tlsProfile = ProxyTlsProfile::Auto;" in strict_body
    assert "case ProxyStealthLevel::CompatStrict:" in level_body
    assert "case ProxyStealthLevel::CompatModern:" in level_body
    assert "case ProxyStealthLevel::DpiAdaptiveHandshake:" in level_body
    assert "case ProxyStealthLevel::DpiAdaptiveData:" in level_body
    assert "case ProxyStealthLevel::Experimental:" in level_body
    assert "result.clientHelloFragmentation = ProxyClientHelloFragmentation::Off;" in level_body
    assert "result.syntheticPsk = false;" in level_body
    assert "result.recordSizing = ProxyRecordSizing::Conservative;" in level_body
    assert "result.timing = ProxyTiming::Gentle;" in level_body
    assert "result.startupCover = ProxyStartupCover::Soft;" in level_body
    assert "proxy.type == ProxyData::Type::Mtproto" in effective_body
    assert "result.transport = ProxyTransport::Tcp;" in effective_body
    mtproxy_branch = effective_body.split(
        "proxy.type == ProxyData::Type::Mtproto) {", 1)[1].split(
        "if (settings == ProxyData::Settings::Enabled", 1)[0]
    assert "result.level == ProxyStealthLevel::Experimental" not in mtproxy_branch
    assert "ApplyProxyStealthLevel(" not in mtproxy_branch
    assert "capability.syntheticPskAllowed" not in mtproxy_branch
    assert "capability.fragmentationAllowed" not in mtproxy_branch
    assert "IsLocalProxyEndpoint(proxy)" in effective_body
    assert "!ProxyWssAllowed(runtime, proxy, settings)" in effective_body
    assert "return CompatStrictProxyStealthOptions(std::move(result));" in effective_body


def test_persisted_transport_is_raw_and_not_mtproxy_clamped():
    source = CORE_SETTINGS_CPP.read_text(encoding="utf-8")

    assert "mtprotoProxyEnabled" not in source
    assert "result.transport = MTP::ProxyTransport::Tcp;" not in source
    assert "copy.transport = MTP::ProxyTransport::Tcp;" not in source
    assert '"mtproxy/stealthLevel"' in source
    assert '"mtproxy/syntheticPsk"' in source
    assert 'write("mtproxy/transport", int(value.transport));' in source
    assert 'write("mtproxy/stealthLevel", int(value.level));' in source
    assert 'write("mtproxy/syntheticPsk", value.syntheticPsk ? 1 : 0);' in source


def test_enabling_mtproxy_does_not_rewrite_saved_transport():
    source = APPLICATION_CPP.read_text(encoding="utf-8")

    assert "DisableWssForMtprotoProxy" not in source
    assert "setProxyStealthOptions(stealth)" not in source


def test_route_via_wss_checkbox_refreshes_after_proxy_change():
    source = CONNECTION_BOX_CPP.read_text(encoding="utf-8")

    assert "QPointer<Ui::Checkbox> _routeViaWss;" in source
    assert "void refreshRouteViaWss();" in source
    assert "void ProxiesBox::refreshRouteViaWss()" in source
    assert "_routeViaWss->setChecked(" in source
    assert "Ui::Checkbox::NotifyAboutChange::DontNotify" in source
    assert "refreshRouteViaWss();" in source


def test_runtime_consumers_use_effective_transport_policy():
    header = PROXY_CHECK_H.read_text(encoding="utf-8")
    source = PROXY_CHECK_CPP.read_text(encoding="utf-8")
    box = CONNECTION_BOX_CPP.read_text(encoding="utf-8")
    session = SESSION_CPP.read_text(encoding="utf-8")
    rotation = PROXY_ROTATION_MANAGER_CPP.read_text(encoding="utf-8")

    assert '#include "mtproto/proxy/transport_policy.h"' in session
    assert "MTP::EffectiveProxyStealthOptions(" in session
    assert "const ProxyStealthOptions &stealth" in header
    assert "const ProxyStealthOptions &stealth" in source
    assert '#include "mtproto/proxy/transport_policy.h"' in source
    assert "MTP::EffectiveProxyStealthOptions(" in source
    assert "checkStealth.transport = ProxyTransport::Tcp;" not in source
    assert "Connection::Create(" in source
    assert "checkStealth);" in source
    assert "ProxyStealthOptions())" not in source
    assert box.count("Core::App().settings().proxyStealthOptions(),") >= 2
    assert "MTP::ProxyWssAllowed(" in box
    assert "App().settings().proxyStealthOptions()," in rotation


def test_wss_dc_coverage_policy_is_centralized_and_soft():
    header = TRANSPORT_POLICY_H.read_text(encoding="utf-8")
    source = TRANSPORT_POLICY_CPP.read_text(encoding="utf-8")

    assert "enum class WssDcCoverage" in header
    assert "Unavailable" in header
    assert "Official" in header
    assert "Custom" in header
    assert "[[nodiscard]] WssDcCoverage WssDcCoverageForDc(" in header
    assert "[[nodiscard]] bool WssNeedsProxyRecommendation(" in header
    assert '#include "mtproto/proxy/wss/socket.h"' in source
    assert "WssCustomRoute(stealth)" in source
    assert "WssOfficialRoute(protocolDcId, protocolForFiles)" in source
    assert "proxy.type == ProxyData::Type::None" in source
    assert "stealth.transport == ProxyTransport::Wss" in source
    assert "WssDcCoverage::Unavailable" in source


def test_wss_direct_fallback_requests_proxy_without_blocking():
    session = read_session_private_sources()

    assert '#include "mtproto/proxy/transport_policy.h"' in session
    assert "WssNeedsProxyRecommendation(" in session
    assert "MTP::ConnectionNotice::WssDirectFallback" in session
    assert "setConnectionNotice(MTP::ConnectionNotice::None)" in session
    assert "_sessionState.options->stealth.transport != ProxyTransport::Wss" in session
    assert "kWaitForProxyTimeout" in session


def test_wss_remembers_working_relay_host_across_sockets():
    header = WSS_SOCKET_H.read_text(encoding="utf-8")
    source = WSS_SOCKET_CPP.read_text(encoding="utf-8")
    connect_body = function_body(
        source,
        "void WssSocket::connectToHost(")
    timed_out_body = function_body(source, "void WssSocket::timedOut()")
    error_body = function_body(source, "void WssSocket::handleError(")
    upgrade_body = function_body(source, "bool WssSocket::tryFinishUpgrade()")

    # A blocked primary relay IP must not be re-tried first by every new
    # socket: the working host is remembered process-wide with a TTL, the
    # in-socket retry flips between hosts in both directions, and the
    # session-level connect watchdog (which kills the socket before
    # errorOccurred fires) records the stalled host too.
    assert "bool _hostFlipped = false;" in header
    assert "kRelayFallbackPreferenceTtl" in source
    assert "Q_UNUSED(address);" in connect_body
    assert "Q_UNUSED(port);" in connect_body
    assert "_usedFallback = PreferRelayFallback(_route);" in connect_body
    assert "NoteRelayAttemptFailed(_route, _usedFallback);" in timed_out_body
    assert "NoteRelayAttemptFailed(_route, _usedFallback);" in error_body
    assert "_usedFallback = !_usedFallback;" in error_body
    assert "NoteRelayUpgraded(_route, _usedFallback);" in upgrade_body


def test_wss_remote_closed_forbids_wss_for_that_proxy():
    source = CONNECTION_TCP_CPP.read_text(encoding="utf-8")
    error_body = function_body(source, "void TcpConnection::socketError(")

    assert '#include "mtproto/proxy/transport_policy.h"' in source
    # The local must not shadow AbstractConnection::error(qint32) which is
    # called at the end of socketError().
    assert "const auto proxyError = SocketProxyConnectionError(errorCode);" in error_body
    assert "const auto error = " not in error_body
    assert "const auto transport = _socket->transportName();" in error_body
    assert "transport == u\"WSS\"_q" in error_body
    assert "proxyError == ProxyConnectionError::RemoteClosed" in error_body
    assert "NoteProxyWssRemoteClosed(_runtime, _proxy);" in error_body
    assert "error(errorCode);" in error_body
    assert ".transport = (transport == u\"WSS\"_q) ? transport : tag()," in error_body


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


if __name__ == "__main__":
    test_wss_transport_is_the_stealth_default()
    test_wss_transport_lives_in_proxy_module()
    test_wss_keeps_tls_peer_verification_enabled()
    test_persisted_transport_falls_back_to_wss()
    test_route_via_wss_toggle_uses_transport_setting()
    test_default_local_proxy_port_matches_documented_telegram_proxy()
    test_wss_transport_policy_is_the_single_effective_entrypoint()
    test_wss_policy_allows_only_direct_or_nonlocal_socks_until_forbidden()
    test_compat_strict_disables_stealth_for_mtproxy_and_local_tunnels()
    test_persisted_transport_is_raw_and_not_mtproxy_clamped()
    test_enabling_mtproxy_does_not_rewrite_saved_transport()
    test_route_via_wss_checkbox_refreshes_after_proxy_change()
    test_runtime_consumers_use_effective_transport_policy()
    test_wss_dc_coverage_policy_is_centralized_and_soft()
    test_wss_direct_fallback_requests_proxy_without_blocking()
    test_wss_remembers_working_relay_host_across_sockets()
    test_wss_remote_closed_forbids_wss_for_that_proxy()
