from pathlib import Path


SOURCE_DIR = Path(__file__).resolve().parents[1]
PROXY_DATA_H = SOURCE_DIR / "mtproto" / "proxy" / "data.h"
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
SESSION_CPP = SOURCE_DIR / "mtproto" / "session.cpp"
SESSION_PRIVATE_CPP = SOURCE_DIR / "mtproto" / "session_private.cpp"
CMAKE_LISTS = SOURCE_DIR.parent / "CMakeLists.txt"


def test_wss_transport_is_the_stealth_default():
    header = PROXY_DATA_H.read_text(encoding="utf-8")

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
    assert "[[nodiscard]] ProxyTransport EffectiveProxyTransport(" in header
    assert "[[nodiscard]] ProxyStealthOptions EffectiveProxyStealthOptions(" in header
    assert "proxy.type != ProxyData::Type::Mtproto" in source
    assert "settings != ProxyData::Settings::Enabled" in source
    assert "result.transport = EffectiveProxyTransport(" in source
    assert "mtproto/proxy/transport_policy.cpp" in cmake
    assert "mtproto/proxy/transport_policy.h" in cmake


def test_persisted_transport_is_raw_and_not_mtproxy_clamped():
    source = CORE_SETTINGS_CPP.read_text(encoding="utf-8")

    assert "mtprotoProxyEnabled" not in source
    assert "result.transport = MTP::ProxyTransport::Tcp;" not in source
    assert "copy.transport = MTP::ProxyTransport::Tcp;" not in source
    assert 'write("mtproxy/transport", int(value.transport));' in source


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
    session = SESSION_PRIVATE_CPP.read_text(encoding="utf-8")

    assert '#include "mtproto/proxy/transport_policy.h"' in session
    assert "WssNeedsProxyRecommendation(" in session
    assert "MTP::ConnectionNotice::WssDirectFallback" in session
    assert "setConnectionNotice(MTP::ConnectionNotice::None)" in session
    assert "_options->stealth.transport != ProxyTransport::Wss" in session
    assert "kWaitForProxyTimeout" in session


if __name__ == "__main__":
    test_wss_transport_is_the_stealth_default()
    test_wss_transport_lives_in_proxy_module()
    test_wss_keeps_tls_peer_verification_enabled()
    test_persisted_transport_falls_back_to_wss()
    test_route_via_wss_toggle_uses_transport_setting()
    test_default_local_proxy_port_matches_documented_telegram_proxy()
    test_wss_transport_policy_is_the_single_effective_entrypoint()
    test_persisted_transport_is_raw_and_not_mtproxy_clamped()
    test_enabling_mtproxy_does_not_rewrite_saved_transport()
    test_route_via_wss_checkbox_refreshes_after_proxy_change()
    test_runtime_consumers_use_effective_transport_policy()
    test_wss_dc_coverage_policy_is_centralized_and_soft()
    test_wss_direct_fallback_requests_proxy_without_blocking()
