from pathlib import Path


SOURCE_DIR = Path(__file__).resolve().parents[1]
PROXY_DATA_H = SOURCE_DIR / "mtproto" / "mtproto_proxy_data.h"
CORE_SETTINGS_CPP = SOURCE_DIR / "core" / "core_settings.cpp"
CONNECTION_BOX_CPP = SOURCE_DIR / "boxes" / "connection_box.cpp"
CORE_SETTINGS_PROXY_CPP = SOURCE_DIR / "core" / "core_settings_proxy.cpp"
APPLICATION_CPP = SOURCE_DIR / "core" / "application.cpp"


def test_wss_transport_is_the_stealth_default():
    header = PROXY_DATA_H.read_text(encoding="utf-8")

    assert "ProxyTransport transport = ProxyTransport::Wss;" in header


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


def test_default_local_proxy_port_is_generated_on_first_add():
    source = CORE_SETTINGS_PROXY_CPP.read_text(encoding="utf-8")

    assert '#include "base/random.h"' in source
    assert "kDefaultProxyPortMin" in source
    assert "kDefaultProxyPortMax" in source
    assert "GenerateDefaultProxyPort()" in source
    assert "def.port = GenerateDefaultProxyPort();" in source
    assert "def.port = 1353;" not in source


def test_active_mtproxy_forces_wss_transport_off():
    source = CORE_SETTINGS_CPP.read_text(encoding="utf-8")

    assert "mtprotoProxyEnabled()" in source
    assert "result.transport = MTP::ProxyTransport::Tcp;" in source
    assert "auto copy = value;" in source
    assert "copy.transport = MTP::ProxyTransport::Tcp;" in source
    assert 'write("mtproxy/transport", int(copy.transport));' in source


def test_enabling_mtproxy_persists_wss_transport_off():
    source = APPLICATION_CPP.read_text(encoding="utf-8")

    assert "DisableWssForMtprotoProxy(" in source
    assert "proxy.type != MTP::ProxyData::Type::Mtproto" in source
    assert "stealth.transport = MTP::ProxyTransport::Tcp;" in source
    assert "settings.setProxyStealthOptions(stealth);" in source


def test_route_via_wss_checkbox_refreshes_after_proxy_change():
    source = CONNECTION_BOX_CPP.read_text(encoding="utf-8")

    assert "QPointer<Ui::Checkbox> _routeViaWss;" in source
    assert "void refreshRouteViaWss();" in source
    assert "void ProxiesBox::refreshRouteViaWss()" in source
    assert "_routeViaWss->setChecked(" in source
    assert "Ui::Checkbox::NotifyAboutChange::DontNotify" in source
    assert "refreshRouteViaWss();" in source


if __name__ == "__main__":
    test_wss_transport_is_the_stealth_default()
    test_persisted_transport_falls_back_to_wss()
    test_route_via_wss_toggle_uses_transport_setting()
    test_default_local_proxy_port_is_generated_on_first_add()
    test_active_mtproxy_forces_wss_transport_off()
    test_enabling_mtproxy_persists_wss_transport_off()
    test_route_via_wss_checkbox_refreshes_after_proxy_change()
