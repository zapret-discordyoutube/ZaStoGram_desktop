from pathlib import Path


SOURCE_DIR = Path(__file__).resolve().parents[1]
ROOT = SOURCE_DIR.parents[1]
CMAKE = ROOT / "Telegram" / "CMakeLists.txt"
MTPROXY_DIR = SOURCE_DIR / "mtproto" / "proxy" / "mtproxy"
DATA_H = SOURCE_DIR / "mtproto" / "proxy" / "data.h"
CORE_SETTINGS_CPP = SOURCE_DIR / "core" / "core_settings.cpp"
CONNECTION_BOX_CPP = SOURCE_DIR / "boxes" / "connection_box.cpp"
SESSION_CPP = SOURCE_DIR / "mtproto" / "session_private.cpp"
PROXY_CHECK_CPP = SOURCE_DIR / "mtproto" / "proxy" / "check.cpp"
ADAPTIVE_POLICY_CPP = MTPROXY_DIR / "adaptive_policy.cpp"
SCHEDULER_H = MTPROXY_DIR / "open_scheduler.h"
SCHEDULER_CPP = MTPROXY_DIR / "open_scheduler.cpp"


def test_mtproxy_open_scheduler_module_is_registered():
    cmake = CMAKE.read_text(encoding="utf-8")

    assert SCHEDULER_H.exists()
    assert SCHEDULER_CPP.exists()
    assert "mtproto/proxy/mtproxy/open_scheduler.cpp" in cmake
    assert "mtproto/proxy/mtproxy/open_scheduler.h" in cmake


def test_connection_spread_defaults_to_browser_and_can_be_disabled():
    data = DATA_H.read_text(encoding="utf-8")
    settings = CORE_SETTINGS_CPP.read_text(encoding="utf-8")
    box = CONNECTION_BOX_CPP.read_text(encoding="utf-8")

    assert (
        "ProxyConnectionPattern connectionPattern "
        "= ProxyConnectionPattern::Browser;"
    ) in data
    assert '"mtproxy/pattern",\n\t\tint(result.connectionPattern),' in settings
    assert (
        "o.connectionPattern = on\n"
        "\t\t\t\t\t? MTP::ProxyConnectionPattern::Browser\n"
        "\t\t\t\t\t: MTP::ProxyConnectionPattern::Off;"
    ) in box


def test_scheduler_defines_safe_open_gap_and_off_bypass():
    header = SCHEDULER_H.read_text(encoding="utf-8")
    source = SCHEDULER_CPP.read_text(encoding="utf-8")

    assert "[[nodiscard]] crl::time OpenConnectionSpacing(" in header
    assert "[[nodiscard]] crl::time ReserveOpenSlot(" in header
    assert "crl::time notBefore = 0" in header
    assert "constexpr auto kOpenSpacingJitter = crl::time(125)" in source
    assert "case ProxyConnectionPattern::Soft: return crl::time(1100);" in source
    assert "case ProxyConnectionPattern::Quiet: return crl::time(1200);" in source
    assert "case ProxyConnectionPattern::Strict: return crl::time(1400);" in source
    assert "case ProxyConnectionPattern::Browser: return crl::time(1150);" in source
    assert "case ProxyConnectionPattern::Off: break;" in source
    assert "return crl::time(0);" in source
    assert "EndpointKey(endpoint)" in source
    assert "nextOpenAt" in source


def test_adaptive_recipe_does_not_reenable_disabled_spread():
    source = ADAPTIVE_POLICY_CPP.read_text(encoding="utf-8")
    body = body_after(source, "bool IsLightConnectionPattern")

    assert "ProxyConnectionPattern::Off" not in body
    assert "ProxyConnectionPattern::Soft" in body
    assert "ProxyConnectionPattern::Browser" in body


def test_live_mtproxy_connects_reserve_global_open_slot_before_syn():
    session = SESSION_CPP.read_text(encoding="utf-8")
    append_body = body_after(session, "bool SessionPrivate::appendTestConnection")

    assert '#include "mtproto/proxy/mtproxy/open_scheduler.h"' in session
    assert "MtProxy::ReserveOpenSlot(" in append_body
    assert "mtproxyEndpoint" in append_body
    assert "_options->stealth.connectionPattern" in append_body
    assert "const auto localDelay = mtproxy" in append_body
    assert "const auto openDelay" in append_body
    assert "QTimer::singleShot(int(openDelay), weak, start);" in append_body
    assert append_body.index("MtProxy::ReserveOpenSlot(") < append_body.index(
        "if (openDelay > 0)")


def test_proxy_check_reserves_same_mtproxy_open_slot_before_syn():
    proxy_check = PROXY_CHECK_CPP.read_text(encoding="utf-8")
    start_body = body_after(proxy_check, "void StartProxyCheck")

    assert '#include "mtproto/proxy/mtproxy/open_scheduler.h"' in proxy_check
    assert "MtProxy::EndpointIdFromProxy(proxy, checkStealth)" in start_body
    assert "MtProxy::ReserveOpenSlot(" in start_body
    assert "checkStealth.connectionPattern" in start_body
    assert "const auto openDelay" in start_body
    assert "checkStealth.connectionPattern,\n\t\t\t\tgateDelay)" in start_body
    assert "QTimer::singleShot(int(openDelay), raw, start);" in start_body
    assert start_body.index("MtProxy::ReserveOpenSlot(") < start_body.index(
        "raw->connectToServer(")


def body_after(text: str, signature: str) -> str:
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
    test_mtproxy_open_scheduler_module_is_registered()
    test_connection_spread_defaults_to_browser_and_can_be_disabled()
    test_scheduler_defines_safe_open_gap_and_off_bypass()
    test_adaptive_recipe_does_not_reenable_disabled_spread()
    test_live_mtproxy_connects_reserve_global_open_slot_before_syn()
    test_proxy_check_reserves_same_mtproxy_open_slot_before_syn()
