from pathlib import Path
from session_private_sources import read_session_private_sources


SOURCE_DIR = Path(__file__).resolve().parents[1]
ROOT = SOURCE_DIR.parents[1]
CMAKE = ROOT / "Telegram" / "CMakeLists.txt"
MTPROXY_DIR = SOURCE_DIR / "mtproto" / "proxy" / "mtproxy"
DATA_H = SOURCE_DIR / "mtproto" / "proxy" / "data.h"
CORE_SETTINGS_CPP = SOURCE_DIR / "core" / "core_settings.cpp"
CONNECTION_BOX_CPP = SOURCE_DIR / "boxes" / "connection_box.cpp"
SESSION_CPP = SOURCE_DIR / "mtproto" / "session" / "private" / "session_private.cpp"
PROXY_CHECK_CPP = SOURCE_DIR / "mtproto" / "proxy" / "check.cpp"
CONNECTION_BROKER_H = SOURCE_DIR / "mtproto" / "proxy" / "connection_broker.h"
CONNECTION_BROKER_CPP = SOURCE_DIR / "mtproto" / "proxy" / "connection_broker.cpp"
ADAPTIVE_POLICY_CPP = MTPROXY_DIR / "adaptive_policy.cpp"
SCHEDULER_H = MTPROXY_DIR / "open_scheduler.h"
SCHEDULER_CPP = MTPROXY_DIR / "open_scheduler.cpp"


def test_mtproxy_open_scheduler_module_is_registered():
    cmake = CMAKE.read_text(encoding="utf-8")

    assert SCHEDULER_H.exists()
    assert SCHEDULER_CPP.exists()
    assert "mtproto/proxy/mtproxy/open_scheduler.cpp" in cmake
    assert "mtproto/proxy/mtproxy/open_scheduler.h" in cmake


def test_connection_spread_defaults_to_browser_and_manual_toggle_is_soft():
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
        "\t\t\t\t\t? MTP::ProxyConnectionPattern::Soft\n"
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


def test_adaptive_recipe_uses_ladder_for_spacing():
    source = ADAPTIVE_POLICY_CPP.read_text(encoding="utf-8")
    body = body_after(source, "AdaptiveRecipeResult ApplyAdaptiveRecipe")

    assert "IsLightConnectionPattern" not in source
    assert "ApplyProxyStealthLevel(" in body
    assert "ProxyConnectionPattern::Quiet" not in body


def test_connection_broker_reserves_global_open_slot_before_start():
    broker = CONNECTION_BROKER_CPP.read_text(encoding="utf-8")
    drain_body = body_after(broker, "void ConnectionBroker::drainQueue(")

    assert '#include "mtproto/proxy/mtproxy/open_scheduler.h"' in broker
    assert '#include "mtproto/proxy/control_plane.h"' in broker
    assert "ProxyControlPlane::Admit({" in drain_body
    assert "MtProxy::ReserveOpenSlot(" in drain_body
    assert "state->request.connectionPattern" in drain_body
    assert "state->request.notBefore" in drain_body
    assert "ConnectionBrokerAction::StartAfter" in drain_body
    assert drain_body.index("MtProxy::ReserveOpenSlot(") < drain_body.index(
        "scheduleStart(state, openDelay)")


def test_connection_broker_cancels_by_runtime_environment():
    broker = CONNECTION_BROKER_H.read_text(encoding="utf-8")

    assert "class RuntimeEnvironment;" in broker
    assert (
        "void cancelByProxyGeneration("
        "RuntimeEnvironment *runtime, uint64 generation);"
    ) in broker
    assert "MTP::Instance" not in broker


def test_live_mtproxy_connects_through_connection_broker_before_syn():
    session = read_session_private_sources()
    append_body = body_after(session, "bool SessionPrivate::appendTestConnection")

    assert '#include "mtproto/proxy/connection_broker.h"' in session
    assert "ConnectionBroker::Instance().request({" in append_body
    assert "MtProxy::ReserveOpenSlot(" not in append_body
    assert "mtproxyEndpoint" in append_body
    assert "stealth.connectionPattern" in append_body
    assert ".start = [=](ConnectionStart start)" in append_body
    assert "weak->connectToServer(" in append_body


def test_proxy_check_uses_same_connection_broker_before_syn():
    proxy_check = PROXY_CHECK_CPP.read_text(encoding="utf-8")
    start_body = body_after(proxy_check, "void StartProxyCheck")

    assert '#include "mtproto/proxy/connection_broker.h"' in (
        SOURCE_DIR / "mtproto" / "proxy" / "check.h").read_text(encoding="utf-8")
    assert "MtProxy::EndpointIdFromProxy(proxy, checkStealth)" in start_body
    assert "details::ConnectionBroker::Instance().request({" in start_body
    assert "MtProxy::ReserveOpenSlot(" not in start_body
    assert "checkStealth.connectionPattern" in start_body
    assert ".notBefore = gateDelay" in start_body
    assert "raw->connectToServer(" in start_body


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


def test_scheduler_paces_adaptively_on_connect_timeouts():
    header = SCHEDULER_H.read_text(encoding="utf-8")
    source = SCHEDULER_CPP.read_text(encoding="utf-8")

    # Failure-driven pacing is independent of the stealth pattern: with
    # the pattern Off a throttling proxy must still get a growing gap
    # between new opens, and successes must shrink it back to zero.
    assert "void NoteConnectTimeout(const EndpointId &endpoint);" in header
    assert "void NoteConnectSuccess(const EndpointId &endpoint);" in header
    assert "constexpr auto kAdaptiveSpacingMin = crl::time(500)" in source
    assert "constexpr auto kAdaptiveSpacingMax = crl::time(6000)" in source
    assert "crl::time adaptiveSpacing = 0;" in source
    assert "state.adaptiveSpacing * 2" in source
    assert "state.adaptiveSpacing / 2" in source


def test_scheduler_limits_open_bursts_per_endpoint():
    source = SCHEDULER_CPP.read_text(encoding="utf-8")

    # A cold start with several accounts/sessions may fire a rapid run
    # of fresh handshakes at one endpoint - the scan-like pattern that
    # makes proxies throttle. Beyond a small burst, opens are spaced.
    assert "constexpr auto kOpenBurstCount = 3;" in source
    assert "constexpr auto kOpenBurstWindow = crl::time(10 * 1000);" in source
    assert "constexpr auto kOpenBurstSpacing = crl::time(2500);" in source
    assert "std::deque<crl::time> recentOpens;" in source
    assert "state.recentOpens.pop_front();" in source
    assert "burstSpacing" in source
    # Burst pacing only engages after a real timeout, not preemptively.
    assert "state.adaptiveSpacing > 0" in source


if __name__ == "__main__":
    test_mtproxy_open_scheduler_module_is_registered()
    test_connection_spread_defaults_to_browser_and_manual_toggle_is_soft()
    test_scheduler_defines_safe_open_gap_and_off_bypass()
    test_adaptive_recipe_uses_ladder_for_spacing()
    test_connection_broker_reserves_global_open_slot_before_start()
    test_connection_broker_cancels_by_runtime_environment()
    test_live_mtproxy_connects_through_connection_broker_before_syn()
    test_proxy_check_uses_same_connection_broker_before_syn()
    test_scheduler_paces_adaptively_on_connect_timeouts()
    test_scheduler_limits_open_bursts_per_endpoint()
