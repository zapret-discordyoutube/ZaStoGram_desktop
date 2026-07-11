from pathlib import Path
from session_private_sources import read_session_private_sources


SOURCE_DIR = Path(__file__).resolve().parents[1]
ROOT = SOURCE_DIR.parents[1]
CMAKE = ROOT / "Telegram" / "CMakeLists.txt"
MTPROXY_DIR = SOURCE_DIR / "mtproto" / "proxy" / "mtproxy"
DATA_H = SOURCE_DIR / "mtproto" / "runtime" / "proxy_data.h"
CORE_SETTINGS_CPP = SOURCE_DIR / "core" / "core_settings.cpp"
CONNECTION_BOX_CPP = SOURCE_DIR / "boxes" / "connection_box.cpp"
SESSION_CPP = SOURCE_DIR / "mtproto" / "session" / "private" / "session_private.cpp"
PROXY_CHECK_CPP = SOURCE_DIR / "mtproto" / "proxy" / "check.cpp"
CONNECTION_BROKER_H = SOURCE_DIR / "mtproto" / "proxy" / "connection_broker.h"
CONNECTION_BROKER_CPP = SOURCE_DIR / "mtproto" / "proxy" / "connection_broker.cpp"
ADAPTIVE_POLICY_CPP = MTPROXY_DIR / "adaptive_policy.cpp"
SCHEDULER_H = MTPROXY_DIR / "open_scheduler.h"
SCHEDULER_CPP = MTPROXY_DIR / "open_scheduler.cpp"
SCHEDULER_TEST_CPP = SOURCE_DIR / "tests" / "test_mtproxy_open_scheduler.cpp"


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


def test_scheduler_defines_safe_open_gap_and_pattern_spacing():
    header = SCHEDULER_H.read_text(encoding="utf-8")
    source = SCHEDULER_CPP.read_text(encoding="utf-8")

    assert "[[nodiscard]] crl::time OpenConnectionSpacing(" in header
    assert "[[nodiscard]] OpenSlotReservation ReserveOpenSlot(" in header
    assert "crl::time notBefore = 0" in header
    assert "constexpr auto kOpenSpacingJitter = crl::time(125)" in source
    assert "constexpr auto kMinimumOpenSpacing = crl::time(500)" in source
    assert "case ProxyConnectionPattern::Soft: return crl::time(1100);" in source
    assert "case ProxyConnectionPattern::Quiet: return crl::time(1200);" in source
    assert "case ProxyConnectionPattern::Strict: return crl::time(1400);" in source
    assert "case ProxyConnectionPattern::Browser: return crl::time(1150);" in source
    assert "case ProxyConnectionPattern::Off: break;" in source
    assert "return crl::time(0);" in source
    assert "EndpointKey(endpoint)" in source
    assert "PendingOpenRecord" in source


def test_adaptive_recipe_uses_ladder_for_spacing():
    source = ADAPTIVE_POLICY_CPP.read_text(encoding="utf-8")
    body = body_after(source, "AdaptiveRecipeResult ApplyAdaptiveRecipe")

    assert "IsLightConnectionPattern" not in source
    assert "ApplyProxyStealthLevel(" in body
    assert "ProxyConnectionPattern::Quiet" not in body


def test_connection_broker_reserves_global_open_slot_before_start():
    broker = CONNECTION_BROKER_CPP.read_text(encoding="utf-8")
    drain_body = body_after(broker, "void ConnectionBroker::drainQueue(")
    verdict_body = body_after(
        broker,
        "ConnectionBroker::DrainVerdict ConnectionBroker::computeVerdict(")
    commit_admitted = body_after(
        broker, "void ConnectionBroker::commitAdmitted(")

    assert '#include "mtproto/proxy/mtproxy/open_scheduler.h"' in broker
    assert '#include "mtproto/proxy/control_plane.h"' in broker
    assert "_runtime->proxyServices().control().admit({" in verdict_body
    assert "MtProxy::ReserveOpenSlot(" in verdict_body
    assert "state->request.connectionPattern" in verdict_body
    assert "state->request.notBefore" in verdict_body
    assert "ConnectionBrokerAction::StartAfter" in commit_admitted
    assert "state->request.notBefore = 0;" in commit_admitted
    assert "state->openRetryAt = _runtime->async().now()" in commit_admitted
    assert "scheduleOpenRetry(state, claim.openRetryAfter);" in drain_body
    assert "releaseAdmission(state);" in commit_admitted
    assert "scheduleOpenRetry(state, openDelay);" in commit_admitted
    # The slot is reserved during the admission pass, before the retry
    # for a delayed open is armed.
    assert broker.index("MtProxy::ReserveOpenSlot(") < broker.index(
        "scheduleOpenRetry(state, openDelay)")


def test_connection_broker_cancels_by_runtime_environment():
    broker = CONNECTION_BROKER_H.read_text(encoding="utf-8")

    assert "class RuntimeEnvironment;" in broker
    assert "void cancelByProxyGeneration(uint64 generation);" in broker
    assert "MTP::Instance" not in broker


def test_live_mtproxy_connects_through_connection_broker_before_syn():
    session = read_session_private_sources()
    append_body = body_after(session, "bool SessionTransport::appendTestConnection")

    assert '#include "mtproto/session/private/proxy_port.h"' in session
    assert "_owner->_proxyPort->requestConnection({" in append_body
    assert "MtProxy::ReserveOpenSlot(" not in append_body
    assert "std::move(start.endpoint)" in append_body
    assert "stealth.connectionPattern" in append_body
    assert ".start = [=](SessionProxyStart start)" in append_body
    assert "weak->connectToServer(" in append_body


def test_proxy_check_uses_same_connection_broker_before_syn():
    proxy_check = PROXY_CHECK_CPP.read_text(encoding="utf-8")
    start_body = body_after(proxy_check, "void StartProxyCheck")

    assert '#include "mtproto/proxy/proxy_services.h"' in proxy_check
    assert "MtProxy::EndpointIdFromProxy(proxy, checkStealth)" in start_body
    assert "runtime->proxyServices().broker().request({" in start_body
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
    assert "void NoteConnectTimeout(" in header
    assert "not_null<RuntimeEnvironment*> runtime" in header
    assert "void NoteConnectSuccess(" in header
    assert "constexpr auto kAdaptiveSpacingMin = crl::time(500)" in source
    assert "constexpr auto kAdaptiveSpacingMax = crl::time(6000)" in source
    context = (SOURCE_DIR / "mtproto" / "proxy" /
        "proxy_endpoint_context_p.h").read_text(encoding="utf-8")
    assert "crl::time adaptiveSpacing = 0;" in context
    assert "state.adaptiveSpacing * 2" in source
    assert "state.adaptiveSpacing / 2" in source


def test_scheduler_evenly_spaces_opens_per_endpoint():
    source = SCHEDULER_CPP.read_text(encoding="utf-8")
    scenario = SCHEDULER_TEST_CPP.read_text(encoding="utf-8")

    assert "constexpr auto kMinimumOpenSpacing = crl::time(500);" in source
    context = (SOURCE_DIR / "mtproto" / "proxy" /
        "proxy_endpoint_context_p.h").read_text(encoding="utf-8")
    assert "std::deque<OpenRecord> recentOpens;" in context
    assert "std::deque<PendingOpenRecord> pendingOpens;" in context
    assert "state.recentOpens.erase(expired" in source
    assert "entry.nextOpenAt <= now" in source
    assert (
        "{ kMinimumOpenSpacing, patternSpacing, state.adaptiveSpacing }"
        in source)
    assert "state.pendingOpens.push_back({" in source
    assert "state.adaptiveSpacing > 0" not in source
    assert "ProxyConnectionPattern::Off" in scenario
    assert "cold endpoint opens should use steady spacing" in scenario
    assert "coldSecond.delay() != crl::time(507)" in scenario
    assert "coldThird.delay() != crl::time(1014)" in scenario
    assert "coldFourth.delay() != crl::time(1521)" in scenario
    assert "cancelled future slots should not delay a retry" in scenario
    assert "empty endpoint should preserve the requested delay" in scenario
    assert "expired real opens should release steady spacing" in scenario
    assert "destroyed reservations should release future slots" in scenario


def test_scheduler_releases_cancelled_broker_reservations():
    header = SCHEDULER_H.read_text(encoding="utf-8")
    source = SCHEDULER_CPP.read_text(encoding="utf-8")
    broker = CONNECTION_BROKER_CPP.read_text(encoding="utf-8")

    assert "class OpenSlotReservation final" in header
    assert "~OpenSlotReservation();" in header
    assert "void commit();" in header
    assert "void cancel();" in header
    assert "state.pendingOpens.erase(i);" in source
    assert "MtProxy::OpenSlotReservation openSlot;" in broker
    assert "state->openSlot = std::move(verdict.openSlot);" in broker
    assert "state->openSlot.commit();" in broker
    assert "state->openSlot.cancel();" in broker


if __name__ == "__main__":
    test_mtproxy_open_scheduler_module_is_registered()
    test_connection_spread_defaults_to_browser_and_manual_toggle_is_soft()
    test_scheduler_defines_safe_open_gap_and_pattern_spacing()
    test_adaptive_recipe_uses_ladder_for_spacing()
    test_connection_broker_reserves_global_open_slot_before_start()
    test_connection_broker_cancels_by_runtime_environment()
    test_live_mtproxy_connects_through_connection_broker_before_syn()
    test_proxy_check_uses_same_connection_broker_before_syn()
    test_scheduler_paces_adaptively_on_connect_timeouts()
    test_scheduler_evenly_spaces_opens_per_endpoint()
    test_scheduler_releases_cancelled_broker_reservations()
