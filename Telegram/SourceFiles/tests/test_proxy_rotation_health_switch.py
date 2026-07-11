from pathlib import Path


SOURCE_DIR = Path(__file__).resolve().parents[1]
ROTATION_MANAGER_H = SOURCE_DIR / "core" / "proxy_rotation_manager.h"
ROTATION_MANAGER_CPP = SOURCE_DIR / "core" / "proxy_rotation_manager.cpp"


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


def handler_body() -> str:
    return function_body(
        read(ROTATION_MANAGER_CPP),
        "void ProxyRotationManager::handleEndpointHealthChanged(")


def test_health_events_are_filtered_to_the_selected_proxy():
    header = read(ROTATION_MANAGER_H)
    body = handler_body()

    # admit() starvation fires for every endpoint in the broker, including
    # candidates the rotation manager probes itself. Only events for the
    # currently selected proxy may extend the health-rotation window,
    # otherwise a starving candidate keeps checking alive forever.
    assert "bool isSelectedProxyEndpoint(" in header
    assert "isSelectedProxyEndpoint(event.endpoint)" in body
    filter_at = body.index("isSelectedProxyEndpoint(event.endpoint)")
    bump_at = body.index("accumulate_max(")
    assert filter_at < bump_at, "filter must run before the window is bumped"


def test_degraded_window_is_decoupled_from_the_short_cooldown():
    source = read(ROTATION_MANAGER_CPP)
    body = handler_body()

    # A proxy that flaps under DPI briefly returns to ConnectedState
    # between failures. If the rotation window only lasted as long as the
    # (now possibly 3s) per-failure cooldown, reevaluate() would stop
    # checking on each brief recovery and rotation could never converge
    # on a stable candidate. Hold the window open a fixed minimum.
    assert "kSelectedDegradedObserveWindow" in source
    assert "crl::now() + kSelectedDegradedObserveWindow" in body


def test_selected_endpoint_match_uses_canonical_endpoint_key():
    source = read(ROTATION_MANAGER_CPP)
    body = function_body(
        source, "bool ProxyRotationManager::isSelectedProxyEndpoint(")

    assert "settings.isEnabled()" in body
    assert "EndpointIdFromProxy(" in body
    assert "EndpointKey(selected)" in body
    assert "!key.isEmpty()" in body


def test_health_request_short_circuits_a_running_switch_wait():
    body = handler_body()

    # startChecking() is a no-op while checks run, so without this the
    # event could never act. When the selected proxy has been starving
    # and a candidate already passed its probe, switch immediately
    # instead of waiting out the rest of proxyRotationTimeout.
    assert "const auto wasChecking = _checking;" in body
    assert "reevaluate();" in body
    assert "if (!wasChecking || !_checking || _waitingToSwitch)" in body
    assert "if (shouldSwitchToAvailable())" in body
    assert "switchToAvailable()" in body


def test_health_request_stays_conservative_without_verified_candidate():
    source = read(ROTATION_MANAGER_CPP)
    body = handler_body()

    # The handler must not force a switch during a total outage: it never
    # enters the waiting-to-switch state and never touches the switch
    # timer, so with no probe-verified candidate nothing changes.
    assert "_waitingToSwitch =" not in body
    assert "_switchTimer" not in body
    assert "switchTimerDone" not in body

    # switchToAvailable() keeps requiring a probe success from the current
    # checking session, so stale availability can't trigger a switch.
    switch = function_body(
        source, "bool ProxyRotationManager::switchToAvailable(")
    assert "entry->availableAt >= _switchStartedAt" in switch
    # It prefers a candidate main-use health has not marked relay-blocked
    # (a ProxyCheck pass alone does not prove the relay), but falls back to
    # any available one so rotation never gets stuck on a total outage.
    assert "proxyRelayHealthy(settings.list()[index])" in switch
    assert "chosen = fallback;" in switch
    health = function_body(
        source, "bool ProxyRotationManager::proxyRelayHealthy(")
    assert "mtproxyEndpointSnapshot(endpoint)" in health
    # Self-healing: block only an endpoint actively in cooldown (halfOpen
    # persists until a fresh success, so it must NOT gate here).
    assert "snapshot.terminalUntil <= crl::now()" in health
    assert "snapshot.halfOpen" not in health
    # Must not abort when no account exists to consult (checkDone path).
    assert "productionAccounts().empty()" in health

    # And the switch remains gated on rotation actually being sensible
    # (observing enabled, accounts present, disconnected or starving).
    gate = function_body(
        source, "bool ProxyRotationManager::shouldSwitchToAvailable(")
    assert "shouldObserve()" in gate
    assert "hasActiveHealthRotationRequest()" in gate


def test_switch_grace_period_prevents_rotation_ping_pong():
    source = read(ROTATION_MANAGER_CPP)
    header = read(ROTATION_MANAGER_H)
    switch = function_body(
        source, "bool ProxyRotationManager::switchToAvailable(")
    handler = handler_body()
    stop = function_body(source, "void ProxyRotationManager::stopChecking(")

    # Every switch restarts all sessions of every account; a freshly
    # selected proxy needs seconds to bring the main session up. Without
    # a grace period the next probe success sees "still not connected"
    # and hops again - observed as the selection ping-ponging across the
    # whole list every ~2 seconds with a restart storm on each hop.
    assert "kAfterSwitchGracePeriod" in source
    assert "crl::time _lastSwitchAt = 0;" in header
    assert "_lastSwitchAt" in switch
    assert switch.index("kAfterSwitchGracePeriod") < switch.index(
        "App().setCurrentProxy(")

    # A successful switch stamps the grace period and drops the health
    # window that belonged to the previous selection.
    assert "_lastSwitchAt = crl::now();" in switch
    assert "_healthRotationRequestedUntil = 0;" in switch

    # Warm-up degradation right after a switch must not re-open the
    # rotation window, and the switch itself must be release-visible in
    # the proxy diagnostics log.
    assert "kAfterSwitchGracePeriod" in handler
    assert "RotationSwitched" in switch

    # The grace period must survive the stopChecking()/startChecking()
    # cycle that setCurrentProxy() triggers through settingsChanged().
    assert "_lastSwitchAt" not in stop


if __name__ == "__main__":
    test_health_events_are_filtered_to_the_selected_proxy()
    test_selected_endpoint_match_uses_canonical_endpoint_key()
    test_health_request_short_circuits_a_running_switch_wait()
    test_health_request_stays_conservative_without_verified_candidate()
    test_switch_grace_period_prevents_rotation_ping_pong()
