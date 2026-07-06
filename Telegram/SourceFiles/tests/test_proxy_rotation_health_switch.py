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
    bump_at = body.index("accumulate_max(_healthRotationRequestedUntil")
    assert filter_at < bump_at, "filter must run before the window is bumped"


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
    assert "entry->availableAt < _switchStartedAt" in switch

    # And the switch remains gated on rotation actually being sensible
    # (observing enabled, accounts present, disconnected or starving).
    gate = function_body(
        source, "bool ProxyRotationManager::shouldSwitchToAvailable(")
    assert "shouldObserve()" in gate
    assert "hasActiveHealthRotationRequest()" in gate


if __name__ == "__main__":
    test_health_events_are_filtered_to_the_selected_proxy()
    test_selected_endpoint_match_uses_canonical_endpoint_key()
    test_health_request_short_circuits_a_running_switch_wait()
    test_health_request_stays_conservative_without_verified_candidate()
