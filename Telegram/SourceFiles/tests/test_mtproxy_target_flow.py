from pathlib import Path
from session_private_sources import read_session_private_sources


SOURCE_DIR = Path(__file__).resolve().parents[1]
PROXY_DIR = SOURCE_DIR / "mtproto" / "proxy"
MTPROXY_DIR = PROXY_DIR / "mtproxy"

SESSION_CPP = SOURCE_DIR / "mtproto" / "session" / "session.cpp"
SESSION_PRIVATE_CPP = SOURCE_DIR / "mtproto" / "session" / "private" / "session_private.cpp"
ABSTRACT_CONNECTION_CPP = SOURCE_DIR / "mtproto" / "transport" / "connection_abstract.cpp"
TRANSPORT_POLICY_CPP = PROXY_DIR / "transport_policy.cpp"
RESOLVING_CPP = PROXY_DIR / "resolving_connection.cpp"
CHECK_H = PROXY_DIR / "check.h"
CHECK_CPP = PROXY_DIR / "check.cpp"
TLS_SOCKET_CPP = MTPROXY_DIR / "tls_socket.cpp"
TLS_SOCKET_HANDSHAKE_CPP = MTPROXY_DIR / "tls_socket_handshake.cpp"
TLS_SOCKET_RECORDS_CPP = MTPROXY_DIR / "tls_socket_records.cpp"
STATUS_CPP = PROXY_DIR / "status.cpp"
WINDOW_CONNECTING_CPP = SOURCE_DIR / "window" / "window_connecting_widget.cpp"


def read(path):
    assert path.exists(), f"missing expected source file: {path}"
    return path.read_text(encoding="utf-8")


def compact(text):
    return " ".join(text.split())


def function_body(text: str, signature: str) -> str:
    start = text.index(signature)
    brace = text.index("{", start)
    depth = 0
    for index in range(brace, len(text)):
        char = text[index]
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return text[brace:index + 1]
    raise AssertionError(f"body not found for {signature}")


def test_user_proxy_selection_uses_capability_then_strict_mtproxy_plan():
    session = read(SESSION_CPP)
    policy = read(TRANSPORT_POLICY_CPP)
    refresh = function_body(session, "void Session::refreshOptions(")
    effective = function_body(policy, "ProxyStealthOptions EffectiveProxyStealthOptions(")
    mtproxy_branch = effective.split(
        "proxy.type == ProxyData::Type::Mtproto) {", 1)[1].split(
        "if (settings == ProxyData::Settings::Enabled", 1)[0]

    assert "EffectiveProxyStealthOptions(" in refresh
    assert "runtime->proxyServices().capabilities().lookup(proxy)" in (
        mtproxy_branch)
    assert mtproxy_branch.index("result.transport = ProxyTransport::Tcp;") < (
        mtproxy_branch.index(
            "runtime->proxyServices().capabilities().lookup(proxy)"))
    assert "BoringMtproxyStealthOptions(std::move(result))" in mtproxy_branch
    assert "ProxyTlsProfile::ChromeModern" in policy
    assert "capability.lastGoodProfile" in mtproxy_branch
    assert mtproxy_branch.index("capability.lastGoodProfile") < (
        mtproxy_branch.index("BoringMtproxyStealthOptions(std::move(result))"))
    assert "ProxyTransport::Wss" not in mtproxy_branch
    assert "ApplyProxyStealthLevel(" not in mtproxy_branch
    assert "syntheticPskAllowed" not in mtproxy_branch
    assert "fragmentationAllowed" not in mtproxy_branch


def test_dns_singleflight_precedes_route_open_and_route_racing_is_bounded():
    abstract = read(ABSTRACT_CONNECTION_CPP)
    resolving = read(RESOLVING_CPP)
    connect = function_body(
        resolving,
        "void ResolvingConnection::connectToServer(")
    start_resolving = function_body(
        resolving,
        "void ResolvingConnection::startResolving()")
    route_order = function_body(
        resolving,
        "std::vector<int> ResolvingConnection::routeOrder(")
    add_route = function_body(
        resolving,
        "void ResolvingConnection::addRouteAttempt(")

    assert "proxy.tryCustomResolve()" in abstract
    assert "ConnectionPointer::New<ResolvingConnection>" in abstract
    assert connect.index("_mtproxyAttempt = context.mtproxyAttempt;") < (
        connect.index("startResolving();"))
    assert "_runtime->proxyServices().dnsResolver().request(" in start_resolving
    assert "domainResolved(" in start_resolving
    assert "_runtime->proxyServices().capabilities().lookup(_proxy)" in (
        route_order)
    assert route_order.index("capability.goodRoutes") < (
        route_order.index("for (auto index = 0; index != int(_proxy.resolvedIPs.size())"))
    assert "MtProxy::RouteEndpointFromAddress(" in route_order
    assert "MtProxy::RouteKey(route)" in route_order
    assert "attempt.child = _child->clone(ToDirectIpProxy(_proxy, ipIndex));" in add_route
    assert add_route.index("ToDirectIpProxy(_proxy, ipIndex)") < (
        add_route.index("stored.child->connectToServer("))
    assert "kRouteRaceDelay = crl::time(300)" in resolving
    assert "kMaxParallelRouteAttempts = 2" in resolving
    assert "activeRouteAttempts() >= kMaxParallelRouteAttempts" in resolving


def test_logs_and_left_proxy_shield_expose_target_flow_state():
    resolving = read(RESOLVING_CPP)
    tls_handshake = read(TLS_SOCKET_HANDSHAKE_CPP)
    window = read(WINDOW_CONNECTING_CPP)
    route_event = function_body(resolving, "void ReportRouteEvent(")

    assert "MtProxy::ToLegacyDiagnostic(reason)" in route_event
    assert 'u"tcp_not_connected"_q' in route_event
    assert "ProxyDiagnosticsPhase::RouteSelected" in resolving
    assert "ProxyDiagnosticsPhase::RouteFailed" in resolving
    assert "ProxyDiagnosticsPhase::ClientHelloSent" in tls_handshake
    assert "reportTransportEvent(" in tls_handshake
    assert "_proxyIcon->moveToLeft(xShift, yShift);" in window
    assert "const auto progressVisible = visible && !_currentLayout.proxyEnabled;" in window
    assert "_proxyIcon->setVisible(_currentLayout.proxyEnabled);" in window
    assert "_cacheErrorDns" in window
    assert "_cacheErrorTimeout" in window
    assert "_cacheErrorHandshake" in window
    assert "_cacheErrorData" in window


def test_first_app_data_reported_once_per_tls_socket():
    tls = read(TLS_SOCKET_RECORDS_CPP)
    body = function_body(tls, "bool TlsSocket::checkNextPacket(")

    # FirstDataReceived progress and the health success report must fire
    # once per socket, not on every incoming TLS record: repeated reports
    # knock the proxy status from Connected back to CheckingTelegram.
    guard = body.index("if (!_firstAppDataReceived) {")
    assert guard < body.index("_firstAppDataReceived = true;")
    assert guard < body.index("connectionProgress(_phase);")
    assert guard < body.index("reportMtproxySuccess({")


def test_resolving_connection_forwards_timeout_to_route_attempts():
    resolving = read(RESOLVING_CPP)
    timed_out = function_body(
        resolving,
        "void ResolvingConnection::timedOut(")

    # The owner times out on the ResolvingConnection wrapper; without
    # forwarding, the TlsSocket doing the actual connect never reports
    # its failure to EndpointHealth and domain proxies never degrade.
    assert "attempt.child->timedOut();" in timed_out
    assert "_child->timedOut();" in timed_out


def test_stealth_option_changes_restart_proxy_connections():
    app = read(SOURCE_DIR / "core" / "application.cpp")
    box = read(SOURCE_DIR / "boxes" / "connection_box.cpp")
    apply_body = function_body(
        app,
        "void Application::applyProxyStealthOptions(")
    restart_body = function_body(
        app,
        "void Application::restartProxyConnections(")

    # Sessions read stealth options only when (re)connecting: writing
    # the setting without restarting MTP leaves e.g. a WSS transport
    # switch inert until something else (like toggling IPv6) restarts
    # connections.
    assert "setProxyStealthOptions(options);" in apply_body
    assert "_proxyRestartTimer" in apply_body
    assert "_proxyChanges.fire" in restart_body
    assert "Core::App().settings().setProxyStealthOptions(" not in box
    assert "Core::App().applyProxyStealthOptions(o);" in box
    assert "Core::App().restartProxyConnections();" in box
