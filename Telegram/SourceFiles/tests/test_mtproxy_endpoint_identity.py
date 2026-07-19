from pathlib import Path
from session_private_sources import read_session_private_sources


SOURCE_DIR = Path(__file__).resolve().parents[1]
MTPROXY_DIR = SOURCE_DIR / "mtproto" / "proxy" / "mtproxy"
ROOT = SOURCE_DIR.parents[1]
CMAKE = ROOT / "Telegram" / "CMakeLists.txt"
ENDPOINT_IDENTITY_H = MTPROXY_DIR / "endpoint_identity.h"
ENDPOINT_IDENTITY_CPP = MTPROXY_DIR / "endpoint_identity.cpp"
ENDPOINT_HEALTH_H = MTPROXY_DIR / "endpoint_health.h"
ENDPOINT_HEALTH_CPP = MTPROXY_DIR / "endpoint_health.cpp"
ENDPOINT_HEALTH_STATE_H = MTPROXY_DIR / "endpoint_health_state.h"
ARBITER_H = SOURCE_DIR / "mtproto" / "proxy" / "endpoint_admission_arbiter.h"
CONNECTION_STATUS_TYPES_H = (
    SOURCE_DIR / "mtproto" / "runtime" / "connection_status_types.h")
RUNTIME_PROXY_ENDPOINT_H = SOURCE_DIR / "mtproto" / "runtime" / "proxy_endpoint.h"
CONNECTION_BROKER_CPP = SOURCE_DIR / "mtproto" / "proxy" / "connection_broker.cpp"
CHECK_CPP = SOURCE_DIR / "mtproto" / "proxy" / "check.cpp"
SESSION_CPP = SOURCE_DIR / "mtproto" / "session" / "private" / "session_private.cpp"
SESSION_PROXY_PORT_CPP = (
    SOURCE_DIR / "mtproto" / "session" / "private" / "proxy_port.cpp")
TLS_SOCKET_CPP = MTPROXY_DIR / "tls_socket.cpp"


def read(path):
    assert path.exists(), f"missing expected source file: {path}"
    return path.read_text(encoding="utf-8")


def function_body(source, signature):
    start = source.index(signature)
    brace = source.index("{", start)
    depth = 0
    for i in range(brace, len(source)):
        if source[i] == "{":
            depth += 1
        elif source[i] == "}":
            depth -= 1
            if depth == 0:
                return source[brace:i + 1]
    raise AssertionError(f"function body not found: {signature}")


def test_endpoint_identity_is_split_into_canonical_and_route():
    cmake = read(CMAKE)
    identity_header = read(ENDPOINT_IDENTITY_H)
    endpoint_header = read(RUNTIME_PROXY_ENDPOINT_H)
    health_header = read(ENDPOINT_HEALTH_H)

    assert "mtproto/proxy/mtproxy/endpoint_identity.cpp" in cmake
    assert "mtproto/proxy/mtproxy/endpoint_identity.h" in cmake
    assert '#include "mtproto/proxy/mtproxy/endpoint_identity.h"' in health_header
    assert "struct CanonicalProxyEndpoint" not in health_header
    assert "EndpointId EndpointIdFromProxy(" not in health_header
    assert "struct CanonicalProxyEndpoint" not in identity_header
    assert "struct CanonicalProxyEndpoint" in endpoint_header
    assert "ProxyData::Type type" in endpoint_header
    assert "QString originalHost;" in endpoint_header
    assert "QString secretHash;" in endpoint_header
    assert "QString domainFromSecret;" in endpoint_header
    assert "ProxyData::Type proxyKind" in endpoint_header
    assert "enum class RouteAddressFamily" in endpoint_header
    assert "struct RouteEndpoint" in endpoint_header
    assert "QString address;" in endpoint_header
    assert "RouteAddressFamily addressFamily" in endpoint_header
    assert "ProxyTransport transport" in endpoint_header
    assert "QString resolvedFromHost;" in endpoint_header
    assert "CanonicalProxyEndpoint canonical;" in endpoint_header
    assert "RouteEndpoint route;" in endpoint_header
    assert "QString resolvedHost;" not in endpoint_header
    assert "QString EndpointKey(const CanonicalProxyEndpoint &endpoint)" in (
        identity_header)
    assert "QString RouteKey(const RouteEndpoint &route)" in identity_header
    assert "bool EndpointEmpty(const EndpointId &endpoint)" in identity_header
    arbiter = read(ARBITER_H)
    ticket_owner = function_body(arbiter, "struct OpeningPermitTicketOwner")
    permit = function_body(arbiter, "struct EndpointOpeningPermit")
    attempt = function_body(
        read(CONNECTION_STATUS_TYPES_H), "struct ProxyConnectionAttempt")
    assert "AdmissionTicketKey key;" in ticket_owner
    assert "uint64 revision = 0;" in ticket_owner
    assert "EndpointOpeningPermitOwner owner;" in permit
    assert "OpenSlotSchedule openings;" in permit
    assert "using EndpointOpeningPermitOwner = std::variant<" in arbiter
    assert "ProxyConnectionAttempt>" in arbiter
    assert "LiveSlot" not in arbiter
    assert "reclaim" not in arbiter
    for field in (
        "runtimeId",
        "traceId",
        "ticketId",
        "proxyGeneration",
        "proxyEpoch",
        "successEpoch",
        "attemptId",
        "use",
        "ticketKey",
    ):
        assert field in attempt


def test_endpoint_id_from_proxy_preserves_host_identity_and_route_identity():
    source = read(ENDPOINT_IDENTITY_CPP)
    health = read(ENDPOINT_HEALTH_CPP)
    body = function_body(source, "EndpointId EndpointIdFromProxy(")
    canonical_key = function_body(
        source,
        "QString EndpointKey(const CanonicalProxyEndpoint &endpoint)")
    route_key = function_body(source, "QString RouteKey(const RouteEndpoint &route)")

    assert "result.canonical.originalHost = ProxyIdentityHost(proxy);" in body
    assert "result.canonical.port = int(proxy.port);" in body
    assert "result.route = RouteEndpointFromAddress(" in body
    assert "result.canonical.originalHost" in body
    assert "result.canonical.secretHash = HashBytes(secret);" in body
    assert "result.canonical.domainFromSecret = DomainFromSecret(secret);" in body
    assert "result.canonical.secretHash = HashText(proxy.password);" in body
    assert "route.address" not in canonical_key
    assert "route.resolvedFromHost" not in canonical_key
    assert "endpoint.originalHost" in canonical_key
    assert "endpoint.secretHash" in canonical_key
    assert "endpoint.domainFromSecret" in canonical_key
    assert "route.address" in route_key
    assert "route.resolvedFromHost" in route_key
    assert "route.transport" in route_key
    assert "route.addressFamily" in route_key
    assert "EndpointId EndpointIdFromProxy(" not in health
    assert "QString EndpointKey(const CanonicalProxyEndpoint &endpoint)" not in (
        health)


def test_route_success_promotes_to_canonical_but_route_failure_stays_local():
    source = read(ENDPOINT_HEALTH_CPP)
    state = read(ENDPOINT_HEALTH_STATE_H)
    context = read(SOURCE_DIR / "mtproto" / "proxy" /
        "proxy_endpoint_context_p.h")
    failure = function_body(source, "void EndpointHealth::reportFailure(")
    success = function_body(source, "void EndpointHealth::reportSuccess(")

    assert "std::map<QString, RouteState> routes;" in context
    assert "std::set<QString> routeKeys;" in state
    assert "RouteKey(report.endpoint.route)" in failure
    assert "NoteRouteFailure(" in failure
    assert "HasHealthyRoute(" in failure
    assert "return;" in failure.split("HasHealthyRoute(")[1]
    assert "RouteKey(report.endpoint.route)" in success
    assert "NoteRouteSuccess(" in success
    assert "state.healthy = true;" in success
    assert "state.lastFailure = FailureReason::None;" in success


def test_consumers_treat_endpoint_empty_as_canonical_empty():
    broker = read(CONNECTION_BROKER_CPP)
    check = read(CHECK_CPP)
    session = read_session_private_sources()
    tls = read(TLS_SOCKET_CPP)

    assert "MtProxy::EndpointEmpty(request.endpoint)" in broker
    assert "MtProxy::EndpointEmpty(state->mtproxyEndpoint)" in check
    assert "EmptySessionProxyEndpoint(connection.mtproxyEndpoint)" in session
    assert "EmptySessionProxyEndpoint(found->mtproxyEndpoint)" in session
    assert "EmptySessionProxyEndpoint(_state.mtproxyEndpoint)" in session
    proxy_port = read(SESSION_PROXY_PORT_CPP)
    assert "endpoint.canonical.type == ProxyData::Type::None" in proxy_port
    assert "_endpointId.route = MtProxy::RouteEndpointFromAddress(" in tls
    assert "MtProxy::EndpointKey(_endpointId.canonical)" in tls


if __name__ == "__main__":
    test_endpoint_identity_is_split_into_canonical_and_route()
    test_endpoint_id_from_proxy_preserves_host_identity_and_route_identity()
    test_route_success_promotes_to_canonical_but_route_failure_stays_local()
    test_consumers_treat_endpoint_empty_as_canonical_empty()
