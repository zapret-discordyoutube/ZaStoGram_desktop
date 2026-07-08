from pathlib import Path


SOURCE_DIR = Path(__file__).resolve().parents[1]
PROXY_DIR = SOURCE_DIR / "mtproto" / "proxy"
CAPABILITIES_CPP = PROXY_DIR / "capabilities.cpp"
ENDPOINT_HEALTH_H = PROXY_DIR / "mtproxy" / "endpoint_health.h"
ENDPOINT_HEALTH_CPP = PROXY_DIR / "mtproxy" / "endpoint_health.cpp"
ENDPOINT_HEALTH_CAPABILITIES_CPP = (
    PROXY_DIR / "mtproxy" / "endpoint_health_capabilities.cpp")
ENDPOINT_IDENTITY_H = PROXY_DIR / "mtproxy" / "endpoint_identity.h"
ENDPOINT_IDENTITY_CPP = PROXY_DIR / "mtproxy" / "endpoint_identity.cpp"
RESOLVING_CONNECTION_CPP = PROXY_DIR / "resolving_connection.cpp"
TRANSPORT_POLICY_CPP = PROXY_DIR / "transport_policy.cpp"


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


def return_statement(body, anchor):
    start = body.index(anchor)
    return body[start:body.index(";", start)]


def assert_ordered(text, tokens):
    position = -1
    for token in tokens:
        index = text.index(token)
        assert index > position, f"segment out of order: {token}"
        position = index


def test_capability_writer_key_matches_reader_key_format():
    # ProxyCapabilityCache cards are written from mtproxy endpoint health
    # reports under CapabilityProxyKey(endpoint) and read back through
    # ProxyCapabilityKey(proxy). Both must produce the exact same string
    # (host:port:type:secretHash:domain) or goodRoutes/lastGoodTransport
    # learning silently becomes dead code.
    capabilities = read(CAPABILITIES_CPP)
    identity = read(ENDPOINT_IDENTITY_CPP)

    reader = function_body(capabilities, "QString ProxyCapabilityKey(")
    writer = function_body(
        identity,
        "QString CapabilityProxyKey(const CanonicalProxyEndpoint &endpoint)")

    reader_return = return_statement(reader, "return host")
    writer_return = return_statement(writer, "return endpoint.originalHost")

    assert_ordered(reader_return, [
        "host",
        "port",
        "QString::number(int(proxy.type))",
        "ProxyCapabilitySecretHash(proxy)",
        "ProxyCapabilityDomain(proxy)",
    ])
    assert_ordered(writer_return, [
        "endpoint.originalHost",
        "QString::number(endpoint.port)",
        "QString::number(int(endpoint.type))",
        "endpoint.secretHash",
        "endpoint.domainFromSecret",
    ])

    # Same number of segments on both sides: five values, four separators.
    assert reader_return.count("':'") == 4
    assert writer_return.count("':'") == 4

    # The extra EndpointKey segment must never leak into the capability key.
    assert "proxyKind" not in writer_return
    assert "endpoint.proxyKind" not in writer.split("return endpoint.originalHost", 1)[1]


def test_capability_key_components_compute_identical_values():
    # The writer key is built from CanonicalProxyEndpoint fields filled by
    # EndpointIdFromProxy, the reader key from ProxyData helpers; each pair
    # of helpers must stay textually identical so both sides hash the same
    # inputs to the same values.
    capabilities = read(CAPABILITIES_CPP)
    identity = read(ENDPOINT_IDENTITY_CPP)

    assert function_body(
        capabilities, "QString ProxyCapabilityHost(",
    ) == function_body(
        identity, "QString ProxyIdentityHost(",
    )
    for helper in (
        "QString DomainFromSecret(",
        "QString HashBytes(",
        "QString HashText(",
    ):
        assert function_body(capabilities, helper) == function_body(
            identity, helper)

    from_proxy = function_body(identity, "EndpointId EndpointIdFromProxy(")
    secret_hash = function_body(
        capabilities, "QString ProxyCapabilitySecretHash(")
    assert "result.canonical.secretHash = HashBytes(secret);" in from_proxy
    assert "result.canonical.secretHash = HashText(proxy.password);" in from_proxy
    assert "HashBytes(bytes::make_span(secret))" in secret_hash
    assert "HashText(proxy.password)" in secret_hash

    domain = function_body(capabilities, "QString ProxyCapabilityDomain(")
    assert "DomainFromSecret(bytes::make_span(secret))" in domain
    assert "result.canonical.domainFromSecret = DomainFromSecret(secret);" in from_proxy


def test_capability_writers_and_readers_use_the_matching_keys():
    capabilities = read(CAPABILITIES_CPP)
    header = read(ENDPOINT_IDENTITY_H)
    health = read(ENDPOINT_HEALTH_CPP)
    capabilities_bridge = read(ENDPOINT_HEALTH_CAPABILITIES_CPP)
    resolving = read(RESOLVING_CONNECTION_CPP)
    policy = read(TRANSPORT_POLICY_CPP)

    assert "QString CapabilityProxyKey(const CanonicalProxyEndpoint &endpoint)" in header

    failure = function_body(health, "void EndpointHealth::reportFailure(")
    success = function_body(health, "void EndpointHealth::reportSuccess(")
    assert "NoteCapabilityMtproxyFailure(" in failure
    assert "runtime->proxyServices().capabilities().noteMtproxyFailure(" in (
        capabilities_bridge)
    assert "CapabilityProxyKey(report.endpoint.canonical)" in failure
    assert "NoteCapabilityMtproxySuccess(" in success
    assert "runtime->proxyServices().capabilities().noteMtproxySuccess(" in (
        capabilities_bridge)
    assert "CapabilityProxyKey(report.endpoint.canonical)" in success

    # Writers must not fall back to the health-state EndpointKey, which has
    # an extra proxyKind segment lookup(proxy) can never match.
    for call in ("noteMtproxyFailure(", "noteMtproxySuccess("):
        callsite = capabilities_bridge[capabilities_bridge.index(call):]
        callsite = callsite[:callsite.index(";")]
        assert "EndpointKey(" not in callsite.replace("CapabilityProxyKey(", "")

    lookup = function_body(
        capabilities,
        "ProxyCapabilityCard ProxyCapabilityCache::lookup(const ProxyData &proxy)")
    assert "lookup(ProxyCapabilityKey(proxy))" in lookup
    route_order = function_body(
        resolving, "std::vector<int> ResolvingConnection::routeOrder(")
    assert "_runtime->proxyServices().capabilities().lookup(_proxy)" in (
        route_order)
    assert "capability.goodRoutes" in route_order
    assert "runtime->proxyServices().capabilities().lookup(proxy)" in policy


if __name__ == "__main__":
    test_capability_writer_key_matches_reader_key_format()
    test_capability_key_components_compute_identical_values()
    test_capability_writers_and_readers_use_the_matching_keys()
