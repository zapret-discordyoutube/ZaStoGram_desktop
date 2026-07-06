from pathlib import Path


SOURCE_DIR = Path(__file__).resolve().parents[1]
ROOT = SOURCE_DIR.parents[1]
CMAKE = ROOT / "Telegram" / "CMakeLists.txt"
PROXY_DIR = SOURCE_DIR / "mtproto" / "proxy"
DNS_CACHE_H = PROXY_DIR / "dns_resolver_cache.h"
DNS_CACHE_CPP = PROXY_DIR / "dns_resolver_cache.cpp"
RESOLVING_H = PROXY_DIR / "resolving_connection.h"
RESOLVING_CPP = PROXY_DIR / "resolving_connection.cpp"
DOMAIN_RESOLVER_CPP = SOURCE_DIR / "mtproto" / "details" / "mtproto_domain_resolver.cpp"


def read(path):
    assert path.exists(), f"missing expected source file: {path}"
    return path.read_text(encoding="utf-8")


def function_body(source, signature):
    start = source.index(signature)
    brace = source.index("{", start)
    depth = 0
    for index in range(brace, len(source)):
        char = source[index]
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return source[brace:index + 1]
    raise AssertionError(f"body not found for {signature}")


def test_dns_resolver_cache_is_registered_and_models_singleflight_states():
    header = read(DNS_CACHE_H)
    source = read(DNS_CACHE_CPP)
    cmake = read(CMAKE)

    assert "mtproto/proxy/dns_resolver_cache.cpp" in cmake
    assert "mtproto/proxy/dns_resolver_cache.h" in cmake
    assert "class DnsResolverCache final" in header
    assert "enum class DnsResolverCacheState" in header
    assert "Fresh" in header
    assert "Inflight" in header
    assert "Negative" in header
    assert "Expired" in header
    assert "struct DnsResolverSubscriber" in source
    assert "std::vector<DnsResolverSubscriber> subscribers;" in source
    assert "state = DnsResolverCacheState::Inflight;" in source
    assert "subscribers.push_back(" in source
    assert "instance->resolveProxyDomain(host);" in source


def test_resolving_connection_subscribes_to_dns_cache_instead_of_resolving():
    source = read(RESOLVING_CPP)
    constructor = source.split("ResolvingConnection::ResolvingConnection(")[1]
    constructor = constructor.split("\n}\n")[0]

    assert '#include "mtproto/proxy/dns_resolver_cache.h"' in source
    assert "DnsResolverCache::Instance().request(" in constructor
    assert "&Instance::proxyDomainResolved" not in constructor
    assert "instance->resolveProxyDomain(host);" not in constructor
    assert "domainResolved(" in constructor


def test_route_racing_is_bounded_and_delayed():
    header = read(RESOLVING_H)
    source = read(RESOLVING_CPP)

    assert "struct RouteAttempt" in header
    assert "std::vector<RouteAttempt> _routeAttempts;" in header
    assert "base::Timer _routeRaceTimer;" in header
    assert "kRouteRaceDelay = crl::time(300)" in source
    assert "kMaxParallelRouteAttempts = 2" in source
    assert "void ResolvingConnection::startNextRouteAttempt()" in source
    assert "void ResolvingConnection::scheduleRouteRace()" in source
    assert "activeRouteAttempts() >= kMaxParallelRouteAttempts" in source
    assert "_routeRaceTimer.callOnce(kRouteRaceDelay);" in source
    assert "setChild(_child->clone(" not in source


def test_route_order_prefers_good_capability_route_before_first_ip():
    source = read(RESOLVING_CPP)
    body = function_body(source, "std::vector<int> ResolvingConnection::routeOrder(")

    assert "ProxyCapabilityCache::Instance().lookup(_proxy)" in body
    assert "capability.goodRoutes" in body
    assert "MtProxy::RouteEndpointFromAddress(" in body
    assert "MtProxy::RouteKey(" in body
    assert "result.push_back(index)" in body


def test_full_connect_timeout_no_longer_scales_linearly_by_ip_count():
    source = read(RESOLVING_CPP)
    body = function_body(source, "crl::time ResolvingConnection::fullConnectTimeout() const")

    assert "qMax(int(_proxy.resolvedIPs.size()), 1)" not in body
    # The budget covers the patient last-route attempt, not a linear
    # multiple of the resolved IP count.
    assert "kOnlyRouteAttemptTimeout" in body
    assert "kRouteRaceDelay" in body


def test_domain_resolver_still_dedups_low_level_attempts():
    source = read(DOMAIN_RESOLVER_CPP)
    body = function_body(source, "void DomainResolver::resolve(const AttemptKey &key)")

    assert "_attempts.find(key)" in body
    assert "_requests.find(key)" in body
    assert "_systemLookups.find(key.domain)" in body


if __name__ == "__main__":
    test_dns_resolver_cache_is_registered_and_models_singleflight_states()
    test_resolving_connection_subscribes_to_dns_cache_instead_of_resolving()
    test_route_racing_is_bounded_and_delayed()
    test_route_order_prefers_good_capability_route_before_first_ip()
    test_full_connect_timeout_no_longer_scales_linearly_by_ip_count()
    test_domain_resolver_still_dedups_low_level_attempts()
