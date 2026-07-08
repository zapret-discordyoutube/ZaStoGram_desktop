from pathlib import Path


SOURCE_DIR = Path(__file__).resolve().parents[1]
RESOLVER_H = SOURCE_DIR / "mtproto" / "details" / "mtproto_domain_resolver.h"
RESOLVER_CPP = SOURCE_DIR / "mtproto" / "details" / "mtproto_domain_resolver.cpp"
RESOLVING_CPP = SOURCE_DIR / "mtproto" / "proxy" / "resolving_connection.cpp"


def read(path):
    assert path.exists(), f"missing expected source file: {path}"
    return path.read_text(encoding="utf-8")


def test_system_dns_is_tried_before_doh():
    header = read(RESOLVER_H)
    source = read(RESOLVER_CPP)

    assert "resolveBySystemDns" in header
    assert "resolveByDnsOverHttps" in header
    assert "QHostInfo::lookupHost" in source
    assert "resolveBySystemDns(key.domain);" in source

    resolve_body = source.split("void DomainResolver::resolve(const AttemptKey &key)")[1]
    resolve_body = resolve_body.split("\n}\n")[0]
    assert "resolveBySystemDns" in resolve_body
    assert "dns.google.com" not in resolve_body

    system_done = source.split("void DomainResolver::systemDnsDone")[1]
    system_done = system_done.split("\n}\n")[0]
    assert "resolveByDnsOverHttps" in system_done

    assert "DohProviders()" in source


def test_doh_fallback_uses_current_rfc8484_registry():
    header = read(RESOLVER_H)
    source = read(RESOLVER_CPP)

    assert "struct DohProvider" in header
    assert "[[nodiscard]] const std::vector<DohProvider> &DohProviders();" in header
    assert "BuildDnsQuery(" in header
    assert "ParseDnsResponse(" in header

    assert "cloudflare-dns.com" in source
    assert "dns.google" in source
    assert "dns.quad9.net" in source
    assert "dns.mullvad.net" in source

    assert "application/dns-message" in source
    assert "_manager.post(request, payload)" in source
    assert "BuildDnsQuery(key.domain, key.ipv6 ? 28 : 1)" in source

    assert "application/dns-json" not in source
    assert "/resolve" not in source
    assert "mozilla.cloudflare-dns.com" not in source


def test_legacy_google_fronting_domains_are_removed():
    header = read(RESOLVER_H)
    source = read(RESOLVER_CPP)

    assert "DnsDomains" not in header
    assert "DnsDomains" not in source
    assert '"google.com"' not in source
    assert '"www.google.com"' not in source
    assert '"google.ru"' not in source
    assert '"www.google.ru"' not in source
    assert 'setRawHeader("Host"' not in source


def test_doh_failure_does_not_block_retries_forever():
    source = read(RESOLVER_CPP)

    assert "checkAttemptsExhausted" in source

    finished = source.split("void DomainResolver::requestFinished")[1]
    finished = finished.split("\n}\n")[0]
    assert "checkAttemptsExhausted(key);" in finished

    exhausted = source.split("void DomainResolver::checkAttemptsExhausted")[1]
    exhausted = exhausted.split("\n}\n")[0]
    assert "_attempts.erase(key);" in exhausted


def test_total_resolve_failure_is_reported_to_callback():
    source = read(RESOLVER_CPP)

    assert "pushResultIfResolveDone" in source

    push = source.split("void DomainResolver::pushResultIfResolveDone")[1]
    push = push.split("\n}\n")[0]
    assert "kNegativeResolveTtl" in source
    assert "_callback(domain, QStringList(), expireAt);" in push


def test_system_lookups_are_aborted_on_destruction():
    source = read(RESOLVER_CPP)

    assert "DomainResolver::~DomainResolver()" in source
    assert "QHostInfo::abortHostLookup" in source


def test_type_restriction_checks_type_field_before_dereference():
    source = read(RESOLVER_CPP)

    type_block = source.split('const auto typeIt = object.find("type");')[1]
    type_block = type_block.split('const auto dataIt = object.find("data");')[0]
    end_check = type_block.find("typeIt == object.constEnd()")
    dereference = type_block.find("(*typeIt)")

    assert dereference != -1
    assert end_check != -1
    assert end_check < dereference


def test_resolve_outcome_reaches_proxy_diagnostics():
    source = read(RESOLVING_CPP)

    assert "proxy host not found" in source
    assert "proxy host resolved" in source


def test_cached_negative_dns_does_not_disable_mtproxy_child():
    source = read(RESOLVING_CPP)
    constructor = source.split("ResolvingConnection::ResolvingConnection(")[1]
    constructor = constructor.split("\n}\n")[0]

    assert "cachedNegative" not in constructor
    assert "_child = nullptr" not in constructor
    assert "proxy.resolvedIPs.empty()" in constructor
    assert "_runtime->proxyServices().dnsResolver().request(" in constructor
    assert "instance->resolveProxyDomain(host);" not in constructor


if __name__ == "__main__":
    test_system_dns_is_tried_before_doh()
    test_doh_fallback_uses_current_rfc8484_registry()
    test_legacy_google_fronting_domains_are_removed()
    test_doh_failure_does_not_block_retries_forever()
    test_total_resolve_failure_is_reported_to_callback()
    test_system_lookups_are_aborted_on_destruction()
    test_type_restriction_checks_type_field_before_dereference()
    test_resolve_outcome_reaches_proxy_diagnostics()
    test_cached_negative_dns_does_not_disable_mtproxy_child()
