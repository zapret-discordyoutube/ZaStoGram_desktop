from pathlib import Path


SOURCE_DIR = Path(__file__).resolve().parents[1]
MTPROXY_DIR = SOURCE_DIR / "mtproto" / "proxy" / "mtproxy"
TLS_SOCKET_CPP = MTPROXY_DIR / "tls_socket.cpp"
ADAPTIVE_POLICY_H = MTPROXY_DIR / "adaptive_policy.h"
ADAPTIVE_POLICY_CPP = MTPROXY_DIR / "adaptive_policy.cpp"


def test_mtproxy_transport_policy_files_live_in_proxy_module():
    header = ADAPTIVE_POLICY_H.read_text(encoding="utf-8")
    source = ADAPTIVE_POLICY_CPP.read_text(encoding="utf-8")

    assert "struct AdaptiveRecipeInput" in header
    assert "ApplyAdaptiveRecipe(" in header
    assert '#include "mtproto/proxy/mtproxy/adaptive_policy.h"' in source


def test_browser_profiles_use_dynamic_psk_marker_instead_of_inline_psk():
    source = TLS_SOCKET_CPP.read_text(encoding="utf-8")
    rules_body = function_body(
        source,
        "MTPTlsClientHello PrepareClientHelloRules(\n\t\tProxyTlsProfile profile)")
    padding_body = function_body(
        source,
        "void Generator::Part::writeBlock(const MTPDtlsBlockPadding &data)")
    permutation_body = function_body(
        source,
        "void Generator::Part::writeBlock(const MTPDtlsBlockPermutation &data)")
    prepare_body = function_body(source, "ClientHello PrepareClientHello(")

    assert 'S("\\x00\\x29"_q);' not in rules_body
    for marker in (
        "case ProxyTlsProfile::Firefox: {",
        "case ProxyTlsProfile::FirefoxAndroid: {",
        "case ProxyTlsProfile::AndroidOkHttp: {",
        "case ProxyTlsProfile::Yandex: {",
        "default: {",
    ):
        profile_body = block_after(rules_body, marker)
        assert "P();" in profile_body
    assert "ShouldPadBeforeSyntheticPsk(profile)" in prepare_body
    assert "_padBeforeSyntheticPsk && length < 513" in padding_body
    assert "nullptr" in permutation_body


def test_synthetic_psk_offer_is_cached_per_endpoint_sni_and_profile():
    source = TLS_SOCKET_CPP.read_text(encoding="utf-8")
    plain_connected = function_body(source, "void TlsSocket::plainConnected()")
    hello_digest = function_body(source, "void TlsSocket::checkHelloDigest()")

    assert "struct SyntheticPskTicket" in source
    assert "struct SyntheticPskCacheEntry" in source
    assert "std::map<QString, SyntheticPskCacheEntry>" in source
    assert "kSyntheticPskPoolSize" in source
    assert "kSyntheticPskMinLifetime" in source
    assert "kSyntheticPskMaxLifetime" in source
    assert "PrepareSyntheticPskOffer(" in source
    assert "NoteSyntheticPskHandshakeSuccess(" in source

    assert "const auto profile = effectiveTlsProfile();" in plain_connected
    assert "_sentTlsProfile = profile;" in plain_connected
    assert "PrepareSyntheticPskOffer(" in plain_connected
    assert "_endpointKey" in plain_connected
    assert "domainFromSecret()" in plain_connected
    assert "profile" in plain_connected
    assert "std::move(pskOffer)" in plain_connected

    assert hello_digest.index("_phase = HandshakePhase::ServerHelloOk;") < (
        hello_digest.index("NoteSyntheticPskHandshakeSuccess("))
    assert "_endpointKey" in hello_digest
    assert "domainFromSecret()" in hello_digest
    assert "_sentTlsProfile" in hello_digest


def test_synthetic_psk_uses_cached_identity_and_plausible_age():
    source = TLS_SOCKET_CPP.read_text(encoding="utf-8")
    helper = function_body(
        source,
        "void Generator::Part::writeSyntheticPskExtension()")
    offer_body = function_body(
        source,
        "std::optional<SyntheticPskOffer> PrepareSyntheticPskOffer(")

    assert "const auto binderLengths = std::array{ 32, 48 };" in helper
    assert "!_pskOffer" in helper
    assert "!*_pskOffer" in helper
    assert "write16(uint16(0x0029));" in helper
    assert "write16(uint16(extensionLength));" in helper
    assert "write16(uint16(identitiesLength));" in helper
    assert "write16(uint16(bindersLength));" in helper
    assert "offer.identity" in helper
    assert "write32(offer.obfuscatedTicketAge);" in helper
    assert "random(identityLength);" not in helper
    assert "random(4);" not in helper
    assert "binderPrefix[0] = bytes::type(binderLength);" in helper
    assert "random(binderLength);" in helper

    assert "ticketAgeAdd" in source
    assert "issuedAt" in source
    assert "expiresAt" in source
    assert "obfuscatedTicketAge" in offer_body
    assert "crl::now()" in offer_body


def test_synthetic_psk_does_not_take_over_mtproxy_digest_slot():
    source = TLS_SOCKET_CPP.read_text(encoding="utf-8")
    helper = function_body(
        source,
        "void Generator::Part::writeSyntheticPskExtension()")
    zero_body = function_body(
        source,
        "void Generator::Part::writeBlock(const MTPDtlsBlockZero &data)")
    finalize_body = function_body(
        source,
        "void Generator::Part::finalize(bytes::const_span key)")

    assert "_digestPosition" not in helper
    assert "MTP_tlsBlockZero" not in helper
    assert "length == kHelloDigestLength && _digestPosition < 0" in zero_body
    assert finalize_body.index("writeDigest(key);") < finalize_body.index(
        "injectTimestamp();")


def function_body(text: str, signature: str) -> str:
    start = text.index(signature)
    brace = text.index(" {\n", start) + 1
    return body_from_brace(text, brace)


def block_after(text: str, marker: str) -> str:
    start = text.index(marker)
    brace = text.index("{", start)
    return body_from_brace(text, brace)


def body_from_brace(text: str, brace: int) -> str:
    depth = 0
    for index in range(brace, len(text)):
        char = text[index]
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return text[brace + 1:index]
    raise AssertionError("body not found")


if __name__ == "__main__":
    test_mtproxy_transport_policy_files_live_in_proxy_module()
    test_browser_profiles_use_dynamic_psk_marker_instead_of_inline_psk()
    test_synthetic_psk_offer_is_cached_per_endpoint_sni_and_profile()
    test_synthetic_psk_uses_cached_identity_and_plausible_age()
    test_synthetic_psk_does_not_take_over_mtproxy_digest_slot()
