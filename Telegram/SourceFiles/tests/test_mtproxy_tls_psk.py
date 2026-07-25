from pathlib import Path


SOURCE_DIR = Path(__file__).resolve().parents[1]
MTPROXY_DIR = SOURCE_DIR / "mtproto" / "proxy" / "mtproxy"
TLS_SOCKET_CPP = MTPROXY_DIR / "tls_socket.cpp"
TLS_SOCKET_H = MTPROXY_DIR / "tls_socket.h"
CLIENT_HELLO_BUILDER_CPP = MTPROXY_DIR / "client_hello_builder.cpp"
CLIENT_HELLO_FRAGMENTATION_CPP = MTPROXY_DIR / "client_hello_fragmentation.cpp"
CLIENT_HELLO_RULES_CPP = MTPROXY_DIR / "client_hello_rules.cpp"
TLS_SOCKET_HANDSHAKE_CPP = MTPROXY_DIR / "tls_socket_handshake.cpp"
TLS_SOCKET_PSK_CPP = MTPROXY_DIR / "tls_socket_psk.cpp"
TLS_SOCKET_PSK_H = MTPROXY_DIR / "tls_socket_psk.h"
TLS_SOCKET_RECORDS_CPP = MTPROXY_DIR / "tls_socket_records.cpp"
TCP_SOCKET_H = SOURCE_DIR / "mtproto" / "transport" / "details" / "mtproto_tcp_socket.h"
PROXY_DATA_H = SOURCE_DIR / "mtproto" / "runtime" / "proxy_data.h"
CONNECTION_BOX_CPP = SOURCE_DIR / "boxes" / "connection_box.cpp"
CORE_SETTINGS_CPP = SOURCE_DIR / "core" / "core_settings.cpp"
README = SOURCE_DIR.parents[1] / "README.md"


def psk_header():
    return TLS_SOCKET_PSK_H.read_text(encoding="utf-8")


def test_qtcp_socket_members_have_direct_header_include():
    tcp_header = TCP_SOCKET_H.read_text(encoding="utf-8")
    tls_header = TLS_SOCKET_H.read_text(encoding="utf-8")

    assert "#include <QtNetwork/QTcpSocket>" in tcp_header
    assert "QTcpSocket _socket;" in tcp_header
    assert "#include <QtNetwork/QTcpSocket>" not in tls_header
    assert "QTcpSocket _socket;" not in tls_header
    assert "std::unique_ptr<TlsSocketTransport> _transport;" in tls_header


def test_server_hello_length_uses_non_narrow_storage():
    header = TLS_SOCKET_H.read_text(encoding="utf-8")

    assert "int _serverHelloLength = 0;" in header
    assert "int16 _serverHelloLength" not in header


def test_browser_profiles_use_dynamic_psk_marker_instead_of_inline_psk():
    source = CLIENT_HELLO_RULES_CPP.read_text(encoding="utf-8")
    builder = CLIENT_HELLO_BUILDER_CPP.read_text(encoding="utf-8")
    rules_body = function_body(
        source,
        "MTPTlsClientHello PrepareClientHelloRulesInternal(\n\t\tProxyTlsProfile profile)")
    padding_body = function_body(
        builder,
        "void Generator::Part::writeBlock(const MTPDtlsBlockPadding &data)")
    permutation_body = function_body(
        builder,
        "void Generator::Part::writeBlock(const MTPDtlsBlockPermutation &data)")
    prepare_body = function_body(builder, "ClientHello PrepareClientHello(")

    assert 'S("\\x00\\x29"_q);' not in rules_body
    for marker in (
        "case ProxyTlsProfile::Firefox: {",
        "case ProxyTlsProfile::FirefoxAndroid: {",
        "case ProxyTlsProfile::AndroidOkHttp: {",
        "case ProxyTlsProfile::Yandex: {",
        "case ProxyTlsProfile::ChromeModern: {",
        "case ProxyTlsProfile::AndroidChrome:",
    ):
        profile_body = block_after(rules_body, marker)
        assert "P();" in profile_body
    assert "ShouldPadBeforeSyntheticPsk(profile)" in prepare_body
    assert "_padBeforeSyntheticPsk && length < 513" in padding_body
    assert "nullptr" in permutation_body


def test_synthetic_psk_offer_is_cached_per_endpoint_sni_and_profile():
    psk = TLS_SOCKET_PSK_CPP.read_text(encoding="utf-8")
    handshake = TLS_SOCKET_HANDSHAKE_CPP.read_text(encoding="utf-8")
    socket = TLS_SOCKET_CPP.read_text(encoding="utf-8")
    plain_connected = function_body(handshake, "void TlsSocket::plainConnected()")
    send_client_hello = function_body(handshake, "void TlsSocket::sendClientHello()")
    terminal_body = function_body(socket, "bool TlsSocket::finishTerminal(")
    hello_digest = function_body(handshake, "void TlsSocket::checkHelloDigest()")

    assert "struct Ticket" in psk_header()
    assert "class SyntheticPskCache final" in psk_header()
    assert "std::map<QString, Entry> _entries;" in psk_header()
    assert "std::map<QString, SyntheticPskCacheEntry>" not in psk
    assert "kSyntheticPskPoolSize" in psk
    assert "kSyntheticPskMinLifetime" in psk
    assert "kSyntheticPskMaxLifetime" in psk
    assert "SyntheticPskCache::prepareOffer(" in psk
    assert "SyntheticPskCache::noteDataPathSuccess(" in psk
    assert "SyntheticPskCache::clear(" in psk

    assert "sendClientHello();" in plain_connected
    assert "_sentTlsProfile = profile;" in send_client_hello
    assert "if (_stealth.syntheticPsk)" in send_client_hello
    assert "_runtime->proxyServices().syntheticPsks().prepareOffer(" in (
        send_client_hello)
    assert "MtProxy::EndpointKey(_endpointId.canonical)" in send_client_hello
    assert "domainFromSecret()" in send_client_hello
    assert "profile" in send_client_hello
    assert "std::move(pskOffer)" in send_client_hello
    assert "clearSyntheticPskOnFailure(reason)" in terminal_body
    assert "_sentTlsProfile" in function_body(
        socket,
        "bool TlsSocket::clearSyntheticPskOnFailure(")

    assert "NoteSyntheticPskHandshakeSuccess(" not in hello_digest
    assert "noteDataPathSuccess(" not in hello_digest


def test_synthetic_psk_cache_is_cleared_on_post_handshake_failure():
    source = TLS_SOCKET_CPP.read_text(encoding="utf-8")
    terminal_body = function_body(source, "bool TlsSocket::finishTerminal(")

    assert "clearSyntheticPskOnFailure(reason)" in terminal_body


def test_synthetic_psk_offer_failures_clear_remaining_tickets():
    header = TLS_SOCKET_H.read_text(encoding="utf-8")
    socket = TLS_SOCKET_CPP.read_text(encoding="utf-8")
    handshake = TLS_SOCKET_HANDSHAKE_CPP.read_text(encoding="utf-8")
    send_client_hello = function_body(handshake, "void TlsSocket::sendClientHello()")
    disconnected_body = function_body(handshake, "void TlsSocket::plainDisconnected()")
    clear_helper = function_body(
        socket,
        "bool TlsSocket::clearSyntheticPskOnFailure(")
    terminal_body = function_body(socket, "bool TlsSocket::finishTerminal(")

    assert "bool _syntheticPskOffered = false;" in header
    assert "_syntheticPskOffered = pskOffer.has_value();" in send_client_hello
    assert "_syntheticPskOffered = false;" in disconnected_body
    assert "clearSyntheticPskOnFailure(reason)" in terminal_body
    assert "if (!_syntheticPskOffered || IsProxyCheck(_endpointUse))" in clear_helper
    for reason in (
        "ClientHelloSentNoServerHello",
        "TlsAlertAfterClientHello",
        "ServerHelloHmacMismatch",
    ):
        assert f"case MtProxy::FailureReason::{reason}:" in clear_helper
    assert "case MtProxy::FailureReason::ServerHelloOkNoAppData:" not in (
        clear_helper)
    assert "_runtime->proxyServices().syntheticPsks().clear(" in clear_helper
    assert "_syntheticPskOffered = false;" in clear_helper


def test_synthetic_psk_uses_cached_identity_and_plausible_age():
    source = CLIENT_HELLO_BUILDER_CPP.read_text(encoding="utf-8")
    tls_socket = TLS_SOCKET_PSK_CPP.read_text(encoding="utf-8")
    helper = function_body(
        source,
        "void Generator::Part::writeSyntheticPskExtension()")
    offer_body = function_body(
        tls_socket,
        "std::optional<SyntheticPskOffer> SyntheticPskCache::prepareOffer(")

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

    assert "ticketAgeAdd" in tls_socket
    assert "issuedAt" in tls_socket
    assert "expiresAt" in tls_socket
    assert "obfuscatedTicketAge" in offer_body
    assert "crl::now()" in offer_body


def test_synthetic_psk_ticket_is_consumed_after_offer():
    source = TLS_SOCKET_PSK_CPP.read_text(encoding="utf-8")
    offer_body = function_body(
        source,
        "std::optional<SyntheticPskOffer> SyntheticPskCache::prepareOffer(")

    assert "const auto ticket = entry.tickets[index];" in offer_body
    assert "entry.tickets.erase(" in offer_body
    assert "entry.nextIndex = (entry.nextIndex + 1) % count;" not in offer_body


def test_synthetic_psk_does_not_take_over_mtproxy_digest_slot():
    source = CLIENT_HELLO_BUILDER_CPP.read_text(encoding="utf-8")
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
    assert "length == kClientHelloDigestLength && !_digestPosition" in zero_body
    assert finalize_body.index("writeDigest(key);") < finalize_body.index(
        "injectTimestamp();")


def test_client_hello_fragmentation_targets_sni_hostname():
    source = CLIENT_HELLO_FRAGMENTATION_CPP.read_text(encoding="utf-8")
    builder_header = (
        MTPROXY_DIR / "client_hello_builder.h").read_text(encoding="utf-8")
    tls_socket = TLS_SOCKET_HANDSHAKE_CPP.read_text(encoding="utf-8")
    header = TLS_SOCKET_H.read_text(encoding="utf-8")
    split_body = function_body(source, "int ClientHelloFragmentSplit(")
    plan_body = function_body(
        source,
        "ClientHelloFragmentationPlan PrepareClientHelloFragmentation(")
    write_body = function_body(
        tls_socket,
        "void TlsSocket::writeClientHello(const QByteArray &data)")
    disconnected_body = function_body(
        tls_socket,
        "void TlsSocket::plainDisconnected()")

    assert "ClientHelloSniHostRange(" in source
    assert "kClientHelloFragmentDelayMin" in source
    assert "kClientHelloFragmentDelayMax" in source
    assert "const auto range = ClientHelloSniHostRange(data);" in split_body
    assert "range.offset + 1 + base::RandomIndex(range.length - 1)" in split_body
    assert "base::RandomIndex(delayRange)" in plan_body
    assert "secondDelay" in builder_header
    assert "QByteArray _clientHelloTail;" in header
    assert "RuntimeTimer _clientHelloFragmentTimer;" in header
    assert "PrepareClientHelloFragmentation(" in write_body
    assert "plan.firstSize" in write_body
    assert "_clientHelloFragmentTimer.callOnce(plan.secondDelay);" in write_body
    assert "writeClientHelloTail();" in write_body
    assert "_clientHelloTail = QByteArray();" in disconnected_body
    assert "_clientHelloFragmentTimer.cancel();" in disconnected_body
    assert "base::RandomIndex(range)" not in tls_socket


def test_mtproxy_profile_wording_does_not_claim_ja4_validation():
    box = CONNECTION_BOX_CPP.read_text(encoding="utf-8")
    readme = README.read_text(encoding="utf-8")

    assert 'u"TLS ClientHello profile"_q' in box
    assert "TLS fingerprint (JA4)" not in box
    assert "JA4" not in readme
    assert "ClientHello" in readme


def test_manual_tls_profiles_have_independent_transport_cases():
    source = CLIENT_HELLO_RULES_CPP.read_text(encoding="utf-8")
    box = CONNECTION_BOX_CPP.read_text(encoding="utf-8")
    rules_body = function_body(
        source,
        "MTPTlsClientHello PrepareClientHelloRulesInternal(\n\t\tProxyTlsProfile profile)")

    for profile, label in (
        ("Auto", "Auto (Chrome)"),
        ("AutoRotate", "Auto-rotate"),
        ("ChromeModern", "Chrome Modern"),
        ("AndroidChrome", "Android Chrome"),
        ("Firefox", "Firefox"),
        ("FirefoxAndroid", "Firefox Android"),
        ("Yandex", "Yandex"),
        ("AndroidOkHttp", "Android OkHttp"),
    ):
        assert f"case ProxyTlsProfile::{profile}: {{" in rules_body
        assert f'addTls(Profile::{profile}, u"{label}"_q);' in box

    assert "case ProxyTlsProfile::Auto:\n\tcase ProxyTlsProfile::AndroidChrome:" not in rules_body
    assert "case ProxyTlsProfile::AndroidChrome:\n\tcase ProxyTlsProfile::AutoRotate:" not in rules_body


def test_stealth_record_timing_and_startup_cover_default_off():
    data = PROXY_DATA_H.read_text(encoding="utf-8")
    settings = CORE_SETTINGS_CPP.read_text(encoding="utf-8")

    assert "ProxyRecordSizing recordSizing = ProxyRecordSizing::Off;" in data
    assert "ProxyTiming timing = ProxyTiming::Off;" in data
    assert "ProxyStartupCover startupCover = ProxyStartupCover::Off;" in data
    assert 'read(\n\t\t"mtproxy/startupCover",\n\t\tint(result.startupCover),' in settings


def test_admission_plan_drives_tls_socket_spacing_and_diagnostics():
    header = TLS_SOCKET_H.read_text(encoding="utf-8")
    source = TLS_SOCKET_HANDSHAKE_CPP.read_text(encoding="utf-8")
    socket = TLS_SOCKET_CPP.read_text(encoding="utf-8")
    connected_body = function_body(source, "void TlsSocket::plainConnected()")
    terminal_body = function_body(socket, "bool TlsSocket::finishTerminal(")
    clear_body = function_body(
        socket,
        "bool TlsSocket::clearSyntheticPskOnFailure(")
    parts12_body = function_body(source, "void TlsSocket::checkHelloParts12(int parts1Size)")
    digest_body = function_body(source, "void TlsSocket::checkHelloDigest()")

    assert "MtProxyAttemptPlan _mtproxyPlan;" in header
    assert "ProxyTlsProfile _configuredTlsProfile" in header
    assert "applyAdaptiveRecipe" not in source
    assert "reportTransportEvent(" in source
    assert "const auto delay = MtProxy::ConnectionSpacing(_connectionPattern);" in connected_body
    assert "_clientHelloTimer.callOnce(delay);" in connected_body
    assert "clearSyntheticPskOnFailure(reason)" in terminal_body
    assert "_sentTlsProfile" in clear_body
    assert "MtProxy::FailureReason::TlsAlertAfterClientHello" in parts12_body
    assert "MtProxy::FailureReason::ProxyProtocolBadResponse" in parts12_body
    assert "MtProxy::FailureReason::ServerHelloHmacMismatch" in digest_body


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
    test_qtcp_socket_members_have_direct_header_include()
    test_server_hello_length_uses_non_narrow_storage()
    test_browser_profiles_use_dynamic_psk_marker_instead_of_inline_psk()
    test_synthetic_psk_offer_is_cached_per_endpoint_sni_and_profile()
    test_synthetic_psk_cache_is_cleared_on_post_handshake_failure()
    test_synthetic_psk_uses_cached_identity_and_plausible_age()
    test_synthetic_psk_ticket_is_consumed_after_offer()
    test_synthetic_psk_does_not_take_over_mtproxy_digest_slot()
    test_client_hello_fragmentation_targets_sni_hostname()
    test_mtproxy_profile_wording_does_not_claim_ja4_validation()
    test_manual_tls_profiles_have_independent_transport_cases()
    test_stealth_record_timing_and_startup_cover_default_off()
    test_admission_plan_drives_tls_socket_spacing_and_diagnostics()
