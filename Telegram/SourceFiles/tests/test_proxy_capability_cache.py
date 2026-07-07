from pathlib import Path


SOURCE_DIR = Path(__file__).resolve().parents[1]
ROOT = SOURCE_DIR.parents[1]
CMAKE = ROOT / "Telegram" / "CMakeLists.txt"
PROXY_DIR = SOURCE_DIR / "mtproto" / "proxy"
CAPABILITIES_H = PROXY_DIR / "capabilities.h"
CAPABILITIES_CPP = PROXY_DIR / "capabilities.cpp"
RUNTIME_CPP = SOURCE_DIR / "mtproto" / "runtime_environment.cpp"
TRANSPORT_POLICY_CPP = PROXY_DIR / "transport_policy.cpp"
ENDPOINT_HEALTH_CPP = PROXY_DIR / "mtproxy" / "endpoint_health.cpp"
TLS_SOCKET_CPP = PROXY_DIR / "mtproxy" / "tls_socket.cpp"


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


def test_capability_cache_module_is_file_backed_and_registered():
    header = read(CAPABILITIES_H)
    source = read(CAPABILITIES_CPP)
    runtime = read(RUNTIME_CPP)
    cmake = read(CMAKE)

    assert "mtproto/proxy/capabilities.cpp" in cmake
    assert "mtproto/proxy/capabilities.h" in cmake
    assert "struct ProxyCapabilityCard" in header
    assert "class ProxyCapabilityCache final" in header
    assert "ProxyCapabilityCache &Instance()" in header
    assert "QJsonDocument" in source
    assert "QSaveFile" in source
    assert 'u"proxy-capabilities.json"_q' in runtime
    assert "cWorkingDir() + u\"tdata/\"_q" in runtime
    assert "QDir().mkpath(" in runtime
    assert "runtime->proxyCapabilitiesPath" in source
    assert "load()" in source
    assert "save()" in source


def test_capability_card_contains_transport_profile_flags_and_routes():
    header = read(CAPABILITIES_H)
    source = read(CAPABILITIES_CPP)

    for field in (
        "QString proxyKey;",
        "ProxyCapabilityTransport lastGoodTransport",
        "QString lastGoodRoute;",
        "ProxyTlsProfile lastGoodProfile",
        "int lastGoodRecipeLevel",
        "bool relayProven",
        "bool autoRotateAllowed",
        "bool wssAllowed",
        "bool syntheticPskAllowed",
        "bool fragmentationAllowed",
        "crl::time lastSuccessAt",
        "crl::time relayProvenAt",
        "QString lastFailureClass;",
        "std::vector<QString> badRoutes;",
        "std::vector<QString> goodRoutes;",
        "crl::time wssBlockedUntil",
    ):
        assert field in header
    for json_key in (
        '"proxyKey"',
        '"lastGoodTransport"',
        '"lastGoodRoute"',
        '"lastGoodProfile"',
        '"lastGoodRecipeLevel"',
        '"relayProven"',
        '"autoRotateAllowed"',
        '"wssAllowed"',
        '"syntheticPskAllowed"',
        '"fragmentationAllowed"',
        '"lastSuccessAt"',
        '"relayProvenAt"',
        '"lastFailureClass"',
        '"badRoutes"',
        '"goodRoutes"',
        '"wssBlockedUntil"',
    ):
        assert json_key in source
    assert 'u"MtproxyFakeTlsTcp"_q' in source
    assert 'u"Wss"_q' in source


def test_proxy_capability_key_uses_canonical_identity_not_route_ip():
    source = read(CAPABILITIES_CPP)
    body = function_body(source, "QString ProxyCapabilityKey(")

    assert "ProxyCapabilityHost(proxy)" in body
    assert "proxy.originalHost.isEmpty()" in source
    assert "? proxy.host" in source
    assert ": proxy.originalHost" in source
    assert "proxy.host +" not in body
    assert "QString::number(int(proxy.type))" in body
    assert "QString::number(proxy.port)" in body
    assert "ProxyCapabilitySecretHash(proxy)" in body
    assert "QCryptographicHash::Sha256" in source


def test_wss_remote_closed_is_persisted_with_ttl_per_proxy():
    source = read(TRANSPORT_POLICY_CPP)
    capabilities = read(CAPABILITIES_CPP)
    note_body = function_body(source, "void NoteProxyWssRemoteClosed(")
    allowed_body = function_body(source, "bool ProxyWssAllowed(")

    assert "kWssRemoteClosedTtl = crl::time(" in source
    assert "ProxyCapabilityCache::Instance().noteWssRemoteClosed(" in note_body
    assert "kWssRemoteClosedTtl" in note_body
    assert "ProxyCapabilityCache::Instance().wssAllowed(proxy)" in allowed_body
    assert "std::set<QString> WssForbiddenProxyKeys" not in source
    assert "QMutex WssForbiddenProxyKeysMutex" not in source
    assert "card.wssAllowed = false;" in capabilities
    assert "card.wssBlockedUntil = crl::now() + ttl;" in capabilities


def test_mtproxy_success_and_failure_update_capability_routes():
    health = read(ENDPOINT_HEALTH_CPP)
    tls = read(TLS_SOCKET_CPP)
    failure = function_body(health, "void EndpointHealth::reportFailure(")
    success = function_body(health, "void EndpointHealth::reportSuccess(")
    packet_body = function_body(tls, "bool TlsSocket::checkNextPacket()")

    assert '#include "mtproto/proxy/capabilities.h"' in health
    assert "ProxyCapabilityCache::Instance().noteMtproxyFailure(" in failure
    assert "ProxyCapabilityCache::Instance().noteMtproxySuccess(" in success
    assert "CapabilityProxyKey(report.endpoint.canonical)" in failure
    assert "RouteKey(report.endpoint.route)" in failure
    assert "CapabilityProxyKey(report.endpoint.canonical)" in success
    assert "RouteKey(report.endpoint.route)" in success
    assert "RouteText(report.endpoint)" in success
    assert "report.scope == SuccessScope::Relay" in success
    assert "successRecipeLevel" in success
    assert ".stealth = _stealth" in packet_body
    assert ".sentProfile = _sentTlsProfile" in packet_body


def test_mtproxy_relay_success_persists_boring_last_good_path():
    header = read(CAPABILITIES_H)
    source = read(CAPABILITIES_CPP)
    success = function_body(source, "void ProxyCapabilityCache::noteMtproxySuccess(")
    read_card = function_body(source, "ProxyCapabilityCard ReadCard(")
    write_card = function_body(source, "QJsonObject WriteCard(")

    assert "QString lastGoodRoute;" in header
    assert "int lastGoodRecipeLevel = 0;" in header
    assert "bool relayProven = false;" in header
    assert "crl::time relayProvenAt = 0;" in header
    assert "bool autoRotateAllowed = true;" in header

    for json_key in (
        '"lastGoodRoute"',
        '"lastGoodRecipeLevel"',
        '"relayProven"',
        '"relayProvenAt"',
        '"autoRotateAllowed"',
    ):
        assert json_key in read_card
        assert json_key in write_card

    assert "const QString &lastGoodRoute" in source
    assert "int recipeLevel" in source
    assert "bool relayProven" in source
    assert "const auto now = crl::now();" in success
    assert "card.lastGoodRoute = lastGoodRoute;" in success
    assert "card.lastGoodRecipeLevel = recipeLevel;" in success
    assert "card.relayProven = relayProven;" in success
    assert "card.relayProvenAt = relayProven ? now : 0;" in success
    assert "card.autoRotateAllowed = false;" in success
    assert "card.syntheticPskAllowed = stealth.syntheticPsk;" in success
    assert ("card.fragmentationAllowed = (stealth.clientHelloFragmentation\n"
        "\t\t!= ProxyClientHelloFragmentation::Off);") in success
    assert "if (stealth.syntheticPsk) {" not in success
    assert "card.syntheticPskAllowed = true;" not in success
    assert "card.fragmentationAllowed = true;" not in success


def test_legacy_relay_cache_uses_last_success_as_proof_time():
    source = read(CAPABILITIES_CPP)
    read_card = function_body(source, "ProxyCapabilityCard ReadCard(")

    assert "const auto relayProvenAt = crl::time(" in read_card
    assert "object.value(\"relayProvenAt\").toDouble()" in read_card
    assert "result.relayProven" in read_card
    assert "result.lastSuccessAt" in read_card


def test_last_good_capability_is_used_before_saved_mtproxy_experiments():
    source = read(TRANSPORT_POLICY_CPP)
    body = function_body(source, "ProxyStealthOptions EffectiveProxyStealthOptions(")
    mtproxy_branch = body.split(
        "proxy.type == ProxyData::Type::Mtproto) {", 1)[1].split(
        "if (settings == ProxyData::Settings::Enabled", 1)[0]

    assert "ProxyCapabilityCache::Instance().lookup(proxy)" in body
    assert "capability.lastGoodTransport" in body
    assert "ProxyCapabilityTransport::MtproxyFakeTlsTcp" in body
    assert "capability.relayProven" in body
    assert "FreshMtproxyRelayProof(card)" in read(CAPABILITIES_CPP)
    assert "capability.lastGoodRecipeLevel == 0" in body
    assert "!capability.autoRotateAllowed" in body
    assert "capability.lastGoodProfile" in body
    assert "CompatStrictProxyStealthOptions(std::move(result))" in body
    assert "capability.syntheticPskAllowed" not in mtproxy_branch
    assert "capability.fragmentationAllowed" not in mtproxy_branch
    assert "result.level == ProxyStealthLevel::Experimental" not in mtproxy_branch


def test_relay_data_degradation_invalidates_persisted_relay_proof():
    header = read(CAPABILITIES_H)
    source = read(CAPABILITIES_CPP)
    health = read(ENDPOINT_HEALTH_CPP)
    relay_failure = function_body(
        source,
        "void ProxyCapabilityCache::noteMtproxyRelayFailure(")
    report_failure = function_body(health, "void EndpointHealth::reportFailure(")
    relay_stall = function_body(health, "void EndpointHealth::noteRelayStall(")

    assert "void noteMtproxyRelayFailure(" in header
    assert "card.relayProven = false;" in relay_failure
    assert "card.relayProvenAt = 0;" in relay_failure
    assert "card.lastFailureClass = failureClass;" in relay_failure
    assert "AddRoute(card.badRoutes, routeKey);" in relay_failure
    assert "ProxyCapabilityCache::Instance().noteMtproxyRelayFailure(" in (
        report_failure)
    assert "ProxyCapabilityCache::Instance().noteMtproxyRelayFailure(" in (
        relay_stall)
    assert "relay_stall" in relay_stall

    no_appdata_warning = report_failure.split(
        "if (SoftNoAppDataFailure(state, report.reason, now)) {", 1)[1].split(
            "if (FailureIsRouteOnly(report.reason)", 1)[0]
    assert "noteMtproxyRelayFailure" not in no_appdata_warning


def test_hard_mtproxy_failures_invalidate_stale_relay_cache():
    source = read(CAPABILITIES_CPP)
    failure = function_body(source, "void ProxyCapabilityCache::noteMtproxyFailure(")

    assert "HardMtproxyFailureInvalidatesRelayProof(" in source
    assert 'u"client_hello_sent_no_server_hello"_q' in source
    assert 'u"tls_alert_after_client_hello"_q' in source
    assert 'u"server_hello_hmac_mismatch"_q' in source
    assert 'u"server_hello_ok_no_appdata"_q' not in function_body(
        source,
        "bool HardMtproxyFailureInvalidatesRelayProof(")
    assert "card.relayProven = false;" in failure
    assert "card.relayProvenAt = 0;" in failure


if __name__ == "__main__":
    test_capability_cache_module_is_file_backed_and_registered()
    test_capability_card_contains_transport_profile_flags_and_routes()
    test_proxy_capability_key_uses_canonical_identity_not_route_ip()
    test_wss_remote_closed_is_persisted_with_ttl_per_proxy()
    test_mtproxy_success_and_failure_update_capability_routes()
    test_mtproxy_relay_success_persists_boring_last_good_path()
    test_legacy_relay_cache_uses_last_success_as_proof_time()
    test_last_good_capability_is_used_before_saved_mtproxy_experiments()
    test_relay_data_degradation_invalidates_persisted_relay_proof()
    test_hard_mtproxy_failures_invalidate_stale_relay_cache()
