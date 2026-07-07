from pathlib import Path


SOURCE_DIR = Path(__file__).resolve().parents[1]
ROOT = SOURCE_DIR.parents[1]
CMAKE = ROOT / "Telegram" / "CMakeLists.txt"
MTPROXY_DIR = SOURCE_DIR / "mtproto" / "proxy" / "mtproxy"
DATA_H = SOURCE_DIR / "mtproto" / "proxy" / "data.h"
DATA_CPP = SOURCE_DIR / "mtproto" / "proxy" / "data.cpp"
ENDPOINT_HEALTH_H = MTPROXY_DIR / "endpoint_health.h"
ENDPOINT_HEALTH_CPP = MTPROXY_DIR / "endpoint_health.cpp"
ABSTRACT_SOCKET_H = SOURCE_DIR / "mtproto" / "details" / "mtproto_abstract_socket.h"
ABSTRACT_SOCKET_CPP = SOURCE_DIR / "mtproto" / "details" / "mtproto_abstract_socket.cpp"
SESSION_H = SOURCE_DIR / "mtproto" / "session_private.h"
SESSION_CPP = SOURCE_DIR / "mtproto" / "session_private.cpp"
CONNECTION_TCP_CPP = SOURCE_DIR / "mtproto" / "connection_tcp.cpp"
CONNECTION_TCP_H = SOURCE_DIR / "mtproto" / "connection_tcp.h"
CONNECTION_ABSTRACT_H = SOURCE_DIR / "mtproto" / "connection_abstract.h"
TLS_SOCKET_H = MTPROXY_DIR / "tls_socket.h"
TLS_SOCKET_CPP = MTPROXY_DIR / "tls_socket.cpp"
ADAPTIVE_POLICY_H = MTPROXY_DIR / "adaptive_policy.h"
ADAPTIVE_POLICY_CPP = MTPROXY_DIR / "adaptive_policy.cpp"
DOMAIN_RESOLVER_CPP = SOURCE_DIR / "mtproto" / "details" / "mtproto_domain_resolver.cpp"
RESOLVING_CONNECTION_CPP = SOURCE_DIR / "mtproto" / "proxy" / "resolving_connection.cpp"
DNS_CACHE_CPP = SOURCE_DIR / "mtproto" / "proxy" / "dns_resolver_cache.cpp"
ROTATION_MANAGER_H = SOURCE_DIR / "core" / "proxy_rotation_manager.h"
ROTATION_MANAGER_CPP = SOURCE_DIR / "core" / "proxy_rotation_manager.cpp"


def read(path):
    assert path.exists(), f"missing expected source file: {path}"
    return path.read_text(encoding="utf-8")


def test_endpoint_health_module_is_registered_and_owns_state():
    header = read(ENDPOINT_HEALTH_H)
    source = read(ENDPOINT_HEALTH_CPP)
    cmake = read(CMAKE)

    assert "mtproto/proxy/mtproxy/endpoint_health.cpp" in cmake
    assert "mtproto/proxy/mtproxy/endpoint_health.h" in cmake
    assert "namespace MTP::details::MtProxy" in header
    assert "struct EndpointId" in header
    assert "enum class FailureReason" in header
    assert "ServerHelloHmacMismatch" in header
    assert "ClientHelloSentNoServerHello" in header
    assert "TlsAlertAfterClientHello" in header
    assert "ServerHelloOkNoAppData" in header
    assert "TcpConnectTimeout" in header
    assert "DnsFailed" in header
    assert "enum class EndpointUse" in header
    assert "enum class AdmissionAction" in header
    assert "class EndpointAttemptLease" in header
    assert "class EndpointHealth" in header
    assert "int recipeLevel" in header
    assert "QString lastDiagnostic" in header
    assert "Admission admit(" in header
    assert "void reportFailure(" in header
    assert "void reportSuccess(" in header
    assert "Snapshot snapshot(" in header
    assert "rpl::producer<EndpointEvent> changes()" in header
    assert "kFirstCooldown = crl::time(15 * 1000)" in source
    assert "kSecondCooldown = crl::time(45 * 1000)" in source
    assert "kMaxCooldown = crl::time(120 * 1000)" in source
    assert "kDnsNegativeTtl = crl::time(30 * 1000)" in source
    assert "kColdActiveCap = 1" in source
    assert "kFreshRelayActiveCap = 2" in source
    assert "kWarmRelayActiveCap = 4" in source
    assert "kStableRelayActiveCap = 8" in source
    assert "kHealthyHandshakeSpacing = crl::time(50)" in source
    assert "EndpointConcurrencyPolicyFor(" in source


def test_session_private_admission_gates_before_socket_creation():
    header = read(SESSION_H)
    source = read(SESSION_CPP)
    append_body = function_body(
        source,
        "bool SessionPrivate::appendTestConnection(")

    assert '#include "mtproto/proxy/connection_broker.h"' in header
    assert "MtProxy::EndpointAttemptLease mtproxyLease;" in header
    assert "std::vector<ConnectionTicket> _connectionBrokerTickets;" in header
    assert "base::flat_map<QString, crl::time> _endpointCooldownUntil" not in header
    assert "noteTestConnectionFailure(" not in header
    assert "kEndpointCooldownPenalty" not in source
    assert "MtproxyEndpointCooldown(" not in source
    assert "_endpointCooldownUntil" not in source
    assert "MtProxy::EndpointHealth::Instance().admit(" not in append_body
    assert "ConnectionBroker::Instance().request({" in append_body
    assert ".status = [=](ConnectionBrokerDecision)" in append_body
    assert "setState(-int(admission.retryAfter));" not in append_body
    assert "mtproxy admission queued" not in append_body
    assert "ProxyDiagnosticsPhase::AdmissionQueued" in read(
        SOURCE_DIR / "mtproto" / "proxy" / "connection_broker.cpp")
    assert "std::move(start.lease)" in append_body
    assert "ReserveHandshakeGateForProxy(_options->proxy)" not in append_body
    assert "const auto proxied =" not in append_body


def test_proxy_endpoint_id_uses_decoded_mtproxy_secret_and_sni():
    data_header = read(DATA_H)
    data_source = read(DATA_CPP)
    header = read(ENDPOINT_HEALTH_H)
    source = read(ENDPOINT_HEALTH_CPP)
    direct_body = function_body(data_source, "ProxyData ToDirectIpProxy(")
    body = function_body(source, "EndpointId EndpointIdFromProxy(")
    key_body = function_body(source, "QString EndpointKey(")

    assert "QString originalHost;" in data_header
    assert "struct CanonicalProxyEndpoint" in header
    assert "struct RouteEndpoint" in header
    assert "QString resolvedHost;" not in header
    assert "result.originalHost = proxy.originalHost.isEmpty()" in direct_body
    assert "? proxy.host" in direct_body
    assert ": proxy.originalHost;" in direct_body
    assert "result.canonical.originalHost = ProxyIdentityHost(proxy);" in body
    assert "result.route = RouteEndpointFromAddress(" in body
    assert "result.host = address.isEmpty() ? proxy.host : address;" not in body
    assert "if (proxy.type == ProxyData::Type::Mtproto)" in body
    assert "const auto secret = proxy.secretFromMtprotoPassword();" in body
    assert "result.canonical.secretHash = HashBytes(secret);" in body
    assert "result.canonical.domainFromSecret = DomainFromSecret(secret);" in body
    assert "result.canonical.secretHash = HashText(proxy.password);" in body
    assert body.index("HashBytes(secret)") < body.index("HashText(proxy.password)")
    assert "endpoint.originalHost" in key_body
    assert "endpoint.domainFromSecret" in key_body
    assert "route.address" not in key_body


def test_session_private_reports_success_and_failure_to_endpoint_health():
    source = read(SESSION_CPP)
    header = read(SESSION_H)
    timeout_body = function_body(source, "void SessionPrivate::connectingTimedOut()")
    connected_body = function_body(source, "void SessionPrivate::onConnected(")
    confirm_body = function_body(source, "void SessionPrivate::confirmBestConnection()")
    error_body = function_body(source, "void SessionPrivate::onError(")
    remove_body = function_body(source, "void SessionPrivate::removeTestConnection(")
    destroy_body = function_body(source, "void SessionPrivate::destroyAllConnections()")

    assert "MtProxy::EndpointId _connectionMtproxyEndpoint;" in header
    assert "MtProxy::EndpointUse _connectionMtproxyUse" in header
    assert "ProxyControlPlane::ReportMtproxyFailure(" in timeout_body
    assert "MtProxy::FailureReason::TcpConnectTimeout" in timeout_body
    assert (
        "connection.mtproxyEndpoint.canonical.domainFromSecret.isEmpty()"
        in timeout_body)
    assert "ProxyControlPlane::ReportMtproxyFailure(" in error_body
    assert "MtProxy::FailureReasonFromErrorCode(errorCode)" in error_body
    assert "_connection.get() == connection.get()" in error_body
    assert "MtProxy::EndpointEmpty(_connectionMtproxyEndpoint)" in error_body
    assert "endpoint = _connectionMtproxyEndpoint" in error_body
    assert "_connectionMtproxyEndpoint = i->mtproxyEndpoint;" in connected_body
    assert "_connectionMtproxyUse = i->mtproxyUse;" in connected_body
    assert "_connectionMtproxyEndpoint = i->mtproxyEndpoint;" in confirm_body
    assert "_connectionMtproxyUse = i->mtproxyUse;" in confirm_body
    assert "_connectionMtproxyEndpoint = MtProxy::EndpointId();" in destroy_body
    assert "i->mtproxyLease.release();" in connected_body
    assert "ProxyControlPlane::ReportMtproxySuccess(" in read(
        TLS_SOCKET_CPP)
    assert "i->mtproxyLease.release();" in remove_body

    # Success must also be reported for non-FakeTLS (plain obfuscated)
    # mtproxy connections, which have no TlsSocket first-app-data hook.
    # Otherwise the endpoint stays "unknown" forever: throttled to
    # activeCap 1 and unable to ignore benign remote_closed.
    usable_body = function_body(
        source,
        "void SessionPrivate::reportMtproxyConnectionUsable(")
    assert "ProxyControlPlane::ReportMtproxySuccess(" in usable_body
    assert "snapshot.healthy && !snapshot.halfOpen" in usable_body
    assert "reportMtproxyConnectionUsable(*i);" in connected_body
    assert "reportMtproxyConnectionUsable(*i);" in confirm_body


def test_relay_success_shadows_older_attempt_failures():
    header = read(ENDPOINT_HEALTH_H)
    source = read(ENDPOINT_HEALTH_CPP)
    abstract_h = read(CONNECTION_ABSTRACT_H)
    tcp_h = read(CONNECTION_TCP_H)
    tcp = read(CONNECTION_TCP_CPP)
    resolving_h = (SOURCE_DIR / "mtproto" / "proxy" / "resolving_connection.h"
        ).read_text(encoding="utf-8")
    resolving = read(RESOLVING_CONNECTION_CPP)
    tls_h = read(TLS_SOCKET_H)
    tls = read(TLS_SOCKET_CPP)
    session = read(SESSION_CPP)

    report_failure = function_body(source, "void EndpointHealth::reportFailure(")
    report_success = function_body(source, "void EndpointHealth::reportSuccess(")
    stale_reasons = function_body(source, "bool FailureCanBeStale(")
    stale_helper = function_body(source, "bool FailureFromStaleAttempt(")
    stale_log = function_body(source, "void LogStaleAttemptFailure(")
    admit_body = function_body(source, "Admission EndpointHealth::admit(")
    tcp_connect = function_body(tcp, "void TcpConnection::connectToServer(")
    tls_timeout = function_body(tls, "void TlsSocket::timedOut()")
    tls_error = function_body(tls, "void TlsSocket::handleError(int errorCode)")
    tls_packet = function_body(tls, "bool TlsSocket::checkNextPacket()")
    session_connected = function_body(session, "void SessionPrivate::onConnected(")
    handle_received = function_body(session, "void SessionPrivate::handleReceived()")
    append_body = function_body(
        session,
        "bool SessionPrivate::appendTestConnection(")

    assert "uint64 successEpoch = 0;" in source
    assert "crl::time lastRelaySuccessAt = 0;" in source
    assert "ProxyTlsProfile lastGoodProfile = ProxyTlsProfile::Auto;" in source
    assert "RouteEndpoint lastGoodRoute;" in source
    assert "uint64 successEpoch = 0;" in header
    assert "crl::time lastRelaySuccessAt = 0;" in header
    assert "ProxyTlsProfile lastGoodProfile = ProxyTlsProfile::Auto;" in header
    assert "RouteEndpoint lastGoodRoute;" in header
    assert "uint64 attemptId = 0;" in header
    assert "uint64 proxyEpoch = 0;" in header
    assert "crl::time attemptStartedAt = 0;" in header
    assert "crl::time startedAt() const" in header

    assert "const auto attemptStartedAt = now;" in admit_body
    assert "state.attemptStarts.emplace(result.attemptId, attemptStartedAt);" in (
        admit_body)
    assert "result.attemptStartedAt = attemptStartedAt;" in admit_body
    assert "crl::time startedAt)" in source
    assert "_startedAt(startedAt)" in source

    assert "void setMtproxyAttempt(" in abstract_h
    assert "void setMtproxyAttempt(" in tcp_h
    assert "void setMtproxyAttempt(" in resolving_h
    assert "_mtproxyAttemptStartedAt" in tcp_h
    assert "_mtproxyAttemptStartedAt" in tls_h
    assert "AbstractSocket::Create(" in tcp_connect
    assert "_mtproxyAttemptStartedAt" in tcp_connect
    assert "_mtproxyAttemptStartedAt = startedAt;" in resolving
    assert "attempt.child->setMtproxyAttempt(" in resolving
    assert "setMtproxyAttempt(" in append_body

    assert ".attemptId = _mtproxyAttempt.attemptId" in tls_timeout
    assert ".proxyEpoch = _mtproxyAttempt.proxyEpoch" in tls_timeout
    assert ".attemptStartedAt = _mtproxyAttemptStartedAt" in tls_timeout
    assert ".attemptId = _mtproxyAttempt.attemptId" in tls_error
    assert ".attemptStartedAt = _mtproxyAttemptStartedAt" in tls_error

    assert "SuccessScope::Relay" in tls_packet
    assert ".attemptId = _mtproxyAttempt.attemptId" in tls_packet
    assert ".attemptStartedAt = _mtproxyAttemptStartedAt" in tls_packet
    assert ".attemptId = _connectionMtproxyAttempt.attemptId" in session
    assert ".attemptStartedAt = _connectionMtproxyAttemptStartedAt" in session
    assert "ProxyControlPlane::ReportMtproxySuccess({" in handle_received
    assert ".attemptId = _connectionMtproxyAttempt.attemptId" in handle_received
    assert ".proxyEpoch = _connectionMtproxyAttempt.proxyEpoch" in (
        handle_received)
    assert ".attemptStartedAt = _connectionMtproxyAttemptStartedAt" in (
        handle_received)
    assert "_connectionMtproxyAttemptStartedAt = mtproxyAttemptStartedAt;" in (
        session_connected)

    assert "state.lastRelaySuccessAt = now;" in report_success
    assert "++state.successEpoch;" in report_success
    assert "state.lastGoodProfile = report.sentProfile;" in report_success
    assert "state.lastGoodRoute = report.endpoint.route;" in report_success
    assert "report.scope == SuccessScope::Relay" in report_success

    assert "stale_attempt_failed" in stale_log
    assert "ProxyDiagnosticsSeverity::Info" in stale_log
    assert "FailureReason::ClientHelloSentNoServerHello" in stale_reasons
    assert "FailureReason::ServerHelloOkNoAppData" in stale_reasons
    assert "FailureReason::TcpConnectTimeout" in stale_reasons
    assert "state.lastRelaySuccessAt" in stale_helper
    assert "AttemptStartedAt(report, state)" in stale_helper

    stale_check = report_failure.index(
        "if (FailureFromStaleAttempt(report, state)) {")
    canonical_degrade = report_failure.index(
        "ProxyDiagnosticsPhase::CanonicalDegraded")
    last_failure = report_failure.index("state.lastFailure = report.reason;")
    capability_failure = report_failure.index(
        "ProxyCapabilityCache::Instance().noteMtproxyFailure(")
    assert stale_check < capability_failure
    assert stale_check < last_failure
    assert stale_check < canonical_degrade
    assert "const auto recipeLevel = state.recipeLevel;" in report_failure
    assert "LogStaleAttemptFailure(report, recipeLevel);" in report_failure
    assert "return;" in report_failure.split(
        "LogStaleAttemptFailure(report, recipeLevel);", 1)[1].split("}", 1)[0]


def test_serverhello_ok_no_appdata_is_warning_not_fatal():
    source = read(ENDPOINT_HEALTH_CPP)
    route_state = source.split("struct RouteState", 1)[1].split("};", 1)[0]
    note_failure = function_body(source, "void NoteRouteFailure(")
    note_success = function_body(source, "void NoteRouteSuccess(")
    cooldown = function_body(source, "crl::time CooldownFor(")
    soft_helper = function_body(source, "bool SoftNoAppDataFailure(")
    warning_helper = function_body(source, "bool NoAppDataWarningStrike(")
    admit_body = function_body(source, "Admission EndpointHealth::admit(")
    report_failure = function_body(source, "void EndpointHealth::reportFailure(")

    assert "kRecentRelaySuccessWindow = crl::time(60 * 1000)" in source
    assert "kNoAppDataSoftRetry = crl::time(1000)" in source
    assert "kNoAppDataWarningCooldown = crl::time(3000)" in source
    assert "int relaySuspect = 0;" in route_state
    assert "++routeState.relaySuspect;" in note_failure
    assert "routeState.relaySuspect = 0;" in note_success

    assert "FailureReason::ServerHelloOkNoAppData" in soft_helper
    assert "RecentRelaySuccess(state, now)" in soft_helper
    assert "FailureReason::ServerHelloOkNoAppData" in warning_helper
    assert "consecutiveFailures <= 3" in warning_helper

    no_appdata_cooldown = cooldown.split(
        "reason == FailureReason::ServerHelloOkNoAppData", 1)[1]
    assert "kNoAppDataWarningCooldown" in no_appdata_cooldown
    assert "consecutiveFailures <= 3" in no_appdata_cooldown
    assert "kFirstCooldown" in no_appdata_cooldown

    assert "state.nextHandshakeAt > now" in admit_body
    assert "result.retryAfter = state.nextHandshakeAt - now;" in admit_body

    soft_check = report_failure.index(
        "if (SoftNoAppDataFailure(state, report.reason, now)) {")
    last_failure = report_failure.index("state.lastFailure = report.reason;")
    canonical_degrade = report_failure.index(
        "ProxyDiagnosticsPhase::CanonicalDegraded")
    assert report_failure.index("NoteRouteFailure(") < soft_check
    assert soft_check < last_failure
    assert soft_check < canonical_degrade

    soft_branch = report_failure.split(
        "if (SoftNoAppDataFailure(state, report.reason, now)) {", 1
    )[1].split("\n\t}", 1)[0]
    assert "state.relayProven = false;" in soft_branch
    assert "state.nextHandshakeAt = now + kNoAppDataSoftRetry;" in soft_branch
    assert "mtproxy no appdata warning after recent relay success" in (
        soft_branch)
    assert "return;" in soft_branch

    compact_failure = "".join(report_failure.split())
    assert "NoAppDataWarningStrike(report.reason,state.consecutiveFailures)" in (
        compact_failure)
    assert ".rotationAllowed = needsCooldown && !noAppDataWarning," in (
        report_failure)
    assert "const auto degraded = needsCooldown && !noAppDataWarning;" in (
        report_failure)
    assert "degraded?ProxyDiagnosticsPhase::CanonicalDegraded" in (
        compact_failure)
    assert "u\"mtproxy no appdata warning\"_q" in report_failure


def test_session_does_not_punish_remote_closed_after_usable_success():
    source = read(SESSION_CPP)
    error_body = function_body(source, "void SessionPrivate::onError(")
    active_body = error_body.split("_connection.get() == connection.get()")[1]

    assert "const auto snapshot =" in active_body
    assert "ProxyControlPlane::MtproxyEndpointSnapshot(" in active_body
    assert "_connectionMtproxyEndpoint" in active_body
    assert "MtProxy::FailureReason::AppDataRemoteClosed" in active_body
    assert "snapshot.healthy" in active_body
    assert "!snapshot.halfOpen" in active_body
    assert "ReportMtproxyFailure({" in active_body
    assert active_body.index("const auto snapshot =") < active_body.index(
        "ReportMtproxyFailure({")


def test_tls_socket_reports_typed_terminal_reasons():
    header = read(TLS_SOCKET_H)
    source = read(TLS_SOCKET_CPP)
    digest_body = function_body(source, "void TlsSocket::checkHelloDigest()")
    parts12_body = function_body(
        source,
        "void TlsSocket::checkHelloParts12(int parts1Size)")
    error_body = function_body(source, "void TlsSocket::handleError(int errorCode)")
    timeout_body = function_body(source, "void TlsSocket::timedOut()")
    tcp_timeout_body = function_body(
        read(CONNECTION_TCP_CPP),
        "void TcpConnection::timedOut()")

    assert '#include "mtproto/proxy/mtproxy/endpoint_health.h"' in header
    assert "MtProxy::FailureReason _failureReason" in header
    assert "MtProxy::EndpointUse _endpointUse" in header
    assert "QString _failureDiagnostic" not in header
    assert "failureDiagnostic()" not in header
    assert "MtProxy::FailureReason::ServerHelloHmacMismatch" in digest_body
    assert 'u"server_hello_hmac_mismatch"_q' not in digest_body
    assert "MtProxy::FailureReason::TlsAlertAfterClientHello" in parts12_body
    assert "MtProxy::FailureReason::ProxyProtocolBadResponse" in parts12_body
    assert "ProxyControlPlane::ReportMtproxySuccess(" in source
    assert "_endpointUse = protocolForFiles" in source
    assert ".use = _endpointUse" in source
    assert ".use = MtProxy::EndpointUse::Main" not in source
    assert "ToLegacyDiagnostic(FailureReason reason)" in read(ENDPOINT_HEALTH_CPP)
    assert "ProxyControlPlane::ReportMtproxyFailure(" in error_body
    assert "MtproxyNoteEndpointFailure(" not in source
    assert "MtproxyNoteEndpointSuccess(" not in source
    assert "const auto reason = failureReason();" in timeout_body
    assert "ProxyControlPlane::ReportMtproxyFailure(" in timeout_body
    assert ".reason = reason" in timeout_body
    assert ".configuredTlsProfile = _tlsProfile" in timeout_body
    assert ".sentProfile = _sentTlsProfile" in timeout_body
    assert "MtProxy::FailureReason::Timeout" not in timeout_body
    assert tcp_timeout_body.index("_socket->timedOut();") < (
        tcp_timeout_body.index("ReportProxyEvent("))
    assert ".mtproxyReason = _socket\n\t\t\t? _socket->mtproxyTerminalReason()" in (
        tcp_timeout_body)
    assert ".terminalUntil = _socket\n\t\t\t? _socket->mtproxyTerminalUntil()" in (
        tcp_timeout_body)
    assert "MtproxyRotateTlsProfileOnFailure(" not in source


def test_tls_socket_uses_endpoint_health_key_for_profile_rotation():
    abstract_header = read(ABSTRACT_SOCKET_H)
    abstract_source = read(ABSTRACT_SOCKET_CPP)
    source = read(TLS_SOCKET_CPP)
    header = read(TLS_SOCKET_H)
    connect_body = function_body(source, "void TlsSocket::connectToHost(")
    effective_body = function_body(source, "ProxyTlsProfile TlsSocket::effectiveTlsProfile() const")
    recipe_body = function_body(source, "void TlsSocket::applyAdaptiveRecipe()")

    assert "const ProxyData &proxy," in abstract_header
    assert "const auto networkProxy = ToNetworkProxy(proxy);" in abstract_source
    assert "const ProxyData &proxy," in header
    assert "_endpointId(MtProxy::EndpointIdFromProxy(proxy, stealth))" in source
    assert "_endpointKey(MtProxy::EndpointKey(_endpointId.canonical))" in source
    assert "MtProxy::EndpointIdFromAddress(" not in connect_body
    assert "_endpointId.route = MtProxy::RouteEndpointFromAddress(" in connect_body
    assert "_endpointId.resolvedHost = address;" not in connect_body
    assert "_endpointId.resolvedPort = port;" not in connect_body
    assert "_endpointKey = MtProxy::EndpointKey(_endpointId);" not in connect_body
    assert 'address + u":%1"_q.arg(port)' not in connect_body
    assert "ResolveEffectiveTlsProfile(_tlsProfile, _endpointKey)" in (
        effective_body)
    assert "input.endpointKey = _endpointKey;" in recipe_body


def test_adaptive_policy_no_longer_owns_endpoint_cooldown():
    header = read(ADAPTIVE_POLICY_H)
    source = read(ADAPTIVE_POLICY_CPP)

    assert "CooldownMsForEndpoint" not in header
    assert "CooldownMsForEndpoint" not in source
    assert "NoteEndpointFailure" not in header
    assert "NoteEndpointSuccess" not in header
    assert "void NoteEndpointFailure" not in source
    assert "void NoteEndpointSuccess" not in source
    assert "EndpointRecipeLevel" not in header
    assert "EndpointLastDiagnostic" not in header
    assert "RotateTlsProfileOnFailure(" in header
    assert "FailureNeedsRecipe(" in header


def test_appdata_remote_closed_is_mtproxy_terminal_reason():
    status_header = read(SOURCE_DIR / "mtproto" / "proxy" / "status.h")
    status_source = read(SOURCE_DIR / "mtproto" / "proxy" / "status.cpp")
    diagnostics = read(SOURCE_DIR / "mtproto" / "proxy" / "diagnostics.cpp")
    source = read(ENDPOINT_HEALTH_CPP)
    cooldown_body = function_body(source, "bool FailureNeedsCooldown(")
    terminal_body = function_body(
        source,
        "ProxyMtproxyTerminalReason ToProxyMtproxyTerminalReason(")

    assert "AppDataRemoteClosed," in status_header
    assert "ProxyMtproxyTerminalReason::AppDataRemoteClosed" in status_source
    assert 'u"appdata_remote_closed"_q' in diagnostics
    assert "case FailureReason::AppDataRemoteClosed:" in cooldown_body
    assert cooldown_body.index("case FailureReason::AppDataRemoteClosed:") < (
        cooldown_body.index("return false;"))
    assert "return ProxyMtproxyTerminalReason::AppDataRemoteClosed;" in terminal_body


def test_dns_negative_result_is_ttl_cached_and_reported_to_health():
    resolver = read(DOMAIN_RESOLVER_CPP)
    resolving = read(RESOLVING_CONNECTION_CPP)

    assert "kNegativeResolveTtl = crl::time(30 * 1000)" in resolver
    assert "_lastTimestamp + kNegativeResolveTtl" in resolver
    constructor = function_body(
        resolving,
        "ResolvingConnection::ResolvingConnection(")
    assert "cachedNegative" not in constructor
    assert "_child = nullptr;" not in constructor
    assert "proxy.resolvedIPs.empty()" in constructor
    assert "DnsResolverCache::Instance().request(" in constructor
    assert "instance->resolveProxyDomain(host);" not in constructor
    assert "MtProxy::FailureReason::DnsFailed" in resolving
    assert "ProxyMtproxyTerminalReason::DnsFailed" in resolving
    assert "emitError(kErrorCodeOther);" in resolving


def test_half_open_media_can_probe_after_cooldown():
    source = read(ENDPOINT_HEALTH_CPP)
    admit_body = function_body(source, "Admission EndpointHealth::admit(")

    assert "state.halfOpen && !IsInteractive(request.use)" not in admit_body
    assert "state.terminalUntil > now" in admit_body
    assert "AdmissionAction::SkipCooldown" not in admit_body
    assert "state.active >= policy.activeCap" in admit_body
    assert admit_body.index("state.terminalUntil > now") < admit_body.index(
        "state.active >= policy.activeCap")


def test_dns_cache_restarts_lost_inflight_and_forgets_dead_instances():
    source = read(DNS_CACHE_CPP)
    request_body = function_body(source, "void DnsResolverCache::request(")
    connect_body = function_body(
        source,
        "void DnsResolverCache::connectInstance(")

    # An in-flight resolve whose Instance died never fires
    # proxyDomainResolved; without an age check the host would stay
    # "resolving" forever and every request would queue silently.
    assert "kInflightRetryTimeout = 30 * crl::time(1000)" in source
    assert "crl::time inflightSince = 0;" in source
    assert "now - entry.inflightSince > kInflightRetryTimeout" in request_body
    # A destroyed Instance must leave ConnectedInstances, otherwise a new
    # Instance recycled at the same address is never connected.
    assert "&QObject::destroyed" in connect_body
    assert "ConnectedInstances.erase(instance);" in connect_body


def test_active_slots_expire_and_sustained_denial_requests_rotation():
    source = read(ENDPOINT_HEALTH_CPP)
    admit_body = function_body(source, "Admission EndpointHealth::admit(")
    release_body = function_body(
        source,
        "void EndpointHealth::releaseAttempt(")

    # A leaked lease must not pin the endpoint at its active cap forever:
    # attempts have a hard TTL, pruned on every admit.
    assert "kAttemptHardTtl = crl::time(120 * 1000)" in source
    assert "PruneExpiredAttempts(state, now);" in admit_body
    assert "state.attemptStarts.emplace(result.attemptId, attemptStartedAt);" in (
        admit_body)
    assert "attemptStarts.erase(attemptId);" in release_body

    # Sustained denial (no grant for kDeniedRotationAfter) fires a
    # rotation-allowed event so ProxyRotationManager can switch proxies
    # even while the main DC session looks connected.
    assert "kDeniedRotationAfter = crl::time(20 * 1000)" in source
    assert "state.deniedSince" in admit_body
    assert ".rotationAllowed = true," in admit_body
    assert "Events.fire(std::move(*rotationEvent));" in admit_body
    assert "mtproxy admission starving, requesting rotation" in admit_body


def test_rotation_manager_is_endpoint_health_aware():
    header = read(ROTATION_MANAGER_H)
    source = read(ROTATION_MANAGER_CPP)

    assert '#include "mtproto/proxy/mtproxy/endpoint_health.h"' in header
    assert "handleEndpointHealthChanged(" in header
    assert "hasActiveHealthRotationRequest() const" in header
    assert "EndpointHealth::Instance().changes(" in source
    assert "event.rotationAllowed" in source
    assert "_healthRotationRequestedUntil" in source
    assert "!hasActiveHealthRotationRequest()" in source
    assert "&& ranges::contains(" in source


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


if __name__ == "__main__":
    test_endpoint_health_module_is_registered_and_owns_state()
    test_session_private_admission_gates_before_socket_creation()
    test_proxy_endpoint_id_uses_decoded_mtproxy_secret_and_sni()
    test_session_private_reports_success_and_failure_to_endpoint_health()
    test_relay_success_shadows_older_attempt_failures()
    test_serverhello_ok_no_appdata_is_warning_not_fatal()
    test_session_does_not_punish_remote_closed_after_usable_success()
    test_tls_socket_reports_typed_terminal_reasons()
    test_tls_socket_uses_endpoint_health_key_for_profile_rotation()
    test_adaptive_policy_no_longer_owns_endpoint_cooldown()
    test_appdata_remote_closed_is_mtproxy_terminal_reason()
    test_dns_negative_result_is_ttl_cached_and_reported_to_health()
    test_half_open_media_can_probe_after_cooldown()
    test_dns_cache_restarts_lost_inflight_and_forgets_dead_instances()
    test_active_slots_expire_and_sustained_denial_requests_rotation()
    test_rotation_manager_is_endpoint_health_aware()
