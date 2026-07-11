from pathlib import Path
from session_private_sources import read_session_private_sources


SOURCE_DIR = Path(__file__).resolve().parents[1]
ROOT = SOURCE_DIR.parents[1]
CMAKE = ROOT / "Telegram" / "CMakeLists.txt"
MTPROXY_DIR = SOURCE_DIR / "mtproto" / "proxy" / "mtproxy"
ENDPOINT_IDENTITY_H = MTPROXY_DIR / "endpoint_identity.h"
DATA_H = SOURCE_DIR / "mtproto" / "proxy" / "data.h"
RUNTIME_PROXY_DATA_H = SOURCE_DIR / "mtproto" / "runtime" / "proxy_data.h"
RUNTIME_PROXY_ENDPOINT_H = (
    SOURCE_DIR / "mtproto" / "runtime" / "proxy_endpoint.h")
DATA_CPP = SOURCE_DIR / "mtproto" / "proxy" / "data.cpp"
ENDPOINT_HEALTH_H = MTPROXY_DIR / "endpoint_health.h"
ENDPOINT_HEALTH_CPP = MTPROXY_DIR / "endpoint_health.cpp"
ENDPOINT_HEALTH_LIFECYCLE_CPP = MTPROXY_DIR / "endpoint_health_lifecycle.cpp"
ENDPOINT_HEALTH_STATE_H = MTPROXY_DIR / "endpoint_health_state.h"
ENDPOINT_HEALTH_POLICY_CPP = MTPROXY_DIR / "endpoint_health_policy.cpp"
ENDPOINT_HEALTH_DIAGNOSTICS_CPP = MTPROXY_DIR / "endpoint_health_diagnostics.cpp"
ABSTRACT_SOCKET_H = SOURCE_DIR / "mtproto" / "transport" / "details" / "mtproto_abstract_socket.h"
ABSTRACT_SOCKET_CPP = SOURCE_DIR / "mtproto" / "transport" / "details" / "mtproto_abstract_socket.cpp"
SESSION_H = SOURCE_DIR / "mtproto" / "session" / "private" / "session_private.h"
SESSION_CPP = SOURCE_DIR / "mtproto" / "session" / "private" / "session_private.cpp"
SESSION_TRANSPORT_H = SOURCE_DIR / "mtproto" / "session" / "private" / "transport.h"
PROXY_ADAPTER_CPP = SOURCE_DIR / "mtproto" / "proxy" / "session_proxy_adapter.cpp"
CONNECTION_TCP_CPP = SOURCE_DIR / "mtproto" / "transport" / "connection_tcp.cpp"
CONNECTION_TCP_H = SOURCE_DIR / "mtproto" / "transport" / "connection_tcp.h"
CONNECTION_ABSTRACT_H = SOURCE_DIR / "mtproto" / "transport" / "connection_abstract.h"
TLS_SOCKET_H = MTPROXY_DIR / "tls_socket.h"
TLS_SOCKET_CPP = MTPROXY_DIR / "tls_socket.cpp"
TLS_SOCKET_HANDSHAKE_CPP = MTPROXY_DIR / "tls_socket_handshake.cpp"
TLS_SOCKET_RECORDS_CPP = MTPROXY_DIR / "tls_socket_records.cpp"
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


def read_endpoint_health_sources():
    return "\n".join(read(path) for path in (
        ENDPOINT_HEALTH_CPP,
        ENDPOINT_HEALTH_LIFECYCLE_CPP,
    ))


def test_endpoint_health_module_is_registered_and_owns_state():
    header = read(ENDPOINT_HEALTH_H)
    identity_header = read(ENDPOINT_IDENTITY_H)
    endpoint_header = read(RUNTIME_PROXY_ENDPOINT_H)
    source = read(ENDPOINT_HEALTH_CPP)
    policy = read(ENDPOINT_HEALTH_POLICY_CPP)
    cmake = read(CMAKE)

    assert "mtproto/proxy/mtproxy/endpoint_health.cpp" in cmake
    assert "mtproto/proxy/mtproxy/endpoint_health.h" in cmake
    assert "mtproto/proxy/mtproxy/endpoint_health_lifecycle.cpp" in cmake
    assert "mtproto/proxy/mtproxy/endpoint_identity.cpp" in cmake
    assert "mtproto/proxy/mtproxy/endpoint_identity.h" in cmake
    assert "namespace MTP::details::MtProxy" in header
    assert '#include "mtproto/proxy/mtproxy/endpoint_identity.h"' in header
    assert "struct EndpointId" in endpoint_header
    assert "struct EndpointId" not in identity_header
    assert "enum class FailureReason" not in header
    assert "enum class FailureReason" in endpoint_header
    assert "ToLegacyDiagnostic(" in identity_header
    assert "ServerHelloHmacMismatch" in endpoint_header
    assert "ClientHelloSentNoServerHello" in endpoint_header
    assert "TlsAlertAfterClientHello" in endpoint_header
    assert "ServerHelloOkNoAppData" in endpoint_header
    assert "TcpConnectTimeout" in endpoint_header
    assert "DnsFailed" in endpoint_header
    assert "using EndpointUse = ProxyConnectionUse;" in header
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
    assert "kFirstCooldown = crl::time(15 * 1000)" in policy
    assert "kSecondCooldown = crl::time(45 * 1000)" in policy
    assert "kMaxCooldown = crl::time(120 * 1000)" in policy
    assert "kDnsNegativeTtl = crl::time(30 * 1000)" in policy
    assert "kColdActiveCap = 1" in policy
    assert "kHealthyActiveCap = 1" in policy
    assert "kHealthyHandshakeSpacing = crl::time(500)" in policy
    assert "EndpointConcurrencyPolicyFor(" in policy


def test_session_private_admission_gates_before_socket_creation():
    header = read(SESSION_TRANSPORT_H)
    source = read_session_private_sources()
    append_body = function_body(
        source,
        "bool SessionTransport::appendTestConnection(")

    assert '#include "mtproto/proxy/connection_broker.h"' not in source
    assert header.count("SessionProxyLease mtproxyLease;") == 2
    assert "std::vector<SessionProxyTicket> brokerTickets;" in header
    assert "base::flat_map<QString, crl::time> _endpointCooldownUntil" not in header
    assert "noteTestConnectionFailure(" not in header
    assert "kEndpointCooldownPenalty" not in source
    assert "MtproxyEndpointCooldown(" not in source
    assert "_endpointCooldownUntil" not in source
    assert "MtProxy::EndpointHealth::Instance().admit(" not in append_body
    assert "_owner->_proxyPort->requestConnection({" in append_body
    assert ".status = [=](SessionProxyAdmissionDecision)" in append_body
    assert "setState(-int(admission.retryAfter));" not in append_body
    assert "mtproxy admission queued" not in append_body
    assert "ProxyDiagnosticsPhase::AdmissionQueued" in read(
        SOURCE_DIR / "mtproto" / "proxy" / "connection_broker.cpp")
    assert "std::move(start.lease)" in append_body
    assert "ReserveHandshakeGateForProxy(_sessionState.options->proxy)" not in append_body
    assert "const auto proxied =" not in append_body


def test_proxy_endpoint_id_uses_decoded_mtproxy_secret_and_sni():
    data_header = read(DATA_H)
    runtime_data_header = read(RUNTIME_PROXY_DATA_H)
    data_source = read(DATA_CPP)
    identity_header = read(ENDPOINT_IDENTITY_H)
    identity_source = read(MTPROXY_DIR / "endpoint_identity.cpp")
    direct_body = function_body(data_source, "ProxyData ToDirectIpProxy(")
    body = function_body(identity_source, "EndpointId EndpointIdFromProxy(")
    key_body = function_body(identity_source, "QString EndpointKey(")

    assert "QString originalHost;" in runtime_data_header
    assert "struct CanonicalProxyEndpoint" in read(RUNTIME_PROXY_ENDPOINT_H)
    assert "struct RouteEndpoint" in read(RUNTIME_PROXY_ENDPOINT_H)
    assert "struct CanonicalProxyEndpoint" not in identity_header
    assert '#include "mtproto/runtime/proxy_data.h"' in data_header
    assert "QString resolvedHost;" not in identity_header
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
    source = read_session_private_sources()
    header = read(SESSION_TRANSPORT_H)
    adapter = read(PROXY_ADAPTER_CPP)
    timeout_body = function_body(source, "void SessionTransport::connectingTimedOut()")
    connected_body = function_body(source, "void SessionTransport::onConnected(")
    confirm_body = function_body(source, "void SessionTransport::confirmBestConnection()")
    error_body = function_body(source, "void SessionTransport::onError(")
    remove_body = function_body(source, "void SessionTransport::removeTestConnection(")
    destroy_body = function_body(
        source,
        "void SessionTransport::destroyAllConnections(ProxyCloseOrigin origin)")

    assert "MtProxy::EndpointId mtproxyEndpoint;" in header
    assert "SessionProxyEndpointUse mtproxyUse" in header
    assert "_owner->_proxyPort->reportConnectTimeout(proxyAttempt(connection));" in timeout_body
    assert "MtProxy::FailureReason::TcpConnectTimeout" in adapter
    assert timeout_body.index("connection.data->timedOut();") < timeout_body.index(
        "reportConnectTimeout(proxyAttempt(connection));")
    assert "const auto typed = attempt.transport.reason;" in adapter
    assert "_owner->_proxyPort->reportConnectionError(" in error_body
    assert "MtProxy::FailureReasonFromErrorCode(errorCode)" not in error_body
    assert "MtProxy::FailureReasonFromErrorCode(errorCode)" in adapter
    assert "_state.connection.get() == connection.get()" in error_body
    assert "EmptySessionProxyEndpoint(_state.mtproxyEndpoint)" in error_body
    assert "_state.mtproxyEndpoint" in error_body
    assert "_state.mtproxyEndpoint = i->mtproxyEndpoint;" in connected_body
    assert "_state.mtproxyUse = i->mtproxyUse;" in connected_body
    assert "_state.mtproxyEndpoint = i->mtproxyEndpoint;" in confirm_body
    assert "_state.mtproxyUse = i->mtproxyUse;" in confirm_body
    assert "_state.mtproxyEndpoint = MtProxy::EndpointId();" in destroy_body
    assert "if (!canProveMtproxyRelay()) {" in connected_body
    assert "i->mtproxyLease.release();" in connected_body
    assert "if (!canProveMtproxyRelay()) {" in confirm_body
    assert "i->mtproxyLease.release();" in confirm_body
    assert "_state.mtproxyLease = std::move(i->mtproxyLease);" in connected_body
    assert "_state.mtproxyLease = std::move(i->mtproxyLease);" in confirm_body
    assert "&_state.mtproxyLease" in error_body
    assert "_state.mtproxyLease = SessionProxyLease();" in destroy_body
    assert "reportMtproxySuccess(" in read(
        TLS_SOCKET_RECORDS_CPP)
    assert "i->mtproxyLease.release();" in remove_body

    usable_body = function_body(
        source,
        "void SessionTransport::reportMtproxyConnectionUsable(")
    assert "_owner->_proxyPort->reportConnected(" in usable_body
    assert "snapshot.healthy && !snapshot.halfOpen" in usable_body
    assert "SessionProxySuccessScope::Handshake" in usable_body
    assert "reportMtproxyConnectionUsable(*i);" in connected_body
    assert "reportMtproxyConnectionUsable(*i);" in confirm_body


def test_relay_success_shadows_older_attempt_failures():
    header = read(ENDPOINT_HEALTH_H)
    source = read(ENDPOINT_HEALTH_CPP)
    state_source = read(ENDPOINT_HEALTH_STATE_H)
    policy = read(ENDPOINT_HEALTH_POLICY_CPP)
    diagnostics = read(ENDPOINT_HEALTH_DIAGNOSTICS_CPP)
    abstract_h = read(CONNECTION_ABSTRACT_H)
    tcp_h = read(CONNECTION_TCP_H)
    tcp = read(CONNECTION_TCP_CPP)
    resolving_h = (SOURCE_DIR / "mtproto" / "proxy" / "resolving_connection.h"
        ).read_text(encoding="utf-8")
    resolving = read(RESOLVING_CONNECTION_CPP)
    tls_h = read(TLS_SOCKET_H)
    tls = read(TLS_SOCKET_CPP)
    tls_records = read(TLS_SOCKET_RECORDS_CPP)
    session = read_session_private_sources()

    report_failure = function_body(source, "void EndpointHealth::reportFailure(")
    report_success = function_body(source, "void EndpointHealth::reportSuccess(")
    stale_reasons = function_body(policy, "bool FailureCanBeStale(")
    stale_helper = function_body(policy, "bool FailureFromStaleAttempt(")
    stale_success_helper = function_body(
        policy,
        "bool SuccessFromStaleAttempt(")
    promotion_helper = function_body(
        state_source,
        "RelayProofPromotionResult PromoteRelayProof(")
    retirement_helper = function_body(
        state_source,
        "bool RetireRelayProof(")
    synchronize_helper = function_body(
        state_source,
        "void SynchronizeRelayProofAggregate(")
    stale_log = function_body(diagnostics, "void LogStaleAttemptFailure(")
    admit_body = function_body(source, "Admission EndpointHealth::admit(")
    tcp_connect = function_body(tcp, "void TcpConnection::connectToServer(")
    tls_timeout = function_body(tls, "void TlsSocket::timedOut()")
    tls_error = function_body(tls, "void TlsSocket::handleError(int errorCode)")
    tls_packet = function_body(tls_records, "bool TlsSocket::checkNextPacket()")
    session_connected = function_body(session, "void SessionTransport::onConnected(")
    handle_received = function_body(session, "void SessionMessageHandler::handleReceived()")
    note_payload = function_body(
        session,
        "void SessionTransport::noteMtprotoPayloadReceived()")
    append_body = function_body(
        session,
        "bool SessionTransport::appendTestConnection(")

    assert "struct RelayProofIdentity" in state_source
    relay_identity = state_source.split(
        "struct RelayProofIdentity {", 1)[1].split("};", 1)[0]
    assert "ProxyRuntimeId runtimeId = 0;" in relay_identity
    assert "uint64 proxyGeneration = 0;" in relay_identity
    assert "uint64 attemptId = 0;" in relay_identity
    assert "struct RelayProofState" in state_source
    assert "crl::time provenAt = 0;" in state_source
    assert "crl::time expiresAt = 0;" in state_source
    assert "std::map<RelayProofIdentity, RelayProofState> relayProofs;" in (
        state_source)
    removed_scalar = "lastRelay" + "AttemptId"
    assert removed_scalar not in state_source
    assert removed_scalar not in header
    assert removed_scalar not in source
    assert "uint64 successEpoch = 0;" in state_source
    assert "crl::time lastRelaySuccessAt = 0;" in state_source
    assert "ProxyTlsProfile lastGoodProfile = ProxyTlsProfile::Auto;" in state_source
    assert "RouteEndpoint lastGoodRoute;" in state_source
    assert "uint64 successEpoch = 0;" in header
    assert "crl::time lastRelaySuccessAt = 0;" in header
    assert "ProxyTlsProfile lastGoodProfile = ProxyTlsProfile::Auto;" in header
    assert "RouteEndpoint lastGoodRoute;" in header
    assert "uint64 attemptId = 0;" in header
    assert "uint64 proxyGeneration = 0;" in header
    assert "uint64 proxyEpoch = 0;" in header
    assert "uint64 successEpoch = 0;" in header
    assert "crl::time attemptStartedAt = 0;" in header
    assert "uint64 proxyGeneration() const" in header
    assert "uint64 successEpoch() const" in header
    assert "crl::time startedAt() const" in header
    assert "const QString &endpointKey() const" in header
    assert "return _key;" in function_body(
        source,
        "const QString &EndpointAttemptLease::endpointKey() const")

    assert "const auto attemptStartedAt = now;" in admit_body
    assert "result.proxyGeneration = request.proxyGeneration;" in admit_body
    assert "result.successEpoch = state.successEpoch;" in admit_body
    assert "state.attemptStarts.emplace(result.attemptId, EndpointAttemptState{" in (
        admit_body)
    assert ".runtimeId = runtimeId" in admit_body
    assert "result.attemptStartedAt = attemptStartedAt;" in admit_body
    assert "uint64 proxyGeneration," in source
    assert "_proxyGeneration(proxyGeneration)" in source
    assert "uint64 successEpoch," in source
    assert "_successEpoch(successEpoch)" in source
    assert "crl::time startedAt)" in source
    assert "_startedAt(startedAt)" in source

    assert "ConnectionStartContext context = {}) = 0;" in abstract_h
    assert "ConnectionStartContext context = {}) override;" in tcp_h
    assert "ConnectionStartContext context = {}) override;" in resolving_h
    assert "_mtproxyAttemptStartedAt" in tcp_h
    assert "_mtproxyAttemptStartedAt" in tls_h
    assert "CreateProxyAwareSocket(" in tcp_connect
    assert "_mtproxyAttemptStartedAt" in tcp_connect
    assert "_mtproxyAttempt = context.mtproxyAttempt;" in resolving
    assert ".mtproxyAttempt = routeConnectionAttempt" in resolving
    assert ".mtproxyAttempt = startAttempt" in append_body

    assert ".attemptId = _mtproxyAttempt.attemptId" in tls_timeout
    assert ".proxyGeneration = _mtproxyAttempt.proxyGeneration" in tls_timeout
    assert ".proxyEpoch = _mtproxyAttempt.proxyEpoch" in tls_timeout
    assert ".successEpoch = _mtproxyAttempt.successEpoch" in tls_timeout
    assert ".attemptStartedAt = _mtproxyAttemptStartedAt" in tls_timeout
    assert ".attemptId = _mtproxyAttempt.attemptId" in tls_error
    assert ".proxyGeneration = _mtproxyAttempt.proxyGeneration" in tls_error
    assert ".successEpoch = _mtproxyAttempt.successEpoch" in tls_error
    assert ".attemptStartedAt = _mtproxyAttemptStartedAt" in tls_error

    assert "FakeTlsAppData," in header
    assert "SuccessScope::FakeTlsAppData" in tls_packet
    assert "SuccessScope::Relay" not in tls_packet
    assert ".attemptId = _mtproxyAttempt.attemptId" in tls_packet
    assert ".proxyGeneration = _mtproxyAttempt.proxyGeneration" in tls_packet
    assert ".successEpoch = _mtproxyAttempt.successEpoch" in tls_packet
    assert ".attemptStartedAt = _mtproxyAttemptStartedAt" in tls_packet
    assert "_state.connection->proxyConnectionAttempt()" in session
    assert ".attempt = attempt" in session
    assert ".attemptStartedAt = _state.mtproxyAttemptStartedAt" in session
    assert "_owner->_transport.noteMtprotoPayloadReceived();" in handle_received
    assert "_owner->_proxyPort->reportFirstMtprotoPayload(" in note_payload
    assert "currentProxyAttempt()" in note_payload
    assert "&_state.mtproxyLease" in note_payload
    assert "_state.mtproxyAttemptStartedAt = mtproxyAttemptStartedAt;" in (
        session_connected)

    assert "const auto promotion = PromoteRelayProof(" in report_success
    assert ".runtimeId = report.runtimeId" in report_success
    assert ".proxyGeneration = report.proxyGeneration" in report_success
    assert ".attemptId = report.attemptId" in report_success
    assert ".provenAt = now" in report_success
    assert ".expiresAt = RelayProofExpiresAt(now)" in report_success
    assert "++state.successEpoch;" in report_success
    assert "state.lastGoodProfile = report.sentProfile;" in report_success
    assert "state.lastGoodRoute = report.endpoint.route;" in report_success
    assert "report.scope != SuccessScope::Relay" in report_success

    assert "stale_attempt_failed" in stale_log
    assert "ProxyDiagnosticsSeverity::Info" in stale_log
    assert "FailureReason::ClientHelloSentNoServerHello" in stale_reasons
    assert "FailureReason::ServerHelloOkNoAppData" in stale_reasons
    assert "FailureReason::TcpConnectTimeout" in stale_reasons
    assert "state.lastRelaySuccessAt" in stale_helper
    assert "HasRelayProof(state, identity)" in stale_helper
    assert "AttemptStartedAt(report, state)" in stale_helper
    assert stale_helper.index("RuntimeProxyGenerationIsStale(") < (
        stale_helper.index("HasRelayProof(state, identity)"))
    assert stale_success_helper.index("RuntimeProxyGenerationIsStale(") < (
        stale_success_helper.index("HasEndpointAttempt(state, identity)"))
    assert stale_success_helper.index("HasEndpointAttempt(state, identity)") < (
        stale_success_helper.index("ReportEpochIsStale("))

    assert promotion_helper.index("HasRelayProof(state, identity)") < (
        promotion_helper.index("HasEndpointAttempt(state, identity)"))
    assert promotion_helper.index(
        "RelayProofPromotionResult::AlreadyProven") < (
            promotion_helper.index("state.relayProofs.emplace(identity, proof);"))
    assert promotion_helper.index(
        "RelayProofPromotionResult::MissingAdmission") < (
            promotion_helper.index("state.relayProofs.emplace(identity, proof);"))
    assert promotion_helper.index("state.relayProofs.emplace(identity, proof);") < (
        promotion_helper.index("state.attemptStarts.erase(identity.attemptId);"))
    assert "state.relayProofs.erase(identity)" in retirement_helper
    assert "SynchronizeRelayProofAggregate(state);" in retirement_helper
    assert "state.relayProven = !state.relayProofs.empty();" in (
        synchronize_helper)
    assert "entry.second.provenAt > state.lastRelaySuccessAt" in (
        synchronize_helper)

    for body in (report_failure, report_success):
        assert "ResolveLeaseIdentity(report);" in body
        assert body.count("report.lease->release();") == 1
        assert body.index("const auto releaseLease = gsl::finally(") < (
            body.index("QMutexLocker lock(&storage.mutex);"))
        key_check = body.index(
            "if (report.lease && report.lease->endpointKey() != key) {")
        assert body.index("const auto key = EndpointKey(report.endpoint);") < (
            key_check)
        assert key_check < body.index("QMutexLocker lock(&storage.mutex);")

    generation_check = report_failure.index(
        "if (RuntimeProxyGenerationIsStale(")
    stale_check = report_failure.index(
        "if (FailureFromStaleAttempt(report, state)) {")
    retirement = report_failure.index(
        "static_cast<void>(RetireRelayProof(state, identity));")
    sibling_guard = report_failure.index("if (state.relayProven) {")
    canonical_write = report_failure.index("state.endpoint = report.endpoint;")
    route_failure = report_failure.index("NoteRouteFailure(")
    assert generation_check < stale_check < retirement < sibling_guard
    assert sibling_guard < canonical_write < route_failure
    sibling_branch = report_failure.split(
        "if (state.relayProven) {", 1)[1].split("}", 1)[0]
    assert "return;" in sibling_branch

    promotion = report_success.index("const auto promotion = PromoteRelayProof(")
    duplicate = report_success.index(
        "case RelayProofPromotionResult::AlreadyProven:")
    missing = report_success.index(
        "case RelayProofPromotionResult::MissingAdmission:")
    first_success_write = report_success.index("state.endpoint = report.endpoint;")
    assert promotion < duplicate <= missing < first_success_write
    rejected_promotions = report_success[duplicate:first_success_write]
    assert "return;" in rejected_promotions
    assert "state.lastSuccessAt" not in rejected_promotions
    assert "++state.successEpoch" not in rejected_promotions
    assert "NoteRouteSuccess" not in rejected_promotions

    canonical_degrade = report_failure.index(
        "ProxyDiagnosticsPhase::CanonicalDegraded")
    last_failure = report_failure.index("state.lastFailure = report.reason;")
    capability_failure = report_failure.index("NoteCapabilityMtproxyFailure(")
    assert stale_check < capability_failure
    assert stale_check < last_failure
    assert stale_check < canonical_degrade
    assert "const auto recipeLevel = state.recipeLevel;" in report_failure
    assert "LogStaleAttemptFailure(_runtime, report, recipeLevel);" in (
        report_failure)
    assert "return;" in report_failure.split(
        "LogStaleAttemptFailure(_runtime, report, recipeLevel);", 1
    )[1].split("}", 1)[0]


def test_relay_success_advances_attempt_epoch_and_shadows_old_reports():
    header = read(ENDPOINT_HEALTH_H)
    source = read(ENDPOINT_HEALTH_CPP)
    state_source = read(ENDPOINT_HEALTH_STATE_H)
    policy = read(ENDPOINT_HEALTH_POLICY_CPP)
    report_failure = function_body(source, "void EndpointHealth::reportFailure(")
    report_success = function_body(source, "void EndpointHealth::reportSuccess(")
    report_epoch_stale = function_body(policy, "bool ReportEpochIsStale(")
    stale_failure = function_body(policy, "bool FailureFromStaleAttempt(")
    stale_success = function_body(policy, "bool SuccessFromStaleAttempt(")
    synchronize = function_body(
        state_source,
        "void SynchronizeRelayProofAggregate(")

    assert "uint64 proxyEpoch = 0;" in header
    assert "uint64 successEpoch = 0;" in header
    assert "uint64 proxyGeneration = 0;" in header
    assert "uint64 proxyEpoch = 1;" in state_source
    assert "uint64 successEpoch = 0;" in state_source
    assert "std::map<ProxyRuntimeId, uint64> generations;" in state_source
    assert "report.runtimeId" in stale_failure
    assert "report.runtimeId" in stale_success
    assert "ReportEpochIsStale(report.proxyEpoch, state)" in stale_failure
    assert "ReportEpochIsStale(report.proxyEpoch, state)" in stale_success
    assert "ReportSuccessEpochIsStale(report.successEpoch, state)" in (
        stale_failure)
    assert "ReportSuccessEpochIsStale(report.successEpoch, state)" in (
        stale_success)
    assert stale_failure.index("RuntimeProxyGenerationIsStale(") < (
        stale_failure.index("HasRelayProof(state, identity)"))
    assert stale_success.index("RuntimeProxyGenerationIsStale(") < (
        stale_success.index("HasEndpointAttempt(state, identity)"))
    assert "HasRelayProof(state, identity)" in stale_success
    assert "proxyEpoch&&proxyEpoch<state.proxyEpoch" in (
        "".join(report_epoch_stale.split()))
    report_success_epoch_stale = function_body(
        policy,
        "bool ReportSuccessEpochIsStale(")
    assert "successEpoch&&successEpoch<state.successEpoch" in (
        "".join(report_success_epoch_stale.split()))
    relay_guard = report_success.index(
        "if (report.scope != SuccessScope::Relay) {")
    preliminary_success = report_success[:relay_guard]
    assert "state.lastSuccessAt = now;" in preliminary_success
    assert "++state.proxyEpoch;" not in preliminary_success
    assert "state.relayProven = true;" not in preliminary_success
    assert "const auto promotion = PromoteRelayProof(" in preliminary_success
    assert relay_guard < report_success.index("state.recipeLevel = 0;")
    assert relay_guard < report_success.index("++state.proxyEpoch;")
    assert relay_guard < report_success.index(
        "NoteConnectSuccess(_runtime, report.endpoint);")
    assert "state.relayProven = !state.relayProofs.empty();" in synchronize
    assert "state.healthy = true;" in synchronize

    failure_stale_check = report_failure.index(
        "if (FailureFromStaleAttempt(report, state)) {")
    failure_state_write = report_failure.index("state.endpoint = report.endpoint;")
    assert failure_stale_check < failure_state_write

    success_generation_check = report_success.index(
        "if (RuntimeProxyGenerationIsStale(")
    success_stale_check = report_success.index(
        "if (SuccessFromStaleAttempt(report, state)) {")
    success_promotion = report_success.index(
        "const auto promotion = PromoteRelayProof(")
    success_state_write = report_success.index("state.endpoint = report.endpoint;")
    success_scheduler = report_success.index(
        "NoteConnectSuccess(_runtime, report.endpoint);")
    assert success_generation_check < success_stale_check < success_promotion
    assert success_promotion < success_state_write
    assert success_stale_check < success_scheduler


def test_serverhello_ok_no_appdata_is_warning_not_fatal():
    source = read(ENDPOINT_HEALTH_CPP)
    state_source = read(ENDPOINT_HEALTH_STATE_H)
    policy = read(ENDPOINT_HEALTH_POLICY_CPP)
    route_state = state_source.split("struct RouteState", 1)[1].split("};", 1)[0]
    note_failure = function_body(source, "void NoteRouteFailure(")
    note_success = function_body(source, "void NoteRouteSuccess(")
    cooldown = function_body(policy, "crl::time CooldownFor(")
    soft_helper = function_body(policy, "bool SoftNoAppDataFailure(")
    warning_helper = function_body(policy, "bool NoAppDataWarningStrike(")
    admit_body = function_body(source, "Admission EndpointHealth::admit(")
    report_failure = function_body(source, "void EndpointHealth::reportFailure(")

    assert "kRecentRelaySuccessWindow = crl::time(60 * 1000)" in policy
    assert "kNoAppDataSoftRetry = crl::time(1000)" in policy
    assert "kNoAppDataWarningCooldown = crl::time(3000)" in policy
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
    assert "state.relayProven = false;" not in soft_branch
    assert "state.relayProofs.clear();" not in soft_branch
    assert "state.nextHandshakeAt = now + NoAppDataSoftRetry();" in soft_branch
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
    source = read_session_private_sources()
    error_body = function_body(source, "void SessionTransport::onError(")
    active_body = error_body.split("_state.connection.get() == connection.get()")[1]

    assert "const auto snapshot =" not in active_body
    assert "_owner->_proxyPort->endpointSnapshot(" not in active_body
    assert "_state.mtproxyEndpoint" in active_body
    assert "_owner->_proxyPort->reportConnectionError(" in active_body
    assert "true);" in active_body
    assert "MtProxy::FailureReason::AppDataRemoteClosed" in read(
        PROXY_ADAPTER_CPP)
    assert "snapshot.healthy" in read(PROXY_ADAPTER_CPP)
    assert "!snapshot.halfOpen" in read(PROXY_ADAPTER_CPP)


def test_tls_socket_reports_typed_terminal_reasons():
    header = read(TLS_SOCKET_H)
    source = read(TLS_SOCKET_CPP)
    handshake = read(TLS_SOCKET_HANDSHAKE_CPP)
    records = read(TLS_SOCKET_RECORDS_CPP)
    tls_sources = "\n".join((source, handshake, records))
    digest_body = function_body(handshake, "void TlsSocket::checkHelloDigest()")
    parts12_body = function_body(
        handshake,
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
    assert "reportMtproxySuccess(" in records
    assert "_endpointUse = _mtproxyAttempt.use;" in source
    assert ".use = _endpointUse" in tls_sources
    assert ".use = MtProxy::EndpointUse::Main" not in tls_sources
    assert "ToLegacyDiagnostic(FailureReason reason)" in read(
        MTPROXY_DIR / "endpoint_identity.cpp")
    assert "reportMtproxyFailure(" in error_body
    assert "MtproxyNoteEndpointFailure(" not in source
    assert "MtproxyNoteEndpointSuccess(" not in source
    assert "auto reason = failureReason();" in timeout_body
    assert "ServerHelloOkNoMtprotoData" in timeout_body
    assert "reportMtproxyFailure(" in timeout_body
    assert ".reason = reason" in timeout_body
    assert ".configuredTlsProfile = _configuredTlsProfile" in timeout_body
    assert ".sentProfile = _sentTlsProfile" in timeout_body
    assert "MtProxy::FailureReason::Timeout" not in timeout_body
    assert tcp_timeout_body.index("_socket->timedOut();") < (
        tcp_timeout_body.index("ReportProxyEvent("))
    assert ".mtproxyReason = _socket\n\t\t\t? _socket->mtproxyTerminalReason()" in (
        tcp_timeout_body)
    assert ".terminalUntil = _socket\n\t\t\t? _socket->mtproxyTerminalUntil()" in (
        tcp_timeout_body)
    assert "MtproxyRotateTlsProfileOnFailure(" not in tls_sources


def test_tls_socket_uses_immutable_admission_plan():
    abstract_header = read(ABSTRACT_SOCKET_H)
    abstract_source = read(ABSTRACT_SOCKET_CPP)
    source = read(TLS_SOCKET_CPP)
    handshake = read(TLS_SOCKET_HANDSHAKE_CPP)
    header = read(TLS_SOCKET_H)
    connect_body = function_body(source, "void TlsSocket::connectToHost(")
    effective_body = function_body(source, "ProxyTlsProfile TlsSocket::effectiveTlsProfile() const")
    socket_factory = read(SOURCE_DIR / "mtproto" / "proxy" / "socket_factory.cpp")

    assert "const ProxyData &proxy," not in abstract_header
    assert "const auto networkProxy = ToNetworkProxy(proxy);" in socket_factory
    assert "std::make_unique<TlsSocket>" in socket_factory
    assert "std::make_unique<WssSocket>" in socket_factory
    assert "const ProxyData &proxy," in header
    assert "_endpointId(MtProxy::EndpointIdFromProxy(proxy, stealth))" in source
    assert "_endpointKey(MtProxy::EndpointKey(_endpointId.canonical))" in source
    assert "MtProxy::EndpointIdFromAddress(" not in connect_body
    assert "_endpointId.route = MtProxy::RouteEndpointFromAddress(" in connect_body
    assert "_endpointId.resolvedHost = address;" not in connect_body
    assert "_endpointId.resolvedPort = port;" not in connect_body
    assert "_endpointKey = MtProxy::EndpointKey(_endpointId);" not in connect_body
    assert 'address + u":%1"_q.arg(port)' not in connect_body
    assert "return _tlsProfile;" in effective_body
    assert "applyAdaptiveRecipe" not in handshake
    assert "_mtproxyPlan(NormalizeAttemptPlan(" in source
    assert "MtProxyAttemptPlan mtproxyPlan" in header


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
    policy = read(ENDPOINT_HEALTH_POLICY_CPP)
    identity_source = read(MTPROXY_DIR / "endpoint_identity.cpp")
    cooldown_body = function_body(policy, "bool FailureNeedsCooldown(")
    terminal_body = function_body(
        identity_source,
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
    start_resolving = function_body(
        resolving,
        "void ResolvingConnection::startResolving(")
    connect = function_body(
        resolving,
        "void ResolvingConnection::connectToServer(")
    assert "cachedNegative" not in constructor
    assert "_child = nullptr;" not in constructor
    assert "_proxy.resolvedIPs.empty()" in connect
    assert "_runtime->proxyServices().dnsResolver().request(" in start_resolving
    assert connect.index("_mtproxyAttempt = context.mtproxyAttempt;") < (
        connect.index("startResolving();"))
    assert "DnsResolverCache::Instance()" not in resolving
    assert "instance->resolveProxyDomain(host);" not in start_resolving
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

    # An in-flight resolve whose Instance died never fires
    # proxyDomainResolved; without an age check the host would stay
    # "resolving" forever and every request would queue silently.
    assert "kInflightRetryTimeout = 30 * crl::time(1000)" in source
    assert "crl::time inflightSince = 0;" in source
    assert "now - entry.inflightSince > kInflightRetryTimeout" in request_body
    assert "struct DnsResolverCache::Storage" in source
    assert "std::map<QString, DnsResolverEntry> entries;" in source


def test_relay_proofs_are_pruned_on_every_non_probe_state_path():
    source = read_endpoint_health_sources()
    policy = read(ENDPOINT_HEALTH_POLICY_CPP)
    admit = function_body(source, "Admission EndpointHealth::admit(")
    failure = function_body(source, "void EndpointHealth::reportFailure(")
    success = function_body(source, "void EndpointHealth::reportSuccess(")
    retirement = function_body(
        source,
        "RelayProofRetirement RetireRelayProofLocked(")
    stall = function_body(source, "void EndpointHealth::noteRelayStall(")
    neutral = function_body(source, "void EndpointHealth::retireRelayProof(")
    generation = function_body(
        source,
        "void EndpointHealth::applyProxyGeneration(")
    snapshot = function_body(source, "Snapshot EndpointHealth::snapshot(")
    prune = function_body(policy, "void PruneExpiredEndpointState(")

    assert "constexpr auto kRelayProofHardTtl" in policy
    assert "PruneExpiredRelayProofs(state, now);" in prune
    for body in (admit, failure, success, retirement, generation, snapshot):
        assert "PruneExpiredEndpointState(" in body
    assert "RetireRelayProofLocked(state, report, now)" in stall
    assert "RetireRelayProofLocked(i->second, report, now)" in neutral
    assert admit.index("IsProxyCheck(request.use)") < admit.index(
        "PruneExpiredEndpointState(state, now);")
    assert failure.index("report.use == EndpointUse::ProxyCheck") < (
        failure.index("PruneExpiredEndpointState(state, now);"))
    assert success.index("report.use == EndpointUse::ProxyCheck") < (
        success.index("PruneExpiredEndpointState(state, now);"))
    assert stall.index("IsProxyCheck(report.use)") < stall.index(
        "RetireRelayProofLocked(state, report, now)")
    assert neutral.index("IsProxyCheck(report.use)") < neutral.index(
        "RetireRelayProofLocked(i->second, report, now)")
    assert snapshot.index("PruneExpiredEndpointState(i->second, now);") < (
        snapshot.index("MakeSnapshot(i->second, _runtimeId)"))


def test_active_slots_expire_and_sustained_denial_requests_rotation():
    source = read(ENDPOINT_HEALTH_CPP)
    policy = read(ENDPOINT_HEALTH_POLICY_CPP)
    admit_body = function_body(source, "Admission EndpointHealth::admit(")
    context = read(SOURCE_DIR / "mtproto" / "proxy" / "proxy_endpoint_context.cpp")
    release_body = function_body(
        context,
        "void ProxyEndpointContext::releaseEndpointAttempt(")

    # A leaked lease must not pin the endpoint at its active cap forever:
    # attempts have a hard TTL, pruned on every admit.
    assert "kAttemptHardTtl = crl::time(120 * 1000)" in policy
    assert "PruneExpiredEndpointState(state, now);" in admit_body
    assert "state.attemptStarts.emplace(result.attemptId, EndpointAttemptState{" in (
        admit_body)
    assert "attemptStarts.erase(attemptId);" in release_body

    # Sustained denial (no grant for kDeniedRotationAfter) fires a
    # rotation-allowed event so ProxyRotationManager can switch proxies
    # even while the main DC session looks connected.
    assert "kDeniedRotationAfter = crl::time(20 * 1000)" in source
    assert "state.deniedSince" in admit_body
    assert ".rotationAllowed = true," in admit_body
    assert "fireEndpointEventOnMain(std::move(*rotationEvent));" in admit_body
    assert "mtproxy admission starving, requesting rotation" in admit_body


def test_endpoint_health_events_are_published_on_main_thread():
    source = read(ENDPOINT_HEALTH_CPP)
    manager = read(ROTATION_MANAGER_CPP)
    publisher = function_body(source, "void EndpointHealth::fireEndpointEventOnMain(")
    admit_body = function_body(source, "Admission EndpointHealth::admit(")
    failure_body = function_body(source, "void EndpointHealth::reportFailure(")
    changes_body = function_body(source, "auto EndpointHealth::changes() const")

    assert '#include <crl/crl_on_main.h>' in source
    assert "EndpointHealth::EndpointHealth(" in source
    assert "std::shared_ptr<ProxyEndpointContext> context" in source
    assert "[[nodiscard]] static EndpointHealth &Instance();" not in read(
        ENDPOINT_HEALTH_H)
    assert "crl::on_main([context, event = std::move(event)]() mutable {" in publisher
    assert "context->storage().events.fire(std::move(event));" in publisher
    assert "fireEndpointEventOnMain(std::move(*rotationEvent));" in admit_body
    assert "fireEndpointEventOnMain(std::move(event));" in failure_body
    assert "_storage->events.fire(" not in admit_body
    assert "_storage->events.fire(" not in failure_body
    assert "return _context->storage().events.events();" in changes_body
    assert "crl::on_main(base::make_weak(this)" not in manager


def test_rotation_manager_is_endpoint_health_aware():
    header = read(ROTATION_MANAGER_H)
    source = read(ROTATION_MANAGER_CPP)

    assert '#include "mtproto/proxy/control_plane.h"' in header
    assert '#include "mtproto/proxy/mtproxy/endpoint_health.h"' not in header
    assert "handleEndpointHealthChanged(" in header
    assert "hasActiveHealthRotationRequest() const" in header
    assert "runtimeEnvironment().proxyServices().control().mtproxyEndpointChanges(" in source
    assert "EndpointHealth::Instance().changes(" not in source
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
    test_relay_success_advances_attempt_epoch_and_shadows_old_reports()
    test_serverhello_ok_no_appdata_is_warning_not_fatal()
    test_session_does_not_punish_remote_closed_after_usable_success()
    test_tls_socket_reports_typed_terminal_reasons()
    test_tls_socket_uses_immutable_admission_plan()
    test_adaptive_policy_no_longer_owns_endpoint_cooldown()
    test_appdata_remote_closed_is_mtproxy_terminal_reason()
    test_dns_negative_result_is_ttl_cached_and_reported_to_health()
    test_half_open_media_can_probe_after_cooldown()
    test_dns_cache_restarts_lost_inflight_and_forgets_dead_instances()
    test_relay_proofs_are_pruned_on_every_non_probe_state_path()
    test_active_slots_expire_and_sustained_denial_requests_rotation()
    test_endpoint_health_events_are_published_on_main_thread()
    test_rotation_manager_is_endpoint_health_aware()
