from pathlib import Path


SOURCE_DIR = Path(__file__).resolve().parents[1]
ROOT = SOURCE_DIR.parents[1]
CMAKE = ROOT / "Telegram" / "CMakeLists.txt"
MTPROXY_DIR = SOURCE_DIR / "mtproto" / "proxy" / "mtproxy"
ENDPOINT_HEALTH_H = MTPROXY_DIR / "endpoint_health.h"
ENDPOINT_HEALTH_CPP = MTPROXY_DIR / "endpoint_health.cpp"
SESSION_H = SOURCE_DIR / "mtproto" / "session_private.h"
SESSION_CPP = SOURCE_DIR / "mtproto" / "session_private.cpp"
CONNECTION_TCP_CPP = SOURCE_DIR / "mtproto" / "connection_tcp.cpp"
TLS_SOCKET_H = MTPROXY_DIR / "tls_socket.h"
TLS_SOCKET_CPP = MTPROXY_DIR / "tls_socket.cpp"
ADAPTIVE_POLICY_H = MTPROXY_DIR / "adaptive_policy.h"
ADAPTIVE_POLICY_CPP = MTPROXY_DIR / "adaptive_policy.cpp"
DOMAIN_RESOLVER_CPP = SOURCE_DIR / "mtproto" / "details" / "mtproto_domain_resolver.cpp"
RESOLVING_CONNECTION_CPP = SOURCE_DIR / "mtproto" / "proxy" / "resolving_connection.cpp"
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
    assert "NoServerHelloAfterClientHello" in header
    assert "TlsAlertAfterClientHello" in header
    assert "ShortTlsResponseAfterClientHello" in header
    assert "UnrecognizedTlsResponseAfterClientHello" in header
    assert "PostHandshakeNoAppData" in header
    assert "DnsHostNotFound" in header
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
    assert "kHealthyActiveCap = 2" in source
    assert "ActiveCap(state)" in source


def test_session_private_admission_gates_before_socket_creation():
    header = read(SESSION_H)
    source = read(SESSION_CPP)
    append_body = function_body(
        source,
        "bool SessionPrivate::appendTestConnection(")

    assert '#include "mtproto/proxy/mtproxy/endpoint_health.h"' in header
    assert "MtProxy::EndpointAttemptLease mtproxyLease;" in header
    assert "base::flat_map<QString, crl::time> _endpointCooldownUntil" not in header
    assert "noteTestConnectionFailure(" not in header
    assert "kEndpointCooldownPenalty" not in source
    assert "MtproxyEndpointCooldown(" not in source
    assert "_endpointCooldownUntil" not in source
    assert "MtProxy::EndpointHealth::Instance().admit(" in append_body
    assert "MtProxy::AdmissionAction::StartNow" in append_body
    assert "setState(-int(admission.retryAfter));" in append_body
    assert append_body.index("MtProxy::EndpointHealth::Instance().admit(") < (
        append_body.index("AbstractConnection::Create("))
    assert "std::move(admission.lease)" in append_body
    assert "ReserveHandshakeGateForProxy(_options->proxy)" not in append_body
    assert "const auto proxied =" not in append_body


def test_proxy_endpoint_id_uses_decoded_mtproxy_secret_and_sni():
    source = read(ENDPOINT_HEALTH_CPP)
    body = function_body(source, "EndpointId EndpointIdFromProxy(")

    assert "if (proxy.type == ProxyData::Type::Mtproto)" in body
    assert "const auto secret = proxy.secretFromMtprotoPassword();" in body
    assert "result.secretHash = HashBytes(secret);" in body
    assert "result.domain = DomainFromSecret(secret);" in body
    assert "result.secretHash = HashText(proxy.password);" in body
    assert body.index("HashBytes(secret)") < body.index("HashText(proxy.password)")


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
    assert "MtProxy::EndpointHealth::Instance().reportFailure(" in timeout_body
    assert "MtProxy::FailureReason::Timeout" in timeout_body
    assert "connection.mtproxyEndpoint.domain.isEmpty()" in timeout_body
    assert "MtProxy::EndpointHealth::Instance().reportFailure(" in error_body
    assert "MtProxy::FailureReasonFromErrorCode(errorCode)" in error_body
    assert "_connection.get() == connection.get()" in error_body
    assert "_connectionMtproxyEndpoint.host.isEmpty()" in error_body
    assert "endpoint = _connectionMtproxyEndpoint" in error_body
    assert "_connectionMtproxyEndpoint = i->mtproxyEndpoint;" in connected_body
    assert "_connectionMtproxyUse = i->mtproxyUse;" in connected_body
    assert "_connectionMtproxyEndpoint = i->mtproxyEndpoint;" in confirm_body
    assert "_connectionMtproxyUse = i->mtproxyUse;" in confirm_body
    assert "_connectionMtproxyEndpoint = MtProxy::EndpointId();" in destroy_body
    assert "i->mtproxyLease.release();" in connected_body
    assert "MtProxy::EndpointHealth::Instance().reportSuccess(" in read(
        TLS_SOCKET_CPP)
    assert "i->mtproxyLease.release();" in remove_body


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
    assert "MtProxy::FailureReason::UnrecognizedTlsResponseAfterClientHello" in parts12_body
    assert "MtProxy::EndpointHealth::Instance().reportSuccess(" in source
    assert "_endpointUse = protocolForFiles" in source
    assert ".use = _endpointUse" in source
    assert ".use = MtProxy::EndpointUse::Main" not in source
    assert "ToLegacyDiagnostic(FailureReason reason)" in read(ENDPOINT_HEALTH_CPP)
    assert "MtProxy::EndpointHealth::Instance().reportFailure(" in error_body
    assert "MtproxyNoteEndpointFailure(" not in source
    assert "MtproxyNoteEndpointSuccess(" not in source
    assert "const auto reason = failureReason();" in timeout_body
    assert "MtProxy::EndpointHealth::Instance().reportFailure(" in timeout_body
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


def test_remote_closed_is_mtproxy_terminal_and_cooldown_worthy():
    status_header = read(SOURCE_DIR / "mtproto" / "proxy" / "status.h")
    status_source = read(SOURCE_DIR / "mtproto" / "proxy" / "status.cpp")
    diagnostics = read(SOURCE_DIR / "mtproto" / "proxy" / "diagnostics.cpp")
    source = read(ENDPOINT_HEALTH_CPP)
    cooldown_body = function_body(source, "bool FailureNeedsCooldown(")
    terminal_body = function_body(
        source,
        "ProxyMtproxyTerminalReason ToProxyMtproxyTerminalReason(")

    assert "RemoteClosed," in status_header
    assert "ProxyMtproxyTerminalReason::RemoteClosed" in status_source
    assert 'u"remote_closed"_q' in diagnostics
    assert "case FailureReason::RemoteClosed:" in cooldown_body
    assert cooldown_body.index("case FailureReason::RemoteClosed:") < (
        cooldown_body.index("return true;"))
    assert "return ProxyMtproxyTerminalReason::RemoteClosed;" in terminal_body


def test_dns_negative_result_is_ttl_cached_and_reported_to_health():
    resolver = read(DOMAIN_RESOLVER_CPP)
    resolving = read(RESOLVING_CONNECTION_CPP)

    assert "kNegativeResolveTtl = crl::time(30 * 1000)" in resolver
    assert "_lastTimestamp + kNegativeResolveTtl" in resolver
    assert "const auto cachedNegative = proxy.tryCustomResolve()" in resolving
    assert "_child = nullptr;" in resolving
    assert "MtProxy::FailureReason::DnsHostNotFound" in resolving
    assert "ProxyMtproxyTerminalReason::DnsHostNotFound" in resolving
    assert "emitError(kErrorCodeOther);" in resolving


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
    test_tls_socket_reports_typed_terminal_reasons()
    test_adaptive_policy_no_longer_owns_endpoint_cooldown()
    test_remote_closed_is_mtproxy_terminal_and_cooldown_worthy()
    test_dns_negative_result_is_ttl_cached_and_reported_to_health()
    test_rotation_manager_is_endpoint_health_aware()
