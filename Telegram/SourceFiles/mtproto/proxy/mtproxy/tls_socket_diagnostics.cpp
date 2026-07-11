/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "mtproto/proxy/mtproxy/tls_socket.h"

#include "mtproto/proxy/mtproxy/handshake_diagnosis.h"
#include "mtproto/proxy/mtproxy/tls_socket_utils.h"
#include "mtproto/proxy/diagnostics.h"
#include "mtproto/proxy/proxy_endpoint_context.h"
#include "mtproto/proxy/proxy_services.h"
#include "mtproto/runtime/runtime_environment.h"

#include <QtCore/QCryptographicHash>

#include <algorithm>

namespace MTP::details {

ProxyTransportFailure TlsSocket::proxyTransportFailure() const {
	const auto clientHelloKnown = _clientHelloBytes > 0;
	const auto domain = domainFromSecret();
	const auto domainBytes = QByteArray(
		reinterpret_cast<const char*>(domain.data()),
		int(domain.size()));
	const auto domainHash = QCryptographicHash::hash(
		domainBytes,
		QCryptographicHash::Sha256);
	const auto parserStage = [&] {
		switch (_phase) {
		case HandshakePhase::None: return u"tcp_connect"_q;
		case HandshakePhase::TcpConnected: return u"client_hello_write"_q;
		case HandshakePhase::ClientHelloSent: return u"server_hello"_q;
		case HandshakePhase::ServerHelloOk: return u"tls_appdata"_q;
		case HandshakePhase::FirstDataReceived: return u"mtproto"_q;
		}
		return QString();
	}();
	return {
		.reason = MtProxy::ToProxyMtproxyTerminalReason(failureReason()),
		.error = _connectionError,
		.closeOrigin = _closeOrigin,
		.parserStage = parserStage,
		.rxAfterClientHello = clientHelloKnown
			? std::make_optional(_rxAfterClientHello)
			: std::nullopt,
		.rxClass = clientHelloKnown ? responseClass() : QString(),
		.block = blockToken(),
		.tlsRecordType = responseRecordType(),
		.tlsRecordVersion = responseRecordVersion(),
		.tlsRecordLength = responseRecordLength(),
		.responsePrefixHash = responsePrefixHash(),
		.sniLength = clientHelloKnown
			? std::make_optional(int(domain.size()))
			: std::nullopt,
		.sniHash = clientHelloKnown
			? QString::fromLatin1(domainHash.toHex().left(16))
			: QString(),
		.clientHelloBytes = clientHelloKnown
			? std::make_optional(_clientHelloBytes)
			: std::nullopt,
		.clientHelloWrites = clientHelloKnown
			? std::make_optional(_clientHelloWrites)
			: std::nullopt,
		.clientHelloAcceptedBytes = clientHelloKnown
			? std::make_optional(_clientHelloAcceptedBytes)
			: std::nullopt,
		.sentTlsProfile = clientHelloKnown
			? std::make_optional(_sentTlsProfile)
			: std::nullopt,
		.pskOffered = clientHelloKnown
			? std::make_optional(_syntheticPskOffered)
			: std::nullopt,
		.fragmentedClientHello = clientHelloKnown
			? std::make_optional(_clientHelloFragmented)
			: std::nullopt,
		.clientHelloFragmentSplit = _clientHelloFragmented
			? std::make_optional(_clientHelloFragmentSplit)
			: std::nullopt,
		.clientHelloFragmentDelayMs = _clientHelloFragmented
			? std::make_optional(_clientHelloFragmentDelayMs)
			: std::nullopt,
		.dnsMs = std::nullopt,
		.tcpMs = (_tcpConnectedAt && _mtproxyAttemptStartedAt)
			? std::make_optional(_tcpConnectedAt - _mtproxyAttemptStartedAt)
			: std::nullopt,
		.firstRxMs = (_firstRxAt && _mtproxyAttemptStartedAt)
			? std::make_optional(_firstRxAt - _mtproxyAttemptStartedAt)
			: std::nullopt,
		.serverHelloMs = (_serverHelloAt && _mtproxyAttemptStartedAt)
			? std::make_optional(_serverHelloAt - _mtproxyAttemptStartedAt)
			: std::nullopt,
		.appDataMs = (_firstAppDataAt && _mtproxyAttemptStartedAt)
			? std::make_optional(_firstAppDataAt - _mtproxyAttemptStartedAt)
			: std::nullopt,
		.livenessReported = _mtproxyAttempt.traceId
			&& !_runtime->proxyEndpointContext().traceActive(
				_mtproxyAttempt.traceId),
	};
}

QString TlsSocket::responseClass() const {
	return FakeTlsResponseClass(_responsePrefix, _rxAfterClientHello);
}

QString TlsSocket::blockToken() const {
	// Only meaningful for the ambiguous "ClientHello sent, no ServerHello"
	// stall - other phases have unambiguous reasons of their own. The peer
	// actively ending the connection (FIN or a network-level reset) is what
	// separates an on-path reset from our own local timeout on silence.
	const auto peerClosed = (_closeOrigin == ProxyCloseOrigin::PeerClosed)
		|| (_closeOrigin == ProxyCloseOrigin::NetworkError);
	const auto evidence = MtProxy::HandshakeBlockEvidence{
		.isNoServerHelloStall = (_phase == HandshakePhase::ClientHelloSent)
			&& (failureReason()
				== MtProxy::FailureReason::ClientHelloSentNoServerHello),
		.clientHelloBytes = _clientHelloBytes,
		.clientHelloAcceptedBytes = _clientHelloAcceptedBytes,
		.rxAfterClientHello = _rxAfterClientHello,
		.responsePrefix = _responsePrefix,
		.peerClosed = peerClosed,
	};
	return MtProxy::HandshakeBlockToken(
		MtProxy::AnalyzeHandshakeBlock(evidence),
		evidence);
}

QString TlsSocket::responseRecordType() const {
	if (_responsePrefix.isEmpty()) {
		return QString();
	}
	switch (uchar(_responsePrefix[0])) {
	case 0x14: return u"change_cipher_spec"_q;
	case 0x15: return u"alert"_q;
	case 0x16: return u"handshake"_q;
	case 0x17: return u"application_data"_q;
	}
	return u"unknown"_q;
}

QString TlsSocket::responseRecordVersion() const {
	if (_responsePrefix.size() < 3) {
		return QString();
	}
	return u"0x%1%2"_q
		.arg(uchar(_responsePrefix[1]), 2, 16, QChar('0'))
		.arg(uchar(_responsePrefix[2]), 2, 16, QChar('0'));
}

std::optional<int> TlsSocket::responseRecordLength() const {
	if (_responsePrefix.size() < 5) {
		return std::nullopt;
	}
	return (int(uchar(_responsePrefix[3])) << 8)
		| int(uchar(_responsePrefix[4]));
}

QString TlsSocket::responsePrefixHash() const {
	if (_responsePrefix.isEmpty()) {
		return QString();
	}
	const auto hash = QCryptographicHash::hash(
		_responsePrefix,
		QCryptographicHash::Sha256);
	return QString::fromLatin1(hash.toHex().left(16));
}

void TlsSocket::noteIncoming(const QByteArray &data) {
	if (data.isEmpty()) {
		return;
	}
	if (!_firstRxAt) {
		_firstRxAt = crl::now();
	}
	_rxAfterClientHello += data.size();
	const auto left = 16 - _responsePrefix.size();
	if (left > 0) {
		_responsePrefix.append(data.constData(), std::min(left, data.size()));
	}
}

void TlsSocket::reportTransportEvent(
		ProxyDiagnosticsPhase phase,
		ProxyDiagnosticsSeverity severity,
		const QString &message) {
	const auto now = crl::now();
	const auto domain = domainFromSecret();
	const auto domainBytes = QByteArray(
		reinterpret_cast<const char*>(domain.data()),
		int(domain.size()));
	const auto domainHash = QCryptographicHash::hash(
		domainBytes,
		QCryptographicHash::Sha256);
	const auto clientHelloKnown = _clientHelloBytes > 0;
	auto attempt = _mtproxyAttempt;
	if (attempt.connectionId.isEmpty()) {
		attempt.connectionId = _debugId;
	}
	ReportProxyEvent(_runtime, {
		.phase = phase,
		.error = (severity == ProxyDiagnosticsSeverity::Error)
			? MtProxy::ToProxyConnectionError(failureReason())
			: ProxyConnectionError::None,
		.mtproxyReason = (severity == ProxyDiagnosticsSeverity::Error)
			? MtProxy::ToProxyMtproxyTerminalReason(failureReason())
			: ProxyMtproxyTerminalReason::None,
		.attempt = attempt,
		.severity = severity,
		.proxy = _proxy,
		.transport = ProxyDiagnosticsTransportName(
			ProxyData::Type::Mtproto,
			_stealth.transport),
		.connectionId = _debugId,
		.message = message,
		.canonical = ProxyDiagnosticsEndpointText(
			_endpointId.canonical.originalHost,
			_endpointId.canonical.port),
		.route = ProxyDiagnosticsEndpointText(
			_endpointId.route.address,
			_endpointId.route.port),
		.proxyKeyHash = ProxyDiagnosticsKeyHash(
			MtProxy::EndpointKey(_endpointId.canonical)),
		.profile = clientHelloKnown
			? ProxyDiagnosticsTlsProfileName(_sentTlsProfile)
			: QString(),
		.configuredProfile = ProxyDiagnosticsTlsProfileName(
			_configuredTlsProfile),
		.effectiveProfile = ProxyDiagnosticsTlsProfileName(_tlsProfile),
		.recipeLevel = _mtproxyPlan.admitted
			? std::make_optional(_mtproxyPlan.recipeLevel)
			: std::nullopt,
		.pskOffered = clientHelloKnown
			? std::make_optional(_syntheticPskOffered)
			: std::nullopt,
		.fragmentedClientHello = clientHelloKnown
			? std::make_optional(_clientHelloFragmented)
			: std::nullopt,
		.phaseAtFailure = (severity == ProxyDiagnosticsSeverity::Error)
			? proxyTransportFailure().parserStage
			: QString(),
		.clientHelloBytes = clientHelloKnown
			? std::make_optional(_clientHelloBytes)
			: std::nullopt,
		.clientHelloWrites = clientHelloKnown
			? std::make_optional(_clientHelloWrites)
			: std::nullopt,
		.clientHelloAcceptedBytes = clientHelloKnown
			? std::make_optional(_clientHelloAcceptedBytes)
			: std::nullopt,
		.clientHelloFragmentSplit = _clientHelloFragmented
			? std::make_optional(_clientHelloFragmentSplit)
			: std::nullopt,
		.clientHelloFragmentDelayMs = _clientHelloFragmented
			? std::make_optional(_clientHelloFragmentDelayMs)
			: std::nullopt,
		.rxAfterClientHello = clientHelloKnown
			? std::make_optional(_rxAfterClientHello)
			: std::nullopt,
		.rxClass = clientHelloKnown ? responseClass() : QString(),
		.block = (severity == ProxyDiagnosticsSeverity::Error)
			? blockToken()
			: QString(),
		.tlsRecordType = _rxAfterClientHello
			? responseRecordType()
			: QString(),
		.tlsRecordVersion = _rxAfterClientHello
			? responseRecordVersion()
			: QString(),
		.tlsRecordLength = _rxAfterClientHello
			? responseRecordLength()
			: std::nullopt,
		.responsePrefixHash = _rxAfterClientHello
			? responsePrefixHash()
			: QString(),
		.sniLength = clientHelloKnown
			? std::make_optional(int(domain.size()))
			: std::nullopt,
		.sniHash = clientHelloKnown
			? QString::fromLatin1(domainHash.toHex().left(16))
			: QString(),
		.parserStage = proxyTransportFailure().parserStage,
		.closeOrigin = (_closeOrigin == ProxyCloseOrigin::None)
			? std::optional<ProxyCloseOrigin>()
			: std::make_optional(_closeOrigin),
		.tcpMs = (_tcpConnectedAt && _mtproxyAttemptStartedAt)
			? std::make_optional(_tcpConnectedAt - _mtproxyAttemptStartedAt)
			: std::nullopt,
		.firstRxMs = (_firstRxAt && _mtproxyAttemptStartedAt)
			? std::make_optional(_firstRxAt - _mtproxyAttemptStartedAt)
			: std::nullopt,
		.serverHelloMs = (_serverHelloAt && _mtproxyAttemptStartedAt)
			? std::make_optional(_serverHelloAt - _mtproxyAttemptStartedAt)
			: std::nullopt,
		.appDataMs = (_firstAppDataAt && _mtproxyAttemptStartedAt)
			? std::make_optional(_firstAppDataAt - _mtproxyAttemptStartedAt)
			: std::nullopt,
		.totalMs = _mtproxyAttemptStartedAt
			? std::make_optional(now - _mtproxyAttemptStartedAt)
			: std::nullopt,
		.traceSchema = 2,
	});
}

} // namespace MTP::details
