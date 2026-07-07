/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "mtproto/proxy/mtproxy/tls_socket.h"

#include "mtproto/proxy/mtproxy/tls_socket_psk.h"
#include "mtproto/transport/details/mtproto_tcp_socket.h"
#include "mtproto/proxy/control_plane.h"
#include "mtproto/proxy/diagnostics.h"
#include "mtproto/proxy/mtproxy/adaptive_policy.h"
#include "base/algorithm.h"
#include "base/invoke_queued.h"
#include "base/unixtime.h"



namespace MTP::details {
namespace {

constexpr auto kEstablishedIdleCloseAge = crl::time(20 * 1000);

} // namespace

TlsSocket::TlsSocket(
	not_null<QThread*> thread,
	const bytes::vector &secret,
	const ProxyData &proxy,
	bool protocolForFiles,
	const ProxyStealthOptions &stealth,
	ProxyConnectionAttempt mtproxyAttempt,
	crl::time mtproxyAttemptStartedAt)
	: AbstractSocket(thread)
	, _secret(secret)
	, _endpointId(MtProxy::EndpointIdFromProxy(proxy, stealth))
	, _endpointKey(MtProxy::EndpointKey(_endpointId.canonical))
	, _mtproxyAttempt(mtproxyAttempt)
	, _mtproxyAttemptStartedAt(mtproxyAttemptStartedAt) {
	Expects(_secret.size() >= 21 && _secret[0] == bytes::type(0xEE));

	_recordSizing = RecordSizing(int(stealth.recordSizing));
	_startupCover = StartupCover(int(stealth.startupCover));
	_clientHelloFragmentation = stealth.clientHelloFragmentation;
	_connectionPattern = stealth.connectionPattern;
	_tlsProfile = stealth.tlsProfile;
	_timing = stealth.timing;
	_stealth = stealth;
	_endpointUse = protocolForFiles
		? MtProxy::EndpointUse::Media
		: MtProxy::EndpointUse::Main;
	_pacingTimer.setCallback([=] { sendOutgoing(); });
	_clientHelloTimer.setCallback([=] { sendClientHello(); });
	_clientHelloFragmentTimer.setCallback([=] { writeClientHelloTail(); });

	_socket.moveToThread(thread);
	_socket.setProxy(ToNetworkProxy(proxy));
	if (protocolForFiles) {
		_socket.setSocketOption(
			QAbstractSocket::SendBufferSizeSocketOption,
			kFilesSendBufferSize);
		_socket.setSocketOption(
			QAbstractSocket::ReceiveBufferSizeSocketOption,
			kFilesReceiveBufferSize);
	}
	const auto wrap = [&](auto handler) {
		return [=](auto &&...args) {
			InvokeQueued(this, [=] { handler(args...); });
		};
	};
	using Error = QAbstractSocket::SocketError;
	connect(
		&_socket,
		&QTcpSocket::connected,
		wrap([=] { plainConnected(); }));
	connect(
		&_socket,
		&QTcpSocket::disconnected,
		wrap([=] { plainDisconnected(); }));
	connect(
		&_socket,
		&QTcpSocket::readyRead,
		wrap([=] { plainReadyRead(); }));
	connect(
		&_socket,
		&QAbstractSocket::errorOccurred,
		wrap([=](Error e) { handleError(e); }));
}

bytes::const_span TlsSocket::domainFromSecret() const {
	return bytes::make_span(_secret).subspan(17);
}

bytes::const_span TlsSocket::keyFromSecret() const {
	return bytes::make_span(_secret).subspan(1, 16);
}

ProxyTlsProfile TlsSocket::effectiveTlsProfile() const {
	if (_usePreparedTlsProfile) {
		return _preparedTlsProfile;
	}
	return ResolveEffectiveTlsProfile(_tlsProfile, _endpointKey);
}

MtProxy::FailureReason TlsSocket::failureReason() const {
	if (_failureReason != MtProxy::FailureReason::None) {
		return _failureReason;
	}
	switch (_phase) {
	case HandshakePhase::None:
		return MtProxy::FailureReason::TcpConnectTimeout;
	case HandshakePhase::TcpConnected:
		return MtProxy::FailureReason::TcpConnectedNoClientHelloWrite;
	case HandshakePhase::ClientHelloSent:
		return MtProxy::FailureReason::ClientHelloSentNoServerHello;
	case HandshakePhase::ServerHelloOk:
		return MtProxy::FailureReason::ServerHelloOkNoAppData;
	case HandshakePhase::FirstDataReceived:
		break;
	}
	return MtProxy::FailureReason::None;
}

bool TlsSocket::clearSyntheticPskOnFailure(MtProxy::FailureReason reason) {
	if (!_syntheticPskOffered) {
		return false;
	}
	switch (reason) {
	case MtProxy::FailureReason::ClientHelloSentNoServerHello:
	case MtProxy::FailureReason::TlsAlertAfterClientHello:
	case MtProxy::FailureReason::ServerHelloHmacMismatch:
		ClearSyntheticPskTickets(
			MtProxy::EndpointKey(_endpointId.canonical),
			domainFromSecret(),
			_sentTlsProfile);
		_syntheticPskOffered = false;
		return true;
	case MtProxy::FailureReason::None:
	case MtProxy::FailureReason::DnsFailed:
	case MtProxy::FailureReason::TcpConnectTimeout:
	case MtProxy::FailureReason::TcpConnectedNoClientHelloWrite:
	case MtProxy::FailureReason::AppDataRemoteClosed:
	case MtProxy::FailureReason::ConnectedNoMtprotoData:
	case MtProxy::FailureReason::ServerHelloOkNoMtprotoData:
	case MtProxy::FailureReason::MtpReceiveTimeoutAfterData:
	case MtProxy::FailureReason::Network:
	case MtProxy::FailureReason::ProxyProtocolBadResponse:
		break;
	}
	return false;
}

void TlsSocket::connectToHost(const QString &address, int port) {
	Expects(_state == State::NotConnected);

	_state = State::Connecting;
	_endpointId.route = MtProxy::RouteEndpointFromAddress(
		address,
		port,
		_stealth.transport,
		_endpointId.canonical.originalHost);
	_socket.connectToHost(address, port);
}

bool TlsSocket::isGoodStartNonce(bytes::const_span nonce) {
	return true;
}

void TlsSocket::timedOut() {
	_syncTimeRequests.fire({});
	if (_state == State::Error) {
		return;
	}
	const auto reason = failureReason();
	_failureReason = reason;
	clearSyntheticPskOnFailure(reason);
	ProxyControlPlane::ReportMtproxyFailure({
		.endpoint = _endpointId,
		.use = _endpointUse,
		.reason = reason,
		.configuredTlsProfile = _tlsProfile,
		.sentProfile = _sentTlsProfile,
		.proxyGeneration = _mtproxyAttempt.proxyGeneration,
		.attemptId = _mtproxyAttempt.attemptId,
		.proxyEpoch = _mtproxyAttempt.proxyEpoch,
		.successEpoch = _mtproxyAttempt.successEpoch,
		.attemptStartedAt = _mtproxyAttemptStartedAt,
	});
	_state = State::Error;
}

bool TlsSocket::isConnected() {
	return (_state == State::Connected);
}

int32 TlsSocket::debugState() {
	return _socket.state();
}

QString TlsSocket::debugPostfix() const {
	return u"_ee"_q;
}

HandshakePhase TlsSocket::handshakePhase() const {
	return _phase;
}

ProxyMtproxyTerminalReason TlsSocket::mtproxyTerminalReason() const {
	return MtProxy::ToProxyMtproxyTerminalReason(failureReason());
}

crl::time TlsSocket::mtproxyTerminalUntil() const {
	return ProxyControlPlane::MtproxyEndpointSnapshot(
		_endpointId).terminalUntil;
}

void TlsSocket::handleError(MtProxy::FailureReason reason, int errorCode) {
	_failureReason = reason;
	handleError(errorCode);
}

void TlsSocket::handleError(int errorCode) {
	auto reason = failureReason();
	if (reason == MtProxy::FailureReason::None && _firstAppDataReceived) {
		reason = MtProxy::FailureReason::AppDataRemoteClosed;
	}
	_failureReason = reason;
	// Proxies routinely close idle established connections (observed
	// about once a minute per idle media session). A remote close of a
	// connection that lived past the handshake for a while is server-side
	// housekeeping, not a health signal - reporting each one degraded the
	// canonical endpoint every minute and marked healthy routes unhealthy
	// all session long. A close shortly after the handshake is different:
	// that looks like a relay kill and must still count.
	const auto benignIdleClose = (reason
			== MtProxy::FailureReason::AppDataRemoteClosed)
		&& _firstAppDataAt
		&& (crl::now() - _firstAppDataAt >= kEstablishedIdleCloseAge);
	if (!benignIdleClose) {
		clearSyntheticPskOnFailure(reason);
	}
	if (!benignIdleClose
		&& (_state != State::Connected
			|| reason == MtProxy::FailureReason::ServerHelloOkNoAppData
			|| reason == MtProxy::FailureReason::AppDataRemoteClosed)) {
		_syncTimeRequests.fire({});
		ProxyControlPlane::ReportMtproxyFailure({
			.endpoint = _endpointId,
			.use = _endpointUse,
			.reason = reason,
			.configuredTlsProfile = _tlsProfile,
			.sentProfile = _sentTlsProfile,
				.proxyGeneration = _mtproxyAttempt.proxyGeneration,
				.attemptId = _mtproxyAttempt.attemptId,
				.proxyEpoch = _mtproxyAttempt.proxyEpoch,
				.successEpoch = _mtproxyAttempt.successEpoch,
				.attemptStartedAt = _mtproxyAttemptStartedAt,
			});
	}
	if (errorCode != AbstractConnection::kErrorCodeOther) {
		logError(errorCode, _socket.errorString());
	}
	_state = State::Error;
	_error.fire_copy(errorCode);
}

} // namespace MTP::details
