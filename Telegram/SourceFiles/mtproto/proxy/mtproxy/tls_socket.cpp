/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "mtproto/proxy/mtproxy/tls_socket.h"

#include "base/algorithm.h"
#include "base/invoke_queued.h"
#include "base/unixtime.h"
#include "mtproto/proxy/mtproxy/tls_socket_psk.h"
#include "mtproto/proxy/diagnostics.h"
#include "mtproto/proxy/proxy_endpoint_context.h"
#include "mtproto/proxy/proxy_services.h"
#include "mtproto/runtime/runtime_environment.h"
#include "mtproto/transport/details/mtproto_tcp_socket.h"

namespace MTP::details {
namespace {

constexpr auto kEstablishedIdleCloseAge = crl::time(20 * 1000);

[[nodiscard]] MtProxyAttemptPlan NormalizeAttemptPlan(
		MtProxyAttemptPlan plan,
		const ProxyStealthOptions &fallback) {
	if (plan.admitted) {
		return plan;
	}
	plan.admitted = true;
	plan.recipeLevel = 0;
	plan.configuredTlsProfile = fallback.tlsProfile;
	plan.effectiveTlsProfile = ProxyTlsProfile::ChromeModern;
	plan.stealth = fallback;
	plan.stealth.level = ProxyStealthLevel::CompatStrict;
	plan.stealth.tlsProfile = plan.effectiveTlsProfile;
	plan.stealth.clientHelloFragmentation
		= ProxyClientHelloFragmentation::Off;
	plan.stealth.connectionPattern = ProxyConnectionPattern::Off;
	plan.stealth.recordSizing = ProxyRecordSizing::Off;
	plan.stealth.timing = ProxyTiming::Off;
	plan.stealth.startupCover = ProxyStartupCover::Off;
	plan.stealth.syntheticPsk = false;
	return plan;
}

} // namespace

TlsSocket::TlsSocket(
	not_null<RuntimeEnvironment*> runtime,
	not_null<QThread*> thread,
	const bytes::vector &secret,
	const ProxyData &proxy,
	bool protocolForFiles,
	const ProxyStealthOptions &stealth,
	ProxyConnectionAttempt mtproxyAttempt,
	MtProxyAttemptPlan mtproxyPlan,
	crl::time mtproxyAttemptStartedAt,
	std::unique_ptr<TlsSocketTransport> transport)
: AbstractSocket(runtime, thread)
, _secret(secret)
, _proxy(proxy)
, _endpointId(MtProxy::EndpointIdFromProxy(proxy, stealth))
, _endpointKey(MtProxy::EndpointKey(_endpointId.canonical))
, _mtproxyAttempt(mtproxyAttempt)
, _mtproxyPlan(NormalizeAttemptPlan(std::move(mtproxyPlan), stealth))
, _mtproxyAttemptStartedAt(mtproxyAttemptStartedAt)
, _transport(
		transport
			? std::move(transport)
			: CreateTlsSocketTransport()) {
	Expects(_secret.size() >= 21 && _secret[0] == bytes::type(0xEE));
	if (!_mtproxyAttemptStartedAt) {
		_mtproxyAttemptStartedAt = crl::now();
	}

	const auto &planned = _mtproxyPlan.stealth;
	_recordSizing = RecordSizing(int(planned.recordSizing));
	_startupCover = StartupCover(int(planned.startupCover));
	_clientHelloFragmentation = planned.clientHelloFragmentation;
	_connectionPattern = planned.connectionPattern;
	_tlsProfile = _mtproxyPlan.effectiveTlsProfile;
	_configuredTlsProfile = _mtproxyPlan.configuredTlsProfile;
	_timing = planned.timing;
	_stealth = planned;
	_endpointUse = _mtproxyAttempt.use;
	_pacingTimer = runtime->async().makeTimer(thread, [=] { sendOutgoing(); });
	_clientHelloTimer = runtime->async().makeTimer(
		thread,
		[=] { sendClientHello(); });
	_clientHelloFragmentTimer = runtime->async().makeTimer(
		thread,
		[=] { writeClientHelloTail(); });

	_transport->moveToThread(thread);
	_transport->setProxy(ToNetworkProxy(proxy));
	if (protocolForFiles) {
		_transport->setSocketOption(
			QAbstractSocket::SendBufferSizeSocketOption,
			kFilesSendBufferSize);
		_transport->setSocketOption(
			QAbstractSocket::ReceiveBufferSizeSocketOption,
			kFilesReceiveBufferSize);
	}
	const auto wrap = [&](auto handler) {
		return [=](auto &&...args) {
			InvokeQueued(this, [=] { handler(args...); });
		};
	};
	_transport->setCallbacks({
		.connected = wrap([=] { plainConnected(); }),
		.disconnected = wrap([=] { plainDisconnected(); }),
		.readyRead = wrap([=] { plainReadyRead(); }),
		.error = wrap([=](QAbstractSocket::SocketError e) {
			handleError(e);
		}),
	});
}

bytes::const_span TlsSocket::domainFromSecret() const {
	return bytes::make_span(_secret).subspan(17);
}

bytes::const_span TlsSocket::keyFromSecret() const {
	return bytes::make_span(_secret).subspan(1, 16);
}

ProxyTlsProfile TlsSocket::effectiveTlsProfile() const {
	return _tlsProfile;
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
		return (_clientHelloAcceptedBytes > 0)
			? MtProxy::FailureReason::ClientHelloSentNoServerHello
			: MtProxy::FailureReason::TcpConnectedNoClientHelloWrite;
	case HandshakePhase::ServerHelloOk:
		return MtProxy::FailureReason::ServerHelloOkNoAppData;
	case HandshakePhase::FirstDataReceived:
		break;
	}
	return MtProxy::FailureReason::None;
}

bool TlsSocket::clearSyntheticPskOnFailure(MtProxy::FailureReason reason) {
	if (!_syntheticPskOffered || IsProxyCheck(_endpointUse)) {
		return false;
	}
	switch (reason) {
	case MtProxy::FailureReason::ClientHelloSentNoServerHello:
	case MtProxy::FailureReason::TlsAlertAfterClientHello:
	case MtProxy::FailureReason::ServerHelloHmacMismatch:
		_runtime->proxyServices().syntheticPsks().clear(
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
	_transport->connectToHost(address, port);
}

bool TlsSocket::isGoodStartNonce(bytes::const_span nonce) {
	return true;
}

void TlsSocket::timedOut() {
	_syncTimeRequests.fire({});
	if (_state == State::Error) {
		return;
	}
	auto reason = failureReason();
	if (reason == MtProxy::FailureReason::None
		&& _phase == HandshakePhase::FirstDataReceived) {
		reason = _mtprotoPayloadReceived
			? MtProxy::FailureReason::MtpReceiveTimeoutAfterData
			: MtProxy::FailureReason::ServerHelloOkNoMtprotoData;
	}
	_failureReason = reason;
	_connectionError = ProxyConnectionError::Timeout;
	_closeOrigin = ProxyCloseOrigin::LocalTimeout;
	clearSyntheticPskOnFailure(reason);
	_runtime->proxyServices().control().reportMtproxyFailure({
		.endpoint = _endpointId,
		.use = _endpointUse,
		.runtimeId = _mtproxyAttempt.runtimeId,
		.reason = reason,
		.configuredTlsProfile = _configuredTlsProfile,
		.sentProfile = _sentTlsProfile,
		.proxyGeneration = _mtproxyAttempt.proxyGeneration,
		.attemptId = _mtproxyAttempt.attemptId,
		.proxyEpoch = _mtproxyAttempt.proxyEpoch,
		.successEpoch = _mtproxyAttempt.successEpoch,
		.attemptStartedAt = _mtproxyAttemptStartedAt,
	});
	const auto terminalPhase = (_mtproxyAttempt.traceId
		&& !_runtime->proxyEndpointContext().traceActive(
			_mtproxyAttempt.traceId))
		? ProxyDiagnosticsPhase::Liveness
		: ProxyDiagnosticsPhase::Failed;
	reportTransportEvent(
		terminalPhase,
		ProxyDiagnosticsSeverity::Error,
		u"mtproxy transport timed out"_q);
	_state = State::Error;
}

bool TlsSocket::isConnected() {
	return (_state == State::Connected);
}

void TlsSocket::markProxyMtprotoPayloadReceived() {
	_mtprotoPayloadReceived = true;
}

int32 TlsSocket::debugState() {
	return _transport->state();
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
	return _runtime->proxyServices().control().mtproxyEndpointSnapshot(
		_endpointId).terminalUntil;
}

void TlsSocket::handleError(MtProxy::FailureReason reason, int errorCode) {
	_failureReason = reason;
	_closeOrigin = ProxyCloseOrigin::ProtocolRejected;
	handleError(errorCode);
}

void TlsSocket::handleError(int errorCode) {
	if (_phase == HandshakePhase::None) {
		_connectionError = SocketProxyConnectionError(errorCode);
	}
	if (_closeOrigin == ProxyCloseOrigin::None) {
		_closeOrigin = (errorCode == QAbstractSocket::RemoteHostClosedError
			|| errorCode == QAbstractSocket::ProxyConnectionClosedError)
			? ProxyCloseOrigin::PeerClosed
			: ProxyCloseOrigin::NetworkError;
	}
	auto reason = failureReason();
	if (reason == MtProxy::FailureReason::None && _firstAppDataReceived) {
		reason = _mtprotoPayloadReceived
			? MtProxy::FailureReason::AppDataRemoteClosed
			: MtProxy::FailureReason::ServerHelloOkNoMtprotoData;
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
		_runtime->proxyServices().control().reportMtproxyFailure({
			.endpoint = _endpointId,
			.use = _endpointUse,
			.runtimeId = _mtproxyAttempt.runtimeId,
			.reason = reason,
			.configuredTlsProfile = _configuredTlsProfile,
			.sentProfile = _sentTlsProfile,
			.proxyGeneration = _mtproxyAttempt.proxyGeneration,
			.attemptId = _mtproxyAttempt.attemptId,
			.proxyEpoch = _mtproxyAttempt.proxyEpoch,
			.successEpoch = _mtproxyAttempt.successEpoch,
			.attemptStartedAt = _mtproxyAttemptStartedAt,
		});
	}
	if (errorCode != AbstractConnection::kErrorCodeOther) {
		logError(errorCode, _transport->errorString());
	}
	const auto terminalPhase = (_mtproxyAttempt.traceId
		&& !_runtime->proxyEndpointContext().traceActive(
			_mtproxyAttempt.traceId))
		? ProxyDiagnosticsPhase::Liveness
		: ProxyDiagnosticsPhase::Failed;
	reportTransportEvent(
		terminalPhase,
		ProxyDiagnosticsSeverity::Error,
		u"mtproxy transport failed"_q);
	_state = State::Error;
	_error.fire_copy(errorCode);
}

} // namespace MTP::details
