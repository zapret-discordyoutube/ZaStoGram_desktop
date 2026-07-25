/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "mtproto/proxy/mtproxy/tls_socket.h"

#include "mtproto/proxy/mtproxy/handshake_plan.h"

#include "base/algorithm.h"
#include "base/invoke_queued.h"
#include "base/openssl_help.h"
#include "mtproto/proxy/mtproxy/client_hello_builder.h"
#include "mtproto/proxy/mtproxy/client_hello_constants.h"
#include "mtproto/proxy/mtproxy/tls_socket_psk.h"
#include "mtproto/proxy/mtproxy/tls_socket_utils.h"
#include "mtproto/proxy/diagnostics.h"
#include "mtproto/proxy/proxy_services.h"
#include "mtproto/runtime/runtime_environment.h"

namespace MTP::details {
namespace {

const auto kServerHelloPart1 = qstr("\x16\x03\x03");
const auto kServerHelloPart3 = qstr("\x14\x03\x03\x00\x01\x01\x17\x03\x03");
constexpr auto kServerHelloDigestPosition = 11;
constexpr auto kMaxServerHelloLength = 65536;

} // namespace

void TlsSocket::writeClientHello(const QByteArray &data) {
	_clientHelloFragmentTimer.cancel();
	_clientHelloTail = QByteArray();
	_clientHelloBytes = data.size();
	_clientHelloFragmentSplit = 0;
	_clientHelloFragmentDelayMs = 0;
	const auto plan = PrepareClientHelloFragmentation(
		data,
		_clientHelloFragmentation);
	if (!plan) {
		writeClientHelloPart(data.constData(), data.size());
		finishClientHelloWrite();
		return;
	}
	_clientHelloFragmented = true;
	_clientHelloFragmentSplit = plan.firstSize;
	_clientHelloFragmentDelayMs = plan.secondDelay;
	writeClientHelloPart(data.constData(), plan.firstSize);
	_transport->flush();
	_clientHelloTail = data.mid(plan.firstSize);
	if (_clientHelloTail.isEmpty()) {
		finishClientHelloWrite();
		return;
	}
	if (plan.secondDelay > 0) {
		_clientHelloFragmentTimer.callOnce(plan.secondDelay);
	} else {
		writeClientHelloTail();
	}
}

void TlsSocket::writeClientHelloPart(const char *data, int size) {
	auto offset = 0;
	while (offset < size) {
		++_clientHelloWrites;
		const auto accepted = _transport->write(data + offset, size - offset);
		if (accepted <= 0) {
			break;
		}
		_clientHelloAcceptedBytes += accepted;
		offset += int(accepted);
	}
}

void TlsSocket::writeClientHelloTail() {
	const auto tail = base::take(_clientHelloTail);
	if (tail.isEmpty()) {
		return;
	}
	writeClientHelloPart(tail.constData(), tail.size());
	finishClientHelloWrite();
}

void TlsSocket::finishClientHelloWrite() {
	if (_terminal
		|| _phase != HandshakePhase::TcpConnected
		|| !_clientHelloTail.isEmpty()
		|| _clientHelloBytes <= 0
		|| _clientHelloAcceptedBytes != _clientHelloBytes) {
		return;
	}
	_phase = HandshakePhase::ClientHelloSent;
	armServerHelloDeadline();
	connectionProgress(_phase);
	reportTransportEvent(
		ProxyDiagnosticsPhase::ClientHelloSent,
		ProxyDiagnosticsSeverity::Info,
		u"mtproxy client hello queued locally"_q);
}

void TlsSocket::plainConnected() {
	if (_state != State::Connecting) {
		return;
	}
	_phase = HandshakePhase::TcpConnected;
	_tcpConnectedAt = crl::now();
	connectionProgress(_phase);
	reportTransportEvent(
		ProxyDiagnosticsPhase::TcpConnected,
		ProxyDiagnosticsSeverity::Info,
		u"mtproxy tcp connected"_q);

	const auto delay = ConnectionSpacing(_connectionPattern);
	if (delay > 0) {
		_clientHelloTimer.callOnce(delay);
	} else {
		sendClientHello();
	}
}

void TlsSocket::sendClientHello() {
	if (_state != State::Connecting) {
		return;
	}
	const auto profile = effectiveTlsProfile();
	_sentTlsProfile = profile;
	const auto rules = PrepareClientHelloRules(profile);
	auto pskOffer = std::optional<SyntheticPskOffer>();
	_clientHelloFragmented = false;
	if (_stealth.syntheticPsk) {
		pskOffer = _runtime->proxyServices().syntheticPsks().prepareOffer(
			MtProxy::EndpointKey(_endpointId.canonical),
			domainFromSecret(),
			profile);
	}
	_syntheticPskOffered = pskOffer.has_value();
	const auto hello = PrepareClientHello(
		rules,
		domainFromSecret(),
		keyFromSecret(),
		profile,
		std::move(pskOffer));
	if (hello.data.isEmpty()) {
		logError(888, "Could not generate Client Hello.");
		handleError(MtProxy::FailureReason::ProxyProtocolBadResponse);
	} else {
		_state = State::WaitingHello;
		_incoming = hello.digest;
		writeClientHello(hello.data);
	}
}

void TlsSocket::plainDisconnected() {
	_state = State::NotConnected;
	_incoming = QByteArray();
	_responsePrefix = QByteArray();
	_serverHelloLength = 0;
	_incomingGoodDataOffset = 0;
	_incomingGoodDataLimit = 0;
	_outgoing = QByteArray();
	_outgoingOffset = 0;
	_clientPrefixSent = false;
	_clientHelloTail = QByteArray();
	_failureReason = MtProxy::FailureReason::None;
	_connectionError = ProxyConnectionError::None;
	_syntheticPskOffered = false;
	_clientHelloFragmented = false;
	_clientHelloBytes = 0;
	_clientHelloWrites = 0;
	_clientHelloAcceptedBytes = 0;
	_clientHelloFragmentSplit = 0;
	_clientHelloFragmentDelayMs = 0;
	_rxAfterClientHello = 0;
	_tcpConnectedAt = 0;
	_firstRxAt = 0;
	_serverHelloAt = 0;
	_firstAppDataAt = 0;
	_closeOrigin = ProxyCloseOrigin::None;
	_firstAppDataReceived = false;
	_mtprotoPayloadReceived = false;
	_sentTlsProfile = ProxyTlsProfile::Auto;
	_phase = HandshakePhase::None;
	_pacingTimer.cancel();
	_clientHelloTimer.cancel();
	_clientHelloFragmentTimer.cancel();
	_serverHelloTimer.cancel();
	_serverHelloDeadline = 0;
	_disconnected.fire({});
}

void TlsSocket::plainReadyRead() {
	switch (_state) {
	case State::WaitingHello: return readHello();
	case State::Connected: return readData();
	}
}

bool TlsSocket::requiredHelloPartReady() const {
	return _incoming.size()
		>= kClientHelloDigestLength + _serverHelloLength;
}

void TlsSocket::readHello() {
	const auto parts1Size = kServerHelloPart1.size() + kTlsLengthFieldSize;
	if (!_serverHelloLength) {
		_serverHelloLength = parts1Size;
	}
	while (!requiredHelloPartReady()) {
		if (!_transport->bytesAvailable()) {
			return;
		}
		const auto received = _transport->readAll();
		noteIncoming(received);
		_incoming.append(received);
	}
	checkHelloParts12(parts1Size);
}

void TlsSocket::checkHelloParts12(int parts1Size) {
	const auto data = bytes::make_span(_incoming).subspan(
		kClientHelloDigestLength,
		parts1Size);
	const auto part2Size = ReadPartLength(
		data,
		parts1Size - kTlsLengthFieldSize);
	const auto parts123Size = parts1Size
		+ part2Size
		+ kServerHelloPart3.size()
		+ kTlsLengthFieldSize;
	if (parts123Size > kMaxServerHelloLength) {
		logError(888, "Bad Server Hello size.");
		handleError(MtProxy::FailureReason::ProxyProtocolBadResponse);
		return;
	}
	if (_serverHelloLength == parts1Size) {
		const auto part1Offset = parts1Size
			- kTlsLengthFieldSize
			- kServerHelloPart1.size();
		if (!CheckPart(data.subspan(part1Offset), kServerHelloPart1)) {
			logError(888, "Bad Server Hello part1.");
			handleError(IsTlsAlert(data.subspan(part1Offset))
				? MtProxy::FailureReason::TlsAlertAfterClientHello
				: MtProxy::FailureReason::ProxyProtocolBadResponse);
			return;
		}
		_serverHelloLength = parts123Size;
		if (!requiredHelloPartReady()) {
			readHello();
			return;
		}
	}
	checkHelloParts34(parts123Size);
}

void TlsSocket::checkHelloParts34(int parts123Size) {
	const auto data = bytes::make_span(_incoming).subspan(
		kClientHelloDigestLength,
		parts123Size);
	const auto part4Size = ReadPartLength(
		data,
		parts123Size - kTlsLengthFieldSize);
	const auto full = parts123Size + part4Size;
	if (full > kMaxServerHelloLength) {
		logError(888, "Bad Server Hello size.");
		handleError(MtProxy::FailureReason::ProxyProtocolBadResponse);
		return;
	}
	if (_serverHelloLength == parts123Size) {
		const auto part3Offset = parts123Size
			- kTlsLengthFieldSize
			- kServerHelloPart3.size();
		if (!CheckPart(data.subspan(part3Offset), kServerHelloPart3)) {
			logError(888, "Bad Server Hello part.");
			handleError(
				MtProxy::FailureReason::ProxyProtocolBadResponse);
			return;
		}
		_serverHelloLength = full;
		if (!requiredHelloPartReady()) {
			readHello();
			return;
		}
	}
	checkHelloDigest();
}

void TlsSocket::checkHelloDigest() {
	if (_serverHelloLength
		< kServerHelloDigestPosition + kClientHelloDigestLength) {
		logError(888, "Bad Server Hello length.");
		handleError(MtProxy::FailureReason::ProxyProtocolBadResponse);
		return;
	}
	const auto fulldata = bytes::make_detached_span(_incoming).subspan(
		0,
		kClientHelloDigestLength + _serverHelloLength);
	const auto digest = fulldata.subspan(
		kClientHelloDigestLength + kServerHelloDigestPosition,
		kClientHelloDigestLength);
	const auto digestCopy = bytes::make_vector(digest);
	bytes::set_with_const(digest, bytes::type(0));
	const auto check = openssl::HmacSha256(keyFromSecret(), fulldata);
	if (bytes::compare(digestCopy, check) != 0) {
		logError(888, "Bad Server Hello digest.");
		handleError(MtProxy::FailureReason::ServerHelloHmacMismatch);
		return;
	}
	shiftIncomingBy(fulldata.size());
	if (!_incoming.isEmpty()) {
		InvokeQueued(this, [=] {
			if (!checkNextPacket()) {
				handleError();
			}
		});
	}
	_incomingGoodDataOffset = _incomingGoodDataLimit = 0;
	_serverHelloTimer.cancel();
	_serverHelloDeadline = 0;
	_state = State::Connected;
	_phase = HandshakePhase::ServerHelloOk;
	_serverHelloAt = crl::now();
	connectionProgress(_phase);
	reportTransportEvent(
		ProxyDiagnosticsPhase::ServerHelloOk,
		ProxyDiagnosticsSeverity::Info,
		u"mtproxy server hello hmac verified"_q);
	if (_startupCover != StartupCover::Off) {
		_startupCoverStartedAt = crl::now();
		_startupCoverFrames = 0;
	}
	_connected.fire({});
}

} // namespace MTP::details
