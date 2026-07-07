/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "mtproto/proxy/mtproxy/tls_socket.h"

#include "mtproto/proxy/mtproxy/client_hello_builder.h"
#include "mtproto/proxy/mtproxy/client_hello_constants.h"
#include "mtproto/proxy/mtproxy/tls_socket_psk.h"
#include "mtproto/proxy/mtproxy/tls_socket_utils.h"
#include "mtproto/proxy/control_plane.h"
#include "mtproto/proxy/diagnostics.h"
#include "mtproto/proxy/mtproxy/adaptive_policy.h"
#include "base/algorithm.h"
#include "base/invoke_queued.h"
#include "base/openssl_help.h"

namespace MTP::details {
namespace {

const auto kServerHelloPart1 = qstr("\x16\x03\x03");
const auto kServerHelloPart3 = qstr("\x14\x03\x03\x00\x01\x01\x17\x03\x03");
constexpr auto kServerHelloDigestPosition = 11;

[[nodiscard]] QString HandshakePhaseText(HandshakePhase phase) {
	switch (phase) {
	case HandshakePhase::None:
		return u"tcp_not_connected"_q;
	case HandshakePhase::TcpConnected:
		return u"tcp_connected"_q;
	case HandshakePhase::ClientHelloSent:
		return u"client_hello_sent_no_server_hello"_q;
	case HandshakePhase::ServerHelloOk:
		return u"server_hello_ok_no_appdata"_q;
	case HandshakePhase::FirstDataReceived:
		return u"appdata_remote_closed"_q;
	}
	return u"unknown"_q;
}

[[nodiscard]] QString CanonicalText(const MtProxy::EndpointId &endpoint) {
	return ProxyDiagnosticsEndpointText(
		endpoint.canonical.originalHost,
		endpoint.canonical.port);
}

[[nodiscard]] QString RouteText(const MtProxy::EndpointId &endpoint) {
	return ProxyDiagnosticsEndpointText(
		endpoint.route.address,
		endpoint.route.port);
}


} // namespace

void TlsSocket::applyAdaptiveRecipe() {
	const auto snapshot = ProxyControlPlane::MtproxyEndpointSnapshot(
		_endpointId);
	if (!snapshot.recipeLevel) {
		return;
	}
	auto input = AdaptiveRecipeInput();
	input.endpointKey = _endpointKey;
	input.recipeLevel = snapshot.recipeLevel;
	input.lastDiagnostic = snapshot.lastDiagnostic;
	input.configuredTlsProfile = _tlsProfile;
	input.effectiveTlsProfile = effectiveTlsProfile();
	input.stealth = _stealth;
	const auto recipe = ApplyAdaptiveRecipe(input);
	if (!recipe.changed) {
		return;
	}
	_recordSizing = RecordSizing(int(recipe.stealth.recordSizing));
	_startupCover = StartupCover(int(recipe.stealth.startupCover));
	_clientHelloFragmentation = recipe.stealth.clientHelloFragmentation;
	_connectionPattern = recipe.stealth.connectionPattern;
	if (recipe.stealth.tlsProfile != input.effectiveTlsProfile) {
		_preparedTlsProfile = recipe.stealth.tlsProfile;
		_usePreparedTlsProfile = true;
	}
	_timing = recipe.stealth.timing;
	_stealth = recipe.stealth;
	WriteProxyDiagnosticsLine({
		.source = ProxyDiagnosticsSource::MTProxy,
		.phase = ProxyDiagnosticsPhase::StealthRecipeApplied,
		.severity = ProxyDiagnosticsSeverity::Info,
		.transport = ProxyDiagnosticsTransportName(
			ProxyData::Type::Mtproto,
			_stealth.transport),
		.message = u"mtproxy stealth recipe applied"_q,
		.canonical = CanonicalText(_endpointId),
		.route = RouteText(_endpointId),
		.proxyKeyHash = ProxyDiagnosticsKeyHash(
			MtProxy::EndpointKey(_endpointId.canonical)),
		.profile = ProxyDiagnosticsTlsProfileName(
			_usePreparedTlsProfile
				? _preparedTlsProfile
				: input.effectiveTlsProfile),
		.recipeLevel = snapshot.recipeLevel,
		.pskOffered = _syntheticPskOffered,
		.pskOfferedKnown = true,
		.fragmentedClientHello = _clientHelloFragmented,
		.fragmentedClientHelloKnown = true,
		.phaseAtFailure = input.lastDiagnostic.isEmpty()
			? HandshakePhaseText(_phase)
			: input.lastDiagnostic,
	});
}

void TlsSocket::writeClientHello(const QByteArray &data) {
	_clientHelloFragmentTimer.cancel();
	_clientHelloTail = QByteArray();
	const auto plan = PrepareClientHelloFragmentation(
		data,
		_clientHelloFragmentation);
	if (!plan) {
		_socket.write(data);
		return;
	}
	_clientHelloFragmented = true;
	_socket.write(data.constData(), plan.firstSize);
	_socket.flush();
	_clientHelloTail = data.mid(plan.firstSize);
	if (plan.secondDelay > 0) {
		_clientHelloFragmentTimer.callOnce(plan.secondDelay);
	} else {
		writeClientHelloTail();
	}
}

void TlsSocket::writeClientHelloTail() {
	const auto tail = base::take(_clientHelloTail);
	if (tail.isEmpty()) {
		return;
	}
	_socket.write(
		tail.constData(),
		tail.size());
}

void TlsSocket::plainConnected() {
	if (_state != State::Connecting) {
		return;
	}
	_phase = HandshakePhase::TcpConnected;
	connectionProgress(_phase);

	applyAdaptiveRecipe();
	const auto delay = MtProxy::ConnectionSpacing(_connectionPattern);
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
	const auto profile = _usePreparedTlsProfile
		? _preparedTlsProfile
		: effectiveTlsProfile();
	_usePreparedTlsProfile = false;
	_sentTlsProfile = profile;
	const auto rules = PrepareClientHelloRules(profile);
	auto pskOffer = std::optional<SyntheticPskOffer>();
	_clientHelloFragmented = false;
	if (_stealth.syntheticPsk) {
		pskOffer = PrepareSyntheticPskOffer(
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
		_phase = HandshakePhase::ClientHelloSent;
		connectionProgress(_phase);
	}
}

void TlsSocket::plainDisconnected() {
	_state = State::NotConnected;
	_incoming = QByteArray();
	_serverHelloLength = 0;
	_incomingGoodDataOffset = 0;
	_incomingGoodDataLimit = 0;
	_outgoing = QByteArray();
	_outgoingOffset = 0;
	_clientPrefixSent = false;
	_usePreparedTlsProfile = false;
	_clientHelloTail = QByteArray();
	_failureReason = MtProxy::FailureReason::None;
	_syntheticPskOffered = false;
	_clientHelloFragmented = false;
	_firstAppDataReceived = false;
	_pacingTimer.cancel();
	_clientHelloTimer.cancel();
	_clientHelloFragmentTimer.cancel();
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
		if (!_socket.bytesAvailable()) {
			return;
		}
		_incoming.append(_socket.readAll());
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
	_state = State::Connected;
	_phase = HandshakePhase::ServerHelloOk;
	connectionProgress(_phase);
	if (_startupCover != StartupCover::Off) {
		_startupCoverStartedAt = crl::now();
		_startupCoverFrames = 0;
	}
	_connected.fire({});
}

} // namespace MTP::details
