/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "mtproto/proxy/mtproxy/tls_socket.h"

#include "mtproto/protocol/mtproto_binary.h"
#include "mtproto/proxy/mtproxy/client_hello_builder.h"
#include "mtproto/transport/details/mtproto_tcp_socket.h"
#include "mtproto/proxy/control_plane.h"
#include "mtproto/proxy/diagnostics.h"
#include "mtproto/proxy/mtproxy/adaptive_policy.h"
#include "base/algorithm.h"
#include "base/openssl_help.h"
#include "base/bytes.h"
#include "base/invoke_queued.h"
#include "base/random.h"
#include "base/unixtime.h"

#include <QtCore/QMutex>
#include <QtCore/QtEndian>

#include <map>
#include <optional>

namespace MTP::details {
namespace {

constexpr auto kHelloDigestLength = 32;
constexpr auto kLengthSize = sizeof(uint16);
const auto kServerHelloPart1 = qstr("\x16\x03\x03");
const auto kServerHelloPart3 = qstr("\x14\x03\x03\x00\x01\x01\x17\x03\x03");
constexpr auto kServerHelloDigestPosition = 11;
const auto kServerHeader = qstr("\x17\x03\x03");
constexpr auto kClientPartSize = 2878;
const auto kClientPrefix = qstr("\x14\x03\x03\x00\x01\x01");
const auto kClientHeader = qstr("\x17\x03\x03");
constexpr auto kStartupCoverSoftWindow = crl::time(12000);
constexpr auto kStartupCoverStrictWindow = crl::time(20000);
constexpr auto kStartupCoverSoftFrames = 8;
constexpr auto kStartupCoverStrictFrames = 14;
constexpr auto kRecordSizeMin = 256;
constexpr auto kMaxPacedFrames = 24;
constexpr auto kSyntheticPskPoolSize = 3;
constexpr auto kSyntheticPskMinLifetime = crl::time(2 * 60 * 60 * 1000);
constexpr auto kSyntheticPskMaxLifetime = crl::time(8 * 60 * 60 * 1000);
constexpr auto kEstablishedIdleCloseAge = crl::time(20 * 1000);

struct SyntheticPskTicket {
	bytes::vector identity;
	uint32 ticketAgeAdd = 0;
	crl::time issuedAt = 0;
	crl::time expiresAt = 0;
	int binderLength = 0;
};

struct SyntheticPskCacheEntry {
	std::vector<SyntheticPskTicket> tickets;
	int nextIndex = 0;
};

QMutex SyntheticPskCacheMutex;
std::map<QString, SyntheticPskCacheEntry> SyntheticPskCache;

[[nodiscard]] uint32 RandomUint32() {
	auto result = uint32();
	bytes::set_random(bytes::object_as_span(&result));
	return result;
}

[[nodiscard]] QString SyntheticPskCacheKey(
		const QString &endpointKey,
		bytes::const_span domain,
		ProxyTlsProfile profile) {
	return endpointKey
		+ u"|"_q
		+ QString::number(int(profile))
		+ u"|"_q
		+ QString::fromLatin1(QByteArray(
			reinterpret_cast<const char*>(domain.data()),
			int(domain.size())).toHex());
}

[[nodiscard]] SyntheticPskTicket MakeSyntheticPskTicket(crl::time now) {
	const auto identityLengths = std::array{ 32, 105, 256 };
	const auto binderLengths = std::array{ 32, 48 };
	const auto identityLength = identityLengths[
		base::RandomIndex(identityLengths.size())];
	const auto binderLength = binderLengths[
		base::RandomIndex(binderLengths.size())];
	const auto lifetimeRange = int(
		kSyntheticPskMaxLifetime - kSyntheticPskMinLifetime + 1);
	auto result = SyntheticPskTicket();
	result.identity.resize(identityLength);
	bytes::set_random(result.identity);
	result.ticketAgeAdd = RandomUint32();
	result.issuedAt = now;
	result.expiresAt = now
		+ kSyntheticPskMinLifetime
		+ base::RandomIndex(lifetimeRange);
	result.binderLength = binderLength;
	return result;
}

void DropExpiredSyntheticPskTickets(
		SyntheticPskCacheEntry &entry,
		crl::time now) {
	for (auto i = entry.tickets.begin(); i != entry.tickets.end();) {
		if (i->expiresAt <= now) {
			i = entry.tickets.erase(i);
		} else {
			++i;
		}
	}
	if (entry.tickets.empty()) {
		entry.nextIndex = 0;
	} else if (entry.nextIndex >= int(entry.tickets.size())) {
		entry.nextIndex = 0;
	}
}

[[nodiscard]] std::optional<SyntheticPskOffer> PrepareSyntheticPskOffer(
		const QString &endpointKey,
		bytes::const_span domain,
		ProxyTlsProfile profile) {
	if (endpointKey.isEmpty() || domain.empty()) {
		return std::nullopt;
	}
	const auto now = crl::now();
	const auto key = SyntheticPskCacheKey(endpointKey, domain, profile);
	QMutexLocker lock(&SyntheticPskCacheMutex);
	const auto i = SyntheticPskCache.find(key);
	if (i == end(SyntheticPskCache)) {
		return std::nullopt;
	}
	auto &entry = i->second;
	DropExpiredSyntheticPskTickets(entry, now);
	if (entry.tickets.empty()) {
		SyntheticPskCache.erase(i);
		return std::nullopt;
	}
	const auto index = entry.nextIndex;
	const auto ticket = entry.tickets[index];
	entry.tickets.erase(entry.tickets.begin() + index);
	if (entry.tickets.empty()) {
		SyntheticPskCache.erase(i);
	} else if (entry.nextIndex >= int(entry.tickets.size())) {
		entry.nextIndex = 0;
	}
	const auto age = std::max(crl::time(0), now - ticket.issuedAt);
	return SyntheticPskOffer{
		.identity = ticket.identity,
		.obfuscatedTicketAge = uint32(
			uint64(ticket.ticketAgeAdd) + uint64(age)),
		.binderLength = ticket.binderLength,
	};
}

void ClearSyntheticPskTickets(
		const QString &endpointKey,
		bytes::const_span domain,
		ProxyTlsProfile profile) {
	if (endpointKey.isEmpty() || domain.empty()) {
		return;
	}
	const auto key = SyntheticPskCacheKey(endpointKey, domain, profile);
	QMutexLocker lock(&SyntheticPskCacheMutex);
	SyntheticPskCache.erase(key);
}

void NoteSyntheticPskDataPathSuccess(
		const QString &endpointKey,
		bytes::const_span domain,
		ProxyTlsProfile profile) {
	if (endpointKey.isEmpty() || domain.empty()) {
		return;
	}
	const auto now = crl::now();
	const auto key = SyntheticPskCacheKey(endpointKey, domain, profile);
	QMutexLocker lock(&SyntheticPskCacheMutex);
	auto &entry = SyntheticPskCache[key];
	DropExpiredSyntheticPskTickets(entry, now);
	while (int(entry.tickets.size()) < kSyntheticPskPoolSize) {
		entry.tickets.push_back(MakeSyntheticPskTicket(now));
	}
	if (entry.nextIndex >= int(entry.tickets.size())) {
		entry.nextIndex = 0;
	}
}

[[nodiscard]] bool CheckPart(bytes::const_span data, QLatin1String check) {
	if (data.size() < check.size()) {
		return false;
	}
	return !bytes::compare(
		data.subspan(0, check.size()),
		bytes::make_span(check.data(), check.size()));
}

[[nodiscard]] bool IsTlsAlert(bytes::const_span data) {
	return data.size() >= 2
		&& data[0] == bytes::type(0x15)
		&& data[1] == bytes::type(0x03);
}

[[nodiscard]] int ReadPartLength(bytes::const_span data, int offset) {
	const auto storage = data.subspan(offset, kLengthSize);
	return qFromBigEndian(binary::Read<uint16>(storage));
}

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
	return _incoming.size() >= kHelloDigestLength + _serverHelloLength;
}

void TlsSocket::readHello() {
	const auto parts1Size = kServerHelloPart1.size() + kLengthSize;
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
		kHelloDigestLength,
		parts1Size);
	const auto part2Size = ReadPartLength(data, parts1Size - kLengthSize);
	const auto parts123Size = parts1Size
		+ part2Size
		+ kServerHelloPart3.size()
		+ kLengthSize;
	if (_serverHelloLength == parts1Size) {
		const auto part1Offset = parts1Size
			- kLengthSize
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
		kHelloDigestLength,
		parts123Size);
	const auto part4Size = ReadPartLength(data, parts123Size - kLengthSize);
	const auto full = parts123Size + part4Size;
	if (_serverHelloLength == parts123Size) {
		const auto part3Offset = parts123Size
			- kLengthSize
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
		kHelloDigestLength + _serverHelloLength);
	const auto digest = fulldata.subspan(
		kHelloDigestLength + kServerHelloDigestPosition,
		kHelloDigestLength);
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

void TlsSocket::readData() {
	if (!isConnected()) {
		return;
	}
	_incoming.append(_socket.readAll());
	if (!checkNextPacket()) {
		handleError();
	} else if (hasBytesAvailable()) {
		_readyRead.fire({});
	}
}

bool TlsSocket::checkNextPacket() {
	auto offset = 0;
	const auto incoming = bytes::make_span(_incoming);
	while (!_incomingGoodDataLimit) {
		const auto fullHeader = kServerHeader.size() + kLengthSize;
		if (incoming.size() <= offset + fullHeader) {
			return true;
		}
		if (!CheckPart(incoming.subspan(offset), kServerHeader)) {
			logError(888, "Bad packet header.");
			return false;
		}
		const auto length = ReadPartLength(
			incoming,
			offset + kServerHeader.size());
		if (length > 0) {
			if (offset > 0) {
				shiftIncomingBy(offset);
			}
			_incomingGoodDataOffset = fullHeader;
			_incomingGoodDataLimit = length;
				if (!_firstAppDataReceived) {
					_firstAppDataReceived = true;
					_firstAppDataAt = crl::now();
					_phase = HandshakePhase::FirstDataReceived;
					connectionProgress(_phase);
					ProxyControlPlane::ReportMtproxySuccess({
						.endpoint = _endpointId,
						.use = _endpointUse,
						.stealth = _stealth,
						.sentProfile = _sentTlsProfile,
							.proxyGeneration = _mtproxyAttempt.proxyGeneration,
							.attemptId = _mtproxyAttempt.attemptId,
							.proxyEpoch = _mtproxyAttempt.proxyEpoch,
							.successEpoch = _mtproxyAttempt.successEpoch,
							.attemptStartedAt = _mtproxyAttemptStartedAt,
							.scope = MtProxy::SuccessScope::FakeTlsAppData,
						});
				NoteSyntheticPskDataPathSuccess(
					MtProxy::EndpointKey(_endpointId.canonical),
					domainFromSecret(),
					_sentTlsProfile);
			}
		} else {
			offset += kServerHeader.size() + kLengthSize + length;
		}
	}
	return true;
}

void TlsSocket::shiftIncomingBy(int amount) {
	Expects(_incomingGoodDataOffset == 0);
	Expects(_incomingGoodDataLimit == 0);

	const auto incoming = bytes::make_detached_span(_incoming);
	if (incoming.size() > amount) {
		bytes::move(incoming, incoming.subspan(amount));
		_incoming.chop(amount);
	} else {
		_incoming.clear();
	}
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

bool TlsSocket::hasBytesAvailable() {
	return (_incomingGoodDataLimit > 0)
		&& (_incomingGoodDataOffset < _incoming.size());
}

int64 TlsSocket::read(bytes::span buffer) {
	auto written = int64(0);
	while (_incomingGoodDataLimit) {
		const auto available = std::min(
			_incomingGoodDataLimit,
			int(_incoming.size()) - _incomingGoodDataOffset);
		if (available <= 0) {
			return written;
		}
		const auto write = std::min(std::size_t(available), buffer.size());
		if (write <= 0) {
			return written;
		}
		bytes::copy(
			buffer,
			bytes::make_span(_incoming).subspan(
				_incomingGoodDataOffset,
				write));
		written += write;
		buffer = buffer.subspan(write);
		_incomingGoodDataLimit -= write;
		_incomingGoodDataOffset += write;
		if (_incomingGoodDataLimit) {
			return written;
		}
		shiftIncomingBy(base::take(_incomingGoodDataOffset));
		if (!checkNextPacket()) {
			_state = State::Error;
			InvokeQueued(this, [=] { handleError(); });
			return written;
		}
	}
	return written;
}

TlsSocket::RecordSizing TlsSocket::effectiveRecordSizing() {
	if (!startupCoverActive()) {
		return _recordSizing;
	} else if (_startupCover == StartupCover::Strict) {
		return RecordSizing::Varied;
	}
	return (_recordSizing == RecordSizing::Off)
		? RecordSizing::Conservative
		: _recordSizing;
}

bool TlsSocket::startupCoverActive() {
	if (_startupCover == StartupCover::Off || !_startupCoverStartedAt) {
		return false;
	}
	const auto strict = (_startupCover == StartupCover::Strict);
	const auto window = strict
		? kStartupCoverStrictWindow
		: kStartupCoverSoftWindow;
	const auto maxFrames = strict
		? kStartupCoverStrictFrames
		: kStartupCoverSoftFrames;
	if (crl::now() - _startupCoverStartedAt > window
		|| _startupCoverFrames >= maxFrames) {
		_startupCoverStartedAt = 0;
		return false;
	}
	return true;
}

int TlsSocket::nextRecordPayloadSize() {
	const auto mode = effectiveRecordSizing();
	auto cap = int(kClientPartSize);
	if (mode == RecordSizing::Conservative) {
		static constexpr int kCaps[] = {
			1440, 1728, 2016, 2304, 2580, 2878,
		};
		cap = kCaps[base::RandomIndex(int(std::size(kCaps)))];
	} else if (mode == RecordSizing::Varied) {
		const auto minCap = _firstAppDataSent ? 768 : 1200;
		const auto maxCap = _firstAppDataSent ? 2878 : 2016;
		cap = minCap + base::RandomIndex(maxCap - minCap + 1);
	}
	return std::clamp(cap, kRecordSizeMin, int(kClientPartSize));
}

void TlsSocket::write(bytes::const_span prefix, bytes::const_span buffer) {
	Expects(!buffer.empty());

	if (!isConnected()) {
		return;
	}
	if (_timing == ProxyTiming::Off) {
		if (!prefix.empty()) {
			_socket.write(kClientPrefix.data(), kClientPrefix.size());
		}
		while (!buffer.empty()) {
			const auto cap = nextRecordPayloadSize();
			const auto write = std::min(
				cap - int(prefix.size()),
				int(buffer.size()));
			_socket.write(kClientHeader.data(), kClientHeader.size());
			const auto size = qToBigEndian(uint16(prefix.size() + write));
			_socket.write(reinterpret_cast<const char*>(&size), sizeof(size));
			if (!prefix.empty()) {
				_socket.write(
					reinterpret_cast<const char*>(prefix.data()),
					prefix.size());
				prefix = bytes::const_span();
			}
			_socket.write(
				reinterpret_cast<const char*>(buffer.data()),
				write);
			buffer = buffer.subspan(write);
			_firstAppDataSent = true;
			++_startupCoverFrames;
		}
		return;
	}
	if (!prefix.empty() && !_clientPrefixSent) {
		_socket.write(kClientPrefix.data(), kClientPrefix.size());
		_clientPrefixSent = true;
	}
	if (!prefix.empty()) {
		_outgoing.append(
			reinterpret_cast<const char*>(prefix.data()),
			prefix.size());
	}
	_outgoing.append(
		reinterpret_cast<const char*>(buffer.data()),
		buffer.size());
	if (!_pacingTimer.isActive()) {
		sendOutgoing();
	}
}

void TlsSocket::sendOutgoing() {
	while (_outgoingOffset < _outgoing.size()) {
		const auto cap = nextRecordPayloadSize();
		const auto available = int(_outgoing.size()) - _outgoingOffset;
		const auto take = std::min(cap, available);
		_socket.write(kClientHeader.data(), kClientHeader.size());
		const auto size = qToBigEndian(uint16(take));
		_socket.write(reinterpret_cast<const char*>(&size), sizeof(size));
		_socket.write(_outgoing.constData() + _outgoingOffset, take);
		_outgoingOffset += take;
		_firstAppDataSent = true;
		++_startupCoverFrames;
		if (_outgoingOffset < _outgoing.size()) {
			const auto delay = recordPacingDelay();
			if (delay > 0) {
				_socket.flush();
				_pacingTimer.callOnce(delay);
				return;
			}
		}
	}
	_outgoing.clear();
	_outgoingOffset = 0;
}

crl::time TlsSocket::recordPacingDelay() {
	if (_startupCoverFrames > kMaxPacedFrames) {
		return 0;
	}
	if (_timing == ProxyTiming::Gentle) {
		return 8 + base::RandomIndex(14) + base::RandomIndex(25);
	} else if (_timing == ProxyTiming::Balanced) {
		return 20 + base::RandomIndex(28) + base::RandomIndex(54);
	}
	return 0;
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
