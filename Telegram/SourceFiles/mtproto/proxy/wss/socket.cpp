/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "mtproto/proxy/wss/socket.h"

#include "mtproto/protocol/mtproto_binary.h"
#include "base/bytes.h"
#include "base/invoke_queued.h"

#include <crl/crl_time.h>

#include <cstring>
#include <algorithm>
#include <map>

#include <QtCore/QCryptographicHash>
#include <QtCore/QMutex>

namespace MTP::details {
namespace {

constexpr auto kWssMaxFrame = 2 * 1024 * 1024;
constexpr auto kWssHeaderLimit = 32 * 1024;

// How long to remember that only the fallback (domain) relay host works.
constexpr auto kRelayFallbackPreferenceTtl = 30 * 60 * crl::time(1000);

// Which relay host actually works is remembered across sockets: a blocked
// primary relay IP would otherwise be retried first by EVERY new socket,
// and the session-level connect watchdog (1s on the first attempt) kills
// the socket before errorOccurred fires, so the in-socket fallback never
// gets a chance and each reconnect repeats the dead-host dance.
struct RelayPreference {
	bool preferFallback = false;
	crl::time until = 0;
};

QMutex RelayPreferencesMutex;
std::map<QString, RelayPreference> RelayPreferences;

[[nodiscard]] QString RelayPreferenceKey(const WssRoute &route) {
	return route.relayHost + u":"_q + QString::number(route.relayPort);
}

[[nodiscard]] bool HasRelayFallback(const WssRoute &route) {
	return !route.relayHostFallback.isEmpty()
		&& (route.relayHostFallback != route.relayHost);
}

[[nodiscard]] bool PreferRelayFallback(const WssRoute &route) {
	if (!HasRelayFallback(route)) {
		return false;
	}
	QMutexLocker lock(&RelayPreferencesMutex);
	const auto i = RelayPreferences.find(RelayPreferenceKey(route));
	return (i != end(RelayPreferences))
		&& i->second.preferFallback
		&& (i->second.until > crl::now());
}

// Отдельный от выбора адреса учёт: у датацентра может не открываться ни один
// адрес релея — у части провайдеров порт 443 к нему закрыт целиком, по обоим
// протоколам. Держать такой датацентр в вечных попытках бессмысленно: медиа
// оттуда не загрузится никогда, хотя прямое соединение может работать. После
// нескольких неудач подряд, ни одна из которых не дошла даже до TCP, маршрут
// WSS для этого датацентра отключается, и фабрика сокетов создаёт обычный TCP.
constexpr auto kRouteFailuresBeforeSuppress = 3;
constexpr auto kRouteSuppressTtl = 10 * 60 * crl::time(1000);

struct RouteHealth {
	int consecutiveFailures = 0;
	crl::time suppressedUntil = 0;
};

std::map<QString, RouteHealth> RouteHealthByDomain;

[[nodiscard]] bool RouteSuppressed(const QString &domain) {
	QMutexLocker lock(&RelayPreferencesMutex);
	const auto i = RouteHealthByDomain.find(domain);
	if (i == end(RouteHealthByDomain) || !i->second.suppressedUntil) {
		return false;
	} else if (i->second.suppressedUntil <= crl::now()) {
		i->second = RouteHealth();
		return false;
	}
	return true;
}

void NoteRouteUnreachable(const WssRoute &route) {
	QMutexLocker lock(&RelayPreferencesMutex);
	auto &health = RouteHealthByDomain[route.domain];
	if (health.suppressedUntil > crl::now()) {
		return;
	} else if (++health.consecutiveFailures >= kRouteFailuresBeforeSuppress) {
		health.suppressedUntil = crl::now() + kRouteSuppressTtl;
	}
}

void NoteRouteReachable(const WssRoute &route) {
	QMutexLocker lock(&RelayPreferencesMutex);
	RouteHealthByDomain[route.domain] = RouteHealth();
}

void NoteRelayAttemptFailed(const WssRoute &route, bool viaFallback) {
	if (!HasRelayFallback(route)) {
		return;
	}
	QMutexLocker lock(&RelayPreferencesMutex);
	if (viaFallback) {
		RelayPreferences.erase(RelayPreferenceKey(route));
	} else {
		RelayPreferences[RelayPreferenceKey(route)] = {
			.preferFallback = true,
			.until = crl::now() + kRelayFallbackPreferenceTtl,
		};
	}
}

void NoteRelayUpgraded(const WssRoute &route, bool viaFallback) {
	if (!HasRelayFallback(route)) {
		return;
	}
	QMutexLocker lock(&RelayPreferencesMutex);
	if (viaFallback) {
		RelayPreferences[RelayPreferenceKey(route)] = {
			.preferFallback = true,
			.until = crl::now() + kRelayFallbackPreferenceTtl,
		};
	} else {
		RelayPreferences.erase(RelayPreferenceKey(route));
	}
}

[[nodiscard]] QByteArray RandomBytes(int count) {
	auto result = QByteArray(count, char(0));
	bytes::set_random(bytes::make_detached_span(result));
	return result;
}

[[nodiscard]] QString OfficialRelayIngress(int dcId) {
	// Each ingress serves only its own datacenters; they are not
	// interchangeable. Verified against live relays on 2026-08-08: all three
	// accept the upgrade and carry real MTProto, including the media (-1)
	// hostnames.
	switch (dcId) {
	case 1:
	case 3: return u"149.154.174.100"_q;
	case 2:
	case 4: return u"149.154.167.220"_q;
	case 5: return u"149.154.170.100"_q;
	}
	return QString();
}

[[nodiscard]] std::optional<WssRoute> OfficialRoute(int16 protocolDcId) {
	const auto raw = int(protocolDcId);
	const auto positive = (raw < 0) ? -raw : raw;
	if (positive >= kTestModeDcIdShift) {
		return std::nullopt; // test-mode DCs have no public web relay
	}
	const auto ingress = OfficialRelayIngress(positive);
	if (ingress.isEmpty()) {
		return std::nullopt; // CDN and unknown ids have no public web relay
	}
	auto route = WssRoute();
	route.relayHost = ingress;
	route.relayPort = 443;
	route.path = u"/apiws"_q;
	const auto name = u"kws%1"_q.arg(positive);
	// A file lane can bootstrap a regular key first. Route by the protocol
	// DC sign, not by its large-buffer/file-lane classification, otherwise a
	// positive DC id reaches a media-only relay and is rejected with -444.
	route.domain = (raw < 0)
		? (name + u"-1.web.telegram.org"_q)
		: (name + u".web.telegram.org"_q);
	// Fallback: if the hardcoded relay IP is unreachable, retry once via the
	// domain so DNS yields a currently-valid address.
	route.relayHostFallback = route.domain;
	return route;
}

} // namespace

std::optional<WssRoute> WssOfficialRoute(int16 protocolDcId) {
	auto route = OfficialRoute(protocolDcId);
	if (!route) {
		return std::nullopt;
	}
	if (RouteSuppressed(route->domain)) {
		// Релей этого датацентра недоступен; пусть соединение идёт напрямую.
		return std::nullopt;
	}
	return route;
}

std::optional<WssRoute> WssCustomRoute(const ProxyStealthOptions &stealth) {
	if (stealth.wssCustomHost.isEmpty()) {
		return std::nullopt;
	}
	auto route = WssRoute();
	route.relayHost = stealth.wssCustomHost;
	route.relayPort = (stealth.wssCustomPort > 0 && stealth.wssCustomPort <= 65535)
		? stealth.wssCustomPort
		: 443;
	route.path = stealth.wssCustomPath.isEmpty()
		? u"/apiws"_q
		: stealth.wssCustomPath;
	route.domain = stealth.wssCustomDomain.isEmpty()
		? stealth.wssCustomHost
		: stealth.wssCustomDomain;
	if (route.domain != route.relayHost) {
		route.relayHostFallback = route.domain;
	}
	return route;
}

WssRouteDiagnostics WssRouteDiagnosticsForDc(
		const ProxyStealthOptions &stealth,
		int16 protocolDcId) {
	auto result = WssRouteDiagnostics();
	result.route = WssCustomRoute(stealth);
	result.custom = result.route.has_value();
	if (!result.route) {
		result.route = OfficialRoute(protocolDcId);
	}
	if (!result.route) {
		return result;
	}
	const auto &route = *result.route;
	result.prefersFallback = PreferRelayFallback(route);
	result.selectedRelayHost = result.prefersFallback
		? route.relayHostFallback
		: route.relayHost;
	if (result.custom) {
		return result;
	}
	result.suppressed = RouteSuppressed(route.domain);
	{
		QMutexLocker lock(&RelayPreferencesMutex);
		const auto i = RouteHealthByDomain.find(route.domain);
		if (i != end(RouteHealthByDomain)) {
			result.consecutiveFailures = i->second.consecutiveFailures;
			result.suppressedFor = std::max(
				i->second.suppressedUntil - crl::now(),
				crl::time(0));
		}
	}
	return result;
}

WssSocket::WssSocket(
	not_null<RuntimeEnvironment*> runtime,
	not_null<QThread*> thread,
	const QNetworkProxy &proxy,
	bool protocolForFiles,
	WssRoute route)
: AbstractSocket(runtime, thread)
, _route(std::move(route)) {
	_socket.moveToThread(thread);
	_socket.setProxy(proxy);
	_socket.setPeerVerifyMode(QSslSocket::VerifyPeer);
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
		&QSslSocket::encrypted,
		wrap([=] { onEncrypted(); }));
	connect(
		&_socket,
		&QSslSocket::disconnected,
		wrap([=] { _disconnected.fire({}); }));
	connect(
		&_socket,
		&QSslSocket::readyRead,
		wrap([=] { onReadyRead(); }));
	connect(
		&_socket,
		&QAbstractSocket::errorOccurred,
		wrap([=](Error e) { handleError(e); }));
}

void WssSocket::connectToHost(const QString &address, int port) {
	Q_UNUSED(address);
	Q_UNUSED(port);
	// MTProto-over-WSS always connects to the relay route; the DC
	// endpoint (address, port) is intentionally ignored - the relay routes
	// to the right data center based on the SNI / Host domain.
	_usedFallback = PreferRelayFallback(_route);
	connectToRelayHost();
}

void WssSocket::connectToRelayHost() {
	const auto host = _usedFallback ? _route.relayHostFallback : _route.relayHost;
	_socket.setPeerVerifyName(_route.domain);
	_socket.connectToHostEncrypted(
		host,
		quint16(_route.relayPort),
		_route.domain);
}

bool WssSocket::isGoodStartNonce(bytes::const_span nonce) {
	Expects(nonce.size() >= 2 * sizeof(uint32));

	const auto zero = binary::Read<uchar>(nonce);
	const auto first = binary::Read<uint32>(nonce);
	const auto second = binary::ReadAt<uint32>(nonce, sizeof(uint32));
	const auto reserved01 = 0x000000EFU;
	const auto reserved11 = 0x44414548U;
	const auto reserved12 = 0x54534F50U;
	const auto reserved13 = 0x20544547U;
	const auto reserved14 = 0xEEEEEEEEU;
	const auto reserved15 = 0xDDDDDDDDU;
	const auto reserved16 = 0x02010316U;
	const auto reserved21 = 0x00000000U;
	return (zero != reserved01)
		&& (first != reserved11)
		&& (first != reserved12)
		&& (first != reserved13)
		&& (first != reserved14)
		&& (first != reserved15)
		&& (first != reserved16)
		&& (second != reserved21);
}

void WssSocket::timedOut() {
	// The session watchdog is killing this socket before any socket error
	// arrived. Remember which relay host stalled so the next socket starts
	// from the other one instead of repeating the same dead-host attempt.
	if (!_upgraded && !_hostFlipped) {
		NoteRelayAttemptFailed(_route, _usedFallback);
	}
	if (!_upgraded && _phase == HandshakePhase::None) {
		// Не дошли даже до установленного TCP: адрес релея недоступен, а не
		// протокол сломан.
		NoteRouteUnreachable(_route);
	}
}

bool WssSocket::isConnected() {
	return _upgraded
		&& (_socket.state() == QAbstractSocket::ConnectedState);
}

bool WssSocket::hasBytesAvailable() {
	return !_readBuffer.isEmpty();
}

int64 WssSocket::read(bytes::span buffer) {
	const auto count = std::min(
		int64(buffer.size()),
		int64(_readBuffer.size()));
	if (count <= 0) {
		return 0;
	}
	binary::Copy(
		buffer,
		bytes::make_span(_readBuffer.constData(), count));
	_readBuffer.remove(0, int(count));
	return count;
}

void WssSocket::write(bytes::const_span prefix, bytes::const_span buffer) {
	Expects(!buffer.empty());

	// Frame boundaries are free EXCEPT for the very first binary frame after
	// the upgrade: the relay parses the 64-byte obfuscation header out of that
	// single frame's payload and never revisits the decision. A shorter first
	// frame is fatal and silent - the relay simply never answers, which looks
	// exactly like a network problem. Neither one TCP write nor real WebSocket
	// fragmentation helps; only the frame payload counts. Measured against the
	// live relays on 2026-08-08: 63 bytes never answered, 64 always did.
	// Combining the header with the first packet keeps that guarantee here.
	if (prefix.empty()) {
		sendFrame(0x2, buffer);
		return;
	}
	auto combined = bytes::vector(prefix.size() + buffer.size());
	auto combinedBytes = bytes::make_span(combined);
	binary::Copy(combinedBytes, prefix);
	binary::Copy(combinedBytes.subspan(prefix.size()), buffer);
	sendFrame(0x2, bytes::make_span(combined));
}

int32 WssSocket::debugState() {
	return _socket.state();
}

QString WssSocket::debugPostfix() const {
	return u"WS"_q;
}

HandshakePhase WssSocket::handshakePhase() const {
	return _phase;
}

QString WssSocket::transportName() const {
	return u"WSS"_q;
}

void WssSocket::handleError(int errorCode) {
	// On a connect/handshake failure, retry once via the other relay host
	// (hardcoded IP <-> domain) before giving up, so a blocked or stale
	// relay IP does not kill web-relay connectivity. The failure is recorded
	// so the next socket starts from the host that still may work.
	if (!_upgraded && !_hostFlipped && HasRelayFallback(_route)) {
		NoteRelayAttemptFailed(_route, _usedFallback);
		_hostFlipped = true;
		_usedFallback = !_usedFallback;
		_incoming = QByteArray();
		_phase = HandshakePhase::None;
		_socket.abort();
		connectToRelayHost();
		return;
	}
	if (!_upgraded && !_hostFlipped) {
		NoteRelayAttemptFailed(_route, _usedFallback);
	}
	logError(errorCode, _socket.errorString());
	_error.fire_copy(errorCode);
}

void WssSocket::onEncrypted() {
	_phase = HandshakePhase::TcpConnected;
	connectionProgress(_phase);
	sendHttpUpgrade();
	_phase = HandshakePhase::ClientHelloSent;
	connectionProgress(_phase);
}

void WssSocket::sendHttpUpgrade() {
	_secWebSocketKey = QString::fromLatin1(RandomBytes(16).toBase64());
	auto host = _route.domain;
	if (_route.relayPort != 443) {
		host += u":%1"_q.arg(_route.relayPort);
	}
	const auto request = (u"GET %1 HTTP/1.1\r\n"
		u"Host: %2\r\n"
		u"Upgrade: websocket\r\n"
		u"Connection: Upgrade\r\n"
		u"Sec-WebSocket-Key: %3\r\n"
		u"Sec-WebSocket-Version: 13\r\n"
		u"Sec-WebSocket-Protocol: binary\r\n"
		u"Origin: https://web.telegram.org\r\n"
		u"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
		u"AppleWebKit/537.36 (KHTML, like Gecko) "
		u"Chrome/131.0.0.0 Safari/537.36\r\n"
		u"\r\n"_q).arg(_route.path, host, _secWebSocketKey);
	const auto utf8 = request.toUtf8();
	_socket.write(utf8);
}

bool WssSocket::tryFinishUpgrade() {
	const auto end = _incoming.indexOf("\r\n\r\n");
	if (end < 0) {
		if (_incoming.size() > kWssHeaderLimit) {
			logError(0, u"WSS HTTP response too large"_q);
			_error.fire_copy(AbstractConnection::kErrorCodeOther);
		}
		return false;
	}
	const auto header = _incoming.left(end);
	_incoming.remove(0, end + 4);
	if (!header.contains(" 101 ") && !header.contains(" 101\r")) {
		logError(0, u"WSS HTTP upgrade rejected"_q);
		_error.fire_copy(AbstractConnection::kErrorCodeOther);
		return false;
	}
	if (!checkUpgradeAccept(header)) {
		logError(0, u"WSS Sec-WebSocket-Accept mismatch"_q);
		_error.fire_copy(AbstractConnection::kErrorCodeOther);
		return false;
	}
	_upgraded = true;
	NoteRouteReachable(_route);
	NoteRelayUpgraded(_route, _usedFallback);
	_phase = HandshakePhase::ServerHelloOk;
	connectionProgress(_phase);
	_connected.fire({});
	return true;
}

bool WssSocket::checkUpgradeAccept(const QByteArray &header) const {
	const auto expected = QCryptographicHash::hash(
		_secWebSocketKey.toLatin1()
			+ QByteArrayLiteral("258EAFA5-E914-47DA-95CA-C5AB0DC85B11"),
		QCryptographicHash::Sha1).toBase64();
	const auto lowered = header.toLower();
	const auto marker = QByteArrayLiteral("sec-websocket-accept:");
	const auto pos = lowered.indexOf(marker);
	if (pos < 0) {
		return false;
	}
	auto valueEnd = header.indexOf('\n', pos);
	if (valueEnd < 0) {
		valueEnd = header.size();
	}
	const auto from = pos + marker.size();
	const auto value = header.mid(from, valueEnd - from).trimmed();
	return (value == expected);
}

void WssSocket::onReadyRead() {
	_incoming += _socket.readAll();
	if (!_upgraded && !tryFinishUpgrade()) {
		return;
	}
	if (_upgraded) {
		parseFrames();
	}
}

void WssSocket::parseFrames() {
	auto produced = false;
	auto offset = 0;
	const auto total = int(_incoming.size());
	const auto data = bytes::make_span(_incoming.constData(), total);
	const auto byteAt = [&](int index) {
		return gsl::to_integer<quint8>(data[index]);
	};
	while (total - offset >= 2) {
		const auto opcode = (byteAt(offset) & 0x0f);
		const auto masked = ((byteAt(offset + 1) & 0x80) != 0);
		auto length = quint64(byteAt(offset + 1) & 0x7f);
		auto headerLen = 2;
		if (length == 126) {
			if (total - offset < 4) {
				break;
			}
			length = (quint64(byteAt(offset + 2)) << 8)
				| quint64(byteAt(offset + 3));
			headerLen = 4;
		} else if (length == 127) {
			if (total - offset < 10) {
				break;
			}
			length = 0;
			for (auto i = 0; i != 8; ++i) {
				length = (length << 8) | quint64(byteAt(offset + 2 + i));
			}
			headerLen = 10;
		}
		if (length > kWssMaxFrame) {
			logError(0, u"WSS frame too large"_q);
			_error.fire_copy(AbstractConnection::kErrorCodeOther);
			return;
		}
		const auto maskLen = masked ? 4 : 0;
		const auto frameLen = quint64(headerLen) + maskLen + length;
		if (quint64(total - offset) < frameLen) {
			break;
		}
		const auto mask = data.subspan(offset + headerLen, maskLen);
		const auto payload = data.subspan(
			offset + headerLen + maskLen,
			int(length));
		if (opcode == 0x8) { // close
			logError(0, u"WSS close frame received"_q);
			_error.fire_copy(AbstractConnection::kErrorCodeOther);
			return;
		} else if (opcode == 0x9) { // ping -> pong
			sendFrame(0xA, payload);
		} else if (opcode == 0x0 || opcode == 0x1 || opcode == 0x2) {
			if (length > 0) {
				const auto at = int(_readBuffer.size());
				const auto count = int(length);
				_readBuffer.resize(at + count);
				auto out = bytes::make_detached_span(_readBuffer).subspan(at);
				if (masked) {
					for (auto i = 0; i != count; ++i) {
						out[i] = bytes::type(
							byteAt(offset + headerLen + maskLen + i)
							^ gsl::to_integer<quint8>(mask[i % 4]));
					}
				} else {
					binary::Copy(out, payload);
				}
				produced = true;
			}
		}
		offset += int(frameLen);
	}
	if (offset > 0) {
		_incoming.remove(0, offset);
	}
	if (produced) {
		if (_phase == HandshakePhase::ServerHelloOk) {
			_phase = HandshakePhase::FirstDataReceived;
			connectionProgress(_phase);
		}
		_readyRead.fire({});
	}
}

void WssSocket::sendFrame(quint8 opcode, bytes::const_span data) {
	const auto size = int(data.size());
	auto frame = QByteArray();
	frame.reserve(size + 14);
	frame.append(char(0x80 | opcode));
	if (size < 126) {
		frame.append(char(0x80 | size));
	} else if (size <= 0xffff) {
		frame.append(char(0x80 | 126));
		frame.append(char((size >> 8) & 0xff));
		frame.append(char(size & 0xff));
	} else {
		frame.append(char(0x80 | 127));
		for (auto i = 7; i >= 0; --i) {
			frame.append(char((quint64(size) >> (i * 8)) & 0xff));
		}
	}
	const auto mask = RandomBytes(4);
	frame.append(mask);
	const auto maskBytes = bytes::make_span(mask);
	const auto base = int(frame.size());
	frame.resize(base + size);
	auto out = bytes::make_detached_span(frame).subspan(base);
	for (auto i = 0; i != size; ++i) {
		out[i] = bytes::type(
			gsl::to_integer<quint8>(data[i])
			^ gsl::to_integer<quint8>(maskBytes[i % 4]));
	}
	_socket.write(frame);
}

} // namespace MTP::details
