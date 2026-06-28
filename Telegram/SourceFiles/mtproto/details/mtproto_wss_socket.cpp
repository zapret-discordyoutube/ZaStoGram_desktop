/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "mtproto/details/mtproto_wss_socket.h"

#include "base/bytes.h"
#include "base/invoke_queued.h"

#include <cstring>
#include <algorithm>

namespace MTP::details {
namespace {

constexpr auto kTestModeDcIdShift = 10000;
constexpr auto kWssMaxFrame = 2 * 1024 * 1024;
constexpr auto kWssHeaderLimit = 32 * 1024;

[[nodiscard]] QByteArray RandomBytes(int count) {
	auto result = QByteArray(count, char(0));
	bytes::set_random(bytes::make_span(
		reinterpret_cast<bytes::type*>(result.data()),
		count));
	return result;
}

} // namespace

std::optional<WssRoute> WssOfficialRoute(int16 protocolDcId, bool media) {
	const auto raw = int(protocolDcId);
	const auto positive = (raw < 0) ? -raw : raw;
	if (positive >= kTestModeDcIdShift) {
		return std::nullopt; // test-mode DCs have no public web relay
	} else if (positive != 2 && positive != 4) {
		return std::nullopt; // web sockets exist only for DC2 / DC4
	}
	auto route = WssRoute();
	route.relayHost = u"149.154.167.220"_q;
	route.relayPort = 443;
	route.path = u"/apiws"_q;
	const auto name = (positive == 4) ? u"kws4"_q : u"kws2"_q;
	route.domain = media
		? (name + u"-1.web.telegram.org"_q)
		: (name + u".web.telegram.org"_q);
	return route;
}

WssSocket::WssSocket(
	not_null<QThread*> thread,
	const QNetworkProxy &proxy,
	bool protocolForFiles,
	WssRoute route)
: AbstractSocket(thread)
, _route(std::move(route)) {
	_socket.moveToThread(thread);
	_socket.setProxy(proxy);
	_socket.setPeerVerifyMode(QSslSocket::VerifyNone);
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
	// MTProto-over-WSS always connects to Telegram's web relay; the DC
	// endpoint (address, port) is intentionally ignored - the relay routes
	// to the right data center based on the SNI / Host domain.
	_socket.connectToHostEncrypted(
		_route.relayHost,
		quint16(_route.relayPort),
		_route.domain);
}

bool WssSocket::isGoodStartNonce(bytes::const_span nonce) {
	Expects(nonce.size() >= 2 * sizeof(uint32));

	const auto data = nonce.data();
	const auto zero = *reinterpret_cast<const uchar*>(data);
	const auto first = *reinterpret_cast<const uint32*>(data);
	const auto second = *(reinterpret_cast<const uint32*>(data) + 1);
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
	memcpy(buffer.data(), _readBuffer.constData(), count);
	_readBuffer.remove(0, int(count));
	return count;
}

void WssSocket::write(bytes::const_span prefix, bytes::const_span buffer) {
	Expects(!buffer.empty());

	if (prefix.empty()) {
		sendFrame(
			0x2,
			reinterpret_cast<const char*>(buffer.data()),
			int(buffer.size()));
		return;
	}
	auto combined = QByteArray();
	combined.reserve(int(prefix.size() + buffer.size()));
	combined.append(
		reinterpret_cast<const char*>(prefix.data()),
		int(prefix.size()));
	combined.append(
		reinterpret_cast<const char*>(buffer.data()),
		int(buffer.size()));
	sendFrame(0x2, combined.constData(), int(combined.size()));
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

void WssSocket::handleError(int errorCode) {
	logError(errorCode, _socket.errorString());
	_error.fire({});
}

void WssSocket::onEncrypted() {
	_phase = HandshakePhase::TcpConnected;
	sendHttpUpgrade();
	_phase = HandshakePhase::ClientHelloSent;
}

void WssSocket::sendHttpUpgrade() {
	const auto key = QString::fromLatin1(RandomBytes(16).toBase64());
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
		u"\r\n"_q).arg(_route.path, host, key);
	const auto utf8 = request.toUtf8();
	_socket.write(utf8);
}

bool WssSocket::tryFinishUpgrade() {
	const auto end = _incoming.indexOf("\r\n\r\n");
	if (end < 0) {
		if (_incoming.size() > kWssHeaderLimit) {
			logError(0, u"WSS HTTP response too large"_q);
			_error.fire({});
		}
		return false;
	}
	const auto header = _incoming.left(end);
	_incoming.remove(0, end + 4);
	if (!header.contains(" 101 ") && !header.contains(" 101\r")) {
		logError(0, u"WSS HTTP upgrade rejected"_q);
		_error.fire({});
		return false;
	}
	_upgraded = true;
	_phase = HandshakePhase::ServerHelloOk;
	_connected.fire({});
	return true;
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
	const auto data = reinterpret_cast<const uchar*>(_incoming.constData());
	const auto total = int(_incoming.size());
	while (total - offset >= 2) {
		const auto p = data + offset;
		const auto opcode = (p[0] & 0x0f);
		const auto masked = ((p[1] & 0x80) != 0);
		auto length = quint64(p[1] & 0x7f);
		auto headerLen = 2;
		if (length == 126) {
			if (total - offset < 4) {
				break;
			}
			length = (quint64(p[2]) << 8) | quint64(p[3]);
			headerLen = 4;
		} else if (length == 127) {
			if (total - offset < 10) {
				break;
			}
			length = 0;
			for (auto i = 0; i != 8; ++i) {
				length = (length << 8) | quint64(p[2 + i]);
			}
			headerLen = 10;
		}
		if (length > kWssMaxFrame) {
			logError(0, u"WSS frame too large"_q);
			_error.fire({});
			return;
		}
		const auto maskLen = masked ? 4 : 0;
		const auto frameLen = quint64(headerLen) + maskLen + length;
		if (quint64(total - offset) < frameLen) {
			break;
		}
		const auto mask = p + headerLen;
		const auto payload = p + headerLen + maskLen;
		if (opcode == 0x8) { // close
			logError(0, u"WSS close frame received"_q);
			_error.fire({});
			return;
		} else if (opcode == 0x9) { // ping -> pong
			sendFrame(
				0xA,
				reinterpret_cast<const char*>(payload),
				int(length));
		} else if (opcode == 0x0 || opcode == 0x1 || opcode == 0x2) {
			if (length > 0) {
				const auto at = int(_readBuffer.size());
				_readBuffer.resize(at + int(length));
				const auto out = reinterpret_cast<uchar*>(
					_readBuffer.data()) + at;
				if (masked) {
					for (auto i = quint64(0); i != length; ++i) {
						out[i] = payload[i] ^ mask[i % 4];
					}
				} else {
					memcpy(out, payload, int(length));
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
		}
		_readyRead.fire({});
	}
}

void WssSocket::sendFrame(quint8 opcode, const char *data, int size) {
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
	const auto maskPtr = reinterpret_cast<const uchar*>(mask.constData());
	const auto base = int(frame.size());
	frame.resize(base + size);
	const auto out = reinterpret_cast<uchar*>(frame.data()) + base;
	const auto in = reinterpret_cast<const uchar*>(data);
	for (auto i = 0; i != size; ++i) {
		out[i] = in[i] ^ maskPtr[i % 4];
	}
	_socket.write(frame);
}

} // namespace MTP::details
