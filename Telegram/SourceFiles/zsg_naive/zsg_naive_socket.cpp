/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "zsg_naive/zsg_naive_socket.h"

#include "base/invoke_queued.h"
#include "logs.h"
#include "mtproto/protocol/mtproto_binary.h"

#include <algorithm>

namespace Zsg::Naive {
namespace {

using namespace MTP::details;

constexpr auto kChunk = 16 * 1024;

} // namespace

NaiveSocket::NaiveSocket(
	not_null<MTP::RuntimeEnvironment*> runtime,
	not_null<QThread*> thread,
	const MTP::ProxyData &proxy,
	bool protocolForFiles)
: AbstractSocket(runtime, thread)
, _proxy(proxy) {
	_tcp.moveToThread(thread);
	_tcp.setProxy(QNetworkProxy::NoProxy);
	if (protocolForFiles) {
		_tcp.setSocketOption(
			QAbstractSocket::SendBufferSizeSocketOption,
			kFilesSendBufferSize);
		_tcp.setSocketOption(
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
		&_tcp,
		&QTcpSocket::connected,
		wrap([=] { onTcpConnected(); }));
	connect(
		&_tcp,
		&QTcpSocket::disconnected,
		wrap([=] {
			if (!_failed) {
				_disconnected.fire({});
			}
		}));
	connect(
		&_tcp,
		&QTcpSocket::readyRead,
		wrap([=] { onReadyRead(); }));
	connect(
		&_tcp,
		&QAbstractSocket::errorOccurred,
		wrap([=](Error e) {
			if (!_failed) {
				_failed = true;
				logError(e, _tcp.errorString());
				_error.fire_copy(e);
			}
		}));
}

NaiveSocket::~NaiveSocket() {
	releaseClient();
	_tcp.abort();
}

void NaiveSocket::releaseClient() {
	if (!_client) {
		return;
	}
	if (_tunnel) {
		_api->naiveCloseTunnel(_client, _tunnel);
		_tunnel = 0;
	}
	_api->naiveFree(_client);
	_client = nullptr;
}

void NaiveSocket::connectToHost(const QString &address, int port) {
	auto loadError = QString();
	_api = LoadApi(&loadError);
	if (!_api) {
		fail(loadError);
		return;
	}
	if (address.contains(':')) {
		// The Naive server reaches the data center over IPv4; a literal IPv6
		// address would only fail on the server side.
		fail(u"naive_ipv6_target"_q);
		return;
	}
	_host = _proxy.host.toUtf8();
	_user = _proxy.user.toUtf8();
	_password = _proxy.password.toUtf8();
	_target = address.toUtf8();

	const auto &trust = SystemTrust();
	const auto &identity = BrowserIdentity();
	auto config = NaiveConfig();
	config.host = _host.constData();
	config.port = uint16_t(_proxy.port ? _proxy.port : 443);
	config.user = _user.constData();
	config.password = _password.constData();
	config.extra_roots_pem = trust.pem.constData();
	config.extra_roots_der = trust.certs.data();
	config.extra_roots_der_count = trust.certs.size();
	config.user_agent = identity.userAgent;
	config.sec_ch_ua = identity.secChUa;
	config.sec_ch_ua_mobile = identity.secChUaMobile;
	config.sec_ch_ua_platform = identity.secChUaPlatform;
	config.send_preamble = 1;
	char error[256] = {};
	_client = _api->naiveNew(&config, error, sizeof(error));
	if (!_client) {
		fail(u"naive_client_create_failed: "_q
			+ QString::fromLatin1(error));
		return;
	}
	_tunnel = _api->naiveOpenTunnel(
		_client,
		_target.constData(),
		uint16_t(port));
	if (!_tunnel) {
		fail(u"naive_open_tunnel_failed"_q);
		return;
	}
	_tcp.connectToHost(_proxy.host, config.port);
}

bool NaiveSocket::isGoodStartNonce(bytes::const_span nonce) {
	Expects(nonce.size() >= 2 * sizeof(uint32));

	const auto zero = binary::Read<uchar>(nonce);
	const auto first = binary::Read<uint32>(nonce);
	const auto second = binary::ReadAt<uint32>(nonce, sizeof(uint32));
	return (zero != 0x000000EFU)
		&& (first != 0x44414548U)
		&& (first != 0x54534F50U)
		&& (first != 0x20544547U)
		&& (first != 0xEEEEEEEEU)
		&& (first != 0xDDDDDDDDU)
		&& (first != 0x02010316U)
		&& (second != 0x00000000U);
}

void NaiveSocket::timedOut() {
}

bool NaiveSocket::isConnected() {
	return _tunnelOpened
		&& (_tcp.state() == QAbstractSocket::ConnectedState);
}

bool NaiveSocket::hasBytesAvailable() {
	return !_readBuffer.isEmpty();
}

int64 NaiveSocket::read(bytes::span buffer) {
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

void NaiveSocket::write(bytes::const_span prefix, bytes::const_span buffer) {
	Expects(!buffer.empty());

	if (!_client || !_tunnel || _failed) {
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
	const auto size = size_t(combined.size());
	if (_api->naiveTunnelWrite(
			_client,
			_tunnel,
			reinterpret_cast<const uint8_t*>(combined.constData()),
			size) != size) {
		fail(u"naive_tunnel_write_failed"_q);
		return;
	}
	[[maybe_unused]] const auto alive = pump();
}

int32 NaiveSocket::debugState() {
	return _tcp.state();
}

QString NaiveSocket::debugPostfix() const {
	return u"NV"_q;
}

HandshakePhase NaiveSocket::handshakePhase() const {
	return _phase;
}

QString NaiveSocket::transportName() const {
	return u"Naive"_q;
}

void NaiveSocket::onTcpConnected() {
	if (_failed || !_client) {
		return;
	}
	_tcpConnected = true;
	// Nagle costs a round trip on the short request-then-wait writes mtproto
	// is made of.
	_tcp.setSocketOption(QAbstractSocket::LowDelayOption, 1);
	_phase = HandshakePhase::TcpConnected;
	connectionProgress(_phase);
	if (!pump()) {
		return;
	}
	if (_phase == HandshakePhase::TcpConnected) {
		_phase = HandshakePhase::ClientHelloSent;
		connectionProgress(_phase);
	}
}

void NaiveSocket::onReadyRead() {
	if (_failed || !_client) {
		return;
	}
	while (_tcp.bytesAvailable() > 0) {
		const auto data = _tcp.read(kChunk);
		if (data.isEmpty()) {
			break;
		}
		_api->naiveFeedNetwork(
			_client,
			reinterpret_cast<const uint8_t*>(data.constData()),
			size_t(data.size()));
	}
	[[maybe_unused]] const auto alive = pump();
}

bool NaiveSocket::pump() {
	if (_failed || !_client) {
		return false;
	}
	uint8_t chunk[kChunk];
	while (true) {
		const auto taken = _api->naiveTakeNetwork(
			_client,
			chunk,
			sizeof(chunk));
		if (!taken) {
			break;
		}
		_tcp.write(reinterpret_cast<const char*>(chunk), qint64(taken));
	}
	const auto state = _api->naiveState(_client);
	if (state == NaiveFailed || state == NaiveClosed) {
		const auto text = (state == NaiveFailed)
			? QString::fromLatin1(_api->naiveError(_client))
			: u"closed"_q;
		fail(u"naive_"_q + text);
		return false;
	}
	if (state >= NaivePreamble && _phase < HandshakePhase::ServerHelloOk) {
		_phase = HandshakePhase::ServerHelloOk;
		connectionProgress(_phase);
	}
	return drainTunnel();
}

bool NaiveSocket::drainTunnel() {
	const auto state = _api->naiveTunnelState(_client, _tunnel);
	if (state == TunnelFailed) {
		// e.g. 407 for wrong credentials, 502 for an unreachable target; a
		// probe-resistant server answers a wrong password like a web site
		// (308), which lands here too.
		fail(u"naive_tunnel_refused http=%1"_q.arg(
			_api->naiveTunnelHttpStatus(_client, _tunnel)));
		return false;
	}
	if (state == TunnelOpen && !_tunnelOpened) {
		_tunnelOpened = true;
		_connected.fire({});
		if (_failed || !_client) {
			return false;
		}
	}
	auto produced = false;
	uint8_t chunk[kChunk];
	while (true) {
		const auto got = _api->naiveTunnelRead(
			_client,
			_tunnel,
			chunk,
			sizeof(chunk));
		if (!got) {
			break;
		}
		_readBuffer.append(reinterpret_cast<const char*>(chunk), int(got));
		produced = true;
	}
	if (produced) {
		if (_phase < HandshakePhase::FirstDataReceived) {
			_phase = HandshakePhase::FirstDataReceived;
			connectionProgress(_phase);
		}
		_readyRead.fire({});
		if (_failed || !_client) {
			return false;
		}
	}
	if (state == TunnelOpen && _api->naiveTunnelEof(_client, _tunnel)) {
		fail(u"naive_tunnel_closed"_q);
		return false;
	}
	return true;
}

void NaiveSocket::fail(const QString &text) {
	if (_failed) {
		return;
	}
	_failed = true;
	logError(0, text);
	_error.fire_copy(MTP::details::AbstractConnection::kErrorCodeOther);
}

} // namespace Zsg::Naive
