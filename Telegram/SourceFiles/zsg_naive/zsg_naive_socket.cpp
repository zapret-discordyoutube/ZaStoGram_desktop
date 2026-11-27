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
#include "settings.h"
#include "zsg_naive/zsg_warp.h"

#include <QtCore/QDateTime>
#include <QtCore/QFile>

#include <algorithm>
#include <memory>

namespace Zsg::Naive {
namespace {

using namespace MTP::details;

constexpr auto kChunk = 16 * 1024;
// NaiveProxy rotates its HTTP/2 session every five minutes (tunnel_timeout).
constexpr auto kMaxAgeMs = qint64(5 * 60 * 1000);
// A couple of connections instead of one: a stall of one TCP connection must
// not freeze every MTProto connection at once.
constexpr auto kMaxShared = 2;

[[nodiscard]] bool ReuseEnabled() {
	static const auto enabled = !qEnvironmentVariableIsEmpty("ZSG_NAIVE_REUSE")
		|| QFile::exists(cWorkingDir() + u"tdata/zsg/naive_reuse"_q);
	return enabled;
}

// Connections of the thread that asked: its sockets and the QTcpSocket of a
// connection live in that thread, and nothing here is locked.
[[nodiscard]] std::vector<std::unique_ptr<SharedConnection>> &Registry() {
	thread_local auto result
		= std::vector<std::unique_ptr<SharedConnection>>();
	return result;
}

} // namespace

SharedConnection *SharedConnection::Acquire(
		not_null<QThread*> thread,
		const MTP::ProxyData &proxy,
		bool share) {
	auto &list = Registry();
	// Forget what nobody uses and nobody can use any more.
	list.erase(
		std::remove_if(list.begin(), list.end(), [](const auto &connection) {
			return !connection->hasSockets() && !connection->usable();
		}),
		list.end());
	if (share) {
		auto best = (SharedConnection*)nullptr;
		auto count = 0;
		for (const auto &connection : list) {
			if (!connection->matches(proxy) || !connection->usable()) {
				continue;
			}
			++count;
			if (!best || connection->tunnelCount() < best->tunnelCount()) {
				best = connection.get();
			}
		}
		if (best && count >= kMaxShared) {
			LOG(("Naive: reusing a connection with %1 tunnel(s), %2 shared."
				).arg(best->tunnelCount()
				).arg(count));
			return best;
		}
	}
	list.push_back(std::unique_ptr<SharedConnection>(
		new SharedConnection(thread, proxy)));
	LOG(("Naive: new connection (%1 held, sharing %2)."
		).arg(int(list.size())
		).arg(share ? u"on"_q : u"off"_q));
	return list.back().get();
}

SharedConnection::SharedConnection(
	not_null<QThread*> thread,
	const MTP::ProxyData &proxy)
: _proxy(proxy)
, _created(QDateTime::currentMSecsSinceEpoch()) {
	if (QThread::currentThread() != thread) {
		moveToThread(thread);
	}
	_tcp.moveToThread(thread);
	_tcp.setProxy(Zsg::Warp::EntryProxy().value_or(QNetworkProxy(QNetworkProxy::NoProxy)));
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
			if (_failed) {
				return;
			}
			_failed = true;
			auto snapshot = _sockets;
			for (const auto socket : snapshot) {
				if (std::find(_sockets.begin(), _sockets.end(), socket)
					!= _sockets.end()) {
					socket->onConnectionClosed();
				}
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
			failAll(u"tcp_error %1: %2"_q.arg(int(e)).arg(_tcp.errorString()));
		}));
	if (!start()) {
		// The reason is in _error; the sockets that attach see it.
		_failed = true;
	}
}

SharedConnection::~SharedConnection() {
	if (_client) {
		_api->naiveFree(_client);
		_client = nullptr;
	}
	_tcp.abort();
}

bool SharedConnection::start() {
	auto loadError = QString();
	_api = LoadApi(&loadError);
	if (!_api) {
		_error = loadError;
		return false;
	}
	_host = _proxy.host.toUtf8();
	_user = _proxy.user.toUtf8();
	_password = _proxy.password.toUtf8();

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
		_error = u"naive_client_create_failed: "_q
			+ QString::fromLatin1(error);
		return false;
	}
	_started = QDateTime::currentMSecsSinceEpoch();
	LOG(("Naive: connecting to %1:%2.").arg(_proxy.host).arg(config.port));
	_tcp.connectToHost(_proxy.host, config.port);
	return true;
}

bool SharedConnection::usable() const {
	return !_failed
		&& !_suspect
		&& (QDateTime::currentMSecsSinceEpoch() - _created) < kMaxAgeMs;
}

bool SharedConnection::matches(const MTP::ProxyData &proxy) const {
	return (proxy.host == _proxy.host)
		&& (proxy.port == _proxy.port)
		&& (proxy.user == _proxy.user)
		&& (proxy.password == _proxy.password);
}

void SharedConnection::attach(not_null<NaiveSocket*> socket) {
	_sockets.push_back(socket);
}

void SharedConnection::detach(not_null<NaiveSocket*> socket) {
	_sockets.erase(
		std::remove(_sockets.begin(), _sockets.end(), socket.get()),
		_sockets.end());
}

int SharedConnection::openTunnel(const QByteArray &host, int port) {
	if (_failed || !_client) {
		return 0;
	}
	const auto tunnel = _api->naiveOpenTunnel(
		_client,
		host.constData(),
		uint16_t(port));
	if (tunnel) {
		++_tunnels;
	}
	return tunnel;
}

void SharedConnection::closeTunnel(int tunnel) {
	if (!tunnel) {
		return;
	}
	if (_tunnels > 0) {
		--_tunnels;
	}
	if (_failed || !_client) {
		return;
	}
	_api->naiveCloseTunnel(_client, tunnel);
	pump();
}

void SharedConnection::noteTimeout() {
	if (!_suspect) {
		_suspect = true;
		LOG(("Naive: a tunnel timed out, the connection takes no new "
			"tunnels."));
	}
}

void SharedConnection::failAll(const QString &text) {
	if (_failed) {
		return;
	}
	_failed = true;
	_error = text;
	LOG(("Naive: connection to %1 failed after %2 ms: %3 (%4 tunnel(s))."
		).arg(_proxy.host
		).arg(QDateTime::currentMSecsSinceEpoch() - _started
		).arg(text
		).arg(_tunnels));
	_tcp.abort();
	auto snapshot = _sockets;
	for (const auto socket : snapshot) {
		if (std::find(_sockets.begin(), _sockets.end(), socket)
			!= _sockets.end()) {
			socket->onConnectionFailed(text);
		}
	}
}

void SharedConnection::onTcpConnected() {
	if (_failed || !_client) {
		return;
	}
	_tcpConnected = true;
	LOG(("Naive: TCP connected to %1 in %2 ms."
		).arg(_proxy.host
		).arg(QDateTime::currentMSecsSinceEpoch() - _started));
	// Nagle costs a round trip on the short request-then-wait writes mtproto
	// is made of; keepalive lets a silently dead path surface.
	_tcp.setSocketOption(QAbstractSocket::LowDelayOption, 1);
	_tcp.setSocketOption(QAbstractSocket::KeepAliveOption, 1);
	pump();
}

void SharedConnection::onReadyRead() {
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
	pump();
}

void SharedConnection::pump() {
	if (_failed || !_client) {
		return;
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
	if (state != _lastState) {
		_lastState = state;
		LOG(("Naive: %1 state %2 after %3 ms."
			).arg(_proxy.host
			).arg(state
			).arg(QDateTime::currentMSecsSinceEpoch() - _started));
	}
	if (state == NaiveFailed || state == NaiveClosed) {
		failAll(u"naive_"_q + ((state == NaiveFailed)
			? QString::fromLatin1(_api->naiveError(_client))
			: u"closed"_q));
		return;
	}
	auto snapshot = _sockets;
	for (const auto socket : snapshot) {
		if (std::find(_sockets.begin(), _sockets.end(), socket)
			== _sockets.end()) {
			continue;
		}
		[[maybe_unused]] const auto alive = socket->onConnectionProgress();
		if (_failed || !_client) {
			return;
		}
	}
}

NaiveSocket::NaiveSocket(
	not_null<MTP::RuntimeEnvironment*> runtime,
	not_null<QThread*> thread,
	const MTP::ProxyData &proxy)
: AbstractSocket(runtime, thread)
, _thread(thread)
, _proxy(proxy) {
}

NaiveSocket::~NaiveSocket() {
	release();
}

void NaiveSocket::release() {
	if (!_conn) {
		return;
	}
	const auto conn = _conn;
	const auto tunnel = _tunnel;
	_conn = nullptr;
	_tunnel = 0;
	conn->detach(this);
	conn->closeTunnel(tunnel);
}

void NaiveSocket::connectToHost(const QString &address, int port) {
	if (address.contains(':')) {
		// The Naive server reaches the data center over IPv4; a literal IPv6
		// address would only fail on the server side.
		fail(u"naive_ipv6_target"_q);
		return;
	}
	_conn = SharedConnection::Acquire(_thread, _proxy, ReuseEnabled());
	if (_conn->failed() && !_conn->error().isEmpty()) {
		const auto text = _conn->error();
		_conn = nullptr;
		fail(text);
		return;
	}
	_conn->attach(this);
	_tunnel = _conn->openTunnel(address.toUtf8(), port);
	if (!_tunnel) {
		fail(u"naive_open_tunnel_failed"_q);
		return;
	}
	if (_conn->tcpConnected()) {
		// Joined a connection that is already up: report where it stands.
		[[maybe_unused]] const auto alive = onConnectionProgress();
		if (alive) {
			_conn->pump();
		}
	}
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
	LOG(("Naive: MTProto connection timed out (tunnel %1, opened %2)."
		).arg(_tunnel
		).arg(_tunnelOpened ? u"yes"_q : u"no"_q));
	if (_conn) {
		_conn->noteTimeout();
	}
}

bool NaiveSocket::isConnected() {
	return _tunnelOpened && _conn && _conn->tcpConnected();
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

	if (!_conn || !_tunnel || _failed) {
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
	if (_conn->api()->naiveTunnelWrite(
			_conn->client(),
			_tunnel,
			reinterpret_cast<const uint8_t*>(combined.constData()),
			size) != size) {
		fail(u"naive_tunnel_write_failed"_q);
		return;
	}
	_conn->pump();
}

int32 NaiveSocket::debugState() {
	return _conn
		? _conn->tcpState()
		: int(QAbstractSocket::UnconnectedState);
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

bool NaiveSocket::onConnectionProgress() {
	if (_failed || !_conn) {
		return false;
	}
	if (!_tunnel) {
		return true; // Attached, the tunnel is not opened yet.
	}
	if (_conn->tcpConnected() && _phase < HandshakePhase::TcpConnected) {
		_phase = HandshakePhase::TcpConnected;
		connectionProgress(_phase);
		if (_failed || !_conn) {
			return false;
		}
		_phase = HandshakePhase::ClientHelloSent;
		connectionProgress(_phase);
		if (_failed || !_conn) {
			return false;
		}
	}
	const auto state = _conn->api()->naiveState(_conn->client());
	if (state >= NaivePreamble && _phase < HandshakePhase::ServerHelloOk) {
		_phase = HandshakePhase::ServerHelloOk;
		connectionProgress(_phase);
		if (_failed || !_conn) {
			return false;
		}
	}
	return drainTunnel();
}

void NaiveSocket::onConnectionFailed(const QString &text) {
	fail(text);
}

void NaiveSocket::onConnectionClosed() {
	if (!_failed) {
		_disconnected.fire({});
	}
}

bool NaiveSocket::drainTunnel() {
	const auto api = _conn->api();
	const auto client = _conn->client();
	const auto state = api->naiveTunnelState(client, _tunnel);
	if (state == TunnelFailed) {
		// e.g. 407 for wrong credentials, 502 for an unreachable target; a
		// probe-resistant server answers a wrong password like a web site
		// (308), which lands here too.
		fail(u"naive_tunnel_refused http=%1"_q.arg(
			api->naiveTunnelHttpStatus(client, _tunnel)));
		return false;
	}
	if (state == TunnelOpen && !_tunnelOpened) {
		_tunnelOpened = true;
		_connected.fire({});
		if (_failed || !_conn) {
			return false;
		}
	}
	auto produced = false;
	uint8_t chunk[kChunk];
	while (true) {
		const auto got = api->naiveTunnelRead(
			client,
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
		if (_failed || !_conn) {
			return false;
		}
	}
	if (state == TunnelOpen && api->naiveTunnelEof(client, _tunnel)) {
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
	LOG(("Naive: socket failed: %1.").arg(text));
	logError(0, text);
	_error.fire_copy(MTP::details::AbstractConnection::kErrorCodeOther);
}

} // namespace Zsg::Naive
