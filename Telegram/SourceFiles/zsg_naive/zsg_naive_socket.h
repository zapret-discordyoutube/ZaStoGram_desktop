/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#pragma once

#include "mtproto/runtime/proxy_data.h"
#include "mtproto/transport/details/mtproto_abstract_socket.h"
#include "zsg_naive/zsg_naive_api.h"

#include <QtNetwork/QTcpSocket>

#include <vector>

namespace Zsg::Naive {

class NaiveSocket;

// One TLS + HTTP/2 connection to a NaiveProxy-compatible server (a Chrome 158
// handshake: the zsgnaive library does TLS, HTTP/2 and the Naive padding, this
// class only moves bytes between it and a QTcpSocket). It carries one or more
// CONNECT tunnels, one per NaiveSocket. By default every socket gets its own
// connection; with connection reuse switched on (a file tdata/zsg/naive_reuse
// or the environment variable ZSG_NAIVE_REUSE) a few connections are shared,
// the way NaiveProxy itself keeps one HTTP/2 session for all its tunnels.
class SharedConnection final : public QObject {
public:
	// A connection for |proxy| in |thread|: one of the shared ones when
	// sharing is on and one is usable, a new one otherwise.
	[[nodiscard]] static SharedConnection *Acquire(
		not_null<QThread*> thread,
		const MTP::ProxyData &proxy,
		bool share);

	~SharedConnection();

	[[nodiscard]] const Api *api() const {
		return _api;
	}
	[[nodiscard]] NaiveHandle *client() const {
		return _client;
	}
	[[nodiscard]] bool tcpConnected() const {
		return _tcpConnected;
	}
	[[nodiscard]] bool failed() const {
		return _failed;
	}
	[[nodiscard]] const QString &error() const {
		return _error;
	}
	[[nodiscard]] int tcpState() const {
		return _tcp.state();
	}
	[[nodiscard]] bool usable() const;
	[[nodiscard]] int tunnelCount() const {
		return _tunnels;
	}
	[[nodiscard]] bool hasSockets() const {
		return !_sockets.empty();
	}
	[[nodiscard]] bool matches(const MTP::ProxyData &proxy) const;

	void attach(not_null<NaiveSocket*> socket);
	void detach(not_null<NaiveSocket*> socket);
	// The tunnel id, 0 on failure (the connection is then failed too).
	[[nodiscard]] int openTunnel(const QByteArray &host, int port);
	void closeTunnel(int tunnel);
	// A tunnel stopped answering in time: no new tunnel goes to this
	// connection any more.
	void noteTimeout();
	// Moves the library's outgoing bytes to the socket and tells every
	// attached socket to look at its tunnel.
	void pump();

private:
	SharedConnection(
		not_null<QThread*> thread,
		const MTP::ProxyData &proxy);

	[[nodiscard]] bool start();
	void failAll(const QString &text);
	void onTcpConnected();
	void onReadyRead();

	QTcpSocket _tcp;
	const MTP::ProxyData _proxy;
	const Api *_api = nullptr;
	NaiveHandle *_client = nullptr;
	QByteArray _host;
	QByteArray _user;
	QByteArray _password;
	QString _error;
	std::vector<NaiveSocket*> _sockets;
	qint64 _created = 0;
	int _tunnels = 0;
	bool _tcpConnected = false;
	bool _failed = false;
	bool _suspect = false;

};

// An MTProto byte stream carried through a NaiveProxy-compatible server: one
// HTTP/2 CONNECT tunnel to the Telegram data center, on a SharedConnection.
class NaiveSocket final : public MTP::details::AbstractSocket {
public:
	NaiveSocket(
		not_null<MTP::RuntimeEnvironment*> runtime,
		not_null<QThread*> thread,
		const MTP::ProxyData &proxy);
	~NaiveSocket();

	void connectToHost(const QString &address, int port) override;
	bool isGoodStartNonce(bytes::const_span nonce) override;
	void timedOut() override;
	bool isConnected() override;
	bool hasBytesAvailable() override;
	int64 read(bytes::span buffer) override;
	void write(bytes::const_span prefix, bytes::const_span buffer) override;

	int32 debugState() override;
	QString debugPostfix() const override;
	MTP::details::HandshakePhase handshakePhase() const override;
	QString transportName() const override;

	// Called by the connection: its state changed, look at the tunnel. False
	// means the socket reported a failure and may be gone.
	[[nodiscard]] bool onConnectionProgress();
	// Called by the connection when it failed as a whole.
	void onConnectionFailed(const QString &text);
	// Called by the connection when the server closed it.
	void onConnectionClosed();

private:
	[[nodiscard]] bool drainTunnel();
	void fail(const QString &text);
	void release();

	not_null<QThread*> _thread;
	const MTP::ProxyData _proxy;
	SharedConnection *_conn = nullptr;
	int _tunnel = 0;
	QByteArray _readBuffer;
	bool _tunnelOpened = false;
	bool _failed = false;
	MTP::details::HandshakePhase _phase
		= MTP::details::HandshakePhase::None;

};

} // namespace Zsg::Naive
