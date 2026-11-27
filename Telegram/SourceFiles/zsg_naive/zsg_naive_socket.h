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

namespace Zsg::Naive {

// An MTProto byte stream carried through a NaiveProxy-compatible server: one
// HTTP/2 CONNECT tunnel to the Telegram data center, over a TLS connection
// that is a Chrome 158 handshake (the zsgnaive library does TLS, HTTP/2 and the
// Naive padding; this class only moves bytes between it and a QTcpSocket).
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

private:
	void onTcpConnected();
	void onReadyRead();
	// Moves the library's outgoing bytes to the socket and reacts to its
	// state. False means the socket has already reported a failure and may
	// be gone: the caller must return at once.
	[[nodiscard]] bool pump();
	[[nodiscard]] bool drainTunnel();
	void fail(const QString &text);
	void releaseClient();

	QTcpSocket _tcp;
	const MTP::ProxyData _proxy;
	const Api *_api = nullptr;
	NaiveHandle *_client = nullptr;
	int _tunnel = 0;
	QByteArray _readBuffer;
	QByteArray _host;
	QByteArray _user;
	QByteArray _password;
	QByteArray _target;
	bool _tcpConnected = false;
	bool _tunnelOpened = false;
	bool _failed = false;
	MTP::details::HandshakePhase _phase
		= MTP::details::HandshakePhase::None;

};

} // namespace Zsg::Naive
