/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#pragma once

#include "base/bytes.h"
#include "base/basic_types.h"
#include "mtproto/transport/connection_abstract.h"
#include "mtproto/runtime/connection_status_types.h"

namespace MTP::details {

enum class HandshakePhase {
	None,
	TcpConnected,
	ClientHelloSent,
	ServerHelloOk,
	FirstDataReceived,
};

class AbstractSocket : protected QObject {
public:
	void setDebugId(const QString &id) {
		_debugId = id;
	}

	AbstractSocket(
		not_null<RuntimeEnvironment*> runtime,
		not_null<QThread*> thread)
	: _runtime(runtime) {
		moveToThread(thread);
	}
	virtual ~AbstractSocket() = default;

	[[nodiscard]] rpl::producer<> connected() const {
		return _connected.events();
	}
	[[nodiscard]] rpl::producer<> disconnected() const {
		return _disconnected.events();
	}
	[[nodiscard]] rpl::producer<> readyRead() const {
		return _readyRead.events();
	}
	[[nodiscard]] rpl::producer<int> error() const {
		return _error.events();
	}
	[[nodiscard]] rpl::producer<> syncTimeRequests() const {
		return _syncTimeRequests.events();
	}
	[[nodiscard]] rpl::producer<HandshakePhase> progress() const {
		return _progress.events();
	}

	virtual void connectToHost(const QString &address, int port) = 0;
	[[nodiscard]] virtual bool isGoodStartNonce(bytes::const_span nonce) = 0;
	virtual void timedOut() = 0;
	// Asked at a packet boundary: true means the connection should be
	// reopened now, and the socket remembers it was closed on purpose.
	[[nodiscard]] virtual bool takeRotation() {
		return false;
	}
	virtual void markProxyMtprotoPayloadReceived() {
	}
	[[nodiscard]] virtual bool isConnected() = 0;
	[[nodiscard]] virtual bool hasBytesAvailable() = 0;
	[[nodiscard]] virtual int64 read(bytes::span buffer) = 0;
	virtual void write(
		bytes::const_span prefix,
		bytes::const_span buffer) = 0;

	virtual int32 debugState() = 0;
	[[nodiscard]] virtual QString debugPostfix() const = 0;

	[[nodiscard]] virtual QString transportName() const {
		return u"TCP"_q;
	}

	[[nodiscard]] virtual HandshakePhase handshakePhase() const {
		return HandshakePhase::None;
	}
	[[nodiscard]] virtual ProxyMtproxyTerminalReason mtproxyTerminalReason()
			const {
		return ProxyMtproxyTerminalReason::None;
	}
	[[nodiscard]] virtual crl::time mtproxyTerminalUntil() const {
		return 0;
	}
	[[nodiscard]] virtual ProxyTransportFailure proxyTransportFailure() const {
		return {};
	}
	[[nodiscard]] virtual ReceiveWaitVerdict receiveWaitVerdict(
			crl::time /*waitStartedAt*/) const {
		return {};
	}

protected:
	static const int kFilesSendBufferSize = 2 * 1024 * 1024;
	static const int kFilesReceiveBufferSize = 2 * 1024 * 1024;

	void logError(int errorCode, const QString &errorText);
	void connectionProgress(HandshakePhase phase) {
		_progress.fire_copy(phase);
	}

	QString _debugId;
	rpl::event_stream<> _connected;
	rpl::event_stream<> _disconnected;
	rpl::event_stream<> _readyRead;
	rpl::event_stream<int> _error;
	rpl::event_stream<> _syncTimeRequests;
	rpl::event_stream<HandshakePhase> _progress;
	const not_null<RuntimeEnvironment*> _runtime;

};

[[nodiscard]] ProxyConnectionError SocketProxyConnectionError(int errorCode);

} // namespace MTP::details
