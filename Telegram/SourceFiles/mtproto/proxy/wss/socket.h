/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#pragma once

#include "mtproto/transport/details/mtproto_abstract_socket.h"

#include <QtNetwork/QSslSocket>

#include <optional>

namespace MTP::details {

struct WssRoute {
	QString relayHost;
	QString relayHostFallback; // retried once if relayHost fails (e.g. domain)
	int relayPort = 443;
	QString domain;
	QString path;
};

// Official MTProto-over-WebSocket route for a data center, mirroring the
// web.telegram.org transport. The public web sockets exist only for DC2/DC4.
[[nodiscard]] std::optional<WssRoute> WssOfficialRoute(
	int16 protocolDcId,
	bool protocolForFiles);

// Expert-only user-configured relay (ProxyStealthOptions.wssCustom*), used
// for any DC when set and verified against the configured relay domain.
[[nodiscard]] std::optional<WssRoute> WssCustomRoute(
	const ProxyStealthOptions &stealth);

// A clean, self-contained MTProto-over-WebSocket(-over-TLS) transport. It
// speaks RFC 6455 over a real QSslSocket and carries the obfuscated MTProto
// stream transparently inside binary frames, so the rest of the connection
// stack (obfuscation, protocol negotiation) is unchanged.
class WssSocket final : public AbstractSocket {
public:
	WssSocket(
		not_null<RuntimeEnvironment*> runtime,
		not_null<QThread*> thread,
		const QNetworkProxy &proxy,
		bool protocolForFiles,
		WssRoute route);

	void connectToHost(const QString &address, int port) override;
	bool isGoodStartNonce(bytes::const_span nonce) override;
	void timedOut() override;
	bool isConnected() override;
	bool hasBytesAvailable() override;
	int64 read(bytes::span buffer) override;
	void write(bytes::const_span prefix, bytes::const_span buffer) override;

	int32 debugState() override;
	QString debugPostfix() const override;
	HandshakePhase handshakePhase() const override;
	QString transportName() const override;

private:
	void handleError(int errorCode);
	void connectToRelayHost();
	void onEncrypted();
	void onReadyRead();
	void sendHttpUpgrade();
	[[nodiscard]] bool tryFinishUpgrade();
	[[nodiscard]] bool checkUpgradeAccept(const QByteArray &header) const;
	void parseFrames();
	void sendFrame(quint8 opcode, bytes::const_span data);

	QSslSocket _socket;
	WssRoute _route;
	QString _secWebSocketKey;
	QByteArray _incoming;
	QByteArray _readBuffer;
	bool _upgraded = false;
	bool _usedFallback = false;
	bool _hostFlipped = false;
	HandshakePhase _phase = HandshakePhase::None;

};

} // namespace MTP::details
