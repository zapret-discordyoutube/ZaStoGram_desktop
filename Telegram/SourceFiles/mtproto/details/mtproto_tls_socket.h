/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#pragma once

#include "mtproto/details/mtproto_abstract_socket.h"
#include "mtproto/mtproto_proxy_data.h"
#include "base/timer.h"

namespace MTP::details {

class TlsSocket final : public AbstractSocket {
public:
	TlsSocket(
		not_null<QThread*> thread,
		const bytes::vector &secret,
		const QNetworkProxy &proxy,
		bool protocolForFiles,
		const ProxyStealthOptions &stealth);

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

private:
	enum class State {
		NotConnected,
		Connecting,
		WaitingHello,
		Connected,
		Error,
	};
	enum class RecordSizing {
		Off,
		Conservative,
		Varied,
	};
	enum class StartupCover {
		Off,
		Soft,
		Strict,
	};

	[[nodiscard]] bytes::const_span domainFromSecret() const;
	[[nodiscard]] bytes::const_span keyFromSecret() const;

	void plainConnected();
	void plainDisconnected();
	void plainReadyRead();
	void handleError(int errorCode = AbstractConnection::kErrorCodeOther);
	[[nodiscard]] bool requiredHelloPartReady() const;
	void readHello();
	void checkHelloParts12(int parts1Size);
	void checkHelloParts34(int parts123Size);
	void checkHelloDigest();
	void readData();
	[[nodiscard]] bool checkNextPacket();
	void shiftIncomingBy(int amount);
	[[nodiscard]] RecordSizing effectiveRecordSizing();
	[[nodiscard]] bool startupCoverActive();
	[[nodiscard]] int nextRecordPayloadSize();
	[[nodiscard]] ProxyTlsProfile effectiveTlsProfile() const;
	[[nodiscard]] QString failureDiagnostic() const;
	void applyAdaptiveRecipe();
	[[nodiscard]] crl::time recordPacingDelay();
	void writeClientHello(const QByteArray &data);
	void sendOutgoing();

	const bytes::vector _secret;
	QString _endpointKey;
	ProxyStealthOptions _stealth;
	QTcpSocket _socket;
	State _state = State::NotConnected;
	QByteArray _incoming;
	int _incomingGoodDataOffset = 0;
	int _incomingGoodDataLimit = 0;
	int16 _serverHelloLength = 0;
	RecordSizing _recordSizing = RecordSizing::Off;
	StartupCover _startupCover = StartupCover::Soft;
	crl::time _startupCoverStartedAt = 0;
	int _startupCoverFrames = 0;
	bool _firstAppDataSent = false;
	ProxyClientHelloFragmentation _clientHelloFragmentation
		= ProxyClientHelloFragmentation::Off;
	ProxyTlsProfile _tlsProfile = ProxyTlsProfile::Auto;
	ProxyTiming _timing = ProxyTiming::Off;
	QByteArray _outgoing;
	int _outgoingOffset = 0;
	bool _clientPrefixSent = false;
	base::Timer _pacingTimer;
	HandshakePhase _phase = HandshakePhase::None;

};

} // namespace MTP::details
