/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#pragma once

#include "mtproto/proxy/mtproxy/tls_socket_transport.h"
#include "mtproto/transport/details/mtproto_abstract_socket.h"
#include "mtproto/proxy/data.h"
#include "mtproto/proxy/mtproxy/endpoint_health.h"

#include <memory>

namespace MTP::details {

class TlsSocket final : public AbstractSocket {
public:
	TlsSocket(
		not_null<RuntimeEnvironment*> runtime,
		not_null<QThread*> thread,
		const bytes::vector &secret,
		const ProxyData &proxy,
		bool protocolForFiles,
		const ProxyStealthOptions &stealth,
		ProxyConnectionAttempt mtproxyAttempt,
		crl::time mtproxyAttemptStartedAt,
		std::unique_ptr<TlsSocketTransport> transport = nullptr);

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
	ProxyMtproxyTerminalReason mtproxyTerminalReason() const override;
	crl::time mtproxyTerminalUntil() const override;

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
	void handleError(
		MtProxy::FailureReason reason,
		int errorCode = AbstractConnection::kErrorCodeOther);
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
	[[nodiscard]] MtProxy::FailureReason failureReason() const;
	bool clearSyntheticPskOnFailure(MtProxy::FailureReason reason);
	void applyAdaptiveRecipe();
	[[nodiscard]] crl::time recordPacingDelay();
	void writeClientHello(const QByteArray &data);
	void writeClientHelloTail();
	void sendClientHello();
	void sendOutgoing();

	const bytes::vector _secret;
	MtProxy::EndpointId _endpointId;
	QString _endpointKey;
	MtProxy::EndpointUse _endpointUse = MtProxy::EndpointUse::Main;
	ProxyConnectionAttempt _mtproxyAttempt;
	crl::time _mtproxyAttemptStartedAt = 0;
	ProxyStealthOptions _stealth;
	std::unique_ptr<TlsSocketTransport> _transport;
	State _state = State::NotConnected;
	QByteArray _incoming;
	int _incomingGoodDataOffset = 0;
	int _incomingGoodDataLimit = 0;
	int _serverHelloLength = 0;
	RecordSizing _recordSizing = RecordSizing::Off;
	StartupCover _startupCover = StartupCover::Off;
	crl::time _startupCoverStartedAt = 0;
	int _startupCoverFrames = 0;
	bool _firstAppDataSent = false;
	ProxyClientHelloFragmentation _clientHelloFragmentation
		= ProxyClientHelloFragmentation::Off;
	ProxyConnectionPattern _connectionPattern = ProxyConnectionPattern::Off;
	ProxyTlsProfile _tlsProfile = ProxyTlsProfile::Auto;
	ProxyTlsProfile _preparedTlsProfile = ProxyTlsProfile::Auto;
	ProxyTlsProfile _sentTlsProfile = ProxyTlsProfile::Auto;
	ProxyTiming _timing = ProxyTiming::Off;
	QByteArray _outgoing;
	int _outgoingOffset = 0;
	bool _clientPrefixSent = false;
	bool _usePreparedTlsProfile = false;
	bool _syntheticPskOffered = false;
	bool _clientHelloFragmented = false;
	bool _firstAppDataReceived = false;
	crl::time _firstAppDataAt = 0;
	QByteArray _clientHelloTail;
	RuntimeTimer _pacingTimer;
	RuntimeTimer _clientHelloTimer;
	RuntimeTimer _clientHelloFragmentTimer;
	MtProxy::FailureReason _failureReason = MtProxy::FailureReason::None;
	HandshakePhase _phase = HandshakePhase::None;

};

} // namespace MTP::details
