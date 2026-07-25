/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#pragma once

#include "mtproto/proxy/mtproxy/client_hello_facts.h"
#include "mtproto/proxy/mtproxy/endpoint_identity.h"
#include "mtproto/proxy/mtproxy/tls_socket_transport.h"
#include "mtproto/proxy/data.h"
#include "mtproto/runtime/runtime_environment.h"
#include "mtproto/transport/details/mtproto_abstract_socket.h"

#include <memory>

namespace MTP {
enum class ProxyDiagnosticsPhase;
enum class ProxyDiagnosticsSeverity;
} // namespace MTP

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
		MtProxyAttemptPlan mtproxyPlan,
		crl::time mtproxyAttemptStartedAt,
		std::unique_ptr<TlsSocketTransport> transport = nullptr);
	~TlsSocket() override;

	void connectToHost(const QString &address, int port) override;
	bool isGoodStartNonce(bytes::const_span nonce) override;
	void timedOut() override;
	void markProxyMtprotoPayloadReceived() override;
	bool isConnected() override;
	bool hasBytesAvailable() override;
	int64 read(bytes::span buffer) override;
	void write(bytes::const_span prefix, bytes::const_span buffer) override;

	int32 debugState() override;
	QString debugPostfix() const override;
	HandshakePhase handshakePhase() const override;
	ProxyMtproxyTerminalReason mtproxyTerminalReason() const override;
	crl::time mtproxyTerminalUntil() const override;
	ProxyTransportFailure proxyTransportFailure() const override;

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
	bool finishTerminal(
		MtProxy::FailureReason reason,
		ProxyConnectionError error,
		ProxyCloseOrigin origin,
		int errorCode,
		const QString &message,
		bool emitError);
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
	[[nodiscard]] crl::time recordPacingDelay();
	void checkClientHelloContract(const QByteArray &hello);
	void writeClientHello(const QByteArray &data);
	void writeClientHelloPart(const char *data, int size);
	void writeClientHelloTail();
	void finishClientHelloWrite();
	void armServerHelloDeadline();
	void handleServerHelloTimeout();
	void sendClientHello();
	void sendOutgoing();
	void noteIncoming(const QByteArray &data);
	void reportTransportEvent(
		ProxyDiagnosticsPhase phase,
		ProxyDiagnosticsSeverity severity,
		const QString &message);
	[[nodiscard]] QString responseClass() const;
	[[nodiscard]] QString blockToken() const;
	[[nodiscard]] ProxyFailureAttribution failureAttribution() const;
	[[nodiscard]] ProxyTransportFailure collectTransportFailure() const;
	[[nodiscard]] QString responseRecordType() const;
	[[nodiscard]] QString responseRecordVersion() const;
	[[nodiscard]] std::optional<int> responseRecordLength() const;
	[[nodiscard]] QString responsePrefixHash() const;

	const bytes::vector _secret;
	const ProxyData _proxy;
	MtProxy::EndpointId _endpointId;
	QString _endpointKey;
	ProxyConnectionUse _endpointUse = ProxyConnectionUse::Main;
	ProxyConnectionAttempt _mtproxyAttempt;
	MtProxyAttemptPlan _mtproxyPlan;
	crl::time _mtproxyAttemptStartedAt = 0;
	ProxyStealthOptions _stealth;
	std::unique_ptr<TlsSocketTransport> _transport;
	State _state = State::NotConnected;
	QByteArray _incoming;
	QByteArray _responsePrefix;
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
	ProxyTlsProfile _configuredTlsProfile = ProxyTlsProfile::Auto;
	ProxyTlsProfile _sentTlsProfile = ProxyTlsProfile::Auto;
	ProxyTiming _timing = ProxyTiming::Off;
	QByteArray _outgoing;
	int _outgoingOffset = 0;
	bool _clientPrefixSent = false;
	bool _syntheticPskOffered = false;
	// Whether the hello we sent satisfies everything the relay checks before
	// accepting one. A relay never says no - it hands a hello it does not
	// recognise to the site it fronts for - so this verdict is what tells an
	// unsigned ServerHello caused by our own template apart from one caused by
	// a secret that is not the relay's.
	ClientHelloContractIssue _clientHelloContract
		= ClientHelloContractIssue::None;
	bool _clientHelloFragmented = false;
	int _clientHelloBytes = 0;
	int _clientHelloWrites = 0;
	qint64 _clientHelloAcceptedBytes = 0;
	int _clientHelloFragmentSplit = 0;
	crl::time _clientHelloFragmentDelayMs = 0;
	bool _firstAppDataReceived = false;
	bool _mtprotoPayloadReceived = false;
	crl::time _firstAppDataAt = 0;
	QByteArray _clientHelloTail;
	RuntimeTimer _pacingTimer;
	RuntimeTimer _clientHelloTimer;
	RuntimeTimer _clientHelloFragmentTimer;
	RuntimeTimer _serverHelloTimer;
	MtProxy::FailureReason _failureReason = MtProxy::FailureReason::None;
	ProxyConnectionError _connectionError = ProxyConnectionError::None;
	ProxyCloseOrigin _closeOrigin = ProxyCloseOrigin::None;
	ProxyTransportFailure _terminalFailure;
	qint64 _rxAfterClientHello = 0;
	crl::time _tcpConnectedAt = 0;
	crl::time _firstRxAt = 0;
	crl::time _serverHelloAt = 0;
	crl::time _serverHelloDeadline = 0;
	crl::time _terminalAt = 0;
	HandshakePhase _phase = HandshakePhase::None;
	bool _terminal = false;

};

} // namespace MTP::details
