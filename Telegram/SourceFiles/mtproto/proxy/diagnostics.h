/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#pragma once

#include "mtproto/proxy/status.h"

#include <QtCore/QDateTime>
#include <QtCore/QString>

#include <optional>

namespace MTP {

class RuntimeEnvironment;

enum class ProxyDiagnosticsSource {
	MTProxy,
	Network,
	MTP,
};

enum class ProxyDiagnosticsPhase {
	None,
	Resolving,
	Connecting,
	TcpConnected,
	ClientHelloSent,
	ServerHelloOk,
	TelegramCheck,
	Connected,
	Failed,
	ProxyCheckStarted,
	ProxyCheckFinished,
	AdmissionQueued,
	AdmissionStarted,
	AdmissionCancelled,
	RouteSelected,
	RouteFailed,
	CanonicalDegraded,
	CanonicalRecovered,
	StealthRecipeApplied,
	TransportFallbackApplied,
	RotationSwitched,
	MtpConnecting,
	MtpTransportReady,
	MtpKeyCreating,
	MtpKeyReady,
	MtpFirstDataReceived,
	MtpReceiveTimeout,
	MtpConnectTimeout,
	MtpBrokerTimeout,
	MtpPingTimeout,
	MtpBindFailed,
	MtpKeyDestroyed,
	MtpRestart,
	AttemptSummary,
	Liveness,
	FileRpc,
	FileProgress,
};

enum class ProxyDiagnosticsSeverity {
	Info,
	Warning,
	Error,
};

enum class ProxyDiagnosticsTransition {
	None,
	Cancelled,
	Queued,
	SendAdmitted,
	Sent,
	Resent,
	Result,
	Error,
	Slow,
	Accepted,
	Acknowledged,
};

enum class ProxyDiagnosticsErrorClass {
	None,
	BadRequest,
	Unauthorized,
	Forbidden,
	NotFound,
	NotAcceptable,
	Flood,
	Server,
	Transport,
	Unknown,
};

enum class ProxyDiagnosticsDirection {
	None,
	Download,
	Upload,
};

enum class ProxyDiagnosticsRpcKind {
	None,
	GetFile,
	GetWebFile,
	GetCdnFile,
	GetCdnFileHashes,
	ReuploadCdnFile,
	SaveFilePart,
	SaveBigFilePart,
};

struct ProxyDiagnosticsEvent {
	ProxyDiagnosticsSource source = ProxyDiagnosticsSource::Network;
	ProxyDiagnosticsPhase phase = ProxyDiagnosticsPhase::None;
	ProxyDiagnosticsSeverity severity = ProxyDiagnosticsSeverity::Info;
	ProxyConnectionError error = ProxyConnectionError::None;
	ProxyMtproxyTerminalReason mtproxyReason
		= ProxyMtproxyTerminalReason::None;
	ProxyConnectionAttempt attempt;
	crl::time terminalUntil = 0;
	ProxyData proxy;
	QString transport;
	QString dc;
	QString connectionId;
	QString socketId;
	QString message;
	QString canonical;
	QString route;
	QString proxyKeyHash;
	QString profile;
	QString configuredProfile;
	QString effectiveProfile;
	std::optional<int> recipeLevel;
	std::optional<bool> pskOffered;
	std::optional<bool> fragmentedClientHello;
	QString phaseAtFailure;
	std::optional<crl::time> queueMs;
	std::optional<int> clientHelloBytes;
	std::optional<int> clientHelloWrites;
	std::optional<qint64> clientHelloAcceptedBytes;
	std::optional<int> clientHelloFragmentSplit;
	std::optional<crl::time> clientHelloFragmentDelayMs;
	std::optional<qint64> rxAfterClientHello;
	QString rxClass;
	QString block;
	QString tlsRecordType;
	QString tlsRecordVersion;
	std::optional<int> tlsRecordLength;
	QString responsePrefixHash;
	std::optional<int> sniLength;
	QString sniHash;
	// The time that went into the hello's digest, and whether any reference
	// stood behind it. A skew reported without the reference is unreadable:
	// with no reference it is zero however wrong the machine's clock is.
	std::optional<TimeId> clientHelloTimestamp;
	QString clockReference;
	std::optional<TimeId> clockSkew;
	QString parserStage;
	std::optional<ProxyCloseOrigin> closeOrigin;
	std::optional<crl::time> dnsMs;
	std::optional<crl::time> tcpMs;
	std::optional<crl::time> firstRxMs;
	std::optional<crl::time> serverHelloMs;
	std::optional<crl::time> appDataMs;
	std::optional<crl::time> mtprotoMs;
	std::optional<crl::time> totalMs;
	int traceSchema = 0;
	QDateTime timestamp;
	ProxyDiagnosticsTransition transition = ProxyDiagnosticsTransition::None;
	ProxyDiagnosticsErrorClass errorClass
		= ProxyDiagnosticsErrorClass::None;
	ProxyDiagnosticsDirection direction = ProxyDiagnosticsDirection::None;
	ProxyDiagnosticsRpcKind rpcKind = ProxyDiagnosticsRpcKind::None;
	uint64 laneOrdinal = 0;
	uint64 requestOrdinal = 0;
	std::optional<int> sendCount;
	std::optional<int> errorCode;
	std::optional<qint64> acceptedBytes;
	std::optional<qint64> acknowledgedBytes;
	std::optional<bool> firstInLane;
	std::optional<bool> isFinal;
};

struct ProxyEventReport {
	ProxyDiagnosticsPhase phase = ProxyDiagnosticsPhase::None;
	ProxyConnectionError error = ProxyConnectionError::None;
	ProxyMtproxyTerminalReason mtproxyReason
		= ProxyMtproxyTerminalReason::None;
	ProxyConnectionAttempt attempt;
	crl::time terminalUntil = 0;
	std::optional<ProxyDiagnosticsSeverity> severity;
	ProxyData proxy;
	QString transport;
	QString dc;
	QString connectionId;
	QString message;
	QString canonical;
	QString route;
	QString proxyKeyHash;
	QString profile;
	QString configuredProfile;
	QString effectiveProfile;
	std::optional<int> recipeLevel;
	std::optional<bool> pskOffered;
	std::optional<bool> fragmentedClientHello;
	QString phaseAtFailure;
	std::optional<crl::time> queueMs;
	std::optional<int> clientHelloBytes;
	std::optional<int> clientHelloWrites;
	std::optional<qint64> clientHelloAcceptedBytes;
	std::optional<int> clientHelloFragmentSplit;
	std::optional<crl::time> clientHelloFragmentDelayMs;
	std::optional<qint64> rxAfterClientHello;
	QString rxClass;
	QString block;
	QString tlsRecordType;
	QString tlsRecordVersion;
	std::optional<int> tlsRecordLength;
	QString responsePrefixHash;
	std::optional<int> sniLength;
	QString sniHash;
	// The time that went into the hello's digest, and whether any reference
	// stood behind it. A skew reported without the reference is unreadable:
	// with no reference it is zero however wrong the machine's clock is.
	std::optional<TimeId> clientHelloTimestamp;
	QString clockReference;
	std::optional<TimeId> clockSkew;
	QString parserStage;
	std::optional<ProxyCloseOrigin> closeOrigin;
	std::optional<crl::time> dnsMs;
	std::optional<crl::time> tcpMs;
	std::optional<crl::time> firstRxMs;
	std::optional<crl::time> serverHelloMs;
	std::optional<crl::time> appDataMs;
	std::optional<crl::time> mtprotoMs;
	std::optional<crl::time> totalMs;
	int traceSchema = 0;
};

[[nodiscard]] QString ProxyDiagnosticsKeyHash(const QString &key);
[[nodiscard]] QString ProxyDiagnosticsProxyKeyHash(const ProxyData &proxy);
[[nodiscard]] QString ProxyDiagnosticsEndpointText(
	const QString &host,
	int port);
[[nodiscard]] QString ProxyDiagnosticsTransportName(
	const ProxyData &proxy,
	ProxyTransport transport);
[[nodiscard]] QString ProxyDiagnosticsTlsProfileName(
	ProxyTlsProfile profile);

[[nodiscard]] QString FormatProxyDiagnosticsEvent(
	const ProxyDiagnosticsEvent &event);
[[nodiscard]] ProxyDiagnosticsSource SourceForReport(
	const ProxyEventReport &report);

void WriteProxyDiagnosticsLine(
	not_null<RuntimeEnvironment*> runtime,
	ProxyDiagnosticsEvent event);
void ReportProxyEvent(
	not_null<RuntimeEnvironment*> runtime,
	ProxyEventReport report);
[[nodiscard]] bool ReportProxyAttemptSummary(
	not_null<RuntimeEnvironment*> runtime,
	ProxyEventReport report);
void ReportProxyLiveness(
	not_null<RuntimeEnvironment*> runtime,
	ProxyEventReport report);

} // namespace MTP
