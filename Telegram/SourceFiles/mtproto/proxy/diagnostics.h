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
};

enum class ProxyDiagnosticsSeverity {
	Info,
	Warning,
	Error,
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
	QString tlsRecordType;
	QString tlsRecordVersion;
	std::optional<int> tlsRecordLength;
	QString responsePrefixHash;
	std::optional<int> sniLength;
	QString sniHash;
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
	QString tlsRecordType;
	QString tlsRecordVersion;
	std::optional<int> tlsRecordLength;
	QString responsePrefixHash;
	std::optional<int> sniLength;
	QString sniHash;
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
	ProxyData::Type proxyType,
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
