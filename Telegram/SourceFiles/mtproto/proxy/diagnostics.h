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
	int recipeLevel = 0;
	bool pskOffered = false;
	bool pskOfferedKnown = false;
	bool fragmentedClientHello = false;
	bool fragmentedClientHelloKnown = false;
	QString phaseAtFailure;
	crl::time queueMs = 0;
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
	int recipeLevel = 0;
	bool pskOffered = false;
	bool pskOfferedKnown = false;
	bool fragmentedClientHello = false;
	bool fragmentedClientHelloKnown = false;
	QString phaseAtFailure;
	crl::time queueMs = 0;
};

[[nodiscard]] QString ProxyDiagnosticsKeyHash(const QString &key);
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
void WriteProxyDiagnosticsLine(ProxyDiagnosticsEvent event);
void ReportProxyEvent(
	not_null<RuntimeEnvironment*> runtime,
	ProxyEventReport report);
void ReportProxyEvent(ProxyEventReport report);

} // namespace MTP
