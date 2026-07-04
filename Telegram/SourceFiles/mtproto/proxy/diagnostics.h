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

#include <rpl/producer.h>

#include <optional>
#include <vector>

namespace MTP {

class Instance;

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
};

[[nodiscard]] QString FormatProxyDiagnosticsEvent(
	const ProxyDiagnosticsEvent &event);
[[nodiscard]] std::vector<ProxyDiagnosticsEvent> ProxyDiagnosticsSnapshot();
[[nodiscard]] auto ProxyDiagnosticsEventsValue()
-> rpl::producer<std::vector<ProxyDiagnosticsEvent>>;
[[nodiscard]] std::vector<ProxyDiagnosticsEvent> LoadProxyDiagnosticsTail(
	int maxLines);

void AddProxyDiagnosticsEvent(ProxyDiagnosticsEvent event);
void WriteProxyDiagnosticsLine(ProxyDiagnosticsEvent event);
void ReportProxyEvent(not_null<Instance*> instance, ProxyEventReport report);

} // namespace MTP
