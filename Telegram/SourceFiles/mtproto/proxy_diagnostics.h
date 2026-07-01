/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#pragma once

#include "mtproto/connection_abstract.h"

#include <QtCore/QDateTime>
#include <QtCore/QString>

#include <rpl/producer.h>

#include <vector>

namespace MTP {

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
	ProxyData proxy;
	QString transport;
	QString dc;
	QString connectionId;
	QString socketId;
	QString message;
	QDateTime timestamp;
};

[[nodiscard]] ProxyDiagnosticsPhase ProxyDiagnosticsPhaseFromStatus(
	ProxyConnectionPhase phase);
[[nodiscard]] QString FormatProxyDiagnosticsEvent(
	const ProxyDiagnosticsEvent &event);
[[nodiscard]] std::vector<ProxyDiagnosticsEvent> ProxyDiagnosticsSnapshot();
[[nodiscard]] auto ProxyDiagnosticsEventsValue()
-> rpl::producer<std::vector<ProxyDiagnosticsEvent>>;
[[nodiscard]] std::vector<ProxyDiagnosticsEvent> LoadProxyDiagnosticsTail(
	int maxLines);

void AddProxyDiagnosticsEvent(ProxyDiagnosticsEvent event);
void WriteProxyDiagnosticsLine(ProxyDiagnosticsEvent event);

} // namespace MTP
