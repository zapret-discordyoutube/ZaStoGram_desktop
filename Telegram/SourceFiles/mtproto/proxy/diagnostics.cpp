/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "mtproto/proxy/diagnostics.h"

#include "base/invoke_queued.h"
#include "logs.h"
#include "mtproto/mtp_instance.h"
#include "settings.h"

#include <QtCore/QDir>
#include <QtCore/QFile>
#include <QtCore/QFileInfo>
#include <QtCore/QRegularExpression>
#include <QtCore/QStringList>

#include <rpl/variable.h>

#include <algorithm>

namespace MTP {
namespace {

constexpr auto kProxyDiagnosticsLimit = 2000;
constexpr auto kProxyDiagnosticsFileTailBytes = 512 * 1024;

rpl::variable<std::vector<ProxyDiagnosticsEvent>> Events;

[[nodiscard]] QString SourceText(ProxyDiagnosticsSource source) {
	switch (source) {
	case ProxyDiagnosticsSource::MTProxy:
		return u"MTProxy"_q;
	case ProxyDiagnosticsSource::Network:
		return u"Network"_q;
	case ProxyDiagnosticsSource::MTP:
		return u"MTP"_q;
	}
	return u"Network"_q;
}

[[nodiscard]] QString PhaseText(ProxyDiagnosticsPhase phase) {
	switch (phase) {
	case ProxyDiagnosticsPhase::None:
		return u"event"_q;
	case ProxyDiagnosticsPhase::Resolving:
		return u"resolving"_q;
	case ProxyDiagnosticsPhase::Connecting:
		return u"connecting"_q;
	case ProxyDiagnosticsPhase::TcpConnected:
		return u"tcp_connected"_q;
	case ProxyDiagnosticsPhase::ClientHelloSent:
		return u"client_hello_sent"_q;
	case ProxyDiagnosticsPhase::ServerHelloOk:
		return u"server_hello_ok"_q;
	case ProxyDiagnosticsPhase::TelegramCheck:
		return u"telegram_check"_q;
	case ProxyDiagnosticsPhase::Connected:
		return u"connected"_q;
	case ProxyDiagnosticsPhase::Failed:
		return u"failed"_q;
	case ProxyDiagnosticsPhase::ProxyCheckStarted:
		return u"proxy_check_started"_q;
	case ProxyDiagnosticsPhase::ProxyCheckFinished:
		return u"proxy_check_finished"_q;
	}
	return u"event"_q;
}

[[nodiscard]] QString SeverityText(ProxyDiagnosticsSeverity severity) {
	switch (severity) {
	case ProxyDiagnosticsSeverity::Info:
		return u"info"_q;
	case ProxyDiagnosticsSeverity::Warning:
		return u"warning"_q;
	case ProxyDiagnosticsSeverity::Error:
		return u"error"_q;
	}
	return u"info"_q;
}

[[nodiscard]] QString ErrorText(ProxyConnectionError error) {
	switch (error) {
	case ProxyConnectionError::None:
		return QString();
	case ProxyConnectionError::HostNotFound:
		return u"host_not_found"_q;
	case ProxyConnectionError::ConnectionRefused:
		return u"connection_refused"_q;
	case ProxyConnectionError::Timeout:
		return u"timeout"_q;
	case ProxyConnectionError::Authentication:
		return u"authentication"_q;
	case ProxyConnectionError::ProxyProtocol:
		return u"proxy_protocol"_q;
	case ProxyConnectionError::RemoteClosed:
		return u"remote_closed"_q;
	case ProxyConnectionError::Network:
		return u"network"_q;
	case ProxyConnectionError::BadResponse:
		return u"bad_response"_q;
	case ProxyConnectionError::Unknown:
		return u"unknown"_q;
	}
	return u"unknown"_q;
}

[[nodiscard]] QString RedactMessage(QString message) {
	static const auto expression = QRegularExpression(
		u"((?:secret|password|pass)=)[^&\\s]+"_q,
		QRegularExpression::CaseInsensitiveOption);
	return message.replace(expression, u"\\1<redacted>"_q);
}

[[nodiscard]] ProxyData RedactProxyData(ProxyData proxy) {
	if (!proxy.password.isEmpty()) {
		const auto password = u"<redacted>"_q;
		const auto secret = u"<redacted>"_q;
		proxy.password = (proxy.type == ProxyData::Type::Mtproto)
			? secret
			: password;
	}
	return proxy;
}

[[nodiscard]] ProxyDiagnosticsEvent RedactEvent(
		ProxyDiagnosticsEvent event) {
	event.proxy = RedactProxyData(std::move(event.proxy));
	event.message = RedactMessage(std::move(event.message));
	return event;
}

[[nodiscard]] QString ProxyEndpointText(const ProxyData &proxy) {
	if (proxy.host.isEmpty() || !proxy.port) {
		return QString();
	}
	return proxy.host + ':' + QString::number(proxy.port);
}

[[nodiscard]] ProxyDiagnosticsSource SourceFromFileName(
		const QString &name) {
	if (name.startsWith(u"mtproxy"_q)) {
		return ProxyDiagnosticsSource::MTProxy;
	} else if (name.startsWith(u"mtp"_q)) {
		return ProxyDiagnosticsSource::MTP;
	}
	return ProxyDiagnosticsSource::Network;
}

[[nodiscard]] ProxyDiagnosticsSeverity SeverityFromLine(
		const QString &line) {
	if (line.contains(u" error"_q, Qt::CaseInsensitive)
		|| line.contains(u" failed"_q, Qt::CaseInsensitive)
		|| line.contains(u" timeout"_q, Qt::CaseInsensitive)) {
		return ProxyDiagnosticsSeverity::Error;
	}
	return ProxyDiagnosticsSeverity::Info;
}

[[nodiscard]] QStringList TailLines(
		const QFileInfo &info,
		int maxLines) {
	auto file = QFile(info.absoluteFilePath());
	if (!file.open(QIODevice::ReadOnly | QIODevice::Text)) {
		return {};
	}
	const auto size = file.size();
	const auto start = std::max<qint64>(
		0,
		size - kProxyDiagnosticsFileTailBytes);
	if (start > 0) {
		file.seek(start);
		file.readLine();
	}
	auto result = QString::fromUtf8(file.readAll()).split('\n');
	while (!result.isEmpty() && result.back().trimmed().isEmpty()) {
		result.removeLast();
	}
	if (result.size() > maxLines) {
		result = result.mid(result.size() - maxLines);
	}
	return result;
}

[[nodiscard]] auto StatusPhaseFromDiagnostics(ProxyDiagnosticsPhase phase)
-> std::optional<ProxyConnectionPhase> {
	switch (phase) {
	case ProxyDiagnosticsPhase::Resolving:
		return ProxyConnectionPhase::Resolving;
	case ProxyDiagnosticsPhase::Connecting:
	case ProxyDiagnosticsPhase::TcpConnected:
		return ProxyConnectionPhase::Connecting;
	case ProxyDiagnosticsPhase::ClientHelloSent:
		return ProxyConnectionPhase::Handshake;
	case ProxyDiagnosticsPhase::ServerHelloOk:
	case ProxyDiagnosticsPhase::TelegramCheck:
		return ProxyConnectionPhase::CheckingTelegram;
	case ProxyDiagnosticsPhase::Connected:
		return ProxyConnectionPhase::Connected;
	case ProxyDiagnosticsPhase::Failed:
		return ProxyConnectionPhase::Failed;
	case ProxyDiagnosticsPhase::None:
	case ProxyDiagnosticsPhase::ProxyCheckStarted:
	case ProxyDiagnosticsPhase::ProxyCheckFinished:
		return std::nullopt;
	}
	return std::nullopt;
}

[[nodiscard]] ProxyDiagnosticsSource SourceForProxy(const ProxyData &proxy) {
	return (proxy.type == ProxyData::Type::Mtproto)
		? ProxyDiagnosticsSource::MTProxy
		: ProxyDiagnosticsSource::Network;
}

} // namespace

QString FormatProxyDiagnosticsEvent(const ProxyDiagnosticsEvent &event) {
	const auto safe = RedactEvent(event);
	auto parts = QStringList();
	const auto timestamp = safe.timestamp.isValid()
		? safe.timestamp.toString(u"hh:mm:ss.zzz"_q)
		: QDateTime::currentDateTime().toString(u"hh:mm:ss.zzz"_q);
	parts.push_back(u"[%1]"_q.arg(timestamp));
	parts.push_back(SourceText(safe.source));
	parts.push_back(SeverityText(safe.severity));
	parts.push_back(PhaseText(safe.phase));
	const auto endpoint = ProxyEndpointText(safe.proxy);
	if (!endpoint.isEmpty()) {
		parts.push_back(u"proxy=%1"_q.arg(endpoint));
	}
	if (!safe.transport.isEmpty()) {
		parts.push_back(u"transport=%1"_q.arg(safe.transport));
	}
	if (!safe.dc.isEmpty()) {
		parts.push_back(u"dc=%1"_q.arg(safe.dc));
	}
	if (!safe.connectionId.isEmpty()) {
		parts.push_back(u"connection=%1"_q.arg(safe.connectionId));
	}
	if (!safe.socketId.isEmpty()) {
		parts.push_back(u"socket=%1"_q.arg(safe.socketId));
	}
	const auto error = ErrorText(safe.error);
	if (!error.isEmpty()) {
		parts.push_back(u"error=%1"_q.arg(error));
	}
	if (!safe.message.isEmpty()) {
		parts.push_back(u"message=%1"_q.arg(safe.message));
	}
	return parts.join(u" | "_q);
}

std::vector<ProxyDiagnosticsEvent> ProxyDiagnosticsSnapshot() {
	return Events.current();
}

auto ProxyDiagnosticsEventsValue()
-> rpl::producer<std::vector<ProxyDiagnosticsEvent>> {
	return Events.value();
}

std::vector<ProxyDiagnosticsEvent> LoadProxyDiagnosticsTail(int maxLines) {
	auto result = std::vector<ProxyDiagnosticsEvent>();
	if (maxLines <= 0) {
		return result;
	}
	auto dir = QDir(cWorkingDir() + u"DebugLogs"_q);
	if (!dir.exists()) {
		return result;
	}
	auto files = QFileInfoList();
	for (const auto &pattern : {
			u"mtproxy*.txt"_q,
			u"mtp*.txt"_q,
			u"log*.txt"_q }) {
		files.append(dir.entryInfoList(
			{ pattern },
			QDir::Files,
			QDir::Time));
	}
	std::sort(files.begin(), files.end(), [](const auto &a, const auto &b) {
		return a.lastModified() < b.lastModified();
	});
	for (const auto &info : files) {
		for (const auto &line : TailLines(info, maxLines)) {
			const auto message = line.trimmed();
			if (message.isEmpty()) {
				continue;
			}
			result.push_back({
				.source = SourceFromFileName(info.fileName()),
				.phase = ProxyDiagnosticsPhase::None,
				.severity = SeverityFromLine(message),
				.message = message,
				.timestamp = info.lastModified(),
			});
		}
		if (int(result.size()) > maxLines) {
			result.erase(result.begin(), result.end() - maxLines);
		}
	}
	return result;
}

void AddProxyDiagnosticsEvent(ProxyDiagnosticsEvent event) {
	event = RedactEvent(std::move(event));
	if (!event.timestamp.isValid()) {
		event.timestamp = QDateTime::currentDateTime();
	}
	crl::on_main([event = std::move(event)]() mutable {
		auto copy = Events.current();
		copy.push_back(std::move(event));
		if (copy.size() > kProxyDiagnosticsLimit) {
			copy.erase(copy.begin(), copy.end() - kProxyDiagnosticsLimit);
		}
		Events.force_assign(std::move(copy));
	});
}

void WriteProxyDiagnosticsLine(ProxyDiagnosticsEvent event) {
	if (!event.timestamp.isValid()) {
		event.timestamp = QDateTime::currentDateTime();
	}
	const auto line = FormatProxyDiagnosticsEvent(event);
	AddProxyDiagnosticsEvent(std::move(event));
	Logs::writeMtproxy(line);
}

void ReportProxyEvent(
		not_null<Instance*> instance,
		ProxyEventReport report) {
	if (report.proxy.type == ProxyData::Type::None) {
		return;
	}
	if (const auto phase = StatusPhaseFromDiagnostics(report.phase)) {
		const auto status = ProxyConnectionStatus{
			*phase,
			report.error,
			report.proxy,
		};
		InvokeQueued(instance, [=] {
			instance->setProxyConnectionStatus(status);
		});
	}
	AddProxyDiagnosticsEvent({
		.source = SourceForProxy(report.proxy),
		.phase = report.phase,
		.severity = report.severity.value_or(
			(report.error == ProxyConnectionError::None)
				? ProxyDiagnosticsSeverity::Info
				: ProxyDiagnosticsSeverity::Error),
		.error = report.error,
		.proxy = std::move(report.proxy),
		.transport = std::move(report.transport),
		.dc = std::move(report.dc),
		.connectionId = std::move(report.connectionId),
		.message = std::move(report.message),
	});
}

} // namespace MTP
