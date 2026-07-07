/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "mtproto/proxy/diagnostics.h"

#include "base/unixtime.h"
#include "logs.h"
#include "mtproto/mtp_instance.h"
#include "mtproto/proxy/control_plane.h"
#include "settings.h"

#include <QtCore/QCryptographicHash>
#include <QtCore/QRegularExpression>
#include <QtCore/QStringList>

namespace MTP {
namespace {

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
	case ProxyDiagnosticsPhase::AdmissionQueued:
		return u"admission_queued"_q;
	case ProxyDiagnosticsPhase::AdmissionStarted:
		return u"admission_started"_q;
	case ProxyDiagnosticsPhase::AdmissionCancelled:
		return u"admission_cancelled"_q;
	case ProxyDiagnosticsPhase::RouteSelected:
		return u"route_selected"_q;
	case ProxyDiagnosticsPhase::RouteFailed:
		return u"route_failed"_q;
	case ProxyDiagnosticsPhase::CanonicalDegraded:
		return u"canonical_degraded"_q;
	case ProxyDiagnosticsPhase::CanonicalRecovered:
		return u"canonical_recovered"_q;
	case ProxyDiagnosticsPhase::StealthRecipeApplied:
		return u"stealth_recipe_applied"_q;
	case ProxyDiagnosticsPhase::TransportFallbackApplied:
		return u"transport_fallback_applied"_q;
	case ProxyDiagnosticsPhase::RotationSwitched:
		return u"rotation_switched"_q;
	case ProxyDiagnosticsPhase::MtpConnecting:
		return u"mtp_connecting"_q;
	case ProxyDiagnosticsPhase::MtpTransportReady:
		return u"mtp_transport_ready"_q;
	case ProxyDiagnosticsPhase::MtpKeyCreating:
		return u"mtp_key_creating"_q;
	case ProxyDiagnosticsPhase::MtpKeyReady:
		return u"mtp_key_ready"_q;
	case ProxyDiagnosticsPhase::MtpFirstDataReceived:
		return u"mtp_first_data"_q;
	case ProxyDiagnosticsPhase::MtpReceiveTimeout:
		return u"mtp_receive_timeout"_q;
	case ProxyDiagnosticsPhase::MtpConnectTimeout:
		return u"mtp_connect_timeout"_q;
	case ProxyDiagnosticsPhase::MtpBrokerTimeout:
		return u"mtp_broker_timeout"_q;
	case ProxyDiagnosticsPhase::MtpPingTimeout:
		return u"mtp_ping_timeout"_q;
	case ProxyDiagnosticsPhase::MtpBindFailed:
		return u"mtp_bind_failed"_q;
	case ProxyDiagnosticsPhase::MtpKeyDestroyed:
		return u"mtp_key_destroyed"_q;
	case ProxyDiagnosticsPhase::MtpRestart:
		return u"mtp_restart"_q;
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

[[nodiscard]] QString ProxyIdentityHost(const ProxyData &proxy) {
	return proxy.originalHost.isEmpty()
		? proxy.host
		: proxy.originalHost;
}

[[nodiscard]] QString ProxyKeyHash(const ProxyData &proxy) {
	const auto host = ProxyIdentityHost(proxy);
	if (host.isEmpty() || !proxy.port) {
		return QString();
	}
	return ProxyDiagnosticsKeyHash(
		QString::number(int(proxy.type))
		+ ':' + host
		+ u":%1:"_q.arg(proxy.port)
		+ proxy.password);
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
	if (event.proxyKeyHash.isEmpty()) {
		event.proxyKeyHash = ProxyKeyHash(event.proxy);
	}
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

[[nodiscard]] QString CanonicalEndpointText(const ProxyData &proxy) {
	return ProxyDiagnosticsEndpointText(ProxyIdentityHost(proxy), proxy.port);
}

[[nodiscard]] QString RouteEndpointText(const ProxyData &proxy) {
	return ProxyDiagnosticsEndpointText(proxy.host, proxy.port);
}

[[nodiscard]] QString MtproxyReasonText(
		ProxyMtproxyTerminalReason reason) {
	switch (reason) {
	case ProxyMtproxyTerminalReason::None:
		return QString();
	case ProxyMtproxyTerminalReason::DnsFailed:
		return u"dns_failed"_q;
	case ProxyMtproxyTerminalReason::TcpConnectTimeout:
		return u"tcp_connect_timeout"_q;
	case ProxyMtproxyTerminalReason::TcpConnectedNoClientHelloWrite:
		return u"tcp_connected_no_client_hello_write"_q;
	case ProxyMtproxyTerminalReason::ClientHelloSentNoServerHello:
		return u"client_hello_sent_no_server_hello"_q;
	case ProxyMtproxyTerminalReason::TlsAlertAfterClientHello:
		return u"tls_alert_after_client_hello"_q;
	case ProxyMtproxyTerminalReason::ServerHelloHmacMismatch:
		return u"server_hello_hmac_mismatch"_q;
	case ProxyMtproxyTerminalReason::ServerHelloOkNoAppData:
		return u"server_hello_ok_no_appdata"_q;
	case ProxyMtproxyTerminalReason::ServerHelloOkNoMtprotoData:
		return u"server_hello_ok_no_mtproto_data"_q;
	case ProxyMtproxyTerminalReason::AppDataRemoteClosed:
		return u"appdata_remote_closed"_q;
	case ProxyMtproxyTerminalReason::ConnectedNoMtprotoData:
		return u"connected_no_mtproto_data"_q;
	case ProxyMtproxyTerminalReason::MtpReceiveTimeoutAfterData:
		return u"mtp_receive_timeout_after_data"_q;
	case ProxyMtproxyTerminalReason::ProxyProtocolBadResponse:
		return u"proxy_protocol_bad_response"_q;
	}
	return QString();
}

[[nodiscard]] bool IsMtpDiagnosticsPhase(ProxyDiagnosticsPhase phase) {
	switch (phase) {
	case ProxyDiagnosticsPhase::MtpConnecting:
	case ProxyDiagnosticsPhase::MtpTransportReady:
	case ProxyDiagnosticsPhase::MtpKeyCreating:
	case ProxyDiagnosticsPhase::MtpKeyReady:
	case ProxyDiagnosticsPhase::MtpFirstDataReceived:
	case ProxyDiagnosticsPhase::MtpReceiveTimeout:
	case ProxyDiagnosticsPhase::MtpConnectTimeout:
	case ProxyDiagnosticsPhase::MtpBrokerTimeout:
	case ProxyDiagnosticsPhase::MtpPingTimeout:
	case ProxyDiagnosticsPhase::MtpBindFailed:
	case ProxyDiagnosticsPhase::MtpKeyDestroyed:
	case ProxyDiagnosticsPhase::MtpRestart:
		return true;
	case ProxyDiagnosticsPhase::None:
	case ProxyDiagnosticsPhase::Resolving:
	case ProxyDiagnosticsPhase::Connecting:
	case ProxyDiagnosticsPhase::TcpConnected:
	case ProxyDiagnosticsPhase::ClientHelloSent:
	case ProxyDiagnosticsPhase::ServerHelloOk:
	case ProxyDiagnosticsPhase::TelegramCheck:
	case ProxyDiagnosticsPhase::Connected:
	case ProxyDiagnosticsPhase::Failed:
	case ProxyDiagnosticsPhase::ProxyCheckStarted:
	case ProxyDiagnosticsPhase::ProxyCheckFinished:
	case ProxyDiagnosticsPhase::AdmissionQueued:
	case ProxyDiagnosticsPhase::AdmissionStarted:
	case ProxyDiagnosticsPhase::AdmissionCancelled:
	case ProxyDiagnosticsPhase::RouteSelected:
	case ProxyDiagnosticsPhase::RouteFailed:
	case ProxyDiagnosticsPhase::CanonicalDegraded:
	case ProxyDiagnosticsPhase::CanonicalRecovered:
	case ProxyDiagnosticsPhase::StealthRecipeApplied:
	case ProxyDiagnosticsPhase::TransportFallbackApplied:
	case ProxyDiagnosticsPhase::RotationSwitched:
		return false;
	}
	return false;
}

[[nodiscard]] ProxyDiagnosticsSource SourceForProxy(const ProxyData &proxy) {
	return (proxy.type == ProxyData::Type::Mtproto)
		? ProxyDiagnosticsSource::MTProxy
		: ProxyDiagnosticsSource::Network;
}

[[nodiscard]] ProxyDiagnosticsSource SourceForReport(
		const ProxyEventReport &report) {
	return IsMtpDiagnosticsPhase(report.phase)
		? ProxyDiagnosticsSource::MTP
		: SourceForProxy(report.proxy);
}

} // namespace

QString ProxyDiagnosticsKeyHash(const QString &key) {
	if (key.isEmpty()) {
		return QString();
	}
	const auto hash = QCryptographicHash::hash(
		key.toUtf8(),
		QCryptographicHash::Sha256);
	return QString::fromLatin1(hash.toHex().left(16));
}

QString ProxyDiagnosticsEndpointText(const QString &host, int port) {
	if (host.isEmpty() || port <= 0) {
		return QString();
	}
	return host + ':' + QString::number(port);
}

QString ProxyDiagnosticsTransportName(
		ProxyData::Type proxyType,
		ProxyTransport transport) {
	if (transport == ProxyTransport::Wss) {
		return u"WSS"_q;
	}
	switch (proxyType) {
	case ProxyData::Type::Mtproto:
		return u"MtproxyFakeTlsTcp"_q;
	case ProxyData::Type::Socks5:
		return u"SocksTcp"_q;
	case ProxyData::Type::Http:
		return u"HttpTcp"_q;
	case ProxyData::Type::None:
		return u"Tcp"_q;
	}
	return u"Tcp"_q;
}

QString ProxyDiagnosticsTlsProfileName(ProxyTlsProfile profile) {
	switch (profile) {
	case ProxyTlsProfile::Auto:
		return u"Auto"_q;
	case ProxyTlsProfile::Firefox:
		return u"Firefox"_q;
	case ProxyTlsProfile::AndroidChrome:
		return u"AndroidChrome"_q;
	case ProxyTlsProfile::Yandex:
		return u"Yandex"_q;
	case ProxyTlsProfile::FirefoxAndroid:
		return u"FirefoxAndroid"_q;
	case ProxyTlsProfile::AndroidOkHttp:
		return u"AndroidOkHttp"_q;
	case ProxyTlsProfile::AutoRotate:
		return u"AutoRotate"_q;
	case ProxyTlsProfile::ChromeModern:
		return u"ChromeModern"_q;
	}
	return u"Auto"_q;
}

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
	const auto canonical = safe.canonical.isEmpty()
		? CanonicalEndpointText(safe.proxy)
		: safe.canonical;
	if (!canonical.isEmpty()) {
		parts.push_back(u"canonical=%1"_q.arg(canonical));
	}
	const auto route = safe.route.isEmpty()
		? RouteEndpointText(safe.proxy)
		: safe.route;
	if (!route.isEmpty()) {
		parts.push_back(u"route=%1"_q.arg(route));
	}
	if (!safe.proxyKeyHash.isEmpty()) {
		parts.push_back(u"proxy_key_hash=%1"_q.arg(safe.proxyKeyHash));
	}
	const auto transport = safe.transport.isEmpty()
		? ProxyDiagnosticsTransportName(
			safe.proxy.type,
			ProxyTransport::Tcp)
		: safe.transport;
	if (!transport.isEmpty()) {
		parts.push_back(u"transport=%1"_q.arg(transport));
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
	const auto mtproxyReason = MtproxyReasonText(safe.mtproxyReason);
	if (!mtproxyReason.isEmpty()) {
		parts.push_back(u"mtproxy_reason=%1"_q.arg(mtproxyReason));
	}
	if (!safe.profile.isEmpty()) {
		parts.push_back(u"profile=%1"_q.arg(safe.profile));
	}
	if (safe.source != ProxyDiagnosticsSource::MTP) {
		parts.push_back(u"recipe_level=%1"_q.arg(safe.recipeLevel));
		parts.push_back(u"psk_offered=%1"_q.arg(
			(safe.pskOfferedKnown && safe.pskOffered)
				? u"true"_q
				: u"false"_q));
		parts.push_back(u"fragmented_ch=%1"_q.arg(
			(safe.fragmentedClientHelloKnown && safe.fragmentedClientHello)
				? u"true"_q
				: u"false"_q));
		parts.push_back(u"phase_at_failure=%1"_q.arg(
			safe.phaseAtFailure.isEmpty()
				? u"none"_q
				: safe.phaseAtFailure));
		parts.push_back(u"queue_ms=%1"_q.arg(safe.queueMs));
	}
	const auto cooldownMs = safe.terminalUntil - crl::now();
	if (cooldownMs > 0) {
		parts.push_back(u"cooldown_ms=%1"_q.arg(cooldownMs));
	}
	if (safe.attempt.proxyGeneration) {
		parts.push_back(u"generation=%1"_q.arg(
			safe.attempt.proxyGeneration));
	}
	if (safe.attempt.attemptId) {
		parts.push_back(u"attempt=%1/%2"_q.arg(
			safe.attempt.proxyEpoch
		).arg(safe.attempt.attemptId));
	}
	if (!safe.message.isEmpty()) {
		parts.push_back(u"message=%1"_q.arg(safe.message));
	}
	return parts.join(u" | "_q);
}

void WriteProxyDiagnosticsLine(ProxyDiagnosticsEvent event) {
	if (!event.timestamp.isValid()) {
		event.timestamp = QDateTime::currentDateTime();
	}
	const auto line = FormatProxyDiagnosticsEvent(event);
	Logs::writeMtproxy(line);
}

void ReportProxyEvent(
		not_null<Instance*> instance,
		ProxyEventReport report) {
	if (report.proxy.type == ProxyData::Type::None) {
		return;
	}
	ProxyControlPlane::SubmitFact(instance, report);
	WriteProxyDiagnosticsLine({
		.source = SourceForReport(report),
		.phase = report.phase,
		.severity = report.severity.value_or(
			(report.error == ProxyConnectionError::None)
				? ProxyDiagnosticsSeverity::Info
				: ProxyDiagnosticsSeverity::Error),
		.error = report.error,
		.mtproxyReason = report.mtproxyReason,
		.attempt = report.attempt,
		.terminalUntil = report.terminalUntil,
		.proxy = std::move(report.proxy),
		.transport = std::move(report.transport),
		.dc = std::move(report.dc),
		.connectionId = std::move(report.connectionId),
		.message = std::move(report.message),
		.canonical = std::move(report.canonical),
		.route = std::move(report.route),
		.proxyKeyHash = std::move(report.proxyKeyHash),
		.profile = std::move(report.profile),
		.recipeLevel = report.recipeLevel,
		.pskOffered = report.pskOffered,
		.pskOfferedKnown = report.pskOfferedKnown,
		.fragmentedClientHello = report.fragmentedClientHello,
		.fragmentedClientHelloKnown = report.fragmentedClientHelloKnown,
		.phaseAtFailure = std::move(report.phaseAtFailure),
		.queueMs = report.queueMs,
	});
}

} // namespace MTP
