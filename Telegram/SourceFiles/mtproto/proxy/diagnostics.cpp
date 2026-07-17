/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "mtproto/proxy/diagnostics.h"

#include "base/unixtime.h"
#include "mtproto/proxy/mtproxy/endpoint_identity.h"
#include "mtproto/proxy/proxy_endpoint_context.h"
#include "mtproto/runtime/runtime_environment.h"

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
	case ProxyDiagnosticsPhase::AttemptSummary:
		return u"attempt_summary"_q;
	case ProxyDiagnosticsPhase::Liveness:
		return u"liveness"_q;
	case ProxyDiagnosticsPhase::CapacityDecision:
		return u"capacity_decision"_q;
	case ProxyDiagnosticsPhase::CapacityProbe:
		return u"capacity_probe"_q;
	case ProxyDiagnosticsPhase::TransferEntitlement:
		return u"transfer_entitlement"_q;
	case ProxyDiagnosticsPhase::CapacityReclaim:
		return u"capacity_reclaim"_q;
	case ProxyDiagnosticsPhase::FileRpc:
		return u"file_rpc"_q;
	case ProxyDiagnosticsPhase::FileProgress:
		return u"file_progress"_q;
	}
	return u"event"_q;
}

[[nodiscard]] bool IsDiskOnlyDiagnosticsPhase(
		ProxyDiagnosticsPhase phase) {
	switch (phase) {
	case ProxyDiagnosticsPhase::CapacityDecision:
	case ProxyDiagnosticsPhase::CapacityProbe:
	case ProxyDiagnosticsPhase::TransferEntitlement:
	case ProxyDiagnosticsPhase::CapacityReclaim:
	case ProxyDiagnosticsPhase::FileRpc:
	case ProxyDiagnosticsPhase::FileProgress:
		return true;
	default:
		return false;
	}
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
	if (proxy.type == ProxyData::Type::Mtproto) {
		return ProxyDiagnosticsKeyHash(details::MtProxy::EndpointKey(
			details::MtProxy::EndpointIdFromProxy(
				proxy,
				ProxyStealthOptions()).canonical));
	}
	return ProxyDiagnosticsKeyHash(QString::number(int(proxy.type))
		+ ':' + host
		+ u":%1:"_q.arg(proxy.port)
		+ proxy.password);
}

[[nodiscard]] QString CloseOriginText(ProxyCloseOrigin origin) {
	switch (origin) {
	case ProxyCloseOrigin::None: return QString();
	case ProxyCloseOrigin::PeerClosed: return u"peer_closed"_q;
	case ProxyCloseOrigin::LocalTimeout: return u"local_timeout"_q;
	case ProxyCloseOrigin::RouteRaceLost: return u"route_race_lost"_q;
	case ProxyCloseOrigin::BrokerCancelled: return u"broker_cancelled"_q;
	case ProxyCloseOrigin::ProxySwitch: return u"proxy_switch"_q;
	case ProxyCloseOrigin::OwnerDestroyed: return u"owner_destroyed"_q;
	case ProxyCloseOrigin::NetworkError: return u"network_error"_q;
	case ProxyCloseOrigin::ProtocolRejected: return u"protocol_rejected"_q;
	}
	return QString();
}

[[nodiscard]] QString ConnectionUseText(ProxyConnectionUse use) {
	switch (use) {
	case ProxyConnectionUse::Main: return u"main"_q;
	case ProxyConnectionUse::Maintenance: return u"maintenance"_q;
	case ProxyConnectionUse::Auxiliary: return u"auxiliary"_q;
	case ProxyConnectionUse::Media: return u"media"_q;
	case ProxyConnectionUse::Upload: return u"upload"_q;
	case ProxyConnectionUse::ProxyCheck: return u"proxy_check"_q;
	}
	return QString();
}

[[nodiscard]] QString DecisionText(ProxyDiagnosticsDecision decision) {
	switch (decision) {
	case ProxyDiagnosticsDecision::None: return QString();
	case ProxyDiagnosticsDecision::Ordinary: return u"ordinary"_q;
	case ProxyDiagnosticsDecision::FrontierProbe: return u"frontier_probe"_q;
	case ProxyDiagnosticsDecision::ExactReplacement:
		return u"exact_replacement"_q;
	case ProxyDiagnosticsDecision::Blocked: return u"blocked"_q;
	case ProxyDiagnosticsDecision::Reservation: return u"reservation"_q;
	case ProxyDiagnosticsDecision::Transfer: return u"transfer"_q;
	case ProxyDiagnosticsDecision::Main: return u"main"_q;
	case ProxyDiagnosticsDecision::Applied: return u"applied"_q;
	case ProxyDiagnosticsDecision::NotApplicable: return u"not_applicable"_q;
	case ProxyDiagnosticsDecision::Retry: return u"retry"_q;
	case ProxyDiagnosticsDecision::NoDemand: return u"no_demand"_q;
	}
	return QString();
}

[[nodiscard]] QString TransitionText(
		ProxyDiagnosticsTransition transition) {
	switch (transition) {
	case ProxyDiagnosticsTransition::None: return QString();
	case ProxyDiagnosticsTransition::Reserved: return u"reserved"_q;
	case ProxyDiagnosticsTransition::Activated: return u"activated"_q;
	case ProxyDiagnosticsTransition::Proved: return u"proved"_q;
	case ProxyDiagnosticsTransition::Failed: return u"failed"_q;
	case ProxyDiagnosticsTransition::Cancelled: return u"cancelled"_q;
	case ProxyDiagnosticsTransition::CooldownStarted:
		return u"cooldown_started"_q;
	case ProxyDiagnosticsTransition::Acquired: return u"acquired"_q;
	case ProxyDiagnosticsTransition::Retained: return u"retained"_q;
	case ProxyDiagnosticsTransition::Released: return u"released"_q;
	case ProxyDiagnosticsTransition::VictimSelected:
		return u"victim_selected"_q;
	case ProxyDiagnosticsTransition::SuspendRequested:
		return u"suspend_requested"_q;
	case ProxyDiagnosticsTransition::SuspendAcknowledged:
		return u"suspend_acknowledged"_q;
	case ProxyDiagnosticsTransition::ParkRequested: return u"park_requested"_q;
	case ProxyDiagnosticsTransition::ParkAcknowledged:
		return u"park_acknowledged"_q;
	case ProxyDiagnosticsTransition::ReplacementGranted:
		return u"replacement_granted"_q;
	case ProxyDiagnosticsTransition::ReplacementProved:
		return u"replacement_proved"_q;
	case ProxyDiagnosticsTransition::ReplacementFailed:
		return u"replacement_failed"_q;
	case ProxyDiagnosticsTransition::RollbackRequested:
		return u"rollback_requested"_q;
	case ProxyDiagnosticsTransition::Resumed: return u"resumed"_q;
	case ProxyDiagnosticsTransition::CapacityOneForegroundMain:
		return u"capacity_one_foreground_main"_q;
	case ProxyDiagnosticsTransition::Queued: return u"queued"_q;
	case ProxyDiagnosticsTransition::SendAdmitted: return u"send_admitted"_q;
	case ProxyDiagnosticsTransition::Sent: return u"sent"_q;
	case ProxyDiagnosticsTransition::Resent: return u"resent"_q;
	case ProxyDiagnosticsTransition::Result: return u"result"_q;
	case ProxyDiagnosticsTransition::Error: return u"error"_q;
	case ProxyDiagnosticsTransition::Slow: return u"slow"_q;
	case ProxyDiagnosticsTransition::Accepted: return u"accepted"_q;
	case ProxyDiagnosticsTransition::Acknowledged: return u"acknowledged"_q;
	}
	return QString();
}

[[nodiscard]] QString DiagnosticsErrorClassText(
		ProxyDiagnosticsErrorClass errorClass) {
	switch (errorClass) {
	case ProxyDiagnosticsErrorClass::None: return QString();
	case ProxyDiagnosticsErrorClass::BadRequest: return u"bad_request"_q;
	case ProxyDiagnosticsErrorClass::Unauthorized: return u"unauthorized"_q;
	case ProxyDiagnosticsErrorClass::Forbidden: return u"forbidden"_q;
	case ProxyDiagnosticsErrorClass::NotFound: return u"not_found"_q;
	case ProxyDiagnosticsErrorClass::NotAcceptable: return u"not_acceptable"_q;
	case ProxyDiagnosticsErrorClass::Flood: return u"flood"_q;
	case ProxyDiagnosticsErrorClass::Server: return u"server"_q;
	case ProxyDiagnosticsErrorClass::Transport: return u"transport"_q;
	case ProxyDiagnosticsErrorClass::Unknown: return u"unknown"_q;
	}
	return QString();
}

[[nodiscard]] QString DirectionText(ProxyDiagnosticsDirection direction) {
	switch (direction) {
	case ProxyDiagnosticsDirection::None: return QString();
	case ProxyDiagnosticsDirection::Download: return u"download"_q;
	case ProxyDiagnosticsDirection::Upload: return u"upload"_q;
	}
	return QString();
}

[[nodiscard]] QString RpcKindText(ProxyDiagnosticsRpcKind kind) {
	switch (kind) {
	case ProxyDiagnosticsRpcKind::None: return QString();
	case ProxyDiagnosticsRpcKind::GetFile: return u"get_file"_q;
	case ProxyDiagnosticsRpcKind::GetWebFile: return u"get_web_file"_q;
	case ProxyDiagnosticsRpcKind::GetCdnFile: return u"get_cdn_file"_q;
	case ProxyDiagnosticsRpcKind::GetCdnFileHashes:
		return u"get_cdn_file_hashes"_q;
	case ProxyDiagnosticsRpcKind::ReuploadCdnFile:
		return u"reupload_cdn_file"_q;
	case ProxyDiagnosticsRpcKind::SaveFilePart: return u"save_file_part"_q;
	case ProxyDiagnosticsRpcKind::SaveBigFilePart:
		return u"save_big_file_part"_q;
	}
	return QString();
}

[[nodiscard]] QString FormatDiskOnlyDiagnosticsEvent(
		const ProxyDiagnosticsEvent &event) {
	auto parts = QStringList();
	const auto timestamp = event.timestamp.isValid()
		? event.timestamp.toString(u"hh:mm:ss.zzz"_q)
		: QDateTime::currentDateTime().toString(u"hh:mm:ss.zzz"_q);
	parts.push_back(u"[%1]"_q.arg(timestamp));
	parts.push_back(SourceText(event.source));
	parts.push_back(SeverityText(event.severity));
	parts.push_back(PhaseText(event.phase));
	const auto appendOrdinal = [&](const QString &name, auto value) {
		if (value) {
			parts.push_back(name + u"=%1"_q.arg(value));
		}
	};
	const auto appendOptional = [&](const QString &name, const auto &value) {
		if (value) {
			parts.push_back(name + u"=%1"_q.arg(*value));
		}
	};
	const auto appendText = [&](const QString &name, const QString &value) {
		if (!value.isEmpty()) {
			parts.push_back(name + '=' + value);
		}
	};
	const auto appendFlag = [&](const QString &name, std::optional<bool> value) {
		if (value) {
			parts.push_back(name + '=' + (*value ? u"true"_q : u"false"_q));
		}
	};
	appendOrdinal(u"runtime"_q, event.attempt.runtimeId);
	appendOrdinal(u"generation"_q, event.attempt.proxyGeneration);
	appendOrdinal(u"trace"_q, event.attempt.traceId);
	const auto hasUse = event.attempt.runtimeId
		|| event.attempt.proxyGeneration
		|| event.attempt.traceId
		|| event.attempt.ticketId
		|| event.attempt.routeAttemptId
		|| event.attempt.attemptId;
	if (hasUse) {
		appendText(u"use"_q, ConnectionUseText(event.attempt.use));
	}
	appendOrdinal(u"ticket"_q, event.attempt.ticketId);
	appendOrdinal(u"route_attempt"_q, event.attempt.routeAttemptId);
	appendOrdinal(u"endpoint_attempt"_q, event.attempt.attemptId);
	appendOrdinal(u"lane_ordinal"_q, event.laneOrdinal);
	appendOrdinal(u"request_ordinal"_q, event.requestOrdinal);
	appendText(u"decision"_q, DecisionText(event.decision));
	appendText(u"transition"_q, TransitionText(event.transition));
	appendOptional(u"commitments"_q, event.commitmentCount);
	appendOptional(u"lower_bound"_q, event.provenLowerBound);
	appendOptional(u"frontier"_q, event.frontier);
	appendOptional(u"cap"_q, event.capacityCap);
	appendOptional(u"send_count"_q, event.sendCount);
	appendText(u"error_class"_q, DiagnosticsErrorClassText(event.errorClass));
	appendOptional(u"error_code"_q, event.errorCode);
	appendOptional(u"queue_ms"_q, event.queueMs);
	appendOptional(u"total_ms"_q, event.totalMs);
	const auto retryMs = event.terminalUntil - crl::now();
	appendOrdinal(u"retry_ms"_q, (retryMs > 0) ? retryMs : crl::time());
	appendOptional(u"accepted_bytes"_q, event.acceptedBytes);
	appendOptional(u"acknowledged_bytes"_q, event.acknowledgedBytes);
	appendText(u"direction"_q, DirectionText(event.direction));
	appendText(u"rpc"_q, RpcKindText(event.rpcKind));
	appendFlag(u"first_in_lane"_q, event.firstInLane);
	appendFlag(u"final"_q, event.isFinal);
	return parts.join(u" | "_q);
}

[[nodiscard]] bool IsCancellationOrigin(
		std::optional<ProxyCloseOrigin> origin) {
	if (!origin) {
		return false;
	}
	switch (*origin) {
	case ProxyCloseOrigin::RouteRaceLost:
	case ProxyCloseOrigin::BrokerCancelled:
	case ProxyCloseOrigin::ProxySwitch:
	case ProxyCloseOrigin::OwnerDestroyed:
		return true;
	case ProxyCloseOrigin::None:
	case ProxyCloseOrigin::PeerClosed:
	case ProxyCloseOrigin::LocalTimeout:
	case ProxyCloseOrigin::NetworkError:
	case ProxyCloseOrigin::ProtocolRejected:
		return false;
	}
	return false;
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
		event.proxyKeyHash = ProxyDiagnosticsProxyKeyHash(event.proxy);
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
	case ProxyDiagnosticsPhase::AttemptSummary:
	case ProxyDiagnosticsPhase::Liveness:
	case ProxyDiagnosticsPhase::CapacityDecision:
	case ProxyDiagnosticsPhase::CapacityProbe:
	case ProxyDiagnosticsPhase::TransferEntitlement:
	case ProxyDiagnosticsPhase::CapacityReclaim:
	case ProxyDiagnosticsPhase::FileRpc:
	case ProxyDiagnosticsPhase::FileProgress:
		return false;
	}
	return false;
}

[[nodiscard]] ProxyDiagnosticsSource SourceForProxy(const ProxyData &proxy) {
	return (proxy.type == ProxyData::Type::Mtproto)
		? ProxyDiagnosticsSource::MTProxy
		: ProxyDiagnosticsSource::Network;
}

} // namespace

ProxyDiagnosticsSource SourceForReport(const ProxyEventReport &report) {
	return IsMtpDiagnosticsPhase(report.phase)
		? ProxyDiagnosticsSource::MTP
		: SourceForProxy(report.proxy);
}

QString ProxyDiagnosticsKeyHash(const QString &key) {
	if (key.isEmpty()) {
		return QString();
	}
	const auto hash = QCryptographicHash::hash(
		key.toUtf8(),
		QCryptographicHash::Sha256);
	return QString::fromLatin1(hash.toHex().left(16));
}

QString ProxyDiagnosticsProxyKeyHash(const ProxyData &proxy) {
	return ProxyKeyHash(proxy);
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
	if (IsDiskOnlyDiagnosticsPhase(event.phase)) {
		return FormatDiskOnlyDiagnosticsEvent(event);
	}
	const auto safe = RedactEvent(event);
	auto parts = QStringList();
	const auto timestamp = safe.timestamp.isValid()
		? safe.timestamp.toString(u"hh:mm:ss.zzz"_q)
		: QDateTime::currentDateTime().toString(u"hh:mm:ss.zzz"_q);
	parts.push_back(u"[%1]"_q.arg(timestamp));
	parts.push_back(SourceText(safe.source));
	parts.push_back(SeverityText(safe.severity));
	parts.push_back(PhaseText(safe.phase));
	if (safe.phase == ProxyDiagnosticsPhase::AttemptSummary) {
		parts.push_back(IsCancellationOrigin(safe.closeOrigin)
			? u"outcome=cancelled"_q
			: (safe.error != ProxyConnectionError::None
				|| safe.mtproxyReason != ProxyMtproxyTerminalReason::None)
			? u"outcome=failure"_q
			: u"outcome=success"_q);
	}
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
	const auto transport = (!safe.transport.isEmpty() || safe.traceSchema)
		? safe.transport
		: ProxyDiagnosticsTransportName(
			safe.proxy.type,
			ProxyTransport::Tcp);
	if (!transport.isEmpty()) {
		parts.push_back(u"transport=%1"_q.arg(transport));
	}
	if (!safe.dc.isEmpty()) {
		parts.push_back(u"dc=%1"_q.arg(safe.dc));
	}
	const auto connectionId = safe.connectionId.isEmpty()
		? safe.attempt.connectionId
		: safe.connectionId;
	if (!connectionId.isEmpty()) {
		parts.push_back(u"connection=%1"_q.arg(connectionId));
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
		parts.push_back(u"sent_profile=%1"_q.arg(safe.profile));
	}
	if (!safe.configuredProfile.isEmpty()) {
		parts.push_back(u"configured_profile=%1"_q.arg(
			safe.configuredProfile));
	}
	if (!safe.effectiveProfile.isEmpty()) {
		parts.push_back(u"effective_profile=%1"_q.arg(
			safe.effectiveProfile));
	}
	if (safe.recipeLevel) {
		parts.push_back(u"recipe_level=%1"_q.arg(*safe.recipeLevel));
	}
	if (safe.pskOffered) {
		parts.push_back(u"psk_offered=%1"_q.arg(
			*safe.pskOffered ? u"true"_q : u"false"_q));
	}
	if (safe.fragmentedClientHello) {
		parts.push_back(u"fragmented_ch=%1"_q.arg(
			*safe.fragmentedClientHello ? u"true"_q : u"false"_q));
	}
	if (!safe.phaseAtFailure.isEmpty()) {
		parts.push_back(u"phase_at_failure=%1"_q.arg(
			safe.phaseAtFailure));
	}
	if (safe.queueMs) {
		parts.push_back(u"queue_ms=%1"_q.arg(*safe.queueMs));
	}
	if (safe.clientHelloBytes) {
		parts.push_back(u"ch_bytes=%1"_q.arg(*safe.clientHelloBytes));
	}
	if (safe.clientHelloWrites) {
		parts.push_back(u"ch_writes=%1"_q.arg(*safe.clientHelloWrites));
	}
	if (safe.clientHelloAcceptedBytes) {
		parts.push_back(u"ch_accepted=%1"_q.arg(
			*safe.clientHelloAcceptedBytes));
	}
	if (safe.clientHelloFragmentSplit) {
		parts.push_back(u"ch_fragment_split=%1"_q.arg(
			*safe.clientHelloFragmentSplit));
	}
	if (safe.clientHelloFragmentDelayMs) {
		parts.push_back(u"ch_fragment_delay_ms=%1"_q.arg(
			*safe.clientHelloFragmentDelayMs));
	}
	if (safe.rxAfterClientHello) {
		parts.push_back(u"rx_after_ch=%1"_q.arg(*safe.rxAfterClientHello));
	}
	if (!safe.rxClass.isEmpty()) {
		parts.push_back(u"rx_class=%1"_q.arg(safe.rxClass));
	}
	if (!safe.block.isEmpty()) {
		parts.push_back(u"block=%1"_q.arg(safe.block));
	}
	if (!safe.tlsRecordType.isEmpty()) {
		parts.push_back(u"tls_record=%1"_q.arg(safe.tlsRecordType));
	}
	if (!safe.tlsRecordVersion.isEmpty()) {
		parts.push_back(u"tls_version=%1"_q.arg(safe.tlsRecordVersion));
	}
	if (safe.tlsRecordLength) {
		parts.push_back(u"tls_record_length=%1"_q.arg(
			*safe.tlsRecordLength));
	}
	if (!safe.responsePrefixHash.isEmpty()) {
		parts.push_back(u"rx_prefix_hash=%1"_q.arg(
			safe.responsePrefixHash));
	}
	if (safe.sniLength) {
		parts.push_back(u"sni_length=%1"_q.arg(*safe.sniLength));
	}
	if (!safe.sniHash.isEmpty()) {
		parts.push_back(u"sni_hash=%1"_q.arg(safe.sniHash));
	}
	if (!safe.parserStage.isEmpty()) {
		parts.push_back(u"parser_stage=%1"_q.arg(safe.parserStage));
	}
	if (safe.closeOrigin) {
		const auto origin = CloseOriginText(*safe.closeOrigin);
		if (!origin.isEmpty()) {
			parts.push_back(u"close_origin=%1"_q.arg(origin));
		}
	}
	const auto cooldownMs = safe.terminalUntil - crl::now();
	if (cooldownMs > 0) {
		parts.push_back(u"cooldown_ms=%1"_q.arg(cooldownMs));
	}
	if (safe.attempt.proxyGeneration) {
		parts.push_back(u"generation=%1"_q.arg(
			safe.attempt.proxyGeneration));
	}
	if (safe.attempt.runtimeId) {
		parts.push_back(u"runtime=%1"_q.arg(safe.attempt.runtimeId));
	}
	if (safe.attempt.traceId) {
		parts.push_back(u"trace=%1"_q.arg(safe.attempt.traceId));
		parts.push_back(u"use=%1"_q.arg(
			ConnectionUseText(safe.attempt.use)));
	}
	if (safe.attempt.ticketId) {
		parts.push_back(u"ticket=%1"_q.arg(safe.attempt.ticketId));
	}
	if (safe.attempt.routeAttemptId) {
		parts.push_back(u"route_attempt=%1"_q.arg(
			safe.attempt.routeAttemptId));
	}
	if (safe.attempt.proxyEpoch) {
		parts.push_back(u"proxy_epoch=%1"_q.arg(
			safe.attempt.proxyEpoch));
	}
	if (safe.attempt.successEpoch) {
		parts.push_back(u"success_epoch=%1"_q.arg(
			safe.attempt.successEpoch));
	}
	if (safe.attempt.attemptId) {
		parts.push_back(u"endpoint_attempt=%1"_q.arg(
			safe.attempt.attemptId));
	}
	const auto appendTiming = [&](const QString &name, auto value) {
		if (value) {
			parts.push_back(name + u"=%1"_q.arg(*value));
		}
	};
	appendTiming(u"dns_ms"_q, safe.dnsMs);
	appendTiming(u"tcp_ms"_q, safe.tcpMs);
	appendTiming(u"first_rx_ms"_q, safe.firstRxMs);
	appendTiming(u"server_hello_ms"_q, safe.serverHelloMs);
	appendTiming(u"appdata_ms"_q, safe.appDataMs);
	appendTiming(u"mtproto_ms"_q, safe.mtprotoMs);
	appendTiming(u"total_ms"_q, safe.totalMs);
	if (safe.traceSchema) {
		parts.push_back(u"trace_schema=%1"_q.arg(safe.traceSchema));
	}
	if (!safe.message.isEmpty()) {
		parts.push_back(u"message=%1"_q.arg(safe.message));
	}
	return parts.join(u" | "_q);
}

void WriteProxyDiagnosticsLine(
		not_null<RuntimeEnvironment*> runtime,
		ProxyDiagnosticsEvent event) {
	if (!event.timestamp.isValid()) {
		event.timestamp = QDateTime::currentDateTime();
	}
	if (runtime->diagnostics().writeProxyDiagnosticsLine) {
		runtime->diagnostics().writeProxyDiagnosticsLine(std::move(event));
	}
}

void ReportProxyEvent(
		not_null<RuntimeEnvironment*> runtime,
		ProxyEventReport report) {
	if (report.proxy.type == ProxyData::Type::None
		&& report.phase != ProxyDiagnosticsPhase::AttemptSummary
		&& report.phase != ProxyDiagnosticsPhase::Liveness) {
		return;
	}
	if (report.attempt.traceId && !report.traceSchema) {
		report.traceSchema = 2;
	}
	if (runtime->diagnostics().reportProxyEvent) {
		runtime->diagnostics().reportProxyEvent(std::move(report));
	}
}

bool ReportProxyAttemptSummary(
		not_null<RuntimeEnvironment*> runtime,
		ProxyEventReport report) {
	if (!runtime->proxyEndpointContext().finishTrace(report.attempt.traceId)) {
		return false;
	}
	report.phase = ProxyDiagnosticsPhase::AttemptSummary;
	report.traceSchema = 2;
	ReportProxyEvent(runtime, std::move(report));
	return true;
}

void ReportProxyLiveness(
		not_null<RuntimeEnvironment*> runtime,
		ProxyEventReport report) {
	report.phase = ProxyDiagnosticsPhase::Liveness;
	report.traceSchema = 2;
	ReportProxyEvent(runtime, std::move(report));
}

} // namespace MTP
