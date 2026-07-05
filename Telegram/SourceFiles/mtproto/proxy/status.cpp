/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "mtproto/proxy/status.h"

#include "base/timer.h"

namespace MTP {
namespace {

[[nodiscard]] bool IsSuccess(const ProxyConnectionStatus &status) {
	return status.phase == ProxyConnectionPhase::Connected;
}

[[nodiscard]] bool IsNewerAttempt(
		const ProxyConnectionAttempt &current,
		const ProxyConnectionAttempt &update) {
	if (update.proxyEpoch != current.proxyEpoch) {
		return update.proxyEpoch > current.proxyEpoch;
	}
	return update.attemptId > current.attemptId;
}

[[nodiscard]] bool StickyWindowActive(
		const ProxyConnectionStatus &status) {
	return status.terminalUntil
		&& (status.terminalUntil > crl::now());
}

} // namespace

bool IsMtproxyTerminalFailure(ProxyMtproxyTerminalReason reason) {
	return reason != ProxyMtproxyTerminalReason::None;
}

ProxyConnectionStatusKind ProxyConnectionStatusKindFor(
		const ProxyConnectionStatus &status) {
	switch (status.mtproxyReason) {
	case ProxyMtproxyTerminalReason::None:
		break;
	case ProxyMtproxyTerminalReason::ClientHelloSentNoServerHello:
		return ProxyConnectionStatusKind::MtproxyNoServerHello;
	case ProxyMtproxyTerminalReason::TlsAlertAfterClientHello:
		return ProxyConnectionStatusKind::MtproxyTlsAlert;
	case ProxyMtproxyTerminalReason::ShortTlsResponseAfterClientHello:
		return ProxyConnectionStatusKind::MtproxyShortResponse;
	case ProxyMtproxyTerminalReason::UnrecognizedTlsResponseAfterClientHello:
		return ProxyConnectionStatusKind::MtproxyUnrecognizedResponse;
	case ProxyMtproxyTerminalReason::ServerHelloHmacMismatch:
		return ProxyConnectionStatusKind::MtproxyServerHelloHmacMismatch;
	case ProxyMtproxyTerminalReason::PostHandshakeNoAppData:
		return ProxyConnectionStatusKind::MtproxyPostHandshakeNoAppData;
	case ProxyMtproxyTerminalReason::DnsHostNotFound:
		return ProxyConnectionStatusKind::MtproxyDnsHostNotFound;
	case ProxyMtproxyTerminalReason::TcpNotConnected:
		return ProxyConnectionStatusKind::MtproxyTcpNotConnected;
	case ProxyMtproxyTerminalReason::Timeout:
		return ProxyConnectionStatusKind::MtproxyTimeout;
	case ProxyMtproxyTerminalReason::RemoteClosed:
		return ProxyConnectionStatusKind::RemoteClosed;
	}
	switch (status.error) {
	case ProxyConnectionError::None:
		break;
	case ProxyConnectionError::HostNotFound:
		return ProxyConnectionStatusKind::HostNotFound;
	case ProxyConnectionError::ConnectionRefused:
		return ProxyConnectionStatusKind::ConnectionRefused;
	case ProxyConnectionError::Timeout:
		return ProxyConnectionStatusKind::Timeout;
	case ProxyConnectionError::Authentication:
		return ProxyConnectionStatusKind::Authentication;
	case ProxyConnectionError::ProxyProtocol:
		return ProxyConnectionStatusKind::ProxyProtocol;
	case ProxyConnectionError::RemoteClosed:
		return ProxyConnectionStatusKind::RemoteClosed;
	case ProxyConnectionError::Network:
		return ProxyConnectionStatusKind::Network;
	case ProxyConnectionError::BadResponse:
		return ProxyConnectionStatusKind::BadResponse;
	case ProxyConnectionError::Unknown:
		return ProxyConnectionStatusKind::Failed;
	}
	switch (status.phase) {
	case ProxyConnectionPhase::None:
		return ProxyConnectionStatusKind::None;
	case ProxyConnectionPhase::Resolving:
		return ProxyConnectionStatusKind::Resolving;
	case ProxyConnectionPhase::Connecting:
		return ProxyConnectionStatusKind::Connecting;
	case ProxyConnectionPhase::Handshake:
		return ProxyConnectionStatusKind::Handshake;
	case ProxyConnectionPhase::CheckingTelegram:
		return ProxyConnectionStatusKind::CheckingTelegram;
	case ProxyConnectionPhase::Connected:
		return ProxyConnectionStatusKind::Connected;
	case ProxyConnectionPhase::Failed:
		return ProxyConnectionStatusKind::Failed;
	}
	return ProxyConnectionStatusKind::None;
}

ProxyConnectionStatusSeverity ProxyConnectionStatusSeverityFor(
		ProxyConnectionStatusKind kind) {
	switch (kind) {
	case ProxyConnectionStatusKind::None:
		return ProxyConnectionStatusSeverity::None;
	case ProxyConnectionStatusKind::Resolving:
	case ProxyConnectionStatusKind::Connecting:
	case ProxyConnectionStatusKind::Handshake:
	case ProxyConnectionStatusKind::CheckingTelegram:
		return ProxyConnectionStatusSeverity::Progress;
	case ProxyConnectionStatusKind::Connected:
		return ProxyConnectionStatusSeverity::Success;
	case ProxyConnectionStatusKind::MtproxyPostHandshakeNoAppData:
		return ProxyConnectionStatusSeverity::Warning;
	case ProxyConnectionStatusKind::HostNotFound:
	case ProxyConnectionStatusKind::ConnectionRefused:
	case ProxyConnectionStatusKind::Timeout:
	case ProxyConnectionStatusKind::Authentication:
	case ProxyConnectionStatusKind::ProxyProtocol:
	case ProxyConnectionStatusKind::RemoteClosed:
	case ProxyConnectionStatusKind::Network:
	case ProxyConnectionStatusKind::BadResponse:
	case ProxyConnectionStatusKind::Failed:
	case ProxyConnectionStatusKind::MtproxyNoServerHello:
	case ProxyConnectionStatusKind::MtproxyTlsAlert:
	case ProxyConnectionStatusKind::MtproxyShortResponse:
	case ProxyConnectionStatusKind::MtproxyUnrecognizedResponse:
	case ProxyConnectionStatusKind::MtproxyServerHelloHmacMismatch:
	case ProxyConnectionStatusKind::MtproxyDnsHostNotFound:
	case ProxyConnectionStatusKind::MtproxyTcpNotConnected:
	case ProxyConnectionStatusKind::MtproxyTimeout:
		return ProxyConnectionStatusSeverity::Error;
	}
	return ProxyConnectionStatusSeverity::None;
}

ProxyConnectionStatusSeverity ProxyConnectionStatusSeverityFor(
		const ProxyConnectionStatus &status) {
	return ProxyConnectionStatusSeverityFor(
		ProxyConnectionStatusKindFor(status));
}

ProxyConnectionStatus ApplyProxyConnectionStatusUpdate(
		const ProxyConnectionStatus &current,
		ProxyConnectionStatus update) {
	if (!IsMtproxyTerminalFailure(current.mtproxyReason)) {
		return update;
	}
	if (IsSuccess(update)
		|| IsMtproxyTerminalFailure(update.mtproxyReason)
		|| IsNewerAttempt(current.attempt, update.attempt)) {
		return update;
	}
	if (StickyWindowActive(current)) {
		return current;
	}
	return update;
}

} // namespace MTP
