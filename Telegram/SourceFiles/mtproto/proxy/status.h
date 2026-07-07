/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#pragma once

#include "mtproto/proxy/data.h"

namespace MTP {

enum class ProxyConnectionPhase {
	None,
	Resolving,
	Connecting,
	Handshake,
	CheckingTelegram,
	Connected,
	Failed,
};

enum class ProxyConnectionError {
	None,
	HostNotFound,
	ConnectionRefused,
	Timeout,
	Authentication,
	ProxyProtocol,
	RemoteClosed,
	Network,
	BadResponse,
	Unknown,
};

enum class ProxyMtproxyTerminalReason {
	None,
	DnsFailed,
	TcpConnectTimeout,
	TcpConnectedNoClientHelloWrite,
	ClientHelloSentNoServerHello,
	TlsAlertAfterClientHello,
	ServerHelloHmacMismatch,
	ServerHelloOkNoAppData,
	AppDataRemoteClosed,
	ConnectedNoMtprotoData,
	ProxyProtocolBadResponse,
};

enum class ConnectionNotice {
	None,
	WssDirectFallback,
};

enum class ProxyConnectionStatusKind {
	None,
	Resolving,
	Connecting,
	Handshake,
	CheckingTelegram,
	Connected,
	HostNotFound,
	ConnectionRefused,
	Timeout,
	Authentication,
	ProxyProtocol,
	RemoteClosed,
	Network,
	BadResponse,
	Failed,
	MtproxyDnsFailed,
	MtproxyTcpConnectTimeout,
	MtproxyTcpConnectedNoClientHelloWrite,
	MtproxyNoServerHello,
	MtproxyTlsAlert,
	MtproxyServerHelloHmacMismatch,
	MtproxyServerHelloOkNoAppData,
	MtproxyAppDataRemoteClosed,
	MtproxyProxyProtocolBadResponse,
};

enum class ProxyConnectionStatusSeverity {
	None,
	Progress,
	Success,
	Warning,
	Error,
};

enum class ProxyConnectionStatusTone {
	None,
	Progress,
	Success,
	Warning,
	Error,
	ErrorDns,
	ErrorTimeout,
	ErrorNetwork,
	ErrorProtocol,
	ErrorAuth,
	ErrorHandshake,
	ErrorData,
};

struct ProxyConnectionAttempt {
	uint64 proxyEpoch = 0;
	uint64 attemptId = 0;
	QString connectionId;

	bool operator==(const ProxyConnectionAttempt &other) const {
		return (proxyEpoch == other.proxyEpoch)
			&& (attemptId == other.attemptId)
			&& (connectionId == other.connectionId);
	}
};

struct ProxyConnectionStatus {
	ProxyConnectionPhase phase = ProxyConnectionPhase::None;
	ProxyConnectionError error = ProxyConnectionError::None;
	ProxyMtproxyTerminalReason mtproxyReason
		= ProxyMtproxyTerminalReason::None;
	ProxyConnectionAttempt attempt;
	crl::time terminalUntil = 0;
	ProxyData proxy;

	bool operator==(const ProxyConnectionStatus &other) const {
		return (phase == other.phase)
			&& (error == other.error)
			&& (mtproxyReason == other.mtproxyReason)
			&& (attempt == other.attempt)
			&& (terminalUntil == other.terminalUntil)
			&& (proxy == other.proxy);
	}

};

[[nodiscard]] bool IsMtproxyTerminalFailure(
	ProxyMtproxyTerminalReason reason);
[[nodiscard]] ProxyConnectionStatusKind ProxyConnectionStatusKindFor(
	const ProxyConnectionStatus &status);
[[nodiscard]] ProxyConnectionStatusSeverity ProxyConnectionStatusSeverityFor(
	ProxyConnectionStatusKind kind);
[[nodiscard]] ProxyConnectionStatusSeverity ProxyConnectionStatusSeverityFor(
	const ProxyConnectionStatus &status);
[[nodiscard]] ProxyConnectionStatusTone ProxyConnectionStatusToneFor(
	ProxyConnectionStatusKind kind);
[[nodiscard]] ProxyConnectionStatusTone ProxyConnectionStatusToneFor(
	const ProxyConnectionStatus &status);
[[nodiscard]] ProxyConnectionStatus ApplyProxyConnectionStatusUpdate(
	const ProxyConnectionStatus &current,
	ProxyConnectionStatus update);

} // namespace MTP
