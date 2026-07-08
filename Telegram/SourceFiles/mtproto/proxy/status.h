/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#pragma once

#include "mtproto/runtime/connection_status_types.h"

namespace MTP {

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
	MtproxyConnectedNoMtprotoData,
	MtproxyAppDataRemoteClosed,
	MtproxyMtpReceiveTimeoutAfterData,
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

} // namespace MTP
