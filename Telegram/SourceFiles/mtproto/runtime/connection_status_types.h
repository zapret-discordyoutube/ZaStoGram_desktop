/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#pragma once

#include "mtproto/runtime/proxy_data.h"

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
	ServerHelloOkNoMtprotoData,
	AppDataRemoteClosed,
	ConnectedNoMtprotoData,
	MtpReceiveTimeoutAfterData,
	ProxyProtocolBadResponse,
};

enum class ConnectionNotice {
	None,
	WssDirectFallback,
};

struct ProxyConnectionAttempt {
	uint64 proxyGeneration = 0;
	uint64 proxyEpoch = 0;
	uint64 successEpoch = 0;
	uint64 attemptId = 0;
	QString connectionId;
	bool probe = false;

	bool operator==(const ProxyConnectionAttempt &other) const {
		return (proxyGeneration == other.proxyGeneration)
			&& (proxyEpoch == other.proxyEpoch)
			&& (successEpoch == other.successEpoch)
			&& (attemptId == other.attemptId)
			&& (connectionId == other.connectionId)
			&& (probe == other.probe);
	}
};

struct ProxyConnectionStatus {
	ProxyConnectionPhase phase = ProxyConnectionPhase::None;
	ProxyConnectionError error = ProxyConnectionError::None;
	ProxyMtproxyTerminalReason mtproxyReason
		= ProxyMtproxyTerminalReason::None;
	ProxyConnectionAttempt attempt;
	crl::time terminalUntil = 0;
	crl::time successUntil = 0;
	ProxyData proxy;

	bool operator==(const ProxyConnectionStatus &other) const {
		return (phase == other.phase)
			&& (error == other.error)
			&& (mtproxyReason == other.mtproxyReason)
			&& (attempt == other.attempt)
			&& (terminalUntil == other.terminalUntil)
			&& (successUntil == other.successUntil)
			&& (proxy == other.proxy);
	}

};

} // namespace MTP
