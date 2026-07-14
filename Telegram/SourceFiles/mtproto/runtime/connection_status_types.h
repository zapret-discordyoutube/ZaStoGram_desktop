/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#pragma once

#include "mtproto/runtime/proxy_data.h"

#include <compare>
#include <optional>

namespace MTP {

using ProxyRuntimeId = uint64;
using ProxyTraceId = uint64;

struct AdmissionTicketKey {
	ProxyRuntimeId runtimeId = 0;
	uint64 ticketId = 0;

	friend inline auto operator<=>(
		AdmissionTicketKey,
		AdmissionTicketKey) = default;
};

struct RuntimeGenerationKey {
	ProxyRuntimeId runtimeId = 0;
	uint64 proxyGeneration = 0;

	friend inline auto operator<=>(
		RuntimeGenerationKey,
		RuntimeGenerationKey) = default;
};

enum class ProxyConnectionUse {
	Main,
	Maintenance,
	Auxiliary,
	Media,
	Upload,
	ProxyCheck,
};

enum class ProxySchedulerLifecycle {
	None,
	Queued,
	Scheduled,
	Granted,
	HandedOff,
	Cancelled,
};

enum class ProxyAdmissionPhase {
	Idle,
	Queued,
	Scheduled,
	Resolving,
	Tcp,
	FakeTls,
};

[[nodiscard]] inline bool IsProxyCheck(ProxyConnectionUse use) {
	return use == ProxyConnectionUse::ProxyCheck;
}

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

enum class ProxyCloseOrigin {
	None,
	PeerClosed,
	LocalTimeout,
	RouteRaceLost,
	BrokerCancelled,
	ProxySwitch,
	OwnerDestroyed,
	NetworkError,
	ProtocolRejected,
};

enum class ProxyFailureAttribution {
	None,
	Unclear,
	Local,
	Client,
	Peer,
	Network,
};

struct ProxyTransportFailure {
	ProxyMtproxyTerminalReason reason = ProxyMtproxyTerminalReason::None;
	ProxyConnectionError error = ProxyConnectionError::None;
	ProxyCloseOrigin closeOrigin = ProxyCloseOrigin::None;
	QString parserStage;
	std::optional<qint64> rxAfterClientHello;
	QString rxClass;
	QString block; // no-ServerHello verdict, "slug:attribution" (see below)
	QString tlsRecordType;
	QString tlsRecordVersion;
	std::optional<int> tlsRecordLength;
	QString responsePrefixHash;
	std::optional<int> sniLength;
	QString sniHash;
	std::optional<int> clientHelloBytes;
	std::optional<int> clientHelloWrites;
	std::optional<qint64> clientHelloAcceptedBytes;
	std::optional<ProxyTlsProfile> sentTlsProfile;
	std::optional<bool> pskOffered;
	std::optional<bool> fragmentedClientHello;
	std::optional<int> clientHelloFragmentSplit;
	std::optional<crl::time> clientHelloFragmentDelayMs;
	std::optional<crl::time> dnsMs;
	std::optional<crl::time> tcpMs;
	std::optional<crl::time> firstRxMs;
	std::optional<crl::time> serverHelloMs;
	std::optional<crl::time> appDataMs;
	bool livenessReported = false;
	ProxyFailureAttribution attribution = ProxyFailureAttribution::None;
};

struct MtProxyAttemptPlan {
	bool admitted = false;
	int recipeLevel = 0;
	ProxyTlsProfile configuredTlsProfile = ProxyTlsProfile::Auto;
	ProxyTlsProfile effectiveTlsProfile = ProxyTlsProfile::Auto;
	ProxyStealthOptions stealth;
	crl::time serverHelloTimeout = 0;
};

struct ProxyConnectionAttempt {
	ProxyRuntimeId runtimeId = 0;
	ProxyTraceId traceId = 0;
	uint64 ticketId = 0;
	uint64 routeAttemptId = 0;
	uint64 proxyGeneration = 0;
	uint64 proxyEpoch = 0;
	uint64 successEpoch = 0;
	uint64 attemptId = 0;
	QString connectionId;
	ProxyConnectionUse use = ProxyConnectionUse::Main;
	AdmissionTicketKey ticketKey;

	bool operator==(const ProxyConnectionAttempt &other) const {
		return (runtimeId == other.runtimeId)
			&& (traceId == other.traceId)
			&& (ticketId == other.ticketId)
			&& (routeAttemptId == other.routeAttemptId)
			&& (proxyGeneration == other.proxyGeneration)
			&& (proxyEpoch == other.proxyEpoch)
			&& (successEpoch == other.successEpoch)
			&& (attemptId == other.attemptId)
			&& (connectionId == other.connectionId)
			&& (use == other.use)
			&& (ticketKey == other.ticketKey);
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
