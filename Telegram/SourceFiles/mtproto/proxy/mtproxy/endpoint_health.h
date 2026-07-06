/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#pragma once

#include "base/bytes.h"
#include "mtproto/proxy/data.h"
#include "mtproto/proxy/status.h"

#include <rpl/producer.h>

namespace MTP::details::MtProxy {

enum class FailureReason {
	None,
	DnsFailed,
	TcpConnectTimeout,
	TcpConnectedNoClientHelloWrite,
	ClientHelloSentNoServerHello,
	TlsAlertAfterClientHello,
	ServerHelloHmacMismatch,
	ServerHelloOkNoAppData,
	AppDataRemoteClosed,
	Network,
	ProxyProtocolBadResponse,
};

enum class EndpointUse {
	Main,
	Media,
	Upload,
	ProxyCheck,
};

enum class AdmissionAction {
	StartNow,
	StartAfter,
	Queued,
	SkipCooldown,
};

enum class RouteAddressFamily {
	Unknown,
	Host,
	IPv4,
	IPv6,
};

struct CanonicalProxyEndpoint {
	ProxyData::Type type = ProxyData::Type::None;
	QString originalHost;
	int port = 0;
	QString secretHash;
	QString domainFromSecret;
	ProxyData::Type proxyKind = ProxyData::Type::None;

	bool operator==(const CanonicalProxyEndpoint &other) const {
		return (type == other.type)
			&& (originalHost == other.originalHost)
			&& (port == other.port)
			&& (secretHash == other.secretHash)
			&& (domainFromSecret == other.domainFromSecret)
			&& (proxyKind == other.proxyKind);
	}
};

struct RouteEndpoint {
	QString address;
	int port = 0;
	RouteAddressFamily addressFamily = RouteAddressFamily::Unknown;
	ProxyTransport transport = ProxyTransport::Tcp;
	QString resolvedFromHost;

	bool operator==(const RouteEndpoint &other) const {
		return (address == other.address)
			&& (port == other.port)
			&& (addressFamily == other.addressFamily)
			&& (transport == other.transport)
			&& (resolvedFromHost == other.resolvedFromHost);
	}
};

struct EndpointId {
	CanonicalProxyEndpoint canonical;
	RouteEndpoint route;

	bool operator==(const EndpointId &other) const {
		return (canonical == other.canonical)
			&& (route == other.route);
	}
};

class EndpointHealth;

class EndpointAttemptLease final {
public:
	EndpointAttemptLease() = default;
	EndpointAttemptLease(const EndpointAttemptLease &other) = delete;
	EndpointAttemptLease &operator=(const EndpointAttemptLease &other) = delete;
	EndpointAttemptLease(EndpointAttemptLease &&other) noexcept;
	EndpointAttemptLease &operator=(EndpointAttemptLease &&other) noexcept;
	~EndpointAttemptLease();

	void release();
	[[nodiscard]] bool active() const;
	[[nodiscard]] uint64 attemptId() const;
	[[nodiscard]] uint64 proxyEpoch() const;

private:
	friend class EndpointHealth;

	EndpointAttemptLease(
		QString key,
		uint64 attemptId,
		uint64 proxyEpoch);

	QString _key;
	uint64 _attemptId = 0;
	uint64 _proxyEpoch = 0;
	bool _active = false;
};

struct AdmissionRequest {
	EndpointId endpoint;
	EndpointUse use = EndpointUse::Main;
	ProxyStealthOptions stealth;
	ProxyTlsProfile configuredTlsProfile = ProxyTlsProfile::Auto;
};

struct Admission {
	AdmissionAction action = AdmissionAction::StartNow;
	crl::time retryAfter = 0;
	FailureReason blockedBy = FailureReason::None;
	ProxyStealthOptions stealth;
	ProxyTlsProfile effectiveTlsProfile = ProxyTlsProfile::Auto;
	EndpointAttemptLease lease;
	uint64 attemptId = 0;
	uint64 proxyEpoch = 0;
};

struct FailureReport {
	EndpointId endpoint;
	EndpointUse use = EndpointUse::Main;
	FailureReason reason = FailureReason::None;
	ProxyTlsProfile configuredTlsProfile = ProxyTlsProfile::Auto;
	ProxyTlsProfile sentProfile = ProxyTlsProfile::Auto;
	EndpointAttemptLease *lease = nullptr;
};

struct SuccessReport {
	EndpointId endpoint;
	EndpointUse use = EndpointUse::Main;
	ProxyStealthOptions stealth;
	ProxyTlsProfile sentProfile = ProxyTlsProfile::Auto;
	EndpointAttemptLease *lease = nullptr;
};

struct Snapshot {
	EndpointId endpoint;
	FailureReason lastFailure = FailureReason::None;
	QString lastDiagnostic;
	crl::time terminalUntil = 0;
	int active = 0;
	int consecutiveFailures = 0;
	int recipeLevel = 0;
	bool healthy = false;
	bool halfOpen = false;
	uint64 proxyEpoch = 0;
	uint64 attemptId = 0;
};

struct EndpointEvent {
	EndpointId endpoint;
	FailureReason reason = FailureReason::None;
	crl::time terminalUntil = 0;
	bool rotationAllowed = false;
};

class EndpointHealth final {
public:
	[[nodiscard]] static EndpointHealth &Instance();

	[[nodiscard]] Admission admit(const AdmissionRequest &request);
	void reportFailure(FailureReport report);
	void reportSuccess(SuccessReport report);
	[[nodiscard]] Snapshot snapshot(const EndpointId &endpoint) const;
	[[nodiscard]] rpl::producer<EndpointEvent> changes() const;

private:
	friend class EndpointAttemptLease;

	void releaseAttempt(const QString &key, uint64 attemptId);
};

[[nodiscard]] EndpointId EndpointIdFromProxy(
	const ProxyData &proxy,
	const ProxyStealthOptions &stealth,
	const QString &address = QString(),
	int port = 0);
[[nodiscard]] EndpointId EndpointIdFromAddress(
	const QString &address,
	int port,
	bytes::const_span secret,
	ProxyTransport transport);
[[nodiscard]] RouteEndpoint RouteEndpointFromAddress(
	const QString &address,
	int port,
	ProxyTransport transport,
	const QString &resolvedFromHost = QString());
[[nodiscard]] bool EndpointEmpty(const CanonicalProxyEndpoint &endpoint);
[[nodiscard]] bool EndpointEmpty(const EndpointId &endpoint);
[[nodiscard]] QString EndpointKey(const CanonicalProxyEndpoint &endpoint);
[[nodiscard]] QString EndpointKey(const EndpointId &endpoint);

// Key for ProxyCapabilityCache cards, matching ProxyCapabilityKey(proxy)
// so that cards written from endpoint health reports are found by
// ProxyCapabilityCache::lookup(proxy). Distinct from EndpointKey, which
// keys the in-memory health state and diagnostics.
[[nodiscard]] QString CapabilityProxyKey(const CanonicalProxyEndpoint &endpoint);
[[nodiscard]] QString RouteKey(const RouteEndpoint &route);
[[nodiscard]] QString RouteKey(const EndpointId &endpoint);
[[nodiscard]] QString ToLegacyDiagnostic(FailureReason reason);
[[nodiscard]] FailureReason FailureReasonFromErrorCode(int errorCode);
[[nodiscard]] ProxyConnectionError ToProxyConnectionError(
	FailureReason reason);
[[nodiscard]] ProxyMtproxyTerminalReason ToProxyMtproxyTerminalReason(
	FailureReason reason);
[[nodiscard]] crl::time ConnectionSpacing(ProxyConnectionPattern pattern);

} // namespace MTP::details::MtProxy
