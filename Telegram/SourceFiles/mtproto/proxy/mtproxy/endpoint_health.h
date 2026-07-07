/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#pragma once

#include "mtproto/proxy/mtproxy/endpoint_identity.h"

#include <rpl/producer.h>

namespace MTP::details::MtProxy {

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
	[[nodiscard]] uint64 proxyGeneration() const;
	[[nodiscard]] uint64 proxyEpoch() const;
	[[nodiscard]] uint64 successEpoch() const;
	[[nodiscard]] crl::time startedAt() const;

private:
	friend class EndpointHealth;

	EndpointAttemptLease(
		QString key,
		uint64 attemptId,
		uint64 proxyGeneration,
		uint64 proxyEpoch,
		uint64 successEpoch,
		crl::time startedAt);

	QString _key;
	uint64 _attemptId = 0;
	uint64 _proxyGeneration = 0;
	uint64 _proxyEpoch = 0;
	uint64 _successEpoch = 0;
	crl::time _startedAt = 0;
	bool _active = false;
};

struct AdmissionRequest {
	EndpointId endpoint;
	EndpointUse use = EndpointUse::Main;
	ProxyStealthOptions stealth;
	ProxyTlsProfile configuredTlsProfile = ProxyTlsProfile::Auto;
	uint64 proxyGeneration = 0;
};

struct Admission {
	AdmissionAction action = AdmissionAction::StartNow;
	crl::time retryAfter = 0;
	FailureReason blockedBy = FailureReason::None;
	ProxyStealthOptions stealth;
	ProxyTlsProfile effectiveTlsProfile = ProxyTlsProfile::Auto;
	EndpointAttemptLease lease;
	uint64 proxyGeneration = 0;
	uint64 attemptId = 0;
	uint64 proxyEpoch = 0;
	uint64 successEpoch = 0;
	crl::time attemptStartedAt = 0;
};

struct FailureReport {
	EndpointId endpoint;
	EndpointUse use = EndpointUse::Main;
	FailureReason reason = FailureReason::None;
	ProxyTlsProfile configuredTlsProfile = ProxyTlsProfile::Auto;
	ProxyTlsProfile sentProfile = ProxyTlsProfile::Auto;
	EndpointAttemptLease *lease = nullptr;
	uint64 proxyGeneration = 0;
	uint64 attemptId = 0;
	uint64 proxyEpoch = 0;
	uint64 successEpoch = 0;
	crl::time attemptStartedAt = 0;

	// Every resolved route of the endpoint has been tried and failed.
	// Route-only reasons (e.g. tcp connect timeout) normally leave the
	// canonical endpoint untouched so other routes can be tried, but with
	// no routes left the canonical must degrade or a fully blackholed
	// proxy never gets a cooldown and never triggers rotation.
	bool routesExhausted = false;
};

// Success evidence comes from two different layers with different meaning.
// Handshake: the proxy accepted our TCP/TLS handshake. FakeTlsAppData: the
// server sent the first FakeTLS app-data frame. Both prove the fingerprint
// and route, so they may reset recipe escalation - but they say nothing
// about whether Telegram data actually flows through the relay.
// Relay: an MTProto payload was actually received through the proxy. Only
// this proves the endpoint end-to-end and may clear a relay-silence cooldown;
// otherwise every reconnect of a dead relay would repaint the endpoint green
// and the sessions would hammer it forever.
enum class SuccessScope {
	Handshake,
	FakeTlsAppData,
	Relay,
};

struct SuccessReport {
	EndpointId endpoint;
	EndpointUse use = EndpointUse::Main;
	ProxyStealthOptions stealth;
	ProxyTlsProfile sentProfile = ProxyTlsProfile::Auto;
	EndpointAttemptLease *lease = nullptr;
	uint64 proxyGeneration = 0;
	uint64 attemptId = 0;
	uint64 proxyEpoch = 0;
	uint64 successEpoch = 0;
	crl::time attemptStartedAt = 0;
	SuccessScope scope = SuccessScope::Handshake;
};

struct RelayStallReport {
	EndpointId endpoint;
	EndpointUse use = EndpointUse::Main;
	uint64 proxyGeneration = 0;
	uint64 attemptId = 0;
	uint64 proxyEpoch = 0;
	uint64 successEpoch = 0;
	crl::time attemptStartedAt = 0;
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
	uint64 successEpoch = 0;
	crl::time lastRelaySuccessAt = 0;
	ProxyTlsProfile lastGoodProfile = ProxyTlsProfile::Auto;
	RouteEndpoint lastGoodRoute;
	bool relayProven = false;
	uint64 proxyGeneration = 0;
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
	void noteRelayStall(RelayStallReport report);
	[[nodiscard]] Snapshot snapshot(const EndpointId &endpoint) const;
	[[nodiscard]] rpl::producer<EndpointEvent> changes() const;

private:
	friend class EndpointAttemptLease;

	void releaseAttempt(const QString &key, uint64 attemptId);
};

[[nodiscard]] crl::time ConnectionSpacing(ProxyConnectionPattern pattern);

} // namespace MTP::details::MtProxy
