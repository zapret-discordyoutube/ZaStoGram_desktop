/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#pragma once

#include "base/basic_types.h"
#include "mtproto/proxy/mtproxy/endpoint_identity.h"
#include "mtproto/runtime/connection_status_types.h"

#include <rpl/producer.h>

#include <memory>

namespace MTP {
class ProxyEndpointContext;
class RuntimeEnvironment;
} // namespace MTP

namespace MTP::details::MtProxy {

using EndpointUse = ProxyConnectionUse;

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
	void releaseAdmissionForRelayCandidate();
	[[nodiscard]] bool active() const;
	[[nodiscard]] ProxyRuntimeId runtimeId() const;
	[[nodiscard]] uint64 attemptId() const;
	[[nodiscard]] uint64 proxyGeneration() const;
	[[nodiscard]] uint64 proxyEpoch() const;
	[[nodiscard]] uint64 successEpoch() const;
	[[nodiscard]] crl::time startedAt() const;
	[[nodiscard]] const QString &endpointKey() const;

private:
	friend class EndpointHealth;

	EndpointAttemptLease(
		std::shared_ptr<ProxyEndpointContext> context,
		QString key,
		ProxyRuntimeId runtimeId,
		uint64 attemptId,
		uint64 proxyGeneration,
		uint64 proxyEpoch,
		uint64 successEpoch,
		crl::time startedAt);

	std::shared_ptr<ProxyEndpointContext> _context;
	QString _key;
	ProxyRuntimeId _runtimeId = 0;
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
	ProxyRuntimeId runtimeId = 0;
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
	MtProxyAttemptPlan plan;
	EndpointAttemptLease lease;
	ProxyRuntimeId runtimeId = 0;
	uint64 proxyGeneration = 0;
	uint64 attemptId = 0;
	uint64 proxyEpoch = 0;
	uint64 successEpoch = 0;
	crl::time attemptStartedAt = 0;
};

struct FailureReport {
	EndpointId endpoint;
	EndpointUse use = EndpointUse::Main;
	ProxyRuntimeId runtimeId = 0;
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
// server sent the first FakeTLS app-data frame. Both are partial evidence:
// neither may reset recipe escalation, relay health, or its cooldown because
// they say nothing about whether Telegram data flows through the relay.
// Relay: a valid Telegram response crossed the proxy, either the transport
// resPQ probe or a session payload. Only this proves the endpoint end-to-end
// and may clear a relay-silence cooldown; otherwise a dead relay would be
// repainted green after every successful FakeTLS handshake.
enum class SuccessScope {
	Handshake,
	FakeTlsAppData,
	Relay,
};

struct SuccessReport {
	EndpointId endpoint;
	EndpointUse use = EndpointUse::Main;
	ProxyRuntimeId runtimeId = 0;
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

struct RelayProofReport {
	EndpointId endpoint;
	EndpointUse use = EndpointUse::Main;
	ProxyRuntimeId runtimeId = 0;
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
	EndpointHealth(
		not_null<RuntimeEnvironment*> runtime,
		std::shared_ptr<ProxyEndpointContext> context);
	EndpointHealth(const EndpointHealth &other) = delete;
	EndpointHealth &operator=(const EndpointHealth &other) = delete;
	~EndpointHealth();

	[[nodiscard]] Admission admit(const AdmissionRequest &request);
	void reportFailure(FailureReport report);
	void reportSuccess(SuccessReport report);
	void noteRelayStall(RelayProofReport report);
	void retireRelayProof(RelayProofReport report);
	void noteEndpointSelected(const EndpointId &endpoint);
	void applyProxyGeneration(uint64 proxyGeneration);
	[[nodiscard]] Snapshot snapshot(const EndpointId &endpoint) const;
	[[nodiscard]] rpl::producer<EndpointEvent> changes() const;

private:
	void fireEndpointEventOnMain(EndpointEvent event);

	const not_null<RuntimeEnvironment*> _runtime;
	const std::shared_ptr<ProxyEndpointContext> _context;
	const ProxyRuntimeId _runtimeId = 0;

};

[[nodiscard]] crl::time ConnectionSpacing(ProxyConnectionPattern pattern);

} // namespace MTP::details::MtProxy
