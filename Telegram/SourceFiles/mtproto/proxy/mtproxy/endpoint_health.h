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

#include <compare>
#include <memory>
#include <optional>

namespace MTP {
class ProxyEndpointContext;
class RuntimeEnvironment;
} // namespace MTP

namespace MTP::details::MtProxy {

struct EndpointContextStorage;

using EndpointUse = ProxyConnectionUse;

struct MainRecoveryTokenAccess;

class MainRecoveryToken final {
public:
	MainRecoveryToken() = default;

	[[nodiscard]] explicit operator bool() const {
		return _id != 0;
	}
	[[nodiscard]] bool operator!() const {
		return !_id;
	}

	friend inline bool operator==(
		MainRecoveryToken,
		MainRecoveryToken) = default;

private:
	friend struct MainRecoveryTokenAccess;

	uint64 _id = 0;

};

enum class MainRecoveryStage {
	TransportBackoff,
	AdmissionTicket,
	ReplacementAttempt,
};

enum class MainRelayProofStrength {
	None,
	SinglePayload,
	RepeatedPayload,
};

enum class EndpointVerdictScope {
	None,
	Attempt,
	Endpoint,
};

enum class EndpointVerdictCause {
	None,
	Transport,
	RelayLiveness,
	Admission,
	Recovery,
};

struct EndpointVerdict {
	ProxyConnectionAttempt sourceAttempt;
	RuntimeGenerationKey runtimeGeneration;
	EndpointVerdictScope scope = EndpointVerdictScope::None;
	EndpointVerdictCause cause = EndpointVerdictCause::None;
	FailureReason reason = FailureReason::None;
	ProxyFailureAttribution attribution = ProxyFailureAttribution::None;
	int confidence = 0;
	crl::time observedAt = 0;
	crl::time terminalAt = 0;
	crl::time retryUntil = 0;

	bool operator==(const EndpointVerdict &other) const = default;
};

struct MainRelayProofView {
	MainRelayProofStrength strength = MainRelayProofStrength::None;
	crl::time provenAt = 0;
	crl::time lastPayloadAt = 0;
	int payloadCount = 0;

	bool operator==(const MainRelayProofView &other) const = default;
};

struct MainRecoveryView {
	MainRecoveryToken token;
	RuntimeGenerationKey runtimeGeneration;
	ProxyConnectionAttempt sourceAttempt;
	crl::time createdAt = 0;
	MainRecoveryStage stage = MainRecoveryStage::TransportBackoff;
	AdmissionTicketKey adoptedTicketKey;
	uint64 replacementAttemptId = 0;

	bool operator==(const MainRecoveryView &other) const = default;
};

struct ProxyEndpointView {
	EndpointId endpoint;
	ProxyConnectionAttempt mainAttempt;
	std::optional<EndpointVerdict> canonicalVerdict;
	RuntimeGenerationKey runtimeGeneration;
	AdmissionTicketKey ticketKey;
	MainRelayProofView mainProof;
	std::optional<MainRecoveryView> mainRecovery;
	MainRelayProofView endpointMainProof;
	ProxySchedulerLifecycle schedulerLifecycle
		= ProxySchedulerLifecycle::None;
	ProxyAdmissionPhase admissionPhase = ProxyAdmissionPhase::Idle;
	ProxyConnectionPhase networkPhase = ProxyConnectionPhase::None;
	crl::time enqueuedAt = 0;
	crl::time scheduledOpenAt = 0;
	crl::time attemptStartedAt = 0;
	crl::time phaseStartedAt = 0;
	crl::time terminalAt = 0;
	crl::time retryUntil = 0;

	bool operator==(const ProxyEndpointView &other) const = default;
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
	void transportReady();
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
	AdmissionTicketKey ticketKey;
	ProxyFailureAttribution attribution = ProxyFailureAttribution::None;
	crl::time terminalAt = 0;
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
	AdmissionTicketKey ticketKey;
	crl::time payloadAt = 0;
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
	AdmissionTicketKey ticketKey;
	crl::time lastPayloadAt = 0;
};

class EndpointHealth final {
public:
	EndpointHealth(
		not_null<RuntimeEnvironment*> runtime,
		std::shared_ptr<ProxyEndpointContext> context);
	EndpointHealth(const EndpointHealth &other) = delete;
	EndpointHealth &operator=(const EndpointHealth &other) = delete;
	~EndpointHealth();

	[[nodiscard]] static std::optional<Admission> BeginScheduledAttemptLocked(
		EndpointContextStorage &storage,
		std::shared_ptr<ProxyEndpointContext> context,
		const AdmissionRequest &request,
		AdmissionTicketKey ticketKey,
		ProxyTraceId traceId,
		crl::time enqueuedAt,
		crl::time scheduledOpenAt,
		crl::time attemptStartedAt);
	void reportFailure(FailureReport report);
	void reportSuccess(SuccessReport report);
	void noteRelayStall(
		RelayProofReport report,
		MainRecoveryToken &recoveryToken);
	void cancelMainRecoveryBackoff(
		const EndpointId &endpoint,
		RuntimeGenerationKey runtimeGeneration,
		MainRecoveryToken token);
	void retireRelayProof(RelayProofReport report);
	void noteEndpointSelected(const EndpointId &endpoint);
	void applyProxyGeneration(uint64 proxyGeneration);

private:
	static void ResolveLeaseIdentity(FailureReport &report);
	static void ResolveLeaseIdentity(SuccessReport &report);

	const not_null<RuntimeEnvironment*> _runtime;
	const std::shared_ptr<ProxyEndpointContext> _context;
	const ProxyRuntimeId _runtimeId = 0;

};

[[nodiscard]] crl::time ConnectionSpacing(ProxyConnectionPattern pattern);

} // namespace MTP::details::MtProxy
