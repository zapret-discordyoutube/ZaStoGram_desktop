/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "mtproto/proxy/mtproxy/endpoint_health_policy.h"

#include <algorithm>

namespace MTP::details::MtProxy {
namespace {

constexpr auto kFirstCooldown = crl::time(15 * 1000);
constexpr auto kSecondCooldown = crl::time(45 * 1000);
constexpr auto kMaxCooldown = crl::time(120 * 1000);
constexpr auto kDnsNegativeTtl = crl::time(30 * 1000);
constexpr auto kColdActiveCap = 1;
constexpr auto kUnknownActiveCap = kColdActiveCap;
constexpr auto kDpiFailureActiveCap = 1;
constexpr auto kHealthyActiveCap = 1;
constexpr auto kFastHealthyActiveCap = 2;
constexpr auto kHealthyHandshakeSpacing = crl::time(500);
constexpr auto kQueuedRetry = crl::time(1000);
constexpr auto kAttemptHardTtl = crl::time(120 * 1000);
constexpr auto kRecentRelaySuccessWindow = crl::time(60 * 1000);
constexpr auto kThrottledRetryCooldown = crl::time(3000);
constexpr auto kNoAppDataSoftRetry = crl::time(1000);
constexpr auto kNoAppDataWarningCooldown = crl::time(3000);

} // namespace

MtProxyAttemptPlan BuildAttemptPlan(
		const AdmissionRequest &request,
		int recipeLevel) {
	auto plan = MtProxyAttemptPlan();
	plan.admitted = true;
	plan.recipeLevel = std::clamp(recipeLevel, 0, 2);
	plan.configuredTlsProfile = request.configuredTlsProfile;
	plan.effectiveTlsProfile = ProxyTlsProfile::ChromeModern;
	plan.stealth = request.stealth;
	plan.stealth.level = (plan.recipeLevel == 0)
		? ProxyStealthLevel::CompatStrict
		: (plan.recipeLevel == 1)
		? ProxyStealthLevel::CompatModern
		: ProxyStealthLevel::DpiAdaptiveHandshake;
	plan.stealth.tlsProfile = plan.effectiveTlsProfile;
	plan.stealth.clientHelloFragmentation = (plan.recipeLevel >= 2)
		? ProxyClientHelloFragmentation::Soft
		: ProxyClientHelloFragmentation::Off;
	plan.stealth.connectionPattern = (plan.recipeLevel >= 1)
		? ProxyConnectionPattern::Soft
		: ProxyConnectionPattern::Off;
	plan.stealth.recordSizing = ProxyRecordSizing::Off;
	plan.stealth.timing = ProxyTiming::Off;
	plan.stealth.startupCover = ProxyStartupCover::Off;
	plan.stealth.syntheticPsk = false;
	return plan;
}

FailureTraits TraitsFor(FailureReason reason) {
	switch (reason) {
	case FailureReason::None:
		return {};
	case FailureReason::DnsFailed:
		return {
			.needsCooldown = true,
		};
	case FailureReason::TcpConnectTimeout:
		// The route never answered: blame the route, not the canonical
		// endpoint - other routes may still work.
		return {
			.routeOnly = true,
			.canBeStale = true,
		};
	case FailureReason::TcpConnectedNoClientHelloWrite:
		return {
			.routeOnly = true,
			.canBeStale = true,
		};
	case FailureReason::ClientHelloSentNoServerHello:
		// The server (or a DPI box in front of it) refused our handshake
		// fingerprint: cool down, mutate the recipe, rotate TLS profile.
		return {
			.needsCooldown = true,
			.escalatesRecipe = true,
			.rotatesTls = true,
			.canBeStale = true,
		};
	case FailureReason::TlsAlertAfterClientHello:
		return {
			.needsCooldown = true,
			.escalatesRecipe = true,
			.rotatesTls = true,
			.canBeStale = true,
		};
	case FailureReason::ServerHelloHmacMismatch:
		return {
			.needsCooldown = true,
			.escalatesRecipe = true,
			.rotatesTls = true,
			.canBeStale = true,
		};
	case FailureReason::ServerHelloOkNoAppData:
		// The server accepted our ClientHello (HMAC verified) and the
		// stall is downstream - the proxy's own link to the DC. Mutating
		// the ClientHello cannot fix that; escalated recipes
		// (fragmentation, pacing, spacing) only add latency and can
		// break a FakeTLS front that was answering fine, turning a slow
		// relay into client_hello_sent_no_server_hello. Escalate only on
		// failures that actually implicate the handshake fingerprint.
		return {
			.needsCooldown = true,
			.invalidatesRelayCapability = true,
			.canBeStale = true,
		};
	case FailureReason::ServerHelloOkNoMtprotoData:
		return {
			.needsCooldown = true,
			.invalidatesRelayCapability = true,
			.canBeStale = true,
		};
	case FailureReason::AppDataRemoteClosed:
		return {};
	case FailureReason::ConnectedNoMtprotoData:
		// Even further downstream than ServerHelloOkNoAppData: the
		// handshake and even the plaintext transport check passed, so
		// the fingerprint is definitely not the problem - cool down and
		// distrust the relay, never touch the recipe.
		return {
			.needsCooldown = true,
			.invalidatesRelayCapability = true,
			.canBeStale = true,
		};
	case FailureReason::MtpReceiveTimeoutAfterData:
		return {
			.invalidatesRelayCapability = true,
			.canBeStale = true,
		};
	case FailureReason::Network:
		return {};
	case FailureReason::ProxyProtocolBadResponse:
		return {
			.needsCooldown = true,
		};
	}
	return {};
}

[[nodiscard]] bool FailureNeedsCooldown(FailureReason reason) {
	return TraitsFor(reason).needsCooldown;
}

[[nodiscard]] bool FailureNeedsRecipeEscalation(FailureReason reason) {
	return TraitsFor(reason).escalatesRecipe;
}

[[nodiscard]] bool FailureNeedsTlsRotation(FailureReason reason) {
	return TraitsFor(reason).rotatesTls;
}

[[nodiscard]] bool FailureIsRouteOnly(FailureReason reason) {
	return TraitsFor(reason).routeOnly;
}

[[nodiscard]] bool RelayFailureInvalidatesCapability(FailureReason reason) {
	return TraitsFor(reason).invalidatesRelayCapability;
}

[[nodiscard]] bool FailureCanBeStale(FailureReason reason) {
	return TraitsFor(reason).canBeStale;
}

[[nodiscard]] bool RecentRelaySuccess(
		const EndpointState &state,
		crl::time now) {
	return state.lastRelaySuccessAt
		&& (now - state.lastRelaySuccessAt < kRecentRelaySuccessWindow);
}

[[nodiscard]] bool SoftNoAppDataFailure(
		const EndpointState &state,
		FailureReason reason,
		crl::time now) {
	return (reason == FailureReason::ServerHelloOkNoAppData)
		&& RecentRelaySuccess(state, now);
}

crl::time NoAppDataSoftRetry() {
	return kNoAppDataSoftRetry;
}

crl::time ThrottledRetryCooldown() {
	return kThrottledRetryCooldown;
}

[[nodiscard]] bool NoAppDataWarningStrike(
		FailureReason reason,
		int consecutiveFailures) {
	return (reason == FailureReason::ServerHelloOkNoAppData)
		&& (consecutiveFailures <= 3);
}

[[nodiscard]] crl::time AttemptStartedAt(
		const FailureReport &report,
		const EndpointState &state) {
	if (report.attemptStartedAt) {
		return report.attemptStartedAt;
	}
	if (report.lease && report.lease->startedAt()) {
		return report.lease->startedAt();
	}
	const auto attemptId = report.attemptId
		? report.attemptId
		: report.lease
		? report.lease->attemptId()
		: uint64();
	if (!attemptId) {
		return 0;
	}
	const auto i = state.attemptStarts.find(attemptId);
	return (i != end(state.attemptStarts))
		? i->second.startedAt
		: crl::time();
}

[[nodiscard]] crl::time AttemptStartedAt(
		const SuccessReport &report,
		const EndpointState &state) {
	if (report.attemptStartedAt) {
		return report.attemptStartedAt;
	}
	if (report.lease && report.lease->startedAt()) {
		return report.lease->startedAt();
	}
	const auto attemptId = report.attemptId
		? report.attemptId
		: report.lease
		? report.lease->attemptId()
		: uint64();
	if (!attemptId) {
		return 0;
	}
	const auto i = state.attemptStarts.find(attemptId);
	return (i != end(state.attemptStarts))
		? i->second.startedAt
		: crl::time();
}

[[nodiscard]] bool ReportEpochIsStale(
		uint64 proxyEpoch,
		const EndpointState &state) {
	return proxyEpoch && proxyEpoch < state.proxyEpoch;
}

[[nodiscard]] bool ReportSuccessEpochIsStale(
		uint64 successEpoch,
		const EndpointState &state) {
	return state.successEpoch && successEpoch < state.successEpoch;
}

void ApplyProxyGeneration(
		EndpointState &state,
		ProxyRuntimeId runtimeId,
		uint64 proxyGeneration) {
	ApplyRuntimeProxyGeneration(state, runtimeId, proxyGeneration);
}

[[nodiscard]] bool FailureFromStaleAttempt(
		const FailureReport &report,
		const EndpointState &state) {
	if (RuntimeProxyGenerationIsStale(
			state,
			report.runtimeId,
			report.proxyGeneration)) {
		return true;
	}
	const auto identity = RelayProofIdentity{
		.runtimeId = report.runtimeId,
		.proxyGeneration = report.proxyGeneration,
		.attemptId = report.attemptId,
	};
	if (HasRelayProof(state, identity)) {
		return false;
	}
	if (ReportEpochIsStale(report.proxyEpoch, state)) {
		return true;
	}
	if (ReportSuccessEpochIsStale(report.successEpoch, state)) {
		return true;
	}
	if (!FailureCanBeStale(report.reason)) {
		return false;
	}
	const auto successAt = FailureNeedsRecipeEscalation(report.reason)
		? state.lastSuccessAt
		: state.lastRelaySuccessAt;
	if (!successAt) {
		return false;
	}
	const auto startedAt = AttemptStartedAt(report, state);
	return startedAt && (startedAt < successAt);
}

[[nodiscard]] bool SuccessFromStaleAttempt(
		const SuccessReport &report,
		const EndpointState &state) {
	if (RuntimeProxyGenerationIsStale(
			state,
			report.runtimeId,
			report.proxyGeneration)) {
		return true;
	}
	const auto identity = RelayProofIdentity{
		.runtimeId = report.runtimeId,
		.proxyGeneration = report.proxyGeneration,
		.attemptId = report.attemptId,
	};
	if (HasEndpointAttempt(state, identity)
		|| HasRelayProof(state, identity)) {
		return false;
	}
	if (ReportEpochIsStale(report.proxyEpoch, state)) {
		return true;
	}
	if (ReportSuccessEpochIsStale(report.successEpoch, state)) {
		return true;
	}
	if (!state.lastRelaySuccessAt) {
		return false;
	}
	const auto startedAt = AttemptStartedAt(report, state);
	return startedAt && (startedAt < state.lastRelaySuccessAt);
}

void PruneExpiredEndpointState(EndpointState &state, crl::time now) {
	for (auto i = begin(state.attemptStarts); i != end(state.attemptStarts);) {
		if (now - i->second.startedAt > kAttemptHardTtl) {
			i = state.attemptStarts.erase(i);
		} else {
			++i;
		}
	}
	SynchronizeEndpointAdmissionAggregate(state);
}

[[nodiscard]] crl::time CooldownFor(
		FailureReason reason,
		int consecutiveFailures) {
	if (reason == FailureReason::DnsFailed) {
		return kDnsNegativeTtl;
	}
	if (reason == FailureReason::ClientHelloSentNoServerHello) {
		return kFirstCooldown;
	}
	if (reason == FailureReason::ServerHelloOkNoAppData) {
		// The proxy is alive and validated our handshake - it just did
		// not relay telegram data in time. That is often transient (the
		// proxy warming up its DC link) - retry quickly instead of the
		// full ladder, capping at the first cooldown so a genuinely
		// broken relay still backs off.
		return (consecutiveFailures <= 3)
			? kNoAppDataWarningCooldown
			: kFirstCooldown;
	}
	if (reason == FailureReason::ServerHelloOkNoMtprotoData
		|| reason == FailureReason::ConnectedNoMtprotoData) {
		// Transport connects and handshakes fine, MTProto payloads never
		// arrive. Hammering with instant reconnects is what sustains a
		// server-side throttle, so back off progressively - but keep the
		// cap below kMaxCooldown: the proxy itself is alive and a probe
		// every 45 seconds is gentle enough.
		return (consecutiveFailures <= 1)
			? kThrottledRetryCooldown
			: (consecutiveFailures == 2)
			? kFirstCooldown
			: kSecondCooldown;
	}
	if (consecutiveFailures <= 1) {
		return kFirstCooldown;
	} else if (consecutiveFailures == 2) {
		return kSecondCooldown;
	}
	return kMaxCooldown;
}

[[nodiscard]] EndpointConcurrencyPolicy EndpointConcurrencyPolicyFor(
		const EndpointState &state,
		EndpointUse use,
		crl::time now,
		bool fastWarmup) {
	auto policy = EndpointConcurrencyPolicy();
	if (FailureNeedsRecipeEscalation(state.lastFailure)) {
		// DPI-implicating failure: strict single probe with escalation
		// allowed, and keep non-main uses off an unproven endpoint.
		policy.activeCap = kDpiFailureActiveCap;
		policy.retryAfter = kQueuedRetry;
		policy.recipeEscalationAllowed = true;
		if (!state.relayProven && use != EndpointUse::Main) {
			policy.useAllowed = false;
		}
	} else if (!state.relayProven || !state.lastRelaySuccessAt) {
		// Never relayed Telegram data: one careful probe at a time, and
		// only the main session may spend it.
		policy.activeCap = kUnknownActiveCap;
		policy.retryAfter = kQueuedRetry;
		if (use != EndpointUse::Main) {
			policy.useAllowed = false;
		}
	} else if (state.healthy) {
		// Proven and currently healthy: pipeline handshakes with spacing.
		// Fast warm-up allows a second concurrent handshake (a browser
		// routinely opens two TLS connections to one host); the careful
		// single-probe rows above are unaffected.
		policy.activeCap = fastWarmup
			? kFastHealthyActiveCap
			: kHealthyActiveCap;
		policy.handshakeSpacing = kHealthyHandshakeSpacing;
		policy.retryAfter = kHealthyHandshakeSpacing;
	} else {
		// Proven but recovering from a failure: back to careful probing.
		policy.activeCap = kUnknownActiveCap;
		policy.retryAfter = kQueuedRetry;
	}
	return policy;
}

[[nodiscard]] Snapshot MakeSnapshot(
		const EndpointState &state,
		ProxyRuntimeId runtimeId) {
	const auto generation = state.generations.find(runtimeId);
	return {
		.endpoint = state.endpoint,
		.lastFailure = state.lastFailure,
		.lastDiagnostic = state.lastDiagnostic,
		.terminalUntil = state.terminalUntil,
		.active = state.active,
		.consecutiveFailures = state.consecutiveFailures,
		.recipeLevel = state.recipeLevel,
		.healthy = state.healthy,
		.halfOpen = state.halfOpen,
		.successEpoch = state.successEpoch,
		.lastRelaySuccessAt = state.lastRelaySuccessAt,
		.lastGoodProfile = state.lastGoodProfile,
		.lastGoodRoute = state.lastGoodRoute,
		.relayProven = state.relayProven,
		.proxyGeneration = (generation != end(state.generations))
			? generation->second
			: uint64(),
		.proxyEpoch = state.proxyEpoch,
		.attemptId = state.lastAttemptId,
	};
}

crl::time ConnectionSpacing(ProxyConnectionPattern pattern) {
	switch (pattern) {
	case ProxyConnectionPattern::Soft: return crl::time(150);
	case ProxyConnectionPattern::Quiet: return crl::time(400);
	case ProxyConnectionPattern::Strict: return crl::time(700);
	case ProxyConnectionPattern::Browser: return crl::time(250);
	case ProxyConnectionPattern::Off: break;
	}
	return crl::time(0);
}

} // namespace MTP::details::MtProxy
