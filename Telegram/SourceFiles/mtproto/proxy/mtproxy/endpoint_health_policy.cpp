/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "mtproto/proxy/mtproxy/endpoint_health_policy.h"

#include "mtproto/proxy/proxy_endpoint_context_p.h"

#include <algorithm>

namespace MTP::details::MtProxy {
namespace {

constexpr auto kFirstCooldown = crl::time(15 * 1000);
constexpr auto kSecondCooldown = crl::time(45 * 1000);
constexpr auto kMaxCooldown = crl::time(120 * 1000);
constexpr auto kDnsNegativeTtl = crl::time(30 * 1000);
constexpr auto kAttemptHardTtl = crl::time(120 * 1000);
constexpr auto kRecentRelaySuccessWindow = crl::time(60 * 1000);
constexpr auto kThrottledRetryCooldown = crl::time(3000);
constexpr auto kNoAppDataWarningCooldown = crl::time(3000);
constexpr auto kRecentRelayServerHelloTimeout = crl::time(2500);
constexpr auto kColdServerHelloTimeout = crl::time(5000);

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

EndpointPhysicalOpeningBoundaryView CurrentPhysicalOpeningBoundary(
		const EndpointState &state,
		crl::time now) {
	auto result = EndpointPhysicalOpeningBoundaryView();
	const auto &boundary = state.physicalOpeningBoundary;
	if (boundary.pressureUntil > now) {
		result = {
			.reason = boundary.pressureReason,
			.retryUntil = boundary.pressureUntil,
		};
	}
	return result;
}

void ApplyPhysicalOpeningTerminal(
		EndpointState &state,
		const ProxyConnectionAttempt &attempt,
		FailureReason reason,
		crl::time observedAt) {
	if (!attempt.attemptId
		|| reason == FailureReason::None
		|| !observedAt) {
		return;
	}
	auto &boundary = state.physicalOpeningBoundary;
	if (attempt.attemptId <= boundary.pressureAttempt.attemptId) {
		return;
	}
	const auto pressureUntil = observedAt + CooldownFor(reason, 1);
	if (boundary.pressureUntil > observedAt
		&& pressureUntil < boundary.pressureUntil) {
		return;
	}
	boundary.pressureAttempt = attempt;
	boundary.pressureReason = reason;
	boundary.pressureObservedAt = observedAt;
	boundary.pressureUntil = pressureUntil;
}

void ApplyPhysicalOpeningRelay(
		EndpointState &state,
		const ProxyConnectionAttempt &attempt,
		crl::time relayAt) {
	if (!attempt.attemptId || !relayAt) {
		return;
	}
	auto &boundary = state.physicalOpeningBoundary;
	if (boundary.pressureAttempt.attemptId < attempt.attemptId
		&& boundary.pressureObservedAt <= relayAt) {
		boundary.pressureAttempt = {};
		boundary.pressureReason = FailureReason::None;
		boundary.pressureObservedAt = 0;
		boundary.pressureUntil = 0;
	}
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

crl::time ThrottledRetryCooldown() {
	return kThrottledRetryCooldown;
}

[[nodiscard]] bool ReportTicketMatches(
		AdmissionTicketKey expected,
		AdmissionTicketKey reported) {
	return (!reported.runtimeId && !reported.ticketId)
		|| reported == expected;
}

[[nodiscard]] bool ReportMatchesAttempt(
		const EndpointAttemptState &attempt,
		EndpointUse use,
		AdmissionTicketKey ticketKey,
		uint64 proxyEpoch,
		uint64 successEpoch,
		crl::time attemptStartedAt) {
	return attempt.use == use
		&& ReportTicketMatches(attempt.ticketKey, ticketKey)
		&& attempt.proxyEpoch == proxyEpoch
		&& attempt.successEpoch == successEpoch
		&& (!attemptStartedAt
			|| attempt.attemptStartedAt == attemptStartedAt);
}

[[nodiscard]] bool ReportMatchesProof(
		const RelayProofState &proof,
		EndpointUse use,
		AdmissionTicketKey ticketKey,
		uint64 proxyEpoch,
		uint64 successEpoch,
		crl::time attemptStartedAt) {
	return proof.use == use
		&& ReportTicketMatches(proof.ticketKey, ticketKey)
		&& proof.proxyEpoch == proxyEpoch
		&& proof.successEpoch == successEpoch
		&& (!attemptStartedAt
			|| proof.attemptStartedAt == attemptStartedAt);
}

void ApplyProxyGeneration(
		EndpointState &state,
		ProxyRuntimeId runtimeId,
		uint64 proxyGeneration) {
	static_cast<void>(ApplyRuntimeProxyGeneration(
		state,
		runtimeId,
		proxyGeneration));
}

[[nodiscard]] bool FailureFromStaleAttempt(
		const FailureReport &report,
		const EndpointState &state) {
	const auto runtimeGeneration = RuntimeGenerationKey{
		.runtimeId = report.runtimeId,
		.proxyGeneration = report.proxyGeneration,
	};
	if (!report.attemptId
		|| !RuntimeGenerationIsCurrent(state, runtimeGeneration)) {
		return true;
	}
	const auto identity = RelayProofIdentity{
		.runtimeId = report.runtimeId,
		.proxyGeneration = report.proxyGeneration,
		.attemptId = report.attemptId,
	};
	const auto proof = state.relayProofs.find(identity);
	if (proof != end(state.relayProofs)) {
		return !ReportMatchesProof(
			proof->second,
			report.use,
			report.ticketKey,
			report.proxyEpoch,
			report.successEpoch,
			report.attemptStartedAt);
	}
	const auto attempt = state.attemptStarts.find(report.attemptId);
	return attempt == end(state.attemptStarts)
		|| attempt->second.runtimeId != report.runtimeId
		|| attempt->second.proxyGeneration != report.proxyGeneration
		|| attempt->second.terminalVerdict.has_value()
		|| !ReportMatchesAttempt(
			attempt->second,
			report.use,
			report.ticketKey,
			report.proxyEpoch,
			report.successEpoch,
			report.attemptStartedAt);
}

[[nodiscard]] bool SuccessFromStaleAttempt(
		const SuccessReport &report,
		const EndpointState &state) {
	const auto runtimeGeneration = RuntimeGenerationKey{
		.runtimeId = report.runtimeId,
		.proxyGeneration = report.proxyGeneration,
	};
	if (!report.attemptId
		|| !RuntimeGenerationIsCurrent(state, runtimeGeneration)) {
		return true;
	}
	const auto identity = RelayProofIdentity{
		.runtimeId = report.runtimeId,
		.proxyGeneration = report.proxyGeneration,
		.attemptId = report.attemptId,
	};
	const auto proof = state.relayProofs.find(identity);
	if (proof != end(state.relayProofs)) {
		return !ReportMatchesProof(
			proof->second,
			report.use,
			report.ticketKey,
			report.proxyEpoch,
			report.successEpoch,
			report.attemptStartedAt);
	}
	const auto attempt = state.attemptStarts.find(report.attemptId);
	return attempt == end(state.attemptStarts)
		|| attempt->second.runtimeId != report.runtimeId
		|| attempt->second.proxyGeneration != report.proxyGeneration
		|| attempt->second.terminalVerdict.has_value()
		|| !ReportMatchesAttempt(
			attempt->second,
			report.use,
			report.ticketKey,
			report.proxyEpoch,
			report.successEpoch,
			report.attemptStartedAt);
}

crl::time EndpointAttemptHardDeadline(
		const EndpointAttemptState &attempt) {
	return attempt.startedAt + kAttemptHardTtl;
}

EndpointDeferredCleanup PruneExpiredEndpointStateDeferred(
		EndpointState &state,
		crl::time now) {
	auto cleanup = EndpointDeferredCleanup();
	auto &boundary = state.physicalOpeningBoundary;
	if (boundary.pressureUntil <= now) {
		boundary.pressureAttempt = {};
		boundary.pressureReason = FailureReason::None;
		boundary.pressureObservedAt = 0;
		boundary.pressureUntil = 0;
	}
	for (auto i = begin(state.attemptStarts); i != end(state.attemptStarts);) {
		if (now >= EndpointAttemptHardDeadline(i->second)) {
			DeferEndpointOwnerDisconnect(
				cleanup,
				i->second.ownerDestroyed);
			i = state.attemptStarts.erase(i);
		} else {
			++i;
		}
	}
	PruneExpiredEndpointOutcomes(state, now);
	return cleanup;
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

crl::time ServerHelloTimeoutFor(
		const EndpointState &state,
		crl::time attemptStartedAt) {
	return RecentRelaySuccess(state, attemptStartedAt)
		? kRecentRelayServerHelloTimeout
		: kColdServerHelloTimeout;
}

void NoteRouteFailure(
		EndpointContextStorage &storage,
		EndpointState &state,
		const RouteEndpoint &route,
		FailureReason reason) {
	const auto routeKey = RouteKey(route);
	if (routeKey.isEmpty()) {
		return;
	}
	state.routeKeys.insert(routeKey);
	auto &routeState = storage.routes[routeKey];
	routeState.route = route;
	routeState.lastFailure = reason;
	routeState.healthy = false;
	if (reason == FailureReason::ServerHelloOkNoAppData) {
		++routeState.relaySuspect;
	}
}

void NoteRouteSuccess(
		EndpointContextStorage &storage,
		EndpointState &state,
		const RouteEndpoint &route) {
	const auto routeKey = RouteKey(route);
	if (routeKey.isEmpty()) {
		return;
	}
	state.routeKeys.insert(routeKey);
	auto &routeState = storage.routes[routeKey];
	routeState.route = route;
	routeState.lastFailure = FailureReason::None;
	routeState.healthy = true;
	routeState.relaySuspect = 0;
}

bool HasHealthyRoute(
		const EndpointContextStorage &storage,
		const EndpointState &state) {
	for (const auto &routeKey : state.routeKeys) {
		const auto i = storage.routes.find(routeKey);
		if (i != end(storage.routes) && i->second.healthy) {
			return true;
		}
	}
	return false;
}

} // namespace MTP::details::MtProxy
