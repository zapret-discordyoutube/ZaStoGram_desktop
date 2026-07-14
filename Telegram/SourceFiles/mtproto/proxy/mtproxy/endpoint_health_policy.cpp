/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "mtproto/proxy/mtproxy/endpoint_health_policy.h"

#include <QtCore/QObject>

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

[[nodiscard]] bool FailureAffectsOpening(FailureReason reason) {
	switch (reason) {
	case FailureReason::DnsFailed:
	case FailureReason::TcpConnectTimeout:
	case FailureReason::TcpConnectedNoClientHelloWrite:
	case FailureReason::ClientHelloSentNoServerHello:
	case FailureReason::TlsAlertAfterClientHello:
	case FailureReason::ServerHelloHmacMismatch:
	case FailureReason::ProxyProtocolBadResponse:
		return true;
	case FailureReason::None:
	case FailureReason::ServerHelloOkNoAppData:
	case FailureReason::ServerHelloOkNoMtprotoData:
	case FailureReason::AppDataRemoteClosed:
	case FailureReason::ConnectedNoMtprotoData:
	case FailureReason::MtpReceiveTimeoutAfterData:
	case FailureReason::Network:
		return false;
	}
	return false;
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
	ApplyRuntimeProxyGeneration(state, runtimeId, proxyGeneration);
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

void PruneExpiredEndpointState(EndpointState &state, crl::time now) {
	for (auto i = begin(state.attemptStarts); i != end(state.attemptStarts);) {
		if (i->second.admissionActive
			&& now - i->second.startedAt > kAttemptHardTtl) {
			QObject::disconnect(i->second.ownerDestroyed);
			i = state.attemptStarts.erase(i);
		} else {
			++i;
		}
	}
	SynchronizeEndpointAdmissionAggregate(state);
	PruneExpiredEndpointOutcomes(state, now);
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

int EndpointUseCount(
		const EndpointUseCounts &counts,
		EndpointUse use) {
	switch (use) {
	case EndpointUse::Main: return counts.main;
	case EndpointUse::Maintenance: return counts.maintenance;
	case EndpointUse::Auxiliary: return counts.auxiliary;
	case EndpointUse::Media: return counts.media;
	case EndpointUse::Upload: return counts.upload;
	case EndpointUse::ProxyCheck: return counts.proxyCheck;
	}
	return 0;
}

int TotalEndpointUseCount(const EndpointUseCounts &counts) {
	return std::max(0, counts.main)
		+ std::max(0, counts.maintenance)
		+ std::max(0, counts.auxiliary)
		+ std::max(0, counts.media)
		+ std::max(0, counts.upload)
		+ std::max(0, counts.proxyCheck);
}

EndpointUseCounts BeginEndpointAdmission(
		EndpointUseCounts counts,
		EndpointUse use) {
	switch (use) {
	case EndpointUse::Main:
		++counts.main;
		break;
	case EndpointUse::Maintenance:
		++counts.maintenance;
		break;
	case EndpointUse::Auxiliary:
		++counts.auxiliary;
		break;
	case EndpointUse::Media:
		++counts.media;
		break;
	case EndpointUse::Upload:
		++counts.upload;
		break;
	case EndpointUse::ProxyCheck:
		++counts.proxyCheck;
		break;
	}
	return counts;
}

EndpointUseCounts ReleaseEndpointAdmission(
		EndpointUseCounts counts,
		EndpointUse use) {
	switch (use) {
	case EndpointUse::Main:
		counts.main = std::max(0, counts.main - 1);
		break;
	case EndpointUse::Maintenance:
		counts.maintenance = std::max(0, counts.maintenance - 1);
		break;
	case EndpointUse::Auxiliary:
		counts.auxiliary = std::max(0, counts.auxiliary - 1);
		break;
	case EndpointUse::Media:
		counts.media = std::max(0, counts.media - 1);
		break;
	case EndpointUse::Upload:
		counts.upload = std::max(0, counts.upload - 1);
		break;
	case EndpointUse::ProxyCheck:
		counts.proxyCheck = std::max(0, counts.proxyCheck - 1);
		break;
	}
	return counts;
}

EndpointConcurrencyPolicy EvaluateEndpointAdmission(
		const EndpointAdmissionPolicyInput &input) {
	auto policy = EndpointConcurrencyPolicy();
	const auto hasMainProof = input.mainProof
		!= MainRelayProofStrength::None;
	const auto endpointHasMainProof = input.endpointMainProof
		!= MainRelayProofStrength::None;
	const auto repeatedMainProof = input.mainProof
		== MainRelayProofStrength::RepeatedPayload;
	const auto repeatedEndpointMainProof = input.endpointMainProof
		== MainRelayProofStrength::RepeatedPayload;
	const auto background = (input.use == EndpointUse::Media)
		|| (input.use == EndpointUse::Upload);
	const auto maintenance = (input.use == EndpointUse::Maintenance);
	const auto auxiliary = (input.use == EndpointUse::Auxiliary);
	const auto localFastWarmup = input.fastWarmup && repeatedMainProof;
	const auto endpointFastWarmup = input.fastWarmup
		&& repeatedEndpointMainProof;
	const auto fastWarmup = (background || auxiliary)
		? localFastWarmup
		: endpointFastWarmup;
	if (FailureNeedsRecipeEscalation(input.lastFailure)) {
		if (input.bootstrapFailure) {
			policy.activeCap = kDpiFailureActiveCap;
		} else if (endpointHasMainProof) {
			policy.activeCap = fastWarmup
				? kFastHealthyActiveCap
				: kHealthyActiveCap;
			policy.handshakeSpacing = kHealthyHandshakeSpacing;
		} else {
			policy.activeCap = kUnknownActiveCap;
		}
		policy.retryAfter = kQueuedRetry;
		if (input.bootstrapFailure) {
			policy.recipeEscalationAllowed = true;
		}
		if ((!input.endpointRelayProven || !endpointHasMainProof)
			&& background) {
			policy.useAllowed = false;
		}
	} else if (!input.endpointRelayProven
		|| !endpointHasMainProof
		|| !input.lastRelaySuccessAt) {
		policy.activeCap = kUnknownActiveCap;
		policy.retryAfter = kQueuedRetry;
		if (background) {
			policy.useAllowed = false;
		}
	} else if (input.healthy) {
		policy.activeCap = fastWarmup
			? kFastHealthyActiveCap
			: kHealthyActiveCap;
		policy.handshakeSpacing = kHealthyHandshakeSpacing;
		policy.retryAfter = kHealthyHandshakeSpacing;
	} else {
		policy.activeCap = kUnknownActiveCap;
		policy.retryAfter = kQueuedRetry;
	}
	const auto urgentMainDemand = (input.foregroundTransfer
			&& policy.activeCap > 1)
		? 0
		: std::max(0, input.urgentMainDemand);
	if (background && (!hasMainProof || urgentMainDemand > 0)) {
		policy.useAllowed = false;
	}
	if (auxiliary && (!hasMainProof || urgentMainDemand > 0)) {
		policy.useAllowed = false;
	}
	if (maintenance && urgentMainDemand > 0) {
		policy.useAllowed = false;
	}
	const auto candidateIsUrgentMain = (input.use == EndpointUse::Main)
		&& !hasMainProof;
	const auto mainOpening = input.active.main + input.scheduled.main;
	policy.mainLaneReserved = (urgentMainDemand > 0)
		&& !candidateIsUrgentMain
		&& (mainOpening == 0);
	const auto availableCap = std::max(
		0,
		policy.activeCap - (policy.mainLaneReserved ? 1 : 0));
	const auto occupied = TotalEndpointUseCount(input.active)
		+ TotalEndpointUseCount(input.scheduled);
	const auto nonMainOccupied = occupied - mainOpening;
	const auto nonMainCandidate = input.use != EndpointUse::Main;
	policy.admissionAllowed = policy.useAllowed
		&& (occupied < availableCap)
		&& (!nonMainCandidate || nonMainOccupied < 1);
	if (input.retryUntil > input.now) {
		policy.retryAfter = std::max(
			policy.retryAfter,
			input.retryUntil - input.now);
		policy.admissionAllowed = false;
	}
	if (input.nextHandshakeAt > input.now
		&& (!endpointHasMainProof
			|| policy.handshakeSpacing > 0)) {
		policy.retryAfter = std::max(
			policy.retryAfter,
			input.nextHandshakeAt - input.now);
		policy.admissionAllowed = false;
	}
	return policy;
}

[[nodiscard]] EndpointConcurrencyPolicy EndpointConcurrencyPolicyFor(
		const EndpointState &state,
		EndpointUse use,
		RuntimeGenerationKey runtimeGeneration,
		crl::time now,
		bool fastWarmup) {
	const auto mainProof = EndpointMainRelayProof(state);
	const auto bootstrap = (use == EndpointUse::Main)
		&& (mainProof.strength == MainRelayProofStrength::None);
	const auto expansion = FindEndpointExpansionFailure(
		state,
		runtimeGeneration,
		use);
	const auto &opening = bootstrap
		? state.opening.bootstrap
		: expansion
		? *expansion
		: state.opening.expansion;
	return EvaluateEndpointAdmission({
		.use = use,
		.mainProof = mainProof.strength,
		.endpointMainProof = mainProof.strength,
		.lastFailure = opening.reason,
		.retryUntil = opening.retryUntil,
		.lastRelaySuccessAt = std::max(
			mainProof.provenAt,
			mainProof.lastPayloadAt),
		.now = now,
		.endpointRelayProven = mainProof.strength
			!= MainRelayProofStrength::None,
		.healthy = state.healthy,
		.fastWarmup = fastWarmup,
		.bootstrapFailure = bootstrap,
	});
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
