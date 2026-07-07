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
constexpr auto kFreshRelayActiveCap = 2;
constexpr auto kWarmRelayActiveCap = 4;
constexpr auto kStableRelayActiveCap = 8;
constexpr auto kFreshRelayWindow = crl::time(10 * 1000);
constexpr auto kWarmRelayWindow = crl::time(20 * 1000);
constexpr auto kHealthyHandshakeSpacing = crl::time(50);
constexpr auto kQueuedRetry = crl::time(1000);
constexpr auto kAttemptHardTtl = crl::time(120 * 1000);
constexpr auto kRecentRelaySuccessWindow = crl::time(60 * 1000);
constexpr auto kThrottledRetryCooldown = crl::time(3000);
constexpr auto kNoAppDataSoftRetry = crl::time(1000);
constexpr auto kNoAppDataWarningCooldown = crl::time(3000);

} // namespace

[[nodiscard]] bool FailureNeedsCooldown(FailureReason reason) {
	switch (reason) {
	case FailureReason::DnsFailed:
	case FailureReason::ClientHelloSentNoServerHello:
	case FailureReason::TlsAlertAfterClientHello:
	case FailureReason::ServerHelloHmacMismatch:
	case FailureReason::ServerHelloOkNoAppData:
	case FailureReason::ServerHelloOkNoMtprotoData:
	case FailureReason::ProxyProtocolBadResponse:
	case FailureReason::ConnectedNoMtprotoData:
		return true;
	case FailureReason::None:
	case FailureReason::TcpConnectTimeout:
	case FailureReason::TcpConnectedNoClientHelloWrite:
	case FailureReason::AppDataRemoteClosed:
	case FailureReason::MtpReceiveTimeoutAfterData:
	case FailureReason::Network:
		return false;
	}
	return false;
}

[[nodiscard]] bool FailureNeedsRecipeEscalation(FailureReason reason) {
	switch (reason) {
	case FailureReason::ClientHelloSentNoServerHello:
	case FailureReason::TlsAlertAfterClientHello:
	case FailureReason::ServerHelloHmacMismatch:
		return true;
	// ServerHelloOkNoAppData means the server accepted our ClientHello
	// (HMAC verified) and the stall is downstream - the proxy's own link
	// to the DC. Mutating the ClientHello cannot fix that; escalated
	// recipes (fragmentation, pacing, spacing) only add latency and can
	// break a FakeTLS front that was answering fine, turning a slow
	// relay into client_hello_sent_no_server_hello. Escalate only on
	// failures that actually implicate the handshake fingerprint.
	// ConnectedNoMtprotoData is even further downstream: the handshake
	// and even the plaintext transport check passed, so the fingerprint
	// is definitely not the problem.
	case FailureReason::None:
	case FailureReason::DnsFailed:
	case FailureReason::TcpConnectTimeout:
	case FailureReason::TcpConnectedNoClientHelloWrite:
	case FailureReason::ServerHelloOkNoAppData:
	case FailureReason::ServerHelloOkNoMtprotoData:
	case FailureReason::AppDataRemoteClosed:
	case FailureReason::ConnectedNoMtprotoData:
	case FailureReason::MtpReceiveTimeoutAfterData:
	case FailureReason::Network:
	case FailureReason::ProxyProtocolBadResponse:
		return false;
	}
	return false;
}

[[nodiscard]] bool FailureNeedsTlsRotation(FailureReason reason) {
	switch (reason) {
	case FailureReason::ClientHelloSentNoServerHello:
	case FailureReason::TlsAlertAfterClientHello:
	case FailureReason::ServerHelloHmacMismatch:
		return true;
	case FailureReason::None:
	case FailureReason::DnsFailed:
	case FailureReason::TcpConnectTimeout:
	case FailureReason::TcpConnectedNoClientHelloWrite:
	case FailureReason::ServerHelloOkNoAppData:
	case FailureReason::ServerHelloOkNoMtprotoData:
	case FailureReason::AppDataRemoteClosed:
	case FailureReason::ConnectedNoMtprotoData:
	case FailureReason::MtpReceiveTimeoutAfterData:
	case FailureReason::Network:
	case FailureReason::ProxyProtocolBadResponse:
		return false;
	}
	return false;
}

[[nodiscard]] bool FailureIsRouteOnly(FailureReason reason) {
	switch (reason) {
	case FailureReason::TcpConnectTimeout:
	case FailureReason::TcpConnectedNoClientHelloWrite:
		return true;
	case FailureReason::None:
	case FailureReason::DnsFailed:
	case FailureReason::ClientHelloSentNoServerHello:
	case FailureReason::TlsAlertAfterClientHello:
	case FailureReason::ServerHelloHmacMismatch:
	case FailureReason::ServerHelloOkNoAppData:
	case FailureReason::ServerHelloOkNoMtprotoData:
	case FailureReason::AppDataRemoteClosed:
	case FailureReason::ConnectedNoMtprotoData:
	case FailureReason::MtpReceiveTimeoutAfterData:
	case FailureReason::Network:
	case FailureReason::ProxyProtocolBadResponse:
		return false;
	}
	return false;
}

[[nodiscard]] bool FailureDowngradesRecipe(FailureReason reason) {
	switch (reason) {
	case FailureReason::ServerHelloOkNoAppData:
	case FailureReason::ServerHelloOkNoMtprotoData:
	case FailureReason::ConnectedNoMtprotoData:
	case FailureReason::MtpReceiveTimeoutAfterData:
		return true;
	case FailureReason::None:
	case FailureReason::DnsFailed:
	case FailureReason::TcpConnectTimeout:
	case FailureReason::TcpConnectedNoClientHelloWrite:
	case FailureReason::ClientHelloSentNoServerHello:
	case FailureReason::TlsAlertAfterClientHello:
	case FailureReason::ServerHelloHmacMismatch:
	case FailureReason::AppDataRemoteClosed:
	case FailureReason::Network:
	case FailureReason::ProxyProtocolBadResponse:
		return false;
	}
	return false;
}

[[nodiscard]] bool RelayFailureInvalidatesCapability(FailureReason reason) {
	switch (reason) {
	case FailureReason::ServerHelloOkNoAppData:
	case FailureReason::ServerHelloOkNoMtprotoData:
	case FailureReason::ConnectedNoMtprotoData:
	case FailureReason::MtpReceiveTimeoutAfterData:
		return true;
	case FailureReason::None:
	case FailureReason::DnsFailed:
	case FailureReason::TcpConnectTimeout:
	case FailureReason::TcpConnectedNoClientHelloWrite:
	case FailureReason::ClientHelloSentNoServerHello:
	case FailureReason::TlsAlertAfterClientHello:
	case FailureReason::ServerHelloHmacMismatch:
	case FailureReason::AppDataRemoteClosed:
	case FailureReason::Network:
	case FailureReason::ProxyProtocolBadResponse:
		return false;
	}
	return false;
}

void DowngradeRecipeForRelayStall(
		EndpointState &state,
		FailureReason reason) {
	if (FailureDowngradesRecipe(reason) && state.recipeLevel > 0) {
		--state.recipeLevel;
	}
}

[[nodiscard]] bool FailureCanBeStale(FailureReason reason) {
	switch (reason) {
	case FailureReason::TcpConnectTimeout:
	case FailureReason::TcpConnectedNoClientHelloWrite:
	case FailureReason::ClientHelloSentNoServerHello:
	case FailureReason::ServerHelloOkNoAppData:
	case FailureReason::ServerHelloOkNoMtprotoData:
	case FailureReason::ConnectedNoMtprotoData:
	case FailureReason::MtpReceiveTimeoutAfterData:
		return true;
	case FailureReason::None:
	case FailureReason::DnsFailed:
	case FailureReason::TlsAlertAfterClientHello:
	case FailureReason::ServerHelloHmacMismatch:
	case FailureReason::AppDataRemoteClosed:
	case FailureReason::Network:
	case FailureReason::ProxyProtocolBadResponse:
		return false;
	}
	return false;
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
	return (i != end(state.attemptStarts)) ? i->second : crl::time();
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
	return (i != end(state.attemptStarts)) ? i->second : crl::time();
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

[[nodiscard]] bool ReportGenerationIsStale(
		uint64 proxyGeneration,
		const EndpointState &state) {
	return proxyGeneration && proxyGeneration < state.proxyGeneration;
}

void ApplyProxyGeneration(
		EndpointState &state,
		uint64 proxyGeneration) {
	if (!proxyGeneration || proxyGeneration <= state.proxyGeneration) {
		return;
	}
	state.proxyGeneration = proxyGeneration;
	state.attemptStarts.clear();
	state.active = 0;
}

[[nodiscard]] bool FailureFromStaleAttempt(
		const FailureReport &report,
		const EndpointState &state) {
	if (ReportGenerationIsStale(report.proxyGeneration, state)) {
		return true;
	}
	if (ReportEpochIsStale(report.proxyEpoch, state)) {
		return true;
	}
	if (ReportSuccessEpochIsStale(report.successEpoch, state)) {
		return true;
	}
	if (!state.lastRelaySuccessAt || !FailureCanBeStale(report.reason)) {
		return false;
	}
	const auto startedAt = AttemptStartedAt(report, state);
	return startedAt && (startedAt < state.lastRelaySuccessAt);
}

[[nodiscard]] bool SuccessFromStaleAttempt(
		const SuccessReport &report,
		const EndpointState &state) {
	if (ReportGenerationIsStale(report.proxyGeneration, state)) {
		return true;
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

void PruneExpiredAttempts(EndpointState &state, crl::time now) {
	for (auto i = begin(state.attemptStarts); i != end(state.attemptStarts);) {
		if (now - i->second > kAttemptHardTtl) {
			i = state.attemptStarts.erase(i);
		} else {
			++i;
		}
	}
	state.active = int(state.attemptStarts.size());
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
		crl::time now) {
	auto policy = EndpointConcurrencyPolicy();
	if (FailureNeedsRecipeEscalation(state.lastFailure)) {
		policy.activeCap = kDpiFailureActiveCap;
		policy.retryAfter = kQueuedRetry;
		policy.recipeEscalationAllowed = true;
		if (!state.relayProven && use != EndpointUse::Main) {
			policy.useAllowed = false;
		}
		return policy;
	}
	switch (state.lastFailure) {
	case FailureReason::None:
	case FailureReason::DnsFailed:
	case FailureReason::TcpConnectTimeout:
	case FailureReason::TcpConnectedNoClientHelloWrite:
	case FailureReason::ClientHelloSentNoServerHello:
	case FailureReason::TlsAlertAfterClientHello:
	case FailureReason::ServerHelloHmacMismatch:
	case FailureReason::ServerHelloOkNoAppData:
	case FailureReason::ServerHelloOkNoMtprotoData:
	case FailureReason::AppDataRemoteClosed:
	case FailureReason::ConnectedNoMtprotoData:
	case FailureReason::MtpReceiveTimeoutAfterData:
	case FailureReason::Network:
	case FailureReason::ProxyProtocolBadResponse:
		break;
	}
	if (!state.relayProven || !state.lastRelaySuccessAt) {
		policy.activeCap = kUnknownActiveCap;
		policy.retryAfter = kQueuedRetry;
		if (use != EndpointUse::Main) {
			policy.useAllowed = false;
		}
	} else if (state.healthy) {
		const auto relayAge = now - state.lastRelaySuccessAt;
		if (relayAge < kFreshRelayWindow) {
			policy.activeCap = kFreshRelayActiveCap;
		} else if (relayAge < kWarmRelayWindow) {
			policy.activeCap = kWarmRelayActiveCap;
		} else {
			policy.activeCap = kStableRelayActiveCap;
		}
		policy.handshakeSpacing = kHealthyHandshakeSpacing;
		policy.retryAfter = kHealthyHandshakeSpacing;
	} else {
		policy.activeCap = kUnknownActiveCap;
		policy.retryAfter = kQueuedRetry;
	}
	return policy;
}

[[nodiscard]] Snapshot MakeSnapshot(const EndpointState &state) {
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
		.proxyGeneration = state.proxyGeneration,
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
