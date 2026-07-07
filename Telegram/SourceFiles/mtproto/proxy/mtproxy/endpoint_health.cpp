/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "mtproto/proxy/mtproxy/endpoint_health.h"

#include "mtproto/proxy/capabilities.h"
#include "mtproto/proxy/diagnostics.h"
#include "mtproto/proxy/mtproxy/adaptive_policy.h"
#include "mtproto/proxy/mtproxy/open_scheduler.h"
#include "base/algorithm.h"
#include "base/timer.h"

#include <QtCore/QMutex>
#include <rpl/event_stream.h>

#include <map>
#include <optional>
#include <set>

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

// No single connect attempt may hold an active slot longer than this.
// A leaked lease (hung socket, lost owner) would otherwise pin the
// endpoint at its active cap and deny admission forever.
constexpr auto kAttemptHardTtl = crl::time(120 * 1000);

// If every admission request for an endpoint has been denied for this
// long without a single grant, ask the rotation manager to look for
// another proxy instead of spinning on this one.
constexpr auto kDeniedRotationAfter = crl::time(20 * 1000);

// A proxy that throttles new TCP connects while serving established
// connections fine looks like "all routes failed" on every unlucky
// reconnect. An endpoint that has succeeded before only degrades after
// this many exhaustions in a row with no success in between; one that
// never succeeded degrades on the first (fast dead-proxy detection).
constexpr auto kExhaustedStrikesAfterSuccess = 3;

// A DPI that kills only some handshakes leaves the endpoint flapping:
// connected for seconds, then a full cooldown on the first killed
// handshake. If the endpoint served a connection this recently, probe
// again quickly with the escalated recipe instead of blocking every
// new connection for the full cooldown - the adaptive open pacing
// keeps the probe rate down.
constexpr auto kRecentSuccessWindow = crl::time(60 * 1000);
constexpr auto kRecentRelaySuccessWindow = crl::time(60 * 1000);
constexpr auto kThrottledRetryCooldown = crl::time(3000);
constexpr auto kNoAppDataSoftRetry = crl::time(1000);
constexpr auto kNoAppDataWarningCooldown = crl::time(3000);

struct EndpointState {
	EndpointId endpoint;
	std::set<QString> routeKeys;
	FailureReason lastFailure = FailureReason::None;
	QString lastDiagnostic;
	crl::time terminalUntil = 0;
	int active = 0;
	int consecutiveFailures = 0;
	int recipeLevel = 0;
	crl::time nextHandshakeAt = 0;
	bool healthy = false;
	bool halfOpen = false;
	uint64 proxyGeneration = 0;
	uint64 proxyEpoch = 1;
	uint64 lastAttemptId = 0;
	std::map<uint64, crl::time> attemptStarts;
	crl::time deniedSince = 0;
	crl::time lastDenialRotationSignal = 0;
	crl::time lastSuccessAt = 0;
	int exhaustedSinceSuccess = 0;
	bool relayProven = false;
	uint64 successEpoch = 0;
	crl::time lastRelaySuccessAt = 0;
	ProxyTlsProfile lastGoodProfile = ProxyTlsProfile::Auto;
	RouteEndpoint lastGoodRoute;
};

struct RouteState {
	RouteEndpoint route;
	FailureReason lastFailure = FailureReason::None;
	bool healthy = false;
	int relaySuspect = 0;
};

struct EndpointConcurrencyPolicy {
	int activeCap = kUnknownActiveCap;
	crl::time handshakeSpacing = 0;
	crl::time retryAfter = kQueuedRetry;
	bool recipeEscalationAllowed = false;
	bool useAllowed = true;
};

struct CapabilitySuccess {
	QString proxyKey;
	QString routeKey;
	QString route;
	ProxyTlsProfile sentProfile = ProxyTlsProfile::Auto;
	ProxyStealthOptions stealth;
	int recipeLevel = 0;
	bool relayProven = false;
};

struct CapabilityFailure {
	QString proxyKey;
	QString routeKey;
	QString diagnostic;
};

QMutex StatesMutex;
std::map<QString, EndpointState> States;
std::map<QString, RouteState> Routes;
rpl::event_stream<EndpointEvent> Events;

void NoteRouteFailure(
		EndpointState &state,
		const RouteEndpoint &route,
		FailureReason reason) {
	const auto routeKey = RouteKey(route);
	if (routeKey.isEmpty()) {
		return;
	}
	state.routeKeys.insert(routeKey);
	auto &routeState = Routes[routeKey];
	routeState.route = route;
	routeState.lastFailure = reason;
	routeState.healthy = false;
	if (reason == FailureReason::ServerHelloOkNoAppData) {
		++routeState.relaySuspect;
	}
}

void NoteRouteSuccess(EndpointState &state, const RouteEndpoint &route) {
	const auto routeKey = RouteKey(route);
	if (routeKey.isEmpty()) {
		return;
	}
	state.routeKeys.insert(routeKey);
	auto &routeState = Routes[routeKey];
	routeState.route = route;
	routeState.lastFailure = FailureReason::None;
	routeState.healthy = true;
	routeState.relaySuspect = 0;
}

[[nodiscard]] bool HasHealthyRoute(const EndpointState &state) {
	for (const auto &routeKey : state.routeKeys) {
		const auto i = Routes.find(routeKey);
		if (i != end(Routes) && i->second.healthy) {
			return true;
		}
	}
	return false;
}

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

[[nodiscard]] QString CanonicalText(const EndpointId &endpoint) {
	return ProxyDiagnosticsEndpointText(
		endpoint.canonical.originalHost,
		endpoint.canonical.port);
}

[[nodiscard]] QString RouteText(const EndpointId &endpoint) {
	return ProxyDiagnosticsEndpointText(
		endpoint.route.address,
		endpoint.route.port);
}

[[nodiscard]] ProxyDiagnosticsEvent CanonicalDiagnosticsEvent(
		ProxyDiagnosticsPhase phase,
		const EndpointState &state,
		FailureReason reason,
		const QString &message) {
	return {
		.source = ProxyDiagnosticsSource::MTProxy,
		.phase = phase,
		.severity = (phase == ProxyDiagnosticsPhase::CanonicalRecovered)
			? ProxyDiagnosticsSeverity::Info
			: ProxyDiagnosticsSeverity::Warning,
		.error = ToProxyConnectionError(reason),
		.mtproxyReason = ToProxyMtproxyTerminalReason(reason),
		.terminalUntil = state.terminalUntil,
		.transport = ProxyDiagnosticsTransportName(
			state.endpoint.canonical.proxyKind,
			state.endpoint.route.transport),
		.message = message,
		.canonical = CanonicalText(state.endpoint),
		.route = RouteText(state.endpoint),
		.proxyKeyHash = ProxyDiagnosticsKeyHash(
			EndpointKey(state.endpoint.canonical)),
		.recipeLevel = state.recipeLevel,
		.phaseAtFailure = ToLegacyDiagnostic(reason),
	};
}

void LogStaleAttemptFailure(
		const FailureReport &report,
		int recipeLevel) {
	WriteProxyDiagnosticsLine({
		.source = ProxyDiagnosticsSource::MTProxy,
		.phase = ProxyDiagnosticsPhase::RouteFailed,
		.severity = ProxyDiagnosticsSeverity::Info,
		.error = ToProxyConnectionError(report.reason),
		.mtproxyReason = ToProxyMtproxyTerminalReason(report.reason),
		.transport = ProxyDiagnosticsTransportName(
			report.endpoint.canonical.proxyKind,
			report.endpoint.route.transport),
		.message = u"stale_attempt_failed"_q,
		.canonical = CanonicalText(report.endpoint),
		.route = RouteText(report.endpoint),
		.proxyKeyHash = ProxyDiagnosticsKeyHash(
			EndpointKey(report.endpoint.canonical)),
		.recipeLevel = recipeLevel,
		.phaseAtFailure = ToLegacyDiagnostic(report.reason),
	});
}

void LogProbeAttemptFailure(const FailureReport &report) {
	WriteProxyDiagnosticsLine({
		.source = ProxyDiagnosticsSource::MTProxy,
		.phase = ProxyDiagnosticsPhase::RouteFailed,
		.severity = ProxyDiagnosticsSeverity::Info,
		.error = ToProxyConnectionError(report.reason),
		.mtproxyReason = ToProxyMtproxyTerminalReason(report.reason),
		.transport = ProxyDiagnosticsTransportName(
			report.endpoint.canonical.proxyKind,
			report.endpoint.route.transport),
		.message = u"probe_attempt_failed"_q,
		.canonical = CanonicalText(report.endpoint),
		.route = RouteText(report.endpoint),
		.proxyKeyHash = ProxyDiagnosticsKeyHash(
			EndpointKey(report.endpoint.canonical)),
		.phaseAtFailure = ToLegacyDiagnostic(report.reason),
	});
}

} // namespace

EndpointAttemptLease::EndpointAttemptLease(
		QString key,
		uint64 attemptId,
		uint64 proxyGeneration,
		uint64 proxyEpoch,
		uint64 successEpoch,
		crl::time startedAt)
: _key(std::move(key))
, _attemptId(attemptId)
, _proxyGeneration(proxyGeneration)
, _proxyEpoch(proxyEpoch)
, _successEpoch(successEpoch)
, _startedAt(startedAt)
, _active(true) {
}

EndpointAttemptLease::EndpointAttemptLease(
		EndpointAttemptLease &&other) noexcept
: _key(std::move(other._key))
, _attemptId(base::take(other._attemptId))
, _proxyGeneration(base::take(other._proxyGeneration))
, _proxyEpoch(base::take(other._proxyEpoch))
, _successEpoch(base::take(other._successEpoch))
, _startedAt(base::take(other._startedAt))
, _active(base::take(other._active)) {
}

EndpointAttemptLease &EndpointAttemptLease::operator=(
		EndpointAttemptLease &&other) noexcept {
	if (this != &other) {
		release();
		_key = std::move(other._key);
		_attemptId = base::take(other._attemptId);
		_proxyGeneration = base::take(other._proxyGeneration);
		_proxyEpoch = base::take(other._proxyEpoch);
		_successEpoch = base::take(other._successEpoch);
		_startedAt = base::take(other._startedAt);
		_active = base::take(other._active);
	}
	return *this;
}

EndpointAttemptLease::~EndpointAttemptLease() {
	release();
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

void EndpointAttemptLease::release() {
	if (!_active) {
		return;
	}
	_active = false;
	EndpointHealth::Instance().releaseAttempt(_key, _attemptId);
}

bool EndpointAttemptLease::active() const {
	return _active;
}

uint64 EndpointAttemptLease::attemptId() const {
	return _attemptId;
}

uint64 EndpointAttemptLease::proxyGeneration() const {
	return _proxyGeneration;
}

uint64 EndpointAttemptLease::proxyEpoch() const {
	return _proxyEpoch;
}

uint64 EndpointAttemptLease::successEpoch() const {
	return _successEpoch;
}

crl::time EndpointAttemptLease::startedAt() const {
	return _startedAt;
}

EndpointHealth &EndpointHealth::Instance() {
	static auto result = EndpointHealth();
	return result;
}

Admission EndpointHealth::admit(const AdmissionRequest &request) {
	const auto key = EndpointKey(request.endpoint);
	const auto now = crl::now();
	auto result = Admission();
	auto rotationEvent = std::optional<EndpointEvent>();
	auto starvationDiagnostics = std::optional<ProxyDiagnosticsEvent>();
	{
		QMutexLocker lock(&StatesMutex);
		auto &state = States[key];
		state.endpoint = request.endpoint;
		ApplyProxyGeneration(state, request.proxyGeneration);
		PruneExpiredAttempts(state, now);
		result.stealth = request.stealth;
		result.effectiveTlsProfile = ResolveEffectiveTlsProfile(
			request.configuredTlsProfile,
			key);
		result.proxyGeneration = request.proxyGeneration;
		result.proxyEpoch = state.proxyEpoch;
		result.successEpoch = state.successEpoch;
		const auto policy = EndpointConcurrencyPolicyFor(
			state,
			request.use,
			now);
		auto denialAllowsRotation = true;
		const auto denied = [&] {
			if (state.terminalUntil > now) {
				result.retryAfter = state.terminalUntil - now;
				return true;
			}
			if (state.nextHandshakeAt > now
				&& (!state.relayProven || policy.handshakeSpacing > 0)) {
				result.retryAfter = state.nextHandshakeAt - now;
				return true;
			}
			if (!policy.useAllowed) {
				denialAllowsRotation = false;
				result.retryAfter = policy.retryAfter;
				return true;
			}
			if (state.active >= policy.activeCap) {
				result.retryAfter = policy.retryAfter;
				return true;
			}
			return false;
		}();
		if (denied) {
			result.action = AdmissionAction::StartAfter;
			result.blockedBy = state.lastFailure;
			if (!denialAllowsRotation) {
				state.deniedSince = 0;
				state.lastDenialRotationSignal = 0;
			} else if (!state.deniedSince) {
				state.deniedSince = now;
			} else if (now - state.deniedSince >= kDeniedRotationAfter
				&& (now - state.lastDenialRotationSignal
					>= kDeniedRotationAfter)) {
				state.lastDenialRotationSignal = now;
				rotationEvent = EndpointEvent{
					.endpoint = state.endpoint,
					.reason = state.lastFailure,
					.terminalUntil = now + kDeniedRotationAfter,
					.rotationAllowed = true,
				};
				starvationDiagnostics = CanonicalDiagnosticsEvent(
					ProxyDiagnosticsPhase::CanonicalDegraded,
					state,
					state.lastFailure,
					u"mtproxy admission starving, requesting rotation"_q);
			}
		} else {
			state.deniedSince = 0;
			state.lastDenialRotationSignal = 0;
			if (policy.handshakeSpacing > 0) {
				state.nextHandshakeAt = now + policy.handshakeSpacing;
			}
			const auto attemptStartedAt = now;
			result.attemptId = ++state.lastAttemptId;
			state.attemptStarts.emplace(result.attemptId, attemptStartedAt);
			state.active = int(state.attemptStarts.size());
			result.proxyGeneration = request.proxyGeneration;
			result.proxyEpoch = state.proxyEpoch;
			result.successEpoch = state.successEpoch;
			result.attemptStartedAt = attemptStartedAt;
			result.lease = EndpointAttemptLease(
				key,
				result.attemptId,
				request.proxyGeneration,
				state.proxyEpoch,
				state.successEpoch,
				attemptStartedAt);
		}
	}
	if (starvationDiagnostics) {
		WriteProxyDiagnosticsLine(std::move(*starvationDiagnostics));
	}
	if (rotationEvent) {
		Events.fire(std::move(*rotationEvent));
	}
	return result;
}

void EndpointHealth::reportFailure(FailureReport report) {
	if (report.lease) {
		if (!report.proxyGeneration) {
			report.proxyGeneration = report.lease->proxyGeneration();
		}
		if (!report.attemptId) {
			report.attemptId = report.lease->attemptId();
		}
		if (!report.proxyEpoch) {
			report.proxyEpoch = report.lease->proxyEpoch();
		}
		if (!report.successEpoch) {
			report.successEpoch = report.lease->successEpoch();
		}
		if (!report.attemptStartedAt) {
			report.attemptStartedAt = report.lease->startedAt();
		}
	}
	if (report.lease) {
		report.lease->release();
	}
	if (report.reason == FailureReason::None) {
		return;
	}
	if (report.use == EndpointUse::ProxyCheck) {
		LogProbeAttemptFailure(report);
		return;
	}
	const auto key = EndpointKey(report.endpoint);
	const auto routeKey = RouteKey(report.endpoint.route);
	const auto diagnostic = ToLegacyDiagnostic(report.reason);
	const auto now = crl::now();
	auto event = EndpointEvent();
	auto capabilityRelayFailure = std::optional<CapabilityFailure>();
	QMutexLocker lock(&StatesMutex);
	auto &state = States[key];
	if (FailureFromStaleAttempt(report, state)) {
		const auto recipeLevel = state.recipeLevel;
		lock.unlock();
		LogStaleAttemptFailure(report, recipeLevel);
		return;
	}
	ApplyProxyGeneration(state, report.proxyGeneration);
	state.endpoint = report.endpoint;
	if (report.reason != FailureReason::ServerHelloOkNoAppData
		&& report.reason != FailureReason::ServerHelloOkNoMtprotoData
		&& report.reason != FailureReason::ConnectedNoMtprotoData
		&& report.reason != FailureReason::MtpReceiveTimeoutAfterData) {
		lock.unlock();
		ProxyCapabilityCache::Instance().noteMtproxyFailure(
			CapabilityProxyKey(report.endpoint.canonical),
			RouteKey(report.endpoint.route),
			diagnostic);
		lock.relock();
	}
	NoteRouteFailure(state, report.endpoint.route, report.reason);
	DowngradeRecipeForRelayStall(state, report.reason);
	if (SoftNoAppDataFailure(state, report.reason, now)) {
		state.relayProven = false;
		state.nextHandshakeAt = now + kNoAppDataSoftRetry;
		auto diagnosticsEvent = CanonicalDiagnosticsEvent(
			ProxyDiagnosticsPhase::RouteFailed,
			state,
			report.reason,
			u"mtproxy no appdata warning after recent relay success"_q);
		lock.unlock();
		WriteProxyDiagnosticsLine(std::move(diagnosticsEvent));
		return;
	}
	if (FailureIsRouteOnly(report.reason) && !report.routesExhausted) {
		// Feed the open scheduler: connect timeouts slow down the pace
		// of new opens to this endpoint. The exhausted follow-up report
		// describes the same failed cycle, so it does not count again.
		NoteConnectTimeout(report.endpoint);
		return;
	}
	if (state.terminalUntil > now) {
		// An active cooldown means this connect cycle already produced a
		// terminal verdict. Several sockets dying in one storm report
		// their failures within the same second, and counting each of
		// them would ratchet consecutiveFailures and the stealth recipe
		// several levels per single incident (observed: recipe 1->4 in
		// under a second when four sockets died together). One incident,
		// one strike.
		return;
	}
	if (report.routesExhausted) {
		++state.exhaustedSinceSuccess;
		if (state.lastSuccessAt
			&& state.exhaustedSinceSuccess < kExhaustedStrikesAfterSuccess
			&& FailureIsRouteOnly(report.reason)) {
			// The proxy served connections before and this is likely
			// per-connect throttling - keep it route-level for now so
			// working connections and retries are not locked out.
			return;
		}
	}
	if (!routeKey.isEmpty()
		&& HasHealthyRoute(state)
		&& !report.routesExhausted) {
		return;
	}
	state.lastFailure = report.reason;
	state.lastDiagnostic = diagnostic;
	if (report.reason == FailureReason::ServerHelloOkNoAppData
		|| report.reason == FailureReason::ServerHelloOkNoMtprotoData
		|| report.reason == FailureReason::MtpReceiveTimeoutAfterData
		|| report.reason == FailureReason::ConnectedNoMtprotoData) {
		state.relayProven = false;
	}
	const auto policy = EndpointConcurrencyPolicyFor(
		state,
		report.use,
		now);
	if (policy.recipeEscalationAllowed && state.recipeLevel < 4) {
		++state.recipeLevel;
	}
	if (report.configuredTlsProfile == ProxyTlsProfile::AutoRotate
		&& FailureNeedsTlsRotation(report.reason)) {
		(void)RotateTlsProfileOnFailure(
			key,
			diagnostic,
			report.sentProfile);
	}
	const auto needsCooldown = FailureNeedsCooldown(report.reason)
		|| report.routesExhausted;
	auto noAppDataWarning = false;
	if (needsCooldown) {
		++state.consecutiveFailures;
		noAppDataWarning = NoAppDataWarningStrike(
			report.reason,
			state.consecutiveFailures);
		state.healthy = false;
		state.halfOpen = true;
		auto cooldown = CooldownFor(
			report.reason,
			state.consecutiveFailures);
		const auto recentSuccess = state.lastSuccessAt
			&& (now - state.lastSuccessAt < kRecentSuccessWindow);
		if (recentSuccess && FailureNeedsRecipeEscalation(report.reason)) {
			cooldown = std::min(cooldown, kThrottledRetryCooldown);
			NoteConnectTimeout(report.endpoint);
		}
		state.terminalUntil = now + cooldown;
	}
	event = {
		.endpoint = state.endpoint,
		.reason = state.lastFailure,
		.terminalUntil = state.terminalUntil,
		.rotationAllowed = needsCooldown && !noAppDataWarning,
	};
	const auto degraded = needsCooldown && !noAppDataWarning;
	if (degraded && RelayFailureInvalidatesCapability(report.reason)) {
		capabilityRelayFailure = CapabilityFailure{
			.proxyKey = CapabilityProxyKey(report.endpoint.canonical),
			.routeKey = RouteKey(report.endpoint.route),
			.diagnostic = diagnostic,
		};
	}
	auto diagnosticsEvent = CanonicalDiagnosticsEvent(
		degraded
			? ProxyDiagnosticsPhase::CanonicalDegraded
			: ProxyDiagnosticsPhase::RouteFailed,
		state,
		report.reason,
		noAppDataWarning
			? u"mtproxy no appdata warning"_q
			: degraded
			? u"mtproxy canonical endpoint degraded"_q
			: u"mtproxy endpoint failure"_q);
	lock.unlock();
	if (capabilityRelayFailure) {
		ProxyCapabilityCache::Instance().noteMtproxyRelayFailure(
			capabilityRelayFailure->proxyKey,
			capabilityRelayFailure->routeKey,
			capabilityRelayFailure->diagnostic);
	}
	WriteProxyDiagnosticsLine(std::move(diagnosticsEvent));
	Events.fire(std::move(event));
}

void EndpointHealth::reportSuccess(SuccessReport report) {
	if (report.lease) {
		if (!report.proxyGeneration) {
			report.proxyGeneration = report.lease->proxyGeneration();
		}
		if (!report.attemptId) {
			report.attemptId = report.lease->attemptId();
		}
		if (!report.proxyEpoch) {
			report.proxyEpoch = report.lease->proxyEpoch();
		}
		if (!report.successEpoch) {
			report.successEpoch = report.lease->successEpoch();
		}
		if (!report.attemptStartedAt) {
			report.attemptStartedAt = report.lease->startedAt();
		}
	}
	if (report.lease) {
		report.lease->release();
	}
	const auto now = crl::now();
	const auto key = EndpointKey(report.endpoint);
	const auto routeKey = RouteKey(report.endpoint.route);
	auto capabilitySuccess = std::optional<CapabilitySuccess>();
	auto diagnosticsEvent = std::optional<ProxyDiagnosticsEvent>();
	QMutexLocker lock(&StatesMutex);
	auto &state = States[key];
	if (SuccessFromStaleAttempt(report, state)) {
		return;
	}
	ApplyProxyGeneration(state, report.proxyGeneration);
	state.endpoint = report.endpoint;
	const auto successRecipeLevel = state.recipeLevel;
	const auto wasDegraded = (state.lastFailure != FailureReason::None)
		|| (state.terminalUntil > 0)
		|| state.halfOpen;
	if (!routeKey.isEmpty()) {
		NoteRouteSuccess(state, report.endpoint.route);
	}
	state.recipeLevel = 0;
	state.lastSuccessAt = now;
	state.exhaustedSinceSuccess = 0;
	if (report.scope == SuccessScope::Relay) {
		state.relayProven = true;
		state.lastRelaySuccessAt = now;
		++state.successEpoch;
		++state.proxyEpoch;
		state.lastGoodProfile = report.sentProfile;
		state.lastGoodRoute = report.endpoint.route;
		capabilitySuccess = CapabilitySuccess{
			.proxyKey = CapabilityProxyKey(report.endpoint.canonical),
			.routeKey = RouteKey(report.endpoint.route),
			.route = RouteText(report.endpoint),
			.sentProfile = report.sentProfile,
			.stealth = report.stealth,
			.recipeLevel = successRecipeLevel,
			.relayProven = true,
		};
	}
	const auto relaySilenceFailure
		= (state.lastFailure == FailureReason::ServerHelloOkNoMtprotoData)
		|| (state.lastFailure == FailureReason::ConnectedNoMtprotoData);
	if (report.scope == SuccessScope::FakeTlsAppData
		&& relaySilenceFailure) {
		lock.unlock();
		NoteConnectSuccess(report.endpoint);
		return;
	}
	if (report.scope == SuccessScope::Handshake && relaySilenceFailure) {
		// A handshake success cannot clear a relay-silence cooldown: on a
		// dead relay every reconnect handshakes fine, and treating that
		// as recovery would repaint the endpoint green each cycle and
		// keep the sessions hammering it forever. Only an actual MTProto
		// payload (SuccessScope::Relay) proves the endpoint end-to-end.
		lock.unlock();
		NoteConnectSuccess(report.endpoint);
		return;
	}
	state.lastFailure = FailureReason::None;
	state.lastDiagnostic.clear();
	state.terminalUntil = 0;
	state.consecutiveFailures = 0;
	state.healthy = true;
	state.halfOpen = false;
	if (wasDegraded) {
		diagnosticsEvent = CanonicalDiagnosticsEvent(
			ProxyDiagnosticsPhase::CanonicalRecovered,
			state,
			FailureReason::None,
			u"mtproxy canonical endpoint recovered"_q);
	}
	lock.unlock();
	NoteConnectSuccess(report.endpoint);
	if (capabilitySuccess) {
		ProxyCapabilityCache::Instance().noteMtproxySuccess(
			capabilitySuccess->proxyKey,
			capabilitySuccess->routeKey,
			capabilitySuccess->route,
			capabilitySuccess->sentProfile,
			capabilitySuccess->stealth,
			capabilitySuccess->recipeLevel,
			capabilitySuccess->relayProven);
	}
	if (diagnosticsEvent) {
		WriteProxyDiagnosticsLine(std::move(*diagnosticsEvent));
	}
}

void EndpointHealth::noteRelayStall(RelayStallReport report) {
	// An established connection that had already received MTProto data
	// went silent mid-session. That is not a failure of any particular
	// connect attempt (no cooldown, reconnects stay allowed), but the
	// relay is no longer proven: the reconnect wave that follows must go
	// out as scouts, not as the full healthy-cap herd.
	auto capabilityRelayFailure = std::optional<CapabilityFailure>();
	auto staleReport = FailureReport{
		.endpoint = report.endpoint,
		.use = report.use,
		.reason = FailureReason::MtpReceiveTimeoutAfterData,
		.proxyGeneration = report.proxyGeneration,
		.attemptId = report.attemptId,
		.proxyEpoch = report.proxyEpoch,
		.successEpoch = report.successEpoch,
		.attemptStartedAt = report.attemptStartedAt,
	};
	{
		QMutexLocker lock(&StatesMutex);
		const auto i = States.find(EndpointKey(report.endpoint));
		if (i != end(States)) {
			auto &state = i->second;
			if (FailureFromStaleAttempt(staleReport, state)) {
				const auto recipeLevel = state.recipeLevel;
				lock.unlock();
				LogStaleAttemptFailure(staleReport, recipeLevel);
				return;
			}
			ApplyProxyGeneration(state, report.proxyGeneration);
			state.relayProven = false;
		}
		capabilityRelayFailure = CapabilityFailure{
			.proxyKey = CapabilityProxyKey(report.endpoint.canonical),
			.routeKey = RouteKey(report.endpoint.route),
			.diagnostic = u"relay_stall"_q,
		};
	}
	if (capabilityRelayFailure) {
		ProxyCapabilityCache::Instance().noteMtproxyRelayFailure(
			capabilityRelayFailure->proxyKey,
			capabilityRelayFailure->routeKey,
			capabilityRelayFailure->diagnostic);
	}
}

Snapshot EndpointHealth::snapshot(const EndpointId &endpoint) const {
	const auto key = EndpointKey(endpoint);
	QMutexLocker lock(&StatesMutex);
	const auto i = States.find(key);
	if (i != end(States)) {
		return MakeSnapshot(i->second);
	}
	auto result = Snapshot();
	result.endpoint = endpoint;
	return result;
}

auto EndpointHealth::changes() const
-> rpl::producer<EndpointEvent> {
	return Events.events();
}

void EndpointHealth::releaseAttempt(
		const QString &key,
		uint64 attemptId) {
	QMutexLocker lock(&StatesMutex);
	const auto i = States.find(key);
	if (i == end(States) || !attemptId) {
		return;
	}
	i->second.attemptStarts.erase(attemptId);
	i->second.active = int(i->second.attemptStarts.size());
}

} // namespace MTP::details::MtProxy
