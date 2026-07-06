/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "mtproto/proxy/mtproxy/endpoint_health.h"

#include "mtproto/connection_abstract.h"
#include "mtproto/proxy/capabilities.h"
#include "mtproto/proxy/diagnostics.h"
#include "mtproto/proxy/mtproxy/adaptive_policy.h"
#include "mtproto/proxy/mtproxy/open_scheduler.h"
#include "base/algorithm.h"
#include "base/timer.h"

#include <QtCore/QCryptographicHash>
#include <QtCore/QMutex>
#include <QtNetwork/QAbstractSocket>
#include <QtNetwork/QHostAddress>
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
// A proven-good proxy must allow browser-like concurrency: opening a
// chat full of photos fans out ~10 media/download connections at once,
// all sharing this one endpoint. Capping healthy concurrency too low
// (the whole point of the Android client, which has no such cap, is
// that it just works) queues those connections behind a trickle,
// sessions time out waiting, cancel and retry - a self-inflicted storm
// that looks exactly like a throttled proxy. Stay generous while
// healthy; the low caps below only engage once failures prove trouble.
constexpr auto kColdActiveCap = 2;
constexpr auto kUnknownActiveCap = kColdActiveCap;
constexpr auto kDpiFailureActiveCap = 1;
constexpr auto kHealthyActiveCap = 8;
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
constexpr auto kThrottledRetryCooldown = crl::time(3000);

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
	uint64 proxyEpoch = 1;
	uint64 lastAttemptId = 0;
	std::map<uint64, crl::time> attemptStarts;
	crl::time deniedSince = 0;
	crl::time lastDenialRotationSignal = 0;
	crl::time lastSuccessAt = 0;
	int exhaustedSinceSuccess = 0;
};

struct RouteState {
	RouteEndpoint route;
	FailureReason lastFailure = FailureReason::None;
	bool healthy = false;
};

struct EndpointConcurrencyPolicy {
	int activeCap = kUnknownActiveCap;
	crl::time handshakeSpacing = 0;
	crl::time retryAfter = kQueuedRetry;
	bool recipeEscalationAllowed = false;
};

QMutex StatesMutex;
std::map<QString, EndpointState> States;
std::map<QString, RouteState> Routes;
rpl::event_stream<EndpointEvent> Events;

[[nodiscard]] QByteArray BytesToQByteArray(bytes::const_span data) {
	auto result = QByteArray();
	result.reserve(int(data.size()));
	for (const auto byte : data) {
		result.append(char(gsl::to_integer<unsigned char>(byte)));
	}
	return result;
}

[[nodiscard]] QString HashBytes(bytes::const_span data) {
	const auto hash = QCryptographicHash::hash(
		BytesToQByteArray(data),
		QCryptographicHash::Sha256);
	return QString::fromLatin1(hash.toHex());
}

[[nodiscard]] QString HashText(const QString &text) {
	const auto hash = QCryptographicHash::hash(
		text.toUtf8(),
		QCryptographicHash::Sha256);
	return QString::fromLatin1(hash.toHex());
}

[[nodiscard]] QString DomainFromSecret(bytes::const_span secret) {
	if (secret.size() <= 17) {
		return QString();
	}
	return QString::fromUtf8(BytesToQByteArray(secret.subspan(17)));
}

[[nodiscard]] QString ProxyIdentityHost(const ProxyData &proxy) {
	return proxy.originalHost.isEmpty()
		? proxy.host
		: proxy.originalHost;
}

[[nodiscard]] RouteAddressFamily AddressFamilyFor(const QString &address) {
	if (address.isEmpty()) {
		return RouteAddressFamily::Unknown;
	}
	const auto parsed = QHostAddress(address);
	switch (parsed.protocol()) {
	case QAbstractSocket::IPv4Protocol:
		return RouteAddressFamily::IPv4;
	case QAbstractSocket::IPv6Protocol:
		return RouteAddressFamily::IPv6;
	default:
		return RouteAddressFamily::Host;
	}
}

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
	case FailureReason::ProxyProtocolBadResponse:
		return true;
	case FailureReason::None:
	case FailureReason::TcpConnectTimeout:
	case FailureReason::TcpConnectedNoClientHelloWrite:
	case FailureReason::AppDataRemoteClosed:
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
	case FailureReason::ServerHelloOkNoAppData:
		return true;
	case FailureReason::None:
	case FailureReason::DnsFailed:
	case FailureReason::TcpConnectTimeout:
	case FailureReason::TcpConnectedNoClientHelloWrite:
	case FailureReason::AppDataRemoteClosed:
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
	case FailureReason::AppDataRemoteClosed:
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
	case FailureReason::AppDataRemoteClosed:
	case FailureReason::Network:
	case FailureReason::ProxyProtocolBadResponse:
		return false;
	}
	return false;
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
	if (consecutiveFailures <= 1) {
		return kFirstCooldown;
	} else if (consecutiveFailures == 2) {
		return kSecondCooldown;
	}
	return kMaxCooldown;
}

[[nodiscard]] EndpointConcurrencyPolicy EndpointConcurrencyPolicyFor(
		const EndpointState &state) {
	auto policy = EndpointConcurrencyPolicy();
	if (FailureNeedsRecipeEscalation(state.lastFailure)) {
		policy.activeCap = kDpiFailureActiveCap;
		policy.retryAfter = kQueuedRetry;
		policy.recipeEscalationAllowed = true;
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
	case FailureReason::AppDataRemoteClosed:
	case FailureReason::Network:
	case FailureReason::ProxyProtocolBadResponse:
		break;
	}
	if (state.healthy) {
		policy.activeCap = kHealthyActiveCap;
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

} // namespace

EndpointAttemptLease::EndpointAttemptLease(
	QString key,
	uint64 attemptId,
	uint64 proxyEpoch)
: _key(std::move(key))
, _attemptId(attemptId)
, _proxyEpoch(proxyEpoch)
, _active(true) {
}

EndpointAttemptLease::EndpointAttemptLease(
		EndpointAttemptLease &&other) noexcept
: _key(std::move(other._key))
, _attemptId(base::take(other._attemptId))
, _proxyEpoch(base::take(other._proxyEpoch))
, _active(base::take(other._active)) {
}

EndpointAttemptLease &EndpointAttemptLease::operator=(
		EndpointAttemptLease &&other) noexcept {
	if (this != &other) {
		release();
		_key = std::move(other._key);
		_attemptId = base::take(other._attemptId);
		_proxyEpoch = base::take(other._proxyEpoch);
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

uint64 EndpointAttemptLease::proxyEpoch() const {
	return _proxyEpoch;
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
		PruneExpiredAttempts(state, now);
		result.stealth = request.stealth;
		result.effectiveTlsProfile = ResolveEffectiveTlsProfile(
			request.configuredTlsProfile,
			key);
		result.proxyEpoch = state.proxyEpoch;
		const auto policy = EndpointConcurrencyPolicyFor(state);
		const auto denied = [&] {
			if (state.terminalUntil > now) {
				result.retryAfter = state.terminalUntil - now;
				return true;
			}
			if (state.active >= policy.activeCap) {
				result.retryAfter = policy.retryAfter;
				return true;
			}
			if (policy.handshakeSpacing > 0
				&& state.active > 0
				&& state.nextHandshakeAt > now) {
				result.retryAfter = state.nextHandshakeAt - now;
				return true;
			}
			return false;
		}();
		if (denied) {
			result.action = AdmissionAction::StartAfter;
			result.blockedBy = state.lastFailure;
			if (!state.deniedSince) {
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
			const auto policy = EndpointConcurrencyPolicyFor(state);
			if (policy.handshakeSpacing > 0) {
				state.nextHandshakeAt = now + policy.handshakeSpacing;
			}
			result.attemptId = ++state.lastAttemptId;
			state.attemptStarts.emplace(result.attemptId, now);
			state.active = int(state.attemptStarts.size());
			result.proxyEpoch = state.proxyEpoch;
			result.lease = EndpointAttemptLease(
				key,
				result.attemptId,
				state.proxyEpoch);
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
		report.lease->release();
	}
	if (report.reason == FailureReason::None) {
		return;
	}
	const auto key = EndpointKey(report.endpoint);
	const auto routeKey = RouteKey(report.endpoint.route);
	const auto diagnostic = ToLegacyDiagnostic(report.reason);
	const auto now = crl::now();
	auto event = EndpointEvent();
	ProxyCapabilityCache::Instance().noteMtproxyFailure(
		CapabilityProxyKey(report.endpoint.canonical),
		RouteKey(report.endpoint.route),
		diagnostic);
	QMutexLocker lock(&StatesMutex);
	auto &state = States[key];
	state.endpoint = report.endpoint;
	NoteRouteFailure(state, report.endpoint.route, report.reason);
	if (FailureIsRouteOnly(report.reason) && !report.routesExhausted) {
		// Feed the open scheduler: connect timeouts slow down the pace
		// of new opens to this endpoint. The exhausted follow-up report
		// describes the same failed cycle, so it does not count again.
		NoteConnectTimeout(report.endpoint);
		return;
	}
	if (report.routesExhausted && state.terminalUntil > now) {
		// The canonical endpoint is already cooling down, likely from the
		// socket-level report of the same connect cycle - don't escalate
		// consecutiveFailures twice for one failure.
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
	const auto policy = EndpointConcurrencyPolicyFor(state);
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
	if (needsCooldown) {
		++state.consecutiveFailures;
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
		.rotationAllowed = needsCooldown,
	};
	auto diagnosticsEvent = CanonicalDiagnosticsEvent(
		ProxyDiagnosticsPhase::CanonicalDegraded,
		state,
		report.reason,
		u"mtproxy canonical endpoint degraded"_q);
	lock.unlock();
	WriteProxyDiagnosticsLine(std::move(diagnosticsEvent));
	Events.fire(std::move(event));
}

void EndpointHealth::reportSuccess(SuccessReport report) {
	if (report.lease) {
		report.lease->release();
	}
	const auto key = EndpointKey(report.endpoint);
	const auto routeKey = RouteKey(report.endpoint.route);
	NoteConnectSuccess(report.endpoint);
	ProxyCapabilityCache::Instance().noteMtproxySuccess(
		CapabilityProxyKey(report.endpoint.canonical),
		RouteKey(report.endpoint.route),
		report.sentProfile,
		report.stealth);
	QMutexLocker lock(&StatesMutex);
	auto &state = States[key];
	state.endpoint = report.endpoint;
	const auto wasDegraded = (state.lastFailure != FailureReason::None)
		|| (state.terminalUntil > 0)
		|| state.halfOpen;
	if (!routeKey.isEmpty()) {
		NoteRouteSuccess(state, report.endpoint.route);
	}
	state.lastFailure = FailureReason::None;
	state.lastDiagnostic.clear();
	state.terminalUntil = 0;
	state.consecutiveFailures = 0;
	state.recipeLevel = 0;
	state.healthy = true;
	state.halfOpen = false;
	state.lastSuccessAt = crl::now();
	state.exhaustedSinceSuccess = 0;
	if (wasDegraded) {
		auto diagnosticsEvent = CanonicalDiagnosticsEvent(
			ProxyDiagnosticsPhase::CanonicalRecovered,
			state,
			FailureReason::None,
			u"mtproxy canonical endpoint recovered"_q);
		lock.unlock();
		WriteProxyDiagnosticsLine(std::move(diagnosticsEvent));
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

EndpointId EndpointIdFromProxy(
		const ProxyData &proxy,
		const ProxyStealthOptions &stealth,
		const QString &address,
		int port) {
	auto result = EndpointId();
	result.canonical.type = proxy.type;
	result.canonical.originalHost = ProxyIdentityHost(proxy);
	result.canonical.port = int(proxy.port);
	result.canonical.proxyKind = proxy.type;
	result.route = RouteEndpointFromAddress(
		address.isEmpty() ? result.canonical.originalHost : address,
		port ? port : int(proxy.port),
		stealth.transport,
		address.isEmpty() ? QString() : result.canonical.originalHost);
	if (proxy.type == ProxyData::Type::Mtproto) {
		const auto secret = proxy.secretFromMtprotoPassword();
		if (!secret.empty()) {
			result.canonical.secretHash = HashBytes(secret);
			result.canonical.domainFromSecret = DomainFromSecret(secret);
			return result;
		}
	}
	result.canonical.secretHash = HashText(proxy.password);
	return result;
}

EndpointId EndpointIdFromAddress(
		const QString &address,
		int port,
		bytes::const_span secret,
		ProxyTransport transport) {
	auto result = EndpointId();
	result.canonical.type = ProxyData::Type::Mtproto;
	result.canonical.originalHost = address;
	result.canonical.port = port;
	result.canonical.secretHash = HashBytes(secret);
	result.canonical.domainFromSecret = DomainFromSecret(secret);
	result.canonical.proxyKind = ProxyData::Type::Mtproto;
	result.route = RouteEndpointFromAddress(address, port, transport);
	return result;
}

RouteEndpoint RouteEndpointFromAddress(
		const QString &address,
		int port,
		ProxyTransport transport,
		const QString &resolvedFromHost) {
	return {
		.address = address,
		.port = port,
		.addressFamily = AddressFamilyFor(address),
		.transport = transport,
		.resolvedFromHost = resolvedFromHost,
	};
}

bool EndpointEmpty(const CanonicalProxyEndpoint &endpoint) {
	return endpoint.originalHost.isEmpty() || endpoint.port <= 0;
}

bool EndpointEmpty(const EndpointId &endpoint) {
	return EndpointEmpty(endpoint.canonical);
}

QString EndpointKey(const CanonicalProxyEndpoint &endpoint) {
	if (EndpointEmpty(endpoint)) {
		return QString();
	}
	return endpoint.originalHost
		+ u":%1:"_q.arg(endpoint.port)
		+ QString::number(int(endpoint.type))
		+ ':'
		+ QString::number(int(endpoint.proxyKind))
		+ ':'
		+ endpoint.secretHash
		+ ':'
		+ endpoint.domainFromSecret;
}

QString EndpointKey(const EndpointId &endpoint) {
	return EndpointKey(endpoint.canonical);
}

QString CapabilityProxyKey(const CanonicalProxyEndpoint &endpoint) {
	// Must produce exactly the key ProxyCapabilityKey(proxy) produces for
	// the same proxy, or ProxyCapabilityCache lookups never find the cards
	// written here: host:port:type:secretHash:domain, no proxyKind segment.
	if (EndpointEmpty(endpoint)) {
		return QString();
	}
	return endpoint.originalHost
		+ ':'
		+ QString::number(endpoint.port)
		+ ':'
		+ QString::number(int(endpoint.type))
		+ ':'
		+ endpoint.secretHash
		+ ':'
		+ endpoint.domainFromSecret;
}

QString RouteKey(const RouteEndpoint &route) {
	if (route.address.isEmpty() || route.port <= 0) {
		return QString();
	}
	return route.address
		+ u":%1:"_q.arg(route.port)
		+ QString::number(int(route.addressFamily))
		+ ':'
		+ QString::number(int(route.transport))
		+ ':'
		+ route.resolvedFromHost;
}

QString RouteKey(const EndpointId &endpoint) {
	return RouteKey(endpoint.route);
}

QString ToLegacyDiagnostic(FailureReason reason) {
	switch (reason) {
	case FailureReason::DnsFailed:
		return u"dns_failed"_q;
	case FailureReason::TcpConnectTimeout:
		return u"tcp_connect_timeout"_q;
	case FailureReason::TcpConnectedNoClientHelloWrite:
		return u"tcp_connected_no_client_hello_write"_q;
	case FailureReason::ClientHelloSentNoServerHello:
		return u"client_hello_sent_no_server_hello"_q;
	case FailureReason::TlsAlertAfterClientHello:
		return u"tls_alert_after_client_hello"_q;
	case FailureReason::ServerHelloHmacMismatch:
		return u"server_hello_hmac_mismatch"_q;
	case FailureReason::ServerHelloOkNoAppData:
		return u"server_hello_ok_no_appdata"_q;
	case FailureReason::AppDataRemoteClosed:
		return u"appdata_remote_closed"_q;
	case FailureReason::Network:
		return u"network_error"_q;
	case FailureReason::ProxyProtocolBadResponse:
		return u"proxy_protocol_bad_response"_q;
	case FailureReason::None:
		return QString();
	}
	return QString();
}

FailureReason FailureReasonFromErrorCode(int errorCode) {
	if (errorCode == AbstractConnection::kErrorCodeOther) {
		return FailureReason::None;
	}
	switch (errorCode) {
	case QAbstractSocket::HostNotFoundError:
	case QAbstractSocket::ProxyNotFoundError:
		return FailureReason::DnsFailed;
	case QAbstractSocket::SocketTimeoutError:
	case QAbstractSocket::ProxyConnectionTimeoutError:
		return FailureReason::TcpConnectTimeout;
	case QAbstractSocket::RemoteHostClosedError:
	case QAbstractSocket::ProxyConnectionClosedError:
		return FailureReason::AppDataRemoteClosed;
	case QAbstractSocket::NetworkError:
		return FailureReason::Network;
	}
	return FailureReason::None;
}

ProxyConnectionError ToProxyConnectionError(FailureReason reason) {
	switch (reason) {
	case FailureReason::DnsFailed:
		return ProxyConnectionError::HostNotFound;
	case FailureReason::TcpConnectTimeout:
	case FailureReason::TcpConnectedNoClientHelloWrite:
		return ProxyConnectionError::Timeout;
	case FailureReason::AppDataRemoteClosed:
		return ProxyConnectionError::RemoteClosed;
	case FailureReason::Network:
		return ProxyConnectionError::Network;
	case FailureReason::ProxyProtocolBadResponse:
	case FailureReason::ClientHelloSentNoServerHello:
	case FailureReason::TlsAlertAfterClientHello:
	case FailureReason::ServerHelloHmacMismatch:
	case FailureReason::ServerHelloOkNoAppData:
		return ProxyConnectionError::BadResponse;
	case FailureReason::None:
		return ProxyConnectionError::None;
	}
	return ProxyConnectionError::Unknown;
}

ProxyMtproxyTerminalReason ToProxyMtproxyTerminalReason(
		FailureReason reason) {
	switch (reason) {
	case FailureReason::DnsFailed:
		return ProxyMtproxyTerminalReason::DnsFailed;
	case FailureReason::TcpConnectTimeout:
		return ProxyMtproxyTerminalReason::TcpConnectTimeout;
	case FailureReason::TcpConnectedNoClientHelloWrite:
		return ProxyMtproxyTerminalReason::TcpConnectedNoClientHelloWrite;
	case FailureReason::ClientHelloSentNoServerHello:
		return ProxyMtproxyTerminalReason::ClientHelloSentNoServerHello;
	case FailureReason::TlsAlertAfterClientHello:
		return ProxyMtproxyTerminalReason::TlsAlertAfterClientHello;
	case FailureReason::ServerHelloHmacMismatch:
		return ProxyMtproxyTerminalReason::ServerHelloHmacMismatch;
	case FailureReason::ServerHelloOkNoAppData:
		return ProxyMtproxyTerminalReason::ServerHelloOkNoAppData;
	case FailureReason::AppDataRemoteClosed:
		return ProxyMtproxyTerminalReason::AppDataRemoteClosed;
	case FailureReason::ProxyProtocolBadResponse:
		return ProxyMtproxyTerminalReason::ProxyProtocolBadResponse;
	case FailureReason::None:
	case FailureReason::Network:
		return ProxyMtproxyTerminalReason::None;
	}
	return ProxyMtproxyTerminalReason::None;
}

} // namespace MTP::details::MtProxy
