/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "mtproto/proxy/mtproxy/endpoint_health.h"

#include "mtproto/proxy/mtproxy/endpoint_health_capabilities.h"
#include "mtproto/proxy/mtproxy/endpoint_health_diagnostics.h"
#include "mtproto/proxy/mtproxy/endpoint_health_policy.h"
#include "mtproto/proxy/mtproxy/endpoint_health_state.h"

#include "mtproto/proxy/diagnostics.h"
#include "mtproto/proxy/mtproxy/adaptive_policy.h"
#include "mtproto/proxy/mtproxy/open_scheduler.h"
#include "mtproto/runtime/runtime_environment.h"
#include "base/algorithm.h"
#include "base/timer.h"

#include <crl/crl_on_main.h>
#include <QtCore/QMutex>
#include <rpl/event_stream.h>

#include <map>
#include <optional>
#include <set>

namespace MTP::details::MtProxy {

struct EndpointHealthStorage {
	QMutex mutex;
	std::map<QString, EndpointState> states;
	std::map<QString, RouteState> routes;
	rpl::event_stream<EndpointEvent> events;
};

namespace {

// If every admission request for an endpoint has been denied for this
// long without a single grant, ask the rotation manager to look for
// another proxy instead of spinning on this one.
constexpr auto kDeniedRotationAfter = crl::time(20 * 1000);
constexpr auto kExhaustedStrikesAfterSuccess = 3;
constexpr auto kRecentSuccessWindow = crl::time(60 * 1000);

void NoteRouteFailure(
		EndpointHealthStorage &storage,
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
		EndpointHealthStorage &storage,
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

[[nodiscard]] bool HasHealthyRoute(
		const EndpointHealthStorage &storage,
		const EndpointState &state) {
	for (const auto &routeKey : state.routeKeys) {
		const auto i = storage.routes.find(routeKey);
		if (i != end(storage.routes) && i->second.healthy) {
			return true;
		}
	}
	return false;
}



} // namespace

EndpointAttemptLease::EndpointAttemptLease(
		EndpointHealth *owner,
		QString key,
		uint64 attemptId,
		uint64 proxyGeneration,
		uint64 proxyEpoch,
		uint64 successEpoch,
		crl::time startedAt)
: _owner(owner)
, _key(std::move(key))
, _attemptId(attemptId)
, _proxyGeneration(proxyGeneration)
, _proxyEpoch(proxyEpoch)
, _successEpoch(successEpoch)
, _startedAt(startedAt)
, _active(true) {
}

EndpointAttemptLease::EndpointAttemptLease(
		EndpointAttemptLease &&other) noexcept
: _owner(base::take(other._owner))
, _key(std::move(other._key))
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
		_owner = base::take(other._owner);
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


void EndpointAttemptLease::release() {
	if (!_active) {
		return;
	}
	_active = false;
	if (_owner) {
		_owner->releaseAttempt(_key, _attemptId);
	}
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

EndpointHealth::EndpointHealth(not_null<RuntimeEnvironment*> runtime)
: _runtime(runtime)
, _storage(std::make_unique<EndpointHealthStorage>()) {
}

EndpointHealth::~EndpointHealth() = default;

Admission EndpointHealth::admit(const AdmissionRequest &request) {
	const auto key = EndpointKey(request.endpoint);
	const auto now = crl::now();
	const auto effectiveTlsProfile = ResolveEffectiveTlsProfile(
		request.configuredTlsProfile,
		key);
	auto result = Admission();
	auto rotationEvent = std::optional<EndpointEvent>();
	auto starvationDiagnostics = std::optional<ProxyDiagnosticsEvent>();
	{
		QMutexLocker lock(&_storage->mutex);
		auto &state = _storage->states[key];
		state.endpoint = request.endpoint;
		ApplyProxyGeneration(state, request.proxyGeneration);
		PruneExpiredAttempts(state, now);
		result.stealth = request.stealth;
		result.effectiveTlsProfile = effectiveTlsProfile;
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
				this,
				key,
				result.attemptId,
				request.proxyGeneration,
				state.proxyEpoch,
				state.successEpoch,
				attemptStartedAt);
		}
	}
	if (starvationDiagnostics) {
		WriteProxyDiagnosticsLine(_runtime, std::move(*starvationDiagnostics));
	}
	if (rotationEvent) {
		fireEndpointEventOnMain(std::move(*rotationEvent));
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
		LogProbeAttemptFailure(_runtime, report);
		return;
	}
	const auto key = EndpointKey(report.endpoint);
	const auto routeKey = RouteKey(report.endpoint.route);
	const auto diagnostic = ToLegacyDiagnostic(report.reason);
	const auto now = crl::now();
	auto event = EndpointEvent();
	auto capabilityFailure = std::optional<CapabilityFailure>();
	auto capabilityRelayFailure = std::optional<CapabilityFailure>();
	auto noteConnectTimeout = false;
	auto rotateTlsProfile = false;
	QMutexLocker lock(&_storage->mutex);
	auto &state = _storage->states[key];
	if (FailureFromStaleAttempt(report, state)) {
		const auto recipeLevel = state.recipeLevel;
		lock.unlock();
		LogStaleAttemptFailure(_runtime, report, recipeLevel);
		return;
	}
	ApplyProxyGeneration(state, report.proxyGeneration);
	state.endpoint = report.endpoint;
	if (report.reason != FailureReason::ServerHelloOkNoAppData
		&& report.reason != FailureReason::ServerHelloOkNoMtprotoData
		&& report.reason != FailureReason::ConnectedNoMtprotoData
		&& report.reason != FailureReason::MtpReceiveTimeoutAfterData) {
		capabilityFailure = CapabilityFailure{
			.proxyKey = CapabilityProxyKey(report.endpoint.canonical),
			.routeKey = RouteKey(report.endpoint.route),
			.diagnostic = diagnostic,
		};
	}
	NoteRouteFailure(*_storage, state, report.endpoint.route, report.reason);
	DowngradeRecipeForRelayStall(state, report.reason);
	if (SoftNoAppDataFailure(state, report.reason, now)) {
		state.relayProven = false;
		state.nextHandshakeAt = now + NoAppDataSoftRetry();
		auto diagnosticsEvent = CanonicalDiagnosticsEvent(
			ProxyDiagnosticsPhase::RouteFailed,
			state,
			report.reason,
			u"mtproxy no appdata warning after recent relay success"_q);
		lock.unlock();
		WriteProxyDiagnosticsLine(_runtime, std::move(diagnosticsEvent));
		return;
	}
	if (FailureIsRouteOnly(report.reason) && !report.routesExhausted) {
		noteConnectTimeout = true;
		lock.unlock();
		if (capabilityFailure) {
			NoteCapabilityMtproxyFailure(
				report.endpoint,
				capabilityFailure->diagnostic);
		}
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
		lock.unlock();
		if (capabilityFailure) {
			NoteCapabilityMtproxyFailure(
				report.endpoint,
				capabilityFailure->diagnostic);
		}
		return;
	}
	if (report.routesExhausted) {
		++state.exhaustedSinceSuccess;
		if (state.lastSuccessAt
			&& state.exhaustedSinceSuccess < kExhaustedStrikesAfterSuccess
			&& FailureIsRouteOnly(report.reason)) {
			lock.unlock();
			if (capabilityFailure) {
				NoteCapabilityMtproxyFailure(
					report.endpoint,
					capabilityFailure->diagnostic);
			}
			return;
		}
	}
	if (!routeKey.isEmpty()
		&& HasHealthyRoute(*_storage, state)
		&& !report.routesExhausted) {
		lock.unlock();
		if (capabilityFailure) {
			NoteCapabilityMtproxyFailure(
				report.endpoint,
				capabilityFailure->diagnostic);
		}
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
		rotateTlsProfile = true;
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
			cooldown = std::min(cooldown, ThrottledRetryCooldown());
			noteConnectTimeout = true;
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
	if (capabilityFailure) {
		NoteCapabilityMtproxyFailure(
			report.endpoint,
			capabilityFailure->diagnostic);
	}
	if (capabilityRelayFailure) {
		NoteCapabilityMtproxyRelayFailure(*capabilityRelayFailure);
	}
	if (rotateTlsProfile) {
		(void)RotateTlsProfileOnFailure(
			key,
			diagnostic,
			report.sentProfile);
	}
	if (noteConnectTimeout) {
		NoteConnectTimeout(report.endpoint);
	}
	WriteProxyDiagnosticsLine(_runtime, std::move(diagnosticsEvent));
	fireEndpointEventOnMain(std::move(event));
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
	if (report.use == EndpointUse::ProxyCheck) {
		LogProbeAttemptSuccess(_runtime, report);
		return;
	}
	const auto now = crl::now();
	const auto key = EndpointKey(report.endpoint);
	const auto routeKey = RouteKey(report.endpoint.route);
	auto capabilitySuccess = std::optional<CapabilitySuccess>();
	auto diagnosticsEvent = std::optional<ProxyDiagnosticsEvent>();
	QMutexLocker lock(&_storage->mutex);
	auto &state = _storage->states[key];
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
		NoteRouteSuccess(*_storage, state, report.endpoint.route);
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
		NoteCapabilityMtproxySuccess(*capabilitySuccess);
	}
	if (diagnosticsEvent) {
		WriteProxyDiagnosticsLine(_runtime, std::move(*diagnosticsEvent));
	}
}

void EndpointHealth::noteRelayStall(RelayStallReport report) {
	auto capabilityRelayFailure = std::optional<CapabilityFailure>();
	auto staleRecipeLevel = std::optional<int>();
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
		QMutexLocker lock(&_storage->mutex);
		const auto i = _storage->states.find(EndpointKey(report.endpoint));
		if (i != end(_storage->states)) {
			auto &state = i->second;
			if (FailureFromStaleAttempt(staleReport, state)) {
				staleRecipeLevel = state.recipeLevel;
			} else {
				ApplyProxyGeneration(state, report.proxyGeneration);
				state.relayProven = false;
			}
		}
		if (!staleRecipeLevel) {
			capabilityRelayFailure = CapabilityFailure{
				.proxyKey = CapabilityProxyKey(report.endpoint.canonical),
				.routeKey = RouteKey(report.endpoint.route),
				.diagnostic = u"relay_stall"_q,
			};
		}
	}
	if (staleRecipeLevel) {
		LogStaleAttemptFailure(_runtime, staleReport, *staleRecipeLevel);
		return;
	}
	if (capabilityRelayFailure) {
		NoteCapabilityMtproxyRelayFailure(*capabilityRelayFailure);
	}
}

Snapshot EndpointHealth::snapshot(const EndpointId &endpoint) const {
	const auto key = EndpointKey(endpoint);
	QMutexLocker lock(&_storage->mutex);
	const auto i = _storage->states.find(key);
	if (i != end(_storage->states)) {
		return MakeSnapshot(i->second);
	}
	auto result = Snapshot();
	result.endpoint = endpoint;
	return result;
}

auto EndpointHealth::changes() const
-> rpl::producer<EndpointEvent> {
	return _storage->events.events();
}

void EndpointHealth::releaseAttempt(
		const QString &key,
		uint64 attemptId) {
	QMutexLocker lock(&_storage->mutex);
	const auto i = _storage->states.find(key);
	if (i == end(_storage->states) || !attemptId) {
		return;
	}
	i->second.attemptStarts.erase(attemptId);
	i->second.active = int(i->second.attemptStarts.size());
}

void EndpointHealth::fireEndpointEventOnMain(EndpointEvent event) {
	crl::on_main([=, event = std::move(event)]() mutable {
		_storage->events.fire(std::move(event));
	});
}

} // namespace MTP::details::MtProxy
