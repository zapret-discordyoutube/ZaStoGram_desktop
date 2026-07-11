/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "mtproto/proxy/mtproxy/endpoint_health.h"

#include "base/algorithm.h"
#include "base/timer.h"
#include "mtproto/proxy/mtproxy/endpoint_health_capabilities.h"
#include "mtproto/proxy/mtproxy/endpoint_health_diagnostics.h"
#include "mtproto/proxy/mtproxy/endpoint_health_policy.h"
#include "mtproto/proxy/mtproxy/endpoint_health_state.h"

#include "mtproto/proxy/diagnostics.h"
#include "mtproto/proxy/mtproxy/open_scheduler.h"
#include "mtproto/proxy/proxy_endpoint_context.h"
#include "mtproto/proxy/proxy_endpoint_context_p.h"
#include "mtproto/runtime/runtime_environment.h"

#include <crl/crl_on_main.h>
#include <QtCore/QMutex>
#include <rpl/event_stream.h>

#include <map>
#include <optional>
#include <set>

namespace MTP::details::MtProxy {

namespace {

// If every admission request for an endpoint has been denied for this
// long without a single grant, ask the rotation manager to look for
// another proxy instead of spinning on this one.
constexpr auto kDeniedRotationAfter = crl::time(20 * 1000);
constexpr auto kExhaustedStrikesAfterSuccess = 3;
constexpr auto kRecentSuccessWindow = crl::time(60 * 1000);

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

[[nodiscard]] bool HasHealthyRoute(
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

void ResolveLeaseIdentity(FailureReport &report) {
	if (!report.lease) {
		return;
	}
	report.runtimeId = report.lease->runtimeId();
	report.proxyGeneration = report.lease->proxyGeneration();
	report.attemptId = report.lease->attemptId();
	report.proxyEpoch = report.lease->proxyEpoch();
	report.successEpoch = report.lease->successEpoch();
	report.attemptStartedAt = report.lease->startedAt();
}

[[nodiscard]] bool FastWarmupEnabled(not_null<RuntimeEnvironment*> runtime) {
	// Evaluated before taking the storage mutex: the getter reaches into
	// application settings.
	const auto &settings = runtime->proxy();
	return settings.fastProxyWarmup ? settings.fastProxyWarmup() : true;
}

void ResolveLeaseIdentity(SuccessReport &report) {
	if (!report.lease) {
		return;
	}
	report.runtimeId = report.lease->runtimeId();
	report.proxyGeneration = report.lease->proxyGeneration();
	report.attemptId = report.lease->attemptId();
	report.proxyEpoch = report.lease->proxyEpoch();
	report.successEpoch = report.lease->successEpoch();
	report.attemptStartedAt = report.lease->startedAt();
}

} // namespace

EndpointAttemptLease::EndpointAttemptLease(
		std::shared_ptr<ProxyEndpointContext> context,
		QString key,
		ProxyRuntimeId runtimeId,
		uint64 attemptId,
		uint64 proxyGeneration,
		uint64 proxyEpoch,
		uint64 successEpoch,
		crl::time startedAt)
: _context(std::move(context))
, _key(std::move(key))
, _runtimeId(runtimeId)
, _attemptId(attemptId)
, _proxyGeneration(proxyGeneration)
, _proxyEpoch(proxyEpoch)
, _successEpoch(successEpoch)
, _startedAt(startedAt)
, _active(true) {
}

EndpointAttemptLease::EndpointAttemptLease(
		EndpointAttemptLease &&other) noexcept
: _context(std::move(other._context))
, _key(std::move(other._key))
, _runtimeId(base::take(other._runtimeId))
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
		_context = std::move(other._context);
		_key = std::move(other._key);
		_runtimeId = base::take(other._runtimeId);
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
	if (_context) {
		_context->releaseEndpointAttempt(_key, _attemptId);
	}
}

void EndpointAttemptLease::releaseAdmissionForRelayCandidate() {
	if (_active && _context) {
		_context->releaseAdmissionForRelayCandidate(
			_key,
			_runtimeId,
			_proxyGeneration,
			_attemptId);
	}
}

bool EndpointAttemptLease::active() const {
	return _active;
}

ProxyRuntimeId EndpointAttemptLease::runtimeId() const {
	return _runtimeId;
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

const QString &EndpointAttemptLease::endpointKey() const {
	return _key;
}

EndpointHealth::EndpointHealth(
	not_null<RuntimeEnvironment*> runtime,
	std::shared_ptr<ProxyEndpointContext> context)
: _runtime(runtime)
, _context(std::move(context))
, _runtimeId(runtime->proxyRuntimeId()) {
	Expects(_context != nullptr);
}

EndpointHealth::~EndpointHealth() = default;

Admission EndpointHealth::admit(const AdmissionRequest &request) {
	const auto key = EndpointKey(request.endpoint);
	const auto runtimeId = request.runtimeId
		? request.runtimeId
		: _runtimeId;
	const auto now = crl::now();
	const auto fastWarmup = FastWarmupEnabled(_runtime);
	auto result = Admission();
	auto rotationEvent = std::optional<EndpointEvent>();
	auto starvationDiagnostics = std::optional<ProxyDiagnosticsEvent>();
	{
		auto &storage = _context->storage();
		QMutexLocker lock(&storage.mutex);
		auto &state = storage.states[key];
		state.endpoint = request.endpoint;
		result.plan = BuildAttemptPlan(request, state.recipeLevel);
		result.stealth = result.plan.stealth;
		result.effectiveTlsProfile = result.plan.effectiveTlsProfile;
		result.runtimeId = runtimeId;
		result.proxyGeneration = request.proxyGeneration;
		result.proxyEpoch = state.proxyEpoch;
		result.successEpoch = state.successEpoch;
		if (IsProxyCheck(request.use)) {
			result.attemptId = ++state.lastAttemptId;
			result.attemptStartedAt = now;
			return result;
		}
		ApplyProxyGeneration(state, runtimeId, request.proxyGeneration);
		PruneExpiredEndpointState(state, now);
		const auto policy = EndpointConcurrencyPolicyFor(
			state,
			request.use,
			now,
			fastWarmup);
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
			state.attemptStarts.emplace(result.attemptId, EndpointAttemptState{
				.runtimeId = runtimeId,
				.proxyGeneration = request.proxyGeneration,
				.startedAt = attemptStartedAt,
				.admissionActive = true,
			});
			SynchronizeEndpointAdmissionAggregate(state);
			result.proxyGeneration = request.proxyGeneration;
			result.proxyEpoch = state.proxyEpoch;
			result.successEpoch = state.successEpoch;
			result.attemptStartedAt = attemptStartedAt;
			result.lease = EndpointAttemptLease(
				_context,
				key,
				runtimeId,
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
	ResolveLeaseIdentity(report);
	const auto releaseLease = gsl::finally([&] {
		if (report.lease) {
			report.lease->release();
		}
	});
	if (!report.runtimeId) {
		report.runtimeId = _runtimeId;
	}
	const auto key = EndpointKey(report.endpoint);
	if (report.lease && report.lease->endpointKey() != key) {
		return;
	}
	if (report.reason == FailureReason::None) {
		return;
	}
	if (report.use == EndpointUse::ProxyCheck) {
		LogProbeAttemptFailure(_runtime, report);
		return;
	}
	const auto routeKey = RouteKey(report.endpoint.route);
	const auto diagnostic = ToLegacyDiagnostic(report.reason);
	const auto now = crl::now();
	const auto fastWarmup = FastWarmupEnabled(_runtime);
	auto event = EndpointEvent();
	auto capabilityFailure = std::optional<CapabilityFailure>();
	auto capabilityRelayFailure = std::optional<CapabilityFailure>();
	auto noteConnectTimeout = false;
	auto &storage = _context->storage();
	QMutexLocker lock(&storage.mutex);
	auto &state = storage.states[key];
	PruneExpiredEndpointState(state, now);
	if (RuntimeProxyGenerationIsStale(
			state,
			report.runtimeId,
			report.proxyGeneration)) {
		const auto recipeLevel = state.recipeLevel;
		lock.unlock();
		LogStaleAttemptFailure(_runtime, report, recipeLevel);
		return;
	}
	ApplyProxyGeneration(state, report.runtimeId, report.proxyGeneration);
	if (FailureFromStaleAttempt(report, state)) {
		const auto recipeLevel = state.recipeLevel;
		lock.unlock();
		LogStaleAttemptFailure(_runtime, report, recipeLevel);
		return;
	}
	const auto identity = RelayProofIdentity{
		.runtimeId = report.runtimeId,
		.proxyGeneration = report.proxyGeneration,
		.attemptId = report.attemptId,
	};
	static_cast<void>(RetireRelayProof(state, identity));
	if (state.relayProven) {
		return;
	}
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
	NoteRouteFailure(storage, state, report.endpoint.route, report.reason);
	if (SoftNoAppDataFailure(state, report.reason, now)) {
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
				_runtime,
				report.endpoint,
				capabilityFailure->diagnostic);
		}
		NoteConnectTimeout(_runtime, report.endpoint);
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
				_runtime,
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
					_runtime,
					report.endpoint,
					capabilityFailure->diagnostic);
			}
			return;
		}
	}
	if (!routeKey.isEmpty()
		&& HasHealthyRoute(storage, state)
		&& !report.routesExhausted) {
		lock.unlock();
		if (capabilityFailure) {
			NoteCapabilityMtproxyFailure(
				_runtime,
				report.endpoint,
				capabilityFailure->diagnostic);
		}
		return;
	}
	state.lastFailure = report.reason;
	state.lastDiagnostic = diagnostic;
	const auto policy = EndpointConcurrencyPolicyFor(
		state,
		report.use,
		now,
		fastWarmup);
	const auto recentSuccess = state.lastSuccessAt
		&& (now - state.lastSuccessAt < kRecentSuccessWindow);
	// Escalate the stealth recipe only when the handshake keeps failing
	// with no recent success. A fingerprint the server accepted seconds
	// ago cannot be why it drops the ClientHello now (it is throttling by
	// rate or IP, not by signature), so mutating it just churns and keeps
	// the endpoint pinned in the strict single-probe DPI branch. At this
	// point state.consecutiveFailures still counts only the PRIOR strikes
	// (it is incremented below), so >=1 means this is at least the second
	// consecutive failure.
	if (policy.recipeEscalationAllowed
		&& state.recipeLevel < 2
		&& !recentSuccess
		&& state.consecutiveFailures >= 1) {
		++state.recipeLevel;
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
			_runtime,
			report.endpoint,
			capabilityFailure->diagnostic);
	}
	if (capabilityRelayFailure) {
		NoteCapabilityMtproxyRelayFailure(_runtime, *capabilityRelayFailure);
	}
	if (noteConnectTimeout) {
		NoteConnectTimeout(_runtime, report.endpoint);
	}
	WriteProxyDiagnosticsLine(_runtime, std::move(diagnosticsEvent));
	fireEndpointEventOnMain(std::move(event));
}

void EndpointHealth::reportSuccess(SuccessReport report) {
	ResolveLeaseIdentity(report);
	const auto releaseLease = gsl::finally([&] {
		if (report.lease) {
			report.lease->release();
		}
	});
	if (!report.runtimeId) {
		report.runtimeId = _runtimeId;
	}
	const auto key = EndpointKey(report.endpoint);
	if (report.lease && report.lease->endpointKey() != key) {
		return;
	}
	if (report.use == EndpointUse::ProxyCheck) {
		LogProbeAttemptSuccess(_runtime, report);
		return;
	}
	const auto now = crl::now();
	const auto routeKey = RouteKey(report.endpoint.route);
	auto capabilitySuccess = std::optional<CapabilitySuccess>();
	auto diagnosticsEvent = std::optional<ProxyDiagnosticsEvent>();
	{
		auto &storage = _context->storage();
		QMutexLocker lock(&storage.mutex);
		auto &state = storage.states[key];
		PruneExpiredEndpointState(state, now);
		if (RuntimeProxyGenerationIsStale(
				state,
				report.runtimeId,
				report.proxyGeneration)) {
			return;
		}
		ApplyProxyGeneration(
			state,
			report.runtimeId,
			report.proxyGeneration);
		if (SuccessFromStaleAttempt(report, state)) {
			return;
		}
		if (report.scope == SuccessScope::Relay) {
			const auto identity = RelayProofIdentity{
				.runtimeId = report.runtimeId,
				.proxyGeneration = report.proxyGeneration,
				.attemptId = report.attemptId,
			};
			const auto promotion = PromoteRelayProof(
				state,
				identity,
				RelayProofState{
					.provenAt = now,
				});
			switch (promotion) {
			case RelayProofPromotionResult::Inserted:
				break;
			case RelayProofPromotionResult::AlreadyProven:
			case RelayProofPromotionResult::MissingAdmission:
				return;
			}
		}
		state.endpoint = report.endpoint;
		state.lastSuccessAt = now;
		if (report.scope != SuccessScope::Relay) {
			return;
		}
		const auto successRecipeLevel = state.recipeLevel;
		const auto wasDegraded = (state.lastFailure != FailureReason::None)
			|| (state.terminalUntil > 0)
			|| state.halfOpen;
		if (!routeKey.isEmpty()) {
			NoteRouteSuccess(storage, state, report.endpoint.route);
		}
		state.recipeLevel = 0;
		state.exhaustedSinceSuccess = 0;
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
	}
	NoteConnectSuccess(_runtime, report.endpoint);
	if (capabilitySuccess) {
		NoteCapabilityMtproxySuccess(_runtime, *capabilitySuccess);
	}
	if (diagnosticsEvent) {
		WriteProxyDiagnosticsLine(_runtime, std::move(*diagnosticsEvent));
	}
}

auto EndpointHealth::changes() const
-> rpl::producer<EndpointEvent> {
	return _context->storage().events.events();
}

void EndpointHealth::fireEndpointEventOnMain(EndpointEvent event) {
	const auto context = _context;
	crl::on_main([context, event = std::move(event)]() mutable {
		context->storage().events.fire(std::move(event));
	});
}

} // namespace MTP::details::MtProxy
