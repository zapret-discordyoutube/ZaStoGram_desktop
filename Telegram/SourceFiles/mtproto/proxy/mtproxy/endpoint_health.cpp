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

#include <QtCore/QMutex>

#include <map>
#include <optional>
#include <set>

namespace MTP::details::MtProxy {

[[nodiscard]] bool RecentRelaySuccess(
	const EndpointState &state,
	crl::time now);

namespace {

constexpr auto kRecentSuccessWindow = crl::time(60 * 1000);
constexpr auto kRecentRelayServerHelloTimeout = crl::time(2500);
constexpr auto kColdServerHelloTimeout = crl::time(5000);

[[nodiscard]] crl::time ServerHelloTimeoutFor(
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

struct TerminalAttemptResult {
	ProxyConnectionAttempt attempt;
	bool proofRetired = false;
};

[[nodiscard]] auto RecordTerminalAttemptLocked(
		EndpointState &state,
		const FailureReport &report,
		crl::time now)
-> std::optional<TerminalAttemptResult> {
	if (FailureFromStaleAttempt(report, state)) {
		return std::nullopt;
	}
	const auto identity = RelayProofIdentity{
		.runtimeId = report.runtimeId,
		.proxyGeneration = report.proxyGeneration,
		.attemptId = report.attemptId,
	};
	auto result = TerminalAttemptResult();
	const auto proof = state.relayProofs.find(identity);
	if (proof != end(state.relayProofs)) {
		result.attempt = {
			.runtimeId = report.runtimeId,
			.traceId = proof->second.traceId,
			.ticketId = proof->second.ticketKey.ticketId,
			.proxyGeneration = report.proxyGeneration,
			.proxyEpoch = proof->second.proxyEpoch,
			.successEpoch = proof->second.successEpoch,
			.attemptId = report.attemptId,
			.use = proof->second.use,
			.ticketKey = proof->second.ticketKey,
		};
		result.proofRetired = RetireRelayProof(state, identity);
	} else {
		const auto attempt = state.attemptStarts.find(report.attemptId);
		if (attempt == end(state.attemptStarts)
			|| attempt->second.terminalVerdict) {
			return std::nullopt;
		}
		result.attempt = {
			.runtimeId = report.runtimeId,
			.traceId = attempt->second.traceId,
			.ticketId = attempt->second.ticketKey.ticketId,
			.proxyGeneration = report.proxyGeneration,
			.proxyEpoch = attempt->second.proxyEpoch,
			.successEpoch = attempt->second.successEpoch,
			.attemptId = report.attemptId,
			.use = attempt->second.use,
			.ticketKey = attempt->second.ticketKey,
		};
	}
	const auto terminalAt = report.terminalAt ? report.terminalAt : now;
	auto verdict = EndpointVerdict{
		.sourceAttempt = result.attempt,
		.runtimeGeneration = {
			.runtimeId = report.runtimeId,
			.proxyGeneration = report.proxyGeneration,
		},
		.scope = EndpointVerdictScope::Attempt,
		.cause = (report.reason
				== FailureReason::MtpReceiveTimeoutAfterData)
			? EndpointVerdictCause::RelayLiveness
			: EndpointVerdictCause::Transport,
		.reason = report.reason,
		.attribution = report.attribution,
		.observedAt = terminalAt,
		.terminalAt = terminalAt,
	};
	const auto attemptTerminal = !FailureIsRouteOnly(report.reason)
		|| report.routesExhausted;
	if (!result.proofRetired && attemptTerminal) {
		auto &attempt = state.attemptStarts.find(report.attemptId)->second;
		attempt.terminalAt = terminalAt;
		attempt.terminalVerdict = verdict;
	}
	if (!RecordCurrentTerminalEvidence(
			state,
			EndpointTerminalEvidence{
				.verdict = verdict,
				.runtimeGeneration = verdict.runtimeGeneration,
				.ticketKey = result.attempt.ticketKey,
				.use = result.attempt.use,
				.attemptId = result.attempt.attemptId,
				.terminalAt = terminalAt,
			},
			now)) {
		return std::nullopt;
	}
	return result;
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

std::optional<Admission> EndpointHealth::BeginScheduledAttemptLocked(
		EndpointContextStorage &storage,
		std::shared_ptr<ProxyEndpointContext> context,
		const AdmissionRequest &request,
		AdmissionTicketKey ticketKey,
		ProxyTraceId traceId,
		crl::time enqueuedAt,
		crl::time scheduledOpenAt,
		crl::time attemptStartedAt) {
	const auto key = EndpointKey(request.endpoint);
	if (!context
		|| key.isEmpty()
		|| !request.runtimeId
		|| ticketKey.runtimeId != request.runtimeId
		|| !ticketKey.ticketId
		|| !storage.runtimes.contains(request.runtimeId)) {
		return std::nullopt;
	}
	const auto existing = storage.states.find(key);
	if (existing != end(storage.states)
		&& RuntimeProxyGenerationIsStale(
			existing->second,
			request.runtimeId,
			request.proxyGeneration)) {
		return std::nullopt;
	}
	auto &state = storage.states[key];
	ApplyProxyGeneration(
		state,
		request.runtimeId,
		request.proxyGeneration);
	PruneExpiredEndpointState(state, attemptStartedAt);
	state.endpoint = request.endpoint;
	state.deniedSince = 0;
	state.lastDenialRotationSignal = 0;
	auto plan = BuildAttemptPlan(request, state.recipeLevel);
	plan.serverHelloTimeout = ServerHelloTimeoutFor(
		state,
		attemptStartedAt);
	const auto stealth = plan.stealth;
	const auto effectiveTlsProfile = plan.effectiveTlsProfile;
	const auto attemptId = ++state.lastAttemptId;
	state.attemptStarts.emplace(attemptId, EndpointAttemptState{
		.runtimeId = request.runtimeId,
		.proxyGeneration = request.proxyGeneration,
		.proxyEpoch = state.proxyEpoch,
		.successEpoch = state.successEpoch,
		.startedAt = attemptStartedAt,
		.admissionActive = true,
		.use = request.use,
		.schedulerLifecycle = ProxySchedulerLifecycle::HandedOff,
		.admissionPhase = ProxyAdmissionPhase::Resolving,
		.networkPhase = ProxyConnectionPhase::Resolving,
		.ticketKey = ticketKey,
		.traceId = traceId,
		.enqueuedAt = enqueuedAt,
		.scheduledOpenAt = scheduledOpenAt,
		.attemptStartedAt = attemptStartedAt,
		.phaseStartedAt = attemptStartedAt,
	});
	SynchronizeEndpointAdmissionAggregate(state);
	return Admission{
		.stealth = stealth,
		.effectiveTlsProfile = effectiveTlsProfile,
		.plan = std::move(plan),
		.lease = EndpointAttemptLease(
			std::move(context),
			key,
			request.runtimeId,
			attemptId,
			request.proxyGeneration,
			state.proxyEpoch,
			state.successEpoch,
			attemptStartedAt),
		.runtimeId = request.runtimeId,
		.proxyGeneration = request.proxyGeneration,
		.attemptId = attemptId,
		.proxyEpoch = state.proxyEpoch,
		.successEpoch = state.successEpoch,
		.attemptStartedAt = attemptStartedAt,
	};
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
	const auto routeKey = RouteKey(report.endpoint.route);
	const auto diagnostic = ToLegacyDiagnostic(report.reason);
	const auto now = crl::now();
	const auto fastWarmup = FastWarmupEnabled(_runtime);
	auto capabilityFailure = std::optional<CapabilityFailure>();
	auto capabilityRelayFailure = std::optional<CapabilityFailure>();
	auto diagnosticsEvent = std::optional<ProxyDiagnosticsEvent>();
	auto noteConnectTimeout = false;
	auto shouldDrain = false;
	auto staleRecipeLevel = std::optional<int>();
	{
		auto &storage = _context->storage();
		QMutexLocker lock(&storage.mutex);
		const auto i = storage.states.find(key);
		if (!storage.runtimes.contains(report.runtimeId)
			|| i == end(storage.states)) {
			staleRecipeLevel = 0;
		} else {
			auto &state = i->second;
			PruneExpiredEndpointState(state, now);
			const auto terminal = RecordTerminalAttemptLocked(
				state,
				report,
				now);
			if (!terminal) {
				staleRecipeLevel = state.recipeLevel;
			} else {
				shouldDrain = terminal->proofRetired;
				noteConnectTimeout = FailureNeedsRecipeEscalation(
					report.reason);
				state.endpoint = report.endpoint;
				if (report.reason
						!= FailureReason::ServerHelloOkNoAppData
					&& report.reason
						!= FailureReason::ServerHelloOkNoMtprotoData
					&& report.reason
						!= FailureReason::ConnectedNoMtprotoData
					&& report.reason
						!= FailureReason::MtpReceiveTimeoutAfterData) {
					capabilityFailure = CapabilityFailure{
						.proxyKey = CapabilityProxyKey(
							report.endpoint.canonical),
						.routeKey = RouteKey(report.endpoint.route),
						.diagnostic = diagnostic,
					};
				}
				NoteRouteFailure(
					storage,
					state,
					report.endpoint.route,
					report.reason);
				const auto routeOnly = FailureIsRouteOnly(report.reason)
					&& !report.routesExhausted;
				if (routeOnly) {
					noteConnectTimeout = true;
					shouldDrain = true;
				}
				if (report.routesExhausted) {
					++state.exhaustedSinceSuccess;
				}
				const auto alternateRoute = !routeKey.isEmpty()
					&& HasHealthyRoute(storage, state)
					&& !report.routesExhausted;
				const auto runtimeGeneration = RuntimeGenerationKey{
					.runtimeId = report.runtimeId,
					.proxyGeneration = report.proxyGeneration,
				};
				const auto canonicalEligible = (report.use
						== EndpointUse::Main)
					&& !routeOnly
					&& !alternateRoute
					&& !HasCurrentMainRelayProof(
						state,
						runtimeGeneration);
				if (canonicalEligible) {
					const auto softNoAppData = SoftNoAppDataFailure(
						state,
						report.reason,
						now);
					if (softNoAppData) {
						state.nextHandshakeAt = now + NoAppDataSoftRetry();
					}
					const auto applyGlobalPenalty = !state.relayProven
						&& !softNoAppData;
					if (applyGlobalPenalty) {
						state.lastFailure = report.reason;
						state.lastDiagnostic = diagnostic;
						if (state.terminalUntil <= now) {
							const auto policy = EndpointConcurrencyPolicyFor(
								state,
								report.use,
								now,
								fastWarmup);
							const auto recentSuccess = state.lastSuccessAt
								&& (now - state.lastSuccessAt
									< kRecentSuccessWindow);
							if (policy.recipeEscalationAllowed
								&& state.recipeLevel < 2
								&& !recentSuccess
								&& state.consecutiveFailures >= 1) {
								++state.recipeLevel;
							}
							const auto needsCooldown = FailureNeedsCooldown(
								report.reason) || report.routesExhausted;
							if (needsCooldown) {
								++state.consecutiveFailures;
								state.healthy = false;
								state.halfOpen = true;
								auto cooldown = CooldownFor(
									report.reason,
									state.consecutiveFailures);
								if (recentSuccess
									&& FailureNeedsRecipeEscalation(
										report.reason)) {
									cooldown = std::min(
										cooldown,
										ThrottledRetryCooldown());
									noteConnectTimeout = true;
								}
								state.terminalUntil = now + cooldown;
							}
						}
					}
					const auto retryUntil = std::max(
						state.terminalUntil,
						state.nextHandshakeAt);
					auto verdict = EndpointVerdict{
						.sourceAttempt = terminal->attempt,
						.runtimeGeneration = runtimeGeneration,
						.scope = EndpointVerdictScope::Endpoint,
						.cause = (report.reason
								== FailureReason::MtpReceiveTimeoutAfterData)
							? EndpointVerdictCause::RelayLiveness
							: EndpointVerdictCause::Transport,
						.reason = report.reason,
						.attribution = report.attribution,
						.confidence = (report.attribution
								== ProxyFailureAttribution::Network)
							? CurrentMainNetworkEvidenceCount(
								state,
								runtimeGeneration,
								now)
							: 0,
						.observedAt = report.terminalAt
							? report.terminalAt
							: now,
						.terminalAt = report.terminalAt
							? report.terminalAt
							: now,
						.retryUntil = retryUntil,
					};
					if (SetCurrentCanonicalVerdict(
							state,
							runtimeGeneration,
							std::move(verdict))) {
						shouldDrain = true;
						diagnosticsEvent = CanonicalDiagnosticsEvent(
							ProxyDiagnosticsPhase::CanonicalDegraded,
							state,
							report.reason,
							u"mtproxy canonical endpoint degraded"_q);
					}
					if (applyGlobalPenalty
						&& RelayFailureInvalidatesCapability(
							report.reason)) {
						capabilityRelayFailure = CapabilityFailure{
							.proxyKey = CapabilityProxyKey(
								report.endpoint.canonical),
							.routeKey = RouteKey(report.endpoint.route),
							.diagnostic = diagnostic,
						};
					}
				}
			}
		}
	}
	if (staleRecipeLevel) {
		LogStaleAttemptFailure(_runtime, report, *staleRecipeLevel);
		return;
	}
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
	if (report.use == EndpointUse::ProxyCheck) {
		LogProbeAttemptFailure(_runtime, report);
	}
	if (diagnosticsEvent) {
		WriteProxyDiagnosticsLine(_runtime, std::move(*diagnosticsEvent));
	}
	if (shouldDrain) {
		_context->notifyEndpointAdmissible(key);
	}
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
	const auto probe = (report.use == EndpointUse::ProxyCheck);
	const auto now = crl::now();
	const auto payloadAt = report.payloadAt ? report.payloadAt : now;
	const auto routeKey = RouteKey(report.endpoint.route);
	auto capabilitySuccess = std::optional<CapabilitySuccess>();
	auto diagnosticsEvent = std::optional<ProxyDiagnosticsEvent>();
	auto shouldDrain = false;
	{
		auto &storage = _context->storage();
		QMutexLocker lock(&storage.mutex);
		const auto i = storage.states.find(key);
		if (!storage.runtimes.contains(report.runtimeId)
			|| i == end(storage.states)) {
			return;
		}
		auto &state = i->second;
		PruneExpiredEndpointState(state, now);
		if (SuccessFromStaleAttempt(report, state)) {
			return;
		}
		state.endpoint = report.endpoint;
		state.lastSuccessAt = now;
		if (report.scope != SuccessScope::Relay) {
			return;
		}
		const auto runtimeGeneration = RuntimeGenerationKey{
			.runtimeId = report.runtimeId,
			.proxyGeneration = report.proxyGeneration,
		};
		const auto beforeMainProof = CurrentMainRelayProof(
			state,
			runtimeGeneration);
		const auto hadGlobalPenalty = (state.lastFailure
				!= FailureReason::None)
			|| (state.terminalUntil > 0)
			|| state.halfOpen
			|| (state.nextHandshakeAt > now)
			|| (state.consecutiveFailures > 0);
		const auto hadCanonical = state.canonicalVerdicts.contains(
			runtimeGeneration);
		const auto successRecipeLevel = state.recipeLevel;
		auto inserted = false;
		const auto identity = RelayProofIdentity{
			.runtimeId = report.runtimeId,
			.proxyGeneration = report.proxyGeneration,
			.attemptId = report.attemptId,
		};
		if (HasRelayProof(state, identity)) {
			if (!RefreshRelayProofPayload(state, identity, payloadAt)) {
				return;
			}
		} else {
			const auto promotion = PromoteRelayProof(
				state,
				identity,
				RelayProofState{
					.provenAt = payloadAt,
					.lastPayloadAt = payloadAt,
					.payloadCount = 1,
				});
			if (promotion != RelayProofPromotionResult::Inserted) {
				return;
			}
			inserted = true;
		}
		if (probe) {
			static_cast<void>(RetireRelayProof(state, identity));
		}
		const auto afterMainProof = CurrentMainRelayProof(
			state,
			runtimeGeneration);
		shouldDrain = inserted
			|| (beforeMainProof.strength != afterMainProof.strength)
			|| hadGlobalPenalty;
		state.lastSuccessAt = payloadAt;
		if (!routeKey.isEmpty()) {
			NoteRouteSuccess(storage, state, report.endpoint.route);
		}
		if (inserted) {
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
		state.recipeLevel = 0;
		state.exhaustedSinceSuccess = 0;
		state.lastFailure = FailureReason::None;
		state.lastDiagnostic.clear();
		state.terminalUntil = 0;
		state.nextHandshakeAt = 0;
		state.consecutiveFailures = 0;
		state.healthy = true;
		state.halfOpen = false;
		if (report.use == EndpointUse::Main) {
			PruneEndpointOutcomesAfterSuccess(
				state,
				runtimeGeneration,
				payloadAt);
		}
		if (report.use == EndpointUse::Main && hadCanonical) {
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
	if (probe) {
		LogProbeAttemptSuccess(_runtime, report);
	}
	if (shouldDrain) {
		_context->notifyEndpointAdmissible(key);
	}
}

} // namespace MTP::details::MtProxy
