/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "mtproto/proxy/mtproxy/endpoint_health.h"

#include "base/timer.h"
#include "mtproto/proxy/mtproxy/endpoint_health_capabilities.h"
#include "mtproto/proxy/mtproxy/endpoint_health_diagnostics.h"
#include "mtproto/proxy/mtproxy/endpoint_health_policy.h"
#include "mtproto/proxy/mtproxy/endpoint_health_state.h"

#include "mtproto/proxy/diagnostics.h"
#include "mtproto/proxy/proxy_endpoint_context.h"
#include "mtproto/proxy/proxy_endpoint_context_p.h"
#include "mtproto/runtime/runtime_environment.h"

#include <QtCore/QMutex>

#include <optional>

namespace MTP::details::MtProxy {
[[nodiscard]] crl::time ServerHelloTimeoutFor(
	const EndpointState &state,
	crl::time attemptStartedAt);
void NoteRouteFailure(
	EndpointContextStorage &storage,
	EndpointState &state,
	const RouteEndpoint &route,
	FailureReason reason);
void NoteRouteSuccess(
	EndpointContextStorage &storage,
	EndpointState &state,
	const RouteEndpoint &route);
[[nodiscard]] bool HasHealthyRoute(
	const EndpointContextStorage &storage,
	const EndpointState &state);

namespace {

constexpr auto kRecentSuccessWindow = crl::time(60 * 1000);

struct TerminalAttemptResult {
	ProxyConnectionAttempt attempt;
	bool proofRetired = false;
	bool finalAttemptTerminal = false;
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
		.cause = (report.reason == FailureReason::MtpReceiveTimeoutAfterData)
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
	result.finalAttemptTerminal = attemptTerminal;
	return result;
}

} // namespace

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
	const auto runtimeGeneration = storage.runtimeGenerations.find(
		request.runtimeId);
	if (runtimeGeneration == end(storage.runtimeGenerations)
		|| (runtimeGeneration->second
			&& runtimeGeneration->second != request.proxyGeneration)) {
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
	ApplyProxyGeneration(state, request.runtimeId, request.proxyGeneration);
	state.endpoint = request.endpoint;
	auto plan = BuildAttemptPlan(request, state.recipeLevel);
	plan.serverHelloTimeout = ServerHelloTimeoutFor(state, attemptStartedAt);
	const auto stealth = plan.stealth;
	const auto effectiveTlsProfile = plan.effectiveTlsProfile;
	const auto attemptId = ++state.lastAttemptId;
	const auto attempt = ProxyConnectionAttempt{
		.runtimeId = request.runtimeId,
		.traceId = traceId,
		.ticketId = ticketKey.ticketId,
		.proxyGeneration = request.proxyGeneration,
		.proxyEpoch = state.proxyEpoch,
		.successEpoch = state.successEpoch,
		.attemptId = attemptId,
		.use = request.use,
		.ticketKey = ticketKey,
	};
	state.attemptStarts.emplace(attemptId, EndpointAttemptState{
		.runtimeId = request.runtimeId,
		.proxyGeneration = request.proxyGeneration,
		.proxyEpoch = state.proxyEpoch,
		.successEpoch = state.successEpoch,
		.startedAt = attemptStartedAt,
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
	return Admission{
		.stealth = stealth,
		.effectiveTlsProfile = effectiveTlsProfile,
		.plan = std::move(plan),
		.lease = EndpointAttemptLease(
			std::move(context),
			key,
			attempt,
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
	auto capabilityFailure = std::optional<CapabilityFailure>();
	auto capabilityRelayFailure = std::optional<CapabilityFailure>();
	auto diagnosticsEvent = std::optional<ProxyDiagnosticsEvent>();
	auto shouldDrain = false;
	auto staleRecipeLevel = std::optional<int>();
	auto deferredCleanup = EndpointDeferredCleanup();
	{
		auto &storage = _context->storage();
		QMutexLocker lock(&storage.mutex);
		const auto i = storage.states.find(key);
		if (!storage.runtimes.contains(report.runtimeId)
			|| i == end(storage.states)) {
			staleRecipeLevel = 0;
		} else {
			auto &state = i->second;
			MergeDeferredCleanup(
				deferredCleanup,
				PruneExpiredEndpointStateDeferred(state, now));
			const auto terminal = RecordTerminalAttemptLocked(
				state,
				report,
				now);
			if (!terminal) {
				staleRecipeLevel = state.recipeLevel;
			} else {
				const auto runtimeGeneration = RuntimeGenerationKey{
					.runtimeId = report.runtimeId,
					.proxyGeneration = report.proxyGeneration,
				};
				if (terminal->finalAttemptTerminal) {
					shouldDrain
						= FinishMainRecoveryByReplacementAttemptLocked(
							storage,
							key,
							runtimeGeneration,
							terminal->attempt.use,
							terminal->attempt.attemptId)
						|| shouldDrain;
				}
				shouldDrain = terminal->proofRetired || shouldDrain;
				state.endpoint = report.endpoint;
				const auto endpointMainProof = EndpointMainRelayProof(state);
				const auto endpointHasMainProof = endpointMainProof.strength
					!= MainRelayProofStrength::None;
				const auto sharedHealthEvidence = report.use
						== EndpointUse::Main
					|| report.use == EndpointUse::ProxyCheck;
				if ((report.use == EndpointUse::ProxyCheck
						|| (report.use == EndpointUse::Main
							&& !endpointHasMainProof))
					&& report.reason
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
				if (sharedHealthEvidence) {
					NoteRouteFailure(
						storage,
						state,
						report.endpoint.route,
						report.reason);
				}
				const auto routeOnly = FailureIsRouteOnly(report.reason)
					&& !report.routesExhausted;
				if (routeOnly && sharedHealthEvidence) {
					shouldDrain = true;
				}
				const auto alternateRoute = !routeKey.isEmpty()
					&& HasHealthyRoute(storage, state)
					&& !report.routesExhausted;
				if (terminal->finalAttemptTerminal
					&& sharedHealthEvidence) {
					if (!FailureNeedsRecipeEscalation(report.reason)) {
						state.recipeFailureStreak = 0;
					} else {
						const auto recentRelay = state.lastRelaySuccessAt
							&& (now - state.lastRelaySuccessAt
								< kRecentSuccessWindow);
						if (recentRelay) {
							state.recipeFailureStreak = 0;
						} else {
							if (state.recipeFailureStreak >= 1
								&& state.recipeLevel < 2) {
								++state.recipeLevel;
							}
							if (state.recipeFailureStreak < 2) {
								++state.recipeFailureStreak;
							}
						}
					}
				}
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
					const auto applyGlobalPenalty = !state.relayProven
						? !softNoAppData
						: !endpointHasMainProof && !softNoAppData;
					if (applyGlobalPenalty) {
						state.lastFailure = report.reason;
						state.lastDiagnostic = diagnostic;
						if (state.terminalUntil <= now) {
							const auto recentSuccess = state.lastSuccessAt
								&& (now - state.lastSuccessAt
									< kRecentSuccessWindow);
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
								}
								state.terminalUntil = now + cooldown;
							}
						}
					}
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
						.retryUntil = state.terminalUntil,
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
	const auto hadDeferredCleanup = HasDeferredCleanup(deferredCleanup);
	DisconnectDeferredOwners(deferredCleanup);
	if (hadDeferredCleanup) {
		_context->notifyEndpointViewChanged(report.endpoint);
		shouldDrain = true;
	}
	if (staleRecipeLevel) {
		LogStaleAttemptFailure(_runtime, report, *staleRecipeLevel);
		if (shouldDrain) {
			_context->notifyEndpointAdmissible(key);
		}
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
	const auto probe = (report.use == EndpointUse::ProxyCheck);
	if (!report.runtimeId) {
		report.runtimeId = _runtimeId;
	}
	const auto key = EndpointKey(report.endpoint);
	if (report.lease && report.lease->endpointKey() != key) {
		return;
	}
	const auto now = crl::now();
	const auto payloadAt = report.payloadAt ? report.payloadAt : now;
	const auto routeKey = RouteKey(report.endpoint.route);
	auto capabilitySuccess = std::optional<CapabilitySuccess>();
	auto diagnosticsEvent = std::optional<ProxyDiagnosticsEvent>();
	auto shouldDrain = false;
	auto deferredCleanup = EndpointDeferredCleanup();
	auto deferredCleanupApplied = false;
	const auto applyDeferredCleanup = [&] {
		if (deferredCleanupApplied) {
			return;
		}
		deferredCleanupApplied = true;
		const auto hadDeferredCleanup = HasDeferredCleanup(deferredCleanup);
		DisconnectDeferredOwners(deferredCleanup);
		if (hadDeferredCleanup) {
			_context->notifyEndpointViewChanged(report.endpoint);
			shouldDrain = true;
		}
	};
	const auto deferredCleanupGuard = gsl::finally([&] {
		applyDeferredCleanup();
		if (shouldDrain) {
			_context->notifyEndpointAdmissible(key);
			shouldDrain = false;
		}
	});
	{
		auto &storage = _context->storage();
		QMutexLocker lock(&storage.mutex);
		const auto i = storage.states.find(key);
		if (!storage.runtimes.contains(report.runtimeId)
			|| i == end(storage.states)) {
			return;
		}
		auto &state = i->second;
		MergeDeferredCleanup(
			deferredCleanup,
			PruneExpiredEndpointStateDeferred(state, now));
		if (SuccessFromStaleAttempt(report, state)) {
			return;
		}
		state.endpoint = report.endpoint;
		if (report.scope != SuccessScope::Relay) {
			return;
		}
		const auto runtimeGeneration = RuntimeGenerationKey{
			.runtimeId = report.runtimeId,
			.proxyGeneration = report.proxyGeneration,
		};
		const auto before = CurrentMainRelayProof(state, runtimeGeneration);
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
			const auto opening = state.attemptStarts.find(report.attemptId);
			if (opening == end(state.attemptStarts)) {
				return;
			}
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
			if (report.use == EndpointUse::Main) {
				static_cast<void>(
					FinishMainRecoveryByReplacementAttemptLocked(
						storage,
						key,
						runtimeGeneration,
						report.use,
						report.attemptId));
			}
		}
		if (probe) {
			static_cast<void>(RetireRelayProof(state, identity));
		}
		const auto after = CurrentMainRelayProof(state, runtimeGeneration);
		shouldDrain = inserted
			|| (before.strength != after.strength);
		if (!routeKey.isEmpty()) {
			NoteRouteSuccess(storage, state, report.endpoint.route);
		}
		if (inserted) {
			state.lastSuccessAt = payloadAt;
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
			state.recipeFailureStreak = 0;
			state.recipeLevel = 0;
			if (report.use == EndpointUse::Main) {
				state.lastFailure = FailureReason::None;
				state.lastDiagnostic.clear();
				state.terminalUntil = 0;
				state.consecutiveFailures = 0;
				state.healthy = true;
				state.halfOpen = false;
			}
		}
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
	applyDeferredCleanup();
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
		shouldDrain = false;
	}
}

} // namespace MTP::details::MtProxy
