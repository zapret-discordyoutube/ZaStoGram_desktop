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
#include "mtproto/proxy/endpoint_admission_arbiter.h"
#include "mtproto/proxy/proxy_endpoint_context.h"
#include "mtproto/proxy/proxy_endpoint_context_p.h"
#include "mtproto/runtime/runtime_environment.h"

#include <QtCore/QMutex>

#include <optional>

namespace MTP::details::MtProxy {

namespace {

enum class RelayProofRetirement {
	StaleGeneration,
	MissingOrDuplicate,
	RetiredWithSurvivors,
	RetiredFinal,
};

struct RelayProofRetirementResult {
	RelayProofRetirement outcome = RelayProofRetirement::MissingOrDuplicate;
	ProxyConnectionAttempt attempt;
	bool mainProofSurvives = false;
	bool endpointProofSurvives = false;
};

[[nodiscard]] RelayProofRetirementResult RetireRelayProofLocked(
		EndpointState &state,
		const RelayProofReport &report,
		crl::time now) {
	PruneExpiredEndpointState(state, now);
	const auto runtimeGeneration = RuntimeGenerationKey{
		.runtimeId = report.runtimeId,
		.proxyGeneration = report.proxyGeneration,
	};
	if (!RuntimeGenerationIsCurrent(state, runtimeGeneration)) {
		return {
			.outcome = RelayProofRetirement::StaleGeneration,
		};
	}
	const auto identity = RelayProofIdentity{
		.runtimeId = report.runtimeId,
		.proxyGeneration = report.proxyGeneration,
		.attemptId = report.attemptId,
	};
	const auto i = state.relayProofs.find(identity);
	if (i == end(state.relayProofs)
		|| i->second.use != report.use
		|| ((report.ticketKey.runtimeId || report.ticketKey.ticketId)
			&& report.ticketKey != i->second.ticketKey)
		|| report.proxyEpoch != i->second.proxyEpoch
		|| report.successEpoch != i->second.successEpoch
		|| (report.attemptStartedAt
			&& report.attemptStartedAt != i->second.attemptStartedAt)
		|| (report.lastPayloadAt
			&& report.lastPayloadAt < i->second.lastPayloadAt)) {
		return {};
	}
	const auto proof = i->second;
	if (!RetireRelayProof(state, identity)) {
		return {};
	}
	return {
		.outcome = state.relayProven
			? RelayProofRetirement::RetiredWithSurvivors
			: RelayProofRetirement::RetiredFinal,
		.attempt = {
			.runtimeId = report.runtimeId,
			.traceId = proof.traceId,
			.ticketId = proof.ticketKey.ticketId,
			.proxyGeneration = report.proxyGeneration,
			.proxyEpoch = proof.proxyEpoch,
			.successEpoch = proof.successEpoch,
			.attemptId = report.attemptId,
			.use = proof.use,
			.ticketKey = proof.ticketKey,
		},
		.mainProofSurvives = HasCurrentMainRelayProof(
			state,
			runtimeGeneration),
		.endpointProofSurvives = EndpointMainRelayProof(state).strength
			!= MainRelayProofStrength::None,
	};
}

[[nodiscard]] FailureReport RelayStallFailureReport(
		const RelayProofReport &report) {
	return {
		.endpoint = report.endpoint,
		.use = report.use,
		.runtimeId = report.runtimeId,
		.reason = FailureReason::MtpReceiveTimeoutAfterData,
		.proxyGeneration = report.proxyGeneration,
		.attemptId = report.attemptId,
		.proxyEpoch = report.proxyEpoch,
		.successEpoch = report.successEpoch,
		.attemptStartedAt = report.attemptStartedAt,
		.ticketKey = report.ticketKey,
	};
}

} // namespace

void EndpointHealth::ResolveLeaseIdentity(FailureReport &report) {
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

void EndpointHealth::ResolveLeaseIdentity(SuccessReport &report) {
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

void EndpointHealth::noteRelayStall(RelayProofReport report) {
	if (!report.runtimeId) {
		report.runtimeId = _runtimeId;
	}
	if (IsProxyCheck(report.use)) {
		return;
	}
	const auto now = crl::now();
	const auto staleReport = RelayStallFailureReport(report);
	auto retirement = RelayProofRetirementResult();
	auto recipeLevel = 0;
	auto capabilityFailure = false;
	const auto key = EndpointKey(report.endpoint);
	{
		auto &storage = _context->storage();
		QMutexLocker lock(&storage.mutex);
		const auto i = storage.states.find(key);
		if (storage.runtimes.contains(report.runtimeId)
			&& i != end(storage.states)) {
			auto &state = i->second;
			recipeLevel = state.recipeLevel;
			retirement = RetireRelayProofLocked(state, report, now);
			const auto runtimeGeneration = RuntimeGenerationKey{
				.runtimeId = report.runtimeId,
				.proxyGeneration = report.proxyGeneration,
			};
			if ((retirement.outcome
					== RelayProofRetirement::RetiredWithSurvivors
					|| retirement.outcome
						== RelayProofRetirement::RetiredFinal)
				&& retirement.attempt.use == EndpointUse::Main
				&& !retirement.mainProofSurvives) {
				const auto terminalAt = now;
				auto verdict = EndpointVerdict{
					.sourceAttempt = retirement.attempt,
					.runtimeGeneration = runtimeGeneration,
					.scope = EndpointVerdictScope::Attempt,
					.cause = EndpointVerdictCause::RelayLiveness,
					.reason = FailureReason::MtpReceiveTimeoutAfterData,
					.observedAt = terminalAt,
					.terminalAt = terminalAt,
				};
				if (RecordCurrentTerminalEvidence(
						state,
						EndpointTerminalEvidence{
							.verdict = verdict,
							.runtimeGeneration = runtimeGeneration,
							.ticketKey = retirement.attempt.ticketKey,
							.use = retirement.attempt.use,
							.attemptId = retirement.attempt.attemptId,
							.terminalAt = terminalAt,
						},
						now)) {
					verdict.scope = EndpointVerdictScope::Endpoint;
					if (SetCurrentCanonicalVerdict(
							state,
							runtimeGeneration,
							std::move(verdict))) {
						state.endpoint = report.endpoint;
						if (!retirement.endpointProofSurvives) {
							state.lastFailure
								= FailureReason::MtpReceiveTimeoutAfterData;
							state.lastDiagnostic = ToLegacyDiagnostic(
								FailureReason::MtpReceiveTimeoutAfterData);
							state.healthy = false;
						}
					}
				}
			}
			capabilityFailure = (retirement.outcome
					== RelayProofRetirement::RetiredWithSurvivors
					|| retirement.outcome
						== RelayProofRetirement::RetiredFinal)
				&& retirement.attempt.use == EndpointUse::Main
				&& !retirement.endpointProofSurvives;
		}
	}
	if (retirement.outcome == RelayProofRetirement::StaleGeneration
		|| retirement.outcome
			== RelayProofRetirement::MissingOrDuplicate) {
		LogStaleAttemptFailure(_runtime, staleReport, recipeLevel);
		return;
	}
	if (capabilityFailure) {
		NoteCapabilityMtproxyRelayFailure(
			_runtime,
			CapabilityFailure{
				.proxyKey = CapabilityProxyKey(report.endpoint.canonical),
				.routeKey = RouteKey(report.endpoint.route),
				.diagnostic = u"relay_stall"_q,
			});
	}
	_context->notifyEndpointAdmissible(key);
}

void EndpointHealth::retireRelayProof(RelayProofReport report) {
	if (!report.runtimeId) {
		report.runtimeId = _runtimeId;
	}
	if (IsProxyCheck(report.use)) {
		return;
	}
	const auto now = crl::now();
	const auto key = EndpointKey(report.endpoint);
	auto retired = false;
	{
		auto &storage = _context->storage();
		QMutexLocker lock(&storage.mutex);
		const auto i = storage.states.find(key);
		if (storage.runtimes.contains(report.runtimeId)
			&& i != end(storage.states)) {
			const auto result = RetireRelayProofLocked(
				i->second,
				report,
				now);
			retired = (result.outcome
					== RelayProofRetirement::RetiredWithSurvivors)
				|| (result.outcome == RelayProofRetirement::RetiredFinal);
		}
	}
	if (retired) {
		_context->notifyEndpointAdmissible(key);
	}
}

void EndpointHealth::noteEndpointSelected(const EndpointId &endpoint) {
	// A manual (re-)selection is explicit user evidence that the proxy is
	// worth trying right now: drop the cooldown ladder and denial
	// bookkeeping so the scout probes immediately, and restart the ladder
	// at the first rung if it fails again. Keep what was learned at cost:
	// recipeLevel (the DPI adaptation - resetting it would burn the fresh
	// probe on the exact fingerprint that just got blocked), lastFailure,
	// relay proofs and the last good profile/route.
	const auto key = EndpointKey(endpoint);
	if (key.isEmpty()) {
		return;
	}
	const auto now = crl::now();
	auto diagnosticsEvent = std::optional<ProxyDiagnosticsEvent>();
	{
		auto &storage = _context->storage();
		QMutexLocker lock(&storage.mutex);
		const auto i = storage.states.find(key);
		if (i == end(storage.states)) {
			return;
		}
		auto &state = i->second;
		// nextHandshakeAt gates admission too (spacing / soft-retry), so a
		// selection that clears only it must still wake the queued scout.
		const auto hadPenalty = (state.terminalUntil > 0)
			|| (state.opening.bootstrap.retryUntil > 0)
			|| (state.opening.expansion.retryUntil > 0)
			|| state.halfOpen
			|| (state.nextHandshakeAt > now)
			|| (state.consecutiveFailures > 0);
		state.terminalUntil = 0;
		state.opening = {};
		state.halfOpen = false;
		state.nextHandshakeAt = 0;
		state.deniedSince = 0;
		state.lastDenialRotationSignal = 0;
		state.consecutiveFailures = 0;
		state.exhaustedSinceSuccess = 0;
		if (hadPenalty) {
			diagnosticsEvent = CanonicalDiagnosticsEvent(
				ProxyDiagnosticsPhase::CanonicalRecovered,
				state,
				FailureReason::None,
				u"mtproxy penalty cleared by manual selection"_q);
		}
	}
	if (diagnosticsEvent) {
		WriteProxyDiagnosticsLine(_runtime, std::move(*diagnosticsEvent));
		// The penalty was cleared early by the manual selection - wake the
		// broker so the scout's queued request drains immediately instead
		// of waiting out its stale cooldown timer.
		_context->notifyEndpointAdmissible(key);
	}
}

void EndpointHealth::applyProxyGeneration(uint64 proxyGeneration) {
	_context->endpointAdmissionArbiter().cancelBeforeGeneration(
		_runtimeId,
		proxyGeneration);
}

} // namespace MTP::details::MtProxy
