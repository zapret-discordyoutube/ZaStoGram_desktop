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

#include <limits>
#include <optional>

namespace MTP::details::MtProxy {

struct MainRecoveryTokenAccess {
	[[nodiscard]] static MainRecoveryToken FromId(uint64 id) {
		Expects(id != 0);
		auto result = MainRecoveryToken();
		result._id = id;
		return result;
	}
};

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
		crl::time now,
		EndpointDeferredCleanup &deferredCleanup) {
	MergeDeferredCleanup(
		deferredCleanup,
		PruneExpiredEndpointStateDeferred(state, now));
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

struct MainRecoveryLookup {
	EndpointState *state = nullptr;
	MainRecoveryState *recovery = nullptr;
};

struct ConstMainRecoveryLookup {
	const MainRecoveryState *recovery = nullptr;
};

[[nodiscard]] bool MainRecoveryIdentityIsValidLocked(
		const EndpointContextStorage &storage,
		const QString &endpointKey,
		const EndpointState &state,
		RuntimeGenerationKey runtimeGeneration,
		const MainRecoveryState &recovery) {
	const auto storageGeneration = storage.runtimeGenerations.find(
		runtimeGeneration.runtimeId);
	return !endpointKey.isEmpty()
		&& runtimeGeneration.runtimeId
		&& runtimeGeneration.proxyGeneration
		&& storage.runtimes.contains(runtimeGeneration.runtimeId)
		&& storageGeneration != end(storage.runtimeGenerations)
		&& (!storageGeneration->second
			|| storageGeneration->second
				== runtimeGeneration.proxyGeneration)
		&& EndpointKey(state.endpoint) == endpointKey
		&& RuntimeGenerationIsCurrent(state, runtimeGeneration)
		&& recovery.runtimeGeneration == runtimeGeneration
		&& recovery.sourceAttempt.runtimeId == runtimeGeneration.runtimeId
		&& recovery.sourceAttempt.proxyGeneration
			== runtimeGeneration.proxyGeneration
		&& recovery.sourceAttempt.attemptId
		&& recovery.sourceAttempt.use == EndpointUse::Main
		&& recovery.token;
}

[[nodiscard]] MainRecoveryLookup FindMainRecoveryLocked(
		EndpointContextStorage &storage,
		const QString &endpointKey,
		RuntimeGenerationKey runtimeGeneration) {
	const auto endpoint = storage.states.find(endpointKey);
	if (endpoint == end(storage.states)) {
		return {};
	}
	const auto recovery = endpoint->second.mainRecoveries.find(
		runtimeGeneration);
	if (recovery == end(endpoint->second.mainRecoveries)
		|| !MainRecoveryIdentityIsValidLocked(
			storage,
			endpointKey,
			endpoint->second,
			runtimeGeneration,
			recovery->second)) {
		return {};
	}
	return {
		.state = &endpoint->second,
		.recovery = &recovery->second,
	};
}

[[nodiscard]] ConstMainRecoveryLookup FindMainRecoveryLocked(
		const EndpointContextStorage &storage,
		const QString &endpointKey,
		RuntimeGenerationKey runtimeGeneration) {
	const auto endpoint = storage.states.find(endpointKey);
	if (endpoint == end(storage.states)) {
		return {};
	}
	const auto recovery = endpoint->second.mainRecoveries.find(
		runtimeGeneration);
	if (recovery == end(endpoint->second.mainRecoveries)
		|| !MainRecoveryIdentityIsValidLocked(
			storage,
			endpointKey,
			endpoint->second,
			runtimeGeneration,
			recovery->second)) {
		return {};
	}
	return {
		.recovery = &recovery->second,
	};
}

[[nodiscard]] MainRecoveryToken AllocateMainRecoveryTokenLocked(
		EndpointContextStorage &storage) {
	if (storage.lastMainRecoveryId
			== std::numeric_limits<uint64>::max()) {
		return {};
	}
	return MainRecoveryTokenAccess::FromId(++storage.lastMainRecoveryId);
}

} // namespace

MainRecoveryToken CreateMainRecoveryLocked(
		EndpointContextStorage &storage,
		const QString &endpointKey,
		RuntimeGenerationKey runtimeGeneration,
		const ProxyConnectionAttempt &sourceAttempt,
		crl::time createdAt) {
	const auto endpoint = storage.states.find(endpointKey);
	const auto storageGeneration = storage.runtimeGenerations.find(
		runtimeGeneration.runtimeId);
	const auto sourceIdentity = RelayProofIdentity{
		.runtimeId = sourceAttempt.runtimeId,
		.proxyGeneration = sourceAttempt.proxyGeneration,
		.attemptId = sourceAttempt.attemptId,
	};
	if (endpoint == end(storage.states)
		|| !runtimeGeneration.runtimeId
		|| !runtimeGeneration.proxyGeneration
		|| !storage.runtimes.contains(runtimeGeneration.runtimeId)
		|| storageGeneration == end(storage.runtimeGenerations)
		|| (storageGeneration->second
			&& storageGeneration->second
				!= runtimeGeneration.proxyGeneration)
		|| EndpointKey(endpoint->second.endpoint) != endpointKey
		|| !RuntimeGenerationIsCurrent(
			endpoint->second,
			runtimeGeneration)
		|| HasCurrentMainRelayProof(
			endpoint->second,
			runtimeGeneration)
		|| sourceAttempt.runtimeId != runtimeGeneration.runtimeId
		|| sourceAttempt.proxyGeneration
			!= runtimeGeneration.proxyGeneration
		|| sourceAttempt.use != EndpointUse::Main
		|| !sourceAttempt.attemptId
		|| HasRelayProof(endpoint->second, sourceIdentity)
		|| !endpoint->second.liveLanes.contains(sourceIdentity)
		|| endpoint->second.mainRecoveries.contains(runtimeGeneration)) {
		return {};
	}
	const auto token = AllocateMainRecoveryTokenLocked(storage);
	if (!token) {
		return {};
	}
	endpoint->second.mainRecoveries.emplace(
		runtimeGeneration,
		MainRecoveryState{
			.token = token,
			.runtimeGeneration = runtimeGeneration,
			.sourceAttempt = sourceAttempt,
			.createdAt = createdAt,
			.stage = MainRecoveryStage::TransportBackoff,
		});
	return token;
}

std::optional<MainRecoveryView> ComposeMainRecoveryViewLocked(
		const EndpointContextStorage &storage,
		const QString &endpointKey,
		RuntimeGenerationKey runtimeGeneration) {
	const auto found = FindMainRecoveryLocked(
		storage,
		endpointKey,
		runtimeGeneration);
	if (!found.recovery) {
		return std::nullopt;
	}
	const auto &recovery = *found.recovery;
	return MainRecoveryView{
		.token = recovery.token,
		.runtimeGeneration = recovery.runtimeGeneration,
		.sourceAttempt = recovery.sourceAttempt,
		.createdAt = recovery.createdAt,
		.stage = recovery.stage,
		.adoptedTicketKey = recovery.adoptedTicketKey,
		.replacementAttemptId = recovery.replacementAttemptId,
	};
}

bool AdoptMainRecoveryAdmissionTicketLocked(
		EndpointContextStorage &storage,
		const QString &endpointKey,
		RuntimeGenerationKey runtimeGeneration,
		EndpointUse use,
		MainRecoveryToken token,
		AdmissionTicketKey ticketKey) {
	const auto found = FindMainRecoveryLocked(
		storage,
		endpointKey,
		runtimeGeneration);
	if (!found.recovery
		|| use != EndpointUse::Main
		|| found.recovery->token != token
		|| found.recovery->stage != MainRecoveryStage::TransportBackoff
		|| found.recovery->adoptedTicketKey.runtimeId
		|| found.recovery->adoptedTicketKey.ticketId
		|| found.recovery->replacementAttemptId
		|| ticketKey.runtimeId != runtimeGeneration.runtimeId
		|| !ticketKey.ticketId) {
		return false;
	}
	found.recovery->stage = MainRecoveryStage::AdmissionTicket;
	found.recovery->adoptedTicketKey = ticketKey;
	return true;
}

bool AdoptMainRecoveryReplacementAttemptLocked(
		EndpointContextStorage &storage,
		const QString &endpointKey,
		RuntimeGenerationKey runtimeGeneration,
		EndpointUse use,
		MainRecoveryToken token,
		AdmissionTicketKey ticketKey,
		uint64 replacementAttemptId) {
	const auto found = FindMainRecoveryLocked(
		storage,
		endpointKey,
		runtimeGeneration);
	if (!found.recovery
		|| use != EndpointUse::Main
		|| found.recovery->token != token
		|| found.recovery->stage != MainRecoveryStage::AdmissionTicket
		|| found.recovery->adoptedTicketKey != ticketKey
		|| found.recovery->replacementAttemptId
		|| !replacementAttemptId) {
		return false;
	}
	const auto attempt = found.state->attemptStarts.find(
		replacementAttemptId);
	if (attempt == end(found.state->attemptStarts)
		|| attempt->second.runtimeId != runtimeGeneration.runtimeId
		|| attempt->second.proxyGeneration
			!= runtimeGeneration.proxyGeneration
		|| attempt->second.use != EndpointUse::Main
		|| attempt->second.ticketKey != ticketKey
		|| attempt->second.terminalVerdict.has_value()) {
		return false;
	}
	found.recovery->stage = MainRecoveryStage::ReplacementAttempt;
	found.recovery->replacementAttemptId = replacementAttemptId;
	return true;
}

bool FinishMainRecoveryByAdmissionTicketLocked(
		EndpointContextStorage &storage,
		const QString &endpointKey,
		RuntimeGenerationKey runtimeGeneration,
		EndpointUse use,
		MainRecoveryToken token,
		AdmissionTicketKey ticketKey) {
	const auto found = FindMainRecoveryLocked(
		storage,
		endpointKey,
		runtimeGeneration);
	if (!found.recovery
		|| use != EndpointUse::Main
		|| found.recovery->token != token
		|| found.recovery->stage != MainRecoveryStage::AdmissionTicket
		|| found.recovery->adoptedTicketKey != ticketKey
		|| ticketKey.runtimeId != runtimeGeneration.runtimeId
		|| !ticketKey.ticketId
		|| found.recovery->replacementAttemptId) {
		return false;
	}
	return found.state->mainRecoveries.erase(runtimeGeneration) > 0;
}

bool FinishMainRecoveryByReplacementAttemptLocked(
		EndpointContextStorage &storage,
		const QString &endpointKey,
		RuntimeGenerationKey runtimeGeneration,
		EndpointUse use,
		uint64 replacementAttemptId) {
	const auto found = FindMainRecoveryLocked(
		storage,
		endpointKey,
		runtimeGeneration);
	if (!found.recovery
		|| use != EndpointUse::Main
		|| found.recovery->stage != MainRecoveryStage::ReplacementAttempt
		|| found.recovery->replacementAttemptId != replacementAttemptId
		|| found.recovery->adoptedTicketKey.runtimeId
			!= runtimeGeneration.runtimeId
		|| !found.recovery->adoptedTicketKey.ticketId) {
		return false;
	}
	const auto identity = RelayProofIdentity{
		.runtimeId = runtimeGeneration.runtimeId,
		.proxyGeneration = runtimeGeneration.proxyGeneration,
		.attemptId = replacementAttemptId,
	};
	const auto attempt = found.state->attemptStarts.find(
		replacementAttemptId);
	const auto lane = found.state->liveLanes.find(identity);
	const auto attemptMatches = attempt != end(found.state->attemptStarts)
		&& attempt->second.runtimeId == runtimeGeneration.runtimeId
		&& attempt->second.proxyGeneration
			== runtimeGeneration.proxyGeneration
		&& attempt->second.use == EndpointUse::Main
		&& attempt->second.ticketKey
			== found.recovery->adoptedTicketKey;
	const auto laneMatches = lane != end(found.state->liveLanes)
		&& lane->second.use == EndpointUse::Main
		&& lane->second.ticketKey == found.recovery->adoptedTicketKey;
	if (!attemptMatches && !laneMatches) {
		return false;
	}
	return found.state->mainRecoveries.erase(runtimeGeneration) > 0;
}

bool CancelMainRecoveryBackoffLocked(
		EndpointContextStorage &storage,
		const QString &endpointKey,
		RuntimeGenerationKey runtimeGeneration,
		MainRecoveryToken token) {
	const auto found = FindMainRecoveryLocked(
		storage,
		endpointKey,
		runtimeGeneration);
	if (!found.recovery
		|| found.recovery->token != token
		|| found.recovery->stage != MainRecoveryStage::TransportBackoff
		|| found.recovery->adoptedTicketKey.runtimeId
		|| found.recovery->adoptedTicketKey.ticketId
		|| found.recovery->replacementAttemptId) {
		return false;
	}
	return found.state->mainRecoveries.erase(runtimeGeneration) > 0;
}

bool RemoveMainRecoveryForGenerationLocked(
		EndpointState &state,
		RuntimeGenerationKey runtimeGeneration) {
	return state.mainRecoveries.erase(runtimeGeneration) > 0;
}

bool RemoveMainRecoveriesForRuntimeLocked(
		EndpointState &state,
		ProxyRuntimeId runtimeId) {
	auto removed = false;
	for (auto i = begin(state.mainRecoveries);
			i != end(state.mainRecoveries);) {
		if (i->first.runtimeId == runtimeId) {
			i = state.mainRecoveries.erase(i);
			removed = true;
		} else {
			++i;
		}
	}
	return removed;
}

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
		_context->cancelEndpointAttempt(_key, _attemptId);
	}
}

void EndpointAttemptLease::transportReady() {
	if (_active && _context) {
		_context->transportReady(
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

void EndpointHealth::noteRelayStall(
		RelayProofReport report,
		MainRecoveryToken &recoveryToken) {
	recoveryToken = {};
	if (!report.runtimeId) {
		report.runtimeId = _runtimeId;
	}
	if (IsProxyCheck(report.use)) {
		return;
	}
	const auto now = crl::now();
	const auto staleReport = RelayStallFailureReport(report);
	auto retirement = RelayProofRetirementResult();
	auto createdRecoveryToken = MainRecoveryToken();
	auto recipeLevel = 0;
	auto capabilityFailure = false;
	auto deferredCleanup = EndpointDeferredCleanup();
	const auto key = EndpointKey(report.endpoint);
	const auto runtimeGeneration = RuntimeGenerationKey{
		.runtimeId = report.runtimeId,
		.proxyGeneration = report.proxyGeneration,
	};
	const auto deferredCleanupGuard = gsl::finally([&] {
		const auto hadDeferredCleanup = HasDeferredCleanup(deferredCleanup);
		DisconnectDeferredOwners(deferredCleanup);
		if (hadDeferredCleanup) {
			_context->notifyEndpointViewChanged(
				report.endpoint,
				runtimeGeneration);
			_context->notifyEndpointAdmissible(key);
		}
	});
	{
		auto &storage = _context->storage();
		QMutexLocker lock(&storage.mutex);
		const auto i = storage.states.find(key);
		if (storage.runtimes.contains(report.runtimeId)
			&& i != end(storage.states)) {
			auto &state = i->second;
			recipeLevel = state.recipeLevel;
			retirement = RetireRelayProofLocked(
				state,
				report,
				now,
				deferredCleanup);
			if ((retirement.outcome
					== RelayProofRetirement::RetiredWithSurvivors
					|| retirement.outcome
						== RelayProofRetirement::RetiredFinal)
				&& retirement.attempt.use == EndpointUse::Main
				&& !retirement.mainProofSurvives) {
				state.endpoint = report.endpoint;
				createdRecoveryToken = CreateMainRecoveryLocked(
					storage,
					key,
					runtimeGeneration,
					retirement.attempt,
					now);
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
	recoveryToken = createdRecoveryToken;
	return;
}

void EndpointHealth::cancelMainRecoveryBackoff(
		const EndpointId &endpoint,
		RuntimeGenerationKey runtimeGeneration,
		MainRecoveryToken token) {
	const auto key = EndpointKey(endpoint);
	if (key.isEmpty()
		|| !runtimeGeneration.runtimeId
		|| !runtimeGeneration.proxyGeneration
		|| !token) {
		return;
	}
	auto cancelled = false;
	{
		auto &storage = _context->storage();
		QMutexLocker lock(&storage.mutex);
		cancelled = CancelMainRecoveryBackoffLocked(
			storage,
			key,
			runtimeGeneration,
			token);
	}
	if (cancelled) {
		_context->notifyEndpointViewChanged(endpoint, runtimeGeneration);
		_context->notifyEndpointAdmissible(key);
	}
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
	auto deferredCleanup = EndpointDeferredCleanup();
	const auto runtimeGeneration = RuntimeGenerationKey{
		.runtimeId = report.runtimeId,
		.proxyGeneration = report.proxyGeneration,
	};
	const auto deferredCleanupGuard = gsl::finally([&] {
		const auto hadDeferredCleanup = HasDeferredCleanup(deferredCleanup);
		DisconnectDeferredOwners(deferredCleanup);
		if (hadDeferredCleanup) {
			_context->notifyEndpointViewChanged(
				report.endpoint,
				runtimeGeneration);
			_context->notifyEndpointAdmissible(key);
		}
	});
	{
		auto &storage = _context->storage();
		QMutexLocker lock(&storage.mutex);
		const auto i = storage.states.find(key);
		if (storage.runtimes.contains(report.runtimeId)
			&& i != end(storage.states)) {
			const auto result = RetireRelayProofLocked(
				i->second,
				report,
				now,
				deferredCleanup);
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
	const auto key = EndpointKey(endpoint);
	if (key.isEmpty()) {
		return;
	}
	auto requester = RuntimeGenerationKey();
	{
		auto &storage = _context->storage();
		QMutexLocker lock(&storage.mutex);
		const auto generation = storage.runtimeGenerations.find(_runtimeId);
		if (!storage.runtimes.contains(_runtimeId)
			|| generation == end(storage.runtimeGenerations)
			|| !generation->second) {
			return;
		}
		requester = {
			.runtimeId = _runtimeId,
			.proxyGeneration = generation->second,
		};
	}
	_context->endpointAdmissionArbiter().requestImmediateScout(
		endpoint.canonical,
		requester);
}

void EndpointHealth::applyProxyGeneration(uint64 proxyGeneration) {
	_context->endpointAdmissionArbiter().cancelBeforeGeneration(
		_runtimeId,
		proxyGeneration);
}

} // namespace MTP::details::MtProxy
