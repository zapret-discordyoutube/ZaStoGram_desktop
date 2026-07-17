/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "mtproto/proxy/mtproxy/endpoint_health_capacity.h"

#include "mtproto/proxy/diagnostics.h"

#include <QtCore/QObject>

#include <algorithm>
#include <iterator>

namespace MTP::details::MtProxy {
namespace {

constexpr auto kCapacityProbeCooldown = crl::time(30 * 1000);
constexpr auto kCapacityPressureConfirmationWindow = crl::time(60 * 1000);
constexpr auto kCapacityPressureConfirmations = 2;

} // namespace

ProxyDiagnosticsEvent CapacityDiagnosticsEvent(
		ProxyDiagnosticsPhase phase,
		ProxyDiagnosticsTransition transition,
		ProxyConnectionAttempt attempt,
		const EndpointState &state) {
	attempt.connectionId.clear();
	return {
		.source = ProxyDiagnosticsSource::MTProxy,
		.phase = phase,
		.attempt = attempt,
		.transition = transition,
		.laneOrdinal = attempt.attemptId,
		.commitmentCount = EndpointCapacityCommitmentCount(state),
		.provenLowerBound = state.liveBudget.provenLowerBound,
		.frontier = state.liveBudget.capacityProbe.frontier
			? std::optional<int>(state.liveBudget.capacityProbe.frontier)
			: std::nullopt,
		.capacityCap = state.liveBudget.learnedLimit,
		.isFinal = true,
	};
}

void MergeDeferredCleanup(
		EndpointDeferredCleanup &target,
		EndpointDeferredCleanup source) {
	target.ownerConnections.insert(
		end(target.ownerConnections),
		std::make_move_iterator(begin(source.ownerConnections)),
		std::make_move_iterator(end(source.ownerConnections)));
	for (const auto token : source.rollbackEpisodes) {
		DeferReclaimEpisodeRollback(target, token);
	}
	if (source.entitlementReleaseCause) {
		target.entitlementReleaseCause = source.entitlementReleaseCause;
	}
}

bool HasDeferredCleanup(const EndpointDeferredCleanup &cleanup) {
	return !cleanup.ownerConnections.empty()
		|| !cleanup.rollbackEpisodes.empty()
		|| cleanup.entitlementReleaseCause.has_value();
}

void DisconnectDeferredOwners(EndpointDeferredCleanup &cleanup) {
	for (const auto &connection : cleanup.ownerConnections) {
		QObject::disconnect(connection);
	}
	cleanup.ownerConnections.clear();
}

std::optional<CapacityProbeState> ExactActiveCapacityProbe(
		const EndpointState &state,
		const RelayProofIdentity &identity) {
	const auto &probe = state.liveBudget.capacityProbe;
	const auto attempt = state.attemptStarts.find(identity.attemptId);
	if (attempt == end(state.attemptStarts)
		|| attempt->second.runtimeId != identity.runtimeId
		|| attempt->second.proxyGeneration != identity.proxyGeneration
		|| attempt->second.ticketKey != probe.ticketKey
		|| (probe.beneficiaryDemand
			&& attempt->second.transferDemand != *probe.beneficiaryDemand)
		|| !CapacityProbeActiveFor(
			state.liveBudget,
			probe.ticketKey,
			probe.runtimeGeneration,
			probe.frontier,
			probe.beneficiaryDemand,
			identity)) {
		return std::nullopt;
	}
	return probe;
}

bool ExactReplacementBeneficiary(
		const EndpointState &state,
		const RelayProofIdentity &identity) {
	const auto attempt = state.attemptStarts.find(identity.attemptId);
	if (attempt == end(state.attemptStarts)
		|| !state.foregroundTransferEntitlement
		|| !state.reclaimEpisode) {
		return false;
	}
	const auto &entitlement = *state.foregroundTransferEntitlement;
	const auto &episode = *state.reclaimEpisode;
	return attempt->second.runtimeId == identity.runtimeId
		&& attempt->second.proxyGeneration == identity.proxyGeneration
		&& ForegroundTransferEntitlementMatches(
			entitlement,
			attempt->second.transferDemand,
			attempt->second.owner)
		&& ReclaimEpisodeMatches(
			episode,
			episode.token,
			attempt->second.transferDemand,
			attempt->second.owner)
		&& episode.stage == ReclaimEpisodeStage::BeneficiaryGranted
		&& episode.beneficiaryAttempt == identity
		&& episode.replacementConsumed;
}

bool AuthorizeExactProbeReplacement(
		EndpointState &state,
		const CapacityProbeTerminalTransition &transition,
		const RelayProofIdentity &identity) {
	if (!transition.probe.beneficiaryDemand
		|| !state.foregroundTransferEntitlement
		|| !state.reclaimEpisode) {
		return false;
	}
	const auto attempt = state.attemptStarts.find(identity.attemptId);
	if (attempt == end(state.attemptStarts)) {
		return false;
	}
	const auto &demand = *transition.probe.beneficiaryDemand;
	const auto &entitlement = *state.foregroundTransferEntitlement;
	auto &episode = *state.reclaimEpisode;
	if (!ForegroundTransferEntitlementMatches(
			entitlement,
			demand,
			attempt->second.owner)
		|| !ReclaimEpisodeMatches(
			episode,
			episode.token,
			demand,
			attempt->second.owner)
		|| episode.beneficiaryAttempt != identity
		|| episode.replacementConsumed
		|| episode.stage == ReclaimEpisodeStage::Committed
		|| episode.stage == ReclaimEpisodeStage::RollbackPending
		|| episode.stage == ReclaimEpisodeStage::Terminal) {
		return false;
	}
	episode.replacementAuthorized = true;
	return true;
}

bool CommitExactReplacementProof(
		EndpointState &state,
		const RelayProofIdentity &identity) {
	if (!ExactReplacementBeneficiary(state, identity)) {
		return false;
	}
	state.reclaimEpisode->stage = ReclaimEpisodeStage::Committed;
	state.reclaimEpisode->replacementAuthorized = false;
	return true;
}

bool MarkExactReplacementRollback(
		EndpointState &state,
		const RelayProofIdentity &identity,
		EndpointDeferredCleanup &cleanup) {
	if (!ExactReplacementBeneficiary(state, identity)) {
		return false;
	}
	const auto &attempt = state.attemptStarts.find(identity.attemptId)->second;
	return MarkReclaimEpisodeRollbackPending(
		state,
		state.reclaimEpisode->token,
		attempt.transferDemand,
		attempt.owner,
		cleanup);
}

bool CompleteCapacityProof(
		EndpointState &state,
		const RelayProofIdentity &identity,
		const std::optional<CapacityProbeState> &activeProbe,
		bool replacementProof,
		const SuccessReport &report,
		std::vector<ProxyDiagnosticsEvent> &diagnostics) {
	if (activeProbe) {
		RaiseProvenEndpointCapacity(
			state.liveBudget,
			activeProbe->frontier);
		static_cast<void>(ReleaseActiveCapacityProbe(
			state.liveBudget,
			activeProbe->ticketKey,
			activeProbe->runtimeGeneration,
			activeProbe->frontier,
			activeProbe->beneficiaryDemand,
			identity));
		diagnostics.push_back(CapacityDiagnosticsEvent(
			ProxyDiagnosticsPhase::CapacityProbe,
			ProxyDiagnosticsTransition::Proved,
			{
				.runtimeId = report.runtimeId,
				.proxyGeneration = report.proxyGeneration,
				.attemptId = report.attemptId,
			},
			state));
	} else if (!replacementProof) {
		RaiseProvenEndpointCapacity(
			state.liveBudget,
			EndpointRelayProofCount(state));
	}
	const auto proved = replacementProof
		&& CommitExactReplacementProof(state, identity);
	if (proved) {
		diagnostics.push_back(CapacityDiagnosticsEvent(
			ProxyDiagnosticsPhase::CapacityReclaim,
			ProxyDiagnosticsTransition::ReplacementProved,
			{
				.runtimeId = report.runtimeId,
				.proxyGeneration = report.proxyGeneration,
				.attemptId = report.attemptId,
			},
			state));
	}
	return proved;
}

auto BeginTypedCapacityProbeCooldown(
		EndpointState &state,
		const FailureReport &report,
		bool finalAttemptTerminal,
		crl::time now)
-> std::optional<CapacityProbeTerminalTransition> {
	if (!finalAttemptTerminal) {
		return std::nullopt;
	}
	const auto identity = RelayProofIdentity{
		.runtimeId = report.runtimeId,
		.proxyGeneration = report.proxyGeneration,
		.attemptId = report.attemptId,
	};
	auto &budget = state.liveBudget;
	const auto probe = budget.capacityProbe;
	if (probe.stage != CapacityProbeStage::Active
		|| probe.frontier <= 1
		|| ((report.ticketKey.runtimeId || report.ticketKey.ticketId)
			&& report.ticketKey != probe.ticketKey)
		|| !CapacityProbeActiveFor(
			budget,
			probe.ticketKey,
			probe.runtimeGeneration,
			probe.frontier,
			probe.beneficiaryDemand,
			identity)) {
		return std::nullopt;
	}
	const auto attempt = state.attemptStarts.find(report.attemptId);
	if (attempt == end(state.attemptStarts)
		|| attempt->second.ticketKey != probe.ticketKey
		|| attempt->second.runtimeId != probe.runtimeGeneration.runtimeId
		|| attempt->second.proxyGeneration
			!= probe.runtimeGeneration.proxyGeneration
		|| (probe.beneficiaryDemand
			&& attempt->second.transferDemand != *probe.beneficiaryDemand)) {
		return std::nullopt;
	}
	if (!BeginCapacityProbeCooldown(
			budget,
			probe.ticketKey,
			probe.runtimeGeneration,
			probe.frontier,
			probe.beneficiaryDemand,
			identity,
			now + kCapacityProbeCooldown)) {
		return std::nullopt;
	}
	return CapacityProbeTerminalTransition{
		.probe = probe,
		.pressureFrontier = probe.frontier - 1,
	};
}

bool ReleaseTypedCapacityProbe(
		EndpointLiveBudgetState &budget,
		const RelayProofIdentity &identity) {
	const auto probe = budget.capacityProbe;
	return (probe.stage == CapacityProbeStage::Active)
		&& ReleaseActiveCapacityProbe(
			budget,
			probe.ticketKey,
			probe.runtimeGeneration,
			probe.frontier,
			probe.beneficiaryDemand,
			identity);
}

bool ExpireTypedCapacityProbeCooldown(
		EndpointLiveBudgetState &budget,
		crl::time now) {
	const auto probe = budget.capacityProbe;
	return (probe.stage == CapacityProbeStage::Cooldown)
		&& ExpireCapacityProbeCooldown(
			budget,
			probe.ticketKey,
			probe.runtimeGeneration,
			probe.frontier,
			probe.beneficiaryDemand,
			probe.activeAttempt,
			now);
}

void NoteCapacityPressure(
		EndpointLiveBudgetState &budget,
		int relayProofs,
		crl::time now) {
	const auto sameObservation = budget.pressureRelayProofs == relayProofs
		&& budget.proofPressureObservedAt
		&& (now - budget.proofPressureObservedAt
			<= kCapacityPressureConfirmationWindow);
	budget.pressureRelayProofs = relayProofs;
	budget.proofPressureObservedAt = now;
	budget.proofPressureStrikes = sameObservation
		? (budget.proofPressureStrikes + 1)
		: 1;
	if (budget.proofPressureStrikes < kCapacityPressureConfirmations) {
		return;
	}
	const auto observedLimit = relayProofs;
	budget.learnedLimit = budget.learnedLimit
		? std::min(budget.learnedLimit, observedLimit)
		: observedLimit;
	budget.provenLowerBound = budget.provenLowerBound
		? std::min(budget.provenLowerBound, observedLimit)
		: observedLimit;
}

void RaiseProvenEndpointCapacity(
		EndpointLiveBudgetState &budget,
		int relayProofCount) {
	budget.provenLowerBound = std::max(
		budget.provenLowerBound,
		relayProofCount);
	if (budget.learnedLimit && relayProofCount > budget.learnedLimit) {
		budget.learnedLimit = relayProofCount;
	}
}

} // namespace MTP::details::MtProxy
