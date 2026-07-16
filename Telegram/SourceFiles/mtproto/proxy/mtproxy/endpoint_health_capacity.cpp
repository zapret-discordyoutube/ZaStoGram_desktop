/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "mtproto/proxy/mtproxy/endpoint_health_capacity.h"

#include <algorithm>

namespace MTP::details::MtProxy {
namespace {

constexpr auto kCapacityProbeCooldown = crl::time(30 * 1000);
constexpr auto kCapacityPressureConfirmationWindow = crl::time(60 * 1000);
constexpr auto kCapacityPressureConfirmations = 2;

} // namespace

std::optional<int> BeginStableCapacityProbeCooldown(
		EndpointState &state,
		const FailureReport &report,
		crl::time now) {
	if (report.reason != FailureReason::ClientHelloSentNoServerHello) {
		return std::nullopt;
	}
	const auto identity = RelayProofIdentity{
		.runtimeId = report.runtimeId,
		.proxyGeneration = report.proxyGeneration,
		.attemptId = report.attemptId,
	};
	auto &budget = state.liveBudget;
	if (!CapacityProbeActiveFor(budget, identity)) {
		return std::nullopt;
	}
	const auto attempt = state.attemptStarts.find(report.attemptId);
	if (attempt == end(state.attemptStarts)) {
		return std::nullopt;
	}
	const auto relayProofs = attempt->second.relayProofsAtStart;
	if (!relayProofs
		|| attempt->second.relayProofPromotionEpochAtStart
			!= budget.relayProofPromotionEpoch
		|| EndpointRelayProofCount(state) != relayProofs) {
		return std::nullopt;
	}
	if (!BeginCapacityProbeCooldown(
			budget,
			identity,
			now + kCapacityProbeCooldown)) {
		return std::nullopt;
	}
	return relayProofs;
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
