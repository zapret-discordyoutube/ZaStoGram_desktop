/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#pragma once

#include "mtproto/proxy/mtproxy/endpoint_health.h"

#include <QtCore/QObject>
#include <QtCore/QPointer>

#include <algorithm>
#include <compare>
#include <cstddef>
#include <deque>
#include <map>
#include <set>
#include <utility>
#include <vector>

namespace MTP::details::MtProxy {

struct EndpointAttemptState {
	ProxyRuntimeId runtimeId = 0;
	uint64 proxyGeneration = 0;
	uint64 proxyEpoch = 0;
	uint64 successEpoch = 0;
	crl::time startedAt = 0;
	bool admissionActive = true;
	EndpointUse use = EndpointUse::Main;
	ProxySchedulerLifecycle schedulerLifecycle
		= ProxySchedulerLifecycle::None;
	ProxyAdmissionPhase admissionPhase = ProxyAdmissionPhase::Idle;
	ProxyConnectionPhase networkPhase = ProxyConnectionPhase::None;
	AdmissionTicketKey ticketKey;
	ProxyTraceId traceId = 0;
	crl::time enqueuedAt = 0;
	crl::time scheduledOpenAt = 0;
	crl::time attemptStartedAt = 0;
	crl::time phaseStartedAt = 0;
	crl::time terminalAt = 0;
	std::optional<EndpointVerdict> terminalVerdict;
	int relayProofsAtStart = 0;
	uint64 relayProofPromotionEpochAtStart = 0;
	QPointer<QObject> owner;
	QMetaObject::Connection ownerDestroyed;
	std::shared_ptr<Fn<void(EndpointLaneCommand)>> laneControl;
	bool preempting = false;
	EndpointTransferDemandKey transferDemand;
};

struct RelayProofIdentity {
	ProxyRuntimeId runtimeId = 0;
	uint64 proxyGeneration = 0;
	uint64 attemptId = 0;

	friend inline auto operator<=>(
		RelayProofIdentity,
		RelayProofIdentity) = default;
};

enum class CapacityProbeStage {
	Idle,
	Reserved,
	Active,
	Cooldown,
};

struct CapacityProbeState {
	CapacityProbeStage stage = CapacityProbeStage::Idle;
	AdmissionTicketKey ticketKey;
	RuntimeGenerationKey runtimeGeneration;
	RelayProofIdentity activeAttempt;
	int frontier = 0;
	std::optional<EndpointTransferDemandKey> beneficiaryDemand;
	crl::time retryAt = 0;
};

struct RelayProofState {
	crl::time provenAt = 0;
	crl::time lastPayloadAt = 0;
	AdmissionTicketKey ticketKey;
	EndpointUse use = EndpointUse::Main;
	ProxyTraceId traceId = 0;
	uint64 proxyEpoch = 0;
	uint64 successEpoch = 0;
	crl::time attemptStartedAt = 0;
	uint8 payloadCount = 0;
	QPointer<QObject> owner;
	std::shared_ptr<Fn<void(EndpointLaneCommand)>> laneControl;
	bool preempting = false;
};

inline constexpr auto kRelayProofPayloadCountLimit = uint8(2);

struct EndpointTerminalEvidence {
	EndpointVerdict verdict;
	RuntimeGenerationKey runtimeGeneration;
	AdmissionTicketKey ticketKey;
	EndpointUse use = EndpointUse::Main;
	uint64 attemptId = 0;
	crl::time terminalAt = 0;
};

enum class RelayProofPromotionResult {
	Inserted,
	AlreadyProven,
	MissingAdmission,
};

struct EndpointOpenFailureState {
	FailureReason reason = FailureReason::None;
	RuntimeGenerationKey runtimeGeneration;
	EndpointUse use = EndpointUse::Main;
	crl::time retryUntil = 0;
	int consecutiveFailures = 0;
};

struct EndpointOpeningFlowKey {
	RuntimeGenerationKey runtimeGeneration;
	EndpointUse use = EndpointUse::Main;

	friend inline auto operator<=>(
		EndpointOpeningFlowKey,
		EndpointOpeningFlowKey) = default;
};

struct EndpointOpeningState {
	EndpointOpenFailureState bootstrap;
	EndpointOpenFailureState expansion;
	std::map<EndpointOpeningFlowKey, EndpointOpenFailureState> expansionFlows;
};

struct EndpointLiveBudgetState {
	int learnedLimit = 0;
	int provenLowerBound = 0;
	int pressureRelayProofs = 0;
	int proofPressureStrikes = 0;
	crl::time proofPressureObservedAt = 0;
	CapacityProbeState capacityProbe;
	uint64 relayProofPromotionEpoch = 0;
};

[[nodiscard]] inline bool CapacityProbeReservedFor(
		const EndpointLiveBudgetState &budget,
		AdmissionTicketKey ticketKey,
		RuntimeGenerationKey runtimeGeneration,
		int frontier,
		const std::optional<EndpointTransferDemandKey> &beneficiaryDemand) {
	return budget.capacityProbe.stage == CapacityProbeStage::Reserved
		&& budget.capacityProbe.ticketKey == ticketKey
		&& budget.capacityProbe.runtimeGeneration == runtimeGeneration
		&& budget.capacityProbe.frontier == frontier
		&& budget.capacityProbe.beneficiaryDemand == beneficiaryDemand;
}

[[nodiscard]] inline bool CapacityProbeActiveFor(
		const EndpointLiveBudgetState &budget,
		AdmissionTicketKey ticketKey,
		RuntimeGenerationKey runtimeGeneration,
		int frontier,
		const std::optional<EndpointTransferDemandKey> &beneficiaryDemand,
		const RelayProofIdentity &activeAttempt) {
	return budget.capacityProbe.stage == CapacityProbeStage::Active
		&& budget.capacityProbe.ticketKey == ticketKey
		&& budget.capacityProbe.runtimeGeneration == runtimeGeneration
		&& budget.capacityProbe.activeAttempt == activeAttempt
		&& budget.capacityProbe.frontier == frontier
		&& budget.capacityProbe.beneficiaryDemand == beneficiaryDemand;
}

[[nodiscard]] inline bool CapacityProbeCooldownFor(
		const EndpointLiveBudgetState &budget,
		AdmissionTicketKey ticketKey,
		RuntimeGenerationKey runtimeGeneration,
		int frontier,
		const std::optional<EndpointTransferDemandKey> &beneficiaryDemand,
		const RelayProofIdentity &activeAttempt) {
	return budget.capacityProbe.stage == CapacityProbeStage::Cooldown
		&& budget.capacityProbe.ticketKey == ticketKey
		&& budget.capacityProbe.runtimeGeneration == runtimeGeneration
		&& budget.capacityProbe.activeAttempt == activeAttempt
		&& budget.capacityProbe.frontier == frontier
		&& budget.capacityProbe.beneficiaryDemand == beneficiaryDemand;
}

[[nodiscard]] inline bool CapacityProbeDemandMatchesGeneration(
		const std::optional<EndpointTransferDemandKey> &beneficiaryDemand,
		RuntimeGenerationKey runtimeGeneration) {
	return !beneficiaryDemand
		|| (static_cast<bool>(*beneficiaryDemand)
			&& beneficiaryDemand->runtimeId == runtimeGeneration.runtimeId
			&& beneficiaryDemand->proxyGeneration
				== runtimeGeneration.proxyGeneration);
}

[[nodiscard]] inline bool ReserveCapacityProbe(
		EndpointLiveBudgetState &budget,
		AdmissionTicketKey ticketKey,
		RuntimeGenerationKey runtimeGeneration,
		int frontier,
		std::optional<EndpointTransferDemandKey> beneficiaryDemand) {
	if (budget.capacityProbe.stage != CapacityProbeStage::Idle
		|| !ticketKey.runtimeId
		|| !ticketKey.ticketId
		|| runtimeGeneration.runtimeId != ticketKey.runtimeId
		|| !runtimeGeneration.proxyGeneration
		|| budget.provenLowerBound <= 0
		|| frontier != budget.provenLowerBound + 1
		|| !CapacityProbeDemandMatchesGeneration(
			beneficiaryDemand,
			runtimeGeneration)) {
		return false;
	}
	budget.capacityProbe = {
		.stage = CapacityProbeStage::Reserved,
		.ticketKey = ticketKey,
		.runtimeGeneration = runtimeGeneration,
		.frontier = frontier,
		.beneficiaryDemand = std::move(beneficiaryDemand),
	};
	return true;
}

[[nodiscard]] inline bool ActivateCapacityProbe(
		EndpointLiveBudgetState &budget,
		AdmissionTicketKey ticketKey,
		RuntimeGenerationKey runtimeGeneration,
		int frontier,
		const std::optional<EndpointTransferDemandKey> &beneficiaryDemand,
		const RelayProofIdentity &identity) {
	if (!CapacityProbeReservedFor(
			budget,
			ticketKey,
			runtimeGeneration,
			frontier,
			beneficiaryDemand)
		|| runtimeGeneration.runtimeId != identity.runtimeId
		|| runtimeGeneration.proxyGeneration != identity.proxyGeneration
		|| !identity.proxyGeneration
		|| !identity.attemptId) {
		return false;
	}
	budget.capacityProbe.stage = CapacityProbeStage::Active;
	budget.capacityProbe.activeAttempt = identity;
	return true;
}

[[nodiscard]] inline bool ReleaseReservedCapacityProbe(
		EndpointLiveBudgetState &budget,
		AdmissionTicketKey ticketKey,
		RuntimeGenerationKey runtimeGeneration,
		int frontier,
		const std::optional<EndpointTransferDemandKey> &beneficiaryDemand) {
	if (!CapacityProbeReservedFor(
			budget,
			ticketKey,
			runtimeGeneration,
			frontier,
			beneficiaryDemand)) {
		return false;
	}
	budget.capacityProbe = {};
	return true;
}

[[nodiscard]] inline bool ReleaseActiveCapacityProbe(
		EndpointLiveBudgetState &budget,
		AdmissionTicketKey ticketKey,
		RuntimeGenerationKey runtimeGeneration,
		int frontier,
		const std::optional<EndpointTransferDemandKey> &beneficiaryDemand,
		const RelayProofIdentity &activeAttempt) {
	if (!CapacityProbeActiveFor(
			budget,
			ticketKey,
			runtimeGeneration,
			frontier,
			beneficiaryDemand,
			activeAttempt)) {
		return false;
	}
	budget.capacityProbe = {};
	return true;
}

[[nodiscard]] inline bool BeginCapacityProbeCooldown(
		EndpointLiveBudgetState &budget,
		AdmissionTicketKey ticketKey,
		RuntimeGenerationKey runtimeGeneration,
		int frontier,
		const std::optional<EndpointTransferDemandKey> &beneficiaryDemand,
		const RelayProofIdentity &activeAttempt,
		crl::time retryAt) {
	if (!CapacityProbeActiveFor(
			budget,
			ticketKey,
			runtimeGeneration,
			frontier,
			beneficiaryDemand,
			activeAttempt)
		|| !retryAt) {
		return false;
	}
	budget.capacityProbe.stage = CapacityProbeStage::Cooldown;
	budget.capacityProbe.retryAt = retryAt;
	return true;
}

[[nodiscard]] inline bool ExpireCapacityProbeCooldown(
		EndpointLiveBudgetState &budget,
		AdmissionTicketKey ticketKey,
		RuntimeGenerationKey runtimeGeneration,
		int frontier,
		const std::optional<EndpointTransferDemandKey> &beneficiaryDemand,
		const RelayProofIdentity &activeAttempt,
		crl::time now) {
	if (!CapacityProbeCooldownFor(
			budget,
			ticketKey,
			runtimeGeneration,
			frontier,
			beneficiaryDemand,
			activeAttempt)
		|| budget.capacityProbe.retryAt > now) {
		return false;
	}
	budget.capacityProbe = {};
	return true;
}

[[nodiscard]] inline bool RemoveCapacityProbeForRuntime(
		EndpointLiveBudgetState &budget,
		ProxyRuntimeId runtimeId) {
	const auto &probe = budget.capacityProbe;
	const auto matches = probe.stage != CapacityProbeStage::Idle
		&& probe.runtimeGeneration.runtimeId == runtimeId;
	if (!matches) {
		return false;
	}
	budget.capacityProbe = {};
	return true;
}

[[nodiscard]] inline bool RemoveStaleCapacityProbeForGeneration(
		EndpointLiveBudgetState &budget,
		ProxyRuntimeId runtimeId,
		uint64 proxyGeneration) {
	const auto &probe = budget.capacityProbe;
	const auto matches = probe.stage != CapacityProbeStage::Idle
		&& probe.runtimeGeneration.runtimeId == runtimeId
		&& probe.runtimeGeneration.proxyGeneration < proxyGeneration;
	if (!matches) {
		return false;
	}
	budget.capacityProbe = {};
	return true;
}

enum class ReclaimEpisodeStage {
	Requested,
	Authorized,
	VictimAcknowledged,
	BeneficiaryGranted,
	Committed,
	RollbackPending,
	Terminal,
};

enum class ReclaimVictimKind {
	None,
	Reservation,
	TransferLane,
	MainLane,
};

struct ReclaimVictimIdentity {
	ReclaimVictimKind kind = ReclaimVictimKind::None;
	AdmissionTicketKey ticketKey;
	RelayProofIdentity attempt;
	EndpointUse use = EndpointUse::Main;

	bool operator==(const ReclaimVictimIdentity &other) const = default;
};

struct ForegroundTransferEntitlement {
	EndpointTransferDemandKey demand;
	QPointer<QObject> owner;
	QMetaObject::Connection ownerDestroyed;
	AdmissionTicketKey ticketKey;
	RelayProofIdentity attempt;
};

struct ReclaimEpisode {
	ReclaimEpisodeToken token;
	EndpointTransferDemandKey beneficiaryDemand;
	QPointer<QObject> beneficiaryOwner;
	ReclaimEpisodeStage stage = ReclaimEpisodeStage::Requested;
	ReclaimVictimIdentity victim;
	AdmissionTicketKey beneficiaryTicketKey;
	RelayProofIdentity beneficiaryAttempt;
	bool replacementAuthorized = false;
	bool replacementConsumed = false;
	bool victimResumeIssued = false;
};

struct ParkedReclaimVictim {
	ReclaimEpisodeToken episodeToken;
	RelayProofIdentity attempt;
	AdmissionTicketKey ticketKey;
	uint64 proxyEpoch = 0;
	uint64 successEpoch = 0;
	crl::time attemptStartedAt = 0;
	QPointer<QObject> owner;
	QMetaObject::Connection ownerDestroyed;
	std::shared_ptr<Fn<void(EndpointLaneCommand)>> laneControl;
	AdmissionTicketKey resumeTicketKey;
	RelayProofIdentity resumeAttempt;
};

enum class ForegroundTransferEntitlementReleaseCause {
	DemandEnded,
	OwnerDestroyed,
	RuntimeRemoved,
	GenerationChanged,
	ForegroundChanged,
	TerminalRollback,
};

struct EndpointDeferredCleanup {
	std::vector<QMetaObject::Connection> ownerConnections;
	std::vector<ReclaimEpisodeToken> rollbackEpisodes;
	std::optional<ForegroundTransferEntitlementReleaseCause>
		entitlementReleaseCause;
};

struct MainRecoveryState {
	MainRecoveryToken token;
	RuntimeGenerationKey runtimeGeneration;
	ProxyConnectionAttempt sourceAttempt;
	crl::time createdAt = 0;
	MainRecoveryStage stage = MainRecoveryStage::TransportBackoff;
	AdmissionTicketKey adoptedTicketKey;
	uint64 replacementAttemptId = 0;
};

struct EndpointState {
	EndpointId endpoint;
	std::set<QString> routeKeys;
	FailureReason lastFailure = FailureReason::None;
	QString lastDiagnostic;
	crl::time terminalUntil = 0;
	EndpointOpeningState opening;
	EndpointLiveBudgetState liveBudget;
	int active = 0;
	int consecutiveFailures = 0;
	int recipeLevel = 0;
	crl::time nextHandshakeAt = 0;
	bool healthy = false;
	bool halfOpen = false;
	uint64 lastReclaimEpisodeId = 0;
	std::optional<ForegroundTransferEntitlement> foregroundTransferEntitlement;
	std::optional<ReclaimEpisode> reclaimEpisode;
	std::optional<ParkedReclaimVictim> parkedReclaimVictim;
	std::map<ProxyRuntimeId, uint64> generations;
	uint64 proxyEpoch = 1;
	uint64 lastAttemptId = 0;
	std::map<uint64, EndpointAttemptState> attemptStarts;
	std::map<RelayProofIdentity, EndpointAttemptState> liveLanes;
	crl::time deniedSince = 0;
	crl::time lastDenialRotationSignal = 0;
	crl::time lastSuccessAt = 0;
	int exhaustedSinceSuccess = 0;
	bool relayProven = false;
	uint64 successEpoch = 0;
	std::map<RelayProofIdentity, RelayProofState> relayProofs;
	crl::time lastRelaySuccessAt = 0;
	ProxyTlsProfile lastGoodProfile = ProxyTlsProfile::Auto;
	RouteEndpoint lastGoodRoute;
	std::deque<EndpointTerminalEvidence> terminalEvidence;
	std::map<RuntimeGenerationKey, EndpointVerdict> canonicalVerdicts;
	std::map<RuntimeGenerationKey, MainRecoveryState> mainRecoveries;
};

[[nodiscard]] inline bool ForegroundTransferEntitlementMatches(
		const ForegroundTransferEntitlement &entitlement,
		const EndpointTransferDemandKey &demand,
		const QPointer<QObject> &owner) {
	return static_cast<bool>(demand)
		&& entitlement.demand == demand
		&& entitlement.owner == owner;
}

[[nodiscard]] inline bool ClearForegroundTransferTicketLineage(
		EndpointState &state,
		const EndpointTransferDemandKey &demand,
		const QPointer<QObject> &owner,
		AdmissionTicketKey ticketKey) {
	if (!state.foregroundTransferEntitlement
		|| !ForegroundTransferEntitlementMatches(
			*state.foregroundTransferEntitlement,
			demand,
			owner)
		|| state.foregroundTransferEntitlement->ticketKey != ticketKey) {
		return false;
	}
	state.foregroundTransferEntitlement->ticketKey = {};
	return true;
}

[[nodiscard]] inline bool ClearForegroundTransferAttemptLineage(
		EndpointState &state,
		const EndpointTransferDemandKey &demand,
		const QPointer<QObject> &owner,
		const RelayProofIdentity &attempt) {
	if (!state.foregroundTransferEntitlement
		|| !ForegroundTransferEntitlementMatches(
			*state.foregroundTransferEntitlement,
			demand,
			owner)
		|| state.foregroundTransferEntitlement->attempt != attempt) {
		return false;
	}
	state.foregroundTransferEntitlement->attempt = {};
	return true;
}

[[nodiscard]] inline bool ReclaimEpisodeMatches(
		const ReclaimEpisode &episode,
		ReclaimEpisodeToken token,
		const EndpointTransferDemandKey &demand,
		const QPointer<QObject> &owner) {
	return token
		&& episode.token == token
		&& episode.beneficiaryDemand == demand
		&& episode.beneficiaryOwner == owner;
}

inline void DeferEndpointOwnerDisconnect(
		EndpointDeferredCleanup &cleanup,
		QMetaObject::Connection connection) {
	if (connection) {
		cleanup.ownerConnections.push_back(std::move(connection));
	}
}

inline void DeferReclaimEpisodeRollback(
		EndpointDeferredCleanup &cleanup,
		ReclaimEpisodeToken token) {
	if (token
		&& std::find(
			begin(cleanup.rollbackEpisodes),
			end(cleanup.rollbackEpisodes),
			token) == end(cleanup.rollbackEpisodes)) {
		cleanup.rollbackEpisodes.push_back(token);
	}
}

[[nodiscard]] inline bool MarkReclaimEpisodeRollbackPending(
		EndpointState &state,
		ReclaimEpisodeToken token,
		const EndpointTransferDemandKey &demand,
		const QPointer<QObject> &owner,
		EndpointDeferredCleanup &cleanup) {
	if (!state.reclaimEpisode
		|| !ReclaimEpisodeMatches(
			*state.reclaimEpisode,
			token,
			demand,
			owner)
		|| state.reclaimEpisode->stage == ReclaimEpisodeStage::Terminal) {
		return false;
	}
	if (state.reclaimEpisode->stage != ReclaimEpisodeStage::RollbackPending) {
		state.reclaimEpisode->stage = ReclaimEpisodeStage::RollbackPending;
		DeferReclaimEpisodeRollback(cleanup, token);
	}
	return true;
}

[[nodiscard]] inline bool ReleaseForegroundTransferEntitlement(
		EndpointState &state,
		const EndpointTransferDemandKey &demand,
		const QPointer<QObject> &owner,
		ForegroundTransferEntitlementReleaseCause cause,
		EndpointDeferredCleanup &cleanup) {
	if (!state.foregroundTransferEntitlement
		|| !ForegroundTransferEntitlementMatches(
			*state.foregroundTransferEntitlement,
			demand,
			owner)) {
		return false;
	}
	if (state.reclaimEpisode
		&& ReclaimEpisodeMatches(
			*state.reclaimEpisode,
			state.reclaimEpisode->token,
			demand,
			owner)) {
		static_cast<void>(MarkReclaimEpisodeRollbackPending(
			state,
			state.reclaimEpisode->token,
			demand,
			owner,
			cleanup));
	}
	DeferEndpointOwnerDisconnect(
		cleanup,
		state.foregroundTransferEntitlement->ownerDestroyed);
	state.foregroundTransferEntitlement.reset();
	cleanup.entitlementReleaseCause = cause;
	return true;
}

[[nodiscard]] inline bool RemoveParkedReclaimVictim(
		EndpointState &state,
		ReclaimEpisodeToken token,
		const RelayProofIdentity &attempt,
		EndpointDeferredCleanup &cleanup) {
	if (!state.parkedReclaimVictim
		|| state.parkedReclaimVictim->episodeToken != token
		|| state.parkedReclaimVictim->attempt != attempt) {
		return false;
	}
	DeferEndpointOwnerDisconnect(
		cleanup,
		state.parkedReclaimVictim->ownerDestroyed);
	state.parkedReclaimVictim.reset();
	if (state.reclaimEpisode
		&& state.reclaimEpisode->token == token) {
		state.reclaimEpisode->stage = ReclaimEpisodeStage::Terminal;
	}
	cleanup.rollbackEpisodes.erase(
		std::remove(
			begin(cleanup.rollbackEpisodes),
			end(cleanup.rollbackEpisodes),
			token),
		end(cleanup.rollbackEpisodes));
	return true;
}

[[nodiscard]] inline auto PrepareEndpointOwnershipCleanup(
		EndpointState &state,
		ProxyRuntimeId runtimeId,
		uint64 staleBeforeGeneration,
		ForegroundTransferEntitlementReleaseCause cause)
-> EndpointDeferredCleanup {
	auto result = EndpointDeferredCleanup();
	if (!runtimeId) {
		return result;
	}
	if (state.foregroundTransferEntitlement
		&& state.foregroundTransferEntitlement->demand.runtimeId
			== runtimeId
		&& (!staleBeforeGeneration
			|| state.foregroundTransferEntitlement->demand.proxyGeneration
				< staleBeforeGeneration)) {
		const auto demand = state.foregroundTransferEntitlement->demand;
		const auto owner = state.foregroundTransferEntitlement->owner;
		static_cast<void>(ReleaseForegroundTransferEntitlement(
			state,
			demand,
			owner,
			cause,
			result));
	}
	if (state.parkedReclaimVictim
		&& state.parkedReclaimVictim->attempt.runtimeId == runtimeId
		&& (!staleBeforeGeneration
			|| state.parkedReclaimVictim->attempt.proxyGeneration
				< staleBeforeGeneration)) {
		const auto token = state.parkedReclaimVictim->episodeToken;
		const auto attempt = state.parkedReclaimVictim->attempt;
		static_cast<void>(RemoveParkedReclaimVictim(
			state,
			token,
			attempt,
			result));
	}
	return result;
}

[[nodiscard]] MainRecoveryToken CreateMainRecoveryLocked(
	EndpointContextStorage &storage,
	const QString &endpointKey,
	RuntimeGenerationKey runtimeGeneration,
	const ProxyConnectionAttempt &sourceAttempt,
	crl::time createdAt);
[[nodiscard]] std::optional<MainRecoveryView> ComposeMainRecoveryViewLocked(
	const EndpointContextStorage &storage,
	const QString &endpointKey,
	RuntimeGenerationKey runtimeGeneration);
[[nodiscard]] bool AdoptMainRecoveryAdmissionTicketLocked(
	EndpointContextStorage &storage,
	const QString &endpointKey,
	RuntimeGenerationKey runtimeGeneration,
	EndpointUse use,
	MainRecoveryToken token,
	AdmissionTicketKey ticketKey);
[[nodiscard]] bool AdoptMainRecoveryReplacementAttemptLocked(
	EndpointContextStorage &storage,
	const QString &endpointKey,
	RuntimeGenerationKey runtimeGeneration,
	EndpointUse use,
	MainRecoveryToken token,
	AdmissionTicketKey ticketKey,
	uint64 replacementAttemptId);
[[nodiscard]] bool FinishMainRecoveryByAdmissionTicketLocked(
	EndpointContextStorage &storage,
	const QString &endpointKey,
	RuntimeGenerationKey runtimeGeneration,
	EndpointUse use,
	MainRecoveryToken token,
	AdmissionTicketKey ticketKey);
[[nodiscard]] bool FinishMainRecoveryByReplacementAttemptLocked(
	EndpointContextStorage &storage,
	const QString &endpointKey,
	RuntimeGenerationKey runtimeGeneration,
	EndpointUse use,
	uint64 replacementAttemptId);
[[nodiscard]] bool CancelMainRecoveryBackoffLocked(
	EndpointContextStorage &storage,
	const QString &endpointKey,
	RuntimeGenerationKey runtimeGeneration,
	MainRecoveryToken token);
[[nodiscard]] bool RemoveMainRecoveryForGenerationLocked(
	EndpointState &state,
	RuntimeGenerationKey runtimeGeneration);
[[nodiscard]] bool RemoveMainRecoveriesForRuntimeLocked(
	EndpointState &state,
	ProxyRuntimeId runtimeId);

[[nodiscard]] inline EndpointOpenFailureState &EndpointOpeningFailure(
		EndpointState &state,
		bool bootstrap) {
	return bootstrap ? state.opening.bootstrap : state.opening.expansion;
}

[[nodiscard]] inline const EndpointOpenFailureState &EndpointOpeningFailure(
		const EndpointState &state,
		bool bootstrap) {
	return bootstrap ? state.opening.bootstrap : state.opening.expansion;
}

[[nodiscard]] inline EndpointOpeningFlowKey EndpointOpeningFlow(
		RuntimeGenerationKey runtimeGeneration,
		EndpointUse use) {
	return {
		.runtimeGeneration = runtimeGeneration,
		.use = use,
	};
}

[[nodiscard]] inline EndpointOpenFailureState *FindEndpointExpansionFailure(
		EndpointState &state,
		RuntimeGenerationKey runtimeGeneration,
		EndpointUse use) {
	const auto i = state.opening.expansionFlows.find(
		EndpointOpeningFlow(runtimeGeneration, use));
	return (i == end(state.opening.expansionFlows)) ? nullptr : &i->second;
}

[[nodiscard]] inline const EndpointOpenFailureState *FindEndpointExpansionFailure(
		const EndpointState &state,
		RuntimeGenerationKey runtimeGeneration,
		EndpointUse use) {
	const auto i = state.opening.expansionFlows.find(
		EndpointOpeningFlow(runtimeGeneration, use));
	return (i == end(state.opening.expansionFlows)) ? nullptr : &i->second;
}

[[nodiscard]] inline EndpointOpenFailureState &EnsureEndpointExpansionFailure(
		EndpointState &state,
		RuntimeGenerationKey runtimeGeneration,
		EndpointUse use) {
	const auto key = EndpointOpeningFlow(runtimeGeneration, use);
	auto &result = state.opening.expansionFlows[key];
	result.runtimeGeneration = runtimeGeneration;
	result.use = use;
	return result;
}

inline void RecomputeEndpointExpansionThrottle(EndpointState &state) {
	state.opening.expansion = {};
	for (const auto &entry : state.opening.expansionFlows) {
		const auto &candidate = entry.second;
		if (candidate.retryUntil > state.opening.expansion.retryUntil) {
			state.opening.expansion = candidate;
		}
	}
}

inline void RemoveEndpointExpansionFailure(
		EndpointState &state,
		RuntimeGenerationKey runtimeGeneration,
		EndpointUse use) {
	state.opening.expansionFlows.erase(
		EndpointOpeningFlow(runtimeGeneration, use));
	RecomputeEndpointExpansionThrottle(state);
}

inline void RemoveEndpointExpansionFailuresForRuntime(
		EndpointState &state,
		ProxyRuntimeId runtimeId) {
	for (auto i = begin(state.opening.expansionFlows);
			i != end(state.opening.expansionFlows);) {
		if (i->first.runtimeGeneration.runtimeId == runtimeId) {
			i = state.opening.expansionFlows.erase(i);
		} else {
			++i;
		}
	}
	RecomputeEndpointExpansionThrottle(state);
}

inline constexpr auto kEndpointTerminalEvidenceLimit = std::size_t(32);
inline constexpr auto kEndpointTerminalEvidenceWindow
	= crl::time(60 * 1000);

[[nodiscard]] inline bool RuntimeGenerationIsCurrent(
		const EndpointState &state,
		const RuntimeGenerationKey &key) {
	const auto i = state.generations.find(key.runtimeId);
	return key.runtimeId
		&& i != end(state.generations)
		&& i->second == key.proxyGeneration;
}

inline void PruneExpiredEndpointOutcomes(
		EndpointState &state,
		crl::time now) {
	const auto expired = std::remove_if(
		begin(state.terminalEvidence),
		end(state.terminalEvidence),
		[=](const EndpointTerminalEvidence &entry) {
			const auto observedAt = entry.terminalAt
				? entry.terminalAt
				: entry.verdict.observedAt;
			return !observedAt
				|| (now - observedAt >= kEndpointTerminalEvidenceWindow);
		});
	state.terminalEvidence.erase(expired, end(state.terminalEvidence));
	for (auto i = begin(state.canonicalVerdicts);
			i != end(state.canonicalVerdicts);) {
		const auto evidenceUntil = i->second.observedAt
			? (i->second.observedAt + kEndpointTerminalEvidenceWindow)
			: crl::time();
		const auto relevantUntil = std::max(
			evidenceUntil,
			i->second.retryUntil);
		if (relevantUntil <= now) {
			i = state.canonicalVerdicts.erase(i);
		} else {
			++i;
		}
	}
}

inline void PruneEndpointOutcomesAfterSuccess(
		EndpointState &state,
		const RuntimeGenerationKey &key,
		crl::time succeededAt) {
	if (!succeededAt) {
		return;
	}
	const auto stale = std::remove_if(
		begin(state.terminalEvidence),
		end(state.terminalEvidence),
		[&](const EndpointTerminalEvidence &entry) {
			const auto observedAt = entry.terminalAt
				? entry.terminalAt
				: entry.verdict.observedAt;
			return entry.runtimeGeneration == key
				&& observedAt <= succeededAt;
		});
	state.terminalEvidence.erase(stale, end(state.terminalEvidence));
	const auto canonical = state.canonicalVerdicts.find(key);
	if (canonical != end(state.canonicalVerdicts)
		&& canonical->second.observedAt <= succeededAt) {
		state.canonicalVerdicts.erase(canonical);
	}
}

inline void PruneEndpointOutcomesForGeneration(
		EndpointState &state,
		ProxyRuntimeId runtimeId,
		uint64 proxyGeneration) {
	const auto stale = std::remove_if(
		begin(state.terminalEvidence),
		end(state.terminalEvidence),
		[=](const EndpointTerminalEvidence &entry) {
			return entry.runtimeGeneration.runtimeId == runtimeId
				&& entry.runtimeGeneration.proxyGeneration
					!= proxyGeneration;
		});
	state.terminalEvidence.erase(stale, end(state.terminalEvidence));
	for (auto i = begin(state.canonicalVerdicts);
			i != end(state.canonicalVerdicts);) {
		if (i->first.runtimeId == runtimeId
			&& i->first.proxyGeneration != proxyGeneration) {
			i = state.canonicalVerdicts.erase(i);
		} else {
			++i;
		}
	}
}

inline void RemoveEndpointOutcomesForRuntime(
		EndpointState &state,
		ProxyRuntimeId runtimeId) {
	const auto removed = std::remove_if(
		begin(state.terminalEvidence),
		end(state.terminalEvidence),
		[=](const EndpointTerminalEvidence &entry) {
			return entry.runtimeGeneration.runtimeId == runtimeId;
		});
	state.terminalEvidence.erase(removed, end(state.terminalEvidence));
	for (auto i = begin(state.canonicalVerdicts);
			i != end(state.canonicalVerdicts);) {
		if (i->first.runtimeId == runtimeId) {
			i = state.canonicalVerdicts.erase(i);
		} else {
			++i;
		}
	}
}

[[nodiscard]] inline bool RecordCurrentTerminalEvidence(
		EndpointState &state,
		EndpointTerminalEvidence evidence,
		crl::time now) {
	PruneExpiredEndpointOutcomes(state, now);
	if (!RuntimeGenerationIsCurrent(state, evidence.runtimeGeneration)) {
		return false;
	}
	evidence.verdict.runtimeGeneration = evidence.runtimeGeneration;
	evidence.verdict.scope = EndpointVerdictScope::Attempt;
	if (!evidence.verdict.observedAt) {
		evidence.verdict.observedAt = now;
	}
	if (!evidence.terminalAt) {
		evidence.terminalAt = evidence.verdict.terminalAt
			? evidence.verdict.terminalAt
			: evidence.verdict.observedAt;
	}
	if (!evidence.verdict.terminalAt) {
		evidence.verdict.terminalAt = evidence.terminalAt;
	}
	state.terminalEvidence.push_back(std::move(evidence));
	while (state.terminalEvidence.size()
			> kEndpointTerminalEvidenceLimit) {
		state.terminalEvidence.pop_front();
	}
	return true;
}

[[nodiscard]] inline int CurrentMainNetworkEvidenceCount(
		const EndpointState &state,
		const RuntimeGenerationKey &key,
		crl::time now) {
	auto result = 0;
	for (const auto &entry : state.terminalEvidence) {
		const auto observedAt = entry.terminalAt
			? entry.terminalAt
			: entry.verdict.observedAt;
		if (entry.runtimeGeneration == key
			&& entry.use == EndpointUse::Main
			&& entry.verdict.attribution
				== ProxyFailureAttribution::Network
			&& observedAt
			&& observedAt <= now
			&& now - observedAt < kEndpointTerminalEvidenceWindow) {
			++result;
		}
	}
	return result;
}

[[nodiscard]] inline bool SetCurrentCanonicalVerdict(
		EndpointState &state,
		const RuntimeGenerationKey &key,
		EndpointVerdict verdict) {
	if (!RuntimeGenerationIsCurrent(state, key)) {
		return false;
	}
	verdict.runtimeGeneration = key;
	verdict.scope = EndpointVerdictScope::Endpoint;
	state.canonicalVerdicts.insert_or_assign(key, std::move(verdict));
	return true;
}

[[nodiscard]] inline bool RuntimeProxyGenerationIsStale(
		const EndpointState &state,
		ProxyRuntimeId runtimeId,
		uint64 proxyGeneration) {
	const auto i = state.generations.find(runtimeId);
	return i != end(state.generations)
		&& proxyGeneration < i->second;
}

[[nodiscard]] inline bool HasEndpointAttempt(
		const EndpointState &state,
		const RelayProofIdentity &identity) {
	const auto i = state.attemptStarts.find(identity.attemptId);
	return (i != end(state.attemptStarts)
		&& i->second.runtimeId == identity.runtimeId
		&& i->second.proxyGeneration == identity.proxyGeneration)
		|| state.liveLanes.contains(identity);
}

[[nodiscard]] inline bool HasRelayProof(
		const EndpointState &state,
		const RelayProofIdentity &identity) {
	return state.relayProofs.contains(identity);
}

[[nodiscard]] inline MainRelayProofView CurrentMainRelayProof(
		const EndpointState &state,
		const RuntimeGenerationKey &key) {
	auto result = MainRelayProofView();
	if (!RuntimeGenerationIsCurrent(state, key)) {
		return result;
	}
	for (const auto &[identity, proof] : state.relayProofs) {
		if (identity.runtimeId != key.runtimeId
			|| identity.proxyGeneration != key.proxyGeneration
			|| proof.use != EndpointUse::Main) {
			continue;
		}
		result.provenAt = std::max(result.provenAt, proof.provenAt);
		result.lastPayloadAt = std::max(
			result.lastPayloadAt,
			proof.lastPayloadAt);
		result.payloadCount = std::min(
			int(kRelayProofPayloadCountLimit),
			result.payloadCount + std::max(1, int(proof.payloadCount)));
	}
	result.strength = (result.payloadCount >= 2)
		? MainRelayProofStrength::RepeatedPayload
		: (result.payloadCount == 1)
		? MainRelayProofStrength::SinglePayload
		: MainRelayProofStrength::None;
	return result;
}

[[nodiscard]] inline bool HasCurrentMainRelayProof(
		const EndpointState &state,
		const RuntimeGenerationKey &key) {
	return CurrentMainRelayProof(state, key).strength
		!= MainRelayProofStrength::None;
}

[[nodiscard]] inline MainRelayProofView EndpointMainRelayProof(
		const EndpointState &state) {
	auto result = MainRelayProofView();
	for (const auto &[identity, proof] : state.relayProofs) {
		const auto generation = state.generations.find(identity.runtimeId);
		if (generation == end(state.generations)
			|| generation->second != identity.proxyGeneration
			|| proof.use != EndpointUse::Main) {
			continue;
		}
		result.provenAt = std::max(result.provenAt, proof.provenAt);
		result.lastPayloadAt = std::max(
			result.lastPayloadAt,
			proof.lastPayloadAt);
		result.payloadCount = std::min(
			int(kRelayProofPayloadCountLimit),
			result.payloadCount + std::max(1, int(proof.payloadCount)));
	}
	result.strength = (result.payloadCount >= 2)
		? MainRelayProofStrength::RepeatedPayload
		: (result.payloadCount == 1)
		? MainRelayProofStrength::SinglePayload
		: MainRelayProofStrength::None;
	return result;
}

[[nodiscard]] inline int ActiveEndpointAdmissionCount(
		const EndpointState &state) {
	auto result = 0;
	for (const auto &entry : state.attemptStarts) {
		if (entry.second.admissionActive) {
			++result;
		}
	}
	return result;
}

[[nodiscard]] inline int EndpointRelayProofCount(
		const EndpointState &state) {
	auto result = 0;
	for (const auto &[identity, proof] : state.relayProofs) {
		const auto generation = state.generations.find(identity.runtimeId);
		if (generation != end(state.generations)
			&& generation->second == identity.proxyGeneration) {
			++result;
		}
	}
	return result;
}

[[nodiscard]] inline int EndpointEstablishedCommitmentCount(
		const EndpointState &state,
		uint64 excludedAttemptId = 0) {
	auto result = 0;
	for (const auto &entry : state.liveLanes) {
		if (entry.first.attemptId != excludedAttemptId) {
			++result;
		}
	}
	for (const auto &[attemptId, attempt] : state.attemptStarts) {
		if (attemptId == excludedAttemptId || attempt.admissionActive) {
			continue;
		}
		++result;
	}
	return result;
}

[[nodiscard]] inline int EndpointCapacityCommitmentCount(
		const EndpointState &state) {
	return ActiveEndpointAdmissionCount(state)
		+ EndpointEstablishedCommitmentCount(state);
}

inline void SynchronizeEndpointAdmissionAggregate(EndpointState &state) {
	state.active = ActiveEndpointAdmissionCount(state);
}

[[nodiscard]] inline bool ReleaseAdmissionForRelayCandidate(
		EndpointState &state,
		const RelayProofIdentity &identity) {
	const auto i = state.attemptStarts.find(identity.attemptId);
	if (i == end(state.attemptStarts)
		|| i->second.runtimeId != identity.runtimeId
		|| i->second.proxyGeneration != identity.proxyGeneration
		|| !i->second.admissionActive) {
		return false;
	}
	i->second.admissionActive = false;
	SynchronizeEndpointAdmissionAggregate(state);
	return true;
}

inline void SynchronizeRelayProofAggregate(EndpointState &state) {
	for (auto i = begin(state.relayProofs);
			i != end(state.relayProofs);) {
		const auto generation = state.generations.find(i->first.runtimeId);
		if (generation != end(state.generations)
			&& i->first.proxyGeneration < generation->second) {
			i = state.relayProofs.erase(i);
		} else {
			++i;
		}
	}
	state.relayProven = !state.relayProofs.empty();
	state.lastRelaySuccessAt = 0;
	for (const auto &entry : state.relayProofs) {
		state.lastRelaySuccessAt = std::max(
			state.lastRelaySuccessAt,
			std::max(
				entry.second.provenAt,
				entry.second.lastPayloadAt));
	}
	if (state.relayProven) {
		state.healthy = true;
	}
}

[[nodiscard]] inline RelayProofPromotionResult PromoteRelayProof(
		EndpointState &state,
		const RelayProofIdentity &identity,
		RelayProofState proof) {
	if (HasRelayProof(state, identity)) {
		return RelayProofPromotionResult::AlreadyProven;
	}
	const auto attempt = state.attemptStarts.find(identity.attemptId);
	if (attempt == end(state.attemptStarts)
		|| attempt->second.runtimeId != identity.runtimeId
		|| attempt->second.proxyGeneration != identity.proxyGeneration
		|| attempt->second.terminalVerdict.has_value()) {
		return RelayProofPromotionResult::MissingAdmission;
	}
	proof.ticketKey = attempt->second.ticketKey;
	proof.use = attempt->second.use;
	proof.traceId = attempt->second.traceId;
	proof.proxyEpoch = attempt->second.proxyEpoch;
	proof.successEpoch = attempt->second.successEpoch;
	proof.attemptStartedAt = attempt->second.attemptStartedAt;
	proof.owner = attempt->second.owner;
	proof.laneControl = attempt->second.laneControl;
	proof.preempting = attempt->second.preempting;
	if (!proof.lastPayloadAt) {
		proof.lastPayloadAt = proof.provenAt;
	}
	proof.payloadCount = std::clamp(
		proof.payloadCount,
		uint8(1),
		kRelayProofPayloadCountLimit);
	attempt->second.admissionActive = false;
	state.relayProofs.emplace(identity, proof);
	state.liveLanes.emplace(identity, attempt->second);
	state.attemptStarts.erase(identity.attemptId);
	SynchronizeEndpointAdmissionAggregate(state);
	SynchronizeRelayProofAggregate(state);
	return RelayProofPromotionResult::Inserted;
}

[[nodiscard]] inline bool RefreshRelayProofPayload(
		EndpointState &state,
		const RelayProofIdentity &identity,
		crl::time payloadAt) {
	const auto i = state.relayProofs.find(identity);
	if (i == end(state.relayProofs)) {
		return false;
	}
	if (payloadAt) {
		i->second.lastPayloadAt = std::max(
			i->second.lastPayloadAt,
			payloadAt);
	}
	if (i->second.payloadCount < kRelayProofPayloadCountLimit) {
		++i->second.payloadCount;
	}
	SynchronizeRelayProofAggregate(state);
	return true;
}

[[nodiscard]] inline bool RetireRelayProof(
		EndpointState &state,
		const RelayProofIdentity &identity) {
	if (!state.relayProofs.erase(identity)) {
		return false;
	}
	SynchronizeRelayProofAggregate(state);
	return true;
}

[[nodiscard]] inline EndpointDeferredCleanup RemoveRelayProofsForRuntime(
		EndpointState &state,
		ProxyRuntimeId runtimeId) {
	auto cleanup = PrepareEndpointOwnershipCleanup(
		state,
		runtimeId,
		0,
		ForegroundTransferEntitlementReleaseCause::RuntimeRemoved);
	static_cast<void>(RemoveCapacityProbeForRuntime(
		state.liveBudget,
		runtimeId));
	for (auto i = begin(state.relayProofs);
			i != end(state.relayProofs);) {
		if (i->first.runtimeId == runtimeId) {
			i = state.relayProofs.erase(i);
		} else {
			++i;
		}
	}
	SynchronizeRelayProofAggregate(state);
	static_cast<void>(RemoveMainRecoveriesForRuntimeLocked(
		state,
		runtimeId));
	RemoveEndpointOutcomesForRuntime(state, runtimeId);
	return cleanup;
}

inline void ApplyRuntimeProxyGeneration(
		EndpointState &state,
		ProxyRuntimeId runtimeId,
		uint64 proxyGeneration,
		EndpointDeferredCleanup *deferredCleanup = nullptr) {
	if (!runtimeId) {
		return;
	}
	const auto current = state.generations.find(runtimeId);
	if (current != end(state.generations)
		&& proxyGeneration <= current->second) {
		return;
	}
	auto cleanup = PrepareEndpointOwnershipCleanup(
		state,
		runtimeId,
		proxyGeneration,
		ForegroundTransferEntitlementReleaseCause::GenerationChanged);
	static_cast<void>(RemoveStaleCapacityProbeForGeneration(
		state.liveBudget,
		runtimeId,
		proxyGeneration));
	state.generations[runtimeId] = proxyGeneration;
	static_cast<void>(RemoveMainRecoveriesForRuntimeLocked(
		state,
		runtimeId));
	for (auto i = begin(state.opening.expansionFlows);
			i != end(state.opening.expansionFlows);) {
		if (i->first.runtimeGeneration.runtimeId == runtimeId
			&& i->first.runtimeGeneration.proxyGeneration < proxyGeneration) {
			i = state.opening.expansionFlows.erase(i);
		} else {
			++i;
		}
	}
	RecomputeEndpointExpansionThrottle(state);
	PruneEndpointOutcomesForGeneration(
		state,
		runtimeId,
		proxyGeneration);
	for (auto i = begin(state.attemptStarts);
			i != end(state.attemptStarts);) {
		if (i->second.runtimeId == runtimeId
			&& i->second.proxyGeneration < proxyGeneration) {
			if (!i->second.preempting) {
				DeferEndpointOwnerDisconnect(
					cleanup,
					i->second.ownerDestroyed);
			}
			i = state.attemptStarts.erase(i);
		} else {
			++i;
		}
	}
	for (auto i = begin(state.liveLanes); i != end(state.liveLanes);) {
		if (i->first.runtimeId == runtimeId
			&& i->first.proxyGeneration < proxyGeneration) {
			if (!i->second.preempting) {
				DeferEndpointOwnerDisconnect(
					cleanup,
					i->second.ownerDestroyed);
			}
			i = state.liveLanes.erase(i);
		} else {
			++i;
		}
	}
	SynchronizeEndpointAdmissionAggregate(state);
	for (auto i = begin(state.relayProofs);
			i != end(state.relayProofs);) {
		if (i->first.runtimeId == runtimeId
			&& i->first.proxyGeneration < proxyGeneration) {
			i = state.relayProofs.erase(i);
		} else {
			++i;
		}
	}
	SynchronizeRelayProofAggregate(state);
	if (deferredCleanup) {
		*deferredCleanup = std::move(cleanup);
	}
}

struct RouteState {
	RouteEndpoint route;
	FailureReason lastFailure = FailureReason::None;
	bool healthy = false;
	int relaySuspect = 0;
};

struct EndpointUseCounts {
	int main = 0;
	int maintenance = 0;
	int auxiliary = 0;
	int media = 0;
	int upload = 0;
	int proxyCheck = 0;

	bool operator==(const EndpointUseCounts &other) const = default;
};

struct EndpointAdmissionPolicyInput {
	EndpointUseCounts active;
	EndpointUseCounts scheduled;
	EndpointUse use = EndpointUse::Main;
	MainRelayProofStrength mainProof = MainRelayProofStrength::None;
	MainRelayProofStrength endpointMainProof
		= MainRelayProofStrength::None;
	FailureReason lastFailure = FailureReason::None;
	int urgentMainDemand = 0;
	crl::time retryUntil = 0;
	crl::time nextHandshakeAt = 0;
	crl::time lastRelaySuccessAt = 0;
	crl::time now = 0;
	bool endpointRelayProven = false;
	bool healthy = false;
	bool fastWarmup = false;
	bool foregroundTransfer = false;
	bool bootstrapFailure = false;
};

struct EndpointConcurrencyPolicy {
	int activeCap = 0;
	crl::time handshakeSpacing = 0;
	crl::time retryAfter = 0;
	bool recipeEscalationAllowed = false;
	bool useAllowed = true;
	bool admissionAllowed = true;
	bool mainLaneReserved = false;
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

} // namespace MTP::details::MtProxy
