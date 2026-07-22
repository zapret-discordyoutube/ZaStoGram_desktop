/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#pragma once

#include "mtproto/proxy/mtproxy/endpoint_health.h"

#include <QtCore/QObject>

#include <algorithm>
#include <compare>
#include <cstddef>
#include <deque>
#include <iterator>
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
	QMetaObject::Connection ownerDestroyed;
};

struct RelayProofIdentity {
	ProxyRuntimeId runtimeId = 0;
	uint64 proxyGeneration = 0;
	uint64 attemptId = 0;

	friend inline auto operator<=>(
		RelayProofIdentity,
		RelayProofIdentity) = default;
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

struct EndpointDeferredCleanup {
	std::vector<QMetaObject::Connection> ownerConnections;
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

struct EndpointPhysicalOpeningBoundary {
	ProxyConnectionAttempt pressureAttempt;
	FailureReason pressureReason = FailureReason::None;
	crl::time pressureObservedAt = 0;
	crl::time pressureUntil = 0;
};

struct EndpointState {
	EndpointId endpoint;
	std::set<QString> routeKeys;
	EndpointPhysicalOpeningBoundary physicalOpeningBoundary;
	FailureReason lastFailure = FailureReason::None;
	QString lastDiagnostic;
	crl::time terminalUntil = 0;
	int consecutiveFailures = 0;
	int recipeFailureStreak = 0;
	int recipeLevel = 0;
	bool healthy = false;
	bool halfOpen = false;
	std::map<ProxyRuntimeId, uint64> generations;
	uint64 proxyEpoch = 1;
	uint64 lastAttemptId = 0;
	std::map<uint64, EndpointAttemptState> attemptStarts;
	std::map<RelayProofIdentity, EndpointAttemptState> liveLanes;
	crl::time lastSuccessAt = 0;
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

inline void DeferEndpointOwnerDisconnect(
		EndpointDeferredCleanup &cleanup,
		QMetaObject::Connection connection) {
	if (connection) {
		cleanup.ownerConnections.push_back(std::move(connection));
	}
}

inline void MergeDeferredCleanup(
		EndpointDeferredCleanup &target,
		EndpointDeferredCleanup source) {
	target.ownerConnections.insert(
		end(target.ownerConnections),
		std::make_move_iterator(begin(source.ownerConnections)),
		std::make_move_iterator(end(source.ownerConnections)));
}

[[nodiscard]] inline bool HasDeferredCleanup(
		const EndpointDeferredCleanup &cleanup) {
	return !cleanup.ownerConnections.empty();
}

inline void DisconnectDeferredOwners(EndpointDeferredCleanup &cleanup) {
	for (const auto &connection : cleanup.ownerConnections) {
		QObject::disconnect(connection);
	}
	cleanup.ownerConnections.clear();
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
	if (!proof.lastPayloadAt) {
		proof.lastPayloadAt = proof.provenAt;
	}
	proof.payloadCount = std::clamp(
		proof.payloadCount,
		uint8(1),
		kRelayProofPayloadCountLimit);
	state.relayProofs.emplace(identity, proof);
	state.liveLanes.emplace(identity, attempt->second);
	state.attemptStarts.erase(identity.attemptId);
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

inline void RemoveRelayProofsForRuntime(
		EndpointState &state,
		ProxyRuntimeId runtimeId) {
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
	auto cleanup = EndpointDeferredCleanup();
	state.generations[runtimeId] = proxyGeneration;
	static_cast<void>(RemoveMainRecoveriesForRuntimeLocked(
		state,
		runtimeId));
	PruneEndpointOutcomesForGeneration(
		state,
		runtimeId,
		proxyGeneration);
	for (auto i = begin(state.attemptStarts);
			i != end(state.attemptStarts);) {
		if (i->second.runtimeId == runtimeId
			&& i->second.proxyGeneration < proxyGeneration) {
			DeferEndpointOwnerDisconnect(
				cleanup,
				i->second.ownerDestroyed);
			i = state.attemptStarts.erase(i);
		} else {
			++i;
		}
	}
	for (auto i = begin(state.liveLanes); i != end(state.liveLanes);) {
		if (i->first.runtimeId == runtimeId
			&& i->first.proxyGeneration < proxyGeneration) {
			DeferEndpointOwnerDisconnect(
				cleanup,
				i->second.ownerDestroyed);
			i = state.liveLanes.erase(i);
		} else {
			++i;
		}
	}
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
