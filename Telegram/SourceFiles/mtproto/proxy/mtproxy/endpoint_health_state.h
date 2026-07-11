/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#pragma once

#include "mtproto/proxy/mtproxy/endpoint_health.h"

#include <compare>
#include <map>
#include <set>

namespace MTP::details::MtProxy {

struct EndpointAttemptState {
	ProxyRuntimeId runtimeId = 0;
	uint64 proxyGeneration = 0;
	crl::time startedAt = 0;
	bool admissionActive = true;
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
};

enum class RelayProofPromotionResult {
	Inserted,
	AlreadyProven,
	MissingAdmission,
};

struct EndpointState {
	EndpointId endpoint;
	std::set<QString> routeKeys;
	FailureReason lastFailure = FailureReason::None;
	QString lastDiagnostic;
	crl::time terminalUntil = 0;
	int active = 0;
	int consecutiveFailures = 0;
	int recipeLevel = 0;
	crl::time nextHandshakeAt = 0;
	bool healthy = false;
	bool halfOpen = false;
	std::map<ProxyRuntimeId, uint64> generations;
	uint64 proxyEpoch = 1;
	uint64 lastAttemptId = 0;
	std::map<uint64, EndpointAttemptState> attemptStarts;
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
};

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
	return i != end(state.attemptStarts)
		&& i->second.runtimeId == identity.runtimeId
		&& i->second.proxyGeneration == identity.proxyGeneration;
}

[[nodiscard]] inline bool HasRelayProof(
		const EndpointState &state,
		const RelayProofIdentity &identity) {
	return state.relayProofs.contains(identity);
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
		if (entry.second.provenAt > state.lastRelaySuccessAt) {
			state.lastRelaySuccessAt = entry.second.provenAt;
		}
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
	if (!HasEndpointAttempt(state, identity)) {
		return RelayProofPromotionResult::MissingAdmission;
	}
	state.relayProofs.emplace(identity, proof);
	state.attemptStarts.erase(identity.attemptId);
	SynchronizeEndpointAdmissionAggregate(state);
	SynchronizeRelayProofAggregate(state);
	return RelayProofPromotionResult::Inserted;
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
}

inline void ApplyRuntimeProxyGeneration(
		EndpointState &state,
		ProxyRuntimeId runtimeId,
		uint64 proxyGeneration) {
	if (!runtimeId) {
		return;
	}
	const auto current = state.generations.find(runtimeId);
	if ((current != end(state.generations)
			&& proxyGeneration <= current->second)
		|| (current == end(state.generations) && !proxyGeneration)) {
		return;
	}
	state.generations[runtimeId] = proxyGeneration;
	for (auto i = begin(state.attemptStarts);
			i != end(state.attemptStarts);) {
		if (i->second.runtimeId == runtimeId
			&& i->second.proxyGeneration < proxyGeneration) {
			i = state.attemptStarts.erase(i);
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
}

struct RouteState {
	RouteEndpoint route;
	FailureReason lastFailure = FailureReason::None;
	bool healthy = false;
	int relaySuspect = 0;
};

struct EndpointConcurrencyPolicy {
	int activeCap = 0;
	crl::time handshakeSpacing = 0;
	crl::time retryAfter = 0;
	bool recipeEscalationAllowed = false;
	bool useAllowed = true;
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
