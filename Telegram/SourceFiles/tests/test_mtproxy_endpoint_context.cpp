/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "mtproto/proxy/mtproxy/endpoint_health_state.h"
#include "mtproto/proxy/proxy_endpoint_context.h"
#include "mtproto/proxy/proxy_endpoint_context_p.h"

#include <cstdio>

namespace {

namespace MtProxy = MTP::details::MtProxy;

constexpr auto kRuntimeA = MTP::ProxyRuntimeId(2);
constexpr auto kRuntimeB = MTP::ProxyRuntimeId(5);
constexpr auto kRuntimeC = MTP::ProxyRuntimeId(3);
constexpr auto kGeneration = uint64(36);

[[nodiscard]] int Fail(const char *message) {
	std::fprintf(stderr, "%s\n", message);
	return 1;
}

void SeedAdmission(
		MtProxy::EndpointState &state,
		const MtProxy::RelayProofIdentity &identity,
		crl::time startedAt) {
	MtProxy::ApplyRuntimeProxyGeneration(
		state,
		identity.runtimeId,
		identity.proxyGeneration);
	state.attemptStarts.emplace(
		identity.attemptId,
		MtProxy::EndpointAttemptState{
			.runtimeId = identity.runtimeId,
			.proxyGeneration = identity.proxyGeneration,
			.startedAt = startedAt,
		});
	state.active = int(state.attemptStarts.size());
}

[[nodiscard]] bool GenerationValidatedRelayProofMembership(
		const MtProxy::EndpointState &state,
		const MtProxy::RelayProofIdentity &identity) {
	if (MtProxy::RuntimeProxyGenerationIsStale(
			state,
			identity.runtimeId,
			identity.proxyGeneration)) {
		return false;
	}
	return MtProxy::HasRelayProof(state, identity);
}

[[nodiscard]] int ScenarioTraceLifecycle() {
	const auto context = MTP::CreateProxyEndpointContext();
	const auto firstRuntime = context->registerRuntime();
	const auto secondRuntime = context->registerRuntime();
	if (!firstRuntime || firstRuntime == secondRuntime) {
		return Fail("runtime ids are not unique");
	}
	const auto firstTrace = context->nextTraceId({
		.runtimeId = firstRuntime,
		.ticketId = 1,
	});
	const auto secondTrace = context->nextTraceId({
		.runtimeId = secondRuntime,
		.ticketId = 1,
	});
	if (!firstTrace || secondTrace <= firstTrace) {
		return Fail("trace ids are not monotonic");
	}
	if (!context->finishTrace(firstTrace) || context->finishTrace(firstTrace)) {
		return Fail("trace finalization is not exactly once");
	}
	if (context->traceActive(firstTrace)
		|| !context->traceActive(secondTrace)) {
		return Fail("trace active state is inconsistent");
	}
	if (context->activeTracesForRuntime(secondRuntime).size() != 1) {
		return Fail("runtime trace ownership failed");
	}
	context->unregisterRuntime(secondRuntime);
	if (!context->activeTracesForRuntime(secondRuntime).empty()
		|| context->finishTrace(secondTrace)) {
		return Fail("runtime traces survived unregister");
	}
	return 0;
}

[[nodiscard]] int ScenarioRelayProofLifecycle() {
	auto state = MtProxy::EndpointState();
	const auto a = MtProxy::RelayProofIdentity{
		.runtimeId = kRuntimeA,
		.proxyGeneration = kGeneration,
		.attemptId = 168,
	};
	const auto b = MtProxy::RelayProofIdentity{
		.runtimeId = kRuntimeB,
		.proxyGeneration = kGeneration,
		.attemptId = 169,
	};
	const auto c = MtProxy::RelayProofIdentity{
		.runtimeId = kRuntimeC,
		.proxyGeneration = kGeneration,
		.attemptId = 170,
	};
	SeedAdmission(state, a, 100);
	SeedAdmission(state, b, 110);
	SeedAdmission(state, c, 120);
	const auto aPromotion = MtProxy::PromoteRelayProof(
		state,
		a,
		MtProxy::RelayProofState{
			.provenAt = 1000,
			.expiresAt = 10'000,
		});
	const auto bPromotion = MtProxy::PromoteRelayProof(
		state,
		b,
		MtProxy::RelayProofState{
			.provenAt = 1100,
			.expiresAt = 10'100,
		});
	const auto cPromotion = MtProxy::PromoteRelayProof(
		state,
		c,
		MtProxy::RelayProofState{
			.provenAt = 1200,
			.expiresAt = 10'200,
		});
	if (aPromotion != MtProxy::RelayProofPromotionResult::Inserted
		|| bPromotion != MtProxy::RelayProofPromotionResult::Inserted
		|| cPromotion != MtProxy::RelayProofPromotionResult::Inserted
		|| state.active != 0
		|| state.relayProofs.size() != 3
		|| !state.relayProven
		|| !state.healthy
		|| state.lastRelaySuccessAt != 1200) {
		return Fail("A/B/C relay proof promotion failed");
	}
	const auto originalA = state.relayProofs.at(a);
	const auto duplicate = MtProxy::PromoteRelayProof(
		state,
		a,
		MtProxy::RelayProofState{
			.provenAt = 1300,
			.expiresAt = 10'300,
		});
	if (duplicate != MtProxy::RelayProofPromotionResult::AlreadyProven
		|| state.relayProofs.size() != 3
		|| state.relayProofs.at(a).provenAt != originalA.provenAt
		|| state.relayProofs.at(a).expiresAt != originalA.expiresAt
		|| state.lastRelaySuccessAt != 1200) {
		return Fail("duplicate relay proof promotion was not idempotent");
	}
	const auto unowned = MtProxy::RelayProofIdentity{
		.runtimeId = kRuntimeA,
		.proxyGeneration = kGeneration,
		.attemptId = 171,
	};
	if (MtProxy::PromoteRelayProof(
			state,
			unowned,
			MtProxy::RelayProofState{
				.provenAt = 1400,
				.expiresAt = 10'400,
			}) != MtProxy::RelayProofPromotionResult::MissingAdmission
		|| state.relayProofs.size() != 3) {
		return Fail("unowned relay proof promotion was accepted");
	}
	const auto retiredA = MtProxy::RetireRelayProof(state, a);
	const auto duplicateRetirement = MtProxy::RetireRelayProof(state, a);
	const auto missingRetirement = MtProxy::RetireRelayProof(state, unowned);
	if (!retiredA
		|| duplicateRetirement
		|| missingRetirement
		|| state.relayProofs.size() != 2
		|| MtProxy::HasRelayProof(state, a)
		|| !MtProxy::HasRelayProof(state, b)
		|| !MtProxy::HasRelayProof(state, c)
		|| !state.relayProven
		|| !state.healthy
		|| state.lastRelaySuccessAt != 1200) {
		return Fail("exact A retirement did not preserve B/C aggregate");
	}
	return 0;
}

[[nodiscard]] int ScenarioCanonicalEndpointIsolation() {
	const auto context = MTP::CreateProxyEndpointContext();
	auto &storage = context->storage();
	auto &canonicalEndpoint = storage.states[QString::fromLatin1(
		"151.247.209.166.sslip.io:45632")];
	auto &otherCanonicalEndpoint = storage.states[QString::fromLatin1(
		"other.example:45632")];
	const auto equalTuple = MtProxy::RelayProofIdentity{
		.runtimeId = kRuntimeA,
		.proxyGeneration = kGeneration,
		.attemptId = 168,
	};
	SeedAdmission(canonicalEndpoint, equalTuple, 100);
	SeedAdmission(otherCanonicalEndpoint, equalTuple, 100);
	const auto firstPromotion = MtProxy::PromoteRelayProof(
		canonicalEndpoint,
		equalTuple,
		MtProxy::RelayProofState{
			.provenAt = 1000,
			.expiresAt = 10'000,
		});
	const auto otherPromotion = MtProxy::PromoteRelayProof(
		otherCanonicalEndpoint,
		equalTuple,
		MtProxy::RelayProofState{
			.provenAt = 1400,
			.expiresAt = 10'400,
		});
	if (firstPromotion != MtProxy::RelayProofPromotionResult::Inserted
		|| otherPromotion != MtProxy::RelayProofPromotionResult::Inserted
		|| !MtProxy::RetireRelayProof(canonicalEndpoint, equalTuple)
		|| canonicalEndpoint.relayProven
		|| canonicalEndpoint.lastRelaySuccessAt != 0
		|| !MtProxy::HasRelayProof(otherCanonicalEndpoint, equalTuple)
		|| !otherCanonicalEndpoint.relayProven
		|| !otherCanonicalEndpoint.healthy
		|| otherCanonicalEndpoint.lastRelaySuccessAt != 1400) {
		return Fail("canonical outer key isolation failed");
	}
	return 0;
}

[[nodiscard]] int ScenarioGenerationRejectionBeforeMembership() {
	auto state = MtProxy::EndpointState();
	state.generations[kRuntimeA] = 37;
	const auto oldGeneration = MtProxy::RelayProofIdentity{
		.runtimeId = kRuntimeA,
		.proxyGeneration = 36,
		.attemptId = 168,
	};
	const auto zeroGeneration = MtProxy::RelayProofIdentity{
		.runtimeId = kRuntimeA,
		.proxyGeneration = 0,
		.attemptId = 169,
	};
	const auto currentGeneration = MtProxy::RelayProofIdentity{
		.runtimeId = kRuntimeA,
		.proxyGeneration = 37,
		.attemptId = 170,
	};
	state.relayProofs.emplace(oldGeneration, MtProxy::RelayProofState{
		.provenAt = 1000,
		.expiresAt = 10'000,
	});
	state.relayProofs.emplace(zeroGeneration, MtProxy::RelayProofState{
		.provenAt = 1100,
		.expiresAt = 10'100,
	});
	state.relayProofs.emplace(currentGeneration, MtProxy::RelayProofState{
		.provenAt = 1200,
		.expiresAt = 10'200,
	});
	if (!state.relayProofs.contains(oldGeneration)
		|| !state.relayProofs.contains(zeroGeneration)
		|| GenerationValidatedRelayProofMembership(state, oldGeneration)
		|| GenerationValidatedRelayProofMembership(state, zeroGeneration)
		|| !GenerationValidatedRelayProofMembership(
			state,
			currentGeneration)) {
		return Fail("stale generation overrode proof membership rejection");
	}
	return 0;
}

[[nodiscard]] int ScenarioPerRuntimeGenerationPruning() {
	auto state = MtProxy::EndpointState();
	const auto a = MtProxy::RelayProofIdentity{
		.runtimeId = kRuntimeA,
		.proxyGeneration = kGeneration,
		.attemptId = 168,
	};
	const auto b = MtProxy::RelayProofIdentity{
		.runtimeId = kRuntimeB,
		.proxyGeneration = kGeneration,
		.attemptId = 169,
	};
	const auto pendingA = MtProxy::RelayProofIdentity{
		.runtimeId = kRuntimeA,
		.proxyGeneration = kGeneration,
		.attemptId = 170,
	};
	const auto pendingB = MtProxy::RelayProofIdentity{
		.runtimeId = kRuntimeB,
		.proxyGeneration = kGeneration,
		.attemptId = 171,
	};
	SeedAdmission(state, a, 100);
	SeedAdmission(state, b, 110);
	if (MtProxy::PromoteRelayProof(
			state,
			a,
			MtProxy::RelayProofState{
				.provenAt = 1000,
				.expiresAt = 10'000,
			}) != MtProxy::RelayProofPromotionResult::Inserted
		|| MtProxy::PromoteRelayProof(
			state,
			b,
			MtProxy::RelayProofState{
				.provenAt = 1100,
				.expiresAt = 10'100,
			}) != MtProxy::RelayProofPromotionResult::Inserted) {
		return Fail("generation pruning setup failed");
	}
	SeedAdmission(state, pendingA, 120);
	SeedAdmission(state, pendingB, 130);
	MtProxy::ApplyRuntimeProxyGeneration(state, kRuntimeA, 37);
	if (state.generations[kRuntimeA] != 37
		|| state.generations[kRuntimeB] != kGeneration
		|| MtProxy::HasRelayProof(state, a)
		|| !MtProxy::HasRelayProof(state, b)
		|| state.attemptStarts.contains(pendingA.attemptId)
		|| !state.attemptStarts.contains(pendingB.attemptId)
		|| state.active != 1
		|| !state.relayProven
		|| !state.healthy
		|| state.lastRelaySuccessAt != 1100) {
		return Fail("runtime generation isolation failed");
	}
	return 0;
}

[[nodiscard]] int ScenarioRuntimeUnregisterPruning() {
	const auto context = MTP::CreateProxyEndpointContext();
	const auto firstRuntime = context->registerRuntime();
	const auto secondRuntime = context->registerRuntime();
	auto &state = context->storage().states[QString::fromLatin1(
		"runtime-unregister")];
	const auto first = MtProxy::RelayProofIdentity{
		.runtimeId = firstRuntime,
		.proxyGeneration = kGeneration,
		.attemptId = 168,
	};
	const auto second = MtProxy::RelayProofIdentity{
		.runtimeId = secondRuntime,
		.proxyGeneration = kGeneration,
		.attemptId = 169,
	};
	const auto pendingFirst = MtProxy::RelayProofIdentity{
		.runtimeId = firstRuntime,
		.proxyGeneration = kGeneration,
		.attemptId = 170,
	};
	const auto pendingSecond = MtProxy::RelayProofIdentity{
		.runtimeId = secondRuntime,
		.proxyGeneration = kGeneration,
		.attemptId = 171,
	};
	SeedAdmission(state, first, 100);
	SeedAdmission(state, second, 110);
	if (MtProxy::PromoteRelayProof(
			state,
			first,
			MtProxy::RelayProofState{
				.provenAt = 1000,
				.expiresAt = 10'000,
			}) != MtProxy::RelayProofPromotionResult::Inserted
		|| MtProxy::PromoteRelayProof(
			state,
			second,
			MtProxy::RelayProofState{
				.provenAt = 1100,
				.expiresAt = 10'100,
			}) != MtProxy::RelayProofPromotionResult::Inserted) {
		return Fail("runtime unregister setup failed");
	}
	SeedAdmission(state, pendingFirst, 120);
	SeedAdmission(state, pendingSecond, 130);
	context->unregisterRuntime(firstRuntime);
	if (state.generations.contains(firstRuntime)
		|| state.generations[secondRuntime] != kGeneration
		|| MtProxy::HasRelayProof(state, first)
		|| !MtProxy::HasRelayProof(state, second)
		|| state.attemptStarts.contains(pendingFirst.attemptId)
		|| !state.attemptStarts.contains(pendingSecond.attemptId)
		|| state.active != 1
		|| !state.relayProven
		|| !state.healthy
		|| state.lastRelaySuccessAt != 1100) {
		return Fail("runtime proof slice survived unregister");
	}
	context->unregisterRuntime(firstRuntime);
	if (!MtProxy::HasRelayProof(state, second)
		|| state.lastRelaySuccessAt != 1100) {
		return Fail("duplicate runtime unregister changed sibling proof");
	}
	return 0;
}

[[nodiscard]] int ScenarioRelayProofExpiryAndBoundedness() {
	auto boundary = MtProxy::EndpointState();
	const auto identity = MtProxy::RelayProofIdentity{
		.runtimeId = kRuntimeA,
		.proxyGeneration = kGeneration,
		.attemptId = 168,
	};
	SeedAdmission(boundary, identity, 100);
	if (MtProxy::PromoteRelayProof(
			boundary,
			identity,
			MtProxy::RelayProofState{
				.provenAt = 1000,
				.expiresAt = 2000,
			}) != MtProxy::RelayProofPromotionResult::Inserted) {
		return Fail("relay proof expiry setup failed");
	}
	MtProxy::PruneExpiredRelayProofs(boundary, 1999);
	if (!MtProxy::HasRelayProof(boundary, identity)
		|| boundary.lastRelaySuccessAt != 1000) {
		return Fail("relay proof expired before boundary");
	}
	MtProxy::PruneExpiredRelayProofs(boundary, 2000);
	if (!boundary.relayProofs.empty()
		|| boundary.relayProven
		|| boundary.lastRelaySuccessAt != 0
		|| !boundary.healthy) {
		return Fail("relay proof survived inclusive expiry boundary");
	}

	auto repeated = MtProxy::EndpointState();
	constexpr auto count = uint64(128);
	for (auto index = uint64(0); index != count; ++index) {
		const auto current = MtProxy::RelayProofIdentity{
			.runtimeId = kRuntimeA,
			.proxyGeneration = kGeneration,
			.attemptId = 1000 + index,
		};
		SeedAdmission(repeated, current, 100 + crl::time(index));
		if (MtProxy::PromoteRelayProof(
				repeated,
				current,
				MtProxy::RelayProofState{
					.provenAt = 3000 + crl::time(index),
					.expiresAt = 4000 + crl::time(index),
				}) != MtProxy::RelayProofPromotionResult::Inserted) {
			return Fail("unique relay proof promotion failed");
		}
	}
	if (repeated.relayProofs.size() != count
		|| repeated.active != 0) {
		return Fail("unique relay proof registry size is inconsistent");
	}
	MtProxy::PruneExpiredRelayProofs(repeated, 4000 + crl::time(count - 1));
	if (!repeated.relayProofs.empty()
		|| repeated.relayProven
		|| repeated.lastRelaySuccessAt != 0
		|| repeated.active != 0) {
		return Fail("repeated unique expired records did not return to empty");
	}
	return 0;
}

} // namespace

int main(int, char *[]) {
	if (ScenarioTraceLifecycle()) {
		return 1;
	}
	if (ScenarioRelayProofLifecycle()) {
		return 1;
	}
	if (ScenarioCanonicalEndpointIsolation()) {
		return 1;
	}
	if (ScenarioGenerationRejectionBeforeMembership()) {
		return 1;
	}
	if (ScenarioPerRuntimeGenerationPruning()) {
		return 1;
	}
	if (ScenarioRuntimeUnregisterPruning()) {
		return 1;
	}
	if (ScenarioRelayProofExpiryAndBoundedness()) {
		return 1;
	}
	return 0;
}
