/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#pragma once

#include "mtproto/proxy/mtproxy/endpoint_health_state.h"

#include <optional>
#include <vector>

namespace MTP {
struct ProxyDiagnosticsEvent;
enum class ProxyDiagnosticsPhase;
enum class ProxyDiagnosticsTransition;
} // namespace MTP

namespace MTP::details::MtProxy {

struct CapacityProbeTerminalTransition {
	CapacityProbeState probe;
	int pressureFrontier = 0;
};

[[nodiscard]] ProxyDiagnosticsEvent CapacityDiagnosticsEvent(
	ProxyDiagnosticsPhase phase,
	ProxyDiagnosticsTransition transition,
	ProxyConnectionAttempt attempt,
	const EndpointState &state);
void MergeDeferredCleanup(
	EndpointDeferredCleanup &target,
	EndpointDeferredCleanup source);
[[nodiscard]] bool HasDeferredCleanup(
	const EndpointDeferredCleanup &cleanup);
void DisconnectDeferredOwners(EndpointDeferredCleanup &cleanup);
[[nodiscard]] std::optional<CapacityProbeState> ExactActiveCapacityProbe(
	const EndpointState &state,
	const RelayProofIdentity &identity);
[[nodiscard]] bool ExactReplacementBeneficiary(
	const EndpointState &state,
	const RelayProofIdentity &identity);
[[nodiscard]] bool AuthorizeExactProbeReplacement(
	EndpointState &state,
	const CapacityProbeTerminalTransition &transition,
	const RelayProofIdentity &identity);
[[nodiscard]] bool CommitExactReplacementProof(
	EndpointState &state,
	const RelayProofIdentity &identity);
[[nodiscard]] bool MarkExactReplacementRollback(
	EndpointState &state,
	const RelayProofIdentity &identity,
	EndpointDeferredCleanup &cleanup);
[[nodiscard]] bool CompleteCapacityProof(
	EndpointState &state,
	const RelayProofIdentity &identity,
	const std::optional<CapacityProbeState> &activeProbe,
	bool replacementProof,
	const SuccessReport &report,
	std::vector<ProxyDiagnosticsEvent> &diagnostics);
[[nodiscard]] auto BeginTypedCapacityProbeCooldown(
	EndpointState &state,
	const FailureReport &report,
	bool finalAttemptTerminal,
	crl::time now)
-> std::optional<CapacityProbeTerminalTransition>;
[[nodiscard]] bool ReleaseTypedCapacityProbe(
	EndpointLiveBudgetState &budget,
	const RelayProofIdentity &identity);
[[nodiscard]] bool ExpireTypedCapacityProbeCooldown(
	EndpointLiveBudgetState &budget,
	crl::time now);
[[nodiscard]] EndpointDeferredCleanup PruneExpiredEndpointStateDeferred(
	EndpointState &state,
	crl::time now);
void NoteCapacityPressure(
	EndpointLiveBudgetState &budget,
	int relayProofs,
	crl::time now);
void RaiseProvenEndpointCapacity(
	EndpointLiveBudgetState &budget,
	int relayProofCount);

} // namespace MTP::details::MtProxy
