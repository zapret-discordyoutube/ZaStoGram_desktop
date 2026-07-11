/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#pragma once

#include "mtproto/proxy/mtproxy/endpoint_health_state.h"

namespace MTP::details::MtProxy {

// One row per FailureReason: every reaction the health machinery may have
// to a failure, in one place. The FailureNeeds*/FailureIs* helpers below
// are thin readers over this table.
struct FailureTraits {
	bool needsCooldown = false;
	bool escalatesRecipe = false;
	bool rotatesTls = false;
	bool routeOnly = false;
	bool invalidatesRelayCapability = false;
	bool canBeStale = false;
};

[[nodiscard]] FailureTraits TraitsFor(FailureReason reason);

[[nodiscard]] bool FailureNeedsCooldown(FailureReason reason);
[[nodiscard]] MtProxyAttemptPlan BuildAttemptPlan(
	const AdmissionRequest &request,
	int recipeLevel);
[[nodiscard]] bool FailureNeedsRecipeEscalation(FailureReason reason);
[[nodiscard]] bool FailureNeedsTlsRotation(FailureReason reason);
[[nodiscard]] bool FailureIsRouteOnly(FailureReason reason);
[[nodiscard]] bool RelayFailureInvalidatesCapability(FailureReason reason);
[[nodiscard]] bool SoftNoAppDataFailure(
	const EndpointState &state,
	FailureReason reason,
	crl::time now);
[[nodiscard]] crl::time NoAppDataSoftRetry();
[[nodiscard]] crl::time ThrottledRetryCooldown();
[[nodiscard]] bool NoAppDataWarningStrike(
	FailureReason reason,
	int consecutiveFailures);
void ApplyProxyGeneration(
	EndpointState &state,
	ProxyRuntimeId runtimeId,
	uint64 proxyGeneration);
[[nodiscard]] bool FailureFromStaleAttempt(
	const FailureReport &report,
	const EndpointState &state);
[[nodiscard]] bool SuccessFromStaleAttempt(
	const SuccessReport &report,
	const EndpointState &state);
void PruneExpiredEndpointState(EndpointState &state, crl::time now);
[[nodiscard]] crl::time CooldownFor(
	FailureReason reason,
	int consecutiveFailures);
[[nodiscard]] EndpointConcurrencyPolicy EndpointConcurrencyPolicyFor(
	const EndpointState &state,
	EndpointUse use,
	crl::time now,
	bool fastWarmup);
[[nodiscard]] Snapshot MakeSnapshot(
	const EndpointState &state,
	ProxyRuntimeId runtimeId);

} // namespace MTP::details::MtProxy
