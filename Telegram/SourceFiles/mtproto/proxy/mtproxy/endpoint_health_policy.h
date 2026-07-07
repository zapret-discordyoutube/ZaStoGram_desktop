/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#pragma once

#include "mtproto/proxy/mtproxy/endpoint_health_state.h"

namespace MTP::details::MtProxy {

[[nodiscard]] bool FailureNeedsCooldown(FailureReason reason);
[[nodiscard]] bool FailureNeedsRecipeEscalation(FailureReason reason);
[[nodiscard]] bool FailureNeedsTlsRotation(FailureReason reason);
[[nodiscard]] bool FailureIsRouteOnly(FailureReason reason);
[[nodiscard]] bool RelayFailureInvalidatesCapability(FailureReason reason);
void DowngradeRecipeForRelayStall(
	EndpointState &state,
	FailureReason reason);
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
	uint64 proxyGeneration);
[[nodiscard]] bool FailureFromStaleAttempt(
	const FailureReport &report,
	const EndpointState &state);
[[nodiscard]] bool SuccessFromStaleAttempt(
	const SuccessReport &report,
	const EndpointState &state);
void PruneExpiredAttempts(EndpointState &state, crl::time now);
[[nodiscard]] crl::time CooldownFor(
	FailureReason reason,
	int consecutiveFailures);
[[nodiscard]] EndpointConcurrencyPolicy EndpointConcurrencyPolicyFor(
	const EndpointState &state,
	EndpointUse use,
	crl::time now);
[[nodiscard]] Snapshot MakeSnapshot(const EndpointState &state);

} // namespace MTP::details::MtProxy
