/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#pragma once

#include "mtproto/proxy/mtproxy/endpoint_health_state.h"

#include <optional>

namespace MTP::details::MtProxy {

[[nodiscard]] std::optional<int> BeginStableCapacityProbeCooldown(
	EndpointState &state,
	const FailureReport &report,
	crl::time now);
void NoteCapacityPressure(
	EndpointLiveBudgetState &budget,
	int relayProofs,
	crl::time now);
void RaiseProvenEndpointCapacity(
	EndpointLiveBudgetState &budget,
	int relayProofCount);

} // namespace MTP::details::MtProxy
