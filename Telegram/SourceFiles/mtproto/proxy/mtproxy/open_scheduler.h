/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#pragma once

#include "mtproto/proxy/mtproxy/endpoint_health.h"

#include <vector>

namespace MTP::details::MtProxy {

struct OpenState;

struct OpenSlotRequest {
	crl::time now = 0;
	crl::time earliestOpenAt = 0;
	crl::time spacing = 0;
	crl::time jitter = 0;
};

struct OpenSlotAssignment {
	uint64 id = 0;
	crl::time openAt = 0;
	crl::time nextOpenAt = 0;
	crl::time delay = 0;

	bool operator==(const OpenSlotAssignment &other) const = default;
};

struct OpenSlotReflowRequest {
	uint64 id = 0;
	crl::time earliestOpenAt = 0;
	crl::time spacing = 0;
	crl::time jitter = 0;
};

[[nodiscard]] OpenSlotAssignment ReserveOpenSlotLocked(
	OpenState &state,
	const OpenSlotRequest &request);
[[nodiscard]] bool CancelOpenSlotLocked(OpenState &state, uint64 id);
[[nodiscard]] bool CommitOpenSlotLocked(OpenState &state, uint64 id);
[[nodiscard]] std::vector<OpenSlotAssignment> ReflowOpenSlotsLocked(
	OpenState &state,
	const std::vector<OpenSlotReflowRequest> &ordered,
	crl::time now);

[[nodiscard]] crl::time OpenConnectionSpacing(ProxyConnectionPattern pattern);

// Failure-driven pacing feedback, independent of the stealth pattern:
// connect timeouts grow a per-endpoint spacing floor for new opens,
// successes shrink it back to zero. A proxy that throttles bursts of
// new connections gets approached gently instead of hammered by every
// reconnecting session at once.
void NoteConnectTimeout(
	not_null<RuntimeEnvironment*> runtime,
	const EndpointId &endpoint);
void NoteConnectSuccess(
	not_null<RuntimeEnvironment*> runtime,
	const EndpointId &endpoint);

} // namespace MTP::details::MtProxy
