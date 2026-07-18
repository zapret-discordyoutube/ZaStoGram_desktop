/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#pragma once

#include "base/basic_types.h"
#include "mtproto/runtime/proxy_data.h"

#include <optional>
#include <vector>

namespace MTP::details::MtProxy {

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

struct OpenSlotRecord {
	uint64 id = 0;
	crl::time openAt = 0;
	crl::time nextOpenAt = 0;

	bool operator==(const OpenSlotRecord &other) const = default;
};

struct OpenSlotSchedule {
	uint64 lastReservationId = 0;
	std::vector<OpenSlotRecord> recent;
	std::vector<OpenSlotRecord> pending;

	bool operator==(const OpenSlotSchedule &other) const = default;
};

struct OpenSlotReduction {
	OpenSlotSchedule schedule;
	std::optional<OpenSlotAssignment> assignment;
	bool applied = false;
};

struct OpenSlotReflowReduction {
	OpenSlotSchedule schedule;
	std::vector<OpenSlotAssignment> assignments;
	bool applied = false;
};

[[nodiscard]] OpenSlotReduction ReserveOpenSlot(
	const OpenSlotSchedule &schedule,
	const OpenSlotRequest &request);
[[nodiscard]] OpenSlotReduction CancelOpenSlot(
	const OpenSlotSchedule &schedule,
	uint64 id);
[[nodiscard]] OpenSlotReduction CommitOpenSlot(
	const OpenSlotSchedule &schedule,
	uint64 id);
[[nodiscard]] OpenSlotReflowReduction ReflowOpenSlots(
	const OpenSlotSchedule &schedule,
	const std::vector<OpenSlotReflowRequest> &ordered,
	crl::time now);

[[nodiscard]] crl::time OpenConnectionSpacing(ProxyConnectionPattern pattern);
[[nodiscard]] crl::time OpenConnectionJitter(int randomValue);

} // namespace MTP::details::MtProxy
