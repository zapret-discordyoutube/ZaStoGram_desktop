/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "mtproto/proxy/mtproxy/open_scheduler.h"

#include "base/algorithm.h"

#include <algorithm>

namespace MTP::details::MtProxy {
namespace {

constexpr auto kMinimumOpenSpacing = crl::time(500);
constexpr auto kMaximumOpenJitter = crl::time(125);

void PruneRecentOpens(OpenSlotSchedule &schedule, crl::time now) {
	const auto expired = std::remove_if(
		begin(schedule.recent),
		end(schedule.recent),
		[=](const OpenSlotRecord &entry) {
			return entry.nextOpenAt <= now;
		});
	schedule.recent.erase(expired, end(schedule.recent));
}

[[nodiscard]] crl::time RecentOpenBoundary(
		const OpenSlotSchedule &schedule) {
	auto result = crl::time();
	for (const auto &entry : schedule.recent) {
		accumulate_max(result, entry.nextOpenAt);
	}
	return result;
}

} // namespace

OpenSlotReduction ReserveOpenSlot(
		const OpenSlotSchedule &schedule,
		const OpenSlotRequest &request) {
	auto result = OpenSlotReduction{ .schedule = schedule };
	PruneRecentOpens(result.schedule, request.now);
	auto openAt = std::max(request.now, request.earliestOpenAt);
	accumulate_max(openAt, RecentOpenBoundary(result.schedule));
	for (const auto &entry : result.schedule.pending) {
		accumulate_max(openAt, entry.nextOpenAt);
	}
	const auto spacing = std::max(kMinimumOpenSpacing, request.spacing);
	const auto jitter = std::clamp(
		request.jitter,
		crl::time(),
		kMaximumOpenJitter);
	const auto nextOpenAt = openAt + spacing + jitter;
	const auto id = ++result.schedule.lastReservationId;
	result.schedule.pending.push_back({
		.id = id,
		.openAt = openAt,
		.nextOpenAt = nextOpenAt,
	});
	result.assignment = OpenSlotAssignment{
		.id = id,
		.openAt = openAt,
		.nextOpenAt = nextOpenAt,
		.delay = std::max(crl::time(), openAt - request.now),
	};
	result.applied = true;
	return result;
}

OpenSlotReduction CancelOpenSlot(
		const OpenSlotSchedule &schedule,
		uint64 id) {
	auto result = OpenSlotReduction{ .schedule = schedule };
	const auto i = std::find_if(
		begin(result.schedule.pending),
		end(result.schedule.pending),
		[=](const OpenSlotRecord &entry) {
			return entry.id == id;
		});
	if (i == end(result.schedule.pending)) {
		return result;
	}
	result.schedule.pending.erase(i);
	result.applied = true;
	return result;
}

OpenSlotReduction CommitOpenSlot(
		const OpenSlotSchedule &schedule,
		uint64 id) {
	auto result = OpenSlotReduction{ .schedule = schedule };
	const auto i = std::find_if(
		begin(result.schedule.pending),
		end(result.schedule.pending),
		[=](const OpenSlotRecord &entry) {
			return entry.id == id;
		});
	if (i == end(result.schedule.pending)) {
		return result;
	}
	const auto committed = *i;
	result.schedule.pending.erase(i);
	result.schedule.recent.push_back({
		.id = committed.id,
		.openAt = committed.openAt,
		.nextOpenAt = committed.nextOpenAt,
	});
	result.applied = true;
	return result;
}

OpenSlotReflowReduction ReflowOpenSlots(
		const OpenSlotSchedule &schedule,
		const std::vector<OpenSlotReflowRequest> &ordered,
		crl::time now) {
	auto result = OpenSlotReflowReduction{ .schedule = schedule };
	PruneRecentOpens(result.schedule, now);
	if (ordered.size() != result.schedule.pending.size()) {
		return result;
	}
	auto reflowed = std::vector<OpenSlotRecord>();
	result.assignments.reserve(ordered.size());
	auto boundary = RecentOpenBoundary(result.schedule);
	for (const auto &request : ordered) {
		if (!request.id) {
			return result;
		}
		const auto existing = std::find_if(
			begin(result.schedule.pending),
			end(result.schedule.pending),
			[&](const OpenSlotRecord &entry) {
				return entry.id == request.id;
			});
		const auto duplicate = std::find_if(
			begin(reflowed),
			end(reflowed),
			[&](const OpenSlotRecord &entry) {
				return entry.id == request.id;
			});
		if (existing == end(result.schedule.pending)
			|| duplicate != end(reflowed)) {
			return result;
		}
		auto openAt = std::max(now, request.earliestOpenAt);
		accumulate_max(openAt, boundary);
		const auto spacing = std::max(kMinimumOpenSpacing, request.spacing);
		const auto jitter = std::clamp(
			request.jitter,
			crl::time(),
			kMaximumOpenJitter);
		const auto nextOpenAt = openAt + spacing + jitter;
		reflowed.push_back({
			.id = request.id,
			.openAt = openAt,
			.nextOpenAt = nextOpenAt,
		});
		result.assignments.push_back({
			.id = request.id,
			.openAt = openAt,
			.nextOpenAt = nextOpenAt,
			.delay = std::max(crl::time(), openAt - now),
		});
		boundary = nextOpenAt;
	}
	result.schedule.pending = std::move(reflowed);
	result.applied = true;
	return result;
}

crl::time OpenConnectionSpacing(ProxyConnectionPattern pattern) {
	switch (pattern) {
	case ProxyConnectionPattern::Soft: return crl::time(1100);
	case ProxyConnectionPattern::Quiet: return crl::time(1200);
	case ProxyConnectionPattern::Strict: return crl::time(1400);
	case ProxyConnectionPattern::Browser: return crl::time(1150);
	case ProxyConnectionPattern::Off: return kMinimumOpenSpacing;
	}
	return kMinimumOpenSpacing;
}

crl::time OpenConnectionJitter(int randomValue) {
	return std::clamp(
		crl::time(randomValue),
		crl::time(),
		kMaximumOpenJitter);
}

} // namespace MTP::details::MtProxy
