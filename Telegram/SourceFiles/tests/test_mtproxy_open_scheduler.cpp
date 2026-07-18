/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "mtproto/proxy/mtproxy/open_scheduler.h"

#include <cstdio>
#include <vector>

namespace {

using namespace MTP::details::MtProxy;

[[nodiscard]] int Fail(const char *message) {
	std::fprintf(stderr, "%s\n", message);
	return 1;
}

} // namespace

int main(int, char *[]) {
	auto schedule = OpenSlotSchedule();
	const auto first = ReserveOpenSlot(schedule, {
		.now = crl::time(1000),
		.spacing = OpenConnectionSpacing(
			MTP::ProxyConnectionPattern::Soft),
		.jitter = OpenConnectionJitter(7),
	});
	if (!first.applied
		|| !first.assignment
		|| first.assignment->delay != 0
		|| first.assignment->nextOpenAt != crl::time(2107)) {
		return Fail("first open should start immediately");
	}
	const auto committed = CommitOpenSlot(
		first.schedule,
		first.assignment->id);
	if (!committed.applied
		|| !committed.schedule.pending.empty()
		|| committed.schedule.recent.size() != 1) {
		return Fail("commit should move the opening into recent history");
	}
	const auto second = ReserveOpenSlot(committed.schedule, {
		.now = crl::time(1000),
		.spacing = OpenConnectionSpacing(
			MTP::ProxyConnectionPattern::Soft),
		.jitter = OpenConnectionJitter(7),
	});
	if (!second.assignment
		|| second.assignment->delay != crl::time(1107)) {
		return Fail("second open should use fake time and fake jitter");
	}
	const auto cancelled = CancelOpenSlot(
		second.schedule,
		second.assignment->id);
	if (!cancelled.applied || !cancelled.schedule.pending.empty()) {
		return Fail("cancel should retire only the pending reservation");
	}
	const auto pendingA = ReserveOpenSlot(cancelled.schedule, {
		.now = crl::time(1000),
		.spacing = crl::time(500),
	});
	const auto pendingB = ReserveOpenSlot(pendingA.schedule, {
		.now = crl::time(1000),
		.spacing = crl::time(500),
	});
	const auto reflow = ReflowOpenSlots(
		pendingB.schedule,
		{
			{
				.id = pendingB.assignment->id,
				.earliestOpenAt = crl::time(2500),
				.spacing = crl::time(500),
			},
			{
				.id = pendingA.assignment->id,
				.earliestOpenAt = crl::time(1000),
				.spacing = crl::time(500),
			},
		},
		crl::time(1000));
	if (!reflow.applied
		|| reflow.assignments.size() != 2
		|| reflow.assignments[0].openAt != crl::time(2500)
		|| reflow.assignments[1].openAt != crl::time(3000)) {
		return Fail("reflow should follow the supplied fairness order");
	}
	return 0;
}
