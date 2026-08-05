/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "export/export_date_range.h"

#include <cstdio>

namespace {

[[nodiscard]] int Fail(const char *message) {
	std::fprintf(stderr, "%s\n", message);
	return 1;
}

} // namespace

int main(int, char *[]) {
	using Export::MessageDateRange;

	const auto unbounded = MessageDateRange();
	if (unbounded.hasLimits()
		|| !unbounded.valid()
		|| !unbounded.contains(1)) {
		return Fail("unbounded export range is not open");
	}

	const auto from = MessageDateRange{ .from = 100 };
	if (!from.hasFrom()
		|| from.hasTill()
		|| from.searchMinDate() != 99
		|| from.searchMaxDate() != 0
		|| from.contains(99)
		|| !from.contains(100)
		|| !from.contains(101)) {
		return Fail("export start boundary is not inclusive");
	}

	const auto till = MessageDateRange{ .till = 200 };
	if (till.hasFrom()
		|| !till.hasTill()
		|| till.searchMinDate() != 0
		|| till.searchMaxDate() != 200
		|| !till.contains(199)
		|| till.contains(200)) {
		return Fail("export end boundary is not exclusive");
	}

	const auto bounded = MessageDateRange{ .from = 100, .till = 200 };
	if (!bounded.hasLimits()
		|| !bounded.valid()
		|| bounded.searchMinDate() != 99
		|| bounded.searchMaxDate() != 200
		|| bounded.contains(99)
		|| !bounded.contains(100)
		|| !bounded.contains(199)
		|| bounded.contains(200)) {
		return Fail("bounded export range does not use [from, till)");
	}

	if (MessageDateRange{ .from = 200, .till = 200 }.valid()
		|| MessageDateRange{ .from = 201, .till = 200 }.valid()) {
		return Fail("invalid export range was accepted");
	}

	return 0;
}
