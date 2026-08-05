/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#pragma once

#include "base/basic_types.h"

namespace Export {

// Message export uses a half-open interval: [from, till).
// A non-positive bound means that side of the interval is unbounded.
struct MessageDateRange {
	TimeId from = 0;
	TimeId till = 0;

	[[nodiscard]] bool hasFrom() const {
		return from > 0;
	}

	[[nodiscard]] bool hasTill() const {
		return till > 0;
	}

	[[nodiscard]] bool hasLimits() const {
		return hasFrom() || hasTill();
	}

	[[nodiscard]] bool valid() const {
		return !hasTill() || till > from;
	}

	// messages.search applies min_date strictly (date > min_date), while
	// this value object deliberately exposes an inclusive lower bound.
	[[nodiscard]] TimeId searchMinDate() const {
		return hasFrom() ? (from - 1) : 0;
	}

	[[nodiscard]] TimeId searchMaxDate() const {
		return hasTill() ? till : 0;
	}

	[[nodiscard]] bool contains(TimeId date) const {
		return (!hasFrom() || date >= from)
			&& (!hasTill() || date < till);
	}
};

} // namespace Export
