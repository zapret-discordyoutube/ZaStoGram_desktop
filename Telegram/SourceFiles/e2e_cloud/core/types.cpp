/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "e2e_cloud/core/types.h"

namespace E2ECloud {

bool IsValidHistoryAccess(const HistoryAccess &access) {
	switch (access.mode) {
	case HistoryAccessMode::None:
	case HistoryAccessMode::FromJoin:
	case HistoryAccessMode::Full:
		return !access.boundaryEventId;
	case HistoryAccessMode::Since:
		return bool(access.boundaryEventId);
	}
	return false;
}

} // namespace E2ECloud
