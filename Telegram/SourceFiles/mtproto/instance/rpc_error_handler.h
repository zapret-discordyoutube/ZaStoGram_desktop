/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#pragma once

#include "mtproto/protocol/mtproto_response.h"
#include "mtproto/dc_id.h"

namespace MTP::details {

struct DefaultRpcErrorRetry {
	enum class Delay {
		Backoff,
		Exact,
		NonPremium,
	};

	Delay delay = Delay::Backoff;
	int seconds = 0;
};

struct DefaultRpcErrorAction {
	enum class Type {
		None,
		Migrate,
		MsgWait,
		Retry,
		Unauthorized,
		ConnectionInit,
		ResetLanguage,
		Frozen,
		ClearBadGuestDc,
	};

	Type type = Type::None;
	DcId migrateDcId = 0;
	DefaultRpcErrorRetry retry;
	bool badGuestDc = false;
};

[[nodiscard]] DefaultRpcErrorAction ClassifyDefaultRpcError(
	const Error &error,
	bool badGuestDcAlreadyRetried);

} // namespace MTP::details
