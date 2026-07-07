/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "mtproto/pause_state.h"

#include <rpl/event_stream.h>

namespace MTP::details {
namespace {

int PauseLevel = 0;
rpl::event_stream<> Unpaused;

} // namespace

bool paused() {
	return PauseLevel > 0;
}

void pause() {
	++PauseLevel;
}

void unpause() {
	--PauseLevel;
	if (!PauseLevel) {
		Unpaused.fire({});
	}
}

rpl::producer<> unpaused() {
	return Unpaused.events();
}

} // namespace MTP::details
