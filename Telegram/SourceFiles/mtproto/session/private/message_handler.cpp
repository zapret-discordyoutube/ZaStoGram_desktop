/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "mtproto/session/private/session_private.h"

namespace MTP::details {

SessionMessageHandler::SessionMessageHandler(
	not_null<SessionPrivate*> owner)
: _owner(owner) {
}

} // namespace MTP::details
