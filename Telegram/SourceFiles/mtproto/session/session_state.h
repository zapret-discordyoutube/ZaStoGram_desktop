/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#pragma once

namespace MTP {

enum {
	DisconnectedState = 0,
	ConnectingState = 1,
	ConnectedState = 2,
};

enum {
	RequestSent = 0,
	RequestConnecting = 1,
	RequestSending = 2
};

} // namespace MTP
