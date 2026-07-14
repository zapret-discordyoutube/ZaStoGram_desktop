/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#pragma once

namespace MTP::details {

enum class SessionRole {
	PrimaryMain,
	Maintenance,
	Auxiliary,
};

} // namespace MTP::details
