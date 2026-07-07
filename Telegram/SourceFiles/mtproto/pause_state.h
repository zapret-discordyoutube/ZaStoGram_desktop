/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#pragma once

#include <rpl/producer.h>

namespace MTP::details {

[[nodiscard]] bool paused();
void pause();
void unpause();
[[nodiscard]] rpl::producer<> unpaused();

} // namespace MTP::details
