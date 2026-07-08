/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#pragma once

#include <crl/crl_time.h>

namespace MTP::details {

constexpr auto kAckSendWaiting = 10 * crl::time(1000);
constexpr auto kMinConnectedTimeout = crl::time(1000);
constexpr auto kMinReceiveTimeout = crl::time(4000);
constexpr auto kSentContainerLives = 600 * crl::time(1000);

} // namespace MTP::details
