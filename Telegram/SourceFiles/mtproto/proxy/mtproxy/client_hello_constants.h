/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#pragma once

#include "base/basic_types.h"

#include <crl/crl_time.h>

namespace MTP::details {

constexpr auto kClientHelloGreaseCount = 8;
constexpr auto kClientHelloLimit = 4096;
constexpr auto kClientHelloDigestLength = 32;
constexpr auto kTlsLengthFieldSize = sizeof(uint16);
constexpr auto kClientHelloFragmentDelayMin = crl::time(2);
constexpr auto kClientHelloFragmentDelayMax = crl::time(7);

} // namespace MTP::details
