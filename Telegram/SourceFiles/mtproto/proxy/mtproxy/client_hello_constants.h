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

// The size of the fake TLS ClientHello every Telegram client sends. It is not
// a free choice: relays identify their own clients by this shape, and the
// length lands in the record header as 0x0200, which the common relay builds
// compare against literally.
constexpr auto kCanonicalClientHelloLength = 517;

// The relay reads the ClientHello into a buffer of this size and then refuses
// anything that did not fit, so a longer hello is never seen as a client's.
constexpr auto kMaxRelayClientHelloLength = 4096;

// Two bytes of extension id plus two of extension length.
constexpr auto kTlsExtensionHeaderLength = 2 * kTlsLengthFieldSize;
constexpr auto kClientHelloFragmentDelayMin = crl::time(2);
constexpr auto kClientHelloFragmentDelayMax = crl::time(7);

} // namespace MTP::details
