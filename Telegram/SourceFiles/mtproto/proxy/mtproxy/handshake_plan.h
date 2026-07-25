/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#pragma once

#include "mtproto/runtime/connection_status_types.h"

namespace MTP::details::MtProxy {

// One fixed FakeTLS handshake shape per configured profile.
//
// The client deliberately does not mutate its own ClientHello in response to
// failures. A fingerprint filter (JA3/JA4) is deterministic: rotating through
// emulated profiles only hands the other side more fingerprints to catalogue,
// while escalated "recipes" - ClientHello fragmentation, connection pacing -
// make the flow less browser-like rather than more. On top of that the signal
// such escalation used to key off, "ClientHello sent, no ServerHello", is
// indistinguishable from a proxy that is simply refusing extra connections.
// So the profile is whatever the user configured, and it stays that way.
[[nodiscard]] MtProxyAttemptPlan MakeAttemptPlan(
	const ProxyStealthOptions &stealth);

[[nodiscard]] crl::time ConnectionSpacing(ProxyConnectionPattern pattern);

} // namespace MTP::details::MtProxy
