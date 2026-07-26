/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#pragma once

#include "mtproto/proxy/data.h"

namespace MTP::details {

enum class ClientHelloProfileValidation {
	Claimed,
	Validated,
};

struct ClientHelloProfileInfo {
	ProxyTlsProfile profile = ProxyTlsProfile::Auto;
	const char *id = "";
	ClientHelloProfileValidation validation
		= ClientHelloProfileValidation::Claimed;
	const char *captureSource = "";
	const char *captureVersion = "";
	const char *expectedJa4 = "";
	// A fingerprint measured to be refused by a network the client has to
	// work on. The template stays here - it is still a correct capture, and
	// the JA4 guard still checks it - but nothing sends it any more. See
	// kWithheldReason for what was measured.
	bool withheld = false;
	const char *withheldReason = "";
};

// Plain lookup: answers about the named profile, including a withheld one.
[[nodiscard]] const ClientHelloProfileInfo &ClientHelloProfile(
	ProxyTlsProfile profile);

// What to actually send for a configured value: resolves the two auto names
// and steers away from a withheld fingerprint, so a setting saved before the
// measurement does not keep a client on a template no relay ever answers.
[[nodiscard]] ProxyTlsProfile EffectiveClientHelloProfile(
	ProxyTlsProfile profile);

[[nodiscard]] ProxyTlsProfile DefaultClientHelloProfile();

[[nodiscard]] bool IsClientHelloProfileValidated(ProxyTlsProfile profile);

} // namespace MTP::details
