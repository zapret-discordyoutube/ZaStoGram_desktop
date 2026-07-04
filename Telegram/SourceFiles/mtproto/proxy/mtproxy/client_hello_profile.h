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
};

[[nodiscard]] const ClientHelloProfileInfo &ClientHelloProfile(
	ProxyTlsProfile profile);

[[nodiscard]] ProxyTlsProfile DefaultClientHelloProfile();

[[nodiscard]] bool IsClientHelloProfileValidated(ProxyTlsProfile profile);

} // namespace MTP::details
