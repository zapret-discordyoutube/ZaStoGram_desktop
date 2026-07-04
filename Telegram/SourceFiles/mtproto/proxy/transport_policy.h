/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#pragma once

#include "mtproto/proxy/data.h"

namespace MTP {

enum class WssDcCoverage {
	Unavailable,
	Official,
	Custom,
};

[[nodiscard]] bool ProxyWssAllowed(
	const ProxyData &proxy,
	ProxyData::Settings settings);

[[nodiscard]] ProxyTransport EffectiveProxyTransport(
	const ProxyData &proxy,
	ProxyData::Settings settings,
	ProxyTransport saved);

[[nodiscard]] ProxyStealthOptions EffectiveProxyStealthOptions(
	const ProxyData &proxy,
	ProxyData::Settings settings,
	ProxyStealthOptions saved);

[[nodiscard]] WssDcCoverage WssDcCoverageForDc(
	const ProxyStealthOptions &stealth,
	int16 protocolDcId,
	bool protocolForFiles);

[[nodiscard]] bool WssNeedsProxyRecommendation(
	const ProxyData &proxy,
	const ProxyStealthOptions &stealth,
	int16 protocolDcId,
	bool protocolForFiles);

} // namespace MTP
