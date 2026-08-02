/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#pragma once

#include "mtproto/proxy/data.h"

namespace MTP {

class RuntimeEnvironment;

enum class WssDcCoverage {
	Unavailable,
	Official,
	Custom,
};

[[nodiscard]] bool ProxyWssAllowed(
	not_null<RuntimeEnvironment*> runtime,
	const ProxyData &proxy,
	ProxyData::Settings settings);
[[nodiscard]] bool ProxyWssAllowed(
	const ProxyData &proxy,
	ProxyData::Settings settings);

void NoteProxyWssRemoteClosed(
	not_null<RuntimeEnvironment*> runtime,
	const ProxyData &proxy);

[[nodiscard]] ProxyTransport EffectiveProxyTransport(
	const ProxyData &proxy,
	ProxyData::Settings settings,
	ProxyTransport saved);
[[nodiscard]] ProxyTransport EffectiveProxyTransport(
	not_null<RuntimeEnvironment*> runtime,
	const ProxyData &proxy,
	ProxyData::Settings settings,
	ProxyTransport saved);

[[nodiscard]] ProxyStealthOptions EffectiveProxyStealthOptions(
	const ProxyData &proxy,
	ProxyData::Settings settings,
	ProxyStealthOptions saved);
[[nodiscard]] ProxyStealthOptions EffectiveProxyStealthOptions(
	not_null<RuntimeEnvironment*> runtime,
	const ProxyData &proxy,
	ProxyData::Settings settings,
	ProxyStealthOptions saved);

[[nodiscard]] WssDcCoverage WssDcCoverageForDc(
	const ProxyStealthOptions &stealth,
	int16 protocolDcId);

[[nodiscard]] bool WssNeedsProxyRecommendation(
	const ProxyData &proxy,
	const ProxyStealthOptions &stealth,
	int16 protocolDcId);

} // namespace MTP
