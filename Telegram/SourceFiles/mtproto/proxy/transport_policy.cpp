/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "mtproto/proxy/transport_policy.h"

namespace MTP {

bool ProxyWssAllowed(
		const ProxyData &proxy,
		ProxyData::Settings settings) {
	return settings != ProxyData::Settings::Enabled
		|| proxy.type != ProxyData::Type::Mtproto;
}

ProxyTransport EffectiveProxyTransport(
		const ProxyData &proxy,
		ProxyData::Settings settings,
		ProxyTransport saved) {
	return ProxyWssAllowed(proxy, settings)
		? saved
		: ProxyTransport::Tcp;
}

ProxyStealthOptions EffectiveProxyStealthOptions(
		const ProxyData &proxy,
		ProxyData::Settings settings,
		ProxyStealthOptions saved) {
	auto result = saved;
	result.transport = EffectiveProxyTransport(
		proxy,
		settings,
		result.transport);
	return result;
}

} // namespace MTP
