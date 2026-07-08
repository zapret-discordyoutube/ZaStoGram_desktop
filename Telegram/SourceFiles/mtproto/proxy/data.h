/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#pragma once

#include "mtproto/runtime/proxy_data.h"

#include <QtNetwork/QNetworkProxy>

namespace MTP {

[[nodiscard]] ProxyData ToDirectIpProxy(
	const ProxyData &proxy,
	int ipIndex = 0);
[[nodiscard]] QNetworkProxy ToNetworkProxy(const ProxyData &proxy);
[[nodiscard]] ProxyStealthOptions CompatStrictProxyStealthOptions(
	ProxyStealthOptions result);
[[nodiscard]] ProxyStealthOptions ApplyProxyStealthLevel(
	ProxyStealthOptions result,
	ProxyStealthLevel level);

} // namespace MTP
