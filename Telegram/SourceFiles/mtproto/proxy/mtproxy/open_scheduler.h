/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#pragma once

#include "mtproto/proxy/mtproxy/endpoint_health.h"

namespace MTP::details::MtProxy {

[[nodiscard]] crl::time OpenConnectionSpacing(ProxyConnectionPattern pattern);
[[nodiscard]] crl::time ReserveOpenSlot(
	const EndpointId &endpoint,
	ProxyConnectionPattern pattern,
	crl::time notBefore = 0);

} // namespace MTP::details::MtProxy
