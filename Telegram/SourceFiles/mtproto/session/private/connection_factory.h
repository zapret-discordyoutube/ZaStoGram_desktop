/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#pragma once

#include "mtproto/transport/connection_abstract.h"

namespace MTP::details {

class SessionConnectionFactory {
public:
	virtual ~SessionConnectionFactory() = default;

	[[nodiscard]] virtual ConnectionPointer create(
		not_null<RuntimeEnvironment*> runtime,
		DcOptions::Variants::Protocol protocol,
		QThread *thread,
		const bytes::vector &secret,
		const ProxyData &proxy,
		const ProxyStealthOptions &stealth) = 0;
};

[[nodiscard]] SessionConnectionFactory &DefaultSessionConnectionFactory();

} // namespace MTP::details
