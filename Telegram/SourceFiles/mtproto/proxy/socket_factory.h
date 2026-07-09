/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#pragma once

#include "mtproto/transport/details/mtproto_abstract_socket.h"

namespace MTP::details {

[[nodiscard]] std::unique_ptr<AbstractSocket> CreateProxyAwareSocket(
	not_null<RuntimeEnvironment*> runtime,
	not_null<QThread*> thread,
	const bytes::vector &secret,
	const ProxyData &proxy,
	bool protocolForFiles,
	const ProxyStealthOptions &stealth,
	int16 protocolDcId = 0,
	ProxyConnectionAttempt mtproxyAttempt = {},
	MtProxyAttemptPlan mtproxyPlan = {},
	crl::time mtproxyAttemptStartedAt = 0);

} // namespace MTP::details
