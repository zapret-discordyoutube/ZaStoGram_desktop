/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#pragma once

#include "mtproto/proxy/data.h"

#include <crl/crl_time.h>

namespace MTP {

class RuntimeEnvironment;

namespace details {

class HandshakeGateLease final {
public:
	HandshakeGateLease() = default;
	HandshakeGateLease(const HandshakeGateLease &other) = delete;
	HandshakeGateLease &operator=(const HandshakeGateLease &other) = delete;
	HandshakeGateLease(HandshakeGateLease &&other) noexcept;
	HandshakeGateLease &operator=(HandshakeGateLease &&other) noexcept;
	~HandshakeGateLease();

	[[nodiscard]] crl::time delay() const;
	void release();

private:
	friend HandshakeGateLease ReserveHandshakeGate(
		not_null<RuntimeEnvironment*> runtime);

	explicit HandshakeGateLease(crl::time delay);

	crl::time _delay = 0;
	bool _active = false;

};

[[nodiscard]] HandshakeGateLease ReserveHandshakeGate(
	not_null<RuntimeEnvironment*> runtime);
[[nodiscard]] HandshakeGateLease ReserveHandshakeGateForProxy(
	not_null<RuntimeEnvironment*> runtime,
	const ProxyData &proxy);

} // namespace details
} // namespace MTP
