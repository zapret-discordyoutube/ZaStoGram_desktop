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
	friend HandshakeGateLease ReserveHandshakeGate();

	explicit HandshakeGateLease(crl::time delay);

	crl::time _delay = 0;
	bool _active = false;

};

[[nodiscard]] HandshakeGateLease ReserveHandshakeGate();
[[nodiscard]] HandshakeGateLease ReserveHandshakeGateForProxy(
	const ProxyData &proxy);

} // namespace details
} // namespace MTP
