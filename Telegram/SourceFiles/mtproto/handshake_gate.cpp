/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "mtproto/handshake_gate.h"

#include "base/random.h"

#include <algorithm>
#include <atomic>
#include <utility>

namespace MTP {
namespace details {
namespace {

constexpr auto kHandshakeGateCap = 3;
constexpr auto kHandshakeGateStep = crl::time(200);
constexpr auto kHandshakeGateMaxDelay = crl::time(2000);
constexpr auto kHandshakeGateJitterLimit = crl::time(100);

std::atomic<int> ActiveHandshakeGateLeases = 0;

[[nodiscard]] crl::time ComputeDelay(int active) {
	const auto over = std::max(0, active - kHandshakeGateCap);
	if (!over) {
		return 0;
	}
	const auto jitter = crl::time(base::RandomIndex(
		int(kHandshakeGateJitterLimit) + 1));
	return std::min(
		kHandshakeGateMaxDelay,
		over * kHandshakeGateStep + jitter);
}

} // namespace

HandshakeGateLease::HandshakeGateLease(crl::time delay)
: _delay(delay)
, _active(true) {
}

HandshakeGateLease::HandshakeGateLease(
		HandshakeGateLease &&other) noexcept
: _delay(std::exchange(other._delay, crl::time(0)))
, _active(std::exchange(other._active, false)) {
}

HandshakeGateLease &HandshakeGateLease::operator=(
		HandshakeGateLease &&other) noexcept {
	if (this != &other) {
		release();
		_delay = std::exchange(other._delay, crl::time(0));
		_active = std::exchange(other._active, false);
	}
	return *this;
}

HandshakeGateLease::~HandshakeGateLease() {
	release();
}

crl::time HandshakeGateLease::delay() const {
	return _delay;
}

void HandshakeGateLease::release() {
	if (!_active) {
		return;
	}
	auto active = ActiveHandshakeGateLeases.load(std::memory_order_relaxed);
	while (active > 0) {
		if (ActiveHandshakeGateLeases.compare_exchange_weak(
				active,
				active - 1,
				std::memory_order_relaxed)) {
			_active = false;
			return;
		}
	}
	_active = false;
}

HandshakeGateLease ReserveHandshakeGate() {
	const auto active = ActiveHandshakeGateLeases.fetch_add(
		1, std::memory_order_relaxed) + 1;
	return HandshakeGateLease(ComputeDelay(active));
}

} // namespace details
} // namespace MTP
