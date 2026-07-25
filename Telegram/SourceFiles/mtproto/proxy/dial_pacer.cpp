/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "mtproto/proxy/dial_pacer.h"

#include "mtproto/proxy/diagnostics.h"
#include "mtproto/runtime/runtime_environment.h"

#include <QtCore/QMutex>

#include <algorithm>
#include <map>
#include <utility>

namespace MTP::details {
namespace {

// Measured against public mtproxies: two parallel handshakes are answered,
// everything above that is accepted on TCP and then never replied to.
constexpr auto kDialsInFlight = 2;

// Spacing between two dials that do not fit into the in-flight budget. A
// full fake-TLS handshake needs about a second, so a quarter of that keeps
// the ramp short while still looking like separate clients to the proxy.
constexpr auto kDialSpacing = crl::time(250);

// A couple of misses can happen to a healthy proxy (a stale route, a
// migrating DC), so the spacing only starts growing after them.
constexpr auto kFailuresBeforeBackoff = 2;
constexpr auto kFailureSpacingStep = crl::time(2000);
constexpr auto kFailureSpacingMax = crl::time(30 * 1000);

// Each session redials on its own retry timer, which tops out around eight
// seconds; without this a dead proxy would collect a dial per session per
// eight seconds forever.
constexpr auto kMaxQueueDelay = crl::time(120 * 1000);

// The in-flight overflow component stays small: it only exists to survive a
// lease that was never released because its owner died oddly.
constexpr auto kMaxInFlightDelay = crl::time(8000);

// A proxy is not punished for a bad hour once it has been left alone.
constexpr auto kFailureMemory = crl::time(5 * 60 * 1000);

constexpr auto kMinDialJitter = crl::time(150);

struct DialState {
	int inFlight = 0;
	int failures = 0;
	crl::time nextFreeAt = 0;
	crl::time lastFailureAt = 0;
};

[[nodiscard]] QMutex &DialMutex() {
	static auto result = QMutex();
	return result;
}

[[nodiscard]] std::map<QString, DialState> &DialStates() {
	static auto result = std::map<QString, DialState>();
	return result;
}

[[nodiscard]] crl::time SpacingFor(int failures) {
	if (failures < kFailuresBeforeBackoff) {
		return kDialSpacing;
	}
	const auto over = failures - kFailuresBeforeBackoff + 1;
	return std::min(kFailureSpacingMax, over * kFailureSpacingStep);
}

[[nodiscard]] bool Forgettable(const DialState &state, crl::time now) {
	return !state.inFlight
		&& state.nextFreeAt <= now
		&& (!state.failures
			|| (now - state.lastFailureAt >= kFailureMemory));
}

} // namespace

ProxyDialLease::ProxyDialLease(QString key, crl::time delay)
: _key(std::move(key))
, _delay(delay) {
}

ProxyDialLease::ProxyDialLease(ProxyDialLease &&other) noexcept
: _key(std::exchange(other._key, QString()))
, _delay(std::exchange(other._delay, crl::time(0))) {
}

ProxyDialLease &ProxyDialLease::operator=(ProxyDialLease &&other) noexcept {
	if (this != &other) {
		release();
		_key = std::exchange(other._key, QString());
		_delay = std::exchange(other._delay, crl::time(0));
	}
	return *this;
}

ProxyDialLease::~ProxyDialLease() {
	release();
}

crl::time ProxyDialLease::delay() const {
	return _delay;
}

void ProxyDialLease::proven() {
	finish(true);
}

void ProxyDialLease::release() {
	finish(false);
}

void ProxyDialLease::finish(bool proven) {
	const auto key = std::exchange(_key, QString());
	if (key.isEmpty()) {
		return;
	}
	_delay = 0;

	const auto now = crl::now();
	QMutexLocker lock(&DialMutex());
	auto &states = DialStates();
	const auto i = states.find(key);
	if (i == end(states)) {
		return;
	}
	auto &state = i->second;
	if (state.inFlight > 0) {
		--state.inFlight;
	}
	if (proven) {
		state.failures = 0;
		state.lastFailureAt = 0;
		state.nextFreeAt = std::min(state.nextFreeAt, now + kDialSpacing);
	} else {
		++state.failures;
		state.lastFailureAt = now;
	}
	if (Forgettable(state, now)) {
		states.erase(i);
	}
}

ProxyDialLease ReserveProxyDial(
		not_null<RuntimeEnvironment*> runtime,
		const ProxyData &proxy) {
	if (proxy.type == ProxyData::Type::None) {
		return ProxyDialLease();
	}
	auto key = ProxyDiagnosticsProxyKeyHash(proxy);
	if (key.isEmpty()) {
		return ProxyDialLease();
	}
	const auto now = runtime->async().now();
	auto at = now;
	auto spacing = kDialSpacing;
	{
		QMutexLocker lock(&DialMutex());
		auto &state = DialStates()[key];
		if (state.failures
			&& (now - state.lastFailureAt >= kFailureMemory)) {
			state.failures = 0;
			state.lastFailureAt = 0;
		}
		spacing = SpacingFor(state.failures);
		at = std::max(now, state.nextFreeAt);
		if (state.inFlight >= kDialsInFlight) {
			const auto over = state.inFlight - kDialsInFlight + 1;
			at = std::max(at, now + std::min(
				kMaxInFlightDelay,
				over * kDialSpacing));
		}
		at = std::min(at, now + kMaxQueueDelay);
		state.nextFreeAt = at + spacing;
		++state.inFlight;
	}
	auto delay = at - now;
	if (delay > 0) {
		// Sessions lose their connect budget together and re-reserve in the
		// same millisecond, so the tail of a queue deeper than kMaxQueueDelay
		// is handed the same clamped slot over and over. A fixed jitter is
		// too small to separate those once the spacing has grown, and they
		// reach the proxy as the burst this exists to prevent. Half a spacing
		// keeps the queued order (two neighbours stay at least half a spacing
		// apart) while spreading everything that shares a slot.
		const auto jitter = std::max(kMinDialJitter, spacing / 2);
		delay += runtime->async().randomIndex(int(jitter) + 1);
	}
	return ProxyDialLease(std::move(key), delay);
}

} // namespace MTP::details
