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
#include <vector>

namespace MTP::details {
namespace {

// Measured against public mtproxies: two parallel handshakes are answered,
// everything above that is accepted on TCP and then never replied to.
constexpr auto kDialsInFlight = 2;

// Spacing between two dials that do fit into the in-flight budget. A full
// fake-TLS handshake needs about a second, so a quarter of that keeps the
// ramp short while still looking like separate clients to the proxy.
constexpr auto kDialSpacing = crl::time(250);

// How long an unproven dial is assumed to occupy a slot at the proxy. The
// slot is normally handed back the moment Telegram answers through the
// socket, which on a healthy relay happens in about a second; this is only
// the fallback for an attempt that never gets there, and it matches the
// deadline the fake TLS handshake itself runs on. It doubles as the leak
// guard: an attempt older than this stops being counted whatever happened
// to its lease.
constexpr auto kDialHandshakeBudget = crl::time(5000);

// A couple of misses can happen to a healthy proxy (a stale route, a
// migrating DC), so the spacing only starts growing after them.
constexpr auto kFailuresBeforeBackoff = 2;
constexpr auto kFailureSpacingStep = crl::time(2000);
constexpr auto kFailureSpacingMax = crl::time(30 * 1000);

// Each session redials on its own retry timer, which tops out around eight
// seconds; without this a dead proxy would collect a dial per session per
// eight seconds forever.
constexpr auto kMaxQueueDelay = crl::time(120 * 1000);

// A proxy is not punished for a bad hour once it has been left alone.
constexpr auto kFailureMemory = crl::time(5 * 60 * 1000);

constexpr auto kMinDialJitter = crl::time(150);

// The jitter is drawn outside the lock, before the spacing it scales is
// known, so it is drawn as a fraction of it.
constexpr auto kJitterFractionBase = 1000;

struct DialState {
	// When each unproven dial is expected to release its slot, ascending.
	std::vector<crl::time> inFlightUntil;
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
	return state.inFlightUntil.empty()
		&& state.nextFreeAt <= now
		&& (!state.failures
			|| (now - state.lastFailureAt >= kFailureMemory));
}

} // namespace

ProxyDialLease::ProxyDialLease(QString key, crl::time delay, crl::time until)
: _key(std::move(key))
, _delay(delay)
, _until(until) {
}

ProxyDialLease::ProxyDialLease(ProxyDialLease &&other) noexcept
: _key(std::exchange(other._key, QString()))
, _delay(std::exchange(other._delay, crl::time(0)))
, _until(std::exchange(other._until, crl::time(0))) {
}

ProxyDialLease &ProxyDialLease::operator=(ProxyDialLease &&other) noexcept {
	if (this != &other) {
		finish(Verdict::Failed);
		_key = std::exchange(other._key, QString());
		_delay = std::exchange(other._delay, crl::time(0));
		_until = std::exchange(other._until, crl::time(0));
	}
	return *this;
}

ProxyDialLease::~ProxyDialLease() {
	finish(Verdict::Failed);
}

crl::time ProxyDialLease::delay() const {
	return _delay;
}

void ProxyDialLease::proven() {
	finish(Verdict::Proven);
}

void ProxyDialLease::release() {
	finish(Verdict::Failed);
}

void ProxyDialLease::cancel() {
	finish(Verdict::Cancelled);
}

void ProxyDialLease::finish(Verdict verdict) {
	const auto key = std::exchange(_key, QString());
	if (key.isEmpty()) {
		return;
	}
	const auto until = std::exchange(_until, crl::time(0));
	_delay = 0;

	const auto now = crl::now();
	QMutexLocker lock(&DialMutex());
	auto &states = DialStates();
	const auto i = states.find(key);
	if (i == end(states)) {
		return;
	}
	auto &state = i->second;
	auto &inFlight = state.inFlightUntil;
	const auto j = std::lower_bound(begin(inFlight), end(inFlight), until);
	if (j != end(inFlight) && *j == until) {
		inFlight.erase(j);
	}
	if (verdict == Verdict::Proven) {
		state.failures = 0;
		state.lastFailureAt = 0;
		state.nextFreeAt = std::min(state.nextFreeAt, now + kDialSpacing);
	} else if (verdict == Verdict::Failed) {
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
	const auto jitterFraction = runtime->async().randomIndex(
		kJitterFractionBase);
	auto at = now;
	auto until = crl::time(0);
	{
		QMutexLocker lock(&DialMutex());
		auto &state = DialStates()[key];
		if (state.failures
			&& (now - state.lastFailureAt >= kFailureMemory)) {
			state.failures = 0;
			state.lastFailureAt = 0;
		}
		auto &inFlight = state.inFlightUntil;
		inFlight.erase(
			begin(inFlight),
			std::upper_bound(begin(inFlight), end(inFlight), now));
		const auto spacing = SpacingFor(state.failures);
		at = std::max(now, state.nextFreeAt);
		if (int(inFlight.size()) >= kDialsInFlight) {
			// The proxy answers kDialsInFlight handshakes at a time and
			// swallows the rest, so a dial that would be one too many waits
			// for a slot instead of being sent into the void. Slots come back
			// as soon as Telegram answers through them, so a batch of
			// sessions becomes a ramp of successes and not a wave of
			// handshakes that time out together.
			at = std::max(
				at,
				inFlight[int(inFlight.size()) - kDialsInFlight]);
		}
		at = std::min(at, now + kMaxQueueDelay);
		if (at > now) {
			// Sessions lose their connect budget together and re-reserve in
			// the same millisecond, so the tail of a queue deeper than
			// kMaxQueueDelay is handed the same clamped slot over and over.
			// A fixed jitter is too small to separate those once the spacing
			// has grown, and they reach the proxy as the burst this exists to
			// prevent. Half a spacing keeps the queued order (two neighbours
			// stay at least half a spacing apart) while spreading everything
			// that shares a slot.
			const auto jitter = std::max(kMinDialJitter, spacing / 2);
			at += (jitter * jitterFraction) / kJitterFractionBase;
		}
		state.nextFreeAt = at + spacing;
		until = at + kDialHandshakeBudget;
		inFlight.insert(
			std::upper_bound(begin(inFlight), end(inFlight), until),
			until);
	}
	return ProxyDialLease(std::move(key), at - now, until);
}

} // namespace MTP::details
