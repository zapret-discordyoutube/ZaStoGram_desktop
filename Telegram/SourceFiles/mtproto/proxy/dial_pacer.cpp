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

// Spacing between two dials to the same relay.
//
// This is the whole of the unconditional limit. There used to be a cap on
// unproven handshakes in flight as well, on the premise that a public
// mtproxy answers about two at a time and swallows the rest. Measured
// against live relays the premise does not hold: they took eight and then
// twenty-four simultaneous dials through to resPQ without a single miss. A
// relay that really does drop the overflow is still handled, by the failure
// spacing below, which acts on what happened rather than on a guess - and
// unlike a cap it costs nothing on the relays that never needed one.
//
// The spacing itself used to be 250ms, on the remaining premise that
// arriving as separate clients rather than as one burst is worth something
// against a filtered network. Two measurements retired that premise. What
// the network keys on was found and it is not the burst: it is the exact
// shape of the hello and the name in SNI, and a hello that matches neither
// is answered however it arrives. And the cost was measured on the other
// side - twenty-four unpaced dials reached resPQ in 170ms all told, where
// the same twenty-four cost about six seconds of queue at a quarter second
// apiece. A cold start pays that six seconds before the first message
// moves, which is what "the proxy is slow" looks like from the outside.
//
// So the spacing is kept, but only at the size that separates a burst from a
// single instant - enough that a relay logging connections sees distinct
// arrivals, small enough that a full ramp costs a second rather than six.
constexpr auto kDialSpacing = crl::time(50);

// Losing a handful at once is what a sleep, a network change or a DC switch
// looks like, and none of that is the relay's doing, so the spacing starts
// growing well after it.
constexpr auto kFailuresBeforeBackoff = 4;
constexpr auto kFailureSpacingStep = crl::time(500);

// Past this the session's own retry timer, which tops out around eight
// seconds, is the slower of the two and takes over as the throttle. Growing
// beyond it only delays the recovery of a relay that has come back.
constexpr auto kFailureSpacingMax = crl::time(4000);

// Without this a dead proxy would collect a dial per session per retry timer
// forever. It has to stay well under the point where a user reads the client
// as hung rather than as reconnecting.
constexpr auto kMaxQueueDelay = crl::time(30 * 1000);

// A proxy is not punished for a bad hour once it has been left alone.
constexpr auto kFailureMemory = crl::time(5 * 60 * 1000);

constexpr auto kMinDialJitter = crl::time(150);

// The jitter is drawn outside the lock, before the spacing it scales is
// known, so it is drawn as a fraction of it.
constexpr auto kJitterFractionBase = 1000;

struct DialState {
	// Live leases, kept only so a quiet relay's entry can be dropped.
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
		finish(Verdict::Failed);
		_key = std::exchange(other._key, QString());
		_delay = std::exchange(other._delay, crl::time(0));
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
	// This pacer protects MTProxy relays from bursts of independent TLS or
	// obfuscated handshakes. Other proxy kinds must not inherit its failure
	// memory or queue. A WEB proxy is a single shared browser transport: each
	// MTP connection here is only a cheap logical stream on that carrier, so
	// pacing those streams delays recovery and lets unrelated stream timeouts
	// poison the whole carrier.
	if (proxy.type != ProxyData::Type::Mtproto) {
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
	{
		QMutexLocker lock(&DialMutex());
		auto &state = DialStates()[key];
		if (state.failures
			&& (now - state.lastFailureAt >= kFailureMemory)) {
			state.failures = 0;
			state.lastFailureAt = 0;
		}
		const auto spacing = SpacingFor(state.failures);
		at = std::max(now, state.nextFreeAt);
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
		++state.inFlight;
	}
	return ProxyDialLease(std::move(key), at - now);
}

} // namespace MTP::details
