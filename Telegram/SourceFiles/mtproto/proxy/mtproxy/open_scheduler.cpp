/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "mtproto/proxy/mtproxy/open_scheduler.h"

#include "base/algorithm.h"
#include "mtproto/proxy/proxy_endpoint_context.h"
#include "mtproto/proxy/proxy_endpoint_context_p.h"

#include <QtCore/QMutex>

#include <algorithm>
#include <vector>

namespace MTP::details::MtProxy {
namespace {

constexpr auto kOpenSpacingJitter = crl::time(125);
constexpr auto kAdaptiveSpacingMin = crl::time(500);
constexpr auto kAdaptiveSpacingMax = crl::time(6000);

// Burst budget: a few opens may go out back-to-back (startup connects a
// handful of sessions), everything beyond that inside the window gets
// spaced out. A cold start with many accounts otherwise fires a rapid
// run of fresh handshakes at one endpoint - the classic scan pattern
// that makes a proxy throttle new connections.
constexpr auto kOpenBurstCount = 3;
constexpr auto kOpenBurstWindow = crl::time(10 * 1000);

} // namespace

OpenSlotReservation::OpenSlotReservation(crl::time delay)
: _delay(delay) {
}

OpenSlotReservation::OpenSlotReservation(
		std::shared_ptr<ProxyEndpointContext> context,
		QString key,
		uint64 id,
		crl::time openAt,
		crl::time nextOpenAt,
		crl::time delay)
: _context(std::move(context))
, _key(std::move(key))
, _id(id)
, _openAt(openAt)
, _nextOpenAt(nextOpenAt)
, _delay(delay) {
}

OpenSlotReservation::OpenSlotReservation(
		OpenSlotReservation &&other) noexcept
: _context(std::move(other._context))
, _key(std::move(other._key))
, _id(base::take(other._id))
, _openAt(base::take(other._openAt))
, _nextOpenAt(base::take(other._nextOpenAt))
, _delay(base::take(other._delay)) {
}

OpenSlotReservation &OpenSlotReservation::operator=(
		OpenSlotReservation &&other) noexcept {
	if (this != &other) {
		cancel();
		_context = std::move(other._context);
		_key = std::move(other._key);
		_id = base::take(other._id);
		_openAt = base::take(other._openAt);
		_nextOpenAt = base::take(other._nextOpenAt);
		_delay = base::take(other._delay);
	}
	return *this;
}

OpenSlotReservation::~OpenSlotReservation() {
	cancel();
}

void OpenSlotReservation::commit() {
	if (!_context || !_id) {
		return;
	}
	{
		auto &storage = _context->storage();
		QMutexLocker lock(&storage.mutex);
		auto &state = storage.openStates[_key];
		const auto i = std::find_if(
			begin(state.pendingOpens),
			end(state.pendingOpens),
			[=](const PendingOpenRecord &entry) {
				return entry.id == _id;
			});
		if (i != end(state.pendingOpens)) {
			state.pendingOpens.erase(i);
		}
		state.recentOpens.push_back({
			.openAt = _openAt,
			.nextOpenAt = _nextOpenAt,
		});
	}
	_context.reset();
	_key.clear();
	_id = 0;
}

void OpenSlotReservation::cancel() {
	if (!_context || !_id) {
		return;
	}
	{
		auto &storage = _context->storage();
		QMutexLocker lock(&storage.mutex);
		const auto state = storage.openStates.find(_key);
		if (state != end(storage.openStates)) {
			auto &pending = state->second.pendingOpens;
			const auto i = std::find_if(
				begin(pending),
				end(pending),
				[=](const PendingOpenRecord &entry) {
					return entry.id == _id;
				});
			if (i != end(pending)) {
				pending.erase(i);
			}
		}
	}
	_context.reset();
	_key.clear();
	_id = 0;
}

crl::time OpenSlotReservation::delay() const {
	return _delay;
}

OpenScheduler::OpenScheduler(const RuntimeAsyncGateway &async)
: _async(async)
, _context(CreateProxyEndpointContext()) {
}

OpenScheduler::OpenScheduler(not_null<RuntimeEnvironment*> runtime)
: _async(runtime->async())
, _context(runtime->proxyEndpointContextShared()) {
}

crl::time OpenConnectionSpacing(ProxyConnectionPattern pattern) {
	switch (pattern) {
	case ProxyConnectionPattern::Soft: return crl::time(1100);
	case ProxyConnectionPattern::Quiet: return crl::time(1200);
	case ProxyConnectionPattern::Strict: return crl::time(1400);
	case ProxyConnectionPattern::Browser: return crl::time(1150);
	case ProxyConnectionPattern::Off: break;
	}
	return crl::time(0);
}

OpenSlotReservation OpenScheduler::ReserveOpenSlot(
		const EndpointId &endpoint,
		ProxyConnectionPattern pattern,
		crl::time notBefore) {
	const auto key = EndpointKey(endpoint);
	if (key.isEmpty()) {
		return OpenSlotReservation(std::max(crl::time(0), notBefore));
	}
	const auto patternSpacing = OpenConnectionSpacing(pattern);
	const auto now = _async.now();
	const auto earliest = now + std::max(crl::time(0), notBefore);
	auto &storage = _context->storage();
	QMutexLocker lock(&storage.mutex);
	auto &state = storage.openStates[key];
	const auto expired = std::remove_if(
		begin(state.recentOpens),
		end(state.recentOpens),
		[=](const OpenRecord &entry) {
			return entry.openAt <= now - kOpenBurstWindow
				&& entry.nextOpenAt <= now;
		});
	state.recentOpens.erase(expired, end(state.recentOpens));
	auto scheduled = std::vector<crl::time>();
	scheduled.reserve(
		state.recentOpens.size() + state.pendingOpens.size());
	auto openAt = earliest;
	for (const auto &entry : state.recentOpens) {
		scheduled.push_back(entry.openAt);
		accumulate_max(openAt, entry.nextOpenAt);
	}
	for (const auto &entry : state.pendingOpens) {
		scheduled.push_back(entry.openAt);
		accumulate_max(openAt, entry.nextOpenAt);
	}
	std::sort(begin(scheduled), end(scheduled));
	while (true) {
		const auto first = std::upper_bound(
			begin(scheduled),
			end(scheduled),
			openAt - kOpenBurstWindow);
		if (end(scheduled) - first < kOpenBurstCount) {
			break;
		}
		const auto jitter = crl::time(
			_async.randomIndex(int(kOpenSpacingJitter) + 1));
		openAt = *(end(scheduled) - kOpenBurstCount)
			+ kOpenBurstWindow
			+ jitter;
	}
	const auto spacing = std::max(
		patternSpacing,
		state.adaptiveSpacing);
	auto nextOpenAt = openAt;
	if (spacing > 0) {
		const auto jitter = crl::time(
			_async.randomIndex(int(kOpenSpacingJitter) + 1));
		nextOpenAt = openAt + spacing + jitter;
	}
	const auto id = ++state.lastReservationId;
	state.pendingOpens.push_back({
		.id = id,
		.openAt = openAt,
		.nextOpenAt = nextOpenAt,
	});
	return OpenSlotReservation(
		_context,
		key,
		id,
		openAt,
		nextOpenAt,
		std::max(crl::time(0), openAt - now));
}

OpenSlotReservation ReserveOpenSlot(
		not_null<RuntimeEnvironment*> runtime,
		const EndpointId &endpoint,
		ProxyConnectionPattern pattern,
		crl::time notBefore) {
	return OpenScheduler(runtime).ReserveOpenSlot(
		endpoint,
		pattern,
		notBefore);
}

void NoteConnectTimeout(
		not_null<RuntimeEnvironment*> runtime,
		const EndpointId &endpoint) {
	const auto key = EndpointKey(endpoint);
	if (key.isEmpty()) {
		return;
	}
	auto &storage = runtime->proxyEndpointContext().storage();
	QMutexLocker lock(&storage.mutex);
	auto &state = storage.openStates[key];
	state.adaptiveSpacing = std::clamp(
		state.adaptiveSpacing * 2,
		kAdaptiveSpacingMin,
		kAdaptiveSpacingMax);
}

void NoteConnectSuccess(
		not_null<RuntimeEnvironment*> runtime,
		const EndpointId &endpoint) {
	const auto key = EndpointKey(endpoint);
	if (key.isEmpty()) {
		return;
	}
	auto &storage = runtime->proxyEndpointContext().storage();
	QMutexLocker lock(&storage.mutex);
	auto &state = storage.openStates[key];
	state.adaptiveSpacing = (state.adaptiveSpacing >= kAdaptiveSpacingMin * 2)
		? (state.adaptiveSpacing / 2)
		: crl::time(0);
}

} // namespace MTP::details::MtProxy
