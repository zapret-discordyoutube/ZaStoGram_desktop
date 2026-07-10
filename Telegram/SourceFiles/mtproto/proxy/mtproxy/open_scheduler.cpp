/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "mtproto/proxy/mtproxy/open_scheduler.h"

#include "mtproto/proxy/proxy_endpoint_context.h"
#include "mtproto/proxy/proxy_endpoint_context_p.h"

#include <QtCore/QMutex>

#include <algorithm>

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

crl::time OpenScheduler::ReserveOpenSlot(
		const EndpointId &endpoint,
		ProxyConnectionPattern pattern,
		crl::time notBefore) {
	const auto key = EndpointKey(endpoint);
	if (key.isEmpty()) {
		return notBefore;
	}
	const auto patternSpacing = OpenConnectionSpacing(pattern);
	const auto now = _async.now();
	const auto earliest = now + std::max(crl::time(0), notBefore);
	auto &storage = _context->storage();
	QMutexLocker lock(&storage.mutex);
	auto &state = storage.openStates[key];
	auto openAt = std::max(earliest, state.nextOpenAt);
	while (!state.recentOpens.empty()
		&& state.recentOpens.front() <= openAt - kOpenBurstWindow) {
		state.recentOpens.pop_front();
	}
	if (int(state.recentOpens.size()) >= kOpenBurstCount) {
		const auto jitter = crl::time(
			_async.randomIndex(int(kOpenSpacingJitter) + 1));
		openAt = std::max(
			openAt,
			state.recentOpens[
				state.recentOpens.size() - kOpenBurstCount]
				+ kOpenBurstWindow
				+ jitter);
		while (!state.recentOpens.empty()
			&& state.recentOpens.front() <= openAt - kOpenBurstWindow) {
			state.recentOpens.pop_front();
		}
	}
	const auto spacing = std::max(
		patternSpacing,
		state.adaptiveSpacing);
	state.nextOpenAt = openAt;
	if (spacing > 0) {
		const auto jitter = crl::time(
			_async.randomIndex(int(kOpenSpacingJitter) + 1));
		state.nextOpenAt = openAt + spacing + jitter;
	}
	state.recentOpens.push_back(openAt);
	return std::max(crl::time(0), openAt - now);
}

crl::time ReserveOpenSlot(
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
