/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "mtproto/proxy/mtproxy/open_scheduler.h"

#include "base/random.h"

#include <QtCore/QMutex>

#include <algorithm>
#include <deque>
#include <map>

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
constexpr auto kOpenBurstSpacing = crl::time(2500);

struct OpenState {
	crl::time nextOpenAt = 0;
	crl::time adaptiveSpacing = 0;
	std::deque<crl::time> recentOpens;
};

QMutex OpenStatesMutex;
std::map<QString, OpenState> OpenStates;

[[nodiscard]] crl::time OpenJitter() {
	return crl::time(base::RandomIndex(int(kOpenSpacingJitter) + 1));
}

} // namespace

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

crl::time ReserveOpenSlot(
		const EndpointId &endpoint,
		ProxyConnectionPattern pattern,
		crl::time notBefore) {
	const auto key = EndpointKey(endpoint);
	if (key.isEmpty()) {
		return notBefore;
	}
	const auto patternSpacing = OpenConnectionSpacing(pattern);
	const auto now = crl::now();
	const auto earliest = now + std::max(crl::time(0), notBefore);
	auto result = crl::time(0);
	QMutexLocker lock(&OpenStatesMutex);
	auto &state = OpenStates[key];
	while (!state.recentOpens.empty()
		&& state.recentOpens.front() <= now - kOpenBurstWindow) {
		state.recentOpens.pop_front();
	}
	const auto burstSpacing = (int(state.recentOpens.size())
		>= kOpenBurstCount)
		? kOpenBurstSpacing
		: crl::time(0);
	const auto spacing = std::max({
		patternSpacing,
		state.adaptiveSpacing,
		burstSpacing });
	const auto openAt = std::max(earliest, state.nextOpenAt);
	if (spacing > 0) {
		state.nextOpenAt = openAt + spacing + OpenJitter();
	}
	state.recentOpens.push_back(openAt);
	result = std::max(crl::time(0), openAt - now);
	return result;
}

void NoteConnectTimeout(const EndpointId &endpoint) {
	const auto key = EndpointKey(endpoint);
	if (key.isEmpty()) {
		return;
	}
	QMutexLocker lock(&OpenStatesMutex);
	auto &state = OpenStates[key];
	state.adaptiveSpacing = std::clamp(
		state.adaptiveSpacing * 2,
		kAdaptiveSpacingMin,
		kAdaptiveSpacingMax);
}

void NoteConnectSuccess(const EndpointId &endpoint) {
	const auto key = EndpointKey(endpoint);
	if (key.isEmpty()) {
		return;
	}
	QMutexLocker lock(&OpenStatesMutex);
	auto &state = OpenStates[key];
	state.adaptiveSpacing = (state.adaptiveSpacing >= kAdaptiveSpacingMin * 2)
		? (state.adaptiveSpacing / 2)
		: crl::time(0);
}

} // namespace MTP::details::MtProxy
