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
#include <map>

namespace MTP::details::MtProxy {
namespace {

constexpr auto kOpenSpacingJitter = crl::time(125);

struct OpenState {
	crl::time nextOpenAt = 0;
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
	const auto spacing = OpenConnectionSpacing(pattern);
	if (spacing <= 0) {
		return notBefore;
	}
	const auto key = EndpointKey(endpoint);
	if (key.isEmpty()) {
		return notBefore;
	}
	const auto now = crl::now();
	const auto earliest = now + std::max(crl::time(0), notBefore);
	auto result = crl::time(0);
	QMutexLocker lock(&OpenStatesMutex);
	auto &state = OpenStates[key];
	const auto openAt = std::max(earliest, state.nextOpenAt);
	state.nextOpenAt = openAt + spacing + OpenJitter();
	result = std::max(crl::time(0), openAt - now);
	return result;
}

} // namespace MTP::details::MtProxy
