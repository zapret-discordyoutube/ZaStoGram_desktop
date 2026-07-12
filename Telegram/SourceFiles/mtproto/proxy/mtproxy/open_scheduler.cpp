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
#include "mtproto/runtime/runtime_environment.h"

#include <QtCore/QMutex>

#include <algorithm>

namespace MTP::details::MtProxy {
namespace {

constexpr auto kAdaptiveSpacingMin = crl::time(500);
constexpr auto kAdaptiveSpacingMax = crl::time(6000);

void PruneRecentOpens(OpenState &state, crl::time now) {
	const auto expired = std::remove_if(
		begin(state.recentOpens),
		end(state.recentOpens),
		[=](const OpenRecord &entry) {
			return entry.nextOpenAt <= now;
		});
	state.recentOpens.erase(expired, end(state.recentOpens));
}

[[nodiscard]] crl::time RecentOpenBoundary(const OpenState &state) {
	auto result = crl::time();
	for (const auto &entry : state.recentOpens) {
		accumulate_max(result, entry.nextOpenAt);
	}
	return result;
}

} // namespace

OpenSlotAssignment ReserveOpenSlotLocked(
		OpenState &state,
		const OpenSlotRequest &request) {
	PruneRecentOpens(state, request.now);
	auto openAt = std::max(request.now, request.earliestOpenAt);
	accumulate_max(openAt, RecentOpenBoundary(state));
	for (const auto &entry : state.pendingOpens) {
		accumulate_max(openAt, entry.nextOpenAt);
	}
	const auto spacing = std::max(crl::time(), request.spacing);
	const auto jitter = std::max(crl::time(), request.jitter);
	const auto nextOpenAt = openAt + spacing + jitter;
	const auto id = ++state.lastReservationId;
	state.pendingOpens.push_back({
		.id = id,
		.openAt = openAt,
		.nextOpenAt = nextOpenAt,
	});
	return {
		.id = id,
		.openAt = openAt,
		.nextOpenAt = nextOpenAt,
		.delay = std::max(crl::time(), openAt - request.now),
	};
}

bool CancelOpenSlotLocked(OpenState &state, uint64 id) {
	const auto i = std::find_if(
		begin(state.pendingOpens),
		end(state.pendingOpens),
		[=](const PendingOpenRecord &entry) {
			return entry.id == id;
		});
	if (i == end(state.pendingOpens)) {
		return false;
	}
	state.pendingOpens.erase(i);
	return true;
}

bool CommitOpenSlotLocked(OpenState &state, uint64 id) {
	const auto i = std::find_if(
		begin(state.pendingOpens),
		end(state.pendingOpens),
		[=](const PendingOpenRecord &entry) {
			return entry.id == id;
		});
	if (i == end(state.pendingOpens)) {
		return false;
	}
	const auto committed = *i;
	state.pendingOpens.erase(i);
	state.recentOpens.push_back({
		.openAt = committed.openAt,
		.nextOpenAt = committed.nextOpenAt,
	});
	return true;
}

std::vector<OpenSlotAssignment> ReflowOpenSlotsLocked(
		OpenState &state,
		const std::vector<OpenSlotReflowRequest> &ordered,
		crl::time now) {
	PruneRecentOpens(state, now);
	if (ordered.size() != state.pendingOpens.size()) {
		return {};
	}
	auto reflowed = std::deque<PendingOpenRecord>();
	auto result = std::vector<OpenSlotAssignment>();
	result.reserve(ordered.size());
	auto boundary = RecentOpenBoundary(state);
	for (const auto &request : ordered) {
		if (!request.id) {
			return {};
		}
		const auto existing = std::find_if(
			begin(state.pendingOpens),
			end(state.pendingOpens),
			[&](const PendingOpenRecord &entry) {
				return entry.id == request.id;
			});
		const auto duplicate = std::find_if(
			begin(reflowed),
			end(reflowed),
			[&](const PendingOpenRecord &entry) {
				return entry.id == request.id;
			});
		if (existing == end(state.pendingOpens)
			|| duplicate != end(reflowed)) {
			return {};
		}
		auto openAt = std::max(now, request.earliestOpenAt);
		accumulate_max(openAt, boundary);
		const auto spacing = std::max(crl::time(), request.spacing);
		const auto jitter = std::max(crl::time(), request.jitter);
		const auto nextOpenAt = openAt + spacing + jitter;
		reflowed.push_back({
			.id = request.id,
			.openAt = openAt,
			.nextOpenAt = nextOpenAt,
		});
		result.push_back({
			.id = request.id,
			.openAt = openAt,
			.nextOpenAt = nextOpenAt,
			.delay = std::max(crl::time(), openAt - now),
		});
		boundary = nextOpenAt;
	}
	state.pendingOpens = std::move(reflowed);
	return result;
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
