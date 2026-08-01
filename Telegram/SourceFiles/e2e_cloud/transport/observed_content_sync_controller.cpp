/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "e2e_cloud/transport/observed_content_sync_controller.h"

#include <algorithm>
#include <limits>
#include <utility>

namespace E2ECloud {
namespace {

inline constexpr auto kDownloadPageLimit = 100;
inline constexpr auto kMaximumCursorSize = 1024;
inline constexpr auto kMaximumPagesPerRun = std::uint64_t(1'000'000);
inline constexpr auto kBoundaryOverlap = std::size_t(32);

} // namespace

struct ObservedContentSyncController::CallbackGuard {
	ObservedContentSyncController *controller = nullptr;
};

ObservedContentSyncController::ObservedContentSyncController(
		ConversationId conversationId,
		std::uint64_t telegramPeerIdBinding,
		TelegramTransport &transport,
		PageCallback pageCallback,
		CompletionCallback completionCallback)
: _conversationId(conversationId)
, _telegramPeerIdBinding(telegramPeerIdBinding)
, _transport(transport)
, _pageCallback(std::move(pageCallback))
, _completionCallback(std::move(completionCallback))
, _callbackGuard(std::make_shared<CallbackGuard>(CallbackGuard{ this })) {
}

ObservedContentSyncController::~ObservedContentSyncController() {
	_callbackGuard->controller = nullptr;
	_running = false;
	_requestActive = false;
}

bool ObservedContentSyncController::start(std::int64_t boundaryMessageId) {
	if (_running
		|| !_conversationId
		|| !_telegramPeerIdBinding
		|| boundaryMessageId < 0
		|| !_pageCallback
		|| !_completionCallback) {
		return false;
	}
	_seenCursors = { QByteArray() };
	_cursor.clear();
	_pages = 0;
	_objects = 0;
	_boundaryCandidates.clear();
	_boundaryMessageId = boundaryMessageId;
	_newestObservedMessageId = 0;
	_lastObservedMessageId = 0;
	_running = true;
	_requestActive = false;
	_requestQueued = true;
	pumpRequests();
	return true;
}

void ObservedContentSyncController::cancel() {
	if (_running) {
		finish(ObservedContentSyncStatus::Cancelled);
	}
}

bool ObservedContentSyncController::running() const {
	return _running;
}

void ObservedContentSyncController::pumpRequests() {
	if (_pumping || !_running) {
		return;
	}
	_pumping = true;
	while (_running && !_requestActive && _requestQueued) {
		_requestQueued = false;
		_requestActive = true;
		const auto guard = _callbackGuard;
		const auto weak = std::weak_ptr<CallbackGuard>(guard);
		_transport.downloadPage({
			.conversationId = _conversationId,
			.cursor = _cursor,
			.limit = kDownloadPageLimit,
		}, [weak](TelegramTransport::DownloadResult result) {
			if (const auto guard = weak.lock(); guard && guard->controller) {
				guard->controller->pageReceived(std::move(result));
			}
		});
		if (guard->controller != this) {
			return;
		} else if (_requestActive) {
			break;
		}
	}
	_pumping = false;
}

void ObservedContentSyncController::pageReceived(
		TelegramTransport::DownloadResult result) {
	if (!_running || !_requestActive) {
		return;
	}
	_requestActive = false;
	if (result.result != TelegramTransport::UploadResult::Accepted) {
		finish((result.result == TelegramTransport::UploadResult::PermanentError)
			? ObservedContentSyncStatus::PermanentTransportError
			: ObservedContentSyncStatus::RetryableTransportError);
		return;
	} else if (_pages == kMaximumPagesPerRun) {
		finish(ObservedContentSyncStatus::InvalidPagination);
		return;
	}
	++_pages;
	auto retained = std::vector<TelegramTransport::UntrustedObject>();
	retained.reserve(result.untrustedObjects.size());
	auto reachedBoundary = false;
	for (auto &object : result.untrustedObjects) {
		const auto messageId = object.observedMessageId;
		if (object.observedTelegramPeerIdBinding
				!= _telegramPeerIdBinding
			|| messageId <= 0
			|| (_lastObservedMessageId
				&& messageId >= _lastObservedMessageId)
			|| (_boundaryMessageId
				&& messageId < _boundaryMessageId)) {
			finish(ObservedContentSyncStatus::SecurityBlocked);
			return;
		}
		_lastObservedMessageId = messageId;
		if (!_newestObservedMessageId) {
			_newestObservedMessageId = messageId;
		}
		if (_boundaryMessageId && messageId == _boundaryMessageId) {
			reachedBoundary = true;
			break;
		}
		if (_boundaryCandidates.size() <= kBoundaryOverlap) {
			_boundaryCandidates.push_back(messageId);
		}
		retained.push_back(std::move(object));
	}
	if (!retained.empty()) {
		if (_objects > std::numeric_limits<std::uint64_t>::max()
				- retained.size()) {
			finish(ObservedContentSyncStatus::PersistenceFailed);
			return;
		}
		_objects += retained.size();
		const auto guard = _callbackGuard;
		const auto callback = _pageCallback;
		const auto persisted = callback(std::move(retained));
		if (guard->controller != this || !_running) {
			return;
		}
		if (persisted != ObservedContentPageResult::Persisted) {
			finish((persisted == ObservedContentPageResult::SecurityBlocked)
				? ObservedContentSyncStatus::SecurityBlocked
				: ObservedContentSyncStatus::PersistenceFailed);
			return;
		}
	}
	if (reachedBoundary) {
		finish(ObservedContentSyncStatus::Complete);
		return;
	} else if (result.complete && _boundaryMessageId) {
		finish(ObservedContentSyncStatus::SecurityBlocked);
		return;
	} else if (result.complete) {
		finish(ObservedContentSyncStatus::Complete);
		return;
	} else if (result.nextCursor.isEmpty()
		|| result.nextCursor.size() > kMaximumCursorSize
		|| std::find(
			begin(_seenCursors),
			end(_seenCursors),
			result.nextCursor) != end(_seenCursors)) {
		finish(ObservedContentSyncStatus::InvalidPagination);
		return;
	}
	_cursor = std::move(result.nextCursor);
	_seenCursors.push_back(_cursor);
	_requestQueued = true;
	pumpRequests();
}

void ObservedContentSyncController::finish(
		ObservedContentSyncStatus status) {
	if (!_running) {
		return;
	}
	_running = false;
	_requestActive = false;
	_requestQueued = false;
	auto nextBoundaryMessageId = _boundaryMessageId;
	if (status == ObservedContentSyncStatus::Complete
		&& !_boundaryCandidates.empty()) {
		if (!_boundaryMessageId) {
			const auto index = std::min(
				kBoundaryOverlap,
				_boundaryCandidates.size() - 1);
			nextBoundaryMessageId = _boundaryCandidates[index];
		} else if (_objects > kBoundaryOverlap) {
			nextBoundaryMessageId = _boundaryCandidates[kBoundaryOverlap];
		}
	}
	const auto callback = _completionCallback;
	callback({
		.status = status,
		.pages = _pages,
		.objects = _objects,
		.previousBoundaryMessageId = _boundaryMessageId,
		.newestObservedMessageId = _newestObservedMessageId,
		.nextBoundaryMessageId = nextBoundaryMessageId,
	});
}

} // namespace E2ECloud
