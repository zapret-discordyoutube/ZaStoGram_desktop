/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "e2e_cloud/transport/observed_content_sync_controller.h"

#include "e2e_cloud/identity/account_identity.h"

#include <algorithm>
#include <limits>
#include <utility>

namespace E2ECloud {
namespace {

inline constexpr auto kDownloadPageLimit = 100;
inline constexpr auto kMaximumCursorSize = 1024;
inline constexpr auto kMaximumPagesPerRun = std::uint64_t(1'000'000);
inline constexpr auto kMaximumStoredCursorBytes
	= std::uint64_t(128 * 1024 * 1024);
inline constexpr auto kMaximumRetainedNewestPageBytes
	= std::uint64_t(64 * 1024 * 1024);
inline constexpr auto kBoundaryOverlap = std::size_t(32);
inline constexpr auto kPageFingerprintDomain
	= "TDE2E/observed-content-page/v1";

void AppendUint64(QByteArray &result, std::uint64_t value) {
	for (auto shift = 56; shift >= 0; shift -= 8) {
		result.append(char(value >> shift));
	}
}

void AppendBytes(QByteArray &result, const QByteArray &value) {
	AppendUint64(result, std::uint64_t(value.size()));
	result.append(value);
}

void AppendDigest(QByteArray &result, Digest digest) {
	result.append(
		reinterpret_cast<const char*>(digest.bytes.data()),
		int(digest.bytes.size()));
}

[[nodiscard]] Digest PageFingerprint(
		const QByteArray &requestCursor,
		const TelegramTransport::DownloadResult &result,
		const Sha256Provider &sha256) {
	auto input = QByteArray(kPageFingerprintDomain);
	input.append(char(0));
	AppendBytes(input, requestCursor);
	AppendBytes(input, result.nextCursor);
	input.append(char(result.complete ? 1 : 0));
	AppendUint64(input, result.untrustedObjects.size());
	for (const auto &object : result.untrustedObjects) {
		AppendUint64(input, object.observedTelegramPeerIdBinding);
		AppendUint64(input, object.observedSenderTelegramUserIdBinding);
		AppendUint64(input, std::uint64_t(object.observedMessageId));
		AppendUint64(input, std::uint64_t(object.bytes.size()));
		AppendDigest(input, sha256.digest(object.bytes));
	}
	return sha256.digest(input);
}

} // namespace

struct ObservedContentSyncController::CallbackGuard {
	ObservedContentSyncController *controller = nullptr;
};

struct ObservedContentSyncController::ScannedPage {
	QByteArray cursor;
	Digest fingerprint;
	std::vector<TelegramTransport::UntrustedObject> retainedNewestObjects;
	std::size_t retainedObjects = 0;
};

ObservedContentSyncController::ObservedContentSyncController(
		ConversationId conversationId,
		std::uint64_t telegramPeerIdBinding,
		TelegramTransport &transport,
		const Sha256Provider &sha256,
		PageCallback pageCallback,
		CompletionCallback completionCallback,
		PreviewPageCallback previewPageCallback)
: _conversationId(conversationId)
, _telegramPeerIdBinding(telegramPeerIdBinding)
, _transport(transport)
, _sha256(sha256)
, _pageCallback(std::move(pageCallback))
, _completionCallback(std::move(completionCallback))
, _previewPageCallback(std::move(previewPageCallback))
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
	_scannedPages.clear();
	_cursor.clear();
	_pages = 0;
	_objects = 0;
	_storedCursorBytes = 0;
	_boundaryCandidates.clear();
	_replayPageIndex = 0;
	_boundaryMessageId = boundaryMessageId;
	_newestObservedMessageId = 0;
	_lastObservedMessageId = 0;
	_phase = Phase::Scanning;
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
	} else if (result.untrustedObjects.size()
			> std::size_t(kDownloadPageLimit)) {
		finish(ObservedContentSyncStatus::SecurityBlocked);
		return;
	}
	const auto fingerprint = PageFingerprint(_cursor, result, _sha256);
	if (_phase == Phase::Replaying) {
		const auto &expected = _scannedPages[_replayPageIndex];
		if (_cursor != expected.cursor
			|| fingerprint != expected.fingerprint) {
			finish(ObservedContentSyncStatus::SecurityBlocked);
			return;
		}
		auto retained = std::vector<TelegramTransport::UntrustedObject>();
		retained.reserve(expected.retainedObjects);
		for (auto &object : result.untrustedObjects) {
			if (_boundaryMessageId
				&& object.observedMessageId == _boundaryMessageId) {
				break;
			}
			retained.push_back(std::move(object));
		}
		if (retained.size() != expected.retainedObjects) {
			finish(ObservedContentSyncStatus::SecurityBlocked);
			return;
		} else if (!deliverPage(std::move(retained))) {
			return;
		}
		if (_replayPageIndex == 1) {
			auto newest = std::move(
				_scannedPages.front().retainedNewestObjects);
			if (!deliverPage(std::move(newest))) {
				return;
			}
			finish(ObservedContentSyncStatus::Complete);
			return;
		}
		--_replayPageIndex;
		_cursor = _scannedPages[_replayPageIndex].cursor;
		_requestQueued = true;
		pumpRequests();
		return;
	} else if (_pages == kMaximumPagesPerRun) {
		finish(ObservedContentSyncStatus::InvalidPagination);
		return;
	}
	++_pages;
	auto retainedObjects = std::size_t(0);
	auto reachedBoundary = false;
	for (const auto &object : result.untrustedObjects) {
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
		++retainedObjects;
	}
	if (retainedObjects) {
		if (_objects > std::numeric_limits<std::uint64_t>::max()
				- retainedObjects) {
			finish(ObservedContentSyncStatus::PersistenceFailed);
			return;
		}
		_objects += retainedObjects;
	}
	const auto terminal = reachedBoundary || result.complete;
	if (result.complete && _boundaryMessageId && !reachedBoundary) {
		finish(ObservedContentSyncStatus::SecurityBlocked);
		return;
	} else if (!terminal && (result.nextCursor.isEmpty()
		|| result.nextCursor.size() > kMaximumCursorSize
		|| _seenCursors.contains(result.nextCursor)
		|| _storedCursorBytes > kMaximumStoredCursorBytes
			- std::uint64_t(result.nextCursor.size()))) {
		finish(ObservedContentSyncStatus::InvalidPagination);
		return;
	}
	if (retainedObjects
		&& !previewPage(result.untrustedObjects, retainedObjects)) {
		return;
	}
	auto retainedNewestObjects
		= std::vector<TelegramTransport::UntrustedObject>();
	if (_pages == 1 && retainedObjects) {
		auto retainedBytes = std::uint64_t(0);
		retainedNewestObjects.reserve(retainedObjects);
		for (auto i = std::size_t(0); i != retainedObjects; ++i) {
			const auto byteSize = std::uint64_t(
				result.untrustedObjects[i].bytes.size());
			if (byteSize > kMaximumRetainedNewestPageBytes
				|| retainedBytes > kMaximumRetainedNewestPageBytes
					- byteSize) {
				finish(ObservedContentSyncStatus::SecurityBlocked);
				return;
			}
			retainedBytes += byteSize;
			retainedNewestObjects.push_back(
				std::move(result.untrustedObjects[i]));
		}
	}
	_scannedPages.push_back({
		.cursor = _cursor,
		.fingerprint = fingerprint,
		.retainedNewestObjects = std::move(retainedNewestObjects),
		.retainedObjects = retainedObjects,
	});
	if (terminal) {
		if (!_objects) {
			finish(ObservedContentSyncStatus::Complete);
			return;
		} else if (_scannedPages.size() == 1) {
			auto newest = std::move(
				_scannedPages.front().retainedNewestObjects);
			if (!deliverPage(std::move(newest))) {
				return;
			}
			finish(ObservedContentSyncStatus::Complete);
			return;
		}
		_phase = Phase::Replaying;
		_replayPageIndex = _scannedPages.size() - 1;
		_cursor = _scannedPages[_replayPageIndex].cursor;
		_requestQueued = true;
		pumpRequests();
		return;
	}
	_cursor = std::move(result.nextCursor);
	_storedCursorBytes += std::uint64_t(_cursor.size());
	_seenCursors.emplace(_cursor);
	_requestQueued = true;
	pumpRequests();
}

bool ObservedContentSyncController::previewPage(
		const std::vector<TelegramTransport::UntrustedObject> &objects,
		std::size_t objectLimit) {
	if (!_previewPageCallback) {
		return true;
	}
	const auto guard = _callbackGuard;
	const auto callback = _previewPageCallback;
	const auto persisted = callback(objects, objectLimit);
	if (guard->controller != this || !_running) {
		return false;
	} else if (persisted != ObservedContentPageResult::Persisted) {
		finish((persisted == ObservedContentPageResult::SecurityBlocked)
			? ObservedContentSyncStatus::SecurityBlocked
			: ObservedContentSyncStatus::PersistenceFailed);
		return false;
	}
	return true;
}

bool ObservedContentSyncController::deliverPage(
		std::vector<TelegramTransport::UntrustedObject> objects) {
	if (objects.empty()) {
		return true;
	}
	const auto guard = _callbackGuard;
	const auto callback = _pageCallback;
	const auto persisted = callback(std::move(objects));
	if (guard->controller != this || !_running) {
		return false;
	} else if (persisted != ObservedContentPageResult::Persisted) {
		finish((persisted == ObservedContentPageResult::SecurityBlocked)
			? ObservedContentSyncStatus::SecurityBlocked
			: ObservedContentSyncStatus::PersistenceFailed);
		return false;
	}
	return true;
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
