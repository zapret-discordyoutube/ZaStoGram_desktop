/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "e2e_cloud/transport/file_chunk_download_controller.h"

#include <limits>
#include <utility>

namespace E2ECloud {
namespace {

// Keep on-demand file pages small enough to surface useful byte progress in
// the native message card instead of jumping from zero straight to complete.
inline constexpr auto kDownloadPageLimit = 4;
inline constexpr auto kMaximumCursorSize = 1024;

} // namespace

struct FileChunkDownloadController::CallbackGuard {
	FileChunkDownloadController *controller = nullptr;
};

FileChunkDownloadController::FileChunkDownloadController(
		ConversationId conversationId,
		std::uint64_t telegramPeerIdBinding,
		std::int64_t minimumMessageIdExclusive,
		std::uint64_t maximumPages,
		std::uint64_t maximumObjects,
		std::uint64_t maximumBytes,
		TelegramTransport &transport,
		PageCallback pageCallback,
		CompletionCallback completionCallback)
: _conversationId(conversationId)
, _telegramPeerIdBinding(telegramPeerIdBinding)
, _minimumMessageIdExclusive(minimumMessageIdExclusive)
, _maximumPages(maximumPages)
, _maximumObjects(maximumObjects)
, _maximumBytes(maximumBytes)
, _transport(transport)
, _pageCallback(std::move(pageCallback))
, _completionCallback(std::move(completionCallback))
, _callbackGuard(std::make_shared<CallbackGuard>(CallbackGuard{ this })) {
}

FileChunkDownloadController::~FileChunkDownloadController() {
	_callbackGuard->controller = nullptr;
	_running = false;
	_requestActive = false;
}

bool FileChunkDownloadController::start() {
	if (_running
		|| !_conversationId
		|| !_telegramPeerIdBinding
		|| _minimumMessageIdExclusive <= 0
		|| !_maximumPages
		|| !_maximumObjects
		|| !_maximumBytes
		|| !_pageCallback
		|| !_completionCallback) {
		return false;
	}
	_seenCursors = { QByteArray() };
	_cursor.clear();
	_pages = 0;
	_objects = 0;
	_bytes = 0;
	_lastObservedMessageId = 0;
	_running = true;
	_requestActive = false;
	_requestQueued = true;
	pumpRequests();
	return true;
}

void FileChunkDownloadController::cancel() {
	if (_running) {
		finish(FileChunkDownloadStatus::Cancelled);
	}
}

bool FileChunkDownloadController::running() const {
	return _running;
}

void FileChunkDownloadController::pumpRequests() {
	if (_pumping || !_running) {
		return;
	}
	_pumping = true;
	while (_running && !_requestActive && _requestQueued) {
		_requestQueued = false;
		_requestActive = true;
		if (++_requestToken == 0) {
			++_requestToken;
		}
		const auto requestToken = _requestToken;
		const auto guard = _callbackGuard;
		const auto weak = std::weak_ptr<CallbackGuard>(guard);
		_transport.downloadPage({
			.conversationId = _conversationId,
			.cursor = _cursor,
			.limit = kDownloadPageLimit,
		}, [weak, requestToken](TelegramTransport::DownloadResult result) {
			if (const auto guard = weak.lock(); guard && guard->controller) {
				guard->controller->pageReceived(
					requestToken,
					std::move(result));
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

void FileChunkDownloadController::pageReceived(
		std::uint64_t requestToken,
		TelegramTransport::DownloadResult result) {
	if (!_running
		|| !_requestActive
		|| requestToken != _requestToken) {
		return;
	}
	_requestActive = false;
	if (result.result != TelegramTransport::UploadResult::Accepted) {
		finish((result.result == TelegramTransport::UploadResult::PermanentError)
			? FileChunkDownloadStatus::PermanentTransportError
			: FileChunkDownloadStatus::RetryableTransportError);
		return;
	} else if (result.untrustedObjects.size()
			> std::size_t(kDownloadPageLimit)) {
		finish(FileChunkDownloadStatus::SecurityBlocked);
		return;
	} else if (_pages == _maximumPages) {
		finish(FileChunkDownloadStatus::LimitExceeded);
		return;
	}
	++_pages;
	auto pageBytes = std::uint64_t();
	for (const auto &object : result.untrustedObjects) {
		const auto messageId = object.observedMessageId;
		const auto size = std::uint64_t(object.bytes.size());
		if (object.observedTelegramPeerIdBinding
				!= _telegramPeerIdBinding
			|| messageId <= _minimumMessageIdExclusive
			|| (_lastObservedMessageId
				&& messageId >= _lastObservedMessageId)) {
			finish(FileChunkDownloadStatus::SecurityBlocked);
			return;
		} else if (pageBytes > std::numeric_limits<std::uint64_t>::max()
				- size) {
			finish(FileChunkDownloadStatus::LimitExceeded);
			return;
		}
		_lastObservedMessageId = messageId;
		pageBytes += size;
	}
	const auto pageObjects = std::uint64_t(result.untrustedObjects.size());
	if (pageObjects > _maximumObjects
		|| _objects > _maximumObjects - pageObjects
		|| pageBytes > _maximumBytes
		|| _bytes > _maximumBytes - pageBytes) {
		finish(FileChunkDownloadStatus::LimitExceeded);
		return;
	}
	_objects += pageObjects;
	_bytes += pageBytes;
	const auto guard = _callbackGuard;
	const auto callback = _pageCallback;
	const auto processed = callback(std::move(result.untrustedObjects));
	if (guard->controller != this || !_running) {
		return;
	} else if (processed == FileChunkDownloadPageStatus::Complete) {
		finish(FileChunkDownloadStatus::Complete);
		return;
	} else if (processed == FileChunkDownloadPageStatus::SecurityBlocked) {
		finish(FileChunkDownloadStatus::SecurityBlocked);
		return;
	} else if (processed == FileChunkDownloadPageStatus::PersistenceFailed) {
		finish(FileChunkDownloadStatus::PersistenceFailed);
		return;
	} else if (result.complete) {
		finish(FileChunkDownloadStatus::Missing);
		return;
	} else if (result.nextCursor.isEmpty()
		|| result.nextCursor.size() > kMaximumCursorSize
		|| _seenCursors.contains(result.nextCursor)) {
		finish(FileChunkDownloadStatus::InvalidPagination);
		return;
	}
	_cursor = std::move(result.nextCursor);
	_seenCursors.emplace(_cursor);
	_requestQueued = true;
	pumpRequests();
}

void FileChunkDownloadController::finish(FileChunkDownloadStatus status) {
	if (!_running) {
		return;
	}
	_running = false;
	_requestActive = false;
	_requestQueued = false;
	const auto callback = _completionCallback;
	callback({
		.status = status,
		.pages = _pages,
		.objects = _objects,
		.bytes = _bytes,
	});
}

} // namespace E2ECloud
