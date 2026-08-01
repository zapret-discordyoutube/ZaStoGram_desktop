/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "e2e_cloud/transport/public_bootstrap_sync_controller.h"

#include <algorithm>
#include <utility>

namespace E2ECloud {
namespace {

inline constexpr auto kDownloadPageLimit = 100;
inline constexpr auto kMaximumCursorSize = 1024;
inline constexpr auto kMaximumObjects = std::size_t(65'536);
inline constexpr auto kMaximumBytes = std::uint64_t(512 * 1024 * 1024);
inline constexpr auto kMaximumPages = std::uint64_t(1'000'000);

[[nodiscard]] PublicBootstrapSyncStatus MapStatus(
		PublicGroupBootstrapStatus status) {
	switch (status) {
	case PublicGroupBootstrapStatus::Verified:
		return PublicBootstrapSyncStatus::Verified;
	case PublicGroupBootstrapStatus::Missing:
		return PublicBootstrapSyncStatus::Missing;
	case PublicGroupBootstrapStatus::CapacityExceeded:
		return PublicBootstrapSyncStatus::CapacityExceeded;
	case PublicGroupBootstrapStatus::ObjectConflict:
		return PublicBootstrapSyncStatus::ObjectConflict;
	case PublicGroupBootstrapStatus::Ambiguous:
		return PublicBootstrapSyncStatus::Ambiguous;
	}
	return PublicBootstrapSyncStatus::Missing;
}

} // namespace

struct PublicBootstrapSyncController::CallbackGuard {
	PublicBootstrapSyncController *controller = nullptr;
};

PublicBootstrapSyncController::PublicBootstrapSyncController(
		ConversationId conversationId,
		std::uint64_t telegramPeerIdBinding,
		std::optional<AccountId> expectedOwnerAccountId,
		TelegramTransport &transport,
		const EnvelopeCodec &envelopeCodec,
		const Sha256Provider &sha256,
		CompletionCallback completionCallback)
: _conversationId(conversationId)
, _telegramPeerIdBinding(telegramPeerIdBinding)
, _expectedOwnerAccountId(expectedOwnerAccountId)
, _transport(transport)
, _envelopeCodec(envelopeCodec)
, _sha256(sha256)
, _completionCallback(std::move(completionCallback))
, _callbackGuard(std::make_shared<CallbackGuard>(CallbackGuard{ this })) {
}

PublicBootstrapSyncController::~PublicBootstrapSyncController() {
	_callbackGuard->controller = nullptr;
}

bool PublicBootstrapSyncController::start(QByteArray cursor) {
	if (_running
		|| !_conversationId
		|| !_telegramPeerIdBinding
		|| cursor.size() > kMaximumCursorSize) {
		return false;
	}
	_objects.clear();
	_seenCursors = { cursor };
	_cursor = std::move(cursor);
	_bytes = 0;
	_pages = 0;
	_running = true;
	_requestActive = false;
	_requestQueued = true;
	pumpRequests();
	return true;
}

void PublicBootstrapSyncController::cancel() {
	if (_running) {
		finish({
			.status = PublicBootstrapSyncStatus::Cancelled,
			.verified = std::nullopt,
			.untrustedObjects = {},
			.pages = _pages,
			.objects = _objects.size(),
		});
	}
}

bool PublicBootstrapSyncController::running() const {
	return _running;
}

void PublicBootstrapSyncController::pumpRequests() {
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

void PublicBootstrapSyncController::pageReceived(
		TelegramTransport::DownloadResult result) {
	if (!_running || !_requestActive) {
		return;
	}
	_requestActive = false;
	if (result.result != TelegramTransport::UploadResult::Accepted) {
		finish({
			.status = (result.result
					== TelegramTransport::UploadResult::PermanentError)
				? PublicBootstrapSyncStatus::PermanentTransportError
				: PublicBootstrapSyncStatus::RetryableTransportError,
			.verified = std::nullopt,
			.untrustedObjects = {},
			.pages = _pages,
			.objects = _objects.size(),
		});
		return;
	} else if (_pages == kMaximumPages) {
		finish({
			.status = PublicBootstrapSyncStatus::InvalidPagination,
			.verified = std::nullopt,
			.untrustedObjects = {},
			.pages = _pages,
			.objects = _objects.size(),
		});
		return;
	}
	++_pages;
	for (auto &object : result.untrustedObjects) {
		if (object.bytes.size() < 0
			|| _objects.size() == kMaximumObjects
			|| _bytes > kMaximumBytes
				- std::uint64_t(object.bytes.size())) {
			finish({
				.status = PublicBootstrapSyncStatus::CapacityExceeded,
				.verified = std::nullopt,
				.untrustedObjects = {},
				.pages = _pages,
				.objects = _objects.size(),
			});
			return;
		}
		_bytes += std::uint64_t(object.bytes.size());
		_objects.push_back(std::move(object));
	}
	if (result.complete) {
		auto outcome = VerifyPublicGroupBootstrap(
			_objects,
			_telegramPeerIdBinding,
			_conversationId,
			_expectedOwnerAccountId,
			_envelopeCodec,
			_sha256);
		const auto objectCount = _objects.size();
		finish({
			.status = MapStatus(outcome.status),
			.verified = std::move(outcome.verified),
			.untrustedObjects = std::move(_objects),
			.pages = _pages,
			.objects = objectCount,
		});
		return;
	} else if (result.nextCursor.isEmpty()
		|| result.nextCursor.size() > kMaximumCursorSize
		|| std::find(
			begin(_seenCursors),
			end(_seenCursors),
			result.nextCursor) != end(_seenCursors)) {
		finish({
			.status = PublicBootstrapSyncStatus::InvalidPagination,
			.verified = std::nullopt,
			.untrustedObjects = {},
			.pages = _pages,
			.objects = _objects.size(),
		});
		return;
	}
	_cursor = std::move(result.nextCursor);
	_seenCursors.push_back(_cursor);
	_requestQueued = true;
	pumpRequests();
}

void PublicBootstrapSyncController::finish(
		PublicBootstrapSyncCompletion completion) {
	if (!_running) {
		return;
	}
	_running = false;
	_requestActive = false;
	_requestQueued = false;
	_objects.clear();
	if (_completionCallback) {
		_completionCallback(std::move(completion));
	}
}

} // namespace E2ECloud
