/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "e2e_cloud/transport/public_bootstrap_discovery_controller.h"

#include <utility>

namespace E2ECloud {
namespace {

inline constexpr auto kDownloadPageLimit = 100;
inline constexpr auto kMaximumCursorSize = 1024;
inline constexpr auto kMaximumObjects = std::size_t(65'536);
inline constexpr auto kMaximumBytes = std::uint64_t(512 * 1024 * 1024);
inline constexpr auto kMaximumPages = std::uint64_t(65'536);
inline constexpr auto kMaximumStoredCursorBytes
	= std::uint64_t(64 * 1024 * 1024);

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

struct PublicBootstrapDiscoveryController::CallbackGuard {
	PublicBootstrapDiscoveryController *controller = nullptr;
};

PublicBootstrapDiscoveryController::PublicBootstrapDiscoveryController(
		std::uint64_t telegramPeerIdBinding,
		TelegramCarrierBackend &backend,
		const EnvelopeCodec &envelopeCodec,
		const Sha256Provider &sha256,
		CompletionCallback completionCallback)
: _telegramPeerIdBinding(telegramPeerIdBinding)
, _backend(backend)
, _envelopeCodec(envelopeCodec)
, _sha256(sha256)
, _completionCallback(std::move(completionCallback))
, _callbackGuard(std::make_shared<CallbackGuard>(CallbackGuard{ this })) {
}

PublicBootstrapDiscoveryController::~PublicBootstrapDiscoveryController() {
	_callbackGuard->controller = nullptr;
}

bool PublicBootstrapDiscoveryController::start(QByteArray cursor) {
	if (_running
		|| !_telegramPeerIdBinding
		|| cursor.size() > kMaximumCursorSize) {
		return false;
	}
	_objects.clear();
	_seenCursors = { cursor };
	_cursor = std::move(cursor);
	_bytes = 0;
	_pages = 0;
	_storedCursorBytes = std::uint64_t(_cursor.size());
	_running = true;
	_requestActive = false;
	_requestQueued = true;
	pumpRequests();
	return true;
}

void PublicBootstrapDiscoveryController::cancel() {
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

bool PublicBootstrapDiscoveryController::running() const {
	return _running;
}

void PublicBootstrapDiscoveryController::pumpRequests() {
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
		_backend.downloadDocuments(
			_telegramPeerIdBinding,
			_cursor,
			kDownloadPageLimit,
			[weak, requestToken](
					TelegramTransport::UploadResult result,
					CarrierDownloadPage page) {
				if (const auto guard = weak.lock();
						guard && guard->controller) {
					guard->controller->pageReceived(
						requestToken,
						result,
						std::move(page));
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

void PublicBootstrapDiscoveryController::pageReceived(
		std::uint64_t requestToken,
		TelegramTransport::UploadResult result,
		CarrierDownloadPage page) {
	if (!_running
		|| !_requestActive
		|| requestToken != _requestToken) {
		return;
	}
	_requestActive = false;
	if (result != TelegramTransport::UploadResult::Accepted) {
		finish({
			.status = (result
					== TelegramTransport::UploadResult::PermanentError)
				? PublicBootstrapSyncStatus::PermanentTransportError
				: PublicBootstrapSyncStatus::RetryableTransportError,
			.verified = std::nullopt,
			.untrustedObjects = {},
			.pages = _pages,
			.objects = _objects.size(),
		});
		return;
	} else if (page.untrustedObjects.size()
			> std::size_t(kDownloadPageLimit)) {
		finish({
			.status = PublicBootstrapSyncStatus::InvalidPagination,
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
	for (auto &object : page.untrustedObjects) {
		if (!IsPublicGroupBootstrapCandidate(
				object,
				_telegramPeerIdBinding,
				std::nullopt,
				_envelopeCodec)) {
			continue;
		} else if (object.bytes.size() < 0
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
	if (page.complete) {
		auto outcome = VerifyPublicGroupBootstrap(
			_objects,
			_telegramPeerIdBinding,
			std::nullopt,
			std::nullopt,
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
	} else if (page.nextCursor.isEmpty()
		|| page.nextCursor.size() > kMaximumCursorSize
		|| _seenCursors.contains(page.nextCursor)
		|| _storedCursorBytes > kMaximumStoredCursorBytes
			- std::uint64_t(page.nextCursor.size())) {
		finish({
			.status = PublicBootstrapSyncStatus::InvalidPagination,
			.verified = std::nullopt,
			.untrustedObjects = {},
			.pages = _pages,
			.objects = _objects.size(),
		});
		return;
	}
	_cursor = std::move(page.nextCursor);
	_storedCursorBytes += std::uint64_t(_cursor.size());
	_seenCursors.emplace(_cursor);
	_requestQueued = true;
	pumpRequests();
}

void PublicBootstrapDiscoveryController::finish(
		PublicBootstrapSyncCompletion completion) {
	if (!_running) {
		return;
	}
	_running = false;
	_requestActive = false;
	_requestQueued = false;
	auto callback = std::move(_completionCallback);
	if (callback) {
		callback(std::move(completion));
	}
}

} // namespace E2ECloud
