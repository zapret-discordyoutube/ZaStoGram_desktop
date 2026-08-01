/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "e2e_cloud/transport/cloud_vault_sync_controller.h"

#include <openssl/crypto.h>

#include <utility>

namespace E2ECloud {
namespace {

inline constexpr auto kDownloadPageLimit = 100;
inline constexpr auto kMaximumCursorSize = 1024;
inline constexpr auto kMaximumCandidates = std::size_t(65536);
inline constexpr auto kMaximumCandidateBytes = std::uint64_t(64 * 1024 * 1024);
inline constexpr auto kMaximumPages = std::uint64_t(1'000'000);
inline constexpr auto kMaximumStoredCursorBytes
	= std::uint64_t(128 * 1024 * 1024);

void Cleanse(QByteArray &bytes) {
	if (!bytes.isEmpty()) {
		OPENSSL_cleanse(bytes.data(), bytes.size());
	}
	bytes.clear();
}

[[nodiscard]] CloudVaultSyncStatus MapStatus(
		CloudVaultSelectionStatus status) {
	switch (status) {
	case CloudVaultSelectionStatus::Selected:
		return CloudVaultSyncStatus::Selected;
	case CloudVaultSelectionStatus::Missing:
		return CloudVaultSyncStatus::Missing;
	case CloudVaultSelectionStatus::Unreadable:
		return CloudVaultSyncStatus::Unreadable;
	case CloudVaultSelectionStatus::CapacityExceeded:
		return CloudVaultSyncStatus::CapacityExceeded;
	case CloudVaultSelectionStatus::IdentityConflict:
		return CloudVaultSyncStatus::IdentityConflict;
	case CloudVaultSelectionStatus::ForkDetected:
		return CloudVaultSyncStatus::ForkDetected;
	case CloudVaultSelectionStatus::RollbackDetected:
		return CloudVaultSyncStatus::RollbackDetected;
	case CloudVaultSelectionStatus::ChainGap:
		return CloudVaultSyncStatus::ChainGap;
	}
	return CloudVaultSyncStatus::Unreadable;
}

} // namespace

struct CloudVaultSyncController::CallbackGuard {
	CloudVaultSyncController *controller = nullptr;
};

CloudVaultSyncController::CloudVaultSyncController(
		std::uint64_t telegramUserIdBinding,
		CloudVaultRemote &remote,
		const CloudVaultSelector &selector,
		CompletionCallback completionCallback)
: _telegramUserIdBinding(telegramUserIdBinding)
, _remote(remote)
, _selector(selector)
, _completionCallback(std::move(completionCallback))
, _callbackGuard(std::make_shared<CallbackGuard>(CallbackGuard{ this })) {
}

CloudVaultSyncController::~CloudVaultSyncController() {
	_callbackGuard->controller = nullptr;
	Cleanse(_password);
}

bool CloudVaultSyncController::start(
		QByteArray password,
		std::optional<CloudVaultAnchor> localAnchor) {
	if (_running || !_telegramUserIdBinding || password.isEmpty()) {
		Cleanse(password);
		return false;
	}
	_password = std::move(password);
	return startRequests(localAnchor);
}

bool CloudVaultSyncController::startDiscovery() {
	if (_running || !_telegramUserIdBinding) {
		return false;
	}
	Cleanse(_password);
	_localAnchor.reset();
	_candidates.clear();
	_seenCursors.clear();
	_cursor.clear();
	_candidateBytes = 0;
	_pages = 0;
	_storedCursorBytes = 0;
	_running = true;
	_requestActive = true;
	_requestQueued = false;
	const auto guard = _callbackGuard;
	const auto weak = std::weak_ptr<CallbackGuard>(guard);
	_remote.discover([weak](
			CloudVaultRemote::Result result,
			bool present) {
		if (const auto guard = weak.lock(); guard && guard->controller) {
			guard->controller->discoveryReceived(result, present);
		}
	});
	return true;
}

bool CloudVaultSyncController::startRequests(
		std::optional<CloudVaultAnchor> localAnchor) {
	_localAnchor = localAnchor;
	_candidates.clear();
	_seenCursors = { QByteArray() };
	_cursor.clear();
	_candidateBytes = 0;
	_pages = 0;
	_storedCursorBytes = std::uint64_t(_cursor.size());
	_running = true;
	_requestActive = false;
	_requestQueued = true;
	pumpRequests();
	return true;
}

void CloudVaultSyncController::cancel() {
	if (_running) {
		finish({
			.status = CloudVaultSyncStatus::Cancelled,
			.vault = std::nullopt,
			.pages = _pages,
			.candidates = _candidates.size(),
		});
	}
}

bool CloudVaultSyncController::running() const {
	return _running;
}

void CloudVaultSyncController::pumpRequests() {
	if (_pumping || !_running) {
		return;
	}
	_pumping = true;
	while (_running && !_requestActive && _requestQueued) {
		_requestQueued = false;
		_requestActive = true;
		const auto guard = _callbackGuard;
		const auto weak = std::weak_ptr<CallbackGuard>(guard);
		_remote.downloadPage(
			_cursor,
			kDownloadPageLimit,
			[weak](
					CloudVaultRemote::Result result,
					CarrierDownloadPage page) {
				if (const auto guard = weak.lock(); guard && guard->controller) {
					guard->controller->pageReceived(
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

void CloudVaultSyncController::pageReceived(
		CloudVaultRemote::Result result,
		CarrierDownloadPage page) {
	if (!_running || !_requestActive) {
		return;
	}
	_requestActive = false;
	if (result != CloudVaultRemote::Result::Accepted) {
		finish({
			.status = (result == CloudVaultRemote::Result::PermanentError)
				? CloudVaultSyncStatus::PermanentTransportError
				: CloudVaultSyncStatus::RetryableTransportError,
			.vault = std::nullopt,
			.pages = _pages,
			.candidates = _candidates.size(),
		});
		return;
	} else if (page.untrustedObjects.size()
			> std::size_t(kDownloadPageLimit)) {
		finish({
			.status = CloudVaultSyncStatus::InvalidPagination,
			.vault = std::nullopt,
			.pages = _pages,
			.candidates = _candidates.size(),
		});
		return;
	} else if (_pages == kMaximumPages) {
		finish({
			.status = CloudVaultSyncStatus::InvalidPagination,
			.vault = std::nullopt,
			.pages = _pages,
			.candidates = _candidates.size(),
		});
		return;
	}
	++_pages;
	for (auto &candidate : page.untrustedObjects) {
		if (candidate.bytes.size() < 0
			|| _candidates.size() == kMaximumCandidates
			|| _candidateBytes > kMaximumCandidateBytes
				- std::uint64_t(candidate.bytes.size())) {
			finish({
				.status = CloudVaultSyncStatus::CapacityExceeded,
				.vault = std::nullopt,
				.pages = _pages,
				.candidates = _candidates.size(),
			});
			return;
		}
		_candidateBytes += std::uint64_t(candidate.bytes.size());
		_candidates.push_back(std::move(candidate.bytes));
	}
	if (page.complete) {
		const auto candidateCount = _candidates.size();
		auto selection = _selector.select(
			std::move(_candidates),
			std::move(_password),
			_telegramUserIdBinding,
			_localAnchor);
		finish({
			.status = MapStatus(selection.status),
			.vault = std::move(selection.vault),
			.pages = _pages,
			.candidates = candidateCount,
		});
		return;
	} else if (page.nextCursor.isEmpty()
		|| page.nextCursor.size() > kMaximumCursorSize
		|| _seenCursors.contains(page.nextCursor)
		|| _storedCursorBytes > kMaximumStoredCursorBytes
			- std::uint64_t(page.nextCursor.size())) {
		finish({
			.status = CloudVaultSyncStatus::InvalidPagination,
			.vault = std::nullopt,
			.pages = _pages,
			.candidates = _candidates.size(),
		});
		return;
	}
	_cursor = std::move(page.nextCursor);
	_storedCursorBytes += std::uint64_t(_cursor.size());
	_seenCursors.emplace(_cursor);
	_requestQueued = true;
	pumpRequests();
}

void CloudVaultSyncController::discoveryReceived(
		CloudVaultRemote::Result result,
		bool present) {
	if (!_running || !_requestActive) {
		return;
	}
	_requestActive = false;
	_pages = 1;
	auto status = CloudVaultSyncStatus::RetryableTransportError;
	if (result == CloudVaultRemote::Result::Accepted) {
		status = present
			? CloudVaultSyncStatus::Present
			: CloudVaultSyncStatus::Missing;
	} else if (result == CloudVaultRemote::Result::PermanentError) {
		status = CloudVaultSyncStatus::PermanentTransportError;
	}
	finish({
		.status = status,
		.vault = std::nullopt,
		.pages = _pages,
		.candidates = present ? 1U : 0U,
	});
}

void CloudVaultSyncController::finish(
		CloudVaultSyncCompletion completion) {
	if (!_running) {
		return;
	}
	_running = false;
	_requestActive = false;
	_requestQueued = false;
	Cleanse(_password);
	_candidates.clear();
	const auto callback = _completionCallback;
	if (callback) {
		callback(std::move(completion));
	}
}

} // namespace E2ECloud
