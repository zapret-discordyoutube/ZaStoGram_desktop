/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "e2e_cloud/transport/carrier_sync_controller.h"

#include <algorithm>
#include <utility>

namespace E2ECloud {
namespace {

inline constexpr auto kDownloadPageLimit = 100;
inline constexpr auto kMaximumCursorSize = 1024;
inline constexpr auto kMaximumPagesPerRun = std::uint64_t(1'000'000);

} // namespace

struct CarrierSyncController::CallbackGuard {
	CarrierSyncController *controller = nullptr;
};

CarrierSyncController::CarrierSyncController(
		ConversationId conversationId,
		TelegramTransport &transport,
		InboundEnvelopeProcessor &processor,
		CompletionCallback completionCallback)
: _conversationId(conversationId)
, _transport(transport)
, _processor(processor)
, _completionCallback(std::move(completionCallback))
, _callbackGuard(std::make_shared<CallbackGuard>(CallbackGuard{ this })) {
}

CarrierSyncController::~CarrierSyncController() {
	_callbackGuard->controller = nullptr;
	if (_running) {
		_running = false;
		_requestActive = false;
	}
}

CarrierSyncStartResult CarrierSyncController::start(QByteArray cursor) {
	if (_running) {
		return CarrierSyncStartResult::AlreadyRunning;
	} else if (!_conversationId || cursor.size() > kMaximumCursorSize) {
		return CarrierSyncStartResult::InvalidCursor;
	}
	_stats = CarrierSyncStats{ .nextCursor = std::move(cursor) };
	_seenCursors.clear();
	_seenCursors.push_back(_stats.nextCursor);
	_running = true;
	_requestActive = false;
	_requestQueued = true;
	pumpRequests();
	return CarrierSyncStartResult::Started;
}

void CarrierSyncController::cancel() {
	if (_running) {
		finish(CarrierSyncFinishReason::Cancelled);
	}
}

InboundProcessResult CarrierSyncController::ingestLive(
		const QByteArray &bytes) {
	const auto result = _processor.process(bytes);
	if (_running) {
		++_stats.objects;
		switch (result) {
		case InboundProcessResult::Accepted:
			++_stats.accepted;
			break;
		case InboundProcessResult::Duplicate:
			++_stats.duplicates;
			break;
		case InboundProcessResult::Deferred:
			++_stats.deferred;
			break;
		case InboundProcessResult::InvalidEncoding:
		case InboundProcessResult::WrongConversation:
		case InboundProcessResult::WrongCarrier:
		case InboundProcessResult::AuthenticationFailed:
		case InboundProcessResult::Rejected:
			++_stats.rejected;
			break;
		case InboundProcessResult::ObjectIdConflict:
		case InboundProcessResult::ForkDetected:
			finish(CarrierSyncFinishReason::SecurityBlocked);
			break;
		case InboundProcessResult::RecoveryRequired:
		case InboundProcessResult::JournalFailure:
			finish(CarrierSyncFinishReason::LocalRecoveryRequired);
			break;
		}
	}
	return result;
}

bool CarrierSyncController::running() const {
	return _running;
}

const CarrierSyncStats &CarrierSyncController::stats() const {
	return _stats;
}

void CarrierSyncController::pumpRequests() {
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
			.cursor = _stats.nextCursor,
			.limit = kDownloadPageLimit,
		}, [weak](TelegramTransport::DownloadResult result) {
			if (const auto guard = weak.lock(); guard && guard->controller) {
				guard->controller->pageReceived(std::move(result));
			}
		});
		if (guard->controller != this) {
			return;
		}
		if (_requestActive) {
			break;
		}
	}
	_pumping = false;
}

void CarrierSyncController::pageReceived(
		TelegramTransport::DownloadResult result) {
	if (!_running || !_requestActive) {
		return;
	}
	_requestActive = false;
	if (result.result != TelegramTransport::UploadResult::Accepted) {
		finish((result.result == TelegramTransport::UploadResult::PermanentError)
			? CarrierSyncFinishReason::PermanentTransportError
			: CarrierSyncFinishReason::RetryableTransportError);
		return;
	} else if (_stats.pages == kMaximumPagesPerRun) {
		finish(CarrierSyncFinishReason::InvalidPagination);
		return;
	}
	++_stats.pages;
	for (const auto &object : result.untrustedObjects) {
		if (!processObject(object.bytes)) {
			return;
		}
	}
	if (result.complete) {
		_stats.nextCursor = std::move(result.nextCursor);
		finish(CarrierSyncFinishReason::Complete);
		return;
	} else if (result.nextCursor.isEmpty()
		|| result.nextCursor.size() > kMaximumCursorSize
		|| std::find(
			std::begin(_seenCursors),
			std::end(_seenCursors),
			result.nextCursor) != std::end(_seenCursors)) {
		finish(CarrierSyncFinishReason::InvalidPagination);
		return;
	}
	_stats.nextCursor = std::move(result.nextCursor);
	_seenCursors.push_back(_stats.nextCursor);
	_requestQueued = true;
	pumpRequests();
}

bool CarrierSyncController::processObject(const QByteArray &bytes) {
	++_stats.objects;
	switch (_processor.process(bytes)) {
	case InboundProcessResult::Accepted:
		++_stats.accepted;
		return true;
	case InboundProcessResult::Duplicate:
		++_stats.duplicates;
		return true;
	case InboundProcessResult::Deferred:
		++_stats.deferred;
		return true;
	case InboundProcessResult::InvalidEncoding:
	case InboundProcessResult::WrongConversation:
	case InboundProcessResult::WrongCarrier:
	case InboundProcessResult::AuthenticationFailed:
	case InboundProcessResult::Rejected:
		++_stats.rejected;
		return true;
	case InboundProcessResult::ObjectIdConflict:
	case InboundProcessResult::ForkDetected:
		finish(CarrierSyncFinishReason::SecurityBlocked);
		return false;
	case InboundProcessResult::RecoveryRequired:
	case InboundProcessResult::JournalFailure:
		finish(CarrierSyncFinishReason::LocalRecoveryRequired);
		return false;
	}
	finish(CarrierSyncFinishReason::LocalRecoveryRequired);
	return false;
}

void CarrierSyncController::finish(CarrierSyncFinishReason reason) {
	if (!_running) {
		return;
	}
	_running = false;
	_requestActive = false;
	_requestQueued = false;
	const auto callback = _completionCallback;
	if (callback) {
		callback({
			.reason = reason,
			.stats = _stats,
		});
	}
}

} // namespace E2ECloud
