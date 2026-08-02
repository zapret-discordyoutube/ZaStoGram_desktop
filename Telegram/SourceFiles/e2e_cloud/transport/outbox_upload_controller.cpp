/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "e2e_cloud/transport/outbox_upload_controller.h"

#include <utility>

namespace E2ECloud {

struct OutboxUploadController::CallbackGuard {
	OutboxUploadController *controller = nullptr;
};

OutboxUploadController::OutboxUploadController(
		OutboxCoordinator &outbox,
		TelegramTransport &transport,
		CompletionCallback completionCallback)
: OutboxUploadController(
	  outbox,
	  transport,
	  nullptr,
	  std::move(completionCallback)) {
}

OutboxUploadController::OutboxUploadController(
		OutboxCoordinator &outbox,
		TelegramTransport &transport,
		BeforeAcknowledgeCallback beforeAcknowledgeCallback,
		CompletionCallback completionCallback)
: _outbox(outbox)
, _transport(transport)
, _beforeAcknowledgeCallback(std::move(beforeAcknowledgeCallback))
, _completionCallback(std::move(completionCallback))
, _callbackGuard(std::make_shared<CallbackGuard>(CallbackGuard{ this })) {
}

OutboxUploadController::~OutboxUploadController() {
	_callbackGuard->controller = nullptr;
	if (_activeObjectId) {
		(void)_outbox.markUploadFailed(*_activeObjectId);
	}
}

UploadPumpResult OutboxUploadController::pump() {
	if (_activeObjectId) {
		return UploadPumpResult::UploadInProgress;
	}
	auto dispatch = _outbox.dispatchNext();
	switch (dispatch.result) {
	case OutboxDispatchResult::Empty:
		return UploadPumpResult::Empty;
	case OutboxDispatchResult::UploadInProgress:
		return UploadPumpResult::UploadInProgress;
	case OutboxDispatchResult::AwaitingFreshness:
		return UploadPumpResult::AwaitingFreshness;
	case OutboxDispatchResult::InvalidItem:
		return UploadPumpResult::InvalidItem;
	case OutboxDispatchResult::ProtectionFailed:
		return UploadPumpResult::ProtectionFailed;
	case OutboxDispatchResult::PersistenceFailed:
		return UploadPumpResult::PersistenceFailed;
	case OutboxDispatchResult::Ready:
		break;
	}
	if (!dispatch.envelope) {
		return UploadPumpResult::InvalidItem;
	}
	const auto objectId = dispatch.envelope->objectId;
	_activeObjectId = objectId;
	if (++_uploadToken == 0) {
		++_uploadToken;
	}
	const auto uploadToken = _uploadToken;
	const auto weak = std::weak_ptr<CallbackGuard>(_callbackGuard);
	_transport.uploadExact(
		std::move(*dispatch.envelope),
		[weak, uploadToken, objectId](
				TelegramTransport::UploadResult result) {
			if (const auto guard = weak.lock(); guard && guard->controller) {
				guard->controller->complete(
					uploadToken,
					objectId,
					result);
			}
		});
	return UploadPumpResult::Started;
}

bool OutboxUploadController::uploadInProgress() const {
	return _activeObjectId.has_value();
}

void OutboxUploadController::complete(
		std::uint64_t uploadToken,
		ObjectId objectId,
		TelegramTransport::UploadResult result) {
	if (!_activeObjectId
		|| *_activeObjectId != objectId
		|| uploadToken != _uploadToken) {
		return;
	}
	const auto guard = _callbackGuard;
	const auto prepared = (result != TelegramTransport::UploadResult::Accepted)
		|| !_beforeAcknowledgeCallback
		|| _beforeAcknowledgeCallback(objectId);
	if (guard->controller != this) {
		return;
	}
	const auto updated = (result == TelegramTransport::UploadResult::Accepted
		&& prepared)
		? _outbox.acknowledgeUploaded(objectId)
		: _outbox.markUploadFailed(objectId) && prepared;
	_activeObjectId.reset();
	const auto callback = _completionCallback;
	if (callback) {
		callback({
			.objectId = objectId,
			.transportResult = result,
			.outboxUpdated = updated,
		});
	}
}

} // namespace E2ECloud
