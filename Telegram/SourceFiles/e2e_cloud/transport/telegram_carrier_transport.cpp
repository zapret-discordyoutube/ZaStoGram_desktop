/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "e2e_cloud/transport/telegram_carrier_transport.h"

#include <utility>

namespace E2ECloud {
namespace {

inline constexpr auto kMaximumCarrierObjectSize = 18 * 1024 * 1024;

[[nodiscard]] QString CarrierFilename() {
	return QString::fromLatin1("protected.tde2e");
}

[[nodiscard]] QString CarrierMimeType() {
	return QString::fromLatin1("application/octet-stream");
}

} // namespace

struct TelegramCarrierTransport::CallbackGuard {
	TelegramCarrierTransport *transport = nullptr;
};

TelegramCarrierTransport::TelegramCarrierTransport(
		ConversationId conversationId,
		std::uint64_t telegramPeerId,
		TelegramCarrierBackend &backend)
: _conversationId(conversationId)
, _telegramPeerId(telegramPeerId)
, _backend(backend)
, _callbackGuard(std::make_shared<CallbackGuard>(CallbackGuard{ this })) {
}

TelegramCarrierTransport::~TelegramCarrierTransport() {
	_callbackGuard->transport = nullptr;
}

void TelegramCarrierTransport::uploadExact(
		EncodedEnvelope envelope,
		UploadCallback callback) {
	if (!callback) {
		return;
	} else if (!_conversationId
		|| !_telegramPeerId
		|| envelope.conversationId != _conversationId
		|| !envelope.objectId
		|| envelope.bytes.isEmpty()
		|| envelope.bytes.size() > kMaximumCarrierObjectSize) {
		callback(UploadResult::PermanentError);
		return;
	} else if (_activeUpload) {
		callback(UploadResult::RetryableError);
		return;
	}
	const auto objectId = envelope.objectId;
	_activeUpload = ActiveUpload{
		.objectId = objectId,
		.callback = std::move(callback),
	};
	const auto weak = std::weak_ptr<CallbackGuard>(_callbackGuard);
	_backend.uploadDocument(
		std::move(envelope.bytes),
		CarrierFilename(),
		CarrierMimeType(),
		[weak, objectId](
				UploadResult result,
				UploadedCarrierFile file) {
			if (const auto guard = weak.lock(); guard && guard->transport) {
				guard->transport->uploadFinished(
					objectId,
					result,
					std::move(file));
			}
		});
}

void TelegramCarrierTransport::download(
		ConversationId conversationId,
		DownloadCallback callback) {
	if (!callback) {
		return;
	} else if (conversationId != _conversationId || !_telegramPeerId) {
		callback({
			.result = UploadResult::PermanentError,
			.untrustedObjects = {},
		});
		return;
	}
	const auto weak = std::weak_ptr<CallbackGuard>(_callbackGuard);
	_backend.downloadDocuments(
		_telegramPeerId,
		[weak, callback = std::move(callback)](
				UploadResult result,
				std::vector<QByteArray> objects) mutable {
			if (const auto guard = weak.lock(); guard && guard->transport) {
				callback({
					.result = result,
					.untrustedObjects = std::move(objects),
				});
			}
		});
}

void TelegramCarrierTransport::uploadFinished(
		ObjectId objectId,
		UploadResult result,
		UploadedCarrierFile file) {
	if (!_activeUpload || _activeUpload->objectId != objectId) {
		return;
	} else if (result != UploadResult::Accepted) {
		finish(objectId, result);
		return;
	} else if (file.backendToken.isEmpty()) {
		finish(objectId, UploadResult::PermanentError);
		return;
	}
	const auto weak = std::weak_ptr<CallbackGuard>(_callbackGuard);
	_backend.sendUploadedDocument(
		_telegramPeerId,
		std::move(file),
		CarrierFilename(),
		CarrierMimeType(),
		[weak, objectId](UploadResult sendResult) {
			if (const auto guard = weak.lock(); guard && guard->transport) {
				guard->transport->sendFinished(objectId, sendResult);
			}
		});
}

void TelegramCarrierTransport::sendFinished(
		ObjectId objectId,
		UploadResult result) {
	finish(objectId, result);
}

void TelegramCarrierTransport::finish(
		ObjectId objectId,
		UploadResult result) {
	if (!_activeUpload || _activeUpload->objectId != objectId) {
		return;
	}
	auto callback = std::move(_activeUpload->callback);
	_activeUpload.reset();
	callback(result);
}

} // namespace E2ECloud
