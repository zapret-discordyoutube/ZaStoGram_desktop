/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "e2e_cloud/transport/telegram_carrier_transport.h"

#include "e2e_cloud/core/envelope_codec.h"

#include <algorithm>
#include <array>
#include <utility>

namespace E2ECloud {
namespace {

inline constexpr auto kMaximumCarrierObjectSize = 18 * 1024 * 1024;

[[nodiscard]] bool ContentKind(ObjectKind kind) {
	return kind == ObjectKind::MlsApplication
		|| kind == ObjectKind::EncryptedMessageBody
		|| kind == ObjectKind::EncryptedFileManifest
		|| kind == ObjectKind::EncryptedFileChunk;
}

} // namespace

QString ProtectedLegacyCarrierFilename() {
	return QString::fromLatin1("protected.tde2e");
}

QString ProtectedControlCarrierFilename() {
	return QString::fromLatin1("protected-control.tde2e");
}

QString ProtectedContentCarrierFilename() {
	return QString::fromLatin1("protected-content.tde2e");
}

QString ProtectedCarrierMimeType() {
	return QString::fromLatin1("application/octet-stream");
}

int ProtectedCarrierMaximumObjectSize() {
	return kMaximumCarrierObjectSize;
}

bool IsProtectedGroupCarrierMetadata(
		const QString &filename,
		const QString &mimeType) {
	if (mimeType != ProtectedCarrierMimeType()) {
		return false;
	}
	const auto filenames = std::array{
		ProtectedLegacyCarrierFilename(),
		ProtectedControlCarrierFilename(),
		ProtectedContentCarrierFilename(),
	};
	return std::find(begin(filenames), end(filenames), filename)
		!= end(filenames);
}

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
	const auto decoded = EnvelopeCodecV1().decode(envelope);
	if (!decoded) {
		callback(UploadResult::PermanentError);
		return;
	}
	const auto objectId = envelope.objectId;
	const auto filename = ContentKind(decoded->objectKind)
		? ProtectedContentCarrierFilename()
		: ProtectedControlCarrierFilename();
	_activeUpload = ActiveUpload{
		.objectId = objectId,
		.filename = filename,
		.callback = std::move(callback),
	};
	const auto weak = std::weak_ptr<CallbackGuard>(_callbackGuard);
	_backend.uploadDocument(
		std::move(envelope.bytes),
		filename,
		ProtectedCarrierMimeType(),
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

void TelegramCarrierTransport::downloadPage(
		DownloadRequest request,
		DownloadCallback callback) {
	if (!callback) {
		return;
	} else if (request.conversationId != _conversationId
		|| !_telegramPeerId
		|| request.limit <= 0
		|| request.limit > 100
		|| request.cursor.size() > 1024) {
		callback({
			.result = UploadResult::PermanentError,
			.untrustedObjects = {},
			.nextCursor = {},
			.complete = false,
		});
		return;
	}
	const auto weak = std::weak_ptr<CallbackGuard>(_callbackGuard);
	_backend.downloadDocuments(
		_telegramPeerId,
		std::move(request.cursor),
		request.limit,
		[weak, callback = std::move(callback)](
				UploadResult result,
				CarrierDownloadPage page) mutable {
			if (const auto guard = weak.lock(); guard && guard->transport) {
				callback({
					.result = result,
					.untrustedObjects = std::move(page.untrustedObjects),
					.nextCursor = std::move(page.nextCursor),
					.complete = page.complete,
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
	const auto filename = _activeUpload->filename;
	_backend.sendUploadedDocument(
		_telegramPeerId,
		std::move(file),
		filename,
		ProtectedCarrierMimeType(),
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
