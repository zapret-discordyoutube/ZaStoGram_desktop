/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "e2e_cloud/transport/telegram_carrier_transport.h"

#include "e2e_cloud/core/envelope_codec.h"
#include "e2e_cloud/files/file_chunk_envelope.h"

#include <algorithm>
#include <array>
#include <utility>

namespace E2ECloud {
namespace {

inline constexpr auto kMaximumCarrierObjectSize = 18 * 1024 * 1024;
inline constexpr auto kMaximumFileChunkObjectSize = 5 * 1024 * 1024;
inline constexpr auto kFileChunkPrefix = "protected-file-";
inline constexpr auto kFileChunkSuffix = ".tde2e";

[[nodiscard]] bool ContentKind(ObjectKind kind) {
	return kind == ObjectKind::MlsApplication
		|| kind == ObjectKind::EncryptedMessageBody
		|| kind == ObjectKind::EncryptedFileManifest;
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

QString ProtectedFileChunkCarrierFilename(FileId fileId) {
	if (!fileId) {
		return {};
	}
	const auto bytes = QByteArray(
		reinterpret_cast<const char*>(fileId.bytes.data()),
		fileId.bytes.size());
	return QString::fromLatin1(kFileChunkPrefix)
		+ QString::fromLatin1(bytes.toHex())
		+ QString::fromLatin1(kFileChunkSuffix);
}

std::optional<FileId> ProtectedFileChunkCarrierFileId(
		const QString &filename) {
	const auto prefix = QString::fromLatin1(kFileChunkPrefix);
	const auto suffix = QString::fromLatin1(kFileChunkSuffix);
	constexpr auto kEncodedFileIdSize = int(FileId().bytes.size() * 2);
	if (filename.size() != prefix.size() + kEncodedFileIdSize + suffix.size()
		|| !filename.startsWith(prefix)
		|| !filename.endsWith(suffix)) {
		return std::nullopt;
	}
	const auto encoded = filename.mid(prefix.size(), kEncodedFileIdSize);
	if (!std::all_of(encoded.begin(), encoded.end(), [](QChar value) {
			return (value >= u'0' && value <= u'9')
				|| (value >= u'a' && value <= u'f');
		})) {
		return std::nullopt;
	}
	const auto decoded = QByteArray::fromHex(encoded.toLatin1());
	auto result = FileId();
	if (decoded.size() != int(result.bytes.size())) {
		return std::nullopt;
	}
	std::copy_n(
		reinterpret_cast<const std::uint8_t*>(decoded.constData()),
		result.bytes.size(),
		result.bytes.begin());
	return result ? std::optional<FileId>(result) : std::nullopt;
}

QString ProtectedCarrierMimeType() {
	return QString::fromLatin1("application/octet-stream");
}

int ProtectedCarrierMaximumObjectSize() {
	return kMaximumCarrierObjectSize;
}

int ProtectedFileChunkMaximumObjectSize() {
	return kMaximumFileChunkObjectSize;
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
		!= end(filenames)
		|| ProtectedFileChunkCarrierFileId(filename).has_value();
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
	const auto chunkMetadata = DecodeFileChunkEnvelopeMetadata(*decoded);
	if (decoded->objectKind == ObjectKind::EncryptedFileChunk
		&& (!chunkMetadata
			|| envelope.bytes.size() > kMaximumFileChunkObjectSize)) {
		callback(UploadResult::PermanentError);
		return;
	}
	const auto filename = chunkMetadata
		? ProtectedFileChunkCarrierFilename(chunkMetadata->fileId)
		: ContentKind(decoded->objectKind)
			? ProtectedContentCarrierFilename()
			: ProtectedControlCarrierFilename();
	if (decoded->objectKind == ObjectKind::EncryptedFileChunk
		&& filename.isEmpty()) {
		callback(UploadResult::PermanentError);
		return;
	}
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
