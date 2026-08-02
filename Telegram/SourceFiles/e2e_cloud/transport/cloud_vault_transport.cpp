/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "e2e_cloud/transport/cloud_vault_transport.h"

#include <utility>

namespace E2ECloud {
namespace {

inline constexpr auto kCloudVaultMaximumCarrierSize = 4 * 1024 * 1024;

} // namespace

QString CloudVaultCarrierFilename() {
	return QString::fromLatin1("protected-vault.tde2e");
}

QString CloudVaultCarrierMimeType() {
	return QString::fromLatin1("application/octet-stream");
}

int CloudVaultMaximumCarrierSize() {
	return kCloudVaultMaximumCarrierSize;
}

bool IsProtectedVaultCarrierMetadata(
		const QString &filename,
		const QString &mimeType) {
	return filename == CloudVaultCarrierFilename()
		&& mimeType == CloudVaultCarrierMimeType();
}

bool IsProtectedCarrierMetadata(
		const QString &filename,
		const QString &mimeType) {
	return IsProtectedVaultCarrierMetadata(filename, mimeType)
		|| IsProtectedGroupCarrierMetadata(filename, mimeType);
}

struct TelegramCloudVaultTransport::CallbackGuard {
	TelegramCloudVaultTransport *transport = nullptr;
};

TelegramCloudVaultTransport::TelegramCloudVaultTransport(
		std::uint64_t telegramSelfPeerId,
		TelegramCarrierBackend &backend)
: _telegramSelfPeerId(telegramSelfPeerId)
, _backend(backend)
, _callbackGuard(std::make_shared<CallbackGuard>(CallbackGuard{ this })) {
}

TelegramCloudVaultTransport::~TelegramCloudVaultTransport() {
	_callbackGuard->transport = nullptr;
}

void TelegramCloudVaultTransport::uploadExact(
		QByteArray bytes,
		UploadCallback callback) {
	if (!callback) {
		return;
	} else if (!_telegramSelfPeerId
		|| bytes.isEmpty()
		|| bytes.size() > kCloudVaultMaximumCarrierSize) {
		callback(Result::PermanentError);
		return;
	} else if (_activeUpload) {
		callback(Result::RetryableError);
		return;
	}
	_activeUpload = ActiveUpload{ .callback = std::move(callback) };
	if (++_uploadToken == 0) {
		++_uploadToken;
	}
	const auto uploadToken = _uploadToken;
	const auto weak = std::weak_ptr<CallbackGuard>(_callbackGuard);
	_backend.uploadDocument(
		std::move(bytes),
		CloudVaultCarrierFilename(),
		CloudVaultCarrierMimeType(),
		[weak, uploadToken](Result result, UploadedCarrierFile file) {
			if (const auto guard = weak.lock(); guard && guard->transport) {
				guard->transport->uploadFinished(
					uploadToken,
					result,
					std::move(file));
			}
		});
}

void TelegramCloudVaultTransport::discover(DiscoveryCallback callback) {
	if (!callback) {
		return;
	} else if (!_telegramSelfPeerId) {
		callback(Result::PermanentError, false);
		return;
	}
	const auto weak = std::weak_ptr<CallbackGuard>(_callbackGuard);
	_backend.findDocument(
		_telegramSelfPeerId,
		[weak, callback = std::move(callback)](
				Result result,
				bool present) mutable {
			if (const auto guard = weak.lock(); guard && guard->transport) {
				callback(result, present);
			}
		});
}

void TelegramCloudVaultTransport::downloadPage(
		QByteArray cursor,
		int limit,
		DownloadCallback callback) {
	if (!callback) {
		return;
	} else if (!_telegramSelfPeerId
		|| cursor.size() > 1024
		|| limit <= 0
		|| limit > 100) {
		callback(Result::PermanentError, {});
		return;
	}
	const auto weak = std::weak_ptr<CallbackGuard>(_callbackGuard);
	_backend.downloadDocuments(
		_telegramSelfPeerId,
		std::move(cursor),
		limit,
		[weak, callback = std::move(callback)](
				Result result,
				CarrierDownloadPage page) mutable {
			if (const auto guard = weak.lock(); guard && guard->transport) {
				callback(result, std::move(page));
			}
		});
}

void TelegramCloudVaultTransport::uploadFinished(
		std::uint64_t uploadToken,
		Result result,
		UploadedCarrierFile file) {
	if (!_activeUpload || uploadToken != _uploadToken) {
		return;
	} else if (result != Result::Accepted) {
		finish(uploadToken, result);
		return;
	} else if (file.backendToken.isEmpty()) {
		finish(uploadToken, Result::PermanentError);
		return;
	}
	const auto weak = std::weak_ptr<CallbackGuard>(_callbackGuard);
	_backend.sendUploadedDocument(
		_telegramSelfPeerId,
		std::move(file),
		CloudVaultCarrierFilename(),
		CloudVaultCarrierMimeType(),
		[weak, uploadToken](Result sendResult) {
			if (const auto guard = weak.lock(); guard && guard->transport) {
				guard->transport->sendFinished(uploadToken, sendResult);
			}
		});
}

void TelegramCloudVaultTransport::sendFinished(
		std::uint64_t uploadToken,
		Result result) {
	finish(uploadToken, result);
}

void TelegramCloudVaultTransport::finish(
		std::uint64_t uploadToken,
		Result result) {
	if (!_activeUpload || uploadToken != _uploadToken) {
		return;
	}
	auto callback = std::move(_activeUpload->callback);
	_activeUpload.reset();
	callback(result);
}

} // namespace E2ECloud
