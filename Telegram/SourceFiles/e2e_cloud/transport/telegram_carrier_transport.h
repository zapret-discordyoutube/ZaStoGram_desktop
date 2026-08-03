/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#pragma once

#include "e2e_cloud/core/interfaces.h"

#include <QtCore/QByteArray>
#include <QtCore/QString>

#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <vector>

namespace E2ECloud {

[[nodiscard]] QString ProtectedLegacyCarrierFilename();
[[nodiscard]] QString ProtectedControlCarrierFilename();
[[nodiscard]] QString ProtectedContentCarrierFilename();
[[nodiscard]] QString ProtectedFileChunkCarrierFilename(FileId fileId);
[[nodiscard]] std::optional<FileId> ProtectedFileChunkCarrierFileId(
	const QString &filename);
[[nodiscard]] QString ProtectedCarrierMimeType();
[[nodiscard]] int ProtectedCarrierMaximumObjectSize();
[[nodiscard]] int ProtectedFileChunkMaximumObjectSize();
[[nodiscard]] bool IsProtectedGroupCarrierFilename(
	const QString &filename);
[[nodiscard]] bool IsProtectedGroupCarrierMetadata(
	const QString &filename,
	const QString &mimeType);

struct UploadedCarrierFile {
	QByteArray backendToken;
};

struct CarrierDownloadPage {
	std::vector<TelegramTransport::UntrustedObject> untrustedObjects;
	QByteArray nextCursor;
	bool complete = false;
};

class TelegramCarrierBackend {
public:
	using Result = TelegramTransport::UploadResult;
	using UploadCallback = std::function<void(
		Result,
		UploadedCarrierFile)>;
	using SendCallback = std::function<void(Result)>;
	using DiscoveryCallback = std::function<void(Result, bool)>;
	using DownloadCallback = std::function<void(
		Result,
		CarrierDownloadPage)>;

	virtual ~TelegramCarrierBackend() = default;

	virtual void uploadDocument(
		QByteArray bytes,
		QString filename,
		QString mimeType,
		UploadCallback callback) = 0;
	virtual void sendUploadedDocument(
		std::uint64_t telegramPeerId,
		UploadedCarrierFile file,
		QString filename,
		QString mimeType,
		SendCallback callback) = 0;
	virtual void downloadDocuments(
		std::uint64_t telegramPeerId,
		QByteArray cursor,
		int limit,
		DownloadCallback callback) = 0;
	virtual void findDocument(
		std::uint64_t telegramPeerId,
		DiscoveryCallback callback) = 0;

};

class TelegramCarrierTransport final : public TelegramTransport {
public:
	TelegramCarrierTransport(
		ConversationId conversationId,
		std::uint64_t telegramPeerId,
		TelegramCarrierBackend &backend);
	~TelegramCarrierTransport();

	void uploadExact(
		EncodedEnvelope envelope,
		UploadCallback callback) override;
	void downloadPage(
		DownloadRequest request,
		DownloadCallback callback) override;

private:
	struct CallbackGuard;
	struct ActiveUpload {
		ObjectId objectId;
		QString filename;
		UploadCallback callback;
	};

	void uploadFinished(
		std::uint64_t uploadToken,
		ObjectId objectId,
		UploadResult result,
		UploadedCarrierFile file);
	void sendFinished(
		std::uint64_t uploadToken,
		ObjectId objectId,
		UploadResult result);
	void finish(
		std::uint64_t uploadToken,
		ObjectId objectId,
		UploadResult result);

	ConversationId _conversationId;
	std::uint64_t _telegramPeerId = 0;
	TelegramCarrierBackend &_backend;
	std::optional<ActiveUpload> _activeUpload;
	std::shared_ptr<CallbackGuard> _callbackGuard;
	std::uint64_t _uploadToken = 0;

};

} // namespace E2ECloud
