/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#pragma once

#include "e2e_cloud/transport/telegram_carrier_transport.h"

#include <QtCore/QByteArray>
#include <QtCore/QString>

#include <cstdint>
#include <functional>
#include <memory>
#include <optional>

namespace E2ECloud {

[[nodiscard]] QString CloudVaultCarrierFilename();
[[nodiscard]] QString CloudVaultCarrierMimeType();
[[nodiscard]] int CloudVaultMaximumCarrierSize();
[[nodiscard]] bool IsProtectedVaultCarrierMetadata(
	const QString &filename,
	const QString &mimeType);
[[nodiscard]] bool IsProtectedCarrierMetadata(
	const QString &filename,
	const QString &mimeType);

class CloudVaultRemote {
public:
	using Result = TelegramTransport::UploadResult;
	using UploadCallback = std::function<void(Result)>;
	using DiscoveryCallback = std::function<void(Result, bool)>;
	using DownloadCallback = std::function<void(Result, CarrierDownloadPage)>;

	virtual ~CloudVaultRemote() = default;

	virtual void uploadExact(
		QByteArray bytes,
		UploadCallback callback) = 0;
	virtual void discover(DiscoveryCallback callback) = 0;
	virtual void downloadPage(
		QByteArray cursor,
		int limit,
		DownloadCallback callback) = 0;
};

class TelegramCloudVaultTransport final : public CloudVaultRemote {
public:
	TelegramCloudVaultTransport(
		std::uint64_t telegramSelfPeerId,
		TelegramCarrierBackend &backend);
	~TelegramCloudVaultTransport();

	void uploadExact(
		QByteArray bytes,
		UploadCallback callback) override;
	void discover(DiscoveryCallback callback) override;
	void downloadPage(
		QByteArray cursor,
		int limit,
		DownloadCallback callback) override;

private:
	struct CallbackGuard;
	struct ActiveUpload {
		UploadCallback callback;
	};

	void uploadFinished(
		std::uint64_t uploadToken,
		Result result,
		UploadedCarrierFile file);
	void sendFinished(std::uint64_t uploadToken, Result result);
	void finish(std::uint64_t uploadToken, Result result);

	std::uint64_t _telegramSelfPeerId = 0;
	TelegramCarrierBackend &_backend;
	std::optional<ActiveUpload> _activeUpload;
	std::shared_ptr<CallbackGuard> _callbackGuard;
	std::uint64_t _uploadToken = 0;
};

} // namespace E2ECloud
