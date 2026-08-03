/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#pragma once

#include "e2e_cloud/transport/telegram_carrier_transport.h"

#include "base/basic_types.h"

#include <memory>

class History;

namespace Main {
class Session;
} // namespace Main

namespace E2ECloud {

class TelegramSessionCarrierBackend final : public TelegramCarrierBackend {
public:
	TelegramSessionCarrierBackend(
		not_null<Main::Session*> session,
		not_null<History*> history,
		std::uint64_t telegramPeerIdBinding);
	TelegramSessionCarrierBackend(
		not_null<Main::Session*> session,
		not_null<History*> history,
		std::uint64_t telegramPeerIdBinding,
		QString filename,
		QString mimeType,
		int maximumObjectSize,
		int maximumDownloadPageBytes = 64 * 1024 * 1024,
		int minimumMessageIdExclusive = 0,
		bool protectedCarrierFamily = false);
	~TelegramSessionCarrierBackend();

	void uploadDocument(
		QByteArray bytes,
		QString filename,
		QString mimeType,
		UploadCallback callback) override;
	void sendUploadedDocument(
		std::uint64_t telegramPeerId,
		UploadedCarrierFile file,
		QString filename,
		QString mimeType,
		SendCallback callback) override;
	void downloadDocuments(
		std::uint64_t telegramPeerId,
		QByteArray cursor,
		int limit,
		DownloadCallback callback) override;
	void findDocument(
		std::uint64_t telegramPeerId,
		DiscoveryCallback callback) override;

private:
	struct State;
	const std::unique_ptr<State> _state;
};

} // namespace E2ECloud
