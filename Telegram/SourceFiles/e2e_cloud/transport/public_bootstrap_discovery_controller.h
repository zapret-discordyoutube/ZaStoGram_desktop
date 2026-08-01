/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#pragma once

#include "e2e_cloud/transport/public_bootstrap_sync_controller.h"
#include "e2e_cloud/transport/telegram_carrier_transport.h"

#include <functional>
#include <memory>

namespace E2ECloud {

class PublicBootstrapDiscoveryController final {
public:
	using CompletionCallback = std::function<void(
		PublicBootstrapSyncCompletion)>;

	PublicBootstrapDiscoveryController(
		std::uint64_t telegramPeerIdBinding,
		TelegramCarrierBackend &backend,
		const EnvelopeCodec &envelopeCodec,
		const Sha256Provider &sha256,
		CompletionCallback completionCallback);
	~PublicBootstrapDiscoveryController();

	[[nodiscard]] bool start(QByteArray cursor = {});
	void cancel();
	[[nodiscard]] bool running() const;

private:
	struct CallbackGuard;

	void pumpRequests();
	void pageReceived(
		TelegramTransport::UploadResult result,
		CarrierDownloadPage page);
	void finish(PublicBootstrapSyncCompletion completion);

	std::uint64_t _telegramPeerIdBinding = 0;
	TelegramCarrierBackend &_backend;
	const EnvelopeCodec &_envelopeCodec;
	const Sha256Provider &_sha256;
	CompletionCallback _completionCallback;
	std::vector<TelegramTransport::UntrustedObject> _objects;
	std::vector<QByteArray> _seenCursors;
	QByteArray _cursor;
	std::uint64_t _bytes = 0;
	std::uint64_t _pages = 0;
	std::shared_ptr<CallbackGuard> _callbackGuard;
	bool _running = false;
	bool _requestActive = false;
	bool _pumping = false;
	bool _requestQueued = false;
};

} // namespace E2ECloud
