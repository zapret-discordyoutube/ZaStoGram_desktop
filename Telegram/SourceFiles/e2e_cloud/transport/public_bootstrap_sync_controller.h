/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#pragma once

#include "e2e_cloud/protocol/public_group_bootstrap.h"

#include <functional>
#include <memory>

namespace E2ECloud {

enum class PublicBootstrapSyncStatus {
	Verified,
	Missing,
	CapacityExceeded,
	ObjectConflict,
	Ambiguous,
	RetryableTransportError,
	PermanentTransportError,
	InvalidPagination,
	Cancelled,
};

struct PublicBootstrapSyncCompletion {
	PublicBootstrapSyncStatus status = PublicBootstrapSyncStatus::Cancelled;
	std::optional<VerifiedPublicGroupBootstrap> verified;
	std::vector<TelegramTransport::UntrustedObject> untrustedObjects;
	std::uint64_t pages = 0;
	std::uint64_t objects = 0;
};

class PublicBootstrapSyncController final {
public:
	using CompletionCallback = std::function<void(
		PublicBootstrapSyncCompletion)>;

	PublicBootstrapSyncController(
		ConversationId conversationId,
		std::uint64_t telegramPeerIdBinding,
		std::optional<AccountId> expectedOwnerAccountId,
		TelegramTransport &transport,
		const EnvelopeCodec &envelopeCodec,
		const Sha256Provider &sha256,
		CompletionCallback completionCallback);
	~PublicBootstrapSyncController();

	[[nodiscard]] bool start(QByteArray cursor = {});
	void cancel();
	[[nodiscard]] bool running() const;

private:
	struct CallbackGuard;

	void pumpRequests();
	void pageReceived(TelegramTransport::DownloadResult result);
	void finish(PublicBootstrapSyncCompletion completion);

	ConversationId _conversationId;
	std::uint64_t _telegramPeerIdBinding = 0;
	std::optional<AccountId> _expectedOwnerAccountId;
	TelegramTransport &_transport;
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
