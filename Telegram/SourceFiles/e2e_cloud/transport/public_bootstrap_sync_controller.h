/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#pragma once

#include "e2e_cloud/protocol/public_group_bootstrap.h"

#include <cstdint>
#include <functional>
#include <memory>
#include <set>

namespace E2ECloud {

enum class PublicBootstrapSyncStatus {
	Verified,
	Incremental,
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
	std::int64_t previousBoundaryMessageId = 0;
	std::int64_t newestObservedMessageId = 0;
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
	[[nodiscard]] bool startForJoin(QByteArray cursor = {});
	[[nodiscard]] bool startFromBoundary(std::int64_t boundaryMessageId);
	[[nodiscard]] bool startForJoinFromBoundary(
		std::int64_t boundaryMessageId);
	void cancel();
	[[nodiscard]] bool running() const;

private:
	struct CallbackGuard;

	void pumpRequests();
	void pageReceived(
		std::uint64_t requestToken,
		TelegramTransport::DownloadResult result);
	void finish(PublicBootstrapSyncCompletion completion);
	[[nodiscard]] bool startInternal(
		QByteArray cursor,
		std::int64_t boundaryMessageId,
		bool joinRelevantOnly);

	ConversationId _conversationId;
	std::uint64_t _telegramPeerIdBinding = 0;
	std::optional<AccountId> _expectedOwnerAccountId;
	TelegramTransport &_transport;
	const EnvelopeCodec &_envelopeCodec;
	const Sha256Provider &_sha256;
	CompletionCallback _completionCallback;
	std::vector<TelegramTransport::UntrustedObject> _objects;
	std::set<QByteArray> _seenCursors;
	QByteArray _cursor;
	std::uint64_t _bytes = 0;
	std::uint64_t _pages = 0;
	std::uint64_t _storedCursorBytes = 0;
	std::uint64_t _requestToken = 0;
	std::int64_t _boundaryMessageId = 0;
	std::int64_t _newestObservedMessageId = 0;
	std::int64_t _lastObservedMessageId = 0;
	std::shared_ptr<CallbackGuard> _callbackGuard;
	bool _running = false;
	bool _requestActive = false;
	bool _pumping = false;
	bool _requestQueued = false;
	bool _joinRelevantOnly = false;

};

} // namespace E2ECloud
