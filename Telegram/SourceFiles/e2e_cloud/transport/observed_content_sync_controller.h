/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#pragma once

#include "e2e_cloud/core/interfaces.h"

#include <QtCore/QByteArray>

#include <cstdint>
#include <functional>
#include <memory>
#include <vector>

namespace E2ECloud {

enum class ObservedContentPageResult {
	Persisted,
	SecurityBlocked,
	PersistenceFailed,
};

enum class ObservedContentSyncStatus {
	Complete,
	RetryableTransportError,
	PermanentTransportError,
	InvalidPagination,
	SecurityBlocked,
	PersistenceFailed,
	Cancelled,
};

struct ObservedContentSyncCompletion {
	ObservedContentSyncStatus status = ObservedContentSyncStatus::Cancelled;
	std::uint64_t pages = 0;
	std::uint64_t objects = 0;
	std::int64_t previousBoundaryMessageId = 0;
	std::int64_t newestObservedMessageId = 0;
	std::int64_t nextBoundaryMessageId = 0;
};

class ObservedContentSyncController final {
public:
	using PageCallback = std::function<ObservedContentPageResult(
		std::vector<TelegramTransport::UntrustedObject>)>;
	using CompletionCallback = std::function<void(
		ObservedContentSyncCompletion)>;

	ObservedContentSyncController(
		ConversationId conversationId,
		std::uint64_t telegramPeerIdBinding,
		TelegramTransport &transport,
		PageCallback pageCallback,
		CompletionCallback completionCallback);
	~ObservedContentSyncController();

	[[nodiscard]] bool start(std::int64_t boundaryMessageId = 0);
	void cancel();
	[[nodiscard]] bool running() const;

private:
	struct CallbackGuard;

	void pumpRequests();
	void pageReceived(TelegramTransport::DownloadResult result);
	void finish(ObservedContentSyncStatus status);

	ConversationId _conversationId;
	std::uint64_t _telegramPeerIdBinding = 0;
	TelegramTransport &_transport;
	PageCallback _pageCallback;
	CompletionCallback _completionCallback;
	std::vector<QByteArray> _seenCursors;
	QByteArray _cursor;
	std::shared_ptr<CallbackGuard> _callbackGuard;
	std::uint64_t _pages = 0;
	std::uint64_t _objects = 0;
	std::vector<std::int64_t> _boundaryCandidates;
	std::int64_t _boundaryMessageId = 0;
	std::int64_t _newestObservedMessageId = 0;
	std::int64_t _lastObservedMessageId = 0;
	bool _running = false;
	bool _requestActive = false;
	bool _requestQueued = false;
	bool _pumping = false;
};

} // namespace E2ECloud
