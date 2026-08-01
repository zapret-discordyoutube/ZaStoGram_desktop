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
#include <set>
#include <vector>

namespace E2ECloud {

enum class FileChunkDownloadPageStatus {
	Incomplete,
	Complete,
	SecurityBlocked,
	PersistenceFailed,
};

enum class FileChunkDownloadStatus {
	Complete,
	Missing,
	RetryableTransportError,
	PermanentTransportError,
	InvalidPagination,
	LimitExceeded,
	SecurityBlocked,
	PersistenceFailed,
	Cancelled,
};

struct FileChunkDownloadCompletion {
	FileChunkDownloadStatus status = FileChunkDownloadStatus::Cancelled;
	std::uint64_t pages = 0;
	std::uint64_t objects = 0;
	std::uint64_t bytes = 0;
};

class FileChunkDownloadController final {
public:
	using PageCallback = std::function<FileChunkDownloadPageStatus(
		std::vector<TelegramTransport::UntrustedObject>)>;
	using CompletionCallback = std::function<void(
		FileChunkDownloadCompletion)>;

	FileChunkDownloadController(
		ConversationId conversationId,
		std::uint64_t telegramPeerIdBinding,
		std::int64_t minimumMessageIdExclusive,
		std::uint64_t maximumPages,
		std::uint64_t maximumObjects,
		std::uint64_t maximumBytes,
		TelegramTransport &transport,
		PageCallback pageCallback,
		CompletionCallback completionCallback);
	~FileChunkDownloadController();

	[[nodiscard]] bool start();
	void cancel();
	[[nodiscard]] bool running() const;

private:
	struct CallbackGuard;

	void pumpRequests();
	void pageReceived(TelegramTransport::DownloadResult result);
	void finish(FileChunkDownloadStatus status);

	ConversationId _conversationId;
	std::uint64_t _telegramPeerIdBinding = 0;
	std::int64_t _minimumMessageIdExclusive = 0;
	std::uint64_t _maximumPages = 0;
	std::uint64_t _maximumObjects = 0;
	std::uint64_t _maximumBytes = 0;
	TelegramTransport &_transport;
	PageCallback _pageCallback;
	CompletionCallback _completionCallback;
	std::set<QByteArray> _seenCursors;
	QByteArray _cursor;
	std::shared_ptr<CallbackGuard> _callbackGuard;
	std::uint64_t _pages = 0;
	std::uint64_t _objects = 0;
	std::uint64_t _bytes = 0;
	std::int64_t _lastObservedMessageId = 0;
	bool _running = false;
	bool _requestActive = false;
	bool _requestQueued = false;
	bool _pumping = false;
};

} // namespace E2ECloud
