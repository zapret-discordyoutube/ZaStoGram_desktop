/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#pragma once

#include "e2e_cloud/core/interfaces.h"
#include "e2e_cloud/protocol/inbound_envelope_processor.h"

#include <QtCore/QByteArray>

#include <cstdint>
#include <functional>
#include <memory>
#include <set>

namespace E2ECloud {

enum class CarrierSyncStartResult {
	Started,
	AlreadyRunning,
	InvalidCursor,
};

enum class CarrierSyncFinishReason {
	Complete,
	RetryRequired,
	RetryableTransportError,
	PermanentTransportError,
	InvalidPagination,
	SecurityBlocked,
	LocalRecoveryRequired,
	Cancelled,
};

struct CarrierSyncStats {
	std::uint64_t pages = 0;
	std::uint64_t objects = 0;
	std::uint64_t accepted = 0;
	std::uint64_t duplicates = 0;
	std::uint64_t deferred = 0;
	std::uint64_t rejected = 0;
	QByteArray nextCursor;
};

struct CarrierSyncCompletion {
	CarrierSyncFinishReason reason = CarrierSyncFinishReason::Cancelled;
	CarrierSyncStats stats;
};

class CarrierSyncController final {
public:
	using CompletionCallback = std::function<void(CarrierSyncCompletion)>;

	CarrierSyncController(
		ConversationId conversationId,
		TelegramTransport &transport,
		InboundEnvelopeProcessor &processor,
		CompletionCallback completionCallback);
	~CarrierSyncController();

	[[nodiscard]] CarrierSyncStartResult start(QByteArray cursor = {});
	void cancel();
	[[nodiscard]] InboundProcessResult ingestLive(const QByteArray &bytes);

	[[nodiscard]] bool running() const;
	[[nodiscard]] const CarrierSyncStats &stats() const;

private:
	struct CallbackGuard;

	void pumpRequests();
	void pageReceived(TelegramTransport::DownloadResult result);
	[[nodiscard]] bool processObject(const QByteArray &bytes);
	void finish(CarrierSyncFinishReason reason);

	ConversationId _conversationId;
	TelegramTransport &_transport;
	InboundEnvelopeProcessor &_processor;
	CompletionCallback _completionCallback;
	CarrierSyncStats _stats;
	std::set<QByteArray> _seenCursors;
	std::shared_ptr<CallbackGuard> _callbackGuard;
	std::uint64_t _storedCursorBytes = 0;
	bool _running = false;
	bool _requestActive = false;
	bool _pumping = false;
	bool _requestQueued = false;
};

} // namespace E2ECloud
