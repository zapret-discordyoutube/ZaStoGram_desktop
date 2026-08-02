/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#pragma once

#include "e2e_cloud/core/interfaces.h"
#include "e2e_cloud/core/outbox.h"

#include <functional>
#include <memory>
#include <optional>

namespace E2ECloud {

enum class UploadPumpResult {
	Empty,
	Started,
	UploadInProgress,
	AwaitingFreshness,
	InvalidItem,
	ProtectionFailed,
	PersistenceFailed,
};

struct UploadCompletion {
	ObjectId objectId;
	TelegramTransport::UploadResult transportResult
		= TelegramTransport::UploadResult::RetryableError;
	bool outboxUpdated = false;
};

class OutboxUploadController final {
public:
	using BeforeAcknowledgeCallback = std::function<bool(ObjectId)>;
	using CompletionCallback = std::function<void(UploadCompletion)>;

	OutboxUploadController(
		OutboxCoordinator &outbox,
		TelegramTransport &transport,
		CompletionCallback completionCallback);
	OutboxUploadController(
		OutboxCoordinator &outbox,
		TelegramTransport &transport,
		BeforeAcknowledgeCallback beforeAcknowledgeCallback,
		CompletionCallback completionCallback);
	~OutboxUploadController();

	[[nodiscard]] UploadPumpResult pump();
	[[nodiscard]] bool uploadInProgress() const;

private:
	struct CallbackGuard;

	void complete(
		std::uint64_t uploadToken,
		ObjectId objectId,
		TelegramTransport::UploadResult result);

	OutboxCoordinator &_outbox;
	TelegramTransport &_transport;
	BeforeAcknowledgeCallback _beforeAcknowledgeCallback;
	CompletionCallback _completionCallback;
	std::optional<ObjectId> _activeObjectId;
	std::shared_ptr<CallbackGuard> _callbackGuard;
	std::uint64_t _uploadToken = 0;

};

} // namespace E2ECloud
