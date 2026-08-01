/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#pragma once

#include "e2e_cloud/core/freshness_gate.h"
#include "e2e_cloud/core/interfaces.h"

#include <QtCore/QByteArray>

#include <optional>

namespace E2ECloud {

struct PendingMessage {
	ConversationId conversationId;
	ObjectId objectId;
	QByteArray plaintext;
	QByteArray authenticatedData;
};

enum class OutboxItemStage {
	Draft,
	Sealed,
};

struct OutboxItem {
	PendingMessage draft;
	OutboxItemStage stage = OutboxItemStage::Draft;
	std::optional<EncodedEnvelope> sealed;
};

class ProtectedOutboxStore {
public:
	virtual ~ProtectedOutboxStore() = default;

	virtual bool append(PendingMessage message) = 0;
	virtual bool appendSealed(EncodedEnvelope envelope) = 0;
	virtual bool appendSealedThenDraft(
		EncodedEnvelope envelope,
		PendingMessage message) = 0;
	[[nodiscard]] virtual std::optional<OutboxItem> front(
		ConversationId conversationId) const = 0;
	virtual bool replaceWithSealed(
		ObjectId objectId,
		EncodedEnvelope envelope) = 0;
	virtual bool remove(ObjectId objectId) = 0;
	[[nodiscard]] virtual bool contains(ObjectId objectId) const = 0;

};

enum class EnqueueResult {
	Queued,
	InvalidMessage,
	PersistenceFailed,
};

enum class OutboxDispatchResult {
	Empty,
	Ready,
	UploadInProgress,
	AwaitingFreshness,
	InvalidItem,
	ProtectionFailed,
	PersistenceFailed,
};

struct OutboxDispatch {
	OutboxDispatchResult result = OutboxDispatchResult::Empty;
	std::optional<EncodedEnvelope> envelope;
};

class OutboxCoordinator final {
public:
	OutboxCoordinator(
		FreshnessGate &freshness,
		ProtectedOutboxStore &store,
		OutboundMessageProtector &protector);

	[[nodiscard]] EnqueueResult enqueue(PendingMessage message);
	[[nodiscard]] EnqueueResult enqueueSealed(EncodedEnvelope envelope);
	[[nodiscard]] EnqueueResult enqueueSealedThenDraft(
		EncodedEnvelope envelope,
		PendingMessage message);
	[[nodiscard]] OutboxDispatch dispatchNext();
	[[nodiscard]] bool acknowledgeUploaded(ObjectId objectId);
	[[nodiscard]] bool markUploadFailed(ObjectId objectId);

private:
	[[nodiscard]] bool validIdentity(const PendingMessage &message) const;
	[[nodiscard]] bool validDraft(const PendingMessage &message) const;
	[[nodiscard]] bool validSealed(
		const OutboxItem &item,
		const EncodedEnvelope &envelope) const;

	FreshnessGate &_freshness;
	ProtectedOutboxStore &_store;
	OutboundMessageProtector &_protector;
	std::optional<ObjectId> _inFlightObjectId;

};

} // namespace E2ECloud
