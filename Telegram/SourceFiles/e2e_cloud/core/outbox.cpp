/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "e2e_cloud/core/outbox.h"

#include <utility>

namespace E2ECloud {

OutboxCoordinator::OutboxCoordinator(
		FreshnessGate &freshness,
		ProtectedOutboxStore &store,
		OutboundMessageProtector &protector)
: _freshness(freshness)
, _store(store)
, _protector(protector) {
}

EnqueueResult OutboxCoordinator::enqueue(PendingMessage message) {
	if (!validDraft(message)) {
		return EnqueueResult::InvalidMessage;
	}
	return _store.append(std::move(message))
		? EnqueueResult::Queued
		: EnqueueResult::PersistenceFailed;
}

OutboxDispatch OutboxCoordinator::dispatchNext() {
	if (!_freshness.sendingAllowed()) {
		return {
			.result = OutboxDispatchResult::AwaitingFreshness,
			.envelope = std::nullopt,
		};
	} else if (_inFlightObjectId) {
		return {
			.result = OutboxDispatchResult::UploadInProgress,
			.envelope = std::nullopt,
		};
	}
	const auto conversationId = _freshness.knownCheckpoint().conversationId;
	const auto item = _store.front(conversationId);
	if (!item) {
		return {
			.result = OutboxDispatchResult::Empty,
			.envelope = std::nullopt,
		};
	} else if (!validIdentity(item->draft)) {
		return {
			.result = OutboxDispatchResult::InvalidItem,
			.envelope = std::nullopt,
		};
	}
	auto sealed = item->sealed;
	if (item->stage == OutboxItemStage::Draft) {
		if (sealed || !validDraft(item->draft)) {
			return {
				.result = OutboxDispatchResult::InvalidItem,
				.envelope = std::nullopt,
			};
		}
		sealed = _protector.protectIdempotently({
			.conversationId = item->draft.conversationId,
			.objectId = item->draft.objectId,
			.plaintext = item->draft.plaintext,
			.authenticatedData = item->draft.authenticatedData,
		});
		if (!sealed) {
			return {
				.result = OutboxDispatchResult::ProtectionFailed,
				.envelope = std::nullopt,
			};
		} else if (!validSealed(*item, *sealed)) {
			return {
				.result = OutboxDispatchResult::InvalidItem,
				.envelope = std::nullopt,
			};
		} else if (!_store.replaceWithSealed(
				item->draft.objectId,
				*sealed)) {
			return {
				.result = OutboxDispatchResult::PersistenceFailed,
				.envelope = std::nullopt,
			};
		}
	} else if (!sealed || !validSealed(*item, *sealed)) {
		return {
			.result = OutboxDispatchResult::InvalidItem,
			.envelope = std::nullopt,
		};
	}
	_inFlightObjectId = sealed->objectId;
	return {
		.result = OutboxDispatchResult::Ready,
		.envelope = std::move(sealed),
	};
}

bool OutboxCoordinator::acknowledgeUploaded(ObjectId objectId) {
	if (!_inFlightObjectId || *_inFlightObjectId != objectId) {
		return false;
	} else if (!_store.remove(objectId)) {
		return false;
	}
	_inFlightObjectId.reset();
	return true;
}

bool OutboxCoordinator::markUploadFailed(ObjectId objectId) {
	if (!_inFlightObjectId || *_inFlightObjectId != objectId) {
		return false;
	}
	_inFlightObjectId.reset();
	return true;
}

bool OutboxCoordinator::validIdentity(const PendingMessage &message) const {
	return message.conversationId
		&& message.objectId
		&& message.conversationId
			== _freshness.knownCheckpoint().conversationId;
}

bool OutboxCoordinator::validDraft(const PendingMessage &message) const {
	return validIdentity(message)
		&& (!message.plaintext.isEmpty()
			|| !message.authenticatedData.isEmpty());
}

bool OutboxCoordinator::validSealed(
		const OutboxItem &item,
		const EncodedEnvelope &envelope) const {
	return envelope.conversationId == item.draft.conversationId
		&& envelope.objectId == item.draft.objectId
		&& !envelope.bytes.isEmpty();
}

} // namespace E2ECloud
