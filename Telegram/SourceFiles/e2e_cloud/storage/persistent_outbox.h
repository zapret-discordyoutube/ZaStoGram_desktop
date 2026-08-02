/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#pragma once

#include "e2e_cloud/core/outbox.h"
#include "e2e_cloud/storage/local_storage.h"

#include <cstdint>
#include <vector>

namespace E2ECloud {

enum class PersistentOutboxLoadResult {
	Loaded,
	Empty,
	StorageError,
	AuthenticationFailed,
	InvalidSnapshot,
};

class PersistentOutboxStore final : public ProtectedOutboxStore {
public:
	PersistentOutboxStore(
		AtomicBlobStore &blobStore,
		const LocalRecordProtector &protector);
	~PersistentOutboxStore() override;

	[[nodiscard]] PersistentOutboxLoadResult load();
	[[nodiscard]] bool loaded() const;
	[[nodiscard]] std::uint64_t revision() const;
	[[nodiscard]] int size() const;
	[[nodiscard]] std::optional<OutboxItem> item(ObjectId objectId) const;

	bool append(PendingMessage message) override;
	bool appendSealed(EncodedEnvelope envelope) override;
	bool appendSealedThenDraft(
		EncodedEnvelope envelope,
		PendingMessage message) override;
	[[nodiscard]] std::optional<OutboxItem> front(
		ConversationId conversationId) const override;
	bool replaceWithSealed(
		ObjectId objectId,
		EncodedEnvelope envelope) override;
	bool clear();
	bool removePair(ObjectId firstObjectId, ObjectId secondObjectId);
	bool remove(ObjectId objectId) override;
	[[nodiscard]] bool contains(ObjectId objectId) const override;

private:
	[[nodiscard]] bool persist(
		const std::vector<OutboxItem> &items,
		std::uint64_t revision) const;
	[[nodiscard]] bool validItem(const OutboxItem &item) const;
	AtomicBlobStore &_blobStore;
	const LocalRecordProtector &_protector;
	std::vector<OutboxItem> _items;
	std::uint64_t _revision = 0;
	bool _loaded = false;

};

} // namespace E2ECloud
