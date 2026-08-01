/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#pragma once

#include "e2e_cloud/core/types.h"
#include "e2e_cloud/storage/local_storage.h"

#include <cstdint>

namespace E2ECloud {

enum class ContentSyncStateLoadResult {
	Loaded,
	Missing,
	ReadFailed,
	AuthenticationFailed,
	InvalidSnapshot,
};

enum class ContentSyncStateCommitResult {
	Committed,
	AlreadyCommitted,
	InvalidBoundary,
	PersistenceFailed,
};

class PersistentContentSyncState final {
public:
	PersistentContentSyncState(
		AtomicBlobStore &blobStore,
		const LocalRecordProtector &protector);

	[[nodiscard]] ContentSyncStateLoadResult load(
		ConversationId conversationId);
	[[nodiscard]] ContentSyncStateCommitResult advance(
		std::int64_t newestObservedMessageId);
	[[nodiscard]] std::int64_t newestObservedMessageId() const;
	[[nodiscard]] std::uint64_t revision() const;
	[[nodiscard]] bool loaded() const;

private:
	[[nodiscard]] bool persist(
		std::int64_t newestObservedMessageId,
		std::uint64_t revision) const;

	AtomicBlobStore &_blobStore;
	const LocalRecordProtector &_protector;
	ConversationId _conversationId;
	std::int64_t _newestObservedMessageId = 0;
	std::uint64_t _revision = 0;
	bool _loaded = false;
};

} // namespace E2ECloud
