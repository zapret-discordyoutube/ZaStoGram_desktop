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
#include <optional>

namespace E2ECloud {

struct ConversationLocalMetadata {
	ConversationId conversationId;
	std::uint64_t telegramPeerIdBinding = 0;
	AccountId accountId;
	ClientId clientId;

	friend inline bool operator==(
		const ConversationLocalMetadata &,
		const ConversationLocalMetadata &) = default;
};

enum class ConversationMetadataLoadResult {
	Loaded,
	Missing,
	StorageError,
	AuthenticationFailed,
	InvalidSnapshot,
};

enum class ConversationMetadataCommitResult {
	Committed,
	AlreadyCommitted,
	NotLoaded,
	InvalidMetadata,
	Conflict,
	PersistenceFailed,
};

class PersistentConversationMetadata final {
public:
	PersistentConversationMetadata(
		AtomicBlobStore &blobStore,
		const LocalRecordProtector &protector);

	[[nodiscard]] ConversationMetadataLoadResult load(
		ConversationId expectedConversationId);
	[[nodiscard]] ConversationMetadataCommitResult initialize(
		ConversationLocalMetadata metadata);

	[[nodiscard]] bool loaded() const;
	[[nodiscard]] std::uint64_t revision() const;
	[[nodiscard]] const ConversationLocalMetadata *metadata() const;

private:
	[[nodiscard]] bool persist(
		const ConversationLocalMetadata &metadata,
		std::uint64_t revision) const;
	void reset();

	AtomicBlobStore &_blobStore;
	const LocalRecordProtector &_protector;
	ConversationId _conversationId;
	std::optional<ConversationLocalMetadata> _metadata;
	std::uint64_t _revision = 0;
	bool _loaded = false;
};

} // namespace E2ECloud
