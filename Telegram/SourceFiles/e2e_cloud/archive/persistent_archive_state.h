/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#pragma once

#include "e2e_cloud/archive/history_grant_crypto.h"
#include "e2e_cloud/storage/local_storage.h"

#include <cstdint>
#include <optional>
#include <vector>

namespace E2ECloud {

enum class ArchiveStateLoadResult {
	Loaded,
	Missing,
	StorageError,
	AuthenticationFailed,
	InvalidSnapshot,
};

enum class ArchiveStateCommitResult {
	Committed,
	AlreadyCommitted,
	NotLoaded,
	InvalidMutation,
	RevisionConflict,
	EpochConflict,
	PersistenceFailed,
};

enum class ArchiveEpochAppendMode {
	Contiguous,
	RejoinGap,
};

class PersistentArchiveState final {
public:
	PersistentArchiveState(
		AtomicBlobStore &blobStore,
		const LocalRecordProtector &protector);

	[[nodiscard]] ArchiveStateLoadResult load(
		ConversationId conversationId);
	[[nodiscard]] ArchiveStateCommitResult initialize(
		ArchiveEpochSecret firstEpoch);
	[[nodiscard]] ArchiveStateCommitResult appendEpoch(
		std::uint64_t baseRevision,
		ArchiveEpochSecret epoch,
		ArchiveEpochAppendMode mode = ArchiveEpochAppendMode::Contiguous);
	[[nodiscard]] ArchiveStateCommitResult replaceForkEpochWithRecovery(
		std::uint64_t baseRevision,
		std::uint64_t resolvedGeneration,
		ArchiveEpochSecret recoveryEpoch);
	[[nodiscard]] ArchiveStateCommitResult mergeHistoryGrant(
		std::uint64_t baseRevision,
		HistoryGrantPayload payload);

	[[nodiscard]] std::optional<std::vector<ArchiveEpochSecret>>
		exportForGrant(
			const HistoryAccess &access,
			std::uint64_t joinedGroupGeneration) const;

	[[nodiscard]] bool loaded() const;
	[[nodiscard]] ConversationId conversationId() const;
	[[nodiscard]] std::uint64_t revision() const;
	[[nodiscard]] int epochCount() const;
	[[nodiscard]] const ArchiveEpochSecret *epoch(
		std::uint64_t generation) const;
	[[nodiscard]] bool epochWasActiveAt(
		std::uint64_t epochGeneration,
		std::uint64_t groupGeneration) const;
	[[nodiscard]] const ArchiveEpochSecret *currentEpoch() const;

private:
	[[nodiscard]] bool persist(
		const std::vector<ArchiveEpochSecret> &epochs,
		std::uint64_t revision) const;
	void clear();

	AtomicBlobStore &_blobStore;
	const LocalRecordProtector &_protector;
	ConversationId _conversationId;
	std::vector<ArchiveEpochSecret> _epochs;
	std::uint64_t _revision = 0;
	bool _loaded = false;

};

} // namespace E2ECloud
