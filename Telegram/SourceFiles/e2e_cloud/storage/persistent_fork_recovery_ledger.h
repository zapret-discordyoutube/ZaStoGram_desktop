/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#pragma once

#include "e2e_cloud/mls/fork_recovery_manifest.h"
#include "e2e_cloud/storage/local_storage.h"

#include <cstdint>
#include <optional>
#include <vector>

namespace E2ECloud {

struct ForkRecoveryRecord {
	std::uint64_t commonGeneration = 0;
	ObjectId recoveryId;
	Digest manifestHash;
	ForkRecoveryCandidate canonicalCandidate;
	std::vector<ForkRecoveryCandidate> candidates;

	friend inline bool operator==(
		const ForkRecoveryRecord &,
		const ForkRecoveryRecord &) = default;
};

enum class ForkRecoveryLedgerLoadResult {
	Loaded,
	Missing,
	StorageError,
	AuthenticationFailed,
	InvalidSnapshot,
};

enum class ForkRecoveryLedgerCommitResult {
	Committed,
	AlreadyCommitted,
	OwnerEquivocation,
	InvalidManifest,
	NotLoaded,
	CapacityExceeded,
	PersistenceFailed,
};

enum class ForkRecoveryCandidateObservation {
	Unresolved,
	Known,
	HiddenCandidate,
	ObjectIdConflict,
	Unavailable,
};

class PersistentForkRecoveryLedger final {
public:
	PersistentForkRecoveryLedger(
		AtomicBlobStore &blobStore,
		const LocalRecordProtector &protector,
		const Sha256Provider &sha256);

	[[nodiscard]] ForkRecoveryLedgerLoadResult load(
		ConversationId conversationId);
	[[nodiscard]] ForkRecoveryLedgerCommitResult commitVerified(
		const SignedForkRecoveryManifest &manifest);
	[[nodiscard]] ForkRecoveryCandidateObservation observe(
		std::uint64_t commonGeneration,
		ForkRecoveryCandidate candidate) const;
	[[nodiscard]] const ForkRecoveryRecord *record(
		std::uint64_t commonGeneration) const;

	[[nodiscard]] bool loaded() const;
	[[nodiscard]] std::uint64_t revision() const;
	[[nodiscard]] const std::vector<ForkRecoveryRecord> &records() const;

private:
	[[nodiscard]] bool persist(
		const std::vector<ForkRecoveryRecord> &records,
		std::uint64_t revision) const;

	AtomicBlobStore &_blobStore;
	const LocalRecordProtector &_protector;
	const Sha256Provider &_sha256;
	ConversationId _conversationId;
	std::vector<ForkRecoveryRecord> _records;
	std::uint64_t _revision = 0;
	bool _loaded = false;
};

} // namespace E2ECloud
