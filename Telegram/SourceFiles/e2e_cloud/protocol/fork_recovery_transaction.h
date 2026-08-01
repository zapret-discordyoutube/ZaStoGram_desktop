/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#pragma once

#include "e2e_cloud/archive/persistent_archive_state.h"
#include "e2e_cloud/group/persistent_group_ledger.h"
#include "e2e_cloud/storage/persistent_fork_recovery_ledger.h"
#include "e2e_cloud/storage/persistent_key_package_pool.h"
#include "e2e_cloud/storage/persistent_mls_state.h"
#include "e2e_cloud/storage/persistent_outbox.h"

#include <cstdint>
#include <optional>
#include <vector>

namespace E2ECloud {

enum class ForkRecoveryTransactionDirection : std::uint8_t {
	Outbound = 1,
	Inbound = 2,
};

struct ForkRecoveryTransaction {
	ConversationId conversationId;
	ObjectId transactionId;
	ForkRecoveryTransactionDirection direction
		= ForkRecoveryTransactionDirection::Outbound;
	std::uint64_t groupBaseRevision = 0;
	std::uint64_t archiveBaseRevision = 0;
	std::uint64_t mlsBaseRevision = 0;
	std::uint64_t forkLedgerBaseRevision = 0;
	SignedForkRecoveryManifest manifest;
	std::optional<SignedGroupTransition> canonicalTransition;
	std::optional<AccountCredentialPublic> canonicalTargetCredential;
	QByteArray canonicalTargetKeyPackage;
	QByteArray canonicalMlsCommit;
	QByteArray canonicalArchiveDistribution;
	std::optional<Digest> consumedKeyPackageHash;
	std::uint64_t keyPackagePoolBaseRevision = 0;
	ArchiveEpochSecret archiveEpoch;
	QByteArray nextMlsEngineState;
	std::vector<EncodedEnvelope> outboxEnvelopes;
};

enum class ForkRecoveryJournalLoadResult {
	Pending,
	Empty,
	StorageError,
	AuthenticationFailed,
	InvalidSnapshot,
};

enum class ForkRecoveryJournalCommitResult {
	Prepared,
	Cleared,
	AlreadyPrepared,
	NotLoaded,
	InvalidTransaction,
	TransactionConflict,
	PersistenceFailed,
};

class PersistentForkRecoveryJournal final {
public:
	PersistentForkRecoveryJournal(
		AtomicBlobStore &blobStore,
		const LocalRecordProtector &protector);
	~PersistentForkRecoveryJournal();

	[[nodiscard]] ForkRecoveryJournalLoadResult load(
		ConversationId conversationId);
	[[nodiscard]] ForkRecoveryJournalCommitResult prepare(
		ForkRecoveryTransaction transaction);
	[[nodiscard]] ForkRecoveryJournalCommitResult clear(
		ObjectId transactionId);

	[[nodiscard]] bool loaded() const;
	[[nodiscard]] std::uint64_t revision() const;
	[[nodiscard]] const ForkRecoveryTransaction *pending() const;

private:
	[[nodiscard]] bool persist(
		const ForkRecoveryTransaction *transaction,
		std::uint64_t revision) const;
	void reset();

	AtomicBlobStore &_blobStore;
	const LocalRecordProtector &_protector;
	ConversationId _conversationId;
	std::optional<ForkRecoveryTransaction> _pending;
	std::uint64_t _revision = 0;
	bool _loaded = false;
};

enum class ForkRecoveryApplyStatus {
	Applied,
	Recovered,
	NoPendingTransaction,
	JournalUnavailable,
	InvalidTransaction,
	RevisionConflict,
	MlsPersistenceFailure,
	ArchivePersistenceFailure,
	GroupPersistenceFailure,
	ForkLedgerPersistenceFailure,
	OutboxPersistenceFailure,
	JournalClearFailure,
};

class ForkRecoveryTransactionCoordinator final {
public:
	ForkRecoveryTransactionCoordinator(
		PersistentForkRecoveryJournal &journal,
		PersistentMlsStateStore &mlsState,
		PersistentArchiveState &archiveState,
		PersistentGroupLedger &groupLedger,
		PersistentForkRecoveryLedger &forkLedger,
		PersistentOutboxStore &outbox,
		const Sha256Provider &sha256);
	ForkRecoveryTransactionCoordinator(
		PersistentForkRecoveryJournal &journal,
		PersistentMlsStateStore &mlsState,
		PersistentArchiveState &archiveState,
		PersistentGroupLedger &groupLedger,
		PersistentForkRecoveryLedger &forkLedger,
		PersistentKeyPackagePool &keyPackagePool,
		const Sha256Provider &sha256);

	[[nodiscard]] ForkRecoveryApplyStatus apply(
		ForkRecoveryTransaction transaction);
	[[nodiscard]] ForkRecoveryApplyStatus recover();

private:
	[[nodiscard]] ForkRecoveryApplyStatus replay(bool recovery);

	PersistentForkRecoveryJournal &_journal;
	PersistentMlsStateStore &_mlsState;
	PersistentArchiveState &_archiveState;
	PersistentGroupLedger &_groupLedger;
	PersistentForkRecoveryLedger &_forkLedger;
	PersistentOutboxStore *_outbox = nullptr;
	PersistentKeyPackagePool *_keyPackagePool = nullptr;
	const Sha256Provider &_sha256;
};

} // namespace E2ECloud
