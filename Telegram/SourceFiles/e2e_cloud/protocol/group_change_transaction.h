/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#pragma once

#include "e2e_cloud/archive/persistent_archive_state.h"
#include "e2e_cloud/group/persistent_group_ledger.h"
#include "e2e_cloud/storage/persistent_mls_state.h"
#include "e2e_cloud/storage/persistent_outbox.h"

#include <cstdint>
#include <optional>
#include <vector>

namespace E2ECloud {

enum class GroupChangeTransactionDirection : std::uint8_t {
	Outbound = 1,
	Inbound = 2,
	InboundJoin = 3,
	InboundRemoval = 4,
	InboundRejoin = 5,
};

struct GroupChangeTransaction {
	ConversationId conversationId;
	ObjectId transactionId;
	GroupChangeTransactionDirection direction
		= GroupChangeTransactionDirection::Outbound;
	std::uint64_t groupBaseRevision = 0;
	std::uint64_t archiveBaseRevision = 0;
	std::uint64_t mlsBaseRevision = 0;
	SignedGroupTransition signedTransition;
	std::optional<AccountCredentialPublic> targetCredential;
	QByteArray targetKeyPackage;
	QByteArray mlsCommit;
	QByteArray archiveDistribution;
	QByteArray nextMlsEngineState;
	std::optional<MlsOperationReceipt> mlsReceipt;
	std::optional<MlsRemovalTombstone> removalTombstone;
	std::optional<ArchiveEpochSecret> archiveEpoch;
	std::vector<EncodedEnvelope> outboxEnvelopes;
};

enum class GroupChangeJournalLoadResult {
	Pending,
	Empty,
	StorageError,
	AuthenticationFailed,
	InvalidSnapshot,
};

enum class GroupChangeJournalCommitResult {
	Prepared,
	Cleared,
	AlreadyPrepared,
	NotLoaded,
	InvalidTransaction,
	TransactionConflict,
	PersistenceFailed,
};

class PersistentGroupChangeJournal final {
public:
	PersistentGroupChangeJournal(
		AtomicBlobStore &blobStore,
		const LocalRecordProtector &protector);
	~PersistentGroupChangeJournal();

	[[nodiscard]] GroupChangeJournalLoadResult load(
		ConversationId conversationId);
	[[nodiscard]] GroupChangeJournalCommitResult prepare(
		GroupChangeTransaction transaction);
	[[nodiscard]] GroupChangeJournalCommitResult clear(
		ObjectId transactionId);

	[[nodiscard]] bool loaded() const;
	[[nodiscard]] std::uint64_t revision() const;
	[[nodiscard]] const GroupChangeTransaction *pending() const;

private:
	[[nodiscard]] bool persist(
		const GroupChangeTransaction *transaction,
		std::uint64_t revision) const;
	void reset();

	AtomicBlobStore &_blobStore;
	const LocalRecordProtector &_protector;
	ConversationId _conversationId;
	std::optional<GroupChangeTransaction> _pending;
	std::uint64_t _revision = 0;
	bool _loaded = false;
};

enum class GroupChangeApplyStatus {
	Applied,
	Recovered,
	NoPendingTransaction,
	JournalUnavailable,
	InvalidTransaction,
	RevisionConflict,
	MlsPersistenceFailure,
	ArchivePersistenceFailure,
	GroupPersistenceFailure,
	OutboxPersistenceFailure,
	JournalClearFailure,
};

class GroupChangeTransactionCoordinator final {
public:
	GroupChangeTransactionCoordinator(
		PersistentGroupChangeJournal &journal,
		PersistentMlsStateStore &mlsState,
		PersistentArchiveState &archiveState,
		PersistentGroupLedger &groupLedger,
		PersistentOutboxStore &outbox,
		const Sha256Provider &sha256);
	GroupChangeTransactionCoordinator(
		PersistentGroupChangeJournal &journal,
		PersistentMlsStateStore &mlsState,
		PersistentArchiveState &archiveState,
		PersistentGroupLedger &groupLedger,
		const Sha256Provider &sha256);

	[[nodiscard]] GroupChangeApplyStatus apply(
		GroupChangeTransaction transaction);
	[[nodiscard]] GroupChangeApplyStatus recover();

private:
	[[nodiscard]] GroupChangeApplyStatus replay(bool recovery);

	PersistentGroupChangeJournal &_journal;
	PersistentMlsStateStore &_mlsState;
	PersistentArchiveState &_archiveState;
	PersistentGroupLedger &_groupLedger;
	PersistentOutboxStore *_outbox = nullptr;
	const Sha256Provider &_sha256;
};

} // namespace E2ECloud
