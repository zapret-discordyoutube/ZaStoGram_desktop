/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#pragma once

#include "e2e_cloud/protocol/group_bootstrap.h"
#include "e2e_cloud/storage/persistent_mls_state.h"
#include "e2e_cloud/storage/persistent_outbox.h"
#include "e2e_cloud/group/persistent_group_ledger.h"
#include "e2e_cloud/archive/persistent_archive_state.h"

#include <cstdint>
#include <optional>

namespace E2ECloud {

struct GroupBootstrapTransaction {
	ConversationId conversationId;
	std::uint64_t outboxBaseRevision = 0;
	SignedGroupGenesis genesis;
	AccountCredentialPublic ownerCredential;
	QByteArray initialMlsPublicObject;
	ArchiveEpochSecret archiveEpoch;
	QByteArray mlsEngineState;
	std::vector<EncodedEnvelope> outboxEnvelopes;
};

enum class GroupBootstrapJournalLoadResult {
	Pending,
	Empty,
	StorageError,
	AuthenticationFailed,
	InvalidSnapshot,
};

enum class GroupBootstrapJournalCommitResult {
	Prepared,
	Cleared,
	AlreadyPrepared,
	NotLoaded,
	InvalidTransaction,
	TransactionConflict,
	PersistenceFailed,
};

class PersistentGroupBootstrapJournal final {
public:
	PersistentGroupBootstrapJournal(
		AtomicBlobStore &blobStore,
		const LocalRecordProtector &protector);
	~PersistentGroupBootstrapJournal();

	[[nodiscard]] GroupBootstrapJournalLoadResult load(
		ConversationId conversationId);
	[[nodiscard]] GroupBootstrapJournalCommitResult prepare(
		GroupBootstrapTransaction transaction);
	[[nodiscard]] GroupBootstrapJournalCommitResult clear(
		ObjectId genesisObjectId);

	[[nodiscard]] bool loaded() const;
	[[nodiscard]] const GroupBootstrapTransaction *pending() const;

private:
	[[nodiscard]] bool persist(
		const GroupBootstrapTransaction *transaction,
		std::uint64_t revision) const;
	void reset();

	AtomicBlobStore &_blobStore;
	const LocalRecordProtector &_protector;
	ConversationId _conversationId;
	std::optional<GroupBootstrapTransaction> _pending;
	std::uint64_t _revision = 0;
	bool _loaded = false;
};

enum class GroupBootstrapApplyStatus {
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

class GroupBootstrapTransactionCoordinator final {
public:
	GroupBootstrapTransactionCoordinator(
		PersistentGroupBootstrapJournal &journal,
		PersistentMlsStateStore &mlsState,
		PersistentArchiveState &archiveState,
		PersistentGroupLedger &groupLedger,
		PersistentOutboxStore &outbox,
		const EnvelopeCodecV1 &envelopeCodec,
		const Sha256Provider &sha256);

	[[nodiscard]] GroupBootstrapApplyStatus apply(
		GroupBootstrapTransaction transaction);
	[[nodiscard]] GroupBootstrapApplyStatus recover();

private:
	[[nodiscard]] GroupBootstrapApplyStatus replay(bool recovery);

	PersistentGroupBootstrapJournal &_journal;
	PersistentMlsStateStore &_mlsState;
	PersistentArchiveState &_archiveState;
	PersistentGroupLedger &_groupLedger;
	PersistentOutboxStore &_outbox;
	const EnvelopeCodecV1 &_envelopeCodec;
	const Sha256Provider &_sha256;
};

[[nodiscard]] GroupBootstrapTransaction MakeGroupBootstrapTransaction(
	PreparedProtectedGroupBootstrap &&prepared,
	const AccountCredentialPublic &ownerCredential,
	std::uint64_t outboxBaseRevision);

} // namespace E2ECloud
