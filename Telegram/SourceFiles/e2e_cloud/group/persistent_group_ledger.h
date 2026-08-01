/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#pragma once

#include "e2e_cloud/group/signed_group_genesis.h"
#include "e2e_cloud/group/signed_group_transition.h"
#include "e2e_cloud/mls/fork_recovery_manifest.h"
#include "e2e_cloud/storage/local_storage.h"

#include <cstdint>
#include <optional>
#include <vector>

namespace E2ECloud {

enum class GroupLedgerEventKind : std::uint8_t {
	Genesis = 1,
	Transition = 2,
	ForkRecovery = 3,
};

struct GroupLedgerEvent {
	GroupLedgerEventKind kind = GroupLedgerEventKind::Genesis;
	std::uint64_t generation = 0;
	ObjectId objectId;
	QByteArray bytes;

	friend inline bool operator==(
		const GroupLedgerEvent &,
		const GroupLedgerEvent &) = default;
};

enum class GroupLedgerLoadResult {
	Loaded,
	Missing,
	StorageError,
	AuthenticationFailed,
	InvalidSnapshot,
};

enum class GroupLedgerCommitResult {
	Committed,
	AlreadyCommitted,
	NotLoaded,
	InvalidMutation,
	RevisionConflict,
	HistoryConflict,
	PersistenceFailed,
};

class PersistentGroupLedger final {
public:
	PersistentGroupLedger(
		AtomicBlobStore &blobStore,
		const LocalRecordProtector &protector,
		const Sha256Provider &sha256);

	[[nodiscard]] GroupLedgerLoadResult load(
		ConversationId conversationId);
	[[nodiscard]] GroupLedgerCommitResult initialize(
		const SignedGroupGenesis &genesis,
		const ProtectedGroupState &state,
		const Checkpoint &checkpoint,
		const AccountCredentialPublic &ownerCredential);
	[[nodiscard]] GroupLedgerCommitResult commitTransition(
		std::uint64_t baseRevision,
		const SignedGroupTransition &signedTransition,
		const AppliedSignedGroupTransition &applied,
		const AccountCredentialPublic *admittedCredential);
	[[nodiscard]] GroupLedgerCommitResult commitVerifiedForkRecovery(
		std::uint64_t baseRevision,
		const SignedForkRecoveryManifest &manifest,
		const ArchiveEpochSecret &archiveEpoch);
	[[nodiscard]] GroupLedgerCommitResult replaceForkBranchAndCommitRecovery(
		std::uint64_t baseRevision,
		const SignedGroupTransition &canonicalTransition,
		const AppliedSignedGroupTransition &canonicalApplied,
		const AccountCredentialPublic *admittedCredential,
		const SignedForkRecoveryManifest &manifest,
		const ArchiveEpochSecret &archiveEpoch);

	[[nodiscard]] bool loaded() const;
	[[nodiscard]] std::uint64_t revision() const;
	[[nodiscard]] const ProtectedGroupState *state() const;
	[[nodiscard]] Checkpoint checkpoint() const;
	[[nodiscard]] const AccountCredentialPublic *credential(
		AccountId accountId) const;
	[[nodiscard]] std::optional<ProtectedGroupState> stateAt(
		std::uint64_t generation) const;
	[[nodiscard]] std::optional<Checkpoint> checkpointAt(
		std::uint64_t generation) const;
	[[nodiscard]] bool wasMemberAt(
		AccountId accountId,
		std::uint64_t generation) const;
	[[nodiscard]] bool wasClientActiveAt(
		AccountId accountId,
		ClientId clientId,
		std::uint64_t generation) const;
	[[nodiscard]] bool verifiesArchiveEpoch(
		const ArchiveEpochSecret &epoch) const;
	[[nodiscard]] const std::vector<GroupLedgerEvent> &events() const;

private:
	struct CredentialRecord {
		AccountId accountId;
		AccountCredentialPublic credential;
	};

	[[nodiscard]] bool persist(
		const ProtectedGroupState &state,
		const Checkpoint &checkpoint,
		const std::vector<CredentialRecord> &credentials,
		const std::vector<GroupLedgerEvent> &events,
		std::uint64_t revision) const;
	void clear();

	AtomicBlobStore &_blobStore;
	const LocalRecordProtector &_protector;
	const Sha256Provider &_sha256;
	ConversationId _conversationId;
	std::optional<ProtectedGroupState> _state;
	Checkpoint _checkpoint;
	std::vector<CredentialRecord> _credentials;
	std::vector<GroupLedgerEvent> _events;
	std::uint64_t _revision = 0;
	bool _loaded = false;
};

} // namespace E2ECloud
