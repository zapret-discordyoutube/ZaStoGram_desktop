/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#pragma once

#include "e2e_cloud/archive/persistent_archive_state.h"
#include "e2e_cloud/group/persistent_group_ledger.h"
#include "e2e_cloud/mls/mls_roster_codec.h"
#include "e2e_cloud/mls/openmls_application_engine.h"
#include "e2e_cloud/protocol/fork_recovery_transaction.h"

#include <optional>
#include <vector>

namespace E2ECloud {

class EnvelopeCodec;
class GroupControlCodecV1;
class OpenMlsBridge;

enum class OpenMlsForkRecoveryPrepareStatus {
	Prepared,
	InvalidArguments,
	StateUnavailable,
	InvalidCandidateSet,
	InvalidPartition,
	InvalidReplacement,
	ArchiveInvariantViolation,
	EncodingFailure,
	MlsFailure,
	RosterMismatch,
	SignatureFailure,
};

struct PrepareOpenMlsForkRecoveryArgs {
	OpenMlsClientContext actor;
	std::uint64_t commonGeneration = 0;
	std::uint64_t currentTime = 0;
	ObjectId recoveryId;
	std::vector<ForkRecoveryCandidate> candidates;
	ForkRecoveryCandidate canonicalCandidate;
	std::vector<ForkRecoveryPartitionClient> canonicalPartition;
	std::vector<TransportEnvelope> replacementKeyPackageEnvelopes;
	ClientId ownerClientId;
	const AccountCredentialPublic *ownerCredential = nullptr;
	const SecureKey32 *ownerSigningPrivateKey = nullptr;
	const ArchiveKey32 *nextArchiveKey = nullptr;
	ObjectId recoveryCommitObjectId;
	ObjectId recoveryWelcomeObjectId;
	ObjectId archiveDistributionObjectId;
};

struct PreparedOpenMlsForkRecovery {
	ForkRecoveryTransaction transaction;
	MlsRoster resultingRoster;
};

struct PrepareOpenMlsForkRecoveryOutcome {
	OpenMlsForkRecoveryPrepareStatus status
		= OpenMlsForkRecoveryPrepareStatus::InvalidArguments;
	std::optional<PreparedOpenMlsForkRecovery> prepared;
};

[[nodiscard]] PrepareOpenMlsForkRecoveryOutcome PrepareOpenMlsForkRecovery(
	PrepareOpenMlsForkRecoveryArgs args,
	const OpenMlsBridge &bridge,
	const MlsContextCodecV1 &contextCodec,
	const MlsRosterCodecV1 &rosterCodec,
	const GroupControlCodecV1 &controlCodec,
	const EnvelopeCodec &envelopeCodec,
	const Sha256Provider &sha256,
	const PersistentMlsStateStore &mlsState,
	const PersistentArchiveState &archiveState,
	const PersistentGroupLedger &groupLedger,
	const PersistentForkRecoveryLedger &forkLedger);

} // namespace E2ECloud
