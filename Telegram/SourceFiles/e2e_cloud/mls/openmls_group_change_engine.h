/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#pragma once

#include "e2e_cloud/mls/openmls_application_engine.h"
#include "e2e_cloud/mls/mls_roster_codec.h"
#include "e2e_cloud/protocol/group_change_transaction.h"
#include "e2e_cloud/protocol/group_control_codec.h"

#include <optional>

namespace E2ECloud {

class OpenMlsBridge;

enum class OpenMlsGroupChangePrepareStatus {
	Prepared,
	InvalidArguments,
	StateUnavailable,
	UnsupportedTransition,
	ArchiveInvariantViolation,
	EncodingFailure,
	MlsFailure,
	SignatureFailure,
	RosterMismatch,
};

struct PrepareOpenMlsAdmissionArgs {
	OpenMlsClientContext actor;
	const ProtectedGroupState *currentGroupState = nullptr;
	Checkpoint currentCheckpoint;
	GroupTransition transition;
	const AccountCredentialPublic *actorCredential = nullptr;
	const SecureKey32 *actorSigningPrivateKey = nullptr;
	const AccountCredentialPublic *targetCredential = nullptr;
	const ClientAuthorizationProof *targetClientAuthorization = nullptr;
	QByteArray targetKeyPackage;
	const ArchiveKey32 *nextArchiveKey = nullptr;
	ObjectId mlsCommitObjectId;
	ObjectId archiveDistributionObjectId;
	ObjectId welcomeObjectId;
};

struct PrepareOpenMlsRemovalArgs {
	OpenMlsClientContext actor;
	const ProtectedGroupState *currentGroupState = nullptr;
	Checkpoint currentCheckpoint;
	GroupTransition transition;
	const AccountCredentialPublic *actorCredential = nullptr;
	const SecureKey32 *actorSigningPrivateKey = nullptr;
	const ArchiveKey32 *nextArchiveKey = nullptr;
	ObjectId mlsCommitObjectId;
	ObjectId archiveDistributionObjectId;
};

struct PrepareOpenMlsPolicyChangeArgs {
	OpenMlsClientContext actor;
	const ProtectedGroupState *currentGroupState = nullptr;
	Checkpoint currentCheckpoint;
	GroupTransition transition;
	const AccountCredentialPublic *actorCredential = nullptr;
	const SecureKey32 *actorSigningPrivateKey = nullptr;
	const ArchiveKey32 *nextArchiveKey = nullptr;
	ObjectId mlsCommitObjectId;
	ObjectId archiveDistributionObjectId;
};

struct PreparedOpenMlsGroupChange {
	GroupChangeTransaction transaction;
	AppliedSignedGroupTransition applied;
	MlsRoster resultingRoster;
};

struct PrepareOpenMlsGroupChangeOutcome {
	OpenMlsGroupChangePrepareStatus status
		= OpenMlsGroupChangePrepareStatus::InvalidArguments;
	std::optional<PreparedOpenMlsGroupChange> prepared;
};

[[nodiscard]] PrepareOpenMlsGroupChangeOutcome PrepareOpenMlsAdmission(
	PrepareOpenMlsAdmissionArgs args,
	const OpenMlsBridge &bridge,
	const MlsContextCodecV1 &contextCodec,
	const MlsRosterCodecV1 &rosterCodec,
	const GroupControlCodecV1 &controlCodec,
	const EnvelopeCodec &envelopeCodec,
	const Sha256Provider &sha256,
	const PersistentMlsStateStore &mlsState,
	const PersistentArchiveState &archiveState,
	const PersistentGroupLedger &groupLedger);

[[nodiscard]] PrepareOpenMlsGroupChangeOutcome PrepareOpenMlsRemoval(
	PrepareOpenMlsRemovalArgs args,
	const OpenMlsBridge &bridge,
	const MlsContextCodecV1 &contextCodec,
	const MlsRosterCodecV1 &rosterCodec,
	const GroupControlCodecV1 &controlCodec,
	const EnvelopeCodec &envelopeCodec,
	const Sha256Provider &sha256,
	const PersistentMlsStateStore &mlsState,
	const PersistentArchiveState &archiveState,
	const PersistentGroupLedger &groupLedger);

[[nodiscard]] PrepareOpenMlsGroupChangeOutcome PrepareOpenMlsPolicyChange(
	PrepareOpenMlsPolicyChangeArgs args,
	const OpenMlsBridge &bridge,
	const MlsContextCodecV1 &contextCodec,
	const MlsRosterCodecV1 &rosterCodec,
	const GroupControlCodecV1 &controlCodec,
	const EnvelopeCodec &envelopeCodec,
	const Sha256Provider &sha256,
	const PersistentMlsStateStore &mlsState,
	const PersistentArchiveState &archiveState,
	const PersistentGroupLedger &groupLedger);

} // namespace E2ECloud
