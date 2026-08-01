/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "e2e_cloud/mls/openmls_group_change_engine.h"

#include "e2e_cloud/mls/openmls_application_engine.h"
#include "e2e_cloud/mls/openmls_bridge.h"

#include <openssl/crypto.h>

#include <set>
#include <utility>

namespace E2ECloud {
namespace {

[[nodiscard]] PrepareOpenMlsGroupChangeOutcome Failure(
		OpenMlsGroupChangePrepareStatus status) {
	return {
		.status = status,
		.prepared = std::nullopt,
	};
}

[[nodiscard]] bool AdmissionKind(GroupTransitionKind kind) {
	return kind == GroupTransitionKind::AddMember
		|| kind == GroupTransitionKind::AddClient;
}

[[nodiscard]] bool RemovalKind(GroupTransitionKind kind) {
	return kind == GroupTransitionKind::RemoveMember
		|| kind == GroupTransitionKind::RemoveClient;
}

[[nodiscard]] bool PolicyKind(GroupTransitionKind kind) {
	return kind == GroupTransitionKind::SetRole
		|| kind == GroupTransitionKind::TransferOwnership
		|| kind == GroupTransitionKind::SetDefaultHistory
		|| kind == GroupTransitionKind::SetMemberHistory;
}

[[nodiscard]] bool ExistingMemberKind(GroupTransitionKind kind) {
	return RemovalKind(kind) || PolicyKind(kind);
}

[[nodiscard]] QByteArray SignatureBytes(const AccountSignature &signature) {
	return QByteArray(
		reinterpret_cast<const char*>(signature.data()),
		signature.size());
}

void Cleanse(QByteArray &bytes) {
	OPENSSL_cleanse(bytes.data(), bytes.size());
}

} // namespace

PrepareOpenMlsGroupChangeOutcome PrepareOpenMlsAdmission(
		PrepareOpenMlsAdmissionArgs args,
		const OpenMlsBridge &bridge,
		const MlsContextCodecV1 &contextCodec,
		const MlsRosterCodecV1 &rosterCodec,
		const GroupControlCodecV1 &controlCodec,
		const EnvelopeCodec &envelopeCodec,
		const Sha256Provider &sha256,
		const PersistentMlsStateStore &mlsState,
		const PersistentArchiveState &archiveState,
		const PersistentGroupLedger &groupLedger) {
	if (!args.currentGroupState
		|| !args.actorCredential
		|| !args.actorSigningPrivateKey
		|| !args.actorSigningPrivateKey->valid()
		|| !args.targetCredential
		|| !args.targetClientAuthorization
		|| args.targetKeyPackage.isEmpty()
		|| !args.nextArchiveKey
		|| !args.nextArchiveKey->valid()
		|| !args.mlsCommitObjectId
		|| !args.archiveDistributionObjectId
		|| !args.welcomeObjectId
		|| args.mlsCommitObjectId == args.archiveDistributionObjectId
		|| args.mlsCommitObjectId == args.welcomeObjectId
		|| args.archiveDistributionObjectId == args.welcomeObjectId
		|| !AdmissionKind(args.transition.kind)) {
		return Failure(OpenMlsGroupChangePrepareStatus::InvalidArguments);
	}
	const auto &current = *args.currentGroupState;
	const auto actorMember = groupLedger.state()
		? groupLedger.state()->memberByClient(args.actor.clientId)
		: nullptr;
	if (!mlsState.loaded()
		|| !mlsState.revision()
		|| mlsState.engineId() != OpenMlsEngineId()
		|| mlsState.engineState().isEmpty()
		|| !archiveState.loaded()
		|| !groupLedger.loaded()) {
		return Failure(OpenMlsGroupChangePrepareStatus::StateUnavailable);
	} else if (args.actor.conversationId != current.conversationId()
		|| mlsState.conversationId() != current.conversationId()
		|| archiveState.conversationId() != current.conversationId()
		|| !groupLedger.state()
		|| groupLedger.state()->conversationId() != current.conversationId()
		|| args.currentCheckpoint != groupLedger.checkpoint()
		|| current.snapshot() != groupLedger.state()->snapshot()
		|| !actorMember
		|| args.actor.accountId != actorMember->accountId) {
		return Failure(OpenMlsGroupChangePrepareStatus::StateUnavailable);
	}
	const auto currentArchiveEpoch = archiveState.currentEpoch();
	if (!currentArchiveEpoch
		|| currentArchiveEpoch->generation != current.generation()
		|| args.transition.previousGeneration != current.generation()
		|| args.transition.generation != current.generation() + 1) {
		return Failure(
			OpenMlsGroupChangePrepareStatus::ArchiveInvariantViolation);
	}
	const auto archiveCommitment = DeriveArchiveKeyCommitment(
		args.transition.conversationId,
		args.transition.generation,
		args.transition.generation,
		args.transition.transitionId,
		*args.nextArchiveKey,
		sha256);
	if (!archiveCommitment) {
		return Failure(OpenMlsGroupChangePrepareStatus::EncodingFailure);
	}
	const auto prelude = GroupChangePrelude{
		.transition = args.transition,
		.actorAccountId = args.actor.accountId,
		.actorClientId = args.actor.clientId,
		.previousStateHash = args.currentCheckpoint.stateHash,
		.mlsCommitObjectId = args.mlsCommitObjectId,
		.archiveDistributionObjectId = args.archiveDistributionObjectId,
		.archiveKeyCommitment = *archiveCommitment,
		.targetClientAuthorization = *args.targetClientAuthorization,
	};
	const auto preludeBytes = controlCodec.encodePrelude(prelude);
	const auto commitAad = preludeBytes
		? contextCodec.encodeAad({
			.conversationId = args.actor.conversationId,
			.objectKind = ObjectKind::MlsCommit,
			.senderAccountId = args.actor.accountId,
			.senderClientId = args.actor.clientId,
			.telegramPeerIdBinding = args.actor.telegramPeerIdBinding,
			.objectId = args.mlsCommitObjectId,
			.context = *preludeBytes,
		})
		: std::nullopt;
	if (!preludeBytes || !commitAad) {
		return Failure(OpenMlsGroupChangePrepareStatus::EncodingFailure);
	}
	auto added = bridge.addMember(
		mlsState.engineState(),
		args.targetKeyPackage,
		*commitAad);
	if (added.status != OpenMlsBridgeStatus::Ok
		|| added.state.isEmpty()
		|| added.commit.isEmpty()
		|| added.welcome.isEmpty()
		|| added.roster.isEmpty()) {
		Cleanse(added.state);
		return Failure(OpenMlsGroupChangePrepareStatus::MlsFailure);
	}
	auto distributionPlaintext = controlCodec.encodeArchiveDistribution({
		.conversationId = args.actor.conversationId,
		.transitionId = args.transition.transitionId,
		.groupGeneration = args.transition.generation,
		.archiveEpochGeneration = args.transition.generation,
		.activationEventId = args.transition.transitionId,
		.key = args.nextArchiveKey->clone(),
	});
	if (!distributionPlaintext) {
		Cleanse(added.state);
		return Failure(OpenMlsGroupChangePrepareStatus::EncodingFailure);
	}
	auto distributionContext = *preludeBytes;
	const auto commitHash = sha256.digest(added.commit);
	distributionContext.append(
		reinterpret_cast<const char*>(commitHash.bytes.data()),
		commitHash.bytes.size());
	const auto distributionAad = contextCodec.encodeAad({
		.conversationId = args.actor.conversationId,
		.objectKind = ObjectKind::ArchiveEpoch,
		.senderAccountId = args.actor.accountId,
		.senderClientId = args.actor.clientId,
		.telegramPeerIdBinding = args.actor.telegramPeerIdBinding,
		.objectId = args.archiveDistributionObjectId,
		.context = std::move(distributionContext),
	});
	if (!distributionAad) {
		Cleanse(added.state);
		Cleanse(*distributionPlaintext);
		return Failure(OpenMlsGroupChangePrepareStatus::EncodingFailure);
	}
	auto distributed = bridge.seal(
		added.state,
		*distributionAad,
		*distributionPlaintext);
	Cleanse(added.state);
	Cleanse(*distributionPlaintext);
	if (distributed.status != OpenMlsBridgeStatus::Ok
		|| distributed.state.isEmpty()
		|| distributed.message.isEmpty()
		|| distributed.epoch != added.epoch) {
		Cleanse(distributed.state);
		return Failure(OpenMlsGroupChangePrepareStatus::MlsFailure);
	}
	const auto signedTransition = CreateSignedGroupTransition({
		.transition = args.transition,
		.actorAccountId = args.actor.accountId,
		.actorClientId = args.actor.clientId,
		.previousStateHash = args.currentCheckpoint.stateHash,
		.mlsCommitObjectId = args.mlsCommitObjectId,
		.actorCredential = args.actorCredential,
		.actorSigningPrivateKey = args.actorSigningPrivateKey,
		.nextArchiveKey = args.nextArchiveKey,
		.archiveDistributionObjectId = args.archiveDistributionObjectId,
		.archiveDistribution = distributed.message,
		.targetClientAuthorization = args.targetClientAuthorization,
		.mlsCommit = added.commit,
	}, sha256);
	if (!signedTransition) {
		Cleanse(distributed.state);
		return Failure(OpenMlsGroupChangePrepareStatus::SignatureFailure);
	}
	auto verified = VerifyAndApplySignedGroupTransition({
		.currentState = &current,
		.currentCheckpoint = args.currentCheckpoint,
		.signedTransition = &*signedTransition,
		.actorCredential = args.actorCredential,
		.targetCredential = args.targetCredential,
		.mlsCommitObjectId = args.mlsCommitObjectId,
		.mlsCommit = added.commit,
		.nextArchiveKey = args.nextArchiveKey,
		.archiveDistributionObjectId = args.archiveDistributionObjectId,
		.archiveDistribution = distributed.message,
		.targetKeyPackage = args.targetKeyPackage,
	}, sha256);
	const auto roster = rosterCodec.decode(added.roster, contextCodec);
	if (verified.result != SignedGroupTransitionResult::Applied
		|| !verified.applied
		|| !roster
		|| !MlsRosterMatchesGroupState(*roster, verified.applied->state)) {
		Cleanse(distributed.state);
		return Failure(OpenMlsGroupChangePrepareStatus::RosterMismatch);
	}
	const auto signedBytes = SignedGroupTransitionCodecV1().encode(
		*signedTransition);
	const auto commitEnvelope = envelopeCodec.encode({
		.conversationId = args.actor.conversationId,
		.objectKind = ObjectKind::MlsCommit,
		.senderAccountId = args.actor.accountId,
		.senderClientId = args.actor.clientId,
		.telegramPeerIdBinding = args.actor.telegramPeerIdBinding,
		.epochOrGeneration = added.epoch,
		.objectId = args.mlsCommitObjectId,
		.payloadHash = sha256.digest(added.commit),
		.payload = added.commit,
		.authenticationData = *commitAad,
	});
	const auto distributionEnvelope = envelopeCodec.encode({
		.conversationId = args.actor.conversationId,
		.objectKind = ObjectKind::ArchiveEpoch,
		.senderAccountId = args.actor.accountId,
		.senderClientId = args.actor.clientId,
		.telegramPeerIdBinding = args.actor.telegramPeerIdBinding,
		.epochOrGeneration = distributed.epoch,
		.objectId = args.archiveDistributionObjectId,
		.payloadHash = sha256.digest(distributed.message),
		.payload = distributed.message,
		.authenticationData = *distributionAad,
	});
	const auto transitionEnvelope = signedBytes
		? envelopeCodec.encode({
			.conversationId = args.actor.conversationId,
			.objectKind = ObjectKind::SignedGroupTransition,
			.senderAccountId = args.actor.accountId,
			.senderClientId = args.actor.clientId,
			.telegramPeerIdBinding = args.actor.telegramPeerIdBinding,
			.epochOrGeneration = args.transition.generation,
			.objectId = args.transition.transitionId,
			.payloadHash = sha256.digest(*signedBytes),
			.payload = *signedBytes,
			.authenticationData = SignatureBytes(
				signedTransition->actorSignature),
		})
		: std::nullopt;
	const auto welcomeEnvelope = signedBytes
		? envelopeCodec.encode({
			.conversationId = args.actor.conversationId,
			.objectKind = ObjectKind::MlsWelcome,
			.senderAccountId = args.actor.accountId,
			.senderClientId = args.actor.clientId,
			.telegramPeerIdBinding = args.actor.telegramPeerIdBinding,
			.epochOrGeneration = added.epoch,
			.objectId = args.welcomeObjectId,
			.payloadHash = sha256.digest(added.welcome),
			.payload = std::move(added.welcome),
			.authenticationData = *signedBytes,
		})
		: std::nullopt;
	if (!signedBytes
		|| !commitEnvelope
		|| !distributionEnvelope
		|| !transitionEnvelope
		|| !welcomeEnvelope) {
		Cleanse(distributed.state);
		return Failure(OpenMlsGroupChangePrepareStatus::EncodingFailure);
	}
	const auto requestHash = sha256.digest(*signedBytes);
	auto transaction = GroupChangeTransaction{
		.conversationId = args.actor.conversationId,
		.transactionId = args.transition.transitionId,
		.groupBaseRevision = groupLedger.revision(),
		.archiveBaseRevision = archiveState.revision(),
		.mlsBaseRevision = mlsState.revision(),
		.signedTransition = *signedTransition,
		.targetCredential = *args.targetCredential,
		.targetKeyPackage = std::move(args.targetKeyPackage),
		.mlsCommit = std::move(added.commit),
		.archiveDistribution = std::move(distributed.message),
		.nextMlsEngineState = std::move(distributed.state),
		.mlsReceipt = MlsOperationReceipt{
			.objectId = args.archiveDistributionObjectId,
			.requestHash = requestHash,
			.envelope = *distributionEnvelope,
		},
		.removalTombstone = std::nullopt,
		.archiveEpoch = ArchiveEpochSecret{
			.generation = args.transition.generation,
			.activationGroupGeneration = args.transition.generation,
			.activationEventId = args.transition.transitionId,
			.key = args.nextArchiveKey->clone(),
		},
		.outboxEnvelopes = {
			*transitionEnvelope,
			*commitEnvelope,
			*welcomeEnvelope,
			*distributionEnvelope,
		},
	};
	return {
		.status = OpenMlsGroupChangePrepareStatus::Prepared,
		.prepared = PreparedOpenMlsGroupChange{
			.transaction = std::move(transaction),
			.applied = std::move(*verified.applied),
			.resultingRoster = std::move(*roster),
		},
	};
}

[[nodiscard]] static auto PrepareOpenMlsExistingChange(
		PrepareOpenMlsRemovalArgs args,
		const OpenMlsBridge &bridge,
		const MlsContextCodecV1 &contextCodec,
		const MlsRosterCodecV1 &rosterCodec,
		const GroupControlCodecV1 &controlCodec,
		const EnvelopeCodec &envelopeCodec,
		const Sha256Provider &sha256,
		const PersistentMlsStateStore &mlsState,
		const PersistentArchiveState &archiveState,
		const PersistentGroupLedger &groupLedger)
-> PrepareOpenMlsGroupChangeOutcome {
	if (!args.currentGroupState
		|| !args.actorCredential
		|| !args.actorSigningPrivateKey
		|| !args.actorSigningPrivateKey->valid()
		|| !args.nextArchiveKey
		|| !args.nextArchiveKey->valid()
		|| !args.mlsCommitObjectId
		|| !args.archiveDistributionObjectId
		|| args.mlsCommitObjectId == args.archiveDistributionObjectId
		|| !ExistingMemberKind(args.transition.kind)) {
		return Failure(OpenMlsGroupChangePrepareStatus::InvalidArguments);
	}
	const auto &current = *args.currentGroupState;
	const auto actorMember = groupLedger.state()
		? groupLedger.state()->memberByClient(args.actor.clientId)
		: nullptr;
	if (!mlsState.loaded()
		|| !mlsState.revision()
		|| mlsState.engineId() != OpenMlsEngineId()
		|| mlsState.engineState().isEmpty()
		|| !archiveState.loaded()
		|| !groupLedger.loaded()
		|| !groupLedger.state()) {
		return Failure(OpenMlsGroupChangePrepareStatus::StateUnavailable);
	} else if (args.actor.conversationId != current.conversationId()
		|| mlsState.conversationId() != current.conversationId()
		|| archiveState.conversationId() != current.conversationId()
		|| groupLedger.state()->conversationId() != current.conversationId()
		|| args.currentCheckpoint != groupLedger.checkpoint()
		|| current.snapshot() != groupLedger.state()->snapshot()
		|| !actorMember
		|| args.actor.accountId != actorMember->accountId) {
		return Failure(OpenMlsGroupChangePrepareStatus::StateUnavailable);
	}
	const auto currentArchiveEpoch = archiveState.currentEpoch();
	if (!currentArchiveEpoch
		|| currentArchiveEpoch->generation != current.generation()
		|| args.transition.previousGeneration != current.generation()
		|| args.transition.generation != current.generation() + 1) {
		return Failure(
			OpenMlsGroupChangePrepareStatus::ArchiveInvariantViolation);
	}
	auto inspected = bridge.inspectGroup(mlsState.engineState());
	const auto currentRoster = inspected.status == OpenMlsBridgeStatus::Ok
		? rosterCodec.decode(inspected.roster, contextCodec)
		: std::nullopt;
	Cleanse(inspected.state);
	if (!currentRoster || !MlsRosterMatchesGroupState(*currentRoster, current)) {
		return Failure(OpenMlsGroupChangePrepareStatus::RosterMismatch);
	}
	auto leafIndices = std::vector<std::uint32_t>();
	if (RemovalKind(args.transition.kind)) {
		for (const auto &member : currentRoster->members) {
			const auto accountMatches = member.credential.accountId
				== args.transition.targetAccountId;
			const auto clientMatches = member.credential.clientId
				== args.transition.targetClientId;
			if ((args.transition.kind == GroupTransitionKind::RemoveMember
					&& accountMatches)
				|| (args.transition.kind == GroupTransitionKind::RemoveClient
					&& accountMatches
					&& clientMatches)) {
				leafIndices.push_back(member.leafIndex);
			}
		}
	}
	if (RemovalKind(args.transition.kind) && leafIndices.empty()) {
		return Failure(OpenMlsGroupChangePrepareStatus::RosterMismatch);
	}
	const auto archiveCommitment = DeriveArchiveKeyCommitment(
		args.transition.conversationId,
		args.transition.generation,
		args.transition.generation,
		args.transition.transitionId,
		*args.nextArchiveKey,
		sha256);
	if (!archiveCommitment) {
		return Failure(OpenMlsGroupChangePrepareStatus::EncodingFailure);
	}
	const auto prelude = GroupChangePrelude{
		.transition = args.transition,
		.actorAccountId = args.actor.accountId,
		.actorClientId = args.actor.clientId,
		.previousStateHash = args.currentCheckpoint.stateHash,
		.mlsCommitObjectId = args.mlsCommitObjectId,
		.archiveDistributionObjectId = args.archiveDistributionObjectId,
		.archiveKeyCommitment = *archiveCommitment,
		.targetClientAuthorization = std::nullopt,
	};
	const auto preludeBytes = controlCodec.encodePrelude(prelude);
	const auto commitAad = preludeBytes
		? contextCodec.encodeAad({
			.conversationId = args.actor.conversationId,
			.objectKind = ObjectKind::MlsCommit,
			.senderAccountId = args.actor.accountId,
			.senderClientId = args.actor.clientId,
			.telegramPeerIdBinding = args.actor.telegramPeerIdBinding,
			.objectId = args.mlsCommitObjectId,
			.context = *preludeBytes,
		})
		: std::nullopt;
	if (!preludeBytes || !commitAad) {
		return Failure(OpenMlsGroupChangePrepareStatus::EncodingFailure);
	}
	auto removed = PolicyKind(args.transition.kind)
		? bridge.updateGroup(mlsState.engineState(), *commitAad)
		: bridge.removeMembers(
			mlsState.engineState(),
			leafIndices,
			*commitAad);
	if (removed.status != OpenMlsBridgeStatus::Ok
		|| removed.state.isEmpty()
		|| removed.commit.isEmpty()
		|| !removed.welcome.isEmpty()
		|| removed.roster.isEmpty()) {
		Cleanse(removed.state);
		return Failure(OpenMlsGroupChangePrepareStatus::MlsFailure);
	}
	auto distributionPlaintext = controlCodec.encodeArchiveDistribution({
		.conversationId = args.actor.conversationId,
		.transitionId = args.transition.transitionId,
		.groupGeneration = args.transition.generation,
		.archiveEpochGeneration = args.transition.generation,
		.activationEventId = args.transition.transitionId,
		.key = args.nextArchiveKey->clone(),
	});
	if (!distributionPlaintext) {
		Cleanse(removed.state);
		return Failure(OpenMlsGroupChangePrepareStatus::EncodingFailure);
	}
	auto distributionContext = *preludeBytes;
	const auto commitHash = sha256.digest(removed.commit);
	distributionContext.append(
		reinterpret_cast<const char*>(commitHash.bytes.data()),
		commitHash.bytes.size());
	const auto distributionAad = contextCodec.encodeAad({
		.conversationId = args.actor.conversationId,
		.objectKind = ObjectKind::ArchiveEpoch,
		.senderAccountId = args.actor.accountId,
		.senderClientId = args.actor.clientId,
		.telegramPeerIdBinding = args.actor.telegramPeerIdBinding,
		.objectId = args.archiveDistributionObjectId,
		.context = std::move(distributionContext),
	});
	if (!distributionAad) {
		Cleanse(removed.state);
		Cleanse(*distributionPlaintext);
		return Failure(OpenMlsGroupChangePrepareStatus::EncodingFailure);
	}
	auto distributed = bridge.seal(
		removed.state,
		*distributionAad,
		*distributionPlaintext);
	Cleanse(removed.state);
	Cleanse(*distributionPlaintext);
	if (distributed.status != OpenMlsBridgeStatus::Ok
		|| distributed.state.isEmpty()
		|| distributed.message.isEmpty()
		|| distributed.epoch != removed.epoch) {
		Cleanse(distributed.state);
		return Failure(OpenMlsGroupChangePrepareStatus::MlsFailure);
	}
	const auto signedTransition = CreateSignedGroupTransition({
		.transition = args.transition,
		.actorAccountId = args.actor.accountId,
		.actorClientId = args.actor.clientId,
		.previousStateHash = args.currentCheckpoint.stateHash,
		.mlsCommitObjectId = args.mlsCommitObjectId,
		.actorCredential = args.actorCredential,
		.actorSigningPrivateKey = args.actorSigningPrivateKey,
		.nextArchiveKey = args.nextArchiveKey,
		.archiveDistributionObjectId = args.archiveDistributionObjectId,
		.archiveDistribution = distributed.message,
		.targetClientAuthorization = nullptr,
		.mlsCommit = removed.commit,
	}, sha256);
	if (!signedTransition) {
		Cleanse(distributed.state);
		return Failure(OpenMlsGroupChangePrepareStatus::SignatureFailure);
	}
	auto verified = VerifyAndApplySignedGroupTransition({
		.currentState = &current,
		.currentCheckpoint = args.currentCheckpoint,
		.signedTransition = &*signedTransition,
		.actorCredential = args.actorCredential,
		.targetCredential = nullptr,
		.mlsCommitObjectId = args.mlsCommitObjectId,
		.mlsCommit = removed.commit,
		.nextArchiveKey = args.nextArchiveKey,
		.archiveDistributionObjectId = args.archiveDistributionObjectId,
		.archiveDistribution = distributed.message,
		.targetKeyPackage = {},
	}, sha256);
	const auto roster = rosterCodec.decode(removed.roster, contextCodec);
	if (verified.result != SignedGroupTransitionResult::Applied
		|| !verified.applied
		|| !roster
		|| !MlsRosterMatchesGroupState(*roster, verified.applied->state)) {
		Cleanse(distributed.state);
		return Failure(OpenMlsGroupChangePrepareStatus::RosterMismatch);
	}
	const auto signedBytes = SignedGroupTransitionCodecV1().encode(
		*signedTransition);
	const auto commitEnvelope = envelopeCodec.encode({
		.conversationId = args.actor.conversationId,
		.objectKind = ObjectKind::MlsCommit,
		.senderAccountId = args.actor.accountId,
		.senderClientId = args.actor.clientId,
		.telegramPeerIdBinding = args.actor.telegramPeerIdBinding,
		.epochOrGeneration = removed.epoch,
		.objectId = args.mlsCommitObjectId,
		.payloadHash = sha256.digest(removed.commit),
		.payload = removed.commit,
		.authenticationData = *commitAad,
	});
	const auto distributionEnvelope = envelopeCodec.encode({
		.conversationId = args.actor.conversationId,
		.objectKind = ObjectKind::ArchiveEpoch,
		.senderAccountId = args.actor.accountId,
		.senderClientId = args.actor.clientId,
		.telegramPeerIdBinding = args.actor.telegramPeerIdBinding,
		.epochOrGeneration = distributed.epoch,
		.objectId = args.archiveDistributionObjectId,
		.payloadHash = sha256.digest(distributed.message),
		.payload = distributed.message,
		.authenticationData = *distributionAad,
	});
	const auto transitionEnvelope = signedBytes
		? envelopeCodec.encode({
			.conversationId = args.actor.conversationId,
			.objectKind = ObjectKind::SignedGroupTransition,
			.senderAccountId = args.actor.accountId,
			.senderClientId = args.actor.clientId,
			.telegramPeerIdBinding = args.actor.telegramPeerIdBinding,
			.epochOrGeneration = args.transition.generation,
			.objectId = args.transition.transitionId,
			.payloadHash = sha256.digest(*signedBytes),
			.payload = *signedBytes,
			.authenticationData = SignatureBytes(
				signedTransition->actorSignature),
		})
		: std::nullopt;
	if (!signedBytes
		|| !commitEnvelope
		|| !distributionEnvelope
		|| !transitionEnvelope) {
		Cleanse(distributed.state);
		return Failure(OpenMlsGroupChangePrepareStatus::EncodingFailure);
	}
	auto transaction = GroupChangeTransaction{
		.conversationId = args.actor.conversationId,
		.transactionId = args.transition.transitionId,
		.groupBaseRevision = groupLedger.revision(),
		.archiveBaseRevision = archiveState.revision(),
		.mlsBaseRevision = mlsState.revision(),
		.signedTransition = *signedTransition,
		.targetCredential = std::nullopt,
		.targetKeyPackage = {},
		.mlsCommit = std::move(removed.commit),
		.archiveDistribution = std::move(distributed.message),
		.nextMlsEngineState = std::move(distributed.state),
		.mlsReceipt = MlsOperationReceipt{
			.objectId = args.archiveDistributionObjectId,
			.requestHash = sha256.digest(*signedBytes),
			.envelope = *distributionEnvelope,
		},
		.removalTombstone = std::nullopt,
		.archiveEpoch = ArchiveEpochSecret{
			.generation = args.transition.generation,
			.activationGroupGeneration = args.transition.generation,
			.activationEventId = args.transition.transitionId,
			.key = args.nextArchiveKey->clone(),
		},
		.outboxEnvelopes = {
			*transitionEnvelope,
			*commitEnvelope,
			*distributionEnvelope,
		},
	};
	return {
		.status = OpenMlsGroupChangePrepareStatus::Prepared,
		.prepared = PreparedOpenMlsGroupChange{
			.transaction = std::move(transaction),
			.applied = std::move(*verified.applied),
			.resultingRoster = std::move(*roster),
		},
	};
}

PrepareOpenMlsGroupChangeOutcome PrepareOpenMlsRemoval(
		PrepareOpenMlsRemovalArgs args,
		const OpenMlsBridge &bridge,
		const MlsContextCodecV1 &contextCodec,
		const MlsRosterCodecV1 &rosterCodec,
		const GroupControlCodecV1 &controlCodec,
		const EnvelopeCodec &envelopeCodec,
		const Sha256Provider &sha256,
		const PersistentMlsStateStore &mlsState,
		const PersistentArchiveState &archiveState,
		const PersistentGroupLedger &groupLedger) {
	if (!RemovalKind(args.transition.kind)) {
		return Failure(OpenMlsGroupChangePrepareStatus::InvalidArguments);
	}
	return PrepareOpenMlsExistingChange(
		std::move(args),
		bridge,
		contextCodec,
		rosterCodec,
		controlCodec,
		envelopeCodec,
		sha256,
		mlsState,
		archiveState,
		groupLedger);
}

PrepareOpenMlsGroupChangeOutcome PrepareOpenMlsPolicyChange(
		PrepareOpenMlsPolicyChangeArgs args,
		const OpenMlsBridge &bridge,
		const MlsContextCodecV1 &contextCodec,
		const MlsRosterCodecV1 &rosterCodec,
		const GroupControlCodecV1 &controlCodec,
		const EnvelopeCodec &envelopeCodec,
		const Sha256Provider &sha256,
		const PersistentMlsStateStore &mlsState,
		const PersistentArchiveState &archiveState,
		const PersistentGroupLedger &groupLedger) {
	if (!PolicyKind(args.transition.kind)) {
		return Failure(OpenMlsGroupChangePrepareStatus::InvalidArguments);
	}
	return PrepareOpenMlsExistingChange({
		.actor = args.actor,
		.currentGroupState = args.currentGroupState,
		.currentCheckpoint = args.currentCheckpoint,
		.transition = args.transition,
		.actorCredential = args.actorCredential,
		.actorSigningPrivateKey = args.actorSigningPrivateKey,
		.nextArchiveKey = args.nextArchiveKey,
		.mlsCommitObjectId = args.mlsCommitObjectId,
		.archiveDistributionObjectId = args.archiveDistributionObjectId,
	},
	bridge,
	contextCodec,
	rosterCodec,
	controlCodec,
	envelopeCodec,
	sha256,
	mlsState,
	archiveState,
	groupLedger);
}

} // namespace E2ECloud
