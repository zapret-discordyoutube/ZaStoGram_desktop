/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "e2e_cloud/mls/openmls_inbound_group_change.h"

#include "e2e_cloud/mls/openmls_bridge.h"

#include <openssl/crypto.h>

#include <algorithm>
#include <utility>

namespace E2ECloud {
namespace {

[[nodiscard]] PrepareOpenMlsInboundGroupChangeOutcome Failure(
		OpenMlsInboundGroupChangeStatus status) {
	return {
		.status = status,
		.prepared = std::nullopt,
	};
}

void Cleanse(QByteArray &bytes) {
	if (!bytes.isEmpty()) {
		OPENSSL_cleanse(bytes.data(), bytes.size());
	}
	bytes.clear();
}

[[nodiscard]] bool AdmissionKind(GroupTransitionKind kind) {
	return kind == GroupTransitionKind::AddMember
		|| kind == GroupTransitionKind::AddClient;
}

[[nodiscard]] bool SupportedKind(GroupTransitionKind kind) {
	return AdmissionKind(kind)
		|| kind == GroupTransitionKind::RemoveMember
		|| kind == GroupTransitionKind::RemoveClient
		|| kind == GroupTransitionKind::SetRole
		|| kind == GroupTransitionKind::TransferOwnership
		|| kind == GroupTransitionKind::SetDefaultHistory
		|| kind == GroupTransitionKind::SetMemberHistory;
}

[[nodiscard]] bool ValidEnvelope(
		const TransportEnvelope &envelope,
		const OpenMlsClientContext &local,
		ObjectKind kind,
		const Sha256Provider &sha256) {
	return ValidateEnvelope(envelope) == EnvelopeValidationError::None
		&& envelope.conversationId == local.conversationId
		&& envelope.telegramPeerIdBinding
			== local.telegramPeerIdBinding
		&& envelope.objectKind == kind
		&& envelope.payloadHash == sha256.digest(envelope.payload);
}

[[nodiscard]] bool SameSender(
		const TransportEnvelope &a,
		const TransportEnvelope &b) {
	return a.senderAccountId == b.senderAccountId
		&& a.senderClientId == b.senderClientId;
}

[[nodiscard]] bool AadMatchesEnvelope(
		const MlsTransportAad &aad,
		const TransportEnvelope &envelope) {
	return aad.conversationId == envelope.conversationId
		&& aad.objectKind == envelope.objectKind
		&& aad.senderAccountId == envelope.senderAccountId
		&& aad.senderClientId == envelope.senderClientId
		&& aad.telegramPeerIdBinding == envelope.telegramPeerIdBinding
		&& aad.objectId == envelope.objectId;
}

[[nodiscard]] OpenMlsInboundGroupChangeStatus ProcessFailure(
		OpenMlsBridgeStatus status,
		OpenMlsInboundGroupChangeStatus deferred,
		OpenMlsInboundGroupChangeStatus rejected) {
	return (status == OpenMlsBridgeStatus::CryptoError)
		? deferred
		: rejected;
}

} // namespace

PrepareOpenMlsInboundGroupChangeOutcome PrepareOpenMlsInboundGroupChange(
		OpenMlsInboundGroupChangeArgs args,
		const OpenMlsBridge &bridge,
		const MlsContextCodecV1 &contextCodec,
		const MlsRosterCodecV1 &rosterCodec,
		const GroupControlCodecV1 &controlCodec,
		const Sha256Provider &sha256,
		const PersistentMlsStateStore &mlsState,
		const PersistentArchiveState &archiveState,
		const PersistentGroupLedger &groupLedger) {
	if (!args.local.conversationId
		|| !args.local.accountId
		|| !args.local.clientId
		|| !args.local.telegramPeerIdBinding
		|| !bridge.compatible()) {
		return Failure(OpenMlsInboundGroupChangeStatus::InvalidArguments);
	} else if (!mlsState.loaded()
		|| !mlsState.revision()
		|| mlsState.engineId() != OpenMlsEngineId()
		|| mlsState.engineState().isEmpty()
		|| !archiveState.loaded()
		|| !groupLedger.loaded()
		|| !groupLedger.state()
		|| mlsState.conversationId() != args.local.conversationId
		|| archiveState.conversationId() != args.local.conversationId
		|| groupLedger.state()->conversationId()
			!= args.local.conversationId
		|| !groupLedger.state()->memberByClient(args.local.clientId)) {
		return Failure(OpenMlsInboundGroupChangeStatus::StateUnavailable);
	}
	const auto &transitionEnvelope = args.transitionEnvelope;
	const auto &commitEnvelope = args.commitEnvelope;
	const auto &distributionEnvelope = args.archiveDistributionEnvelope;
	if (!ValidEnvelope(
			transitionEnvelope,
			args.local,
			ObjectKind::SignedGroupTransition,
			sha256)
		|| !ValidEnvelope(
			commitEnvelope,
			args.local,
			ObjectKind::MlsCommit,
			sha256)
		|| !ValidEnvelope(
			distributionEnvelope,
			args.local,
			ObjectKind::ArchiveEpoch,
			sha256)
		|| !SameSender(transitionEnvelope, commitEnvelope)
		|| !SameSender(transitionEnvelope, distributionEnvelope)) {
		return Failure(OpenMlsInboundGroupChangeStatus::InvalidEnvelope);
	}
	const auto signedTransition = SignedGroupTransitionCodecV1().decode(
		transitionEnvelope.payload);
	if (!signedTransition
		|| !SupportedKind(signedTransition->transition.kind)
		|| transitionEnvelope.objectId
			!= signedTransition->transition.transitionId
		|| transitionEnvelope.epochOrGeneration
			!= signedTransition->transition.generation
		|| transitionEnvelope.senderAccountId
			!= signedTransition->actorAccountId
		|| transitionEnvelope.senderClientId
			!= signedTransition->actorClientId
		|| commitEnvelope.objectId
			!= signedTransition->mlsCommitObjectId
		|| commitEnvelope.payloadHash != signedTransition->mlsCommitHash
		|| distributionEnvelope.objectId
			!= signedTransition->archiveDistributionObjectId
		|| distributionEnvelope.payloadHash
			!= signedTransition->archiveDistributionHash
		|| transitionEnvelope.authenticationData.size()
			!= int(signedTransition->actorSignature.size())
		|| !std::equal(
			std::begin(signedTransition->actorSignature),
			std::end(signedTransition->actorSignature),
			reinterpret_cast<const std::uint8_t*>(
				transitionEnvelope.authenticationData.constData()))) {
		return Failure(OpenMlsInboundGroupChangeStatus::InvalidEnvelope);
	}
	const auto actorMember = groupLedger.state()->memberByClient(
		signedTransition->actorClientId);
	const auto actorCredential = groupLedger.credential(
		signedTransition->actorAccountId);
	const auto currentArchiveEpoch = archiveState.currentEpoch();
	if (!actorMember
		|| actorMember->accountId != signedTransition->actorAccountId
		|| !actorCredential
		|| signedTransition->transition.previousGeneration
			!= groupLedger.state()->generation()
		|| signedTransition->transition.generation
			!= groupLedger.state()->generation() + 1
		|| signedTransition->previousStateHash
			!= groupLedger.checkpoint().stateHash
		|| !currentArchiveEpoch
		|| currentArchiveEpoch->generation
			!= groupLedger.state()->generation()) {
		return Failure(OpenMlsInboundGroupChangeStatus::StateUnavailable);
	}
	const auto targetCredential = args.targetCredential
		? &*args.targetCredential
		: groupLedger.credential(
			signedTransition->transition.targetAccountId);
	if (AdmissionKind(signedTransition->transition.kind)
		&& (!targetCredential || args.targetKeyPackage.isEmpty())) {
		return Failure(
			OpenMlsInboundGroupChangeStatus::MissingAdmissionMaterial);
	} else if (!AdmissionKind(signedTransition->transition.kind)
		&& (args.targetCredential || !args.targetKeyPackage.isEmpty())) {
		return Failure(OpenMlsInboundGroupChangeStatus::InvalidArguments);
	}
	auto inspected = bridge.inspectGroup(mlsState.engineState());
	const auto currentRoster = inspected.status == OpenMlsBridgeStatus::Ok
		? rosterCodec.decode(inspected.roster, contextCodec)
		: std::nullopt;
	Cleanse(inspected.state);
	if (!currentRoster
		|| !MlsRosterMatchesGroupState(*currentRoster, *groupLedger.state())) {
		return Failure(OpenMlsInboundGroupChangeStatus::RosterMismatch);
	}
	const auto commitAad = contextCodec.decodeAad(
		commitEnvelope.authenticationData);
	const auto prelude = commitAad
		? controlCodec.decodePrelude(commitAad->context)
		: std::nullopt;
	if (!commitAad
		|| !AadMatchesEnvelope(*commitAad, commitEnvelope)
		|| !prelude
		|| !GroupChangePreludeMatchesSignedTransition(
			*prelude,
			*signedTransition)) {
		return Failure(OpenMlsInboundGroupChangeStatus::InvalidEnvelope);
	}
	auto committed = bridge.process(
		mlsState.engineState(),
		commitEnvelope.payload);
	if (committed.status != OpenMlsBridgeStatus::Ok) {
		Cleanse(committed.state);
		Cleanse(committed.plaintext);
		return Failure(ProcessFailure(
			committed.status,
			OpenMlsInboundGroupChangeStatus::CommitDeferred,
			OpenMlsInboundGroupChangeStatus::CommitRejected));
	}
	const auto commitSender = contextCodec.decodeCredential(
		committed.senderCredential);
	const auto committedRoster = rosterCodec.decode(
		committed.roster,
		contextCodec);
	if (committed.kind != OpenMlsContentKind::Commit
		|| committed.senderIndex == kOpenMlsNonMemberSender
		|| !committed.plaintext.isEmpty()
		|| committed.authenticatedData != commitEnvelope.authenticationData
		|| !commitSender
		|| commitSender->conversationId != args.local.conversationId
		|| commitSender->accountId != signedTransition->actorAccountId
		|| commitSender->clientId != signedTransition->actorClientId
		|| !committedRoster
		|| committedRoster->epoch != commitEnvelope.epochOrGeneration
		|| distributionEnvelope.epochOrGeneration
			!= committedRoster->epoch) {
		Cleanse(committed.state);
		Cleanse(committed.plaintext);
		return Failure(OpenMlsInboundGroupChangeStatus::CommitRejected);
	}
	const auto distributionAad = contextCodec.decodeAad(
		distributionEnvelope.authenticationData);
	auto expectedDistributionContext = commitAad->context;
	const auto commitHash = sha256.digest(commitEnvelope.payload);
	expectedDistributionContext.append(
		reinterpret_cast<const char*>(commitHash.bytes.data()),
		commitHash.bytes.size());
	if (!distributionAad
		|| !AadMatchesEnvelope(*distributionAad, distributionEnvelope)
		|| distributionAad->context != expectedDistributionContext) {
		Cleanse(committed.state);
		return Failure(OpenMlsInboundGroupChangeStatus::InvalidEnvelope);
	}
	const auto localStillPresent = std::any_of(
		std::begin(committedRoster->members),
		std::end(committedRoster->members),
		[&](const MlsRosterMember &member) {
			return member.credential.accountId == args.local.accountId
				&& member.credential.clientId == args.local.clientId;
		});
	if (!localStillPresent) {
		const auto removesLocal = signedTransition->transition.kind
			== GroupTransitionKind::RemoveMember
			? (signedTransition->transition.targetAccountId
				== args.local.accountId)
			: (signedTransition->transition.kind
					== GroupTransitionKind::RemoveClient
				&& signedTransition->transition.targetAccountId
					== args.local.accountId
				&& signedTransition->transition.targetClientId
					== args.local.clientId);
		auto verified = removesLocal
			? VerifyAndApplySignedGroupTransition({
				.currentState = groupLedger.state(),
				.currentCheckpoint = groupLedger.checkpoint(),
				.signedTransition = &*signedTransition,
				.actorCredential = actorCredential,
				.targetCredential = nullptr,
				.mlsCommitObjectId = commitEnvelope.objectId,
				.mlsCommit = commitEnvelope.payload,
				.nextArchiveKey = nullptr,
				.archiveDistributionObjectId = distributionEnvelope.objectId,
				.archiveDistribution = distributionEnvelope.payload,
				.targetKeyPackage = {},
				.allowMissingArchiveKey = true,
			}, sha256)
			: VerifySignedGroupTransitionOutcome();
		Cleanse(committed.state);
		if (!removesLocal
			|| verified.result != SignedGroupTransitionResult::Applied
			|| !verified.applied
			|| !MlsRosterMatchesGroupState(
				*committedRoster,
				verified.applied->state)) {
			return Failure(OpenMlsInboundGroupChangeStatus::RosterMismatch);
		}
		auto transaction = GroupChangeTransaction{
			.conversationId = args.local.conversationId,
			.transactionId = signedTransition->transition.transitionId,
			.direction = GroupChangeTransactionDirection::InboundRemoval,
			.groupBaseRevision = groupLedger.revision(),
			.archiveBaseRevision = archiveState.revision(),
			.mlsBaseRevision = mlsState.revision(),
			.signedTransition = *signedTransition,
			.targetCredential = std::nullopt,
			.targetKeyPackage = {},
			.mlsCommit = commitEnvelope.payload,
			.archiveDistribution = distributionEnvelope.payload,
			.nextMlsEngineState = {},
			.mlsReceipt = std::nullopt,
			.removalTombstone = MlsRemovalTombstone{
				.transitionId = signedTransition->transition.transitionId,
				.generation = signedTransition->transition.generation,
				.resultingStateHash = signedTransition->resultingStateHash,
				.mlsCommitHash = signedTransition->mlsCommitHash,
				.removedAccountId = args.local.accountId,
				.removedClientId = args.local.clientId,
			},
			.archiveEpoch = std::nullopt,
			.outboxEnvelopes = {},
		};
		return {
			.status = OpenMlsInboundGroupChangeStatus::Prepared,
			.prepared = PreparedOpenMlsInboundGroupChange{
				.transaction = std::move(transaction),
				.applied = std::move(*verified.applied),
				.resultingRoster = std::move(*committedRoster),
			},
		};
	}
	auto distributed = bridge.process(
		committed.state,
		distributionEnvelope.payload);
	Cleanse(committed.state);
	if (distributed.status != OpenMlsBridgeStatus::Ok) {
		Cleanse(distributed.state);
		Cleanse(distributed.plaintext);
		return Failure(ProcessFailure(
			distributed.status,
			OpenMlsInboundGroupChangeStatus::DistributionDeferred,
			OpenMlsInboundGroupChangeStatus::DistributionRejected));
	}
	const auto distributionSender = contextCodec.decodeCredential(
		distributed.senderCredential);
	const auto resultingRoster = rosterCodec.decode(
		distributed.roster,
		contextCodec);
	auto archiveDistribution = controlCodec.decodeArchiveDistribution(
		distributed.plaintext);
	Cleanse(distributed.plaintext);
	if (distributed.kind != OpenMlsContentKind::Application
		|| distributed.senderIndex == kOpenMlsNonMemberSender
		|| distributed.epoch != distributionEnvelope.epochOrGeneration
		|| distributed.authenticatedData
			!= distributionEnvelope.authenticationData
		|| !distributionSender
		|| distributionSender->conversationId != args.local.conversationId
		|| distributionSender->accountId != signedTransition->actorAccountId
		|| distributionSender->clientId != signedTransition->actorClientId
		|| !resultingRoster
		|| *resultingRoster != *committedRoster
		|| !archiveDistribution
		|| archiveDistribution->conversationId != args.local.conversationId
		|| archiveDistribution->transitionId
			!= signedTransition->transition.transitionId
		|| archiveDistribution->groupGeneration
			!= signedTransition->transition.generation
		|| archiveDistribution->archiveEpochGeneration
			!= signedTransition->transition.generation
		|| archiveDistribution->activationEventId
			!= signedTransition->transition.transitionId) {
		Cleanse(distributed.state);
		return Failure(
			OpenMlsInboundGroupChangeStatus::DistributionRejected);
	}
	auto verified = VerifyAndApplySignedGroupTransition({
		.currentState = groupLedger.state(),
		.currentCheckpoint = groupLedger.checkpoint(),
		.signedTransition = &*signedTransition,
		.actorCredential = actorCredential,
		.targetCredential = targetCredential,
		.mlsCommitObjectId = commitEnvelope.objectId,
		.mlsCommit = commitEnvelope.payload,
		.nextArchiveKey = &archiveDistribution->key,
		.archiveDistributionObjectId = distributionEnvelope.objectId,
		.archiveDistribution = distributionEnvelope.payload,
		.targetKeyPackage = args.targetKeyPackage,
	}, sha256);
	if (verified.result != SignedGroupTransitionResult::Applied
		|| !verified.applied) {
		Cleanse(distributed.state);
		return Failure(OpenMlsInboundGroupChangeStatus::TransitionRejected);
	} else if (!MlsRosterMatchesGroupState(
			*resultingRoster,
			verified.applied->state)) {
		Cleanse(distributed.state);
		return Failure(OpenMlsInboundGroupChangeStatus::RosterMismatch);
	}
	auto transaction = GroupChangeTransaction{
		.conversationId = args.local.conversationId,
		.transactionId = signedTransition->transition.transitionId,
		.direction = GroupChangeTransactionDirection::Inbound,
		.groupBaseRevision = groupLedger.revision(),
		.archiveBaseRevision = archiveState.revision(),
		.mlsBaseRevision = mlsState.revision(),
		.signedTransition = *signedTransition,
		.targetCredential = std::move(args.targetCredential),
		.targetKeyPackage = std::move(args.targetKeyPackage),
		.mlsCommit = commitEnvelope.payload,
		.archiveDistribution = distributionEnvelope.payload,
		.nextMlsEngineState = std::move(distributed.state),
		.mlsReceipt = std::nullopt,
		.removalTombstone = std::nullopt,
		.archiveEpoch = ArchiveEpochSecret{
			.generation = signedTransition->transition.generation,
			.activationGroupGeneration =
				signedTransition->transition.generation,
			.activationEventId = signedTransition->transition.transitionId,
			.key = archiveDistribution->key.clone(),
		},
		.outboxEnvelopes = {},
	};
	if (AdmissionKind(signedTransition->transition.kind)
		&& !transaction.targetCredential) {
		transaction.targetCredential = *targetCredential;
	}
	return {
		.status = OpenMlsInboundGroupChangeStatus::Prepared,
		.prepared = PreparedOpenMlsInboundGroupChange{
			.transaction = std::move(transaction),
			.applied = std::move(*verified.applied),
			.resultingRoster = std::move(*resultingRoster),
		},
	};
}

PrepareOpenMlsInboundGroupChangeOutcome PrepareOpenMlsInboundJoin(
		OpenMlsInboundJoinArgs args,
		const OpenMlsBridge &bridge,
		const MlsContextCodecV1 &contextCodec,
		const MlsRosterCodecV1 &rosterCodec,
		const GroupControlCodecV1 &controlCodec,
		const Sha256Provider &sha256,
		const PersistentMlsStateStore &mlsState,
		const PersistentArchiveState &archiveState,
		const PersistentGroupLedger &groupLedger) {
	if (!args.local.conversationId
		|| !args.local.accountId
		|| !args.local.clientId
		|| !args.local.telegramPeerIdBinding
		|| args.targetKeyPackage.isEmpty()
		|| !bridge.compatible()) {
		return Failure(OpenMlsInboundGroupChangeStatus::InvalidArguments);
	} else if (!mlsState.loaded()
		|| !mlsState.revision()
		|| mlsState.engineId() != OpenMlsEngineId()
		|| mlsState.engineState().isEmpty()
		|| mlsState.removed()
		|| (archiveState.loaded() != bool(archiveState.revision()))
		|| !groupLedger.loaded()
		|| !groupLedger.state()
		|| mlsState.conversationId() != args.local.conversationId
		|| archiveState.conversationId() != args.local.conversationId
		|| groupLedger.state()->conversationId()
			!= args.local.conversationId
		|| groupLedger.state()->memberByClient(args.local.clientId)) {
		return Failure(OpenMlsInboundGroupChangeStatus::StateUnavailable);
	}
	const auto firstJoin = !archiveState.loaded();
	const auto &transitionEnvelope = args.transitionEnvelope;
	const auto &commitEnvelope = args.commitEnvelope;
	const auto &welcomeEnvelope = args.welcomeEnvelope;
	const auto &distributionEnvelope = args.archiveDistributionEnvelope;
	if (!ValidEnvelope(
			transitionEnvelope,
			args.local,
			ObjectKind::SignedGroupTransition,
			sha256)
		|| !ValidEnvelope(
			commitEnvelope,
			args.local,
			ObjectKind::MlsCommit,
			sha256)
		|| !ValidEnvelope(
			welcomeEnvelope,
			args.local,
			ObjectKind::MlsWelcome,
			sha256)
		|| !ValidEnvelope(
			distributionEnvelope,
			args.local,
			ObjectKind::ArchiveEpoch,
			sha256)
		|| !SameSender(transitionEnvelope, commitEnvelope)
		|| !SameSender(transitionEnvelope, welcomeEnvelope)
		|| !SameSender(transitionEnvelope, distributionEnvelope)) {
		return Failure(OpenMlsInboundGroupChangeStatus::InvalidEnvelope);
	}
	const auto signedTransition = SignedGroupTransitionCodecV1().decode(
		transitionEnvelope.payload);
	if (!signedTransition
		|| !AdmissionKind(signedTransition->transition.kind)
		|| signedTransition->transition.targetAccountId
			!= args.local.accountId
		|| signedTransition->transition.targetClientId
			!= args.local.clientId
		|| transitionEnvelope.objectId
			!= signedTransition->transition.transitionId
		|| transitionEnvelope.epochOrGeneration
			!= signedTransition->transition.generation
		|| transitionEnvelope.senderAccountId
			!= signedTransition->actorAccountId
		|| transitionEnvelope.senderClientId
			!= signedTransition->actorClientId
		|| commitEnvelope.objectId
			!= signedTransition->mlsCommitObjectId
		|| commitEnvelope.payloadHash != signedTransition->mlsCommitHash
		|| distributionEnvelope.objectId
			!= signedTransition->archiveDistributionObjectId
		|| distributionEnvelope.payloadHash
			!= signedTransition->archiveDistributionHash
		|| welcomeEnvelope.authenticationData != transitionEnvelope.payload
		|| welcomeEnvelope.epochOrGeneration
			!= commitEnvelope.epochOrGeneration
		|| distributionEnvelope.epochOrGeneration
			!= commitEnvelope.epochOrGeneration
		|| transitionEnvelope.authenticationData.size()
			!= int(signedTransition->actorSignature.size())
		|| !std::equal(
			std::begin(signedTransition->actorSignature),
			std::end(signedTransition->actorSignature),
			reinterpret_cast<const std::uint8_t*>(
				transitionEnvelope.authenticationData.constData()))) {
		return Failure(OpenMlsInboundGroupChangeStatus::InvalidEnvelope);
	}
	const auto actorMember = groupLedger.state()->memberByClient(
		signedTransition->actorClientId);
	const auto actorCredential = groupLedger.credential(
		signedTransition->actorAccountId);
	const auto targetCredential = args.targetCredential
		? &*args.targetCredential
		: groupLedger.credential(args.local.accountId);
	if (!actorMember
		|| actorMember->accountId != signedTransition->actorAccountId
		|| !actorCredential
		|| !targetCredential
		|| signedTransition->transition.previousGeneration
			!= groupLedger.state()->generation()
		|| signedTransition->transition.generation
			!= groupLedger.state()->generation() + 1
		|| signedTransition->previousStateHash
			!= groupLedger.checkpoint().stateHash) {
		return Failure(OpenMlsInboundGroupChangeStatus::StateUnavailable);
	}
	const auto commitAad = contextCodec.decodeAad(
		commitEnvelope.authenticationData);
	const auto prelude = commitAad
		? controlCodec.decodePrelude(commitAad->context)
		: std::nullopt;
	if (!commitAad
		|| !AadMatchesEnvelope(*commitAad, commitEnvelope)
		|| !prelude
		|| !GroupChangePreludeMatchesSignedTransition(
			*prelude,
			*signedTransition)) {
		return Failure(OpenMlsInboundGroupChangeStatus::InvalidEnvelope);
	}
	auto joined = bridge.join(
		mlsState.engineState(),
		welcomeEnvelope.payload);
	const auto joinedRoster = joined.status == OpenMlsBridgeStatus::Ok
		? rosterCodec.decode(joined.roster, contextCodec)
		: std::nullopt;
	if (joined.status != OpenMlsBridgeStatus::Ok
		|| joined.state.isEmpty()
		|| joined.epoch != welcomeEnvelope.epochOrGeneration
		|| !joinedRoster) {
		Cleanse(joined.state);
		return Failure(ProcessFailure(
			joined.status,
			OpenMlsInboundGroupChangeStatus::CommitDeferred,
			OpenMlsInboundGroupChangeStatus::CommitRejected));
	}
	const auto distributionAad = contextCodec.decodeAad(
		distributionEnvelope.authenticationData);
	auto expectedDistributionContext = commitAad->context;
	const auto commitHash = sha256.digest(commitEnvelope.payload);
	expectedDistributionContext.append(
		reinterpret_cast<const char*>(commitHash.bytes.data()),
		commitHash.bytes.size());
	if (!distributionAad
		|| !AadMatchesEnvelope(*distributionAad, distributionEnvelope)
		|| distributionAad->context != expectedDistributionContext) {
		Cleanse(joined.state);
		return Failure(OpenMlsInboundGroupChangeStatus::InvalidEnvelope);
	}
	auto distributed = bridge.process(
		joined.state,
		distributionEnvelope.payload);
	Cleanse(joined.state);
	if (distributed.status != OpenMlsBridgeStatus::Ok) {
		Cleanse(distributed.state);
		Cleanse(distributed.plaintext);
		return Failure(ProcessFailure(
			distributed.status,
			OpenMlsInboundGroupChangeStatus::DistributionDeferred,
			OpenMlsInboundGroupChangeStatus::DistributionRejected));
	}
	const auto distributionSender = contextCodec.decodeCredential(
		distributed.senderCredential);
	const auto resultingRoster = rosterCodec.decode(
		distributed.roster,
		contextCodec);
	auto archiveDistribution = controlCodec.decodeArchiveDistribution(
		distributed.plaintext);
	Cleanse(distributed.plaintext);
	if (distributed.kind != OpenMlsContentKind::Application
		|| distributed.senderIndex == kOpenMlsNonMemberSender
		|| distributed.epoch != distributionEnvelope.epochOrGeneration
		|| distributed.authenticatedData
			!= distributionEnvelope.authenticationData
		|| !distributionSender
		|| distributionSender->conversationId != args.local.conversationId
		|| distributionSender->accountId != signedTransition->actorAccountId
		|| distributionSender->clientId != signedTransition->actorClientId
		|| !resultingRoster
		|| *resultingRoster != *joinedRoster
		|| !archiveDistribution
		|| archiveDistribution->conversationId != args.local.conversationId
		|| archiveDistribution->transitionId
			!= signedTransition->transition.transitionId
		|| archiveDistribution->groupGeneration
			!= signedTransition->transition.generation
		|| archiveDistribution->archiveEpochGeneration
			!= signedTransition->transition.generation
		|| archiveDistribution->activationEventId
			!= signedTransition->transition.transitionId) {
		Cleanse(distributed.state);
		return Failure(
			OpenMlsInboundGroupChangeStatus::DistributionRejected);
	}
	auto verified = VerifyAndApplySignedGroupTransition({
		.currentState = groupLedger.state(),
		.currentCheckpoint = groupLedger.checkpoint(),
		.signedTransition = &*signedTransition,
		.actorCredential = actorCredential,
		.targetCredential = targetCredential,
		.mlsCommitObjectId = commitEnvelope.objectId,
		.mlsCommit = commitEnvelope.payload,
		.nextArchiveKey = &archiveDistribution->key,
		.archiveDistributionObjectId = distributionEnvelope.objectId,
		.archiveDistribution = distributionEnvelope.payload,
		.targetKeyPackage = args.targetKeyPackage,
	}, sha256);
	if (verified.result != SignedGroupTransitionResult::Applied
		|| !verified.applied) {
		Cleanse(distributed.state);
		return Failure(OpenMlsInboundGroupChangeStatus::TransitionRejected);
	} else if (!MlsRosterMatchesGroupState(
			*resultingRoster,
			verified.applied->state)) {
		Cleanse(distributed.state);
		return Failure(OpenMlsInboundGroupChangeStatus::RosterMismatch);
	}
	auto transaction = GroupChangeTransaction{
		.conversationId = args.local.conversationId,
		.transactionId = signedTransition->transition.transitionId,
		.direction = firstJoin
			? GroupChangeTransactionDirection::InboundJoin
			: GroupChangeTransactionDirection::InboundRejoin,
		.groupBaseRevision = groupLedger.revision(),
		.archiveBaseRevision = archiveState.revision(),
		.mlsBaseRevision = mlsState.revision(),
		.signedTransition = *signedTransition,
		.targetCredential = std::move(args.targetCredential),
		.targetKeyPackage = std::move(args.targetKeyPackage),
		.mlsCommit = commitEnvelope.payload,
		.archiveDistribution = distributionEnvelope.payload,
		.nextMlsEngineState = std::move(distributed.state),
		.mlsReceipt = std::nullopt,
		.removalTombstone = std::nullopt,
		.archiveEpoch = ArchiveEpochSecret{
			.generation = signedTransition->transition.generation,
			.activationGroupGeneration =
				signedTransition->transition.generation,
			.activationEventId = signedTransition->transition.transitionId,
			.key = archiveDistribution->key.clone(),
		},
		.outboxEnvelopes = {},
	};
	if (!transaction.targetCredential) {
		transaction.targetCredential = *targetCredential;
	}
	return {
		.status = OpenMlsInboundGroupChangeStatus::Prepared,
		.prepared = PreparedOpenMlsInboundGroupChange{
			.transaction = std::move(transaction),
			.applied = std::move(*verified.applied),
			.resultingRoster = std::move(*resultingRoster),
		},
	};
}

} // namespace E2ECloud
