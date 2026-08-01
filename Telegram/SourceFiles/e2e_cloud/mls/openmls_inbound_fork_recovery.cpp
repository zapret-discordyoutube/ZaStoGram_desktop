/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "e2e_cloud/mls/openmls_inbound_fork_recovery.h"

#include "e2e_cloud/mls/openmls_bridge.h"
#include "e2e_cloud/protocol/group_control_codec.h"

#include <openssl/crypto.h>

#include <algorithm>
#include <utility>

namespace E2ECloud {
namespace {

[[nodiscard]] PrepareOpenMlsInboundForkRecoveryOutcome Failure(
		OpenMlsInboundForkRecoveryStatus status) {
	return {
		.status = status,
		.prepared = std::nullopt,
	};
}

template <typename Array>
void AppendArray(QByteArray &result, const Array &value) {
	result.append(
		reinterpret_cast<const char*>(value.data()),
		int(value.size()));
}

[[nodiscard]] QByteArray SignatureBytes(
		const AccountSignature &signature) {
	return QByteArray(
		reinterpret_cast<const char*>(signature.data()),
		int(signature.size()));
}

[[nodiscard]] QByteArray WelcomeAuthenticationData(
		ObjectId recoveryId,
		Digest manifestHash) {
	auto result = QByteArray();
	result.reserve(64);
	AppendArray(result, recoveryId.bytes);
	AppendArray(result, manifestHash.bytes);
	return result;
}

void Cleanse(QByteArray &bytes) {
	if (!bytes.isEmpty()) {
		OPENSSL_cleanse(bytes.data(), bytes.size());
	}
	bytes.clear();
}

[[nodiscard]] bool EnvelopeMatches(
		const TransportEnvelope &envelope,
		ConversationId conversationId,
		std::uint64_t peerBinding,
		ObjectKind kind,
		ObjectId objectId,
		Digest payloadHash,
		const Sha256Provider &sha256) {
	return ValidateEnvelope(envelope) == EnvelopeValidationError::None
		&& envelope.conversationId == conversationId
		&& envelope.telegramPeerIdBinding == peerBinding
		&& envelope.objectKind == kind
		&& envelope.objectId == objectId
		&& envelope.payloadHash == payloadHash
		&& envelope.payloadHash == sha256.digest(envelope.payload);
}

} // namespace

PrepareOpenMlsInboundForkRecoveryOutcome PrepareOpenMlsInboundForkRecovery(
		PrepareOpenMlsInboundForkRecoveryArgs args,
		const OpenMlsBridge &bridge,
		const MlsContextCodecV1 &contextCodec,
		const MlsRosterCodecV1 &rosterCodec,
		const GroupControlCodecV1 &controlCodec,
		const Sha256Provider &sha256,
		const PersistentMlsStateStore &mlsState,
		const PersistentArchiveState &archiveState,
		const PersistentGroupLedger &groupLedger,
		const PersistentForkRecoveryLedger &forkLedger,
		const PersistentKeyPackagePool &keyPackagePool) {
	if (!args.local.conversationId
		|| !args.local.accountId
		|| !args.local.clientId
		|| !args.local.telegramPeerIdBinding
		|| !args.currentTime
		|| args.observedCandidates.size() < 2
		|| args.replacementKeyPackageEnvelopes.empty()) {
		return Failure(OpenMlsInboundForkRecoveryStatus::InvalidArguments);
	}
	if (!bridge.compatible()
		|| !mlsState.loaded()
		|| mlsState.removed()
		|| mlsState.engineId() != OpenMlsEngineId()
		|| !archiveState.loaded()
		|| !groupLedger.loaded()
		|| !forkLedger.loaded()
		|| !keyPackagePool.loaded()
		|| mlsState.conversationId() != args.local.conversationId
		|| archiveState.conversationId() != args.local.conversationId
		|| !groupLedger.state()
		|| groupLedger.state()->conversationId()
			!= args.local.conversationId) {
		return Failure(OpenMlsInboundForkRecoveryStatus::StateUnavailable);
	}
	const auto manifest = SignedForkRecoveryManifestCodecV1().decode(
		args.manifestEnvelope.payload);
	if (!manifest
		|| !EnvelopeMatches(
			args.manifestEnvelope,
			args.local.conversationId,
			args.local.telegramPeerIdBinding,
			ObjectKind::ForkRecoveryManifest,
			manifest->recoveryId,
			sha256.digest(args.manifestEnvelope.payload),
			sha256)
		|| args.manifestEnvelope.senderAccountId
			!= manifest->ownerAccountId
		|| args.manifestEnvelope.senderClientId != manifest->ownerClientId
		|| args.manifestEnvelope.authenticationData
			!= SignatureBytes(manifest->ownerSignature)) {
		return Failure(OpenMlsInboundForkRecoveryStatus::InvalidManifest);
	}
	const auto ownerCredential = groupLedger.credential(
		manifest->ownerAccountId);
	if (!ownerCredential
		|| !VerifySignedForkRecoveryManifestSignature(
			*manifest,
			*ownerCredential,
			sha256)) {
		return Failure(OpenMlsInboundForkRecoveryStatus::InvalidManifest);
	}
	const auto canonicalTransition = SignedGroupTransitionCodecV1().decode(
		args.canonicalTransitionEnvelope.payload);
	const auto commonState = groupLedger.stateAt(manifest->commonGeneration);
	const auto commonCheckpoint = groupLedger.checkpointAt(
		manifest->commonGeneration);
	const auto canonicalActorCredential = canonicalTransition
		? groupLedger.credential(canonicalTransition->actorAccountId)
		: nullptr;
	if (!canonicalTransition
		|| !commonState
		|| !commonCheckpoint
		|| !canonicalActorCredential
		|| !EnvelopeMatches(
			args.canonicalTransitionEnvelope,
			args.local.conversationId,
			args.local.telegramPeerIdBinding,
			ObjectKind::SignedGroupTransition,
			manifest->canonicalTransitionId,
			manifest->canonicalTransitionPayloadHash,
			sha256)
		|| args.canonicalTransitionEnvelope.senderAccountId
			!= canonicalTransition->actorAccountId
		|| args.canonicalTransitionEnvelope.senderClientId
			!= canonicalTransition->actorClientId
		|| !EnvelopeMatches(
			args.canonicalCommitEnvelope,
			args.local.conversationId,
			args.local.telegramPeerIdBinding,
			ObjectKind::MlsCommit,
			canonicalTransition->mlsCommitObjectId,
			canonicalTransition->mlsCommitHash,
			sha256)
		|| !EnvelopeMatches(
			args.canonicalArchiveDistributionEnvelope,
			args.local.conversationId,
			args.local.telegramPeerIdBinding,
			ObjectKind::ArchiveEpoch,
			canonicalTransition->archiveDistributionObjectId,
			canonicalTransition->archiveDistributionHash,
			sha256)) {
		return Failure(
			OpenMlsInboundForkRecoveryStatus::InvalidCanonicalTransition);
	}
	auto canonicalApplied = VerifyAndApplySignedGroupTransition({
		.currentState = &*commonState,
		.currentCheckpoint = *commonCheckpoint,
		.signedTransition = &*canonicalTransition,
		.actorCredential = canonicalActorCredential,
		.targetCredential = args.canonicalTargetCredential
			? &*args.canonicalTargetCredential
			: nullptr,
		.mlsCommitObjectId = canonicalTransition->mlsCommitObjectId,
		.mlsCommit = args.canonicalCommitEnvelope.payload,
		.nextArchiveKey = nullptr,
		.archiveDistributionObjectId =
			canonicalTransition->archiveDistributionObjectId,
		.archiveDistribution =
			args.canonicalArchiveDistributionEnvelope.payload,
		.targetKeyPackage = args.canonicalTargetKeyPackage,
		.allowMissingArchiveKey = true,
	}, sha256);
	if (canonicalApplied.result != SignedGroupTransitionResult::Applied
		|| !canonicalApplied.applied
		|| canonicalApplied.applied->checkpoint.stateHash
			!= manifest->canonicalStateHash) {
		return Failure(
			OpenMlsInboundForkRecoveryStatus::InvalidCanonicalTransition);
	}
	const auto localReplacement = std::find_if(
		begin(manifest->replacements),
		end(manifest->replacements),
		[&](const auto &replacement) {
			return replacement.accountId == args.local.accountId
				&& replacement.clientId == args.local.clientId;
		});
	if (localReplacement == end(manifest->replacements)) {
		return Failure(
			OpenMlsInboundForkRecoveryStatus::KeyPackageUnavailable);
	}
	const auto storedPackage = keyPackagePool.find(
		localReplacement->keyPackageHash,
		args.currentTime);
	if (!storedPackage
		|| !bridge.isKeyPackageState(storedPackage->privateEngineState)) {
		return Failure(
			OpenMlsInboundForkRecoveryStatus::KeyPackageUnavailable);
	}
	if (!EnvelopeMatches(
			args.recoveryCommitEnvelope,
			args.local.conversationId,
			args.local.telegramPeerIdBinding,
			ObjectKind::MlsCommit,
			manifest->recoveryCommitObjectId,
			manifest->recoveryCommitHash,
			sha256)
		|| !EnvelopeMatches(
			args.recoveryWelcomeEnvelope,
			args.local.conversationId,
			args.local.telegramPeerIdBinding,
			ObjectKind::MlsWelcome,
			manifest->recoveryWelcomeObjectId,
			manifest->recoveryWelcomeHash,
			sha256)
		|| args.recoveryWelcomeEnvelope.authenticationData
			!= WelcomeAuthenticationData(
				manifest->recoveryId,
				args.manifestEnvelope.payloadHash)
		|| !EnvelopeMatches(
			args.recoveryArchiveDistributionEnvelope,
			args.local.conversationId,
			args.local.telegramPeerIdBinding,
			ObjectKind::ArchiveEpoch,
			manifest->archiveDistributionObjectId,
			manifest->archiveDistributionHash,
			sha256)) {
		return Failure(OpenMlsInboundForkRecoveryStatus::InvalidEnvelope);
	}
	auto joined = bridge.join(
		storedPackage->privateEngineState,
		args.recoveryWelcomeEnvelope.payload);
	if (joined.status != OpenMlsBridgeStatus::Ok || joined.state.isEmpty()) {
		Cleanse(joined.state);
		return Failure(OpenMlsInboundForkRecoveryStatus::MlsFailure);
	}
	auto distributed = bridge.process(
		joined.state,
		args.recoveryArchiveDistributionEnvelope.payload);
	Cleanse(joined.state);
	if (distributed.status != OpenMlsBridgeStatus::Ok
		|| distributed.kind != OpenMlsContentKind::Application
		|| distributed.state.isEmpty()
		|| distributed.plaintext.isEmpty()
		|| distributed.authenticatedData
			!= args.recoveryArchiveDistributionEnvelope.authenticationData) {
		Cleanse(distributed.state);
		Cleanse(distributed.plaintext);
		return Failure(OpenMlsInboundForkRecoveryStatus::MlsFailure);
	}
	const auto archiveDistribution = controlCodec.decodeArchiveDistribution(
		distributed.plaintext);
	Cleanse(distributed.plaintext);
	if (!archiveDistribution
		|| archiveDistribution->conversationId != args.local.conversationId
		|| archiveDistribution->transitionId != manifest->recoveryId
		|| archiveDistribution->groupGeneration
			!= manifest->recoveryGeneration
		|| archiveDistribution->archiveEpochGeneration
			!= manifest->recoveryGeneration
		|| archiveDistribution->activationEventId != manifest->recoveryId) {
		Cleanse(distributed.state);
		return Failure(
			OpenMlsInboundForkRecoveryStatus::ArchiveInvariantViolation);
	}
	const auto resultingRoster = rosterCodec.decode(
		distributed.roster,
		contextCodec);
	if (!resultingRoster
		|| !MlsRosterMatchesGroupState(
			*resultingRoster,
			canonicalApplied.applied->state)) {
		Cleanse(distributed.state);
		return Failure(OpenMlsInboundForkRecoveryStatus::RosterMismatch);
	}
	if (VerifySignedForkRecoveryManifest({
		.manifest = &*manifest,
		.commonState = &*commonState,
		.canonicalState = &canonicalApplied.applied->state,
		.commonCheckpoint = *commonCheckpoint,
		.canonicalCheckpoint = canonicalApplied.applied->checkpoint,
		.observedCandidates = args.observedCandidates,
		.replacementKeyPackageEnvelopes =
			args.replacementKeyPackageEnvelopes,
		.recoveryCommitObjectId = args.recoveryCommitEnvelope.objectId,
		.recoveryCommit = args.recoveryCommitEnvelope.payload,
		.recoveryWelcomeObjectId = args.recoveryWelcomeEnvelope.objectId,
		.recoveryWelcome = args.recoveryWelcomeEnvelope.payload,
		.archiveDistributionObjectId =
			args.recoveryArchiveDistributionEnvelope.objectId,
		.archiveDistribution =
			args.recoveryArchiveDistributionEnvelope.payload,
		.nextArchiveKey = &archiveDistribution->key,
		.ownerCredential = ownerCredential,
		.currentTime = args.currentTime,
	}, sha256) != ForkRecoveryManifestResult::Verified) {
		Cleanse(distributed.state);
		return Failure(OpenMlsInboundForkRecoveryStatus::InvalidManifest);
	}
	const auto currentArchiveEpoch = archiveState.currentEpoch();
	if (!currentArchiveEpoch
		|| currentArchiveEpoch->generation != manifest->resolvedGeneration
		|| groupLedger.state()->generation() != manifest->resolvedGeneration) {
		Cleanse(distributed.state);
		return Failure(
			OpenMlsInboundForkRecoveryStatus::ArchiveInvariantViolation);
	}
	return {
		.status = OpenMlsInboundForkRecoveryStatus::Prepared,
		.prepared = PreparedOpenMlsInboundForkRecovery{
			.transaction = {
				.conversationId = args.local.conversationId,
				.transactionId = manifest->recoveryId,
				.direction = ForkRecoveryTransactionDirection::Inbound,
				.groupBaseRevision = groupLedger.revision(),
				.archiveBaseRevision = archiveState.revision(),
				.mlsBaseRevision = mlsState.revision(),
				.forkLedgerBaseRevision = forkLedger.revision(),
				.manifest = *manifest,
				.canonicalTransition = *canonicalTransition,
				.canonicalTargetCredential =
					args.canonicalTargetCredential,
				.canonicalTargetKeyPackage =
					std::move(args.canonicalTargetKeyPackage),
				.canonicalMlsCommit = args.canonicalCommitEnvelope.payload,
				.canonicalArchiveDistribution =
					args.canonicalArchiveDistributionEnvelope.payload,
				.consumedKeyPackageHash =
					localReplacement->keyPackageHash,
				.keyPackagePoolBaseRevision = keyPackagePool.revision(),
				.archiveEpoch = {
					.generation = manifest->recoveryGeneration,
					.activationGroupGeneration = manifest->recoveryGeneration,
					.activationEventId = manifest->recoveryId,
					.key = archiveDistribution->key.clone(),
				},
				.nextMlsEngineState = std::move(distributed.state),
				.outboxEnvelopes = {},
			},
			.resultingRoster = *resultingRoster,
		},
	};
}

} // namespace E2ECloud
