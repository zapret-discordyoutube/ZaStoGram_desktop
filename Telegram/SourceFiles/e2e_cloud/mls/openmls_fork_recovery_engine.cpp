/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "e2e_cloud/mls/openmls_fork_recovery_engine.h"

#include "e2e_cloud/core/envelope_codec.h"
#include "e2e_cloud/mls/openmls_bridge.h"
#include "e2e_cloud/protocol/group_control_codec.h"

#include <openssl/crypto.h>

#include <algorithm>
#include <array>
#include <map>
#include <set>
#include <utility>

namespace E2ECloud {
namespace {

inline constexpr auto kIntentMagic = std::array<std::uint8_t, 8>{
	'T', 'D', 'E', '2', 'E', 'F', 'R', 'I',
};

[[nodiscard]] PrepareOpenMlsForkRecoveryOutcome Failure(
		OpenMlsForkRecoveryPrepareStatus status) {
	return {
		.status = status,
		.prepared = std::nullopt,
	};
}

void AppendUint16(QByteArray &result, std::uint16_t value) {
	result.append(char(value >> 8));
	result.append(char(value));
}

void AppendUint64(QByteArray &result, std::uint64_t value) {
	for (auto shift = 56; shift >= 0; shift -= 8) {
		result.append(char(value >> shift));
	}
}

template <typename Array>
void AppendArray(QByteArray &result, const Array &value) {
	result.append(
		reinterpret_cast<const char*>(value.data()),
		int(value.size()));
}

void Cleanse(QByteArray &bytes) {
	if (!bytes.isEmpty()) {
		OPENSSL_cleanse(bytes.data(), bytes.size());
	}
	bytes.clear();
}

[[nodiscard]] bool ClientLess(
		const ForkRecoveryPartitionClient &a,
		const ForkRecoveryPartitionClient &b) {
	return (a.accountId != b.accountId)
		? a.accountId < b.accountId
		: a.clientId < b.clientId;
}

[[nodiscard]] bool CandidateLess(
		const ForkRecoveryCandidate &a,
		const ForkRecoveryCandidate &b) {
	return (a.transitionId != b.transitionId)
		? a.transitionId < b.transitionId
		: a.transitionPayloadHash < b.transitionPayloadHash;
}

[[nodiscard]] QByteArray SignatureBytes(
		const AccountSignature &signature) {
	return QByteArray(
		reinterpret_cast<const char*>(signature.data()),
		int(signature.size()));
}

[[nodiscard]] QByteArray DigestBytes(Digest digest) {
	return QByteArray(
		reinterpret_cast<const char*>(digest.bytes.data()),
		int(digest.bytes.size()));
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

struct ReplacementMaterial {
	ForkRecoveryPartitionClient client;
	ObjectId publicationObjectId;
	Digest publicationPayloadHash;
	Digest keyPackageHash;
	QByteArray keyPackage;
};

[[nodiscard]] std::optional<std::vector<ReplacementMaterial>>
DecodeReplacements(
		const std::vector<TransportEnvelope> &envelopes,
		ConversationId conversationId,
		std::uint64_t peerBinding,
		std::uint64_t commonGeneration,
		std::uint64_t currentTime,
		const Sha256Provider &sha256) {
	auto result = std::vector<ReplacementMaterial>();
	result.reserve(envelopes.size());
	for (const auto &envelope : envelopes) {
		const auto verified = VerifyClientKeyPackageEnvelope(
			envelope,
			conversationId,
			peerBinding,
			commonGeneration,
			sha256);
		if (verified.result != ClientKeyPackageEnvelopeResult::Verified
			|| !verified.publication
			|| !ClientAuthorizationUsableAt(
				verified.publication->authorization,
				currentTime)) {
			return std::nullopt;
		}
		result.push_back({
			.client = {
				.accountId = envelope.senderAccountId,
				.clientId = envelope.senderClientId,
			},
			.publicationObjectId = envelope.objectId,
			.publicationPayloadHash = envelope.payloadHash,
			.keyPackageHash = sha256.digest(
				verified.publication->keyPackage),
			.keyPackage = std::move(verified.publication->keyPackage),
		});
	}
	std::sort(
		begin(result),
		end(result),
		[](const auto &a, const auto &b) {
			return ClientLess(a.client, b.client);
		});
	return std::adjacent_find(
		begin(result),
		end(result),
		[](const auto &a, const auto &b) {
			return a.client == b.client;
		}) == end(result)
		? std::optional<std::vector<ReplacementMaterial>>(
			std::move(result))
		: std::nullopt;
}

[[nodiscard]] QByteArray RecoveryIntent(
		const PrepareOpenMlsForkRecoveryArgs &args,
		const Checkpoint &commonCheckpoint,
		const Checkpoint &canonicalCheckpoint,
		AccountId ownerAccountId,
		Digest archiveKeyCommitment,
		std::vector<ForkRecoveryCandidate> candidates,
		std::vector<ForkRecoveryPartitionClient> partition,
		const std::vector<ReplacementMaterial> &replacements) {
	std::sort(begin(candidates), end(candidates), CandidateLess);
	std::sort(begin(partition), end(partition), ClientLess);
	auto result = QByteArray();
	AppendArray(result, kIntentMagic);
	AppendUint16(result, 1);
	AppendArray(result, args.actor.conversationId.bytes);
	AppendArray(result, args.recoveryId.bytes);
	AppendUint64(result, commonCheckpoint.generation);
	AppendArray(result, commonCheckpoint.stateHash.bytes);
	AppendArray(result, canonicalCheckpoint.stateHash.bytes);
	AppendArray(result, ownerAccountId.bytes);
	AppendArray(result, args.ownerClientId.bytes);
	AppendUint16(result, std::uint16_t(candidates.size()));
	for (const auto &candidate : candidates) {
		AppendArray(result, candidate.transitionId.bytes);
		AppendArray(result, candidate.transitionPayloadHash.bytes);
	}
	AppendArray(result, args.canonicalCandidate.transitionId.bytes);
	AppendArray(result, args.canonicalCandidate.transitionPayloadHash.bytes);
	AppendUint16(result, std::uint16_t(partition.size()));
	for (const auto &client : partition) {
		AppendArray(result, client.accountId.bytes);
		AppendArray(result, client.clientId.bytes);
	}
	AppendUint16(result, std::uint16_t(replacements.size()));
	for (const auto &replacement : replacements) {
		AppendArray(result, replacement.client.accountId.bytes);
		AppendArray(result, replacement.client.clientId.bytes);
		AppendArray(result, replacement.publicationObjectId.bytes);
		AppendArray(result, replacement.publicationPayloadHash.bytes);
		AppendArray(result, replacement.keyPackageHash.bytes);
	}
	AppendArray(result, args.recoveryCommitObjectId.bytes);
	AppendArray(result, args.recoveryWelcomeObjectId.bytes);
	AppendArray(result, args.archiveDistributionObjectId.bytes);
	AppendArray(result, archiveKeyCommitment.bytes);
	return result;
}

} // namespace

PrepareOpenMlsForkRecoveryOutcome PrepareOpenMlsForkRecovery(
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
		const PersistentForkRecoveryLedger &forkLedger) {
	if (!args.actor.conversationId
		|| !args.actor.accountId
		|| !args.actor.clientId
		|| !args.actor.telegramPeerIdBinding
		|| !args.commonGeneration
		|| !args.currentTime
		|| !args.recoveryId
		|| args.candidates.size() < 2
		|| args.candidates.size() > kMaximumForkRecoveryCandidates
		|| !args.canonicalCandidate.transitionId
		|| !args.canonicalCandidate.transitionPayloadHash
		|| args.canonicalPartition.empty()
		|| args.replacementKeyPackageEnvelopes.empty()
		|| !args.ownerClientId
		|| !args.ownerCredential
		|| !args.ownerSigningPrivateKey
		|| !args.ownerSigningPrivateKey->valid()
		|| !args.nextArchiveKey
		|| !args.nextArchiveKey->valid()
		|| !args.recoveryCommitObjectId
		|| !args.recoveryWelcomeObjectId
		|| !args.archiveDistributionObjectId) {
		return Failure(OpenMlsForkRecoveryPrepareStatus::InvalidArguments);
	}
	const auto currentState = groupLedger.state();
	const auto commonState = groupLedger.stateAt(args.commonGeneration);
	const auto commonCheckpoint = groupLedger.checkpointAt(
		args.commonGeneration);
	const auto canonicalCheckpoint = groupLedger.checkpoint();
	const auto currentArchiveEpoch = archiveState.currentEpoch();
	if (!bridge.compatible()
		|| !mlsState.loaded()
		|| mlsState.removed()
		|| mlsState.engineId() != OpenMlsEngineId()
		|| mlsState.engineState().isEmpty()
		|| !archiveState.loaded()
		|| !groupLedger.loaded()
		|| !forkLedger.loaded()
		|| !currentState
		|| !commonState
		|| !commonCheckpoint
		|| !currentArchiveEpoch) {
		return Failure(OpenMlsForkRecoveryPrepareStatus::StateUnavailable);
	}
	if (args.actor.conversationId != currentState->conversationId()
		|| mlsState.conversationId() != currentState->conversationId()
		|| archiveState.conversationId() != currentState->conversationId()
		|| currentState->generation() != args.commonGeneration + 1
		|| canonicalCheckpoint.generation != currentState->generation()
		|| currentArchiveEpoch->generation != currentState->generation()) {
		return Failure(
			OpenMlsForkRecoveryPrepareStatus::ArchiveInvariantViolation);
	}
	auto candidates = args.candidates;
	std::sort(begin(candidates), end(candidates), CandidateLess);
	if (std::adjacent_find(
			begin(candidates),
			end(candidates),
			[](const auto &a, const auto &b) {
				return a.transitionId == b.transitionId;
			}) != end(candidates)
		|| std::find(
			begin(candidates),
			end(candidates),
			args.canonicalCandidate) == end(candidates)
		|| groupLedger.events().empty()
		|| groupLedger.events().back().kind
			!= GroupLedgerEventKind::Transition
		|| groupLedger.events().back().objectId
			!= args.canonicalCandidate.transitionId
		|| sha256.digest(groupLedger.events().back().bytes)
			!= args.canonicalCandidate.transitionPayloadHash) {
		return Failure(OpenMlsForkRecoveryPrepareStatus::InvalidCandidateSet);
	}
	const auto ownerAccountId = DeriveAccountId(*args.ownerCredential, sha256);
	const auto commonOwner = ownerAccountId
		? commonState->member(*ownerAccountId)
		: nullptr;
	if (!ownerAccountId
		|| !commonOwner
		|| commonOwner->role != GroupRole::Owner
		|| std::find(
			begin(commonOwner->clients),
			end(commonOwner->clients),
			args.ownerClientId) == end(commonOwner->clients)) {
		return Failure(OpenMlsForkRecoveryPrepareStatus::SignatureFailure);
	}
	const auto replacements = DecodeReplacements(
		args.replacementKeyPackageEnvelopes,
		args.actor.conversationId,
		args.actor.telegramPeerIdBinding,
		args.commonGeneration,
		args.currentTime,
		sha256);
	if (!replacements) {
		return Failure(OpenMlsForkRecoveryPrepareStatus::InvalidReplacement);
	}
	auto partition = args.canonicalPartition;
	std::sort(begin(partition), end(partition), ClientLess);
	if (std::adjacent_find(begin(partition), end(partition)) != end(partition)) {
		return Failure(OpenMlsForkRecoveryPrepareStatus::InvalidPartition);
	}
	const auto inspected = bridge.inspectGroup(mlsState.engineState());
	const auto roster = inspected.status == OpenMlsBridgeStatus::Ok
		? rosterCodec.decode(inspected.roster, contextCodec)
		: std::nullopt;
	if (!roster || !MlsRosterMatchesGroupState(*roster, *currentState)) {
		return Failure(OpenMlsForkRecoveryPrepareStatus::RosterMismatch);
	}
	auto replacementByClient = std::map<
		ForkRecoveryPartitionClient,
		const ReplacementMaterial*,
		decltype(&ClientLess)>(&ClientLess);
	for (const auto &replacement : *replacements) {
		replacementByClient.emplace(replacement.client, &replacement);
	}
	auto ownLeafIndices = std::vector<std::uint32_t>();
	auto replacementKeyPackages = std::vector<QByteArray>();
	for (const auto &member : roster->members) {
		const auto client = ForkRecoveryPartitionClient{
			.accountId = member.credential.accountId,
			.clientId = member.credential.clientId,
		};
		if (std::binary_search(
				begin(partition),
				end(partition),
				client,
				ClientLess)) {
			ownLeafIndices.push_back(member.leafIndex);
		} else {
			const auto replacement = replacementByClient.find(client);
			if (replacement == end(replacementByClient)) {
				return Failure(
					OpenMlsForkRecoveryPrepareStatus::InvalidReplacement);
			}
			replacementKeyPackages.push_back(
				replacement->second->keyPackage);
			replacementByClient.erase(replacement);
		}
	}
	const auto actorClient = ForkRecoveryPartitionClient{
		.accountId = args.actor.accountId,
		.clientId = args.actor.clientId,
	};
	if (ownLeafIndices.empty()
		|| replacementKeyPackages.empty()
		|| !replacementByClient.empty()
		|| !std::binary_search(
			begin(partition),
			end(partition),
			actorClient,
			ClientLess)) {
		return Failure(OpenMlsForkRecoveryPrepareStatus::InvalidPartition);
	}
	const auto recoveryGeneration = args.commonGeneration + 2;
	const auto archiveKeyCommitment = DeriveArchiveKeyCommitment(
		args.actor.conversationId,
		recoveryGeneration,
		recoveryGeneration,
		args.recoveryId,
		*args.nextArchiveKey,
		sha256);
	if (!archiveKeyCommitment) {
		return Failure(OpenMlsForkRecoveryPrepareStatus::EncodingFailure);
	}
	const auto intent = RecoveryIntent(
		args,
		*commonCheckpoint,
		canonicalCheckpoint,
		*ownerAccountId,
		*archiveKeyCommitment,
		candidates,
		partition,
		*replacements);
	const auto commitAad = contextCodec.encodeAad({
		.conversationId = args.actor.conversationId,
		.objectKind = ObjectKind::MlsCommit,
		.senderAccountId = args.actor.accountId,
		.senderClientId = args.actor.clientId,
		.telegramPeerIdBinding = args.actor.telegramPeerIdBinding,
		.objectId = args.recoveryCommitObjectId,
		.context = DigestBytes(sha256.digest(intent)),
	});
	if (!commitAad) {
		return Failure(OpenMlsForkRecoveryPrepareStatus::EncodingFailure);
	}
	auto recovered = bridge.recoverFork(
		mlsState.engineState(),
		ownLeafIndices,
		replacementKeyPackages,
		*commitAad);
	if (recovered.status != OpenMlsBridgeStatus::Ok
		|| recovered.state.isEmpty()
		|| recovered.commit.isEmpty()
		|| recovered.welcome.isEmpty()
		|| recovered.roster.isEmpty()) {
		Cleanse(recovered.state);
		return Failure(OpenMlsForkRecoveryPrepareStatus::MlsFailure);
	}
	const auto resultingRoster = rosterCodec.decode(
		recovered.roster,
		contextCodec);
	if (!resultingRoster
		|| !MlsRosterMatchesGroupState(*resultingRoster, *currentState)) {
		Cleanse(recovered.state);
		return Failure(OpenMlsForkRecoveryPrepareStatus::RosterMismatch);
	}
	auto distributionPlaintext = controlCodec.encodeArchiveDistribution({
		.conversationId = args.actor.conversationId,
		.transitionId = args.recoveryId,
		.groupGeneration = recoveryGeneration,
		.archiveEpochGeneration = recoveryGeneration,
		.activationEventId = args.recoveryId,
		.key = args.nextArchiveKey->clone(),
	});
	if (!distributionPlaintext) {
		Cleanse(recovered.state);
		return Failure(OpenMlsForkRecoveryPrepareStatus::EncodingFailure);
	}
	auto distributionContext = DigestBytes(sha256.digest(intent));
	const auto commitHash = sha256.digest(recovered.commit);
	AppendArray(distributionContext, commitHash.bytes);
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
		Cleanse(recovered.state);
		Cleanse(*distributionPlaintext);
		return Failure(OpenMlsForkRecoveryPrepareStatus::EncodingFailure);
	}
	auto distributed = bridge.seal(
		recovered.state,
		*distributionAad,
		*distributionPlaintext);
	Cleanse(recovered.state);
	Cleanse(*distributionPlaintext);
	if (distributed.status != OpenMlsBridgeStatus::Ok
		|| distributed.state.isEmpty()
		|| distributed.message.isEmpty()
		|| distributed.epoch != recovered.epoch) {
		Cleanse(distributed.state);
		return Failure(OpenMlsForkRecoveryPrepareStatus::MlsFailure);
	}
	const auto manifest = CreateSignedForkRecoveryManifest({
		.conversationId = args.actor.conversationId,
		.recoveryId = args.recoveryId,
		.telegramPeerIdBinding = args.actor.telegramPeerIdBinding,
		.currentTime = args.currentTime,
		.commonCheckpoint = *commonCheckpoint,
		.canonicalCheckpoint = canonicalCheckpoint,
		.commonState = &*commonState,
		.canonicalState = currentState,
		.candidates = candidates,
		.canonicalCandidate = args.canonicalCandidate,
		.canonicalPartition = partition,
		.replacementKeyPackageEnvelopes =
			args.replacementKeyPackageEnvelopes,
		.recoveryCommitObjectId = args.recoveryCommitObjectId,
		.recoveryCommit = recovered.commit,
		.recoveryWelcomeObjectId = args.recoveryWelcomeObjectId,
		.recoveryWelcome = recovered.welcome,
		.archiveDistributionObjectId = args.archiveDistributionObjectId,
		.archiveDistribution = distributed.message,
		.nextArchiveKey = args.nextArchiveKey,
		.ownerAccountId = *ownerAccountId,
		.ownerClientId = args.ownerClientId,
		.ownerCredential = args.ownerCredential,
		.ownerSigningPrivateKey = args.ownerSigningPrivateKey,
	}, sha256);
	const auto manifestBytes = manifest
		? SignedForkRecoveryManifestCodecV1().encode(*manifest)
		: std::nullopt;
	if (!manifest || !manifestBytes) {
		Cleanse(distributed.state);
		return Failure(OpenMlsForkRecoveryPrepareStatus::SignatureFailure);
	}
	const auto manifestHash = sha256.digest(*manifestBytes);
	const auto manifestEnvelope = TransportEnvelope{
		.conversationId = args.actor.conversationId,
		.objectKind = ObjectKind::ForkRecoveryManifest,
		.senderAccountId = *ownerAccountId,
		.senderClientId = args.ownerClientId,
		.telegramPeerIdBinding = args.actor.telegramPeerIdBinding,
		.epochOrGeneration = recoveryGeneration,
		.objectId = args.recoveryId,
		.payloadHash = manifestHash,
		.payload = *manifestBytes,
		.authenticationData = SignatureBytes(manifest->ownerSignature),
	};
	const auto commitEnvelope = TransportEnvelope{
		.conversationId = args.actor.conversationId,
		.objectKind = ObjectKind::MlsCommit,
		.senderAccountId = args.actor.accountId,
		.senderClientId = args.actor.clientId,
		.telegramPeerIdBinding = args.actor.telegramPeerIdBinding,
		.epochOrGeneration = recovered.epoch,
		.objectId = args.recoveryCommitObjectId,
		.payloadHash = commitHash,
		.payload = recovered.commit,
		.authenticationData = *commitAad,
	};
	const auto welcomeEnvelope = TransportEnvelope{
		.conversationId = args.actor.conversationId,
		.objectKind = ObjectKind::MlsWelcome,
		.senderAccountId = args.actor.accountId,
		.senderClientId = args.actor.clientId,
		.telegramPeerIdBinding = args.actor.telegramPeerIdBinding,
		.epochOrGeneration = recovered.epoch,
		.objectId = args.recoveryWelcomeObjectId,
		.payloadHash = sha256.digest(recovered.welcome),
		.payload = recovered.welcome,
		.authenticationData = WelcomeAuthenticationData(
			args.recoveryId,
			manifestHash),
	};
	const auto distributionEnvelope = TransportEnvelope{
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
	};
	auto encodedEnvelopes = std::vector<EncodedEnvelope>();
	for (const auto &envelope : {
			manifestEnvelope,
			commitEnvelope,
			welcomeEnvelope,
			distributionEnvelope,
		}) {
		const auto encoded = envelopeCodec.encode(envelope);
		if (!encoded) {
			Cleanse(distributed.state);
			return Failure(
				OpenMlsForkRecoveryPrepareStatus::EncodingFailure);
		}
		encodedEnvelopes.push_back(*encoded);
	}
	return {
		.status = OpenMlsForkRecoveryPrepareStatus::Prepared,
		.prepared = PreparedOpenMlsForkRecovery{
			.transaction = {
				.conversationId = args.actor.conversationId,
				.transactionId = args.recoveryId,
				.direction = ForkRecoveryTransactionDirection::Outbound,
				.groupBaseRevision = groupLedger.revision(),
				.archiveBaseRevision = archiveState.revision(),
				.mlsBaseRevision = mlsState.revision(),
				.forkLedgerBaseRevision = forkLedger.revision(),
				.manifest = *manifest,
				.canonicalTransition = std::nullopt,
				.canonicalTargetCredential = std::nullopt,
				.canonicalTargetKeyPackage = {},
				.canonicalMlsCommit = {},
				.canonicalArchiveDistribution = {},
				.consumedKeyPackageHash = std::nullopt,
				.keyPackagePoolBaseRevision = 0,
				.archiveEpoch = {
					.generation = recoveryGeneration,
					.activationGroupGeneration = recoveryGeneration,
					.activationEventId = args.recoveryId,
					.key = args.nextArchiveKey->clone(),
				},
				.nextMlsEngineState = std::move(distributed.state),
				.outboxEnvelopes = std::move(encodedEnvelopes),
			},
			.resultingRoster = *resultingRoster,
		},
	};
}

} // namespace E2ECloud
