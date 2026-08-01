/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "e2e_cloud/core/envelope_codec.h"
#include "e2e_cloud/archive/persistent_archive_state.h"
#include "e2e_cloud/group/persistent_group_ledger.h"
#include "e2e_cloud/group/signed_group_genesis.h"
#include "e2e_cloud/identity/openssl_account_crypto.h"
#include "e2e_cloud/mls/fork_recovery_manifest.h"
#include "e2e_cloud/mls/mls_context_codec.h"
#include "e2e_cloud/mls/openmls_bridge.h"
#include "e2e_cloud/storage/aes_gcm_local_record_protector.h"
#include "e2e_cloud/storage/persistent_fork_recovery_ledger.h"

#include <algorithm>
#include <cstdio>
#include <optional>

namespace {

using namespace E2ECloud;

template <typename Id>
[[nodiscard]] Id FilledId(std::uint8_t value) {
	auto result = Id();
	result.bytes.fill(value);
	return result;
}

[[nodiscard]] int Fail(const char *message) {
	std::fprintf(stderr, "%s\n", message);
	return 1;
}

class MemoryBlobStore final : public AtomicBlobStore {
public:
	[[nodiscard]] BlobReadResult read() const override {
		return bytes
			? BlobReadResult{
				.status = BlobReadStatus::Found,
				.bytes = *bytes,
			}
			: BlobReadResult{
				.status = BlobReadStatus::Missing,
				.bytes = {},
			};
	}

	bool writeAtomic(const QByteArray &value) override {
		bytes = value;
		return true;
	}

	std::optional<QByteArray> bytes;
};

[[nodiscard]] std::optional<TransportEnvelope> KeyPackageEnvelope(
		ConversationId conversationId,
		std::uint64_t peerBinding,
		std::uint64_t generation,
		ObjectId objectId,
		ClientId clientId,
		const AccountPrivateIdentity &identity,
		const Sha256Provider &sha256) {
	const auto accountId = DeriveAccountId(identity.credential, sha256);
	const auto keyPackage = QByteArray("bob-recovery-key-package");
	const auto proof = accountId
		? CreateClientAuthorizationProof({
			.conversationId = conversationId,
			.authorizationId = objectId,
			.accountId = *accountId,
			.clientId = clientId,
			.requestedAfterGeneration = generation,
			.createdAt = 1'000'000,
			.accountCredential = &identity.credential,
			.accountSigningPrivateKey = &identity.signingPrivateKey,
			.keyPackage = keyPackage,
		}, sha256)
		: std::nullopt;
	const auto payload = proof
		? ClientKeyPackagePublicationCodecV1().encode({
			.accountCredential = identity.credential,
			.authorization = *proof,
			.keyPackage = keyPackage,
		})
		: std::nullopt;
	if (!accountId || !proof || !payload) {
		return std::nullopt;
	}
	return TransportEnvelope{
		.conversationId = conversationId,
		.objectKind = ObjectKind::ClientKeyPackage,
		.senderAccountId = *accountId,
		.senderClientId = clientId,
		.telegramPeerIdBinding = peerBinding,
		.epochOrGeneration = generation,
		.objectId = objectId,
		.payloadHash = sha256.digest(*payload),
		.payload = *payload,
		.authenticationData = QByteArray(
			reinterpret_cast<const char*>(proof->signature.data()),
			int(proof->signature.size())),
	};
}

[[nodiscard]] int ScenarioSignedForkRecoveryManifest() {
	const auto sha256 = OpenSslSha256Provider();
	auto ownerIdentity = GenerateAccountPrivateIdentity();
	auto bobIdentity = GenerateAccountPrivateIdentity();
	const auto ownerAccountId = ownerIdentity
		? DeriveAccountId(ownerIdentity->credential, sha256)
		: std::nullopt;
	const auto bobAccountId = bobIdentity
		? DeriveAccountId(bobIdentity->credential, sha256)
		: std::nullopt;
	if (!ownerIdentity
		|| !bobIdentity
		|| !ownerAccountId
		|| !bobAccountId) {
		return Fail("fork identities could not be initialized");
	}
	const auto conversationId = FilledId<ConversationId>(1);
	const auto ownerClientId = FilledId<ClientId>(2);
	const auto bobClientId = FilledId<ClientId>(3);
	const auto peerBinding = std::uint64_t(1001);
	auto commonState = ProtectedGroupState::Create({
		.conversationId = conversationId,
		.ownerAccountId = *ownerAccountId,
		.ownerClientId = ownerClientId,
		.ownerTelegramUserIdBinding = 2001,
		.policy = {
			.defaultHistoryAccess = {
				.mode = HistoryAccessMode::FromJoin,
				.boundaryEventId = {},
			},
		},
	});
	if (!commonState) {
		return Fail("fork common state could not be created");
	}
	const auto addBob = GroupTransition{
		.conversationId = conversationId,
		.transitionId = FilledId<ObjectId>(4),
		.previousGeneration = 1,
		.generation = 2,
		.kind = GroupTransitionKind::AddMember,
		.targetAccountId = *bobAccountId,
		.targetClientId = bobClientId,
		.targetTelegramUserIdBinding = 2002,
		.targetRole = GroupRole::Member,
		.targetAdminPermissions = 0,
		.historyAccess = {
			.mode = HistoryAccessMode::FromJoin,
			.boundaryEventId = {},
		},
	};
	if (commonState->applyVerified(addBob, {
		.actor = {
			.accountId = *ownerAccountId,
			.clientId = ownerClientId,
		},
		.targetClientAuthorization = VerifiedClientAuthorization{
			.accountId = *bobAccountId,
			.clientId = bobClientId,
		},
	}) != GroupTransitionResult::Allowed) {
		return Fail("fork common member could not be admitted");
	}
	auto canonicalState = *commonState;
	const auto policyChange = GroupTransition{
		.conversationId = conversationId,
		.transitionId = FilledId<ObjectId>(5),
		.previousGeneration = 2,
		.generation = 3,
		.kind = GroupTransitionKind::SetDefaultHistory,
		.targetAccountId = {},
		.targetClientId = {},
		.targetTelegramUserIdBinding = 0,
		.targetRole = GroupRole::Member,
		.targetAdminPermissions = 0,
		.historyAccess = {
			.mode = HistoryAccessMode::None,
			.boundaryEventId = {},
		},
	};
	if (canonicalState.applyVerified(policyChange, {
		.actor = {
			.accountId = *ownerAccountId,
			.clientId = ownerClientId,
		},
		.targetClientAuthorization = std::nullopt,
	}) != GroupTransitionResult::Allowed) {
		return Fail("fork canonical state could not be advanced");
	}
	const auto replacementEnvelope = KeyPackageEnvelope(
		conversationId,
		peerBinding,
		commonState->generation(),
		FilledId<ObjectId>(6),
		bobClientId,
		*bobIdentity,
		sha256);
	if (!replacementEnvelope) {
		return Fail("fork replacement KeyPackage could not be published");
	}
	const auto candidates = std::vector<ForkRecoveryCandidate>{
		{
			.transitionId = policyChange.transitionId,
			.transitionPayloadHash = FilledId<Digest>(7),
		},
		{
			.transitionId = FilledId<ObjectId>(8),
			.transitionPayloadHash = FilledId<Digest>(9),
		},
	};
	const auto commonCheckpoint = Checkpoint{
		.conversationId = conversationId,
		.generation = commonState->generation(),
		.stateHash = FilledId<Digest>(10),
	};
	const auto canonicalCheckpoint = Checkpoint{
		.conversationId = conversationId,
		.generation = canonicalState.generation(),
		.stateHash = FilledId<Digest>(19),
	};
	auto archiveKeyBytes = std::array<std::uint8_t, kArchiveKeySize>();
	archiveKeyBytes.fill(20);
	const auto archiveKey = ArchiveKey32(std::move(archiveKeyBytes));
	const auto commitObjectId = FilledId<ObjectId>(11);
	const auto welcomeObjectId = FilledId<ObjectId>(12);
	const auto distributionObjectId = FilledId<ObjectId>(13);
	const auto commit = QByteArray("fork recovery commit");
	const auto welcome = QByteArray("fork recovery welcome");
	const auto distribution = QByteArray("fork archive distribution");
	const auto manifest = CreateSignedForkRecoveryManifest({
		.conversationId = conversationId,
		.recoveryId = FilledId<ObjectId>(14),
		.telegramPeerIdBinding = peerBinding,
		.currentTime = 1'000'000,
		.commonCheckpoint = commonCheckpoint,
		.canonicalCheckpoint = canonicalCheckpoint,
		.commonState = &*commonState,
		.canonicalState = &canonicalState,
		.candidates = { candidates[1], candidates[0] },
		.canonicalCandidate = candidates[0],
		.canonicalPartition = {
			{
				.accountId = *ownerAccountId,
				.clientId = ownerClientId,
			},
		},
		.replacementKeyPackageEnvelopes = { *replacementEnvelope },
		.recoveryCommitObjectId = commitObjectId,
		.recoveryCommit = commit,
		.recoveryWelcomeObjectId = welcomeObjectId,
		.recoveryWelcome = welcome,
		.archiveDistributionObjectId = distributionObjectId,
		.archiveDistribution = distribution,
		.nextArchiveKey = &archiveKey,
		.ownerAccountId = *ownerAccountId,
		.ownerClientId = ownerClientId,
		.ownerCredential = &ownerIdentity->credential,
		.ownerSigningPrivateKey = &ownerIdentity->signingPrivateKey,
	}, sha256);
	const auto encoded = manifest
		? SignedForkRecoveryManifestCodecV1().encode(*manifest)
		: std::nullopt;
	const auto decoded = encoded
		? SignedForkRecoveryManifestCodecV1().decode(*encoded)
		: std::nullopt;
	if (!manifest || !encoded || !decoded || *decoded != *manifest) {
		return Fail("signed fork manifest did not round-trip");
	}
	const auto verify = [&](const SignedForkRecoveryManifest &value,
			std::vector<ForkRecoveryCandidate> observed,
			std::vector<TransportEnvelope> replacements,
			QByteArray recoveryCommit) {
		return VerifySignedForkRecoveryManifest({
			.manifest = &value,
			.commonState = &*commonState,
			.canonicalState = &canonicalState,
			.commonCheckpoint = commonCheckpoint,
			.canonicalCheckpoint = canonicalCheckpoint,
			.observedCandidates = std::move(observed),
			.replacementKeyPackageEnvelopes = std::move(replacements),
			.recoveryCommitObjectId = commitObjectId,
			.recoveryCommit = std::move(recoveryCommit),
			.recoveryWelcomeObjectId = welcomeObjectId,
			.recoveryWelcome = welcome,
			.archiveDistributionObjectId = distributionObjectId,
			.archiveDistribution = distribution,
			.nextArchiveKey = &archiveKey,
			.ownerCredential = &ownerIdentity->credential,
			.currentTime = 1'000'000,
		}, sha256);
	};
	if (verify(*manifest, candidates, { *replacementEnvelope }, commit)
			!= ForkRecoveryManifestResult::Verified) {
		return Fail("signed fork manifest did not verify");
	}
	if (verify(*manifest, { candidates[0] }, { *replacementEnvelope }, commit)
			!= ForkRecoveryManifestResult::CandidateSetMismatch) {
		return Fail("server-hidden fork candidate was not detected");
	}
	auto modifiedSignature = *manifest;
	modifiedSignature.ownerSignature[0] ^= 1;
	if (verify(
			modifiedSignature,
			candidates,
			{ *replacementEnvelope },
			commit) != ForkRecoveryManifestResult::InvalidSignature) {
		return Fail("modified fork owner signature was accepted");
	}
	auto modifiedEnvelope = *replacementEnvelope;
	modifiedEnvelope.payload[modifiedEnvelope.payload.size() - 1] ^= 1;
	if (verify(*manifest, candidates, { modifiedEnvelope }, commit)
			!= ForkRecoveryManifestResult::InvalidReplacement) {
		return Fail("modified fork replacement KeyPackage was accepted");
	}
	if (verify(
			*manifest,
			candidates,
			{ *replacementEnvelope },
			QByteArray("different commit"))
			!= ForkRecoveryManifestResult::ArtifactMismatch) {
		return Fail("modified fork recovery artifact was accepted");
	}
	auto localKey = LocalRecordKey();
	localKey.fill(15);
	const auto protector = AesGcmLocalRecordProtector(std::move(localKey));
	auto blob = MemoryBlobStore();
	auto ledger = PersistentForkRecoveryLedger(blob, protector, sha256);
	if (ledger.load(conversationId)
			!= ForkRecoveryLedgerLoadResult::Missing
		|| ledger.commitVerified(*manifest)
			!= ForkRecoveryLedgerCommitResult::Committed
		|| ledger.commitVerified(*manifest)
			!= ForkRecoveryLedgerCommitResult::AlreadyCommitted
		|| ledger.observe(commonState->generation(), candidates[0])
			!= ForkRecoveryCandidateObservation::Known
		|| ledger.observe(commonState->generation(), {
			.transitionId = FilledId<ObjectId>(16),
			.transitionPayloadHash = FilledId<Digest>(17),
		}) != ForkRecoveryCandidateObservation::HiddenCandidate
		|| ledger.observe(commonState->generation(), {
			.transitionId = candidates[0].transitionId,
			.transitionPayloadHash = FilledId<Digest>(18),
		}) != ForkRecoveryCandidateObservation::ObjectIdConflict) {
		return Fail("fork recovery ledger did not detect late conflicts");
	}
	auto reloaded = PersistentForkRecoveryLedger(blob, protector, sha256);
	if (reloaded.load(conversationId)
			!= ForkRecoveryLedgerLoadResult::Loaded
		|| reloaded.revision() != ledger.revision()
		|| reloaded.records() != ledger.records()) {
		return Fail("fork recovery ledger did not persist");
	}
	auto equivocation = *manifest;
	equivocation.ownerSignature[0] ^= 1;
	if (ledger.commitVerified(equivocation)
			!= ForkRecoveryLedgerCommitResult::OwnerEquivocation) {
		return Fail("fork owner equivocation was not detected");
	}
	if (!blob.bytes) {
		return Fail("fork recovery ledger snapshot is missing");
	}
	(*blob.bytes)[blob.bytes->size() - 1] ^= 1;
	auto tampered = PersistentForkRecoveryLedger(blob, protector, sha256);
	if (tampered.load(conversationId)
			!= ForkRecoveryLedgerLoadResult::AuthenticationFailed) {
		return Fail("modified fork recovery ledger was accepted");
	}
	return 0;
}

[[nodiscard]] int ScenarioForkRecoveryExtendsGroupLedger() {
	const auto sha256 = OpenSslSha256Provider();
	auto ownerIdentity = GenerateAccountPrivateIdentity();
	const auto ownerAccountId = ownerIdentity
		? DeriveAccountId(ownerIdentity->credential, sha256)
		: std::nullopt;
	if (!ownerIdentity || !ownerAccountId) {
		return Fail("fork ledger owner could not be initialized");
	}
	const auto conversationId = FilledId<ConversationId>(21);
	const auto ownerClientId = FilledId<ClientId>(22);
	const auto peerBinding = std::uint64_t(3001);
	auto initialKeyBytes = std::array<std::uint8_t, kArchiveKeySize>();
	initialKeyBytes.fill(23);
	const auto initialKey = ArchiveKey32(std::move(initialKeyBytes));
	const auto groupId = QByteArray(
		reinterpret_cast<const char*>(conversationId.bytes.data()),
		int(conversationId.bytes.size()));
	const auto ownerMlsCredential = MlsContextCodecV1().encodeCredential({
		.conversationId = conversationId,
		.accountId = *ownerAccountId,
		.clientId = ownerClientId,
	});
	const auto initialMls = ownerMlsCredential
		? OpenMlsBridge().createGroup(*ownerMlsCredential, groupId)
		: OpenMlsStateOutput();
	const auto initialMlsPublicObject = initialMls.roster;
	const auto genesis = CreateSignedGroupGenesis({
		.conversationId = conversationId,
		.genesisObjectId = FilledId<ObjectId>(24),
		.telegramPeerIdBinding = peerBinding,
		.ownerAccountId = *ownerAccountId,
		.ownerClientId = ownerClientId,
		.ownerTelegramUserIdBinding = 3002,
		.policy = {
			.defaultHistoryAccess = {
				.mode = HistoryAccessMode::FromJoin,
				.boundaryEventId = {},
			},
		},
		.mlsGroupId = sha256.digest(groupId),
		.initialMlsPublicObjectId = FilledId<ObjectId>(26),
		.archiveActivationEventId = FilledId<ObjectId>(27),
		.initialArchiveKey = &initialKey,
		.ownerCredential = &ownerIdentity->credential,
		.ownerSigningPrivateKey = &ownerIdentity->signingPrivateKey,
		.initialMlsPublicObject = initialMlsPublicObject,
	}, sha256);
	const auto verifiedGenesis = genesis
		? VerifySignedGroupGenesis({
			.genesis = &*genesis,
			.ownerCredential = &ownerIdentity->credential,
			.genesisObjectId = genesis->genesisObjectId,
			.initialMlsPublicObjectId = genesis->initialMlsPublicObjectId,
			.initialMlsPublicObject = initialMlsPublicObject,
			.initialArchiveKey = &initialKey,
		}, sha256)
		: VerifySignedGroupGenesisOutcome();
	auto localKey = LocalRecordKey();
	localKey.fill(28);
	const auto protector = AesGcmLocalRecordProtector(std::move(localKey));
	auto blob = MemoryBlobStore();
	auto ledger = PersistentGroupLedger(blob, protector, sha256);
	if (initialMls.status != OpenMlsBridgeStatus::Ok
			|| initialMlsPublicObject.isEmpty()
			|| !genesis
			|| !verifiedGenesis.verified) {
		return Fail("fork group ledger genesis did not verify");
	} else if (ledger.load(conversationId)
			!= GroupLedgerLoadResult::Missing) {
		return Fail("fork group ledger initial load failed");
	} else if (ledger.initialize(
			*genesis,
			verifiedGenesis.verified->state,
			verifiedGenesis.verified->checkpoint,
			ownerIdentity->credential) != GroupLedgerCommitResult::Committed) {
		return Fail("fork group ledger genesis could not be persisted");
	}
	const auto canonicalTransition = GroupTransition{
		.conversationId = conversationId,
		.transitionId = FilledId<ObjectId>(29),
		.previousGeneration = 1,
		.generation = 2,
		.kind = GroupTransitionKind::SetDefaultHistory,
		.targetAccountId = {},
		.targetClientId = {},
		.targetTelegramUserIdBinding = 0,
		.targetRole = GroupRole::Member,
		.targetAdminPermissions = 0,
		.historyAccess = {
			.mode = HistoryAccessMode::None,
			.boundaryEventId = {},
		},
	};
	auto canonicalArchiveKeyBytes =
		std::array<std::uint8_t, kArchiveKeySize>();
	canonicalArchiveKeyBytes.fill(30);
	const auto canonicalArchiveKey = ArchiveKey32(
		std::move(canonicalArchiveKeyBytes));
	const auto canonicalCommitObjectId = FilledId<ObjectId>(31);
	const auto canonicalDistributionObjectId = FilledId<ObjectId>(32);
	const auto canonicalCommit = QByteArray("canonical fork commit");
	const auto canonicalDistribution = QByteArray(
		"canonical archive distribution");
	const auto signedCanonical = CreateSignedGroupTransition({
		.transition = canonicalTransition,
		.actorAccountId = *ownerAccountId,
		.actorClientId = ownerClientId,
		.previousStateHash = ledger.checkpoint().stateHash,
		.mlsCommitObjectId = canonicalCommitObjectId,
		.actorCredential = &ownerIdentity->credential,
		.actorSigningPrivateKey = &ownerIdentity->signingPrivateKey,
		.nextArchiveKey = &canonicalArchiveKey,
		.archiveDistributionObjectId = canonicalDistributionObjectId,
		.archiveDistribution = canonicalDistribution,
		.targetClientAuthorization = nullptr,
		.mlsCommit = canonicalCommit,
	}, sha256);
	const auto appliedCanonical = signedCanonical
		? VerifyAndApplySignedGroupTransition({
			.currentState = ledger.state(),
			.currentCheckpoint = ledger.checkpoint(),
			.signedTransition = &*signedCanonical,
			.actorCredential = &ownerIdentity->credential,
			.targetCredential = nullptr,
			.mlsCommitObjectId = canonicalCommitObjectId,
			.mlsCommit = canonicalCommit,
			.nextArchiveKey = &canonicalArchiveKey,
			.archiveDistributionObjectId =
				canonicalDistributionObjectId,
			.archiveDistribution = canonicalDistribution,
			.targetKeyPackage = {},
		}, sha256)
		: VerifySignedGroupTransitionOutcome();
	const auto canonicalBytes = signedCanonical
		? SignedGroupTransitionCodecV1().encode(*signedCanonical)
		: std::nullopt;
	const auto commonCheckpoint = ledger.checkpoint();
	const auto competingTransition = GroupTransition{
		.conversationId = conversationId,
		.transitionId = FilledId<ObjectId>(33),
		.previousGeneration = 1,
		.generation = 2,
		.kind = GroupTransitionKind::SetDefaultHistory,
		.targetAccountId = {},
		.targetClientId = {},
		.targetTelegramUserIdBinding = 0,
		.targetRole = GroupRole::Member,
		.targetAdminPermissions = 0,
		.historyAccess = {
			.mode = HistoryAccessMode::Full,
			.boundaryEventId = {},
		},
	};
	auto competingArchiveKeyBytes =
		std::array<std::uint8_t, kArchiveKeySize>();
	competingArchiveKeyBytes.fill(34);
	const auto competingArchiveKey = ArchiveKey32(
		std::move(competingArchiveKeyBytes));
	const auto competingCommitObjectId = FilledId<ObjectId>(40);
	const auto competingDistributionObjectId = FilledId<ObjectId>(41);
	const auto competingCommit = QByteArray("competing fork commit");
	const auto competingDistribution = QByteArray(
		"competing archive distribution");
	const auto signedCompeting = CreateSignedGroupTransition({
		.transition = competingTransition,
		.actorAccountId = *ownerAccountId,
		.actorClientId = ownerClientId,
		.previousStateHash = commonCheckpoint.stateHash,
		.mlsCommitObjectId = competingCommitObjectId,
		.actorCredential = &ownerIdentity->credential,
		.actorSigningPrivateKey = &ownerIdentity->signingPrivateKey,
		.nextArchiveKey = &competingArchiveKey,
		.archiveDistributionObjectId = competingDistributionObjectId,
		.archiveDistribution = competingDistribution,
		.targetClientAuthorization = nullptr,
		.mlsCommit = competingCommit,
	}, sha256);
	const auto appliedCompeting = signedCompeting
		? VerifyAndApplySignedGroupTransition({
			.currentState = ledger.state(),
			.currentCheckpoint = commonCheckpoint,
			.signedTransition = &*signedCompeting,
			.actorCredential = &ownerIdentity->credential,
			.targetCredential = nullptr,
			.mlsCommitObjectId = competingCommitObjectId,
			.mlsCommit = competingCommit,
			.nextArchiveKey = &competingArchiveKey,
			.archiveDistributionObjectId =
				competingDistributionObjectId,
			.archiveDistribution = competingDistribution,
			.targetKeyPackage = {},
		}, sha256)
		: VerifySignedGroupTransitionOutcome();
	const auto competingBytes = signedCompeting
		? SignedGroupTransitionCodecV1().encode(*signedCompeting)
		: std::nullopt;
	if (!signedCanonical
		|| !appliedCanonical.applied
		|| !canonicalBytes
		|| !signedCompeting
		|| !appliedCompeting.applied
		|| !competingBytes
		|| ledger.commitTransition(
			ledger.revision(),
			*signedCanonical,
			*appliedCanonical.applied,
			nullptr) != GroupLedgerCommitResult::Committed) {
		return Fail("canonical fork branch could not be persisted");
	}
	const auto canonicalCandidate = ForkRecoveryCandidate{
		.transitionId = canonicalTransition.transitionId,
		.transitionPayloadHash = sha256.digest(*canonicalBytes),
	};
	const auto candidates = std::vector<ForkRecoveryCandidate>{
		canonicalCandidate,
		{
			.transitionId = competingTransition.transitionId,
			.transitionPayloadHash = sha256.digest(*competingBytes),
		},
	};
	auto recoveryArchiveKeyBytes =
		std::array<std::uint8_t, kArchiveKeySize>();
	recoveryArchiveKeyBytes.fill(35);
	const auto recoveryArchiveKey = ArchiveKey32(
		std::move(recoveryArchiveKeyBytes));
	const auto recoveryCommit = QByteArray("fork repair commit");
	const auto recoveryWelcome = QByteArray("fork repair welcome");
	const auto recoveryDistribution = QByteArray(
		"fork repair archive distribution");
	const auto manifest = CreateSignedForkRecoveryManifest({
		.conversationId = conversationId,
		.recoveryId = FilledId<ObjectId>(36),
		.telegramPeerIdBinding = peerBinding,
		.currentTime = 1'000'000,
		.commonCheckpoint = commonCheckpoint,
		.canonicalCheckpoint = ledger.checkpoint(),
		.commonState = &verifiedGenesis.verified->state,
		.canonicalState = ledger.state(),
		.candidates = candidates,
		.canonicalCandidate = canonicalCandidate,
		.canonicalPartition = {
			{
				.accountId = *ownerAccountId,
				.clientId = ownerClientId,
			},
		},
		.replacementKeyPackageEnvelopes = {},
		.recoveryCommitObjectId = FilledId<ObjectId>(37),
		.recoveryCommit = recoveryCommit,
		.recoveryWelcomeObjectId = FilledId<ObjectId>(38),
		.recoveryWelcome = recoveryWelcome,
		.archiveDistributionObjectId = FilledId<ObjectId>(39),
		.archiveDistribution = recoveryDistribution,
		.nextArchiveKey = &recoveryArchiveKey,
		.ownerAccountId = *ownerAccountId,
		.ownerClientId = ownerClientId,
		.ownerCredential = &ownerIdentity->credential,
		.ownerSigningPrivateKey = &ownerIdentity->signingPrivateKey,
	}, sha256);
	if (!manifest
		|| ledger.commitVerifiedForkRecovery(
			ledger.revision(),
			*manifest,
			{
				.generation = manifest->recoveryGeneration,
				.activationGroupGeneration = manifest->recoveryGeneration,
				.activationEventId = manifest->recoveryId,
				.key = recoveryArchiveKey.clone(),
			}) != GroupLedgerCommitResult::Committed
		|| ledger.checkpoint().generation != 3
		|| !ledger.state()
		|| ledger.state()->generation() != 3
		|| ledger.events().back().kind
			!= GroupLedgerEventKind::ForkRecovery
		|| !ledger.wasClientActiveAt(*ownerAccountId, ownerClientId, 3)) {
		return Fail("verified fork recovery did not extend group ledger");
	}
	const auto recoveryEpoch = ArchiveEpochSecret{
		.generation = manifest->recoveryGeneration,
		.activationGroupGeneration = manifest->recoveryGeneration,
		.activationEventId = manifest->recoveryId,
		.key = recoveryArchiveKey.clone(),
	};
	if (!ledger.verifiesArchiveEpoch(recoveryEpoch)
		|| !ledger.stateAt(1)
		|| !ledger.stateAt(2)
		|| !ledger.stateAt(3)) {
		return Fail("fork recovery ledger history could not be replayed");
	}
	auto restored = PersistentGroupLedger(blob, protector, sha256);
	if (restored.load(conversationId) != GroupLedgerLoadResult::Loaded
		|| restored.checkpoint() != ledger.checkpoint()
		|| !restored.state()
		|| restored.state()->snapshot() != ledger.state()->snapshot()) {
		return Fail("fork recovery group ledger did not survive restart");
	}
	auto losingGroupBlob = MemoryBlobStore();
	auto losingArchiveBlob = MemoryBlobStore();
	auto losingLedger = PersistentGroupLedger(
		losingGroupBlob,
		protector,
		sha256);
	auto losingArchive = PersistentArchiveState(
		losingArchiveBlob,
		protector);
	if (losingLedger.load(conversationId) != GroupLedgerLoadResult::Missing
		|| losingLedger.initialize(
			*genesis,
			verifiedGenesis.verified->state,
			verifiedGenesis.verified->checkpoint,
			ownerIdentity->credential) != GroupLedgerCommitResult::Committed
		|| losingLedger.commitTransition(
			losingLedger.revision(),
			*signedCompeting,
			*appliedCompeting.applied,
			nullptr) != GroupLedgerCommitResult::Committed
		|| losingArchive.load(conversationId)
			!= ArchiveStateLoadResult::Missing
		|| losingArchive.initialize({
			.generation = 1,
			.activationGroupGeneration = 1,
			.activationEventId = genesis->archiveActivationEventId,
			.key = initialKey.clone(),
		}) != ArchiveStateCommitResult::Committed
		|| losingArchive.appendEpoch(losingArchive.revision(), {
			.generation = 2,
			.activationGroupGeneration = 2,
			.activationEventId = competingTransition.transitionId,
			.key = competingArchiveKey.clone(),
		}) != ArchiveStateCommitResult::Committed
		|| losingLedger.replaceForkBranchAndCommitRecovery(
			losingLedger.revision(),
			*signedCanonical,
			*appliedCanonical.applied,
			nullptr,
			*manifest,
			recoveryEpoch) != GroupLedgerCommitResult::Committed
		|| losingArchive.replaceForkEpochWithRecovery(
			losingArchive.revision(),
			manifest->resolvedGeneration,
			{
				.generation = recoveryEpoch.generation,
				.activationGroupGeneration =
					recoveryEpoch.activationGroupGeneration,
				.activationEventId = recoveryEpoch.activationEventId,
				.key = recoveryEpoch.key.clone(),
			}) != ArchiveStateCommitResult::Committed
		|| losingLedger.state()->snapshot() != ledger.state()->snapshot()
		|| losingArchive.epoch(manifest->resolvedGeneration)
		|| !losingArchive.epoch(manifest->recoveryGeneration)) {
		return Fail("losing fork branch was not replaced by canonical state");
	}
	return 0;
}

} // namespace

int main() {
	if (const auto result = ScenarioSignedForkRecoveryManifest()) {
		return result;
	}
	return ScenarioForkRecoveryExtendsGroupLedger();
}
