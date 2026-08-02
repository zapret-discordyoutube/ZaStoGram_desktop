/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "e2e_cloud/archive/persistent_archive_state.h"
#include "e2e_cloud/core/envelope_codec.h"
#include "e2e_cloud/group/persistent_group_ledger.h"
#include "e2e_cloud/group/signed_group_genesis.h"
#include "e2e_cloud/identity/openssl_account_crypto.h"
#include "e2e_cloud/mls/key_package_lifecycle.h"
#include "e2e_cloud/mls/openmls_bridge.h"
#include "e2e_cloud/mls/openmls_fork_recovery_engine.h"
#include "e2e_cloud/mls/openmls_inbound_fork_recovery.h"
#include "e2e_cloud/protocol/group_control_codec.h"
#include "e2e_cloud/storage/aes_gcm_local_record_protector.h"
#include "e2e_cloud/storage/persistent_outbox.h"

#include <openssl/crypto.h>

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
		if (failNextWrite) {
			failNextWrite = false;
			return false;
		}
		bytes = value;
		return true;
	}

	std::optional<QByteArray> bytes;
	bool failNextWrite = false;
};

[[nodiscard]] ArchiveKey32 ArchiveKey(std::uint8_t value) {
	auto bytes = std::array<std::uint8_t, kArchiveKeySize>();
	bytes.fill(value);
	return ArchiveKey32(std::move(bytes));
}

[[nodiscard]] QByteArray IdBytes(ConversationId id) {
	return QByteArray(
		reinterpret_cast<const char*>(id.bytes.data()),
		int(id.bytes.size()));
}

[[nodiscard]] std::optional<TransportEnvelope> DecodePublication(
		const StoredClientKeyPackage &stored,
		const EnvelopeCodec &codec) {
	return codec.decode(stored.publicationEnvelope);
}

[[nodiscard]] std::optional<TransportEnvelope> FindEnvelope(
		const std::vector<TransportEnvelope> &envelopes,
		ObjectKind kind) {
	const auto i = std::find_if(
		begin(envelopes),
		end(envelopes),
		[&](const auto &envelope) { return envelope.objectKind == kind; });
	return i == end(envelopes)
		? std::nullopt
		: std::optional<TransportEnvelope>(*i);
}

[[nodiscard]] int ScenarioRepairsRealOpenMlsFork() {
	const auto sha256 = OpenSslSha256Provider();
	const auto bridge = OpenMlsBridge();
	const auto contextCodec = MlsContextCodecV1();
	const auto rosterCodec = MlsRosterCodecV1();
	const auto controlCodec = GroupControlCodecV1();
	const auto envelopeCodec = EnvelopeCodecV1();
	auto alice = GenerateAccountPrivateIdentity();
	auto bob = GenerateAccountPrivateIdentity();
	const auto aliceAccountId = alice
		? DeriveAccountId(alice->credential, sha256)
		: std::nullopt;
	const auto bobAccountId = bob
		? DeriveAccountId(bob->credential, sha256)
		: std::nullopt;
	if (!bridge.compatible()
		|| !alice
		|| !bob
		|| !aliceAccountId
		|| !bobAccountId) {
		return Fail("fork recovery identities could not be initialized");
	}
	const auto conversationId = FilledId<ConversationId>(1);
	const auto aliceClientId = FilledId<ClientId>(2);
	const auto bobClientId = FilledId<ClientId>(3);
	const auto addedBobClientId = FilledId<ClientId>(4);
	const auto peerBinding = std::uint64_t(4001);
	const auto aliceCredential = contextCodec.encodeCredential({
		.conversationId = conversationId,
		.accountId = *aliceAccountId,
		.clientId = aliceClientId,
	});
	const auto bobCredential = contextCodec.encodeCredential({
		.conversationId = conversationId,
		.accountId = *bobAccountId,
		.clientId = bobClientId,
	});
	const auto addedBobCredential = contextCodec.encodeCredential({
		.conversationId = conversationId,
		.accountId = *bobAccountId,
		.clientId = addedBobClientId,
	});
	auto aliceGroup = aliceCredential
		? bridge.createGroup(*aliceCredential, IdBytes(conversationId))
		: OpenMlsStateOutput();
	auto bobAdmissionPackage = bobCredential
		? bridge.createKeyPackage(*bobCredential, IdBytes(conversationId))
		: OpenMlsKeyPackageOutput();
	const auto addBobAad = QByteArray("add initial Bob client");
	auto aliceWithBob = bobAdmissionPackage.status == OpenMlsBridgeStatus::Ok
		? bridge.addMember(
			aliceGroup.state,
			bobAdmissionPackage.keyPackage,
			addBobAad)
		: OpenMlsCommitOutput();
	auto bobJoined = aliceWithBob.status == OpenMlsBridgeStatus::Ok
		? bridge.join(bobAdmissionPackage.state, aliceWithBob.welcome)
		: OpenMlsStateOutput();
	if (aliceGroup.status != OpenMlsBridgeStatus::Ok
		|| bobAdmissionPackage.status != OpenMlsBridgeStatus::Ok
		|| aliceWithBob.status != OpenMlsBridgeStatus::Ok
		|| bobJoined.status != OpenMlsBridgeStatus::Ok) {
		return Fail("common two-client MLS state could not be created");
	}
	const auto bobAuthorization = CreateClientAuthorizationProof({
		.conversationId = conversationId,
		.authorizationId = FilledId<ObjectId>(5),
		.accountId = *bobAccountId,
		.clientId = bobClientId,
		.requestedAfterGeneration = 1,
		.createdAt = 1'000'000,
		.accountCredential = &bob->credential,
		.accountSigningPrivateKey = &bob->signingPrivateKey,
		.keyPackage = bobAdmissionPackage.keyPackage,
	}, sha256);
	const auto initialArchiveKey = ArchiveKey(6);
	const auto secondArchiveKey = ArchiveKey(7);
	const auto genesis = CreateSignedGroupGenesis({
		.conversationId = conversationId,
		.genesisObjectId = FilledId<ObjectId>(8),
		.telegramPeerIdBinding = peerBinding,
		.ownerAccountId = *aliceAccountId,
		.ownerClientId = aliceClientId,
		.ownerTelegramUserIdBinding = 4002,
		.policy = {
			.defaultHistoryAccess = {
				.mode = HistoryAccessMode::FromJoin,
				.boundaryEventId = {},
			},
		},
		.mlsGroupId = sha256.digest(IdBytes(conversationId)),
		.initialMlsPublicObjectId = FilledId<ObjectId>(9),
		.archiveActivationEventId = FilledId<ObjectId>(10),
		.initialArchiveKey = &initialArchiveKey,
		.ownerCredential = &alice->credential,
		.ownerSigningPrivateKey = &alice->signingPrivateKey,
		.initialMlsPublicObject = aliceGroup.roster,
	}, sha256);
	const auto verifiedGenesis = genesis
		? VerifySignedGroupGenesis({
			.genesis = &*genesis,
			.ownerCredential = &alice->credential,
			.genesisObjectId = genesis->genesisObjectId,
			.initialMlsPublicObjectId = genesis->initialMlsPublicObjectId,
			.initialMlsPublicObject = aliceGroup.roster,
			.initialArchiveKey = &initialArchiveKey,
		}, sha256)
		: VerifySignedGroupGenesisOutcome();
	const auto addBobTransition = GroupTransition{
		.conversationId = conversationId,
		.transitionId = FilledId<ObjectId>(11),
		.previousGeneration = 1,
		.generation = 2,
		.kind = GroupTransitionKind::AddMember,
		.targetAccountId = *bobAccountId,
		.targetClientId = bobClientId,
		.targetTelegramUserIdBinding = 4003,
		.targetRole = GroupRole::Member,
		.targetAdminPermissions = 0,
		.historyAccess = {
			.mode = HistoryAccessMode::FromJoin,
			.boundaryEventId = {},
		},
	};
	const auto addBobDistribution = QByteArray("add Bob archive distribution");
	const auto signedAddBob = bobAuthorization && verifiedGenesis.verified
		? CreateSignedGroupTransition({
			.transition = addBobTransition,
			.actorAccountId = *aliceAccountId,
			.actorClientId = aliceClientId,
			.previousStateHash =
				verifiedGenesis.verified->checkpoint.stateHash,
			.mlsCommitObjectId = FilledId<ObjectId>(12),
			.actorCredential = &alice->credential,
			.actorSigningPrivateKey = &alice->signingPrivateKey,
			.nextArchiveKey = &secondArchiveKey,
			.archiveDistributionObjectId = FilledId<ObjectId>(13),
			.archiveDistribution = addBobDistribution,
			.targetClientAuthorization = &*bobAuthorization,
			.mlsCommit = aliceWithBob.commit,
		}, sha256)
		: std::nullopt;
	const auto appliedAddBob = signedAddBob && verifiedGenesis.verified
		? VerifyAndApplySignedGroupTransition({
			.currentState = &verifiedGenesis.verified->state,
			.currentCheckpoint = verifiedGenesis.verified->checkpoint,
			.signedTransition = &*signedAddBob,
			.actorCredential = &alice->credential,
			.targetCredential = &bob->credential,
			.mlsCommitObjectId = signedAddBob->mlsCommitObjectId,
			.mlsCommit = aliceWithBob.commit,
			.nextArchiveKey = &secondArchiveKey,
			.archiveDistributionObjectId =
				signedAddBob->archiveDistributionObjectId,
			.archiveDistribution = addBobDistribution,
			.targetKeyPackage = bobAdmissionPackage.keyPackage,
		}, sha256)
		: VerifySignedGroupTransitionOutcome();
	auto localKey = LocalRecordKey();
	localKey.fill(14);
	const auto protector = AesGcmLocalRecordProtector(std::move(localKey));
	auto groupBlob = MemoryBlobStore();
	auto archiveBlob = MemoryBlobStore();
	auto mlsBlob = MemoryBlobStore();
	auto forkLedgerBlob = MemoryBlobStore();
	auto outboxBlob = MemoryBlobStore();
	auto forkJournalBlob = MemoryBlobStore();
	auto groupLedger = PersistentGroupLedger(groupBlob, protector, sha256);
	auto archiveState = PersistentArchiveState(archiveBlob, protector);
	auto mlsState = PersistentMlsStateStore(mlsBlob, protector);
	auto forkLedger = PersistentForkRecoveryLedger(
		forkLedgerBlob,
		protector,
		sha256);
	auto outbox = PersistentOutboxStore(outboxBlob, protector);
	auto forkJournal = PersistentForkRecoveryJournal(
		forkJournalBlob,
		protector);
	if (!genesis
		|| !verifiedGenesis.verified
		|| !signedAddBob
		|| !appliedAddBob.applied
		|| groupLedger.load(conversationId) != GroupLedgerLoadResult::Missing
		|| groupLedger.initialize(
			*genesis,
			verifiedGenesis.verified->state,
			verifiedGenesis.verified->checkpoint,
			alice->credential) != GroupLedgerCommitResult::Committed
		|| groupLedger.commitTransition(
			groupLedger.revision(),
			*signedAddBob,
			*appliedAddBob.applied,
			&bob->credential) != GroupLedgerCommitResult::Committed
		|| archiveState.load(conversationId) != ArchiveStateLoadResult::Missing
		|| archiveState.initialize({
			.generation = 1,
			.activationGroupGeneration = 1,
			.activationEventId = genesis->archiveActivationEventId,
			.key = initialArchiveKey.clone(),
		}) != ArchiveStateCommitResult::Committed
		|| archiveState.appendEpoch(archiveState.revision(), {
			.generation = 2,
			.activationGroupGeneration = 2,
			.activationEventId = addBobTransition.transitionId,
			.key = secondArchiveKey.clone(),
		}) != ArchiveStateCommitResult::Committed
		|| forkLedger.load(conversationId)
			!= ForkRecoveryLedgerLoadResult::Missing
		|| outbox.load() != PersistentOutboxLoadResult::Empty
		|| forkJournal.load(conversationId)
			!= ForkRecoveryJournalLoadResult::Empty) {
		return Fail("common fork authority stores could not be initialized");
	}
	const auto bobContext = OpenMlsClientContext{
		.conversationId = conversationId,
		.accountId = *bobAccountId,
		.clientId = bobClientId,
		.telegramPeerIdBinding = peerBinding,
	};
	const auto bobRecovery = PrepareClientKeyPackage({
		.client = bobContext,
		.currentGeneration = 2,
		.telegramUserIdBinding = 4003,
		.createdAt = 1'000'000,
		.accountCredential = &bob->credential,
		.accountSigningPrivateKey = &bob->signingPrivateKey,
	}, bridge, contextCodec, ClientKeyPackagePublicationCodecV1(),
		envelopeCodec, sha256);
	const auto bobRecoveryEnvelope = bobRecovery.entry
		? DecodePublication(*bobRecovery.entry, envelopeCodec)
		: std::nullopt;
	auto addedClientPackage = addedBobCredential
		? bridge.createKeyPackage(*addedBobCredential, IdBytes(conversationId))
		: OpenMlsKeyPackageOutput();
	const auto addedClientAuthorization = CreateClientAuthorizationProof({
		.conversationId = conversationId,
		.authorizationId = FilledId<ObjectId>(16),
		.accountId = *bobAccountId,
		.clientId = addedBobClientId,
		.requestedAfterGeneration = 2,
		.createdAt = 1'000'000,
		.accountCredential = &bob->credential,
		.accountSigningPrivateKey = &bob->signingPrivateKey,
		.keyPackage = addedClientPackage.keyPackage,
	}, sha256);
	if (bobRecovery.status != PrepareClientKeyPackageStatus::Prepared
		|| !bobRecovery.entry
		|| !bobRecoveryEnvelope
		|| addedClientPackage.status != OpenMlsBridgeStatus::Ok
		|| !addedClientAuthorization) {
		return Fail("fork recovery KeyPackages could not be prepared");
	}
	const auto aliceForkAad = QByteArray("Alice canonical fork commit");
	const auto bobForkAad = QByteArray("Bob competing fork commit");
	auto aliceFork = bridge.addMember(
		aliceWithBob.state,
		addedClientPackage.keyPackage,
		aliceForkAad);
	auto bobFork = bridge.addMember(
		bobJoined.state,
		addedClientPackage.keyPackage,
		bobForkAad);
	if (aliceFork.status != OpenMlsBridgeStatus::Ok
		|| bobFork.status != OpenMlsBridgeStatus::Ok) {
		return Fail("concurrent OpenMLS branches could not be created");
	}
	const auto canonicalTransition = GroupTransition{
		.conversationId = conversationId,
		.transitionId = FilledId<ObjectId>(17),
		.previousGeneration = 2,
		.generation = 3,
		.kind = GroupTransitionKind::AddClient,
		.targetAccountId = *bobAccountId,
		.targetClientId = addedBobClientId,
		.targetTelegramUserIdBinding = 0,
		.targetRole = GroupRole::Member,
		.targetAdminPermissions = 0,
		.historyAccess = {},
	};
	const auto competingTransition = GroupTransition{
		.conversationId = conversationId,
		.transitionId = FilledId<ObjectId>(18),
		.previousGeneration = 2,
		.generation = 3,
		.kind = GroupTransitionKind::AddClient,
		.targetAccountId = *bobAccountId,
		.targetClientId = addedBobClientId,
		.targetTelegramUserIdBinding = 0,
		.targetRole = GroupRole::Member,
		.targetAdminPermissions = 0,
		.historyAccess = {},
	};
	const auto canonicalArchiveKey = ArchiveKey(19);
	const auto competingArchiveKey = ArchiveKey(20);
	const auto canonicalDistribution = QByteArray("canonical distribution");
	const auto competingDistribution = QByteArray("competing distribution");
	const auto signedCanonical = CreateSignedGroupTransition({
		.transition = canonicalTransition,
		.actorAccountId = *aliceAccountId,
		.actorClientId = aliceClientId,
		.previousStateHash = groupLedger.checkpoint().stateHash,
		.mlsCommitObjectId = FilledId<ObjectId>(21),
		.actorCredential = &alice->credential,
		.actorSigningPrivateKey = &alice->signingPrivateKey,
		.nextArchiveKey = &canonicalArchiveKey,
		.archiveDistributionObjectId = FilledId<ObjectId>(22),
		.archiveDistribution = canonicalDistribution,
		.targetClientAuthorization = &*addedClientAuthorization,
		.mlsCommit = aliceFork.commit,
	}, sha256);
	const auto signedCompeting = CreateSignedGroupTransition({
		.transition = competingTransition,
		.actorAccountId = *bobAccountId,
		.actorClientId = bobClientId,
		.previousStateHash = groupLedger.checkpoint().stateHash,
		.mlsCommitObjectId = FilledId<ObjectId>(23),
		.actorCredential = &bob->credential,
		.actorSigningPrivateKey = &bob->signingPrivateKey,
		.nextArchiveKey = &competingArchiveKey,
		.archiveDistributionObjectId = FilledId<ObjectId>(24),
		.archiveDistribution = competingDistribution,
		.targetClientAuthorization = &*addedClientAuthorization,
		.mlsCommit = bobFork.commit,
	}, sha256);
	const auto appliedCompeting = signedCompeting
		? VerifyAndApplySignedGroupTransition({
			.currentState = groupLedger.state(),
			.currentCheckpoint = groupLedger.checkpoint(),
			.signedTransition = &*signedCompeting,
			.actorCredential = &bob->credential,
			.targetCredential = &bob->credential,
			.mlsCommitObjectId = signedCompeting->mlsCommitObjectId,
			.mlsCommit = bobFork.commit,
			.nextArchiveKey = &competingArchiveKey,
			.archiveDistributionObjectId =
				signedCompeting->archiveDistributionObjectId,
			.archiveDistribution = competingDistribution,
			.targetKeyPackage = addedClientPackage.keyPackage,
		}, sha256)
		: VerifySignedGroupTransitionOutcome();
	const auto appliedCanonical = signedCanonical
		? VerifyAndApplySignedGroupTransition({
			.currentState = groupLedger.state(),
			.currentCheckpoint = groupLedger.checkpoint(),
			.signedTransition = &*signedCanonical,
			.actorCredential = &alice->credential,
			.targetCredential = &bob->credential,
			.mlsCommitObjectId = signedCanonical->mlsCommitObjectId,
			.mlsCommit = aliceFork.commit,
			.nextArchiveKey = &canonicalArchiveKey,
			.archiveDistributionObjectId =
				signedCanonical->archiveDistributionObjectId,
			.archiveDistribution = canonicalDistribution,
			.targetKeyPackage = addedClientPackage.keyPackage,
		}, sha256)
		: VerifySignedGroupTransitionOutcome();
	const auto canonicalBytes = signedCanonical
		? SignedGroupTransitionCodecV1().encode(*signedCanonical)
		: std::nullopt;
	const auto competingBytes = signedCompeting
		? SignedGroupTransitionCodecV1().encode(*signedCompeting)
		: std::nullopt;
	if (!signedCanonical
		|| !signedCompeting
		|| !appliedCompeting.applied
		|| !appliedCanonical.applied
		|| !canonicalBytes
		|| !competingBytes
		|| groupLedger.commitTransition(
			groupLedger.revision(),
			*signedCanonical,
			*appliedCanonical.applied,
			nullptr) != GroupLedgerCommitResult::Committed
		|| archiveState.appendEpoch(archiveState.revision(), {
			.generation = 3,
			.activationGroupGeneration = 3,
			.activationEventId = canonicalTransition.transitionId,
			.key = canonicalArchiveKey.clone(),
		}) != ArchiveStateCommitResult::Committed
		|| mlsState.load(conversationId) != MlsStateLoadResult::Missing
		|| mlsState.initialize(OpenMlsEngineId(), aliceFork.state)
			!= MlsStateCommitResult::Committed) {
		return Fail("canonical fork branch could not be persisted");
	}
	const auto canonicalCandidate = ForkRecoveryCandidate{
		.transitionId = canonicalTransition.transitionId,
		.transitionPayloadHash = sha256.digest(*canonicalBytes),
	};
	const auto competingCandidate = ForkRecoveryCandidate{
		.transitionId = competingTransition.transitionId,
		.transitionPayloadHash = sha256.digest(*competingBytes),
	};
	const auto recoveryArchiveKey = ArchiveKey(25);
	auto prepared = PrepareOpenMlsForkRecovery({
		.actor = {
			.conversationId = conversationId,
			.accountId = *aliceAccountId,
			.clientId = aliceClientId,
			.telegramPeerIdBinding = peerBinding,
		},
		.commonGeneration = 2,
		.currentTime = 1'000'000,
		.recoveryId = FilledId<ObjectId>(26),
		.candidates = { competingCandidate, canonicalCandidate },
		.canonicalCandidate = canonicalCandidate,
		.canonicalPartition = {
			{
				.accountId = *aliceAccountId,
				.clientId = aliceClientId,
			},
			{
				.accountId = *bobAccountId,
				.clientId = addedBobClientId,
			},
		},
		.replacementKeyPackageEnvelopes = { *bobRecoveryEnvelope },
		.ownerClientId = aliceClientId,
		.ownerCredential = &alice->credential,
		.ownerSigningPrivateKey = &alice->signingPrivateKey,
		.nextArchiveKey = &recoveryArchiveKey,
		.recoveryCommitObjectId = FilledId<ObjectId>(27),
		.recoveryWelcomeObjectId = FilledId<ObjectId>(28),
		.archiveDistributionObjectId = FilledId<ObjectId>(29),
	}, bridge, contextCodec, rosterCodec, controlCodec, envelopeCodec, sha256,
		mlsState, archiveState, groupLedger, forkLedger);
	if (prepared.status != OpenMlsForkRecoveryPrepareStatus::Prepared
		|| !prepared.prepared
		|| prepared.prepared->transaction.outboxEnvelopes.size() != 4
		|| prepared.prepared->resultingRoster.members.size() != 3) {
		return Fail("real OpenMLS fork recovery was not prepared");
	}
	auto decodedEnvelopes = std::vector<TransportEnvelope>();
	for (const auto &encoded
			: prepared.prepared->transaction.outboxEnvelopes) {
		const auto decoded = envelopeCodec.decode(encoded);
		if (!decoded) {
			return Fail("fork recovery transaction envelope was invalid");
		}
		decodedEnvelopes.push_back(*decoded);
	}
	const auto manifestEnvelope = FindEnvelope(
		decodedEnvelopes,
		ObjectKind::ForkRecoveryManifest);
	const auto welcomeEnvelope = FindEnvelope(
		decodedEnvelopes,
		ObjectKind::MlsWelcome);
	const auto distributionEnvelope = FindEnvelope(
		decodedEnvelopes,
		ObjectKind::ArchiveEpoch);
	const auto commitEnvelope = FindEnvelope(
		decodedEnvelopes,
		ObjectKind::MlsCommit);
	const auto manifestCommonState = groupLedger.stateAt(2);
	const auto manifestCommonCheckpoint = groupLedger.checkpointAt(2);
	if (!manifestEnvelope
		|| !welcomeEnvelope
		|| !distributionEnvelope
		|| !commitEnvelope
		|| !manifestCommonState
		|| !manifestCommonCheckpoint
		|| VerifySignedForkRecoveryManifest({
			.manifest = &prepared.prepared->transaction.manifest,
			.commonState = &*manifestCommonState,
			.canonicalState = groupLedger.state(),
			.commonCheckpoint = *manifestCommonCheckpoint,
			.canonicalCheckpoint = groupLedger.checkpoint(),
			.observedCandidates = {
				canonicalCandidate,
				competingCandidate,
			},
			.replacementKeyPackageEnvelopes = { *bobRecoveryEnvelope },
			.recoveryCommitObjectId =
				prepared.prepared->transaction.manifest
					.recoveryCommitObjectId,
			.recoveryCommit = commitEnvelope->payload,
			.recoveryWelcomeObjectId = welcomeEnvelope->objectId,
			.recoveryWelcome = welcomeEnvelope->payload,
			.archiveDistributionObjectId = distributionEnvelope->objectId,
			.archiveDistribution = distributionEnvelope->payload,
			.nextArchiveKey = &recoveryArchiveKey,
			.ownerCredential = &alice->credential,
			.currentTime = 1'000'000,
		}, sha256) != ForkRecoveryManifestResult::Verified) {
		return Fail("prepared OpenMLS fork manifest did not verify");
	}
	const auto canonicalTransitionEnvelope = TransportEnvelope{
		.conversationId = conversationId,
		.objectKind = ObjectKind::SignedGroupTransition,
		.senderAccountId = *aliceAccountId,
		.senderClientId = aliceClientId,
		.telegramPeerIdBinding = peerBinding,
		.epochOrGeneration = canonicalTransition.generation,
		.objectId = canonicalTransition.transitionId,
		.payloadHash = canonicalCandidate.transitionPayloadHash,
		.payload = *canonicalBytes,
		.authenticationData = QByteArray(
			reinterpret_cast<const char*>(
				signedCanonical->actorSignature.data()),
			int(signedCanonical->actorSignature.size())),
	};
	const auto canonicalCommitEnvelope = TransportEnvelope{
		.conversationId = conversationId,
		.objectKind = ObjectKind::MlsCommit,
		.senderAccountId = *aliceAccountId,
		.senderClientId = aliceClientId,
		.telegramPeerIdBinding = peerBinding,
		.epochOrGeneration = aliceFork.epoch,
		.objectId = signedCanonical->mlsCommitObjectId,
		.payloadHash = signedCanonical->mlsCommitHash,
		.payload = aliceFork.commit,
		.authenticationData = QByteArray("canonical commit aad"),
	};
	const auto canonicalDistributionEnvelope = TransportEnvelope{
		.conversationId = conversationId,
		.objectKind = ObjectKind::ArchiveEpoch,
		.senderAccountId = *aliceAccountId,
		.senderClientId = aliceClientId,
		.telegramPeerIdBinding = peerBinding,
		.epochOrGeneration = aliceFork.epoch,
		.objectId = signedCanonical->archiveDistributionObjectId,
		.payloadHash = signedCanonical->archiveDistributionHash,
		.payload = canonicalDistribution,
		.authenticationData = QByteArray("canonical distribution aad"),
	};
	auto losingGroupBlob = MemoryBlobStore();
	auto losingArchiveBlob = MemoryBlobStore();
	auto losingMlsBlob = MemoryBlobStore();
	auto losingForkLedgerBlob = MemoryBlobStore();
	auto losingKeyPackagePoolBlob = MemoryBlobStore();
	auto losingJournalBlob = MemoryBlobStore();
	auto losingGroupLedger = PersistentGroupLedger(
		losingGroupBlob,
		protector,
		sha256);
	auto losingArchiveState = PersistentArchiveState(
		losingArchiveBlob,
		protector);
	auto losingMlsState = PersistentMlsStateStore(
		losingMlsBlob,
		protector);
	auto losingForkLedger = PersistentForkRecoveryLedger(
		losingForkLedgerBlob,
		protector,
		sha256);
	auto losingKeyPackagePool = PersistentKeyPackagePool(
		losingKeyPackagePoolBlob,
		protector,
		envelopeCodec,
		sha256);
	auto losingJournal = PersistentForkRecoveryJournal(
		losingJournalBlob,
		protector);
	if (losingGroupLedger.load(conversationId)
			!= GroupLedgerLoadResult::Missing
		|| losingGroupLedger.initialize(
			*genesis,
			verifiedGenesis.verified->state,
			verifiedGenesis.verified->checkpoint,
			alice->credential) != GroupLedgerCommitResult::Committed
		|| losingGroupLedger.commitTransition(
			losingGroupLedger.revision(),
			*signedAddBob,
			*appliedAddBob.applied,
			&bob->credential) != GroupLedgerCommitResult::Committed
		|| losingGroupLedger.commitTransition(
			losingGroupLedger.revision(),
			*signedCompeting,
			*appliedCompeting.applied,
			nullptr) != GroupLedgerCommitResult::Committed
		|| losingArchiveState.load(conversationId)
			!= ArchiveStateLoadResult::Missing
		|| losingArchiveState.initialize({
			.generation = 1,
			.activationGroupGeneration = 1,
			.activationEventId = genesis->archiveActivationEventId,
			.key = initialArchiveKey.clone(),
		}) != ArchiveStateCommitResult::Committed
		|| losingArchiveState.appendEpoch(
			losingArchiveState.revision(),
			{
				.generation = 2,
				.activationGroupGeneration = 2,
				.activationEventId = addBobTransition.transitionId,
				.key = secondArchiveKey.clone(),
			}) != ArchiveStateCommitResult::Committed
		|| losingArchiveState.appendEpoch(
			losingArchiveState.revision(),
			{
				.generation = 3,
				.activationGroupGeneration = 3,
				.activationEventId = competingTransition.transitionId,
				.key = competingArchiveKey.clone(),
			}) != ArchiveStateCommitResult::Committed
		|| losingMlsState.load(conversationId)
			!= MlsStateLoadResult::Missing
		|| losingMlsState.initialize(OpenMlsEngineId(), bobFork.state)
			!= MlsStateCommitResult::Committed
		|| losingForkLedger.load(conversationId)
			!= ForkRecoveryLedgerLoadResult::Missing
		|| losingKeyPackagePool.load(conversationId, peerBinding)
			!= KeyPackagePoolLoadResult::Empty
		|| losingKeyPackagePool.add(*bobRecovery.entry)
			!= KeyPackagePoolMutationResult::Committed
		|| losingJournal.load(conversationId)
			!= ForkRecoveryJournalLoadResult::Empty) {
		return Fail("losing fork stores could not be initialized");
	}
	auto inboundPrepared = PrepareOpenMlsInboundForkRecovery({
		.local = bobContext,
		.manifestEnvelope = *manifestEnvelope,
		.canonicalTransitionEnvelope = canonicalTransitionEnvelope,
		.canonicalCommitEnvelope = canonicalCommitEnvelope,
		.canonicalArchiveDistributionEnvelope =
			canonicalDistributionEnvelope,
		.recoveryCommitEnvelope = *commitEnvelope,
		.recoveryWelcomeEnvelope = *welcomeEnvelope,
		.recoveryArchiveDistributionEnvelope = *distributionEnvelope,
		.observedCandidates = {
			canonicalCandidate,
			competingCandidate,
		},
		.replacementKeyPackageEnvelopes = { *bobRecoveryEnvelope },
		.canonicalTargetCredential = bob->credential,
		.canonicalTargetKeyPackage = addedClientPackage.keyPackage,
		.currentTime = 1'000'001,
	}, bridge, contextCodec, rosterCodec, controlCodec, sha256,
		losingMlsState, losingArchiveState, losingGroupLedger,
		losingForkLedger, losingKeyPackagePool);
	if (inboundPrepared.status
			!= OpenMlsInboundForkRecoveryStatus::Prepared
		|| !inboundPrepared.prepared) {
		return Fail("losing OpenMLS fork recovery was not prepared");
	}
	auto losingCoordinator = ForkRecoveryTransactionCoordinator(
		losingJournal,
		losingMlsState,
		losingArchiveState,
		losingGroupLedger,
		losingForkLedger,
		losingKeyPackagePool,
		sha256);
	losingGroupBlob.failNextWrite = true;
	const auto losingFirstApply = losingCoordinator.apply(
		std::move(inboundPrepared.prepared->transaction));
	const auto losingRecoveredApply = losingCoordinator.recover();
	if (losingFirstApply != ForkRecoveryApplyStatus::GroupPersistenceFailure
		|| losingRecoveredApply != ForkRecoveryApplyStatus::Recovered
		|| losingGroupLedger.state()->generation() != 4
		|| losingArchiveState.epoch(3)
		|| !losingArchiveState.epoch(4)
		|| !losingKeyPackagePool.entries().empty()
		|| losingForkLedger.records().size() != 1
		|| losingJournal.pending()) {
		return Fail("losing fork transaction did not recover atomically");
	}
	auto bobRecovered = bridge.join(
		bobRecovery.entry->privateEngineState,
		welcomeEnvelope->payload);
	auto bobDistribution = bobRecovered.status == OpenMlsBridgeStatus::Ok
		? bridge.process(bobRecovered.state, distributionEnvelope->payload)
		: OpenMlsProcessOutput();
	OPENSSL_cleanse(bobRecovered.state.data(), bobRecovered.state.size());
	const auto openedDistribution = bobDistribution.status
		== OpenMlsBridgeStatus::Ok
		? controlCodec.decodeArchiveDistribution(bobDistribution.plaintext)
		: std::nullopt;
	if (bobDistribution.status != OpenMlsBridgeStatus::Ok
		|| bobDistribution.kind != OpenMlsContentKind::Application
		|| !openedDistribution
		|| openedDistribution->transitionId
			!= prepared.prepared->transaction.manifest.recoveryId
		|| openedDistribution->key.bytes() != recoveryArchiveKey.bytes()) {
		return Fail("losing OpenMLS partition did not rejoin and decrypt");
	}
	auto coordinator = ForkRecoveryTransactionCoordinator(
		forkJournal,
		mlsState,
		archiveState,
		groupLedger,
		forkLedger,
		outbox,
		sha256);
	groupBlob.failNextWrite = true;
	const auto firstApply = coordinator.apply(
		std::move(prepared.prepared->transaction));
	const auto recoveredApply = coordinator.recover();
	if (firstApply != ForkRecoveryApplyStatus::GroupPersistenceFailure
		|| recoveredApply != ForkRecoveryApplyStatus::Recovered
		|| groupLedger.state()->generation() != 4
		|| archiveState.currentEpoch()->generation != 4
		|| forkLedger.records().size() != 1
		|| outbox.size() != 4
		|| forkJournal.pending()) {
		return Fail("fork recovery authority state could not be committed");
	}
	return 0;
}

} // namespace

int main() {
	return ScenarioRepairsRealOpenMlsFork();
}
