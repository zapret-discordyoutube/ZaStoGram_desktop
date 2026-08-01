/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "e2e_cloud/archive/persistent_archive_state.h"
#include "e2e_cloud/core/envelope_codec.h"
#include "e2e_cloud/group/signed_group_genesis.h"
#include "e2e_cloud/identity/openssl_account_crypto.h"
#include "e2e_cloud/mls/key_package_lifecycle.h"
#include "e2e_cloud/mls/openmls_group_change_engine.h"
#include "e2e_cloud/mls/openmls_inbound_group_change.h"
#include "e2e_cloud/mls/openmls_bridge.h"
#include "e2e_cloud/protocol/group_change_inbox.h"
#include "e2e_cloud/protocol/observed_group_change_sync.h"
#include "e2e_cloud/protocol/public_join_catchup.h"
#include "e2e_cloud/storage/aes_gcm_local_record_protector.h"
#include "e2e_cloud/storage/persistent_inbound_journal.h"
#include "e2e_cloud/storage/persistent_key_package_pool.h"

#include <openssl/crypto.h>

#include <cstdio>
#include <optional>
#include <utility>

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

[[nodiscard]] int ScenarioAdmissionTransaction() {
	auto owner = GenerateAccountPrivateIdentity();
	auto target = GenerateAccountPrivateIdentity();
	const auto sha256 = OpenSslSha256Provider();
	const auto ownerAccountId = owner
		? DeriveAccountId(owner->credential, sha256)
		: std::nullopt;
	const auto targetAccountId = target
		? DeriveAccountId(target->credential, sha256)
		: std::nullopt;
	const auto archiveCrypto = ArchiveEpochCrypto();
	auto initialArchiveKey = archiveCrypto.generateKey();
	auto nextArchiveKey = archiveCrypto.generateKey();
	if (!owner
		|| !target
		|| !ownerAccountId
		|| !targetAccountId
		|| !initialArchiveKey
		|| !nextArchiveKey) {
		return Fail("group change identities could not be initialized");
	}
	const auto conversationId = FilledId<ConversationId>(1);
	const auto ownerClientId = FilledId<ClientId>(2);
	const auto targetClientId = FilledId<ClientId>(3);
	const auto peerId = std::uint64_t(1001);
	const auto bridge = OpenMlsBridge();
	const auto contextCodec = MlsContextCodecV1();
	const auto rosterCodec = MlsRosterCodecV1();
	const auto controlCodec = GroupControlCodecV1();
	const auto envelopeCodec = EnvelopeCodecV1();
	auto localKey = LocalRecordKey();
	localKey.fill(4);
	const auto protector = AesGcmLocalRecordProtector(std::move(localKey));
	auto mlsBlob = MemoryBlobStore();
	auto archiveBlob = MemoryBlobStore();
	auto groupBlob = MemoryBlobStore();
	auto outboxBlob = MemoryBlobStore();
	auto journalBlob = MemoryBlobStore();
	auto mlsState = PersistentMlsStateStore(mlsBlob, protector);
	auto archiveState = PersistentArchiveState(archiveBlob, protector);
	auto groupLedger = PersistentGroupLedger(groupBlob, protector, sha256);
	auto outbox = PersistentOutboxStore(outboxBlob, protector);
	auto journal = PersistentGroupChangeJournal(journalBlob, protector);
	const auto ownerContext = OpenMlsClientContext{
		.conversationId = conversationId,
		.accountId = *ownerAccountId,
		.clientId = ownerClientId,
		.telegramPeerIdBinding = peerId,
	};
	if (mlsState.load(conversationId) != MlsStateLoadResult::Missing
		|| InitializeOpenMlsCreator(
			ownerContext,
			bridge,
			contextCodec,
			mlsState).status != OpenMlsBootstrapStatus::Initialized) {
		return Fail("creator OpenMLS state could not be initialized");
	}
	const auto initialMlsPublic = bridge.inspectGroup(mlsState.engineState());
	if (initialMlsPublic.status != OpenMlsBridgeStatus::Ok
		|| initialMlsPublic.roster.isEmpty()) {
		return Fail("creator public OpenMLS roster could not be exported");
	}
	const auto genesisObjectId = FilledId<ObjectId>(5);
	const auto initialMlsPublicObjectId = FilledId<ObjectId>(6);
	const auto archiveActivationEventId = FilledId<ObjectId>(7);
	const auto groupIdBytes = QByteArray(
		reinterpret_cast<const char*>(conversationId.bytes.data()),
		conversationId.bytes.size());
	const auto genesis = CreateSignedGroupGenesis({
		.conversationId = conversationId,
		.genesisObjectId = genesisObjectId,
		.telegramPeerIdBinding = peerId,
		.ownerAccountId = *ownerAccountId,
		.ownerClientId = ownerClientId,
		.ownerTelegramUserIdBinding = 2001,
		.policy = {
			.defaultHistoryAccess = {
				.mode = HistoryAccessMode::FromJoin,
				.boundaryEventId = {},
			},
		},
		.mlsGroupId = sha256.digest(groupIdBytes),
		.initialMlsPublicObjectId = initialMlsPublicObjectId,
		.archiveActivationEventId = archiveActivationEventId,
		.initialArchiveKey = &*initialArchiveKey,
		.ownerCredential = &owner->credential,
		.ownerSigningPrivateKey = &owner->signingPrivateKey,
		.initialMlsPublicObject = initialMlsPublic.roster,
	}, sha256);
	const auto verifiedGenesis = genesis
		? VerifySignedGroupGenesis({
			.genesis = &*genesis,
			.ownerCredential = &owner->credential,
			.genesisObjectId = genesisObjectId,
			.initialMlsPublicObjectId = initialMlsPublicObjectId,
			.initialMlsPublicObject = initialMlsPublic.roster,
			.initialArchiveKey = &*initialArchiveKey,
		}, sha256)
		: VerifySignedGroupGenesisOutcome();
	auto initialArchiveStateKey = initialArchiveKey->bytes();
	if (!genesis
		|| !verifiedGenesis.verified
		|| groupLedger.load(conversationId) != GroupLedgerLoadResult::Missing
		|| groupLedger.initialize(
			*genesis,
			verifiedGenesis.verified->state,
			verifiedGenesis.verified->checkpoint,
			owner->credential) != GroupLedgerCommitResult::Committed
		|| archiveState.load(conversationId)
			!= ArchiveStateLoadResult::Missing
		|| archiveState.initialize({
			.generation = 1,
			.activationGroupGeneration = 1,
			.activationEventId = archiveActivationEventId,
			.key = ArchiveKey32(std::move(initialArchiveStateKey)),
		}) != ArchiveStateCommitResult::Committed
		|| outbox.load() != PersistentOutboxLoadResult::Empty
		|| journal.load(conversationId) != GroupChangeJournalLoadResult::Empty) {
		return Fail("protected group stores could not be initialized");
	}
	const auto targetCredentialBytes = contextCodec.encodeCredential({
		.conversationId = conversationId,
		.accountId = *targetAccountId,
		.clientId = targetClientId,
	});
	auto targetPackage = targetCredentialBytes
		? bridge.createKeyPackage(*targetCredentialBytes, groupIdBytes)
		: OpenMlsKeyPackageOutput();
	auto targetMlsBlob = MemoryBlobStore();
	auto targetMlsState = PersistentMlsStateStore(targetMlsBlob, protector);
	if (!targetCredentialBytes
		|| targetPackage.status != OpenMlsBridgeStatus::Ok
		|| targetMlsState.load(conversationId) != MlsStateLoadResult::Missing
		|| targetMlsState.initialize(
			OpenMlsEngineId(),
			targetPackage.state) != MlsStateCommitResult::Committed) {
		return Fail("joining client KeyPackage could not be persisted");
	}
	const auto authorization = CreateClientAuthorizationProof({
		.conversationId = conversationId,
		.authorizationId = FilledId<ObjectId>(8),
		.accountId = *targetAccountId,
		.clientId = targetClientId,
		.requestedAfterGeneration = 1,
		.createdAt = 100,
		.accountCredential = &target->credential,
		.accountSigningPrivateKey = &target->signingPrivateKey,
		.keyPackage = targetPackage.keyPackage,
	}, sha256);
	const auto transition = GroupTransition{
		.conversationId = conversationId,
		.transitionId = FilledId<ObjectId>(9),
		.previousGeneration = 1,
		.generation = 2,
		.kind = GroupTransitionKind::AddMember,
		.targetAccountId = *targetAccountId,
		.targetClientId = targetClientId,
		.targetTelegramUserIdBinding = 2002,
		.targetRole = GroupRole::Member,
		.targetAdminPermissions = 0,
		.historyAccess = {
			.mode = HistoryAccessMode::FromJoin,
			.boundaryEventId = {},
		},
	};
	auto prepared = authorization
		? PrepareOpenMlsAdmission({
			.actor = ownerContext,
			.currentGroupState = groupLedger.state(),
			.currentCheckpoint = groupLedger.checkpoint(),
			.transition = transition,
			.actorCredential = &owner->credential,
			.actorSigningPrivateKey = &owner->signingPrivateKey,
			.targetCredential = &target->credential,
			.targetClientAuthorization = &*authorization,
			.targetKeyPackage = targetPackage.keyPackage,
			.nextArchiveKey = &*nextArchiveKey,
			.mlsCommitObjectId = FilledId<ObjectId>(10),
			.archiveDistributionObjectId = FilledId<ObjectId>(11),
			.welcomeObjectId = FilledId<ObjectId>(12),
		},
		bridge,
		contextCodec,
		rosterCodec,
		controlCodec,
		envelopeCodec,
		sha256,
		mlsState,
		archiveState,
		groupLedger)
		: PrepareOpenMlsGroupChangeOutcome();
	if (prepared.status != OpenMlsGroupChangePrepareStatus::Prepared
		|| !prepared.prepared
		|| prepared.prepared->transaction.outboxEnvelopes.size() != 4
		|| prepared.prepared->resultingRoster.members.size() != 2) {
		return Fail("OpenMLS admission transaction was not prepared");
	}
	auto transitionEnvelope = std::optional<TransportEnvelope>();
	auto commitEnvelope = std::optional<TransportEnvelope>();
	auto welcomeEnvelope = std::optional<TransportEnvelope>();
	auto distributionEnvelope = std::optional<TransportEnvelope>();
	for (const auto &encoded : prepared.prepared->transaction.outboxEnvelopes) {
		const auto decoded = envelopeCodec.decode(encoded);
		if (!decoded) {
			return Fail("admission transaction contained an invalid envelope");
		}
		switch (decoded->objectKind) {
		case ObjectKind::SignedGroupTransition:
			transitionEnvelope = *decoded;
			break;
		case ObjectKind::MlsCommit:
			commitEnvelope = *decoded;
			break;
		case ObjectKind::MlsWelcome:
			welcomeEnvelope = *decoded;
			break;
		case ObjectKind::ArchiveEpoch:
			distributionEnvelope = *decoded;
			break;
		default:
			return Fail("admission transaction used an unexpected object kind");
		}
	}
	const auto publicationPayload = authorization
		? ClientKeyPackagePublicationCodecV1().encode({
			.accountCredential = target->credential,
			.authorization = *authorization,
			.keyPackage = targetPackage.keyPackage,
		})
		: std::nullopt;
	const auto publicationEnvelope = publicationPayload
		? envelopeCodec.encode({
			.conversationId = conversationId,
			.objectKind = ObjectKind::ClientKeyPackage,
			.senderAccountId = *targetAccountId,
			.senderClientId = targetClientId,
			.telegramPeerIdBinding = peerId,
			.epochOrGeneration = 1,
			.objectId = authorization->authorizationId,
			.payloadHash = sha256.digest(*publicationPayload),
			.payload = *publicationPayload,
			.authenticationData = QByteArray(
				reinterpret_cast<const char*>(
					authorization->signature.data()),
				int(authorization->signature.size())),
		})
		: std::nullopt;
	auto catchupGroupBlob = MemoryBlobStore();
	auto catchupPoolBlob = MemoryBlobStore();
	auto catchupLedger = PersistentGroupLedger(
		catchupGroupBlob,
		protector,
		sha256);
	auto catchupPool = PersistentKeyPackagePool(
		catchupPoolBlob,
		protector,
		envelopeCodec,
		sha256);
	auto observedObjects = std::vector<
		TelegramTransport::UntrustedObject>();
	if (publicationEnvelope) {
		observedObjects.push_back({
			.bytes = publicationEnvelope->bytes,
			.observedTelegramPeerIdBinding = peerId,
			.observedSenderTelegramUserIdBinding = 2002,
			.observedMessageId = 40,
		});
	}
	auto observedMessageId = std::int64_t(41);
	for (const auto &encoded
			: prepared.prepared->transaction.outboxEnvelopes) {
		observedObjects.push_back({
			.bytes = encoded.bytes,
			.observedTelegramPeerIdBinding = peerId,
			.observedSenderTelegramUserIdBinding = 2001,
			.observedMessageId = observedMessageId++,
		});
	}
	const auto catchupReady = publicationEnvelope
		&& catchupLedger.load(conversationId)
			== GroupLedgerLoadResult::Missing
		&& catchupLedger.initialize(
			*genesis,
			verifiedGenesis.verified->state,
			verifiedGenesis.verified->checkpoint,
			owner->credential) == GroupLedgerCommitResult::Committed
		&& catchupPool.load(conversationId, peerId)
			== KeyPackagePoolLoadResult::Empty
		&& catchupPool.add({
			.keyPackageHash = sha256.digest(targetPackage.keyPackage),
			.createdAt = 100,
			.expiresAt = 100 + kOpenMlsKeyPackageLifetimeSeconds,
			.privateEngineState = targetPackage.state,
			.publicationEnvelope = *publicationEnvelope,
			.queued = false,
		}) == KeyPackagePoolMutationResult::Committed;
	auto catchup = catchupReady
		? CatchUpPublicJoin(
			observedObjects,
			conversationId,
			peerId,
			*targetAccountId,
			targetClientId,
			target->credential,
			101,
			envelopeCodec,
			sha256,
			catchupLedger,
			catchupPool)
		: PublicJoinCatchupOutcome();
	if (catchup.status != PublicJoinCatchupStatus::Ready
		|| !catchup.bundle
		|| catchup.bundle->targetKeyPackage != targetPackage.keyPackage
		|| catchupLedger.state()->generation() != 1) {
		return Fail("public join catch-up did not select exact admission");
	}
	auto coordinator = GroupChangeTransactionCoordinator(
		journal,
		mlsState,
		archiveState,
		groupLedger,
		outbox,
		sha256);
	if (!transitionEnvelope
		|| !commitEnvelope
		|| !welcomeEnvelope
		|| !distributionEnvelope
		|| coordinator.apply(std::move(prepared.prepared->transaction))
			!= GroupChangeApplyStatus::Applied
		|| journal.pending()
		|| groupLedger.state()->generation() != 2
		|| !groupLedger.state()->member(*targetAccountId)
		|| archiveState.currentEpoch()->generation != 2
		|| mlsState.revision() != 2
		|| outbox.size() != 4) {
		return Fail("admission transaction did not commit atomically");
	}
	auto joined = bridge.join(
		targetMlsState.engineState(),
		welcomeEnvelope->payload);
	if (joined.status != OpenMlsBridgeStatus::Ok
		|| joined.state.isEmpty()
		|| joined.epoch != 1) {
		return Fail("joining client rejected the committed Welcome");
	}
	auto distributed = bridge.process(joined.state, distributionEnvelope->payload);
	OPENSSL_cleanse(joined.state.data(), joined.state.size());
	if (distributed.status != OpenMlsBridgeStatus::Ok
		|| distributed.kind != OpenMlsContentKind::Application
		|| distributed.epoch != 1
		|| distributed.plaintext.isEmpty()
		|| distributed.authenticatedData
			!= distributionEnvelope->authenticationData) {
		return Fail("joining client rejected archive-key distribution");
	}
	const auto signedTransition = SignedGroupTransitionCodecV1().decode(
		transitionEnvelope->payload);
	const auto distribution = controlCodec.decodeArchiveDistribution(
		distributed.plaintext);
	const auto commitAad = contextCodec.decodeAad(
		commitEnvelope->authenticationData);
	const auto distributionAad = contextCodec.decodeAad(
		distributionEnvelope->authenticationData);
	const auto prelude = commitAad
		? controlCodec.decodePrelude(commitAad->context)
		: std::nullopt;
	const auto targetRoster = rosterCodec.decode(distributed.roster, contextCodec);
	if (!signedTransition
		|| !distribution
		|| !commitAad
		|| !distributionAad
		|| !prelude
		|| !targetRoster
		|| distributionAad->context.size()
			!= kGroupChangePreludeEncodedSize + 32
		|| QByteArray(
			distributionAad->context.constData(),
			kGroupChangePreludeEncodedSize) != commitAad->context
		|| !GroupChangePreludeMatchesSignedTransition(
			*prelude,
			*signedTransition)
		|| distribution->conversationId != conversationId
		|| distribution->transitionId != transition.transitionId
		|| distribution->groupGeneration != 2
		|| distribution->archiveEpochGeneration != 2
		|| distribution->activationEventId != transition.transitionId) {
		return Fail("joining client lost signed admission bindings");
	}
	auto verified = VerifyAndApplySignedGroupTransition({
		.currentState = &verifiedGenesis.verified->state,
		.currentCheckpoint = verifiedGenesis.verified->checkpoint,
		.signedTransition = &*signedTransition,
		.actorCredential = &owner->credential,
		.targetCredential = &target->credential,
		.mlsCommitObjectId = commitEnvelope->objectId,
		.mlsCommit = commitEnvelope->payload,
		.nextArchiveKey = &distribution->key,
		.archiveDistributionObjectId = distributionEnvelope->objectId,
		.archiveDistribution = distributionEnvelope->payload,
		.targetKeyPackage = targetPackage.keyPackage,
	}, sha256);
	if (verified.result != SignedGroupTransitionResult::Applied
		|| !verified.applied
		|| !MlsRosterMatchesGroupState(
			*targetRoster,
			verified.applied->state)) {
		return Fail("joining client could not verify the resulting roster");
	}
	auto targetArchiveBlob = MemoryBlobStore();
	auto targetGroupBlob = MemoryBlobStore();
	auto targetJournalBlob = MemoryBlobStore();
	auto targetArchiveState = PersistentArchiveState(
		targetArchiveBlob,
		protector);
	auto targetGroupLedger = PersistentGroupLedger(
		targetGroupBlob,
		protector,
		sha256);
	auto targetJournal = PersistentGroupChangeJournal(
		targetJournalBlob,
		protector);
	auto targetContext = OpenMlsClientContext{
		.conversationId = conversationId,
		.accountId = *targetAccountId,
		.clientId = targetClientId,
		.telegramPeerIdBinding = peerId,
	};
	if (targetGroupLedger.load(conversationId)
			!= GroupLedgerLoadResult::Missing
		|| targetGroupLedger.initialize(
			*genesis,
			verifiedGenesis.verified->state,
			verifiedGenesis.verified->checkpoint,
			owner->credential) != GroupLedgerCommitResult::Committed
		|| targetArchiveState.load(conversationId)
			!= ArchiveStateLoadResult::Missing
		|| targetJournal.load(conversationId)
			!= GroupChangeJournalLoadResult::Empty) {
		return Fail("joining client stores could not begin admission");
	}
	auto preparedJoin = PrepareOpenMlsInboundJoin({
		.local = targetContext,
		.transitionEnvelope = *transitionEnvelope,
		.commitEnvelope = *commitEnvelope,
		.welcomeEnvelope = *welcomeEnvelope,
		.archiveDistributionEnvelope = *distributionEnvelope,
		.targetCredential = target->credential,
		.targetKeyPackage = targetPackage.keyPackage,
	},
	bridge,
	contextCodec,
	rosterCodec,
	controlCodec,
	sha256,
	targetMlsState,
	targetArchiveState,
	targetGroupLedger);
	auto targetJoinCoordinator = GroupChangeTransactionCoordinator(
		targetJournal,
		targetMlsState,
		targetArchiveState,
		targetGroupLedger,
		sha256);
	targetGroupBlob.failNextWrite = true;
	const auto joinApply = preparedJoin.prepared
		? targetJoinCoordinator.apply(std::move(
			preparedJoin.prepared->transaction))
		: GroupChangeApplyStatus::InvalidTransaction;
	const auto joinRecovery = targetJoinCoordinator.recover();
	if (preparedJoin.status != OpenMlsInboundGroupChangeStatus::Prepared
		|| joinApply != GroupChangeApplyStatus::GroupPersistenceFailure
		|| joinRecovery != GroupChangeApplyStatus::Recovered
		|| targetGroupLedger.state()->generation() != 2
		|| !targetGroupLedger.state()->member(*targetAccountId)
		|| targetArchiveState.revision() != 1
		|| targetArchiveState.currentEpoch()->generation != 2
		|| targetMlsState.revision() != 2
		|| targetJournal.pending()) {
		std::fprintf(
			stderr,
			"join prepare=%d apply=%d recovery=%d "
			"group=%llu archive_rev=%llu "
			"archive_gen=%llu mls=%llu pending=%d\n",
			int(preparedJoin.status),
			int(joinApply),
			int(joinRecovery),
			static_cast<unsigned long long>(
				targetGroupLedger.state()->generation()),
			static_cast<unsigned long long>(
				targetArchiveState.revision()),
			static_cast<unsigned long long>(
				targetArchiveState.currentEpoch()
					? targetArchiveState.currentEpoch()->generation
					: 0),
			static_cast<unsigned long long>(targetMlsState.revision()),
			targetJournal.pending() ? 1 : 0);
		return Fail("joining client could not atomically adopt admission");
	}
	auto third = GenerateAccountPrivateIdentity();
	const auto thirdAccountId = third
		? DeriveAccountId(third->credential, sha256)
		: std::nullopt;
	const auto thirdClientId = FilledId<ClientId>(16);
	const auto thirdCredentialBytes = thirdAccountId
		? contextCodec.encodeCredential({
			.conversationId = conversationId,
			.accountId = *thirdAccountId,
			.clientId = thirdClientId,
		})
		: std::nullopt;
	auto thirdPackage = thirdCredentialBytes
		? bridge.createKeyPackage(*thirdCredentialBytes, groupIdBytes)
		: OpenMlsKeyPackageOutput();
	const auto thirdAuthorization = (third && thirdAccountId)
		? CreateClientAuthorizationProof({
			.conversationId = conversationId,
			.authorizationId = FilledId<ObjectId>(17),
			.accountId = *thirdAccountId,
			.clientId = thirdClientId,
			.requestedAfterGeneration = 1,
			.createdAt = 1'000'000,
			.accountCredential = &third->credential,
			.accountSigningPrivateKey = &third->signingPrivateKey,
			.keyPackage = thirdPackage.keyPackage,
		}, sha256)
		: std::nullopt;
	auto thirdArchiveKey = archiveCrypto.generateKey();
	const auto thirdTransition = GroupTransition{
		.conversationId = conversationId,
		.transitionId = FilledId<ObjectId>(18),
		.previousGeneration = 2,
		.generation = 3,
		.kind = GroupTransitionKind::AddMember,
		.targetAccountId = thirdAccountId.value_or(AccountId()),
		.targetClientId = thirdClientId,
		.targetTelegramUserIdBinding = 2003,
		.targetRole = GroupRole::Member,
		.targetAdminPermissions = 0,
		.historyAccess = {
			.mode = HistoryAccessMode::FromJoin,
			.boundaryEventId = {},
		},
	};
	auto preparedThird = (third
		&& thirdAccountId
		&& thirdAuthorization
		&& thirdArchiveKey)
		? PrepareOpenMlsAdmission({
			.actor = ownerContext,
			.currentGroupState = groupLedger.state(),
			.currentCheckpoint = groupLedger.checkpoint(),
			.transition = thirdTransition,
			.actorCredential = &owner->credential,
			.actorSigningPrivateKey = &owner->signingPrivateKey,
			.targetCredential = &third->credential,
			.targetClientAuthorization = &*thirdAuthorization,
			.targetKeyPackage = thirdPackage.keyPackage,
			.nextArchiveKey = &*thirdArchiveKey,
			.mlsCommitObjectId = FilledId<ObjectId>(19),
			.archiveDistributionObjectId = FilledId<ObjectId>(20),
			.welcomeObjectId = FilledId<ObjectId>(21),
		},
		bridge,
		contextCodec,
		rosterCodec,
		controlCodec,
		envelopeCodec,
		sha256,
		mlsState,
		archiveState,
		groupLedger)
		: PrepareOpenMlsGroupChangeOutcome();
	auto thirdTransitionEnvelope = std::optional<TransportEnvelope>();
	auto thirdCommitEnvelope = std::optional<TransportEnvelope>();
	auto thirdDistributionEnvelope = std::optional<TransportEnvelope>();
	if (preparedThird.prepared) {
		for (const auto &encoded
				: preparedThird.prepared->transaction.outboxEnvelopes) {
			const auto envelope = envelopeCodec.decode(encoded);
			if (envelope
					&& envelope->objectKind
						== ObjectKind::SignedGroupTransition) {
				thirdTransitionEnvelope = *envelope;
			} else if (envelope
					&& envelope->objectKind == ObjectKind::MlsCommit) {
				thirdCommitEnvelope = *envelope;
			} else if (envelope
					&& envelope->objectKind == ObjectKind::ArchiveEpoch) {
				thirdDistributionEnvelope = *envelope;
			}
		}
	}
	const auto thirdPublicationPayload = thirdAuthorization
		? ClientKeyPackagePublicationCodecV1().encode({
			.accountCredential = third->credential,
			.authorization = *thirdAuthorization,
			.keyPackage = thirdPackage.keyPackage,
		})
		: std::nullopt;
	const auto thirdPublicationEnvelope = thirdPublicationPayload
		? envelopeCodec.encode({
			.conversationId = conversationId,
			.objectKind = ObjectKind::ClientKeyPackage,
			.senderAccountId = *thirdAccountId,
			.senderClientId = thirdClientId,
			.telegramPeerIdBinding = peerId,
			.epochOrGeneration = 1,
			.objectId = thirdAuthorization->authorizationId,
			.payloadHash = sha256.digest(*thirdPublicationPayload),
			.payload = *thirdPublicationPayload,
			.authenticationData = QByteArray(
				reinterpret_cast<const char*>(
					thirdAuthorization->signature.data()),
				int(thirdAuthorization->signature.size())),
		})
		: std::nullopt;
	auto syncMlsBlob = targetMlsBlob;
	auto syncArchiveBlob = targetArchiveBlob;
	auto syncGroupBlob = targetGroupBlob;
	auto syncJournalBlob = MemoryBlobStore();
	auto syncMlsState = PersistentMlsStateStore(syncMlsBlob, protector);
	auto syncArchiveState = PersistentArchiveState(
		syncArchiveBlob,
		protector);
	auto syncGroupLedger = PersistentGroupLedger(
		syncGroupBlob,
		protector,
		sha256);
	auto syncJournal = PersistentGroupChangeJournal(
		syncJournalBlob,
		protector);
	auto syncObjects = std::vector<TelegramTransport::UntrustedObject>();
	if (thirdPublicationEnvelope) {
		syncObjects.push_back({
			.bytes = thirdPublicationEnvelope->bytes,
			.observedTelegramPeerIdBinding = peerId,
			.observedSenderTelegramUserIdBinding = 2003,
			.observedMessageId = 50,
		});
	}
	auto syncMessageId = std::int64_t(51);
	if (preparedThird.prepared) {
		for (const auto &encoded
				: preparedThird.prepared->transaction.outboxEnvelopes) {
			syncObjects.push_back({
				.bytes = encoded.bytes,
				.observedTelegramPeerIdBinding = peerId,
				.observedSenderTelegramUserIdBinding = 2001,
				.observedMessageId = syncMessageId++,
			});
		}
	}
	const auto syncReady = thirdPublicationEnvelope
		&& syncMlsState.load(conversationId) == MlsStateLoadResult::Loaded
		&& syncArchiveState.load(conversationId)
			== ArchiveStateLoadResult::Loaded
		&& syncGroupLedger.load(conversationId)
			== GroupLedgerLoadResult::Loaded
		&& syncJournal.load(conversationId)
			== GroupChangeJournalLoadResult::Empty;
	const auto synchronized = syncReady
		? SynchronizeObservedGroupChanges(
			syncObjects,
			targetContext,
			1'000'000,
			envelopeCodec,
			bridge,
			contextCodec,
			rosterCodec,
			controlCodec,
			sha256,
			syncMlsState,
			syncArchiveState,
			syncGroupLedger,
			syncJournal)
		: ObservedGroupChangeSyncOutcome();
	if (synchronized.status != ObservedGroupChangeSyncStatus::Updated
		|| synchronized.appliedTransitions != 1
		|| syncGroupLedger.state()->generation() != 3
		|| syncArchiveState.currentEpoch()->generation != 3
		|| syncMlsState.revision() != 3
		|| syncJournal.pending()) {
		return Fail("observed group synchronizer did not apply admission");
	}
	auto substitutedObjects = syncObjects;
	for (auto &object : substitutedObjects) {
		const auto envelope = envelopeCodec.decodeUntrusted(object.bytes);
		if (envelope
				&& envelope->objectKind
					== ObjectKind::SignedGroupTransition) {
			object.observedSenderTelegramUserIdBinding = 9999;
		}
	}
	auto substitutedMlsBlob = targetMlsBlob;
	auto substitutedArchiveBlob = targetArchiveBlob;
	auto substitutedGroupBlob = targetGroupBlob;
	auto substitutedJournalBlob = MemoryBlobStore();
	auto substitutedMlsState = PersistentMlsStateStore(
		substitutedMlsBlob,
		protector);
	auto substitutedArchiveState = PersistentArchiveState(
		substitutedArchiveBlob,
		protector);
	auto substitutedGroupLedger = PersistentGroupLedger(
		substitutedGroupBlob,
		protector,
		sha256);
	auto substitutedJournal = PersistentGroupChangeJournal(
		substitutedJournalBlob,
		protector);
	const auto substitutedReady = substitutedMlsState.load(conversationId)
			== MlsStateLoadResult::Loaded
		&& substitutedArchiveState.load(conversationId)
			== ArchiveStateLoadResult::Loaded
		&& substitutedGroupLedger.load(conversationId)
			== GroupLedgerLoadResult::Loaded
		&& substitutedJournal.load(conversationId)
			== GroupChangeJournalLoadResult::Empty;
	const auto substituted = substitutedReady
		? SynchronizeObservedGroupChanges(
			substitutedObjects,
			targetContext,
			1'000'000,
			envelopeCodec,
			bridge,
			contextCodec,
			rosterCodec,
			controlCodec,
			sha256,
			substitutedMlsState,
			substitutedArchiveState,
			substitutedGroupLedger,
			substitutedJournal)
		: ObservedGroupChangeSyncOutcome();
	if (substituted.status
			!= ObservedGroupChangeSyncStatus::ForkDetected
		|| substituted.appliedTransitions
		|| substitutedGroupLedger.state()->generation() != 2) {
		return Fail("observed group synchronizer accepted sender substitution");
	}
	auto targetInboxBlob = MemoryBlobStore();
	auto targetInboundJournalBlob = MemoryBlobStore();
	auto targetInbox = PersistentGroupChangeInbox(
		targetInboxBlob,
		protector,
		envelopeCodec,
		sha256);
	auto targetInboundJournal = PersistentInboundJournal(
		targetInboundJournalBlob,
		protector);
	auto targetInboxApplier = GroupChangeInboxApplier(targetInbox);
	auto targetInboxAuthenticator = OpenMlsGroupChangeEnvelopeAuthenticator(
		contextCodec,
		controlCodec,
		targetGroupLedger,
		sha256);
	auto targetInboundProcessor = InboundEnvelopeProcessor(
		conversationId,
		peerId,
		envelopeCodec,
		targetInboxAuthenticator,
		targetInboundJournal,
		targetInboxApplier);
	const auto encodedThirdTransition = thirdTransitionEnvelope
		? envelopeCodec.encode(*thirdTransitionEnvelope)
		: std::nullopt;
	const auto encodedThirdCommit = thirdCommitEnvelope
		? envelopeCodec.encode(*thirdCommitEnvelope)
		: std::nullopt;
	const auto encodedThirdDistribution = thirdDistributionEnvelope
		? envelopeCodec.encode(*thirdDistributionEnvelope)
		: std::nullopt;
	if (!encodedThirdTransition
		|| !encodedThirdCommit
		|| !encodedThirdDistribution
		|| targetInbox.load(conversationId)
			!= GroupChangeInboxLoadResult::Missing
		|| targetInboundJournal.load()
			!= InboundJournalLoadResult::Missing
		|| targetInboundProcessor.process(encodedThirdDistribution->bytes)
			!= InboundProcessResult::Accepted
		|| targetInbox.ready(2).status
			!= GroupChangeInboxReadyStatus::Incomplete
		|| targetInboundProcessor.process(encodedThirdTransition->bytes)
			!= InboundProcessResult::Accepted
		|| targetInbox.ready(2).status
			!= GroupChangeInboxReadyStatus::Incomplete
		|| targetInboundProcessor.process(encodedThirdCommit->bytes)
			!= InboundProcessResult::Accepted) {
		return Fail("group-change inbox rejected out-of-order envelopes");
	}
	auto reloadedTargetInbox = PersistentGroupChangeInbox(
		targetInboxBlob,
		protector,
		envelopeCodec,
		sha256);
	const auto readyInbound = reloadedTargetInbox.load(conversationId)
		== GroupChangeInboxLoadResult::Loaded
		? reloadedTargetInbox.ready(2)
		: GroupChangeInboxReadyResult();
	auto preparedInbound = (third
		&& readyInbound.status == GroupChangeInboxReadyStatus::Ready
		&& readyInbound.bundle)
		? PrepareOpenMlsInboundGroupChange({
			.local = targetContext,
			.transitionEnvelope = readyInbound.bundle->transitionEnvelope,
			.commitEnvelope = readyInbound.bundle->commitEnvelope,
			.archiveDistributionEnvelope = readyInbound.bundle
				->archiveDistributionEnvelope,
			.targetCredential = third->credential,
			.targetKeyPackage = thirdPackage.keyPackage,
		},
		bridge,
		contextCodec,
		rosterCodec,
		controlCodec,
		sha256,
		targetMlsState,
		targetArchiveState,
		targetGroupLedger)
		: PrepareOpenMlsInboundGroupChangeOutcome();
	auto targetCoordinator = GroupChangeTransactionCoordinator(
		targetJournal,
		targetMlsState,
		targetArchiveState,
		targetGroupLedger,
		sha256);
	const auto thirdOutboundApply = preparedThird.prepared
		? coordinator.apply(std::move(
			preparedThird.prepared->transaction))
		: GroupChangeApplyStatus::InvalidTransaction;
	const auto thirdInboundApply = preparedInbound.prepared
		? targetCoordinator.apply(std::move(
			preparedInbound.prepared->transaction))
		: GroupChangeApplyStatus::InvalidTransaction;
	if (preparedThird.status != OpenMlsGroupChangePrepareStatus::Prepared
		|| preparedInbound.status
			!= OpenMlsInboundGroupChangeStatus::Prepared
		|| thirdOutboundApply != GroupChangeApplyStatus::Applied
		|| thirdInboundApply != GroupChangeApplyStatus::Applied
		|| groupLedger.state()->generation() != 3
		|| targetGroupLedger.state()->snapshot()
			!= groupLedger.state()->snapshot()
		|| targetArchiveState.currentEpoch()->generation != 3
		|| targetMlsState.revision() != 3
		|| targetJournal.pending()
		|| !reloadedTargetInbox.discardBundle(
			thirdTransition.transitionId)
		|| reloadedTargetInbox.size()
		|| outbox.size() != 8) {
		std::fprintf(
			stderr,
			"third prepare=%d inbound=%d out=%d in=%d "
			"group=%llu target=%llu archive=%llu mls=%llu "
			"pending=%d inbox=%zu outbox=%d\n",
			int(preparedThird.status),
			int(preparedInbound.status),
			int(thirdOutboundApply),
			int(thirdInboundApply),
			static_cast<unsigned long long>(
				groupLedger.state()->generation()),
			static_cast<unsigned long long>(
				targetGroupLedger.state()->generation()),
			static_cast<unsigned long long>(
				targetArchiveState.currentEpoch()->generation),
			static_cast<unsigned long long>(targetMlsState.revision()),
			targetJournal.pending() ? 1 : 0,
			reloadedTargetInbox.size(),
			outbox.size());
		return Fail("existing member could not atomically receive admission");
	}
	auto policyArchiveKey = archiveCrypto.generateKey();
	const auto policyTransition = GroupTransition{
		.conversationId = conversationId,
		.transitionId = FilledId<ObjectId>(22),
		.previousGeneration = 3,
		.generation = 4,
		.kind = GroupTransitionKind::SetMemberHistory,
		.targetAccountId = *thirdAccountId,
		.targetClientId = {},
		.targetTelegramUserIdBinding = 0,
		.targetRole = GroupRole::Member,
		.targetAdminPermissions = 0,
		.historyAccess = {
			.mode = HistoryAccessMode::Full,
			.boundaryEventId = {},
		},
	};
	auto preparedPolicy = policyArchiveKey
		? PrepareOpenMlsPolicyChange({
			.actor = ownerContext,
			.currentGroupState = groupLedger.state(),
			.currentCheckpoint = groupLedger.checkpoint(),
			.transition = policyTransition,
			.actorCredential = &owner->credential,
			.actorSigningPrivateKey = &owner->signingPrivateKey,
			.nextArchiveKey = &*policyArchiveKey,
			.mlsCommitObjectId = FilledId<ObjectId>(23),
			.archiveDistributionObjectId = FilledId<ObjectId>(24),
		},
		bridge,
		contextCodec,
		rosterCodec,
		controlCodec,
		envelopeCodec,
		sha256,
		mlsState,
		archiveState,
		groupLedger)
		: PrepareOpenMlsGroupChangeOutcome();
	auto policyTransitionEnvelope = std::optional<TransportEnvelope>();
	auto policyCommitEnvelope = std::optional<TransportEnvelope>();
	auto policyDistributionEnvelope = std::optional<TransportEnvelope>();
	if (preparedPolicy.prepared) {
		for (const auto &encoded
				: preparedPolicy.prepared->transaction.outboxEnvelopes) {
			const auto envelope = envelopeCodec.decode(encoded);
			if (envelope
					&& envelope->objectKind
						== ObjectKind::SignedGroupTransition) {
				policyTransitionEnvelope = *envelope;
			} else if (envelope
					&& envelope->objectKind == ObjectKind::MlsCommit) {
				policyCommitEnvelope = *envelope;
			} else if (envelope
					&& envelope->objectKind == ObjectKind::ArchiveEpoch) {
				policyDistributionEnvelope = *envelope;
			}
		}
	}
	auto preparedInboundPolicy = (policyTransitionEnvelope
		&& policyCommitEnvelope
		&& policyDistributionEnvelope)
		? PrepareOpenMlsInboundGroupChange({
			.local = targetContext,
			.transitionEnvelope = *policyTransitionEnvelope,
			.commitEnvelope = *policyCommitEnvelope,
			.archiveDistributionEnvelope = *policyDistributionEnvelope,
			.targetCredential = std::nullopt,
			.targetKeyPackage = {},
		},
		bridge,
		contextCodec,
		rosterCodec,
		controlCodec,
		sha256,
		targetMlsState,
		targetArchiveState,
		targetGroupLedger)
		: PrepareOpenMlsInboundGroupChangeOutcome();
	const auto policyOutboundApply = preparedPolicy.prepared
		? coordinator.apply(std::move(
			preparedPolicy.prepared->transaction))
		: GroupChangeApplyStatus::InvalidTransaction;
	const auto policyInboundApply = preparedInboundPolicy.prepared
		? targetCoordinator.apply(std::move(
			preparedInboundPolicy.prepared->transaction))
		: GroupChangeApplyStatus::InvalidTransaction;
	const auto thirdMember = groupLedger.state()->member(*thirdAccountId);
	if (preparedPolicy.status != OpenMlsGroupChangePrepareStatus::Prepared
		|| preparedInboundPolicy.status
			!= OpenMlsInboundGroupChangeStatus::Prepared
		|| policyOutboundApply != GroupChangeApplyStatus::Applied
		|| policyInboundApply != GroupChangeApplyStatus::Applied
		|| groupLedger.state()->generation() != 4
		|| targetGroupLedger.state()->snapshot()
			!= groupLedger.state()->snapshot()
		|| !thirdMember
		|| thirdMember->historyAccess.mode != HistoryAccessMode::Full
		|| targetArchiveState.currentEpoch()->generation != 4
		|| targetMlsState.revision() != 4
		|| outbox.size() != 11) {
		std::fprintf(
			stderr,
			"policy prepare=%d inbound=%d out=%d in=%d "
			"group=%llu target=%llu archive=%llu mls=%llu outbox=%d\n",
			int(preparedPolicy.status),
			int(preparedInboundPolicy.status),
			int(policyOutboundApply),
			int(policyInboundApply),
			static_cast<unsigned long long>(
				groupLedger.state()->generation()),
			static_cast<unsigned long long>(
				targetGroupLedger.state()->generation()),
			static_cast<unsigned long long>(
				targetArchiveState.currentEpoch()->generation),
			static_cast<unsigned long long>(targetMlsState.revision()),
			outbox.size());
		return Fail("existing member could not receive a policy update");
	}
	auto removedClientState = targetMlsState.engineState();
	auto removalArchiveKey = archiveCrypto.generateKey();
	const auto removalTransition = GroupTransition{
		.conversationId = conversationId,
		.transitionId = FilledId<ObjectId>(13),
		.previousGeneration = 4,
		.generation = 5,
		.kind = GroupTransitionKind::RemoveMember,
		.targetAccountId = *targetAccountId,
		.targetClientId = {},
		.targetTelegramUserIdBinding = 0,
		.targetRole = GroupRole::Member,
		.targetAdminPermissions = 0,
		.historyAccess = {
			.mode = HistoryAccessMode::FromJoin,
			.boundaryEventId = {},
		},
	};
	auto preparedRemoval = removalArchiveKey
		? PrepareOpenMlsRemoval({
			.actor = ownerContext,
			.currentGroupState = groupLedger.state(),
			.currentCheckpoint = groupLedger.checkpoint(),
			.transition = removalTransition,
			.actorCredential = &owner->credential,
			.actorSigningPrivateKey = &owner->signingPrivateKey,
			.nextArchiveKey = &*removalArchiveKey,
			.mlsCommitObjectId = FilledId<ObjectId>(14),
			.archiveDistributionObjectId = FilledId<ObjectId>(15),
		},
		bridge,
		contextCodec,
		rosterCodec,
		controlCodec,
		envelopeCodec,
		sha256,
		mlsState,
		archiveState,
		groupLedger)
		: PrepareOpenMlsGroupChangeOutcome();
	auto removalTransitionEnvelope = std::optional<TransportEnvelope>();
	auto removalCommitEnvelope = std::optional<TransportEnvelope>();
	auto removalDistributionEnvelope = std::optional<TransportEnvelope>();
	if (preparedRemoval.prepared) {
		for (const auto &encoded
				: preparedRemoval.prepared->transaction.outboxEnvelopes) {
			const auto envelope = envelopeCodec.decode(encoded);
			if (envelope
					&& envelope->objectKind
						== ObjectKind::SignedGroupTransition) {
				removalTransitionEnvelope = *envelope;
			} else if (envelope
					&& envelope->objectKind == ObjectKind::MlsCommit) {
				removalCommitEnvelope = *envelope;
			} else if (envelope
					&& envelope->objectKind == ObjectKind::ArchiveEpoch) {
				removalDistributionEnvelope = *envelope;
			}
		}
	}
	const auto removalApply = preparedRemoval.prepared
		? coordinator.apply(std::move(
			preparedRemoval.prepared->transaction))
		: GroupChangeApplyStatus::InvalidTransaction;
	if (preparedRemoval.status
			!= OpenMlsGroupChangePrepareStatus::Prepared
		|| !preparedRemoval.prepared
		|| !removalTransitionEnvelope
		|| !removalCommitEnvelope
		|| !removalDistributionEnvelope
		|| preparedRemoval.prepared->resultingRoster.members.size() != 2
		|| removalApply != GroupChangeApplyStatus::Applied
		|| groupLedger.state()->generation() != 5
		|| groupLedger.state()->member(*targetAccountId)
		|| archiveState.currentEpoch()->generation != 5
		|| mlsState.revision() != 5
		|| outbox.size() != 14) {
		std::fprintf(
			stderr,
			"prepare=%d apply=%d group=%llu archive=%llu mls=%llu outbox=%d\n",
			int(preparedRemoval.status),
			int(removalApply),
			static_cast<unsigned long long>(
				groupLedger.state()->generation()),
			static_cast<unsigned long long>(
				archiveState.currentEpoch()->generation),
			static_cast<unsigned long long>(mlsState.revision()),
			outbox.size());
		return Fail("OpenMLS removal transaction did not commit atomically");
	}
	auto preparedInboundRemoval = PrepareOpenMlsInboundGroupChange({
		.local = targetContext,
		.transitionEnvelope = *removalTransitionEnvelope,
		.commitEnvelope = *removalCommitEnvelope,
		.archiveDistributionEnvelope = *removalDistributionEnvelope,
		.targetCredential = std::nullopt,
		.targetKeyPackage = {},
	},
	bridge,
	contextCodec,
	rosterCodec,
	controlCodec,
	sha256,
	targetMlsState,
	targetArchiveState,
	targetGroupLedger);
	targetGroupBlob.failNextWrite = true;
	const auto inboundRemovalApply = preparedInboundRemoval.prepared
		? targetCoordinator.apply(std::move(
			preparedInboundRemoval.prepared->transaction))
		: GroupChangeApplyStatus::InvalidTransaction;
	const auto inboundRemovalRecovery = targetCoordinator.recover();
	const auto removalTombstone = targetMlsState.removalTombstone();
	if (preparedInboundRemoval.status
			!= OpenMlsInboundGroupChangeStatus::Prepared
		|| inboundRemovalApply
			!= GroupChangeApplyStatus::GroupPersistenceFailure
		|| inboundRemovalRecovery != GroupChangeApplyStatus::Recovered
		|| targetGroupLedger.state()->generation() != 5
		|| targetGroupLedger.state()->member(*targetAccountId)
		|| targetArchiveState.currentEpoch()->generation != 4
		|| targetMlsState.revision() != 5
		|| !targetMlsState.removed()
		|| !targetMlsState.engineState().isEmpty()
		|| !removalTombstone
		|| removalTombstone->transitionId
			!= removalTransition.transitionId
		|| removalTombstone->removedAccountId != *targetAccountId
		|| removalTombstone->removedClientId != targetClientId
		|| targetJournal.pending()) {
		return Fail("removed client state did not become a durable tombstone");
	}
	auto removalAtRemovedClient = bridge.process(
		removedClientState,
		removalCommitEnvelope->payload);
	const auto removedDistribution = removalAtRemovedClient.status
		== OpenMlsBridgeStatus::Ok
		? bridge.process(
			removalAtRemovedClient.state,
			removalDistributionEnvelope->payload)
		: bridge.process(
			removedClientState,
			removalDistributionEnvelope->payload);
	OPENSSL_cleanse(
		removalAtRemovedClient.state.data(),
		removalAtRemovedClient.state.size());
	OPENSSL_cleanse(removedClientState.data(), removedClientState.size());
	if (removedDistribution.status == OpenMlsBridgeStatus::Ok) {
		return Fail("removed MLS client decrypted the rotated archive key");
	}
	const auto publicationCodec = ClientKeyPackagePublicationCodecV1();
	const auto rejoinCreatedAt = std::uint64_t(2'000'000);
	auto rejoinPackage = PrepareClientKeyPackage({
		.client = targetContext,
		.currentGeneration = 5,
		.publicationObjectId = FilledId<ObjectId>(31),
		.createdAt = rejoinCreatedAt,
		.accountCredential = &target->credential,
		.accountSigningPrivateKey = &target->signingPrivateKey,
	}, bridge, contextCodec, publicationCodec, envelopeCodec, sha256);
	auto rejoinPoolBlob = MemoryBlobStore();
	auto rejoinPool = PersistentKeyPackagePool(
		rejoinPoolBlob,
		protector,
		envelopeCodec,
		sha256);
	if (rejoinPackage.status != PrepareClientKeyPackageStatus::Prepared
		|| !rejoinPackage.entry
		|| rejoinPool.load(conversationId, peerId)
			!= KeyPackagePoolLoadResult::Empty
		|| rejoinPool.add(std::move(*rejoinPackage.entry))
			!= KeyPackagePoolMutationResult::Committed) {
		return Fail("removed client could not retain a fresh KeyPackage");
	}
	const auto rejoinPublicationEnvelope = envelopeCodec.decode(
		rejoinPool.entries().front().publicationEnvelope);
	const auto rejoinPublication = rejoinPublicationEnvelope
		? publicationCodec.decode(rejoinPublicationEnvelope->payload)
		: std::nullopt;
	if (!rejoinPublication
		|| InstallClientKeyPackageForWelcome(
			rejoinPublication->keyPackage,
			rejoinCreatedAt,
			bridge,
			sha256,
			rejoinPool,
			targetMlsState) != InstallClientKeyPackageStatus::Installed
		|| targetMlsState.removed()
		|| targetMlsState.revision() != 6) {
		return Fail("removed client could not install a fresh KeyPackage");
	}
	const auto &rejoinAuthorization = rejoinPublication->authorization;
	auto rejoinArchiveKey = archiveCrypto.generateKey();
	const auto rejoinTransition = GroupTransition{
		.conversationId = conversationId,
		.transitionId = FilledId<ObjectId>(32),
		.previousGeneration = 5,
		.generation = 6,
		.kind = GroupTransitionKind::AddMember,
		.targetAccountId = *targetAccountId,
		.targetClientId = targetClientId,
		.targetTelegramUserIdBinding = 2002,
		.targetRole = GroupRole::Member,
		.targetAdminPermissions = 0,
		.historyAccess = {
			.mode = HistoryAccessMode::FromJoin,
			.boundaryEventId = {},
		},
	};
	auto preparedRejoin = rejoinArchiveKey
		? PrepareOpenMlsAdmission({
			.actor = ownerContext,
			.currentGroupState = groupLedger.state(),
			.currentCheckpoint = groupLedger.checkpoint(),
			.transition = rejoinTransition,
			.actorCredential = &owner->credential,
			.actorSigningPrivateKey = &owner->signingPrivateKey,
			.targetCredential = &target->credential,
			.targetClientAuthorization = &rejoinAuthorization,
			.targetKeyPackage = rejoinPublication->keyPackage,
			.nextArchiveKey = &*rejoinArchiveKey,
			.mlsCommitObjectId = FilledId<ObjectId>(33),
			.archiveDistributionObjectId = FilledId<ObjectId>(34),
			.welcomeObjectId = FilledId<ObjectId>(35),
		},
		bridge,
		contextCodec,
		rosterCodec,
		controlCodec,
		envelopeCodec,
		sha256,
		mlsState,
		archiveState,
		groupLedger)
		: PrepareOpenMlsGroupChangeOutcome();
	auto rejoinTransitionEnvelope = std::optional<TransportEnvelope>();
	auto rejoinCommitEnvelope = std::optional<TransportEnvelope>();
	auto rejoinWelcomeEnvelope = std::optional<TransportEnvelope>();
	auto rejoinDistributionEnvelope = std::optional<TransportEnvelope>();
	if (preparedRejoin.prepared) {
		for (const auto &encoded
				: preparedRejoin.prepared->transaction.outboxEnvelopes) {
			const auto envelope = envelopeCodec.decode(encoded);
			if (!envelope) {
				continue;
			}
			switch (envelope->objectKind) {
			case ObjectKind::SignedGroupTransition:
				rejoinTransitionEnvelope = *envelope;
				break;
			case ObjectKind::MlsCommit:
				rejoinCommitEnvelope = *envelope;
				break;
			case ObjectKind::MlsWelcome:
				rejoinWelcomeEnvelope = *envelope;
				break;
			case ObjectKind::ArchiveEpoch:
				rejoinDistributionEnvelope = *envelope;
				break;
			default:
				break;
			}
		}
	}
	auto preparedInboundRejoin = (rejoinTransitionEnvelope
		&& rejoinCommitEnvelope
		&& rejoinWelcomeEnvelope
		&& rejoinDistributionEnvelope)
		? PrepareOpenMlsInboundJoin({
			.local = targetContext,
			.transitionEnvelope = *rejoinTransitionEnvelope,
			.commitEnvelope = *rejoinCommitEnvelope,
			.welcomeEnvelope = *rejoinWelcomeEnvelope,
			.archiveDistributionEnvelope = *rejoinDistributionEnvelope,
			.targetCredential = std::nullopt,
			.targetKeyPackage = rejoinPublication->keyPackage,
		},
		bridge,
		contextCodec,
		rosterCodec,
		controlCodec,
		sha256,
		targetMlsState,
		targetArchiveState,
		targetGroupLedger)
		: PrepareOpenMlsInboundGroupChangeOutcome();
	const auto rejoinOutboundApply = preparedRejoin.prepared
		? coordinator.apply(std::move(
			preparedRejoin.prepared->transaction))
		: GroupChangeApplyStatus::InvalidTransaction;
	const auto rejoinInboundApply = preparedInboundRejoin.prepared
		? targetCoordinator.apply(std::move(
			preparedInboundRejoin.prepared->transaction))
		: GroupChangeApplyStatus::InvalidTransaction;
	const auto rejoinFinalized = rejoinInboundApply
		== GroupChangeApplyStatus::Applied
		? FinalizeClientKeyPackageWelcome(
			rejoinPublication->keyPackage,
			bridge,
			sha256,
			rejoinPool,
			targetMlsState)
		: FinalizeClientKeyPackageStatus::GroupStateUnavailable;
	if (preparedRejoin.status
			!= OpenMlsGroupChangePrepareStatus::Prepared
		|| preparedInboundRejoin.status
			!= OpenMlsInboundGroupChangeStatus::Prepared
		|| rejoinOutboundApply != GroupChangeApplyStatus::Applied
		|| rejoinInboundApply != GroupChangeApplyStatus::Applied
		|| rejoinFinalized != FinalizeClientKeyPackageStatus::Finalized
		|| !rejoinPool.entries().empty()
		|| groupLedger.state()->generation() != 6
		|| targetGroupLedger.state()->snapshot()
			!= groupLedger.state()->snapshot()
		|| !targetGroupLedger.state()->member(*targetAccountId)
		|| targetArchiveState.currentEpoch()->generation != 6
		|| targetArchiveState.epoch(5)
		|| targetMlsState.revision() != 7
		|| targetMlsState.removed()
		|| targetMlsState.engineState().isEmpty()) {
		return Fail("removed client could not rejoin across an archive-key gap");
	}
	OPENSSL_cleanse(
		distributed.plaintext.data(),
		distributed.plaintext.size());
	OPENSSL_cleanse(distributed.state.data(), distributed.state.size());
	return 0;
}

} // namespace

int main(int, char *[]) {
	return ScenarioAdmissionTransaction();
}
