/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "e2e_cloud/archive/archive_epoch_crypto.h"
#include "e2e_cloud/protocol/group_bootstrap.h"
#include "e2e_cloud/protocol/group_bootstrap_transaction.h"
#include "e2e_cloud/protocol/public_group_bootstrap.h"
#include "e2e_cloud/storage/aes_gcm_local_record_protector.h"

#include <cstdio>

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

[[nodiscard]] ProtectedGroupBootstrapOutcome PrepareFixture(
		AccountPrivateIdentity &identity,
		const ArchiveKey32 &archiveKey) {
	return PrepareProtectedGroupBootstrap({
		.conversationId = FilledId<ConversationId>(1),
		.telegramPeerIdBinding = 1001,
		.ownerTelegramUserIdBinding = 2001,
		.ownerClientId = FilledId<ClientId>(2),
		.policy = {
			.defaultHistoryAccess = {
				.mode = HistoryAccessMode::FromJoin,
				.boundaryEventId = {},
			},
		},
		.genesisObjectId = FilledId<ObjectId>(3),
		.ownerCredentialObjectId = FilledId<ObjectId>(4),
		.initialMlsPublicObjectId = FilledId<ObjectId>(5),
		.archiveActivationEventId = FilledId<ObjectId>(6),
		.ownerHistoryGrantObjectId = FilledId<ObjectId>(7),
		.ownerIdentity = &identity,
		.initialArchiveKey = &archiveKey,
	},
	OpenMlsBridge(),
	MlsContextCodecV1(),
	MlsRosterCodecV1(),
	EnvelopeCodecV1(),
	OpenSslSha256Provider());
}

[[nodiscard]] int ScenarioPreparesPublicBootstrapOnly() {
	auto identity = GenerateAccountPrivateIdentity();
	auto archiveKey = ArchiveEpochCrypto().generateKey();
	const auto bridge = OpenMlsBridge();
	const auto contextCodec = MlsContextCodecV1();
	const auto rosterCodec = MlsRosterCodecV1();
	const auto envelopeCodec = EnvelopeCodecV1();
	const auto sha256 = OpenSslSha256Provider();
	if (!identity || !archiveKey || !bridge.compatible()) {
		return Fail("protected bootstrap cryptography was unavailable");
	}
	const auto outcome = PrepareProtectedGroupBootstrap({
		.conversationId = FilledId<ConversationId>(1),
		.telegramPeerIdBinding = 1001,
		.ownerTelegramUserIdBinding = 2001,
		.ownerClientId = FilledId<ClientId>(2),
		.policy = {
			.defaultHistoryAccess = {
				.mode = HistoryAccessMode::FromJoin,
				.boundaryEventId = {},
			},
		},
		.genesisObjectId = FilledId<ObjectId>(3),
		.ownerCredentialObjectId = FilledId<ObjectId>(4),
		.initialMlsPublicObjectId = FilledId<ObjectId>(5),
		.archiveActivationEventId = FilledId<ObjectId>(6),
		.ownerHistoryGrantObjectId = FilledId<ObjectId>(7),
		.ownerIdentity = &*identity,
		.initialArchiveKey = &*archiveKey,
	}, bridge, contextCodec, rosterCodec, envelopeCodec, sha256);
	if (outcome.status != ProtectedGroupBootstrapStatus::Prepared
		|| !outcome.prepared
		|| outcome.prepared->outboxEnvelopes.size() != 4
		|| outcome.prepared->mlsEngineState.isEmpty()
		|| outcome.prepared->initialMlsPublicObject.isEmpty()
		|| outcome.prepared->mlsEngineState
			== outcome.prepared->initialMlsPublicObject) {
		return Fail("protected group bootstrap was not prepared");
	}
	auto kinds = std::vector<ObjectKind>();
	for (const auto &encoded : outcome.prepared->outboxEnvelopes) {
		const auto envelope = envelopeCodec.decode(encoded);
		if (!envelope
			|| envelope->payload == outcome.prepared->mlsEngineState) {
			return Fail("private OpenMLS provider state entered the outbox");
		}
		kinds.push_back(envelope->objectKind);
	}
	if (kinds != std::vector<ObjectKind>{
		ObjectKind::AccountCredential,
		ObjectKind::MlsGroupInfo,
		ObjectKind::InitialGroupState,
		ObjectKind::HistoryGrant,
	}) {
		return Fail("protected bootstrap emitted an incomplete public bundle");
	}
	const auto publicEnvelope = envelopeCodec.decode(
		outcome.prepared->outboxEnvelopes[1]);
	const auto roster = publicEnvelope
		? rosterCodec.decode(publicEnvelope->payload, contextCodec)
		: std::nullopt;
	if (!roster
		|| roster->members.size() != 1
		|| roster->members.front().credential.accountId
			!= outcome.prepared->ownerAccountId
		|| outcome.prepared->genesis.initialMlsPublicHash
			!= sha256.digest(publicEnvelope->payload)) {
		return Fail("public bootstrap roster did not match signed genesis");
	}
	const auto credentialEnvelope = envelopeCodec.decode(
		outcome.prepared->outboxEnvelopes[0]);
	const auto genesisEnvelope = envelopeCodec.decode(
		outcome.prepared->outboxEnvelopes[2]);
	const auto credential = credentialEnvelope
		? AccountCredentialCodecV1().decode(credentialEnvelope->payload)
		: std::nullopt;
	const auto genesis = genesisEnvelope
		? SignedGroupGenesisCodecV1().decode(genesisEnvelope->payload)
		: std::nullopt;
	const auto publicVerification = (credential && genesis && publicEnvelope)
		? VerifySignedGroupGenesisPublic({
			.genesis = &*genesis,
			.ownerCredential = &*credential,
			.genesisObjectId = genesisEnvelope->objectId,
			.initialMlsPublicObjectId = publicEnvelope->objectId,
			.initialMlsPublicObject = publicEnvelope->payload,
			.initialArchiveKey = nullptr,
		}, sha256)
		: VerifySignedGroupGenesisPublicOutcome();
	if (!publicVerification.verified
		|| publicVerification.verified->checkpoint
			!= outcome.prepared->checkpoint) {
		return Fail("public bootstrap required a private archive secret");
	}
	const auto grantEnvelope = envelopeCodec.decode(
		outcome.prepared->outboxEnvelopes[3]);
	const auto encryptedGrant = grantEnvelope
		? EncryptedHistoryGrantCodecV1().decode(grantEnvelope->payload)
		: std::nullopt;
	const auto grant = encryptedGrant
		? OpenHistoryGrant(
			*encryptedGrant,
			outcome.prepared->ownerAccountId,
			identity->archiveHpkePrivateKey,
			identity->credential,
			sha256,
			bridge)
		: std::nullopt;
	if (!grant
		|| grant->historyAccess.mode != HistoryAccessMode::Full
		|| grant->epochs.size() != 1
		|| grant->epochs.front().generation != 1
		|| grant->epochs.front().key.bytes() != archiveKey->bytes()) {
		return Fail("owner archive recovery grant was not in bootstrap");
	}
	return 0;
}

[[nodiscard]] int ScenarioRejectsAliasedBootstrapObjectIds() {
	auto identity = GenerateAccountPrivateIdentity();
	auto archiveKey = ArchiveEpochCrypto().generateKey();
	const auto duplicated = FilledId<ObjectId>(3);
	const auto outcome = (identity && archiveKey)
		? PrepareProtectedGroupBootstrap({
			.conversationId = FilledId<ConversationId>(1),
			.telegramPeerIdBinding = 1001,
			.ownerTelegramUserIdBinding = 2001,
			.ownerClientId = FilledId<ClientId>(2),
			.policy = {
				.defaultHistoryAccess = {
					.mode = HistoryAccessMode::FromJoin,
					.boundaryEventId = {},
				},
			},
			.genesisObjectId = duplicated,
			.ownerCredentialObjectId = duplicated,
			.initialMlsPublicObjectId = FilledId<ObjectId>(5),
			.archiveActivationEventId = FilledId<ObjectId>(6),
			.ownerHistoryGrantObjectId = FilledId<ObjectId>(7),
			.ownerIdentity = &*identity,
			.initialArchiveKey = &*archiveKey,
		},
		OpenMlsBridge(),
		MlsContextCodecV1(),
		MlsRosterCodecV1(),
		EnvelopeCodecV1(),
		OpenSslSha256Provider())
		: ProtectedGroupBootstrapOutcome();
	if (outcome.status != ProtectedGroupBootstrapStatus::InvalidArgument
		|| outcome.prepared) {
		return Fail("protected bootstrap accepted aliased object identifiers");
	}
	return 0;
}

[[nodiscard]] int ScenarioVerifiesObservedPublicBootstrap() {
	auto identity = GenerateAccountPrivateIdentity();
	auto archiveKey = ArchiveEpochCrypto().generateKey();
	auto prepared = (identity && archiveKey)
		? PrepareFixture(*identity, *archiveKey)
		: ProtectedGroupBootstrapOutcome();
	if (!prepared.prepared) {
		return Fail("observed bootstrap fixture could not be prepared");
	}
	auto objects = std::vector<TelegramTransport::UntrustedObject>();
	for (auto i = std::size_t();
			i != prepared.prepared->outboxEnvelopes.size();
			++i) {
		objects.push_back({
			.bytes = prepared.prepared->outboxEnvelopes[i].bytes,
			.observedTelegramPeerIdBinding = 1001,
			.observedSenderTelegramUserIdBinding = 2001,
			.observedMessageId = std::int64_t(i + 1),
		});
	}
	const auto verified = VerifyPublicGroupBootstrap(
		objects,
		1001,
		FilledId<ConversationId>(1),
		prepared.prepared->ownerAccountId,
		EnvelopeCodecV1(),
		OpenSslSha256Provider());
	if (!IsPublicGroupBootstrapCandidate(
			objects[0],
			1001,
			FilledId<ConversationId>(1),
			EnvelopeCodecV1())
		|| !IsPublicGroupBootstrapCandidate(
			objects[1],
			1001,
			FilledId<ConversationId>(1),
			EnvelopeCodecV1())
		|| !IsPublicGroupBootstrapCandidate(
			objects[2],
			1001,
			FilledId<ConversationId>(1),
			EnvelopeCodecV1())
		|| IsPublicGroupBootstrapCandidate(
			objects[3],
			1001,
			FilledId<ConversationId>(1),
			EnvelopeCodecV1())
		|| verified.status != PublicGroupBootstrapStatus::Verified
		|| !verified.verified
		|| verified.verified->checkpoint
			!= prepared.prepared->checkpoint) {
		return Fail("observed public bootstrap was not verified");
	}
	auto substituted = objects;
	substituted.front().observedSenderTelegramUserIdBinding = 2002;
	const auto rejected = VerifyPublicGroupBootstrap(
		substituted,
		1001,
		FilledId<ConversationId>(1),
		prepared.prepared->ownerAccountId,
		EnvelopeCodecV1(),
		OpenSslSha256Provider());
	if (rejected.status == PublicGroupBootstrapStatus::Verified) {
		return Fail("public bootstrap ignored its Telegram sender binding");
	}
	substituted.push_back(objects.front());
	const auto conflict = VerifyPublicGroupBootstrap(
		substituted,
		1001,
		FilledId<ConversationId>(1),
		prepared.prepared->ownerAccountId,
		EnvelopeCodecV1(),
		OpenSslSha256Provider());
	if (conflict.status != PublicGroupBootstrapStatus::ObjectConflict) {
		return Fail("public bootstrap ignored conflicting observations");
	}
	return 0;
}

[[nodiscard]] int ScenarioBootstrapTransactionRecoversPartialWrite() {
	auto identity = GenerateAccountPrivateIdentity();
	auto archiveKey = ArchiveEpochCrypto().generateKey();
	auto prepared = (identity && archiveKey)
		? PrepareFixture(*identity, *archiveKey)
		: ProtectedGroupBootstrapOutcome();
	if (!identity || !prepared.prepared) {
		return Fail("bootstrap transaction fixture could not be prepared");
	}
	const auto expectedEnvelopes = prepared.prepared->outboxEnvelopes;
	auto localKey = LocalRecordKey();
	localKey.fill(9);
	const auto protector = AesGcmLocalRecordProtector(std::move(localKey));
	auto journalBlob = MemoryBlobStore();
	auto mlsBlob = MemoryBlobStore();
	auto archiveBlob = MemoryBlobStore();
	auto groupBlob = MemoryBlobStore();
	auto outboxBlob = MemoryBlobStore();
	auto journal = PersistentGroupBootstrapJournal(
		journalBlob,
		protector);
	auto mlsState = PersistentMlsStateStore(mlsBlob, protector);
	auto archiveState = PersistentArchiveState(archiveBlob, protector);
	const auto sha256 = OpenSslSha256Provider();
	auto groupLedger = PersistentGroupLedger(
		groupBlob,
		protector,
		sha256);
	auto outbox = PersistentOutboxStore(outboxBlob, protector);
	const auto conversationId = FilledId<ConversationId>(1);
	if (journal.load(conversationId)
			!= GroupBootstrapJournalLoadResult::Empty
		|| mlsState.load(conversationId) != MlsStateLoadResult::Missing
		|| archiveState.load(conversationId)
			!= ArchiveStateLoadResult::Missing
		|| groupLedger.load(conversationId)
			!= GroupLedgerLoadResult::Missing
		|| outbox.load() != PersistentOutboxLoadResult::Empty) {
		return Fail("bootstrap transaction stores did not initialize empty");
	}
	auto transaction = MakeGroupBootstrapTransaction(
		std::move(*prepared.prepared),
		identity->credential,
		outbox.revision());
	groupBlob.failNextWrite = true;
	const auto envelopeCodec = EnvelopeCodecV1();
	auto coordinator = GroupBootstrapTransactionCoordinator(
		journal,
		mlsState,
		archiveState,
		groupLedger,
		outbox,
		envelopeCodec,
		sha256);
	const auto firstApply = coordinator.apply(std::move(transaction));
	if (firstApply != GroupBootstrapApplyStatus::GroupPersistenceFailure
		|| !journal.pending()
		|| mlsState.revision() != 1
		|| archiveState.revision() != 1
		|| groupLedger.revision() != 0
		|| outbox.size() != 0) {
		return Fail("bootstrap WAL did not preserve a partial local write");
	}
	if (coordinator.recover() != GroupBootstrapApplyStatus::Recovered
		|| journal.pending()
		|| groupLedger.revision() != 1
		|| outbox.size() != 4) {
		return Fail("bootstrap WAL did not recover all local stores");
	}
	for (const auto &expected : expectedEnvelopes) {
		const auto item = outbox.item(expected.objectId);
		if (!item
			|| item->stage != OutboxItemStage::Sealed
			|| item->sealed != expected) {
			return Fail("bootstrap recovery changed exact retry bytes");
		}
	}
	return 0;
}

[[nodiscard]] int ScenarioBootstrapJournalRejectsChangedExactRetry() {
	auto identity = GenerateAccountPrivateIdentity();
	auto archiveKey = ArchiveEpochCrypto().generateKey();
	auto first = (identity && archiveKey)
		? PrepareFixture(*identity, *archiveKey)
		: ProtectedGroupBootstrapOutcome();
	auto second = (identity && archiveKey)
		? PrepareFixture(*identity, *archiveKey)
		: ProtectedGroupBootstrapOutcome();
	if (!identity || !first.prepared || !second.prepared) {
		return Fail("bootstrap conflict fixtures could not be prepared");
	}
	auto localKey = LocalRecordKey();
	localKey.fill(10);
	const auto protector = AesGcmLocalRecordProtector(std::move(localKey));
	auto journalBlob = MemoryBlobStore();
	auto journal = PersistentGroupBootstrapJournal(journalBlob, protector);
	const auto conversationId = FilledId<ConversationId>(1);
	if (journal.load(conversationId)
			!= GroupBootstrapJournalLoadResult::Empty) {
		return Fail("bootstrap conflict journal did not initialize empty");
	}
	auto firstTransaction = MakeGroupBootstrapTransaction(
		std::move(*first.prepared),
		identity->credential,
		0);
	auto secondTransaction = MakeGroupBootstrapTransaction(
		std::move(*second.prepared),
		identity->credential,
		0);
	if (journal.prepare(std::move(firstTransaction))
			!= GroupBootstrapJournalCommitResult::Prepared
		|| journal.prepare(std::move(secondTransaction))
			!= GroupBootstrapJournalCommitResult::TransactionConflict) {
		return Fail("bootstrap journal accepted changed exact-retry bytes");
	}
	return 0;
}

} // namespace

int main(int, char *[]) {
	for (const auto scenario : {
		ScenarioPreparesPublicBootstrapOnly,
		ScenarioRejectsAliasedBootstrapObjectIds,
		ScenarioVerifiesObservedPublicBootstrap,
		ScenarioBootstrapTransactionRecoversPartialWrite,
		ScenarioBootstrapJournalRejectsChangedExactRetry,
	}) {
		if (const auto result = scenario()) {
			return result;
		}
	}
	return 0;
}
