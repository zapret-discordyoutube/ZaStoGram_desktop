/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "e2e_cloud/core/envelope_codec.h"
#include "e2e_cloud/identity/openssl_account_crypto.h"
#include "e2e_cloud/mls/mls_context_codec.h"
#include "e2e_cloud/mls/mls_roster_codec.h"
#include "e2e_cloud/mls/key_package_lifecycle.h"
#include "e2e_cloud/mls/openmls_application_engine.h"
#include "e2e_cloud/mls/openmls_bridge.h"
#include "e2e_cloud/storage/aes_gcm_local_record_protector.h"
#include "e2e_cloud/storage/persistent_inbound_journal.h"
#include "e2e_cloud/storage/persistent_key_package_pool.h"
#include "e2e_cloud/storage/persistent_mls_state.h"

#include <algorithm>
#include <cstdio>
#include <optional>
#include <string_view>
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

[[nodiscard]] bool Contains(
		const QByteArray &haystack,
		std::string_view needle) {
	const auto first = haystack.constData();
	const auto last = first + haystack.size();
	return std::search(
		first,
		last,
		begin(needle),
		end(needle)) != last;
}

class MemoryBlobStore final : public AtomicBlobStore {
public:
	[[nodiscard]] BlobReadResult read() const override {
		if (readError) {
			return {
				.status = BlobReadStatus::Error,
				.bytes = {},
			};
		} else if (!bytes) {
			return {
				.status = BlobReadStatus::Missing,
				.bytes = {},
			};
		}
		return {
			.status = BlobReadStatus::Found,
			.bytes = *bytes,
		};
	}

	bool writeAtomic(const QByteArray &value) override {
		++writeCount;
		if (writeError || (failOnWrite && writeCount == failOnWrite)) {
			return false;
		}
		bytes = value;
		return true;
	}

	std::optional<QByteArray> bytes;
	bool readError = false;
	bool writeError = false;
	int writeCount = 0;
	int failOnWrite = 0;

};

[[nodiscard]] int ScenarioContextCodec() {
	const auto codec = MlsContextCodecV1();
	const auto credential = MlsClientCredential{
		.conversationId = FilledId<ConversationId>(1),
		.accountId = FilledId<AccountId>(2),
		.clientId = FilledId<ClientId>(3),
	};
	const auto encodedCredential = codec.encodeCredential(credential);
	if (!encodedCredential
		|| encodedCredential->size() != kMlsClientCredentialEncodedSize
		|| codec.decodeCredential(*encodedCredential) != credential) {
		return Fail("MLS client credential did not round-trip");
	}
	auto corruptedCredential = *encodedCredential;
	corruptedCredential[0] ^= 1;
	if (codec.decodeCredential(corruptedCredential)) {
		return Fail("MLS client credential accepted a wrong domain");
	}
	const auto aad = MlsTransportAad{
		.conversationId = credential.conversationId,
		.objectKind = ObjectKind::MlsApplication,
		.senderAccountId = credential.accountId,
		.senderClientId = credential.clientId,
		.telegramPeerIdBinding = 42,
		.objectId = FilledId<ObjectId>(4),
		.context = QByteArray("reply metadata"),
	};
	const auto encodedAad = codec.encodeAad(aad);
	if (!encodedAad
		|| encodedAad->size()
			!= kMlsTransportAadFixedSize + aad.context.size()
		|| codec.decodeAad(*encodedAad) != aad) {
		return Fail("MLS transport AAD did not round-trip");
	}
	auto trailingAad = *encodedAad;
	trailingAad.append(char(0));
	if (codec.decodeAad(trailingAad)) {
		return Fail("MLS transport AAD accepted trailing bytes");
	}
	return 0;
}

[[nodiscard]] int ScenarioTransactionalApplicationSeal() {
	auto localKey = LocalRecordKey();
	localKey.fill(7);
	const auto protector = AesGcmLocalRecordProtector(std::move(localKey));
	auto blob = MemoryBlobStore();
	auto store = PersistentMlsStateStore(blob, protector);
	const auto context = OpenMlsClientContext{
		.conversationId = FilledId<ConversationId>(11),
		.accountId = FilledId<AccountId>(12),
		.clientId = FilledId<ClientId>(13),
		.telegramPeerIdBinding = 123456,
	};
	const auto bridge = OpenMlsBridge();
	const auto contextCodec = MlsContextCodecV1();
	const auto envelopeCodec = EnvelopeCodecV1();
	const auto sha256 = OpenSslSha256Provider();
	if (store.load(context.conversationId) != MlsStateLoadResult::Missing) {
		return Fail("MLS creator store did not load empty");
	}
	const auto initialized = InitializeOpenMlsCreator(
		context,
		bridge,
		contextCodec,
		store);
	if (initialized.status != OpenMlsBootstrapStatus::Initialized
		|| initialized.roster.isEmpty()
		|| store.engineId() != OpenMlsEngineId()
		|| store.revision() != 1) {
		return Fail("OpenMLS creator state was not initialized transactionally");
	}
	const auto rosterCodec = MlsRosterCodecV1();
	const auto creatorRoster = rosterCodec.decode(
		initialized.roster,
		contextCodec);
	auto protectedGroup = ProtectedGroupState::Create({
		.conversationId = context.conversationId,
		.ownerAccountId = context.accountId,
		.ownerClientId = context.clientId,
		.ownerTelegramUserIdBinding = 100,
		.policy = {
			.defaultHistoryAccess = {
				.mode = HistoryAccessMode::FromJoin,
				.boundaryEventId = {},
			},
		},
	});
	if (!creatorRoster
		|| creatorRoster->epoch
		|| creatorRoster->members.size() != 1
		|| creatorRoster->members.front().leafIndex != 0
		|| !protectedGroup
		|| !MlsRosterMatchesGroupState(*creatorRoster, *protectedGroup)) {
		return Fail("OpenMLS creator roster did not match protected clients");
	}
	auto bobKey = LocalRecordKey();
	bobKey.fill(8);
	const auto bobProtector = AesGcmLocalRecordProtector(std::move(bobKey));
	auto bobBlob = MemoryBlobStore();
	auto bobStore = PersistentMlsStateStore(bobBlob, bobProtector);
	const auto bobContext = OpenMlsClientContext{
		.conversationId = context.conversationId,
		.accountId = FilledId<AccountId>(22),
		.clientId = FilledId<ClientId>(23),
		.telegramPeerIdBinding = context.telegramPeerIdBinding,
	};
	const auto bobCredential = contextCodec.encodeCredential({
		.conversationId = bobContext.conversationId,
		.accountId = bobContext.accountId,
		.clientId = bobContext.clientId,
	});
	const auto groupId = QByteArray(
		reinterpret_cast<const char*>(context.conversationId.bytes.data()),
		context.conversationId.bytes.size());
	if (!bobCredential
		|| bobStore.load(context.conversationId)
			!= MlsStateLoadResult::Missing) {
		return Fail("joining MLS client state did not initialize cleanly");
	}
	auto bobPackage = bridge.createKeyPackage(*bobCredential, groupId);
	if (bobPackage.status != OpenMlsBridgeStatus::Ok
		|| bobPackage.state.isEmpty()
		|| bobPackage.keyPackage.isEmpty()
		|| bobStore.initialize(
			OpenMlsEngineId(),
			std::move(bobPackage.state))
			!= MlsStateCommitResult::Committed) {
		return Fail("joining MLS client could not create a KeyPackage");
	}
	const auto addAad = contextCodec.encodeAad({
		.conversationId = context.conversationId,
		.objectKind = ObjectKind::MlsCommit,
		.senderAccountId = context.accountId,
		.senderClientId = context.clientId,
		.telegramPeerIdBinding = context.telegramPeerIdBinding,
		.objectId = FilledId<ObjectId>(24),
		.context = QByteArray("authenticated add transition"),
	});
	if (!addAad) {
		return Fail("MLS add transition AAD was invalid");
	}
	auto added = bridge.addMember(
		store.engineState(),
		bobPackage.keyPackage,
		*addAad);
	if (added.status != OpenMlsBridgeStatus::Ok
		|| added.epoch != 1
		|| added.state.isEmpty()
		|| added.commit.isEmpty()
		|| added.welcome.isEmpty()
		|| store.commit({
			.baseRevision = 1,
			.engineState = std::move(added.state),
			.receipt = std::nullopt,
			.inboundApplication = std::nullopt,
			.removalTombstone = std::nullopt,
		}) != MlsStateCommitResult::Committed) {
		return Fail("MLS creator could not add the joining client");
	}
	const auto addedRoster = rosterCodec.decode(added.roster, contextCodec);
	const auto addTransition = GroupTransition{
		.conversationId = context.conversationId,
		.transitionId = FilledId<ObjectId>(25),
		.previousGeneration = 1,
		.generation = 2,
		.kind = GroupTransitionKind::AddMember,
		.targetAccountId = bobContext.accountId,
		.targetClientId = bobContext.clientId,
		.targetTelegramUserIdBinding = 200,
		.targetRole = GroupRole::Member,
		.targetAdminPermissions = 0,
		.historyAccess = {
			.mode = HistoryAccessMode::FromJoin,
			.boundaryEventId = {},
		},
	};
	if (!addedRoster
		|| addedRoster->epoch != 1
		|| addedRoster->members.size() != 2
		|| protectedGroup->applyVerified(
			addTransition,
			{
				.actor = {
					.accountId = context.accountId,
					.clientId = context.clientId,
				},
				.targetClientAuthorization = VerifiedClientAuthorization{
					.accountId = bobContext.accountId,
					.clientId = bobContext.clientId,
				},
			}) != GroupTransitionResult::Allowed
		|| !MlsRosterMatchesGroupState(*addedRoster, *protectedGroup)) {
		return Fail("OpenMLS admission roster diverged from protected group");
	}
	auto joined = bridge.join(bobStore.engineState(), added.welcome);
	if (joined.status != OpenMlsBridgeStatus::Ok
		|| joined.epoch != 1
		|| joined.state.isEmpty()
		|| joined.roster != added.roster
		|| bobStore.commit({
			.baseRevision = 1,
			.engineState = std::move(joined.state),
			.receipt = std::nullopt,
			.inboundApplication = std::nullopt,
			.removalTombstone = std::nullopt,
		}) != MlsStateCommitResult::Committed) {
		return Fail("joining MLS client could not process its Welcome");
	}
	auto engine = OpenMlsApplicationEngine(
		context,
		bridge,
		contextCodec,
		envelopeCodec,
		sha256,
		store);
	if (!engine.ready()) {
		return Fail("OpenMLS application engine rejected initialized state");
	}
	const auto request = MlsSealRequest{
		.conversationId = context.conversationId,
		.objectId = FilledId<ObjectId>(14),
		.plaintext = QByteArray("secret application body"),
		.authenticatedData = QByteArray("reply metadata"),
	};
	const auto first = engine.protectIdempotently(request);
	if (!first
		|| store.revision() != 3
		|| store.receiptCount() != 1
		|| Contains(first->bytes, "secret application body")) {
		return Fail("MLS application was not sealed and committed atomically");
	}
	const auto envelope = envelopeCodec.decode(*first);
	const auto aad = envelope
		? contextCodec.decodeAad(envelope->authenticationData)
		: std::nullopt;
	if (!envelope
		|| !aad
		|| envelope->conversationId != context.conversationId
		|| envelope->senderAccountId != context.accountId
		|| envelope->senderClientId != context.clientId
		|| envelope->telegramPeerIdBinding != context.telegramPeerIdBinding
		|| envelope->objectId != request.objectId
		|| envelope->payloadHash != sha256.digest(envelope->payload)
		|| aad->conversationId != context.conversationId
		|| aad->senderAccountId != context.accountId
		|| aad->senderClientId != context.clientId
		|| aad->telegramPeerIdBinding != context.telegramPeerIdBinding
		|| aad->objectId != request.objectId
		|| aad->context != request.authenticatedData) {
		return Fail("MLS ciphertext was not bound to its transport context");
	}
	const auto retry = engine.protectIdempotently(request);
	if (retry != first || store.revision() != 3) {
		return Fail("MLS retry did not reuse exact persisted ciphertext");
	}
	auto conflicting = request;
	conflicting.plaintext = QByteArray("different plaintext");
	if (engine.protectIdempotently(conflicting) || store.revision() != 3) {
		return Fail("MLS object identifier accepted conflicting plaintext");
	}
	auto restored = PersistentMlsStateStore(blob, protector);
	if (restored.load(context.conversationId) != MlsStateLoadResult::Loaded) {
		return Fail("MLS application state did not survive restart");
	}
	auto restarted = OpenMlsApplicationEngine(
		context,
		bridge,
		contextCodec,
		envelopeCodec,
		sha256,
		restored);
	if (restarted.protectIdempotently(request) != first
		|| restored.revision() != 3) {
		return Fail("MLS restart regenerated an acknowledged ciphertext");
	}
	const auto stateBeforeFailure = restored.engineState();
	const auto secondRequest = MlsSealRequest{
		.conversationId = context.conversationId,
		.objectId = FilledId<ObjectId>(15),
		.plaintext = QByteArray("second secret body"),
		.authenticatedData = QByteArray(),
	};
	blob.writeError = true;
	if (restarted.protectIdempotently(secondRequest)
		|| restored.engineState() != stateBeforeFailure
		|| restored.revision() != 3) {
		return Fail("failed MLS persistence advanced the live sender ratchet");
	}
	blob.writeError = false;
	if (!restarted.protectIdempotently(secondRequest)
		|| restored.revision() != 4
		|| restored.receiptCount() != 2) {
		return Fail("MLS sender did not recover after a failed atomic write");
	}
	auto journalKey = LocalRecordKey();
	journalKey.fill(9);
	const auto journalProtector = AesGcmLocalRecordProtector(
		std::move(journalKey));
	auto journalBlob = MemoryBlobStore();
	journalBlob.failOnWrite = 2;
	auto journal = PersistentInboundJournal(journalBlob, journalProtector);
	if (journal.load() != InboundJournalLoadResult::Missing) {
		return Fail("MLS inbound journal did not initialize cleanly");
	}
	const auto inboundAuthenticator = OpenMlsEnvelopeAuthenticator(
		contextCodec,
		sha256);
	auto inboundApplier = OpenMlsApplicationInboundApplier(
		bobContext,
		bridge,
		contextCodec,
		sha256,
		bobStore);
	auto inboundProcessor = InboundEnvelopeProcessor(
		context.conversationId,
		context.telegramPeerIdBinding,
		envelopeCodec,
		inboundAuthenticator,
		journal,
		inboundApplier);
	if (inboundProcessor.process(first->bytes)
			!= InboundProcessResult::RecoveryRequired
		|| bobStore.revision() != 3
		|| bobStore.inboundApplicationCount() != 1
		|| journal.lookup(
			context.conversationId,
			request.objectId,
			envelope->payloadHash) != InboundJournalLookup::Pending) {
		return Fail("MLS journal failure lost the atomically decrypted delivery");
	}
	journalBlob.failOnWrite = 0;
	auto bobRestored = PersistentMlsStateStore(bobBlob, bobProtector);
	auto journalRestored = PersistentInboundJournal(
		journalBlob,
		journalProtector);
	if (bobRestored.load(context.conversationId)
			!= MlsStateLoadResult::Loaded
		|| journalRestored.load() != InboundJournalLoadResult::Loaded) {
		return Fail("MLS pending inbound transaction did not survive restart");
	}
	auto inboundApplierRestored = OpenMlsApplicationInboundApplier(
		bobContext,
		bridge,
		contextCodec,
		sha256,
		bobRestored);
	auto inboundProcessorRestored = InboundEnvelopeProcessor(
		context.conversationId,
		context.telegramPeerIdBinding,
		envelopeCodec,
		inboundAuthenticator,
		journalRestored,
		inboundApplierRestored);
	if (inboundProcessorRestored.process(first->bytes)
			!= InboundProcessResult::Accepted
		|| bobRestored.revision() != 3
		|| inboundProcessorRestored.process(first->bytes)
			!= InboundProcessResult::Duplicate
		|| bobRestored.revision() != 3) {
		return Fail("MLS pending journal entry replayed an applied ratchet step");
	}
	const auto delivered = inboundApplierRestored.application(request.objectId);
	if (!delivered
		|| delivered->plaintext != request.plaintext
		|| delivered->context != request.authenticatedData
		|| delivered->senderAccountId != context.accountId
		|| delivered->senderClientId != context.clientId
		|| delivered->senderLeafIndex != 0
		|| delivered->epoch != 1) {
		return Fail("MLS inbound delivery lost authenticated sender metadata");
	}
	auto modifiedHeader = *envelope;
	modifiedHeader.senderAccountId = FilledId<AccountId>(99);
	const auto modifiedEncoded = envelopeCodec.encode(modifiedHeader);
	if (!modifiedEncoded
		|| inboundProcessorRestored.process(modifiedEncoded->bytes)
			!= InboundProcessResult::AuthenticationFailed) {
		return Fail("MLS transport accepted a server-modified sender header");
	}
	if (!inboundApplierRestored.acknowledgeDelivered(request.objectId)
		|| bobRestored.inboundApplicationCount()
		|| bobRestored.revision() != 4) {
		return Fail("MLS decrypted delivery was not durably acknowledged");
	}
	return 0;
}

[[nodiscard]] int ScenarioKeyPackageLifecycleConsumesEveryCandidate() {
	auto localKey = LocalRecordKey();
	localKey.fill(17);
	const auto protector = AesGcmLocalRecordProtector(std::move(localKey));
	const auto bridge = OpenMlsBridge();
	const auto contextCodec = MlsContextCodecV1();
	const auto publicationCodec = ClientKeyPackagePublicationCodecV1();
	const auto envelopeCodec = EnvelopeCodecV1();
	const auto sha256 = OpenSslSha256Provider();
	const auto conversationId = FilledId<ConversationId>(71);
	const auto clientId = FilledId<ClientId>(73);
	const auto peerBinding = std::uint64_t(7400);
	const auto generation = std::uint64_t(5);
	const auto createdAt = std::uint64_t(2'000'000);
	auto identity = GenerateAccountPrivateIdentity();
	const auto accountId = identity
		? DeriveAccountId(identity->credential, sha256)
		: std::nullopt;
	if (!identity || !accountId) {
		return Fail("KeyPackage lifecycle identity setup failed");
	}
	const auto context = OpenMlsClientContext{
		.conversationId = conversationId,
		.accountId = *accountId,
		.clientId = clientId,
		.telegramPeerIdBinding = peerBinding,
	};
	auto first = PrepareClientKeyPackage({
		.client = context,
		.currentGeneration = generation,
		.telegramUserIdBinding = 7401,
		.createdAt = createdAt,
		.accountCredential = &identity->credential,
		.accountSigningPrivateKey = &identity->signingPrivateKey,
	}, bridge, contextCodec, publicationCodec, envelopeCodec, sha256);
	auto second = PrepareClientKeyPackage({
		.client = context,
		.currentGeneration = generation,
		.telegramUserIdBinding = 7401,
		.createdAt = createdAt,
		.accountCredential = &identity->credential,
		.accountSigningPrivateKey = &identity->signingPrivateKey,
	}, bridge, contextCodec, publicationCodec, envelopeCodec, sha256);
	auto poolBlob = MemoryBlobStore();
	auto pool = PersistentKeyPackagePool(
		poolBlob,
		protector,
		envelopeCodec,
		sha256);
	if (first.status != PrepareClientKeyPackageStatus::Prepared
		|| !first.entry
		|| second.status != PrepareClientKeyPackageStatus::Prepared
		|| !second.entry
		|| pool.load(conversationId, peerBinding)
			!= KeyPackagePoolLoadResult::Empty
		|| pool.add(std::move(*first.entry))
			!= KeyPackagePoolMutationResult::Committed
		|| pool.add(std::move(*second.entry))
			!= KeyPackagePoolMutationResult::Committed
		|| pool.entries().size() != 2) {
		return Fail("KeyPackage lifecycle did not retain candidate states");
	}
	const auto firstEnvelope = envelopeCodec.decode(
		pool.entries().front().publicationEnvelope);
	const auto firstPublication = firstEnvelope
		? publicationCodec.decode(firstEnvelope->payload)
		: std::nullopt;
	const auto secondEnvelope = envelopeCodec.decode(
		pool.entries().back().publicationEnvelope);
	const auto secondPublication = secondEnvelope
		? publicationCodec.decode(secondEnvelope->payload)
		: std::nullopt;
	if (!firstPublication || !secondPublication) {
		return Fail("KeyPackage lifecycle lost its public candidate");
	}
	auto mlsBlob = MemoryBlobStore();
	auto mlsState = PersistentMlsStateStore(mlsBlob, protector);
	if (mlsState.load(conversationId) != MlsStateLoadResult::Missing
		|| InstallClientKeyPackageForWelcome(
			firstPublication->keyPackage,
			createdAt,
			bridge,
			sha256,
			pool,
			mlsState) != InstallClientKeyPackageStatus::Installed
		|| InstallClientKeyPackageForWelcome(
			secondPublication->keyPackage,
			createdAt,
			bridge,
			sha256,
			pool,
			mlsState) != InstallClientKeyPackageStatus::Installed
		|| InstallClientKeyPackageForWelcome(
			firstPublication->keyPackage,
			createdAt,
			bridge,
			sha256,
			pool,
			mlsState) != InstallClientKeyPackageStatus::Installed
		|| !bridge.isKeyPackageState(mlsState.engineState())) {
		return Fail("retained KeyPackage candidates were not interchangeable");
	}
	const auto ownerCredential = contextCodec.encodeCredential({
		.conversationId = conversationId,
		.accountId = FilledId<AccountId>(76),
		.clientId = FilledId<ClientId>(77),
	});
	const auto groupIdBytes = QByteArray(
		reinterpret_cast<const char*>(conversationId.bytes.data()),
		int(conversationId.bytes.size()));
	const auto owner = ownerCredential
		? bridge.createGroup(*ownerCredential, groupIdBytes)
		: OpenMlsStateOutput();
	const auto added = owner.status == OpenMlsBridgeStatus::Ok
		? bridge.addMember(
			owner.state,
			firstPublication->keyPackage,
			QByteArray("bound lifecycle admission"))
		: OpenMlsCommitOutput();
	const auto joined = added.status == OpenMlsBridgeStatus::Ok
		? bridge.join(mlsState.engineState(), added.welcome)
		: OpenMlsStateOutput();
	if (joined.status != OpenMlsBridgeStatus::Ok
		|| mlsState.commit({
			.baseRevision = mlsState.revision(),
			.engineState = joined.state,
			.receipt = std::nullopt,
			.inboundApplication = std::nullopt,
			.removalTombstone = std::nullopt,
		}) != MlsStateCommitResult::Committed
		|| FinalizeClientKeyPackageWelcome(
			firstPublication->keyPackage,
			bridge,
			sha256,
			pool,
			mlsState) != FinalizeClientKeyPackageStatus::Finalized
		|| !pool.entries().empty()
		|| bridge.inspectGroup(mlsState.engineState()).status
			!= OpenMlsBridgeStatus::Ok) {
		return Fail("Welcome did not consume all obsolete KeyPackage secrets");
	}
	return 0;
}

} // namespace

int main(int, char *[]) {
	if (const auto result = ScenarioContextCodec()) {
		return result;
	} else if (const auto result
			= ScenarioKeyPackageLifecycleConsumesEveryCandidate()) {
		return result;
	}
	return ScenarioTransactionalApplicationSeal();
}
