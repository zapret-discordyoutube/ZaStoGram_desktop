/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "e2e_cloud/archive/archive_epoch_crypto.h"
#include "e2e_cloud/archive/archived_content_crypto.h"
#include "e2e_cloud/archive/archived_content_outbox.h"
#include "e2e_cloud/archive/history_grant_crypto.h"
#include "e2e_cloud/archive/persistent_archive_state.h"
#include "e2e_cloud/core/envelope_codec.h"
#include "e2e_cloud/identity/openssl_account_crypto.h"
#include "e2e_cloud/mls/openmls_bridge.h"
#include "e2e_cloud/storage/aes_gcm_local_record_protector.h"
#include "e2e_cloud/storage/persistent_outbox.h"

#include <algorithm>
#include <cstdio>
#include <optional>
#include <string_view>
#include <utility>
#include <vector>

namespace {

using namespace E2ECloud;

template <typename Id>
[[nodiscard]] Id FilledId(std::uint8_t value) {
	auto result = Id();
	result.bytes.fill(value);
	return result;
}

template <typename Array>
[[nodiscard]] QByteArray Bytes(const Array &value) {
	return QByteArray(
		reinterpret_cast<const char*>(value.data()),
		int(value.size()));
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
		if (failWrites) {
			return false;
		}
		bytes = value;
		return true;
	}

	std::optional<QByteArray> bytes;
	bool failWrites = false;
};

class UnusedProtector final : public OutboundMessageProtector {
public:
	[[nodiscard]] std::optional<EncodedEnvelope> protectIdempotently(
			const MlsSealRequest &) override {
		++calls;
		return std::nullopt;
	}

	int calls = 0;
};

[[nodiscard]] ArchiveEpochSecret NewEpoch(
		std::uint64_t generation,
		std::uint64_t groupGeneration,
		std::uint8_t eventByte) {
	auto key = std::array<std::uint8_t, kArchiveKeySize>();
	key.fill(std::uint8_t(generation + eventByte));
	return {
		.generation = generation,
		.activationGroupGeneration = groupGeneration,
		.activationEventId = FilledId<ObjectId>(eventByte),
		.key = ArchiveKey32(std::move(key)),
	};
}

[[nodiscard]] int ScenarioContentKeyEnvelope() {
	const auto crypto = ArchiveEpochCrypto();
	auto epochKey = crypto.generateKey();
	auto contentKey = crypto.generateKey();
	if (!epochKey || !contentKey) {
		return Fail("archive key generation failed");
	}
	const auto wrapped = crypto.wrapContentKey(
		FilledId<ConversationId>(1),
		7,
		FilledId<ObjectId>(2),
		FilledId<ObjectId>(3),
		*epochKey,
		*contentKey);
	const auto codec = ArchiveContentKeyEnvelopeCodecV1();
	const auto encoded = wrapped ? codec.encode(*wrapped) : std::nullopt;
	const auto decoded = encoded ? codec.decode(*encoded) : std::nullopt;
	const auto opened = decoded
		? crypto.unwrapContentKey(*epochKey, *decoded)
		: std::nullopt;
	if (!wrapped
		|| !encoded
		|| encoded->size() != kArchiveContentKeyEnvelopeEncodedSize
		|| !decoded
		|| *decoded != *wrapped
		|| !opened
		|| opened->bytes() != contentKey->bytes()) {
		return Fail("archive content key envelope did not round-trip");
	}
	auto tampered = *wrapped;
	tampered.authenticationTag[0] ^= 1;
	if (crypto.unwrapContentKey(*epochKey, tampered)) {
		return Fail("archive content key accepted a modified tag");
	}
	auto wrongKey = crypto.generateKey();
	if (!wrongKey || crypto.unwrapContentKey(*wrongKey, *wrapped)) {
		return Fail("archive content key opened under a wrong epoch key");
	}
	auto trailing = *encoded;
	trailing.append(char(0));
	if (codec.decode(trailing)) {
		return Fail("archive content key codec accepted trailing bytes");
	}
	return 0;
}

[[nodiscard]] int ScenarioHpkeGrantPrimitive() {
	auto identity = GenerateAccountPrivateIdentity();
	if (!identity) {
		return Fail("archive recipient identity generation failed");
	}
	const auto bridge = OpenMlsBridge();
	const auto publicKey = Bytes(identity->credential.archiveHpkePublicKey);
	const auto privateKey = Bytes(identity->archiveHpkePrivateKey.bytes());
	const auto info = QByteArray("TDE2E/archive-grant/v1");
	const auto aad = QByteArray("canonical signed grant header");
	const auto plaintext = QByteArray("epoch-4-key;epoch-5-key");
	const auto first = bridge.hpkeSeal(publicKey, info, aad, plaintext);
	const auto second = bridge.hpkeSeal(publicKey, info, aad, plaintext);
	if (first.status != OpenMlsBridgeStatus::Ok
		|| second.status != OpenMlsBridgeStatus::Ok
		|| first.encapsulatedKey.size() != 32
		|| first.ciphertext.size() != plaintext.size() + 16
		|| first.encapsulatedKey == second.encapsulatedKey
		|| first.ciphertext == second.ciphertext) {
		return Fail("archive HPKE did not use fresh encapsulation");
	}
	const auto opened = bridge.hpkeOpen(
		privateKey,
		first.encapsulatedKey,
		info,
		aad,
		first.ciphertext);
	if (opened.status != OpenMlsBridgeStatus::Ok
		|| opened.plaintext != plaintext) {
		return Fail("archive HPKE grant did not round-trip");
	}
	const auto modified = bridge.hpkeOpen(
		privateKey,
		first.encapsulatedKey,
		info,
		QByteArray("modified grant header"),
		first.ciphertext);
	if (modified.status == OpenMlsBridgeStatus::Ok) {
		return Fail("archive HPKE accepted modified authenticated data");
	}
	return 0;
}

[[nodiscard]] int ScenarioSignedHistoryGrant() {
	auto issuer = GenerateAccountPrivateIdentity();
	auto recipient = GenerateAccountPrivateIdentity();
	const auto sha256 = OpenSslSha256Provider();
	const auto issuerAccountId = issuer
		? DeriveAccountId(issuer->credential, sha256)
		: std::nullopt;
	const auto recipientAccountId = recipient
		? DeriveAccountId(recipient->credential, sha256)
		: std::nullopt;
	if (!issuer
		|| !recipient
		|| !issuerAccountId
		|| !recipientAccountId) {
		return Fail("history grant identities could not be created");
	}
	const auto epochCrypto = ArchiveEpochCrypto();
	auto firstKey = epochCrypto.generateKey();
	auto secondKey = epochCrypto.generateKey();
	if (!firstKey || !secondKey) {
		return Fail("history grant epoch keys could not be created");
	}
	auto epochs = std::vector<ArchiveEpochSecret>();
	epochs.push_back({
		.generation = 4,
		.activationGroupGeneration = 7,
		.activationEventId = FilledId<ObjectId>(31),
		.key = std::move(*firstKey),
	});
	epochs.push_back({
		.generation = 5,
		.activationGroupGeneration = 9,
		.activationEventId = FilledId<ObjectId>(34),
		.key = std::move(*secondKey),
	});
	const auto access = HistoryAccess{
		.mode = HistoryAccessMode::Since,
		.boundaryEventId = FilledId<ObjectId>(31),
	};
	const auto bridge = OpenMlsBridge();
	const auto grant = CreateHistoryGrant({
		.conversationId = FilledId<ConversationId>(30),
		.grantId = FilledId<ObjectId>(32),
		.issuerAccountId = *issuerAccountId,
		.issuerClientId = FilledId<ClientId>(33),
		.recipientAccountId = *recipientAccountId,
		.telegramPeerIdBinding = 42,
		.groupGeneration = 9,
		.historyAccess = access,
		.recipientArchivePublicKey =
			recipient->credential.archiveHpkePublicKey,
		.issuerSigningPrivateKey = &issuer->signingPrivateKey,
		.epochs = &epochs,
	}, bridge);
	const auto codec = EncryptedHistoryGrantCodecV1();
	const auto encoded = grant ? codec.encode(*grant) : std::nullopt;
	const auto decoded = encoded ? codec.decode(*encoded) : std::nullopt;
	auto opened = decoded
		? OpenHistoryGrant(
			*decoded,
			*recipientAccountId,
			recipient->archiveHpkePrivateKey,
			issuer->credential,
			sha256,
			bridge)
		: std::nullopt;
	if (!grant
		|| !encoded
		|| !decoded
		|| *decoded != *grant
		|| !opened
		|| opened->conversationId != grant->conversationId
		|| opened->grantId != grant->grantId
		|| opened->recipientAccountId != *recipientAccountId
		|| opened->historyAccess != access
		|| opened->epochs.size() != 2
		|| opened->epochs[0].generation != 4
		|| opened->epochs[0].key.bytes() != epochs[0].key.bytes()
		|| opened->epochs[1].generation != 5
		|| opened->epochs[1].key.bytes() != epochs[1].key.bytes()) {
		return Fail("signed encrypted history grant did not round-trip");
	}
	auto modifiedCiphertext = *grant;
	modifiedCiphertext.ciphertext[0] ^= 1;
	if (OpenHistoryGrant(
		modifiedCiphertext,
		*recipientAccountId,
		recipient->archiveHpkePrivateKey,
		issuer->credential,
		sha256,
		bridge)) {
		return Fail("history grant accepted modified ciphertext");
	}
	auto modifiedPolicy = *grant;
	modifiedPolicy.historyAccess = {
		.mode = HistoryAccessMode::Full,
		.boundaryEventId = {},
	};
	if (OpenHistoryGrant(
		modifiedPolicy,
		*recipientAccountId,
		recipient->archiveHpkePrivateKey,
		issuer->credential,
		sha256,
		bridge)) {
		return Fail("history grant accepted a modified policy");
	}
	return 0;
}

[[nodiscard]] int ScenarioArchivedContent() {
	auto sender = GenerateAccountPrivateIdentity();
	auto stranger = GenerateAccountPrivateIdentity();
	const auto sha256 = OpenSslSha256Provider();
	const auto senderAccountId = sender
		? DeriveAccountId(sender->credential, sha256)
		: std::nullopt;
	const auto archiveCrypto = ArchiveEpochCrypto();
	auto epochKey = archiveCrypto.generateKey();
	if (!sender || !stranger || !senderAccountId || !epochKey) {
		return Fail("archived content setup failed");
	}
	const auto plaintext = QByteArray("private message body with metadata");
	auto prepared = PrepareArchivedContent({
		.conversationId = FilledId<ConversationId>(71),
		.eventObjectId = FilledId<ObjectId>(72),
		.contentObjectId = FilledId<ObjectId>(73),
		.objectKind = ObjectKind::EncryptedMessageBody,
		.groupGeneration = 9,
		.senderAccountId = *senderAccountId,
		.senderClientId = FilledId<ClientId>(74),
		.archiveEpochGeneration = 5,
		.archiveEpochKey = &*epochKey,
		.senderSigningPrivateKey = &sender->signingPrivateKey,
		.plaintext = plaintext,
	}, archiveCrypto);
	const auto codec = EncryptedArchivedContentCodecV1();
	const auto encoded = prepared
		? codec.encode(prepared->encrypted)
		: std::nullopt;
	const auto decoded = encoded ? codec.decode(*encoded) : std::nullopt;
	const auto liveOpened = decoded && prepared
		? OpenArchivedContentWithContentKey(
			*decoded,
			prepared->contentKey,
			sender->credential,
			sha256)
		: std::nullopt;
	const auto archiveOpened = decoded
		? OpenArchivedContentWithEpochKey(
			*decoded,
			*epochKey,
			sender->credential,
			sha256,
			archiveCrypto)
		: std::nullopt;
	if (!prepared
		|| !encoded
		|| !decoded
		|| *decoded != prepared->encrypted
		|| liveOpened != plaintext
		|| archiveOpened != plaintext) {
		return Fail("archived content did not round-trip");
	}
	auto descriptorKey = prepared->contentKey.bytes();
	auto descriptor = ArchivedContentDescriptor{
		.conversationId = decoded->conversationId,
		.eventObjectId = decoded->eventObjectId,
		.contentObjectId = decoded->contentObjectId,
		.objectKind = decoded->objectKind,
		.groupGeneration = decoded->groupGeneration,
		.archiveEpochGeneration =
			decoded->wrappedContentKey.epochGeneration,
		.encodedContentHash = sha256.digest(*encoded),
		.contentKey = ArchiveKey32(std::move(descriptorKey)),
	};
	const auto descriptorCodec = ArchivedContentDescriptorCodecV1();
	const auto encodedDescriptor = descriptorCodec.encodePlaintext(descriptor);
	auto decodedDescriptor = encodedDescriptor
		? descriptorCodec.decodePlaintext(*encodedDescriptor)
		: std::nullopt;
	if (!encodedDescriptor
		|| encodedDescriptor->size() != kArchivedContentDescriptorEncodedSize
		|| !decodedDescriptor
		|| decodedDescriptor->groupGeneration != 9
		|| decodedDescriptor->encodedContentHash != sha256.digest(*encoded)
		|| decodedDescriptor->contentKey.bytes()
			!= prepared->contentKey.bytes()) {
		return Fail("archived content descriptor did not round-trip");
	}
	if (OpenArchivedContentWithContentKey(
		*decoded,
		prepared->contentKey,
		stranger->credential,
		sha256)) {
		return Fail("archived content accepted a substituted sender identity");
	}
	auto tampered = *decoded;
	tampered.ciphertext[0] ^= 1;
	if (OpenArchivedContentWithEpochKey(
		tampered,
		*epochKey,
		sender->credential,
		sha256,
		archiveCrypto)) {
		return Fail("archived content accepted modified ciphertext");
	}
	return 0;
}

[[nodiscard]] int ScenarioPersistentArchiveState() {
	auto localKey = LocalRecordKey();
	localKey.fill(61);
	const auto protector = AesGcmLocalRecordProtector(std::move(localKey));
	auto blob = MemoryBlobStore();
	const auto conversationId = FilledId<ConversationId>(60);
	auto state = PersistentArchiveState(blob, protector);
	if (state.load(conversationId) != ArchiveStateLoadResult::Missing
		|| state.initialize(NewEpoch(1, 1, 62))
			!= ArchiveStateCommitResult::Committed
		|| state.appendEpoch(state.revision(), NewEpoch(2, 5, 63))
			!= ArchiveStateCommitResult::Committed) {
		return Fail("archive state initialization failed");
	}
	const auto persisted = blob.bytes;
	blob.failWrites = true;
	if (state.appendEpoch(state.revision(), NewEpoch(3, 9, 64))
			!= ArchiveStateCommitResult::PersistenceFailed
		|| state.revision() != 2
		|| state.epochCount() != 2) {
		return Fail("archive state advanced after a failed atomic write");
	}
	blob.failWrites = false;
	blob.bytes = persisted;
	auto restored = PersistentArchiveState(blob, protector);
	if (restored.load(conversationId) != ArchiveStateLoadResult::Loaded
		|| restored.revision() != 2
		|| restored.epochCount() != 2) {
		return Fail("archive state did not survive restart");
	}
	auto full = restored.exportForGrant({
		.mode = HistoryAccessMode::Full,
		.boundaryEventId = {},
	}, 0);
	auto fromJoin = restored.exportForGrant({
		.mode = HistoryAccessMode::FromJoin,
		.boundaryEventId = {},
	}, 5);
	auto since = restored.exportForGrant({
		.mode = HistoryAccessMode::Since,
		.boundaryEventId = FilledId<ObjectId>(63),
	}, 0);
	if (!full
		|| full->size() != 2
		|| !fromJoin
		|| fromJoin->size() != 1
		|| fromJoin->front().generation != 2
		|| !since
		|| since->size() != 1
		|| since->front().generation != 2
		|| restored.exportForGrant({
			.mode = HistoryAccessMode::Since,
			.boundaryEventId = FilledId<ObjectId>(65),
		}, 0)) {
		return Fail("archive state exported an unsafe history boundary");
	}
	auto grant = HistoryGrantPayload{
		.conversationId = conversationId,
		.grantId = FilledId<ObjectId>(66),
		.recipientAccountId = FilledId<AccountId>(67),
		.historyAccess = {
			.mode = HistoryAccessMode::Full,
			.boundaryEventId = {},
		},
		.epochs = {},
	};
	grant.epochs.push_back(NewEpoch(3, 9, 64));
	if (restored.mergeHistoryGrant(restored.revision(), std::move(grant))
			!= ArchiveStateCommitResult::Committed
		|| restored.currentEpoch()->generation != 3) {
		return Fail("archive grant did not merge atomically");
	}
	auto conflicting = HistoryGrantPayload{
		.conversationId = conversationId,
		.grantId = FilledId<ObjectId>(68),
		.recipientAccountId = FilledId<AccountId>(67),
		.historyAccess = {
			.mode = HistoryAccessMode::Full,
			.boundaryEventId = {},
		},
		.epochs = {},
	};
	conflicting.epochs.push_back(NewEpoch(3, 9, 69));
	if (restored.mergeHistoryGrant(restored.revision(), std::move(conflicting))
			!= ArchiveStateCommitResult::EpochConflict
		|| restored.epochCount() != 3) {
		return Fail("archive state accepted a conflicting epoch key");
	}
	auto foreign = PersistentArchiveState(blob, protector);
	if (foreign.load(FilledId<ConversationId>(70))
		!= ArchiveStateLoadResult::AuthenticationFailed) {
		return Fail("archive state was not bound to its conversation");
	}
	return 0;
}

[[nodiscard]] int ScenarioArchivedContentOutboxTransaction() {
	auto sender = GenerateAccountPrivateIdentity();
	const auto sha256 = OpenSslSha256Provider();
	const auto senderAccountId = sender
		? DeriveAccountId(sender->credential, sha256)
		: std::nullopt;
	const auto archiveCrypto = ArchiveEpochCrypto();
	auto epochKey = archiveCrypto.generateKey();
	if (!sender || !senderAccountId || !epochKey) {
		return Fail("archived outbox setup failed");
	}
	auto localKey = LocalRecordKey();
	localKey.fill(81);
	const auto protector = AesGcmLocalRecordProtector(std::move(localKey));
	auto blob = MemoryBlobStore();
	auto store = PersistentOutboxStore(blob, protector);
	const auto conversationId = FilledId<ConversationId>(82);
	auto freshness = FreshnessGate({
		.conversationId = conversationId,
		.generation = 3,
		.stateHash = FilledId<Digest>(83),
	});
	auto unusedProtector = UnusedProtector();
	auto outbox = OutboxCoordinator(freshness, store, unusedProtector);
	const auto envelopeCodec = EnvelopeCodecV1();
	if (store.load() != PersistentOutboxLoadResult::Empty
		|| QueueArchivedContent({
			.conversationId = conversationId,
			.eventObjectId = FilledId<ObjectId>(84),
			.contentObjectId = FilledId<ObjectId>(85),
			.objectKind = ObjectKind::EncryptedMessageBody,
			.senderAccountId = *senderAccountId,
			.senderClientId = FilledId<ClientId>(86),
			.telegramPeerIdBinding = 87,
			.groupGeneration = 3,
			.archiveEpochGeneration = 4,
			.archiveEpochKey = &*epochKey,
			.senderSigningPrivateKey = &sender->signingPrivateKey,
			.plaintext = QByteArray("atomic archived body"),
			.mlsContext = QByteArray("reply context"),
		},
		archiveCrypto,
		EncryptedArchivedContentCodecV1(),
		ArchivedContentDescriptorCodecV1(),
		envelopeCodec,
		sha256,
		outbox) != ArchivedContentQueueResult::Queued
		|| store.size() != 2
		|| store.revision() != 1) {
		return Fail("archived body and MLS descriptor were not queued atomically");
	}
	const auto contentItem = store.front(conversationId);
	const auto contentEnvelope = contentItem && contentItem->sealed
		? envelopeCodec.decode(*contentItem->sealed)
		: std::nullopt;
	if (!contentItem
		|| contentItem->stage != OutboxItemStage::Sealed
		|| !contentEnvelope
		|| contentEnvelope->objectKind != ObjectKind::EncryptedMessageBody
		|| contentEnvelope->epochOrGeneration != 3
		|| contentEnvelope->payloadHash
			!= sha256.digest(contentEnvelope->payload)
		|| unusedProtector.calls) {
		return Fail("archived outbox did not place ciphertext first");
	}
	if (!store.remove(contentItem->draft.objectId)) {
		return Fail("archived outbox could not advance to its MLS descriptor");
	}
	const auto descriptorItem = store.front(conversationId);
	const auto descriptor = descriptorItem
		? ArchivedContentDescriptorCodecV1().decodePlaintext(
			descriptorItem->draft.plaintext)
		: std::nullopt;
	if (!descriptorItem
		|| descriptorItem->stage != OutboxItemStage::Draft
		|| !descriptor
		|| descriptor->contentObjectId != FilledId<ObjectId>(85)
		|| descriptor->groupGeneration != 3
		|| descriptor->encodedContentHash != contentEnvelope->payloadHash
		|| descriptorItem->draft.authenticatedData
			!= QByteArray("reply context")) {
		return Fail("archived outbox lost its MLS content descriptor");
	}
	auto failedBlob = MemoryBlobStore();
	failedBlob.failWrites = true;
	auto failedStore = PersistentOutboxStore(failedBlob, protector);
	auto failedOutbox = OutboxCoordinator(
		freshness,
		failedStore,
		unusedProtector);
	if (failedStore.load() != PersistentOutboxLoadResult::Empty
		|| QueueArchivedContent({
			.conversationId = conversationId,
			.eventObjectId = FilledId<ObjectId>(88),
			.contentObjectId = FilledId<ObjectId>(89),
			.objectKind = ObjectKind::EncryptedMessageBody,
			.senderAccountId = *senderAccountId,
			.senderClientId = FilledId<ClientId>(86),
			.telegramPeerIdBinding = 87,
			.groupGeneration = 3,
			.archiveEpochGeneration = 4,
			.archiveEpochKey = &*epochKey,
			.senderSigningPrivateKey = &sender->signingPrivateKey,
			.plaintext = QByteArray("must not partially queue"),
			.mlsContext = {},
		},
		archiveCrypto,
		EncryptedArchivedContentCodecV1(),
		ArchivedContentDescriptorCodecV1(),
		envelopeCodec,
		sha256,
		failedOutbox) != ArchivedContentQueueResult::PersistenceFailed
		|| failedStore.size()
		|| failedStore.revision()) {
		return Fail("archived outbox exposed a partial failed transaction");
	}
	return 0;
}

} // namespace

int main(int, char *[]) {
	if (const auto result = ScenarioContentKeyEnvelope()) {
		return result;
	} else if (const auto result = ScenarioHpkeGrantPrimitive()) {
		return result;
	} else if (const auto result = ScenarioSignedHistoryGrant()) {
		return result;
	} else if (const auto result = ScenarioArchivedContent()) {
		return result;
	} else if (const auto result = ScenarioPersistentArchiveState()) {
		return result;
	}
	return ScenarioArchivedContentOutboxTransaction();
}
