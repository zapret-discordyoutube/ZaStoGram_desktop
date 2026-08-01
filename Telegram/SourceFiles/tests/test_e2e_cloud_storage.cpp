/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "e2e_cloud/storage/aes_gcm_local_record_protector.h"
#include "e2e_cloud/storage/local_record_key_derivation.h"
#include "e2e_cloud/storage/persistent_conversation_metadata.h"
#include "e2e_cloud/storage/persistent_content_sync_state.h"
#include "e2e_cloud/storage/persistent_freshness_trust.h"
#include "e2e_cloud/files/persistent_file_transfer.h"
#include "e2e_cloud/files/private_file_manifest.h"
#include "e2e_cloud/core/envelope_codec.h"
#include "e2e_cloud/group/signed_group_transition.h"
#include "e2e_cloud/identity/openssl_account_crypto.h"
#include "e2e_cloud/mls/client_key_package.h"
#include "e2e_cloud/mls/mls_outbox_reconciler.h"
#include "e2e_cloud/mls/observed_key_package.h"
#include "e2e_cloud/storage/persistent_inbound_journal.h"
#include "e2e_cloud/storage/persistent_key_package_pool.h"
#include "e2e_cloud/storage/persistent_mls_state.h"
#include "e2e_cloud/storage/persistent_outbox.h"

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
		if (writeError) {
			return false;
		}
		bytes = value;
		return true;
	}

	std::optional<QByteArray> bytes;
	bool readError = false;
	bool writeError = false;

};

[[nodiscard]] PendingMessage Message() {
	return {
		.conversationId = FilledId<ConversationId>(1),
		.objectId = FilledId<ObjectId>(2),
		.plaintext = QByteArray("private draft"),
		.authenticatedData = QByteArray("metadata"),
	};
}

[[nodiscard]] TransportEnvelope Envelope() {
	return {
		.conversationId = FilledId<ConversationId>(1),
		.objectKind = ObjectKind::MlsApplication,
		.senderAccountId = FilledId<AccountId>(2),
		.senderClientId = FilledId<ClientId>(3),
		.telegramPeerIdBinding = 42,
		.epochOrGeneration = 7,
		.objectId = FilledId<ObjectId>(4),
		.payloadHash = FilledId<Digest>(5),
		.payload = QByteArray("payload"),
		.authenticationData = QByteArray("authentication"),
	};
}

[[nodiscard]] MlsOperationReceipt MlsReceipt() {
	return {
		.objectId = FilledId<ObjectId>(13),
		.requestHash = FilledId<Digest>(14),
		.envelope = {
			.conversationId = FilledId<ConversationId>(12),
			.objectId = FilledId<ObjectId>(13),
			.bytes = QByteArray("exact MLS ciphertext"),
		},
	};
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

[[nodiscard]] int ScenarioAeadProtection() {
	auto key = LocalRecordKey();
	key.fill(7);
	const auto protector = AesGcmLocalRecordProtector(std::move(key));
	const auto purpose = QByteArray("test-purpose");
	const auto plaintext = QByteArray("protected value");
	const auto first = protector.seal(purpose, plaintext);
	const auto second = protector.seal(purpose, plaintext);
	if (std::any_of(begin(key), end(key), [](std::uint8_t byte) {
			return byte != 0;
		})
		|| !first
		|| !second
		|| first == second
		|| Contains(*first, "protected value")
		|| protector.open(purpose, *first) != plaintext
		|| protector.open(QByteArray("wrong-purpose"), *first)) {
		return Fail("local AEAD did not bind nonce, purpose, and plaintext");
	}
	auto tampered = *first;
	tampered[tampered.size() - 1] ^= 1;
	if (protector.open(purpose, tampered)) {
		return Fail("local AEAD accepted a modified authentication tag");
	}
	auto emptyKey = LocalRecordKey();
	const auto invalid = AesGcmLocalRecordProtector(std::move(emptyKey));
	if (invalid.seal(purpose, plaintext)) {
		return Fail("local AEAD accepted an empty record key");
	}
	return 0;
}

[[nodiscard]] int ScenarioConversationRecordKeyDerivation() {
	auto masterBytes = std::array<std::uint8_t, 32>();
	masterBytes.fill(11);
	const auto masterKey = SecureKey32(std::move(masterBytes));
	const auto first = DeriveConversationLocalRecordKey(
		masterKey,
		42,
		FilledId<ConversationId>(1));
	const auto retry = DeriveConversationLocalRecordKey(
		masterKey,
		42,
		FilledId<ConversationId>(1));
	const auto otherConversation = DeriveConversationLocalRecordKey(
		masterKey,
		42,
		FilledId<ConversationId>(2));
	const auto otherAccount = DeriveConversationLocalRecordKey(
		masterKey,
		43,
		FilledId<ConversationId>(1));
	if (!first
		|| first != retry
		|| first == otherConversation
		|| first == otherAccount
		|| DeriveConversationLocalRecordKey(
			masterKey,
			0,
			FilledId<ConversationId>(1))
		|| DeriveConversationLocalRecordKey(
			masterKey,
			42,
			ConversationId())) {
		return Fail("local record keys were not domain-separated");
	}
	return 0;
}

[[nodiscard]] int ScenarioContentSyncBoundarySurvivesRestart() {
	auto key = LocalRecordKey();
	key.fill(31);
	const auto protector = AesGcmLocalRecordProtector(std::move(key));
	auto blob = MemoryBlobStore();
	auto state = PersistentContentSyncState(blob, protector);
	const auto conversationId = FilledId<ConversationId>(32);
	if (state.load(conversationId) != ContentSyncStateLoadResult::Missing
		|| state.advance(100) != ContentSyncStateCommitResult::Committed
		|| state.advance(99)
			!= ContentSyncStateCommitResult::InvalidBoundary
		|| state.advance(100)
			!= ContentSyncStateCommitResult::AlreadyCommitted) {
		return Fail("content synchronization boundary was not monotonic");
	}
	auto restored = PersistentContentSyncState(blob, protector);
	if (restored.load(conversationId)
			!= ContentSyncStateLoadResult::Loaded
		|| restored.newestObservedMessageId() != 100
		|| restored.revision() != 1
		|| restored.advance(150)
			!= ContentSyncStateCommitResult::Committed) {
		return Fail("content synchronization boundary did not survive restart");
	}
	auto tampered = *blob.bytes;
	tampered[tampered.size() - 1] ^= 1;
	blob.bytes = tampered;
	auto damaged = PersistentContentSyncState(blob, protector);
	if (damaged.load(conversationId)
			!= ContentSyncStateLoadResult::AuthenticationFailed) {
		return Fail("content synchronization boundary accepted tampering");
	}
	return 0;
}

[[nodiscard]] int ScenarioFileTransferSurvivesRestart() {
	auto localKey = LocalRecordKey();
	localKey.fill(33);
	const auto protector = AesGcmLocalRecordProtector(std::move(localKey));
	auto fileKey = std::array<std::uint8_t, 32>();
	fileKey.fill(34);
	auto context = FileChunkContext{
		.conversationId = FilledId<ConversationId>(35),
		.fileId = FilledId<FileId>(36),
		.plaintextSize = 13,
		.chunkSize = 64 * 1024,
		.chunkCount = 1,
		.noncePrefix = {},
	};
	context.noncePrefix.fill(37);
	const auto manifest = PrivateFileManifestCodecV1().encodePlaintext({
		.context = context,
		.key = FileEncryptionKey(std::move(fileKey)),
		.plaintextHash = FilledId<Digest>(38),
		.unixTime = 1'725'000'000,
		.filenameUtf8 = QByteArray("backup.any"),
		.mimeTypeUtf8 = QByteArray("application/octet-stream"),
	});
	auto blob = MemoryBlobStore();
	auto transfer = PersistentFileTransfer(blob, protector);
	if (!manifest
		|| transfer.load(context.conversationId)
			!= FileTransferLoadResult::Empty
		|| transfer.begin({
			.conversationId = context.conversationId,
			.eventObjectId = FilledId<ObjectId>(39),
			.contentObjectId = FilledId<ObjectId>(40),
			.groupGeneration = 7,
			.nextChunkIndex = 0,
			.sourcePathUtf8 = QByteArray("/private/source.any"),
			.manifestPlaintext = manifest.value_or(QByteArray()),
		}) != FileTransferCommitResult::Committed
		|| transfer.advance(0) != FileTransferCommitResult::Committed) {
		return Fail("resumable file transfer was not persisted");
	}
	auto restored = PersistentFileTransfer(blob, protector);
	const auto restoredLoad = restored.load(context.conversationId);
	if (restoredLoad == FileTransferLoadResult::AuthenticationFailed) {
		return Fail("resumable file transfer snapshot authentication failed");
	} else if (restoredLoad == FileTransferLoadResult::InvalidSnapshot) {
		return Fail("resumable file transfer snapshot was invalid");
	} else if (restoredLoad != FileTransferLoadResult::Loaded) {
		return Fail("resumable file transfer snapshot did not load");
	} else if (!restored.pending()
		|| restored.pending()->nextChunkIndex != 1) {
		return Fail("resumable file transfer did not restore its chunk cursor");
	}
	auto replacementContext = context;
	replacementContext.fileId = FilledId<FileId>(41);
	auto replacementKey = std::array<std::uint8_t, 32>();
	replacementKey.fill(42);
	const auto replacementManifest = PrivateFileManifestCodecV1()
		.encodePlaintext({
			.context = replacementContext,
			.key = FileEncryptionKey(std::move(replacementKey)),
			.plaintextHash = FilledId<Digest>(43),
			.unixTime = 1'725'000'001,
			.filenameUtf8 = QByteArray("replacement.any"),
			.mimeTypeUtf8 = QByteArray("application/octet-stream"),
		});
	const auto replacement = PendingFileTransfer{
		.conversationId = context.conversationId,
		.eventObjectId = FilledId<ObjectId>(44),
		.contentObjectId = FilledId<ObjectId>(45),
		.groupGeneration = 8,
		.nextChunkIndex = 0,
		.sourcePathUtf8 = QByteArray("/private/replacement.any"),
		.manifestPlaintext = replacementManifest.value_or(QByteArray()),
	};
	blob.writeError = true;
	if (!replacementManifest
		|| restored.replace(replacement)
			!= FileTransferCommitResult::PersistenceFailed
		|| !restored.pending()
		|| restored.pending()->eventObjectId != FilledId<ObjectId>(39)) {
		return Fail("failed file transfer replacement changed pending state");
	}
	blob.writeError = false;
	if (restored.replace(replacement) != FileTransferCommitResult::Committed
		|| !restored.pending()
		|| restored.pending()->eventObjectId != replacement.eventObjectId
		|| restored.revision() != 3) {
		return Fail("file transfer could not be replaced atomically");
	}
	auto replaced = PersistentFileTransfer(blob, protector);
	if (replaced.load(context.conversationId)
			!= FileTransferLoadResult::Loaded
		|| !replaced.pending()
		|| replaced.pending()->sourcePathUtf8
			!= replacement.sourcePathUtf8
		|| replaced.clear() != FileTransferCommitResult::Committed) {
		return Fail("resumable file transfer could not be cleared");
	}
	auto completed = PersistentFileTransfer(blob, protector);
	if (completed.load(context.conversationId)
			!= FileTransferLoadResult::Empty
		|| completed.pending()) {
		return Fail("completed file transfer reappeared after restart");
	}
	return 0;
}

[[nodiscard]] int ScenarioPersistentDraftRoundTrip() {
	auto key = LocalRecordKey();
	key.fill(8);
	const auto protector = AesGcmLocalRecordProtector(std::move(key));
	auto blob = MemoryBlobStore();
	auto store = PersistentOutboxStore(blob, protector);
	if (store.load() != PersistentOutboxLoadResult::Empty
		|| !store.loaded()
		|| store.size()
		|| store.revision()) {
		return Fail("empty protected outbox did not initialize cleanly");
	}
	blob.writeError = true;
	if (store.append(Message()) || store.size() || store.revision()) {
		return Fail("failed atomic write changed the in-memory outbox");
	}
	blob.writeError = false;
	if (!store.append(Message())
		|| store.size() != 1
		|| store.revision() != 1
		|| !blob.bytes
		|| Contains(*blob.bytes, "private draft")) {
		return Fail("protected draft was not atomically encrypted at rest");
	}
	auto restored = PersistentOutboxStore(blob, protector);
	const auto loaded = restored.load();
	const auto item = restored.front(FilledId<ConversationId>(1));
	if (loaded != PersistentOutboxLoadResult::Loaded
		|| !item
		|| item->stage != OutboxItemStage::Draft
		|| item->draft.plaintext != QByteArray("private draft")
		|| restored.revision() != 1) {
		return Fail("protected draft did not survive authenticated reload");
	}
	return 0;
}

[[nodiscard]] int ScenarioConversationMetadataRoundTrip() {
	auto key = LocalRecordKey();
	key.fill(12);
	const auto protector = AesGcmLocalRecordProtector(std::move(key));
	auto blob = MemoryBlobStore();
	auto store = PersistentConversationMetadata(blob, protector);
	const auto metadata = ConversationLocalMetadata{
		.conversationId = FilledId<ConversationId>(31),
		.telegramPeerIdBinding = 32,
		.accountId = FilledId<AccountId>(33),
		.clientId = FilledId<ClientId>(34),
	};
	if (store.load(metadata.conversationId)
			!= ConversationMetadataLoadResult::Missing
		|| store.initialize(metadata)
			!= ConversationMetadataCommitResult::Committed
		|| !blob.bytes) {
		return Fail("conversation metadata did not persist");
	}
	auto restored = PersistentConversationMetadata(blob, protector);
	if (restored.load(metadata.conversationId)
			!= ConversationMetadataLoadResult::Loaded
		|| !restored.metadata()
		|| *restored.metadata() != metadata
		|| restored.revision() != 1
		|| restored.initialize(metadata)
			!= ConversationMetadataCommitResult::AlreadyCommitted) {
		return Fail("conversation metadata did not round-trip exactly");
	}
	auto conflicting = metadata;
	conflicting.clientId = FilledId<ClientId>(35);
	if (restored.initialize(conflicting)
			!= ConversationMetadataCommitResult::Conflict) {
		return Fail("conversation metadata accepted a client identity conflict");
	}
	return 0;
}

[[nodiscard]] int ScenarioFreshnessTrustSurvivesRestart() {
	auto key = LocalRecordKey();
	key.fill(36);
	const auto protector = AesGcmLocalRecordProtector(std::move(key));
	auto blob = MemoryBlobStore();
	const auto conversationId = FilledId<ConversationId>(37);
	auto store = PersistentFreshnessTrust(blob, protector);
	if (store.load(conversationId) != FreshnessTrustLoadResult::Missing
		|| store.initialize(false) != FreshnessTrustCommitResult::Committed
		|| store.trusted()
		|| store.confirm() != FreshnessTrustCommitResult::Committed
		|| !store.trusted()) {
		return Fail("freshness trust did not commit monotonically");
	}
	auto restored = PersistentFreshnessTrust(blob, protector);
	if (restored.load(conversationId) != FreshnessTrustLoadResult::Loaded
		|| !restored.trusted()
		|| restored.confirm()
			!= FreshnessTrustCommitResult::AlreadyCommitted) {
		return Fail("freshness trust did not survive restart");
	}
	return 0;
}

[[nodiscard]] int ScenarioSealedRetrySurvivesRestart() {
	auto key = LocalRecordKey();
	key.fill(9);
	const auto protector = AesGcmLocalRecordProtector(std::move(key));
	auto blob = MemoryBlobStore();
	auto store = PersistentOutboxStore(blob, protector);
	if (store.load() != PersistentOutboxLoadResult::Empty
		|| !store.append(Message())) {
		return Fail("protected outbox setup failed");
	}
	const auto sealed = EncodedEnvelope{
		.conversationId = FilledId<ConversationId>(1),
		.objectId = FilledId<ObjectId>(2),
		.bytes = QByteArray("opaque ciphertext"),
	};
	if (!store.replaceWithSealed(sealed.objectId, sealed)
		|| store.revision() != 2) {
		return Fail("sealed envelope was not persisted for exact retry");
	}
	auto restored = PersistentOutboxStore(blob, protector);
	const auto loaded = restored.load();
	const auto item = restored.front(sealed.conversationId);
	if (loaded != PersistentOutboxLoadResult::Loaded
		|| !item
		|| item->stage != OutboxItemStage::Sealed
		|| item->sealed != sealed
		|| !item->draft.plaintext.isEmpty()
		|| !item->draft.authenticatedData.isEmpty()) {
		return Fail("sealed retry regenerated or retained plaintext after restart");
	}
	if (!restored.remove(sealed.objectId)
		|| restored.size()
		|| restored.revision() != 3) {
		return Fail("uploaded protected outbox item was not atomically removed");
	}
	return 0;
}

[[nodiscard]] int ScenarioCorruptionFailsClosed() {
	auto key = LocalRecordKey();
	key.fill(10);
	const auto protector = AesGcmLocalRecordProtector(std::move(key));
	auto blob = MemoryBlobStore();
	auto store = PersistentOutboxStore(blob, protector);
	if (store.load() != PersistentOutboxLoadResult::Empty
		|| !store.append(Message())
		|| !blob.bytes) {
		return Fail("protected outbox setup failed");
	}
	(*blob.bytes)[blob.bytes->size() - 1] ^= 1;
	auto corrupted = PersistentOutboxStore(blob, protector);
	if (corrupted.load()
			!= PersistentOutboxLoadResult::AuthenticationFailed
		|| corrupted.loaded()
		|| corrupted.size()) {
		return Fail("corrupted protected outbox did not fail closed");
	}
	return 0;
}

[[nodiscard]] int ScenarioMlsStateTransaction() {
	auto key = LocalRecordKey();
	key.fill(15);
	const auto protector = AesGcmLocalRecordProtector(std::move(key));
	auto blob = MemoryBlobStore();
	auto store = PersistentMlsStateStore(blob, protector);
	const auto conversationId = FilledId<ConversationId>(12);
	if (store.load(conversationId) != MlsStateLoadResult::Missing
		|| !store.loaded()
		|| store.revision()) {
		return Fail("missing MLS state did not initialize cleanly");
	}
	blob.writeError = true;
	if (store.initialize(
			QByteArray("openmls-0.8.1-0e99bc88-rustcrypto-v1"),
			QByteArray("initial secret state"))
			!= MlsStateCommitResult::PersistenceFailed
		|| store.revision()
		|| !store.engineState().isEmpty()) {
		return Fail("failed MLS initialization changed live state");
	}
	blob.writeError = false;
	if (store.initialize(
			QByteArray("openmls-0.8.1-0e99bc88-rustcrypto-v1"),
			QByteArray("initial secret state"))
			!= MlsStateCommitResult::Committed
		|| store.revision() != 1
		|| !blob.bytes
		|| Contains(*blob.bytes, "initial secret state")) {
		return Fail("MLS state was not atomically protected");
	}
	auto receipt = MlsReceipt();
	receipt.envelope.conversationId = conversationId;
	if (store.commit({
			.baseRevision = 1,
			.engineState = QByteArray("advanced secret state"),
			.receipt = receipt,
			.inboundApplication = std::nullopt,
			.removalTombstone = std::nullopt,
		}) != MlsStateCommitResult::Committed
		|| store.revision() != 2
		|| store.engineState() != QByteArray("advanced secret state")
		|| store.receipt(receipt.objectId) != receipt) {
		return Fail("MLS state and ciphertext receipt were not one commit");
	}
	if (store.commit({
			.baseRevision = 1,
			.engineState = QByteArray("discarded retry state"),
			.receipt = receipt,
			.inboundApplication = std::nullopt,
			.removalTombstone = std::nullopt,
		}) != MlsStateCommitResult::AlreadyCommitted
		|| store.revision() != 2
		|| store.engineState() != QByteArray("advanced secret state")) {
		return Fail("MLS exact retry was not idempotent");
	}
	auto conflicting = receipt;
	conflicting.envelope.bytes = QByteArray("different ciphertext");
	if (store.commit({
			.baseRevision = 2,
			.engineState = QByteArray("conflicting state"),
			.receipt = conflicting,
			.inboundApplication = std::nullopt,
			.removalTombstone = std::nullopt,
		}) != MlsStateCommitResult::InvalidMutation
		|| store.revision() != 2) {
		return Fail("MLS operation identifier accepted conflicting ciphertext");
	}
	blob.writeError = true;
	if (store.commit({
			.baseRevision = 2,
			.engineState = QByteArray("uncommitted secret state"),
			.receipt = std::nullopt,
			.inboundApplication = std::nullopt,
			.removalTombstone = std::nullopt,
		}) != MlsStateCommitResult::PersistenceFailed
		|| store.engineState() != QByteArray("advanced secret state")
		|| store.revision() != 2) {
		return Fail("failed MLS state write changed live ratchet state");
	}
	blob.writeError = false;
	auto restored = PersistentMlsStateStore(blob, protector);
	if (restored.load(conversationId) != MlsStateLoadResult::Loaded
		|| restored.engineId()
			!= QByteArray("openmls-0.8.1-0e99bc88-rustcrypto-v1")
		|| restored.engineState() != QByteArray("advanced secret state")
		|| restored.receipt(receipt.objectId) != receipt
		|| !restored.acknowledgeReceipt(receipt.objectId)
		|| restored.receiptCount()
		|| restored.revision() != 3) {
		return Fail("MLS transaction did not survive restart and acknowledgement");
	}
	const auto tombstone = MlsRemovalTombstone{
		.transitionId = FilledId<ObjectId>(61),
		.generation = 9,
		.resultingStateHash = FilledId<Digest>(62),
		.mlsCommitHash = FilledId<Digest>(63),
		.removedAccountId = FilledId<AccountId>(64),
		.removedClientId = FilledId<ClientId>(65),
	};
	if (restored.commit({
			.baseRevision = restored.revision(),
			.engineState = {},
			.receipt = std::nullopt,
			.inboundApplication = std::nullopt,
			.removalTombstone = tombstone,
		}) != MlsStateCommitResult::Committed
		|| !restored.removed()
		|| restored.removalTombstone() != tombstone
		|| !restored.engineState().isEmpty()
		|| restored.receiptCount()
		|| restored.inboundApplicationCount()) {
		return Fail("MLS removal tombstone did not replace active state");
	}
	auto removed = PersistentMlsStateStore(blob, protector);
	if (removed.load(conversationId) != MlsStateLoadResult::Loaded
		|| !removed.removed()
		|| removed.removalTombstone() != tombstone
		|| removed.commit({
			.baseRevision = removed.revision(),
			.engineState = QByteArray("must not reactivate implicitly"),
			.receipt = std::nullopt,
			.inboundApplication = std::nullopt,
			.removalTombstone = std::nullopt,
		}) != MlsStateCommitResult::InvalidMutation
		|| removed.replaceRemovedWithKeyPackage(
			removed.revision(),
			QByteArray("fresh KeyPackage state"))
			!= MlsStateCommitResult::Committed
		|| removed.removed()
		|| removed.engineState() != QByteArray("fresh KeyPackage state")) {
		return Fail("MLS tombstone re-admission path failed closed");
	}
	return 0;
}

[[nodiscard]] int ScenarioMlsStateBindingAndCorruption() {
	auto key = LocalRecordKey();
	key.fill(16);
	const auto protector = AesGcmLocalRecordProtector(std::move(key));
	auto blob = MemoryBlobStore();
	const auto conversationId = FilledId<ConversationId>(17);
	auto store = PersistentMlsStateStore(blob, protector);
	if (store.load(conversationId) != MlsStateLoadResult::Missing
		|| store.initialize(
			QByteArray("openmls-0.8.1-0e99bc88-rustcrypto-v1"),
			QByteArray("bound state"))
			!= MlsStateCommitResult::Committed
		|| !blob.bytes) {
		return Fail("MLS binding test setup failed");
	}
	auto swapped = PersistentMlsStateStore(blob, protector);
	if (swapped.load(FilledId<ConversationId>(18))
			!= MlsStateLoadResult::AuthenticationFailed) {
		return Fail("MLS state could be swapped between conversations");
	}
	(*blob.bytes)[blob.bytes->size() - 1] ^= 1;
	auto corrupted = PersistentMlsStateStore(blob, protector);
	if (corrupted.load(conversationId)
			!= MlsStateLoadResult::AuthenticationFailed
		|| corrupted.loaded()
		|| corrupted.revision()) {
		return Fail("corrupted MLS state did not fail closed");
	}
	return 0;
}

[[nodiscard]] int ScenarioMlsReceiptOutboxReconciliation() {
	auto key = LocalRecordKey();
	key.fill(19);
	const auto protector = AesGcmLocalRecordProtector(std::move(key));
	auto mlsBlob = MemoryBlobStore();
	auto outboxBlob = MemoryBlobStore();
	auto mls = PersistentMlsStateStore(mlsBlob, protector);
	auto outbox = PersistentOutboxStore(outboxBlob, protector);
	const auto conversationId = FilledId<ConversationId>(20);
	auto receipt = MlsReceipt();
	receipt.envelope.conversationId = conversationId;
	if (mls.load(conversationId) != MlsStateLoadResult::Missing
		|| mls.initialize(
			QByteArray("openmls-0.8.1-0e99bc88-rustcrypto-v1"),
			QByteArray("reconcile state"))
			!= MlsStateCommitResult::Committed
		|| mls.commit({
			.baseRevision = mls.revision(),
			.engineState = QByteArray("reconcile advanced state"),
			.receipt = receipt,
			.inboundApplication = std::nullopt,
			.removalTombstone = std::nullopt,
		}) != MlsStateCommitResult::Committed
		|| outbox.load() != PersistentOutboxLoadResult::Empty
		|| !outbox.append({
			.conversationId = conversationId,
			.objectId = receipt.objectId,
			.plaintext = QByteArray("descriptor"),
			.authenticatedData = {},
		})) {
		return Fail("MLS receipt reconciliation setup failed");
	}
	if (ReconcileMlsOutboxReceipts(mls, outbox)
			!= MlsReceiptReconcileResult::NothingToDo
		|| mls.receiptCount() != 1
		|| !outbox.remove(receipt.objectId)
		|| ReconcileMlsOutboxReceipts(mls, outbox)
			!= MlsReceiptReconcileResult::Reconciled
		|| mls.receiptCount()) {
		return Fail("MLS receipt was not tied to durable outbox delivery");
	}
	return 0;
}

[[nodiscard]] int ScenarioInboundJournalSurvivesRestart() {
	auto key = LocalRecordKey();
	key.fill(11);
	const auto protector = AesGcmLocalRecordProtector(std::move(key));
	auto blob = MemoryBlobStore();
	auto journal = PersistentInboundJournal(blob, protector);
	const auto envelope = Envelope();
	if (journal.load() != InboundJournalLoadResult::Missing
		|| journal.lookup(
			envelope.conversationId,
			envelope.objectId,
			envelope.payloadHash) != InboundJournalLookup::Missing
		|| !journal.begin(envelope)
		|| journal.revision() != 1
		|| journal.lookup(
			envelope.conversationId,
			envelope.objectId,
			envelope.payloadHash) != InboundJournalLookup::Pending) {
		return Fail("inbound journal did not persist its pending phase");
	}
	auto pending = PersistentInboundJournal(blob, protector);
	if (pending.load() != InboundJournalLoadResult::Loaded
		|| pending.lookup(
			envelope.conversationId,
			envelope.objectId,
			envelope.payloadHash) != InboundJournalLookup::Pending
		|| !pending.accept(envelope.conversationId, envelope.objectId)
		|| pending.revision() != 2) {
		return Fail("inbound journal lost pending crash recovery state");
	}
	auto accepted = PersistentInboundJournal(blob, protector);
	if (accepted.load() != InboundJournalLoadResult::Loaded
		|| accepted.lookup(
			envelope.conversationId,
			envelope.objectId,
			envelope.payloadHash) != InboundJournalLookup::Accepted
		|| accepted.lookup(
			envelope.conversationId,
			envelope.objectId,
			FilledId<Digest>(9))
			!= InboundJournalLookup::ObjectIdConflict) {
		return Fail("inbound journal did not retain accepted replay state");
	}
	return 0;
}

[[nodiscard]] int ScenarioInboundJournalWriteFailureIsTransactional() {
	auto key = LocalRecordKey();
	key.fill(12);
	const auto protector = AesGcmLocalRecordProtector(std::move(key));
	auto blob = MemoryBlobStore();
	auto journal = PersistentInboundJournal(blob, protector);
	const auto envelope = Envelope();
	if (journal.load() != InboundJournalLoadResult::Missing) {
		return Fail("inbound journal setup failed");
	}
	blob.writeError = true;
	if (journal.begin(envelope)
		|| journal.size()
		|| journal.revision()
		|| journal.lookup(
			envelope.conversationId,
			envelope.objectId,
			envelope.payloadHash) != InboundJournalLookup::Missing) {
		return Fail("failed inbound journal write changed live state");
	}
	blob.writeError = false;
	if (!journal.begin(envelope)) {
		return Fail("transient inbound journal write failure poisoned storage");
	}
	return 0;
}

[[nodiscard]] int ScenarioInboundJournalCorruptionFailsClosed() {
	auto key = LocalRecordKey();
	key.fill(13);
	const auto protector = AesGcmLocalRecordProtector(std::move(key));
	auto blob = MemoryBlobStore();
	auto journal = PersistentInboundJournal(blob, protector);
	if (journal.load() != InboundJournalLoadResult::Missing
		|| !journal.begin(Envelope())
		|| !blob.bytes) {
		return Fail("inbound journal corruption setup failed");
	}
	(*blob.bytes)[blob.bytes->size() - 1] ^= 1;
	auto corrupted = PersistentInboundJournal(blob, protector);
	if (corrupted.load()
			!= InboundJournalLoadResult::AuthenticationFailed
		|| corrupted.lookup(
			FilledId<ConversationId>(1),
			FilledId<ObjectId>(4),
			FilledId<Digest>(5)) != InboundJournalLookup::StorageError) {
		return Fail("corrupted inbound journal did not fail closed");
	}
	return 0;
}

[[nodiscard]] int ScenarioKeyPackagePoolRetainsReplacementSecrets() {
	auto key = LocalRecordKey();
	key.fill(15);
	const auto protector = AesGcmLocalRecordProtector(std::move(key));
	const auto envelopeCodec = EnvelopeCodecV1();
	const auto sha256 = OpenSslSha256Provider();
	const auto conversationId = FilledId<ConversationId>(61);
	const auto clientId = FilledId<ClientId>(62);
	const auto peerBinding = std::uint64_t(63);
	const auto generation = std::uint64_t(7);
	const auto createdAt = std::uint64_t(1'000'000);
	auto identity = GenerateAccountPrivateIdentity();
	const auto accountId = identity
		? DeriveAccountId(identity->credential, sha256)
		: std::nullopt;
	if (!identity || !accountId) {
		return Fail("KeyPackage pool identity setup failed");
	}
	const auto makeEntry = [&](std::uint8_t id, const char *package) {
		const auto objectId = FilledId<ObjectId>(id);
		const auto keyPackage = QByteArray(package);
		const auto authorization = CreateClientAuthorizationProof({
			.conversationId = conversationId,
			.authorizationId = objectId,
			.accountId = *accountId,
			.clientId = clientId,
			.requestedAfterGeneration = generation,
			.createdAt = createdAt,
			.accountCredential = &identity->credential,
			.accountSigningPrivateKey = &identity->signingPrivateKey,
			.keyPackage = keyPackage,
		}, sha256);
		const auto payload = authorization
			? ClientKeyPackagePublicationCodecV1().encode({
				.accountCredential = identity->credential,
				.authorization = *authorization,
				.keyPackage = keyPackage,
			})
			: std::nullopt;
		const auto signature = authorization
			? QByteArray(
				reinterpret_cast<const char*>(
					authorization->signature.data()),
				int(authorization->signature.size()))
			: QByteArray();
		const auto envelope = payload
			? envelopeCodec.encode({
				.conversationId = conversationId,
				.objectKind = ObjectKind::ClientKeyPackage,
				.senderAccountId = *accountId,
				.senderClientId = clientId,
				.telegramPeerIdBinding = peerBinding,
				.epochOrGeneration = generation,
				.objectId = objectId,
				.payloadHash = sha256.digest(*payload),
				.payload = *payload,
				.authenticationData = signature,
			})
			: std::nullopt;
		return envelope
			? std::optional<StoredClientKeyPackage>({
				.keyPackageHash = sha256.digest(keyPackage),
				.createdAt = createdAt,
				.expiresAt = createdAt
					+ kOpenMlsKeyPackageLifetimeSeconds,
				.privateEngineState = QByteArray("private-") + keyPackage,
				.publicationEnvelope = *envelope,
				.queued = false,
			})
			: std::nullopt;
	};
	auto first = makeEntry(64, "first-public-package");
	auto second = makeEntry(65, "replacement-public-package");
	const auto observed = first
		? VerifyObservedClientKeyPackage({
			.bytes = first->publicationEnvelope.bytes,
			.observedTelegramPeerIdBinding = peerBinding,
			.observedSenderTelegramUserIdBinding = 7001,
			.observedMessageId = 91,
		},
		conversationId,
		peerBinding,
		generation,
		createdAt,
		envelopeCodec,
		sha256)
		: VerifyObservedClientKeyPackageOutcome();
	const auto wrongCarrier = first
		? VerifyObservedClientKeyPackage({
			.bytes = first->publicationEnvelope.bytes,
			.observedTelegramPeerIdBinding = peerBinding + 1,
			.observedSenderTelegramUserIdBinding = 7001,
			.observedMessageId = 91,
		},
		conversationId,
		peerBinding,
		generation,
		createdAt,
		envelopeCodec,
		sha256)
		: VerifyObservedClientKeyPackageOutcome();
	if (observed.status != ObservedClientKeyPackageStatus::Verified
		|| !observed.verified
		|| observed.verified->telegramUserIdBinding != 7001
		|| observed.verified->publication.authorization.clientId != clientId
		|| wrongCarrier.status
			!= ObservedClientKeyPackageStatus::InvalidTransportMetadata) {
		return Fail("KeyPackage did not bind observed Telegram authorship");
	}
	auto poolBlob = MemoryBlobStore();
	auto pool = PersistentKeyPackagePool(
		poolBlob,
		protector,
		envelopeCodec,
		sha256);
	if (!first
		|| !second
		|| pool.load(conversationId, peerBinding)
			!= KeyPackagePoolLoadResult::Empty
		|| pool.add(*first) != KeyPackagePoolMutationResult::Committed
		|| pool.add(*second) != KeyPackagePoolMutationResult::Committed
		|| pool.entries().size() != 2
		|| pool.needsRefresh(createdAt, generation)
		|| !pool.find(first->keyPackageHash, createdAt)) {
		return Fail("KeyPackage pool did not retain valid replacements");
	}
	auto outboxBlob = MemoryBlobStore();
	auto outbox = PersistentOutboxStore(outboxBlob, protector);
	if (outbox.load() != PersistentOutboxLoadResult::Empty
		|| pool.enqueuePending(outbox, createdAt)
			!= KeyPackagePoolEnqueueResult::Queued
		|| outbox.size() != 2
		|| std::any_of(
			begin(pool.entries()),
			end(pool.entries()),
			[](const StoredClientKeyPackage &entry) {
				return !entry.queued;
			})) {
		return Fail("KeyPackage pool did not reconcile its exact publications");
	}
	auto restored = PersistentKeyPackagePool(
		poolBlob,
		protector,
		envelopeCodec,
		sha256);
	if (restored.load(conversationId, peerBinding)
			!= KeyPackagePoolLoadResult::Loaded
		|| restored.entries().size() != 2
		|| !restored.find(second->keyPackageHash, createdAt)
		|| restored.consume(second->keyPackageHash)
			!= KeyPackagePoolMutationResult::Committed
		|| !restored.entries().empty()) {
		return Fail("KeyPackage pool did not consume all obsolete secrets");
	}
	auto consumed = PersistentKeyPackagePool(
		poolBlob,
		protector,
		envelopeCodec,
		sha256);
	if (consumed.load(conversationId, peerBinding)
			!= KeyPackagePoolLoadResult::Loaded
		|| !consumed.entries().empty()
		|| !consumed.needsRefresh(createdAt, generation)) {
		return Fail("consumed KeyPackage secrets survived restart");
	}
	return 0;
}

} // namespace

int main(int, char *[]) {
	for (const auto scenario : {
		ScenarioAeadProtection,
		ScenarioConversationRecordKeyDerivation,
		ScenarioContentSyncBoundarySurvivesRestart,
		ScenarioFileTransferSurvivesRestart,
		ScenarioConversationMetadataRoundTrip,
		ScenarioFreshnessTrustSurvivesRestart,
		ScenarioPersistentDraftRoundTrip,
		ScenarioSealedRetrySurvivesRestart,
		ScenarioCorruptionFailsClosed,
		ScenarioMlsStateTransaction,
		ScenarioMlsStateBindingAndCorruption,
		ScenarioMlsReceiptOutboxReconciliation,
		ScenarioInboundJournalSurvivesRestart,
		ScenarioInboundJournalWriteFailureIsTransactional,
		ScenarioInboundJournalCorruptionFailsClosed,
		ScenarioKeyPackagePoolRetainsReplacementSecrets,
	}) {
		if (const auto result = scenario()) {
			return result;
		}
	}
	return 0;
}
