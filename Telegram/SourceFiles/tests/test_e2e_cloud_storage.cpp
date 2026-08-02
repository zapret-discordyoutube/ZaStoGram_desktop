/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "e2e_cloud/storage/aes_gcm_local_record_protector.h"
#include "e2e_cloud/storage/file_atomic_blob_store.h"
#include "e2e_cloud/storage/local_record_key_derivation.h"
#include "e2e_cloud/storage/persistent_conversation_metadata.h"
#include "e2e_cloud/storage/persistent_content_store.h"
#include "e2e_cloud/storage/persistent_content_sync_state.h"
#include "e2e_cloud/storage/persistent_control_observation_state.h"
#include "e2e_cloud/storage/persistent_freshness_trust.h"
#include "e2e_cloud/files/persistent_file_transfer.h"
#include "e2e_cloud/files/private_file_manifest.h"
#include "e2e_cloud/core/envelope_codec.h"
#include "e2e_cloud/group/signed_group_transition.h"
#include "e2e_cloud/identity/openssl_account_crypto.h"
#include "e2e_cloud/mls/client_key_package.h"
#include "e2e_cloud/mls/mls_outbox_reconciler.h"
#include "e2e_cloud/mls/observed_key_package.h"
#include "e2e_cloud/protocol/freshness_protocol.h"
#include "e2e_cloud/storage/persistent_inbound_journal.h"
#include "e2e_cloud/storage/persistent_key_package_pool.h"
#include "e2e_cloud/storage/persistent_mls_state.h"
#include "e2e_cloud/storage/persistent_outbox.h"

#include <QtCore/QFile>
#include <QtCore/QTemporaryDir>

#include <algorithm>
#include <array>
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

void AppendTestUint16(QByteArray &result, std::uint16_t value) {
	result.append(char(value >> 8));
	result.append(char(value));
}

void AppendTestUint32(QByteArray &result, std::uint32_t value) {
	result.append(char(value >> 24));
	result.append(char(value >> 16));
	result.append(char(value >> 8));
	result.append(char(value));
}

void AppendTestUint64(QByteArray &result, std::uint64_t value) {
	for (auto shift = 56; shift >= 0; shift -= 8) {
		result.append(char(value >> shift));
	}
}

template <typename Array>
void AppendTestArray(QByteArray &result, const Array &value) {
	result.append(
		reinterpret_cast<const char*>(value.data()),
		int(value.size()));
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

class CountingLocalRecordProtector final : public LocalRecordProtector {
public:
	explicit CountingLocalRecordProtector(LocalRecordKey &&key);

	[[nodiscard]] std::optional<QByteArray> seal(
			const QByteArray &purpose,
			const QByteArray &plaintext) const override;

	[[nodiscard]] std::optional<QByteArray> open(
			const QByteArray &purpose,
			const QByteArray &ciphertext) const override;

	void resetOpenCalls() const;

	[[nodiscard]] int openCalls() const;

private:
	AesGcmLocalRecordProtector _protector;
	mutable int _openCalls = 0;

};

CountingLocalRecordProtector::CountingLocalRecordProtector(
		LocalRecordKey &&key)
: _protector(std::move(key)) {
}

std::optional<QByteArray> CountingLocalRecordProtector::seal(
		const QByteArray &purpose,
		const QByteArray &plaintext) const {
	return _protector.seal(purpose, plaintext);
}

std::optional<QByteArray> CountingLocalRecordProtector::open(
		const QByteArray &purpose,
		const QByteArray &ciphertext) const {
	++_openCalls;
	return _protector.open(purpose, ciphertext);
}

void CountingLocalRecordProtector::resetOpenCalls() const {
	_openCalls = 0;
}

int CountingLocalRecordProtector::openCalls() const {
	return _openCalls;
}

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

[[nodiscard]] int ScenarioAtomicBlobRejectsOversizedFile() {
	auto directory = QTemporaryDir();
	if (!directory.isValid()) {
		return Fail("atomic blob temporary directory was unavailable");
	}
	const auto path = directory.filePath("oversized.blob");
	auto file = QFile(path);
	constexpr auto kMaximumProtectedBlobSize = qint64(
		128 * 1024 * 1024 + 42);
	if (!file.open(QIODevice::WriteOnly)
		|| !file.seek(kMaximumProtectedBlobSize)
		|| file.write("x", 1) != 1) {
		return Fail("oversized atomic blob fixture could not be created");
	}
	file.close();
	const auto stored = FileAtomicBlobStore(path).read();
	if (stored.status != BlobReadStatus::Error || !stored.bytes.isEmpty()) {
		return Fail("atomic blob read allocated an oversized local record");
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
	auto wrongStream = PersistentContentSyncState(
		blob,
		protector,
		ObservedSyncStream::Control);
	if (wrongStream.load(conversationId)
			!= ContentSyncStateLoadResult::AuthenticationFailed
		|| wrongStream.loaded()) {
		return Fail("content and control boundaries were not domain-separated");
	}
	auto tampered = *blob.bytes;
	tampered[tampered.size() - 1] ^= 1;
	blob.bytes = tampered;
	if (restored.load(conversationId)
			!= ContentSyncStateLoadResult::AuthenticationFailed
		|| restored.loaded()
		|| restored.newestObservedMessageId()
		|| restored.revision()
		|| restored.advance(200)
			!= ContentSyncStateCommitResult::InvalidBoundary) {
		return Fail("content synchronization boundary accepted tampering");
	}
	return 0;
}

[[nodiscard]] int ScenarioControlObservationStateSurvivesRestart() {
	auto key = LocalRecordKey();
	key.fill(33);
	const auto protector = AesGcmLocalRecordProtector(std::move(key));
	const auto conversationId = FilledId<ConversationId>(34);
	const auto localAccountId = FilledId<AccountId>(35);
	const auto remoteAccountId = FilledId<AccountId>(36);
	const auto checkpoint = Checkpoint{
		.conversationId = conversationId,
		.generation = 7,
		.stateHash = FilledId<Digest>(37),
	};
	const auto witnesses = std::set<AccountId>{
		localAccountId,
		remoteAccountId,
	};
	auto blob = MemoryBlobStore();
	auto state = PersistentControlObservationState(blob, protector);
	if (state.load(conversationId)
			!= ControlObservationStateLoadResult::Missing
		|| state.advance(100, checkpoint, witnesses, true)
			!= ControlObservationStateCommitResult::Committed
		|| state.advance(99, checkpoint, witnesses, true)
			!= ControlObservationStateCommitResult::InvalidState
		|| state.advance(100, checkpoint, witnesses, true)
			!= ControlObservationStateCommitResult::AlreadyCommitted) {
		return Fail("control observation state was not monotonic");
	}
	auto restored = PersistentControlObservationState(blob, protector);
	if (restored.load(conversationId)
			!= ControlObservationStateLoadResult::Loaded
		|| restored.newestObservedMessageId() != 100
		|| restored.checkpoint() != checkpoint
		|| restored.safetyWitnesses() != witnesses
		|| !restored.ownSafetyGossipObserved()
		|| restored.revision() != 1
		|| restored.legacy()) {
		return Fail("control witnesses did not survive restart");
	}
	blob.writeError = true;
	const auto nextWitnesses = std::set<AccountId>{ localAccountId };
	if (restored.advance(150, checkpoint, nextWitnesses, false)
			!= ControlObservationStateCommitResult::PersistenceFailed
		|| restored.newestObservedMessageId() != 100
		|| restored.safetyWitnesses() != witnesses
		|| !restored.ownSafetyGossipObserved()) {
		return Fail("failed control observation write changed live state");
	}
	blob.writeError = false;
	auto contentState = PersistentContentSyncState(blob, protector);
	if (contentState.load(conversationId)
			!= ContentSyncStateLoadResult::AuthenticationFailed) {
		return Fail("control observation state was not domain-separated");
	}
	auto tampered = *blob.bytes;
	tampered[tampered.size() - 1] ^= 1;
	blob.bytes = tampered;
	if (restored.load(conversationId)
			!= ControlObservationStateLoadResult::AuthenticationFailed
		|| restored.loaded()
		|| restored.newestObservedMessageId()
		|| restored.revision()
		|| !restored.safetyWitnesses().empty()) {
		return Fail("control observation state accepted tampering");
	}
	return 0;
}

[[nodiscard]] int ScenarioLegacyControlBoundaryMigrates() {
	auto key = LocalRecordKey();
	key.fill(38);
	const auto protector = AesGcmLocalRecordProtector(std::move(key));
	const auto conversationId = FilledId<ConversationId>(39);
	const auto accountId = FilledId<AccountId>(40);
	const auto checkpoint = Checkpoint{
		.conversationId = conversationId,
		.generation = 8,
		.stateHash = FilledId<Digest>(41),
	};
	auto blob = MemoryBlobStore();
	auto legacy = PersistentContentSyncState(
		blob,
		protector,
		ObservedSyncStream::Control);
	if (legacy.load(conversationId) != ContentSyncStateLoadResult::Missing
		|| legacy.advance(75) != ContentSyncStateCommitResult::Committed) {
		return Fail("legacy control boundary setup failed");
	}
	auto migrated = PersistentControlObservationState(blob, protector);
	if (migrated.load(conversationId)
			!= ControlObservationStateLoadResult::LegacyLoaded
		|| !migrated.legacy()
		|| migrated.newestObservedMessageId() != 75
		|| migrated.revision() != 1
		|| migrated.advance(75, checkpoint, { accountId }, false)
			!= ControlObservationStateCommitResult::Committed
		|| migrated.legacy()
		|| migrated.revision() != 2) {
		return Fail("legacy control boundary was not migrated");
	}
	auto restored = PersistentControlObservationState(blob, protector);
	if (restored.load(conversationId)
			!= ControlObservationStateLoadResult::Loaded
		|| restored.checkpoint() != checkpoint
		|| restored.safetyWitnesses()
			!= std::set<AccountId>{ accountId }) {
		return Fail("migrated control observation state did not reload");
	}
	return 0;
}

[[nodiscard]] int ScenarioContentStoreReloadFailureClearsPlaintext() {
	auto key = LocalRecordKey();
	key.fill(51);
	const auto protector = AesGcmLocalRecordProtector(std::move(key));
	const auto sha256 = OpenSslSha256Provider();
	const auto conversationId = FilledId<ConversationId>(52);
	const auto eventObjectId = FilledId<ObjectId>(53);
	auto indexBlob = MemoryBlobStore();
	auto directory = QTemporaryDir();
	if (!directory.isValid()) {
		return Fail("content store temporary directory was unavailable");
	}
	auto store = PersistentContentStore(
		conversationId,
		directory.path(),
		indexBlob,
		protector,
		sha256);
	if (store.load() != ContentStoreLoadResult::Missing
		|| store.append({
			.conversationId = conversationId,
			.eventObjectId = eventObjectId,
			.contentObjectId = FilledId<ObjectId>(54),
			.objectKind = ObjectKind::EncryptedMessageBody,
			.groupGeneration = 7,
			.senderAccountId = FilledId<AccountId>(55),
			.senderClientId = FilledId<ClientId>(56),
			.unixTime = 1'725'000'000,
			.observedTelegramMessageId = 99,
			.plaintext = QByteArray("decrypted protected message"),
		}) != ContentStoreAppendResult::Stored
		|| !store.record(eventObjectId)) {
		return Fail("content store reload fixture could not be persisted");
	}
	(*indexBlob.bytes)[indexBlob.bytes->size() - 1] ^= 1;
	if (store.load() != ContentStoreLoadResult::AuthenticationFailed
		|| store.loaded()
		|| store.revision()
		|| store.size()
		|| !store.records(0, 1).empty()
		|| store.record(eventObjectId)) {
		return Fail("failed content store reload retained plaintext state");
	}
	return 0;
}

[[nodiscard]] int ScenarioContentStoreAcceptsCarrierDuplicates() {
	auto key = LocalRecordKey();
	key.fill(57);
	const auto protector = AesGcmLocalRecordProtector(std::move(key));
	const auto sha256 = OpenSslSha256Provider();
	const auto conversationId = FilledId<ConversationId>(58);
	auto indexBlob = MemoryBlobStore();
	auto directory = QTemporaryDir();
	if (!directory.isValid()) {
		return Fail("content duplicate temporary directory was unavailable");
	}
	auto store = PersistentContentStore(
		conversationId,
		directory.path(),
		indexBlob,
		protector,
		sha256);
	auto record = ProtectedContentRecord{
		.conversationId = conversationId,
		.eventObjectId = FilledId<ObjectId>(59),
		.contentObjectId = FilledId<ObjectId>(60),
		.objectKind = ObjectKind::EncryptedMessageBody,
		.groupGeneration = 7,
		.senderAccountId = FilledId<AccountId>(61),
		.senderClientId = FilledId<ClientId>(62),
		.unixTime = 1'725'000'000,
		.observedTelegramMessageId = 100,
		.plaintext = QByteArray("same protected message"),
	};
	if (store.load() != ContentStoreLoadResult::Missing
		|| store.append(record) != ContentStoreAppendResult::Stored) {
		return Fail("content duplicate fixture could not be persisted");
	}
	record.observedTelegramMessageId = 101;
	const auto newerDuplicate = store.append(record);
	const auto afterNewerDuplicate = store.record(record.eventObjectId);
	if (newerDuplicate != ContentStoreAppendResult::AlreadyStored
		|| store.revision() != 1
		|| store.size() != 1
		|| !afterNewerDuplicate
		|| afterNewerDuplicate->observedTelegramMessageId != 100) {
		return Fail("same content under another carrier id was a conflict");
	}
	record.observedTelegramMessageId = 99;
	indexBlob.writeError = true;
	const auto failed = store.append(record);
	const auto afterFailedWrite = store.record(record.eventObjectId);
	if (failed != ContentStoreAppendResult::PersistenceFailed
		|| store.revision() != 1
		|| !afterFailedWrite
		|| afterFailedWrite->observedTelegramMessageId != 100) {
		return Fail("failed duplicate boundary write changed live content");
	}
	indexBlob.writeError = false;
	const auto retried = store.append(record);
	const auto afterOlderDuplicate = store.record(record.eventObjectId);
	if (retried != ContentStoreAppendResult::AlreadyStored
		|| store.revision() != 2
		|| !afterOlderDuplicate
		|| afterOlderDuplicate->observedTelegramMessageId != 99) {
		return Fail("older carrier duplicate did not lower its search boundary");
	}
	record.plaintext.append('!');
	if (store.append(std::move(record)) != ContentStoreAppendResult::Conflict) {
		return Fail("changed protected content escaped conflict detection");
	}
	return 0;
}

[[nodiscard]] int ScenarioContentStorePagesAndMigratesLegacyIndex() {
	auto key = LocalRecordKey();
	key.fill(63);
	const auto protector = CountingLocalRecordProtector(std::move(key));
	const auto sha256 = OpenSslSha256Provider();
	const auto conversationId = FilledId<ConversationId>(64);
	auto indexBlob = MemoryBlobStore();
	auto directory = QTemporaryDir();
	if (!directory.isValid()) {
		return Fail("content paging temporary directory was unavailable");
	}
	auto store = PersistentContentStore(
		conversationId,
		directory.path(),
		indexBlob,
		protector,
		sha256);
	if (store.load() != ContentStoreLoadResult::Missing) {
		return Fail("content paging store did not start empty");
	}
	const auto times = std::array<std::uint64_t, 3>{ 300, 100, 200 };
	for (auto index = std::size_t(); index != times.size(); ++index) {
		if (store.append({
			.conversationId = conversationId,
			.eventObjectId = FilledId<ObjectId>(
				std::uint8_t(65 + index)),
			.contentObjectId = FilledId<ObjectId>(
				std::uint8_t(68 + index)),
			.objectKind = (index == 2)
				? ObjectKind::EncryptedFileManifest
				: ObjectKind::EncryptedMessageBody,
			.groupGeneration = 7,
			.senderAccountId = FilledId<AccountId>(71),
			.senderClientId = FilledId<ClientId>(72),
			.unixTime = times[index],
			.observedTelegramMessageId = 100 + std::int64_t(index),
			.plaintext = QByteArray("paged protected content"),
		}) != ContentStoreAppendResult::Stored) {
			return Fail("content paging fixture could not be persisted");
		}
	}
	const auto purpose = QByteArray("e2e-cloud-content-index-v1");
	auto versionThree = indexBlob.bytes
		? protector.open(purpose, *indexBlob.bytes)
		: std::nullopt;
	if (!versionThree || versionThree->size() != 54 + 3 * 82) {
		return Fail("content paging index was not written as version three");
	}
	auto versionTwo = QByteArray(versionThree->constData(), 54);
	versionTwo[8] = 0;
	versionTwo[9] = 2;
	for (auto index = 0; index != 3; ++index) {
		versionTwo.append(
			versionThree->constData() + 54 + index * 82,
			74);
	}
	indexBlob.bytes = protector.seal(purpose, versionTwo);
	auto restoredVersionTwo = PersistentContentStore(
		conversationId,
		directory.path(),
		indexBlob,
		protector,
		sha256);
	if (!indexBlob.bytes
		|| restoredVersionTwo.load() != ContentStoreLoadResult::Loaded) {
		return Fail("version-two content index did not migrate");
	}
	const auto versionTwoFiles = restoredVersionTwo.records(
		0,
		1,
		ObjectKind::EncryptedFileManifest);
	const auto migratedVersionTwo = indexBlob.bytes
		? protector.open(purpose, *indexBlob.bytes)
		: std::nullopt;
	if (versionTwoFiles.size() != 1
		|| versionTwoFiles[0].observedTelegramMessageId != 1
		|| !migratedVersionTwo
		|| migratedVersionTwo->size() != 54 + 3 * 82
		|| std::uint8_t((*migratedVersionTwo)[9]) != 3) {
		return Fail("version-two manifest boundary was not made conservative");
	}
	auto versionOne = QByteArray(versionThree->constData(), 54);
	versionOne[8] = 0;
	versionOne[9] = 1;
	for (auto index = 0; index != 3; ++index) {
		versionOne.append(versionThree->constData() + 54 + index * 82, 64);
	}
	indexBlob.bytes = protector.seal(purpose, versionOne);
	if (!indexBlob.bytes) {
		return Fail("legacy content index fixture could not be protected");
	}
	auto restored = PersistentContentStore(
		conversationId,
		directory.path(),
		indexBlob,
		protector,
		sha256);
	if (restored.load() != ContentStoreLoadResult::Loaded
		|| restored.size() != 3
		|| restored.size(ObjectKind::EncryptedFileManifest) != 1) {
		return Fail("legacy content index did not migrate");
	}
	const auto firstPage = restored.records(0, 2);
	const auto secondPage = restored.records(2, 1);
	const auto files = restored.records(
		0,
		1,
		ObjectKind::EncryptedFileManifest);
	if (firstPage.size() != 2
		|| firstPage[0].unixTime != 100
		|| firstPage[1].unixTime != 200
		|| secondPage.size() != 1
		|| secondPage[0].unixTime != 300
		|| files.size() != 1
		|| files[0].objectKind != ObjectKind::EncryptedFileManifest
		|| files[0].unixTime != 200
		|| files[0].observedTelegramMessageId != 1) {
		return Fail("content store did not load only the requested sorted page");
	}
	const auto migrated = indexBlob.bytes
		? protector.open(purpose, *indexBlob.bytes)
		: std::nullopt;
	if (!migrated
		|| migrated->size() != 54 + 3 * 82
		|| std::uint8_t((*migrated)[8]) != 0
		|| std::uint8_t((*migrated)[9]) != 3) {
		return Fail("legacy content index was not upgraded atomically");
	}
	protector.resetOpenCalls();
	auto reloaded = PersistentContentStore(
		conversationId,
		directory.path(),
		indexBlob,
		protector,
		sha256);
	if (reloaded.load() != ContentStoreLoadResult::Loaded
		|| protector.openCalls() != 1) {
		return Fail("version-three content load decrypted every message");
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
		.preview = PrivateFilePreview{
			.width = 320,
			.height = 180,
			.jpegBytes = QByteArray(70 * 1024, 'p'),
		},
	});
	auto blob = MemoryBlobStore();
	auto transfer = PersistentFileTransfer(blob, protector);
	if (!manifest) {
		return Fail("resumable file transfer manifest was not encoded");
	}
	if (transfer.load(context.conversationId)
			!= FileTransferLoadResult::Empty) {
		return Fail("resumable file transfer was not initially empty");
	}
	if (transfer.begin({
			.conversationId = context.conversationId,
			.eventObjectId = FilledId<ObjectId>(39),
			.contentObjectId = FilledId<ObjectId>(40),
			.groupGeneration = 7,
			.archiveEpochGeneration = 3,
			.manifestPublished = false,
			.nextChunkIndex = 0,
			.sourcePathUtf8 = QByteArray("/private/source.any"),
			.manifestPlaintext = manifest.value_or(QByteArray()),
		}) != FileTransferCommitResult::Committed) {
		return Fail("resumable file transfer was not started");
	}
	if (transfer.advance(0) != FileTransferCommitResult::InvalidMutation) {
		return Fail("resumable file transfer advanced before publication");
	}
	if (transfer.markManifestPublished(3)
			!= FileTransferCommitResult::Committed) {
		return Fail("resumable file transfer publication was not persisted");
	}
	if (transfer.advance(0) != FileTransferCommitResult::Committed) {
		return Fail("resumable file transfer progress was not persisted");
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
		|| !restored.pending()->manifestPublished
		|| restored.pending()->archiveEpochGeneration != 3
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
		.archiveEpochGeneration = 4,
		.manifestPublished = false,
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
		|| restored.revision() != 4) {
		return Fail("file transfer could not be replaced atomically");
	}
	auto replaced = PersistentFileTransfer(blob, protector);
	if (replaced.load(context.conversationId)
			!= FileTransferLoadResult::Loaded
		|| !replaced.pending()
		|| replaced.pending()->sourcePathUtf8
			!= replacement.sourcePathUtf8) {
		return Fail("resumable file transfer replacement did not reload");
	}
	const auto replacementSnapshot = *blob.bytes;
	(*blob.bytes)[blob.bytes->size() - 1] ^= 1;
	if (replaced.load(context.conversationId)
			!= FileTransferLoadResult::AuthenticationFailed
		|| replaced.loaded()
		|| replaced.pending()
		|| replaced.revision()) {
		return Fail("failed file transfer reload retained pending plaintext");
	}
	blob.bytes = replacementSnapshot;
	if (replaced.load(context.conversationId)
			!= FileTransferLoadResult::Loaded) {
		return Fail("file transfer cancellation fixture did not reload");
	}
	blob.writeError = true;
	if (replaced.requestCancel()
			!= FileTransferCommitResult::PersistenceFailed
		|| !replaced.pending()
		|| replaced.pending()->cancelRequested) {
		return Fail("failed cancellation changed pending file transfer");
	}
	blob.writeError = false;
	if (replaced.requestCancel()
			!= FileTransferCommitResult::Committed
		|| !replaced.pending()
		|| !replaced.pending()->cancelRequested
		|| replaced.markManifestPublished(4)
			!= FileTransferCommitResult::Committed
		|| !replaced.pending()
		|| !replaced.pending()->cancelRequested
		|| !replaced.pending()->manifestPublished
		|| replaced.revision() != 6) {
		return Fail("file transfer cancellation was not durable");
	}
	auto cancelling = PersistentFileTransfer(blob, protector);
	if (cancelling.load(context.conversationId)
			!= FileTransferLoadResult::Loaded
		|| !cancelling.pending()
		|| !cancelling.pending()->cancelRequested
		|| cancelling.requestCancel()
			!= FileTransferCommitResult::AlreadyCommitted
		|| cancelling.clear() != FileTransferCommitResult::Committed) {
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

[[nodiscard]] int ScenarioLegacyFileTransferPublishesManifestFirst() {
	auto localKey = LocalRecordKey();
	localKey.fill(50);
	const auto protector = AesGcmLocalRecordProtector(std::move(localKey));
	auto fileKey = std::array<std::uint8_t, 32>();
	fileKey.fill(51);
	auto context = FileChunkContext{
		.conversationId = FilledId<ConversationId>(52),
		.fileId = FilledId<FileId>(53),
		.plaintextSize = 13,
		.chunkSize = 64 * 1024,
		.chunkCount = 1,
		.noncePrefix = {},
	};
	context.noncePrefix.fill(54);
	const auto manifest = PrivateFileManifestCodecV1().encodePlaintext({
		.context = context,
		.key = FileEncryptionKey(std::move(fileKey)),
		.plaintextHash = FilledId<Digest>(55),
		.unixTime = 1'725'000'002,
		.filenameUtf8 = QByteArray("legacy.any"),
		.mimeTypeUtf8 = QByteArray("application/octet-stream"),
	});
	if (!manifest) {
		return Fail("legacy file transfer manifest could not be encoded");
	}
	const auto eventObjectId = FilledId<ObjectId>(56);
	const auto contentObjectId = FilledId<ObjectId>(57);
	const auto sourcePath = QByteArray("/private/legacy.any");
	auto plaintext = QByteArray("TDE2EFTR", 8);
	AppendTestUint16(plaintext, 1);
	AppendTestArray(plaintext, context.conversationId.bytes);
	AppendTestUint64(plaintext, 5);
	plaintext.append(char(1));
	AppendTestArray(plaintext, eventObjectId.bytes);
	AppendTestArray(plaintext, contentObjectId.bytes);
	AppendTestUint64(plaintext, 7);
	AppendTestUint32(plaintext, 0);
	AppendTestUint32(plaintext, std::uint32_t(sourcePath.size()));
	plaintext.append(sourcePath);
	AppendTestUint32(plaintext, std::uint32_t(manifest->size()));
	plaintext.append(*manifest);
	auto blob = MemoryBlobStore();
	blob.bytes = protector.seal(
		QByteArray("e2e-cloud-file-transfer-v1"),
		plaintext);
	auto transfer = PersistentFileTransfer(blob, protector);
	if (!blob.bytes
		|| transfer.load(context.conversationId)
			!= FileTransferLoadResult::Loaded
		|| !transfer.pending()
		|| transfer.pending()->manifestPublished
		|| transfer.pending()->archiveEpochGeneration
		|| transfer.advance(0)
			!= FileTransferCommitResult::InvalidMutation
		|| transfer.markManifestPublished(3)
			!= FileTransferCommitResult::Committed
		|| !transfer.pending()
		|| !transfer.pending()->manifestPublished
		|| transfer.pending()->archiveEpochGeneration != 3
		|| transfer.revision() != 6) {
		return Fail("legacy file transfer bypassed manifest-first migration");
	}
	auto restored = PersistentFileTransfer(blob, protector);
	if (restored.load(context.conversationId)
			!= FileTransferLoadResult::Loaded
		|| !restored.pending()
		|| !restored.pending()->manifestPublished
		|| restored.pending()->cancelRequested
		|| restored.pending()->archiveEpochGeneration != 3) {
		return Fail("migrated file transfer did not persist version three");
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
	auto second = Message();
	second.objectId = FilledId<ObjectId>(3);
	if (!restored.append(std::move(second)) || restored.size() != 2) {
		return Fail("protected outbox pair setup failed");
	}
	blob.writeError = true;
	if (restored.removePair(
			FilledId<ObjectId>(2),
			FilledId<ObjectId>(3))
		|| restored.size() != 2) {
		return Fail("failed outbox pair removal changed live state");
	}
	blob.writeError = false;
	if (!restored.removePair(
			FilledId<ObjectId>(2),
			FilledId<ObjectId>(3))
		|| restored.size()
		|| restored.revision() != 3
		|| !restored.removePair(
			FilledId<ObjectId>(2),
			FilledId<ObjectId>(3))
		|| restored.revision() != 3) {
		return Fail("protected outbox pair was not removed atomically");
	}
	auto remaining = Message();
	remaining.objectId = FilledId<ObjectId>(4);
	if (!restored.append(std::move(remaining)) || restored.size() != 1) {
		return Fail("protected outbox clear setup failed");
	}
	blob.writeError = true;
	if (restored.clear() || restored.size() != 1) {
		return Fail("failed outbox clear changed live state");
	}
	blob.writeError = false;
	if (!restored.clear()
		|| restored.size()
		|| restored.revision() != 5
		|| !restored.clear()
		|| restored.revision() != 5) {
		return Fail("protected outbox was not cleared atomically");
	}
	return 0;
}

[[nodiscard]] int ScenarioOutboxPlaintextCleanup() {
	auto message = Message();
	CleansePendingMessage(message);
	if (!message.plaintext.isEmpty()
		|| !message.authenticatedData.isEmpty()) {
		return Fail("pending outbox message was not cleansed");
	}
	auto item = OutboxItem{
		.draft = Message(),
		.stage = OutboxItemStage::Draft,
		.sealed = std::nullopt,
	};
	CleanseOutboxItem(item);
	if (!item.draft.plaintext.isEmpty()
		|| !item.draft.authenticatedData.isEmpty()) {
		return Fail("outbox item plaintext was not cleansed");
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

[[nodiscard]] int ScenarioFreshnessResponseReplayIsPersistent() {
	auto key = LocalRecordKey();
	key.fill(54);
	const auto protector = AesGcmLocalRecordProtector(std::move(key));
	auto outboxBlob = MemoryBlobStore();
	auto journalBlob = MemoryBlobStore();
	auto outbox = PersistentOutboxStore(outboxBlob, protector);
	auto journal = PersistentInboundJournal(
		journalBlob,
		protector,
		InboundJournalDomain::Control);
	const auto conversationId = FilledId<ConversationId>(55);
	const auto challengeObjectId = FilledId<ObjectId>(56);
	const auto challengeHash = FilledId<Digest>(57);
	const auto response = EncodedEnvelope{
		.conversationId = conversationId,
		.objectId = FilledId<ObjectId>(58),
		.bytes = QByteArray("exact signed freshness response"),
	};
	const auto queue = [&](bool alreadyPublished = false) {
		return QueueFreshnessResponseOnce({
			.conversationId = conversationId,
			.challengeObjectId = challengeObjectId,
			.challengePayloadHash = challengeHash,
			.responseEnvelope = response,
			.responseAlreadyPublished = alreadyPublished,
		}, outbox, journal);
	};
	if (outbox.load() != PersistentOutboxLoadResult::Empty
		|| journal.load() != InboundJournalLoadResult::Missing
		|| queue() != FreshnessResponseQueueResult::Queued
		|| outbox.size() != 1
		|| journal.lookup(
			conversationId,
			challengeObjectId,
			challengeHash) != InboundJournalLookup::Accepted
		|| queue() != FreshnessResponseQueueResult::AlreadyResponded
		|| !outbox.remove(response.objectId)) {
		return Fail("freshness response replay setup was not durable");
	}
	auto wrongDomain = PersistentInboundJournal(journalBlob, protector);
	if (wrongDomain.load() != InboundJournalLoadResult::AuthenticationFailed) {
		return Fail("control replay journal was swappable with content state");
	}
	auto restoredOutbox = PersistentOutboxStore(outboxBlob, protector);
	auto restoredJournal = PersistentInboundJournal(
		journalBlob,
		protector,
		InboundJournalDomain::Control);
	if (restoredOutbox.load() != PersistentOutboxLoadResult::Loaded
		|| restoredJournal.load() != InboundJournalLoadResult::Loaded
		|| QueueFreshnessResponseOnce({
			.conversationId = conversationId,
			.challengeObjectId = challengeObjectId,
			.challengePayloadHash = challengeHash,
			.responseEnvelope = response,
		}, restoredOutbox, restoredJournal)
			!= FreshnessResponseQueueResult::AlreadyResponded
		|| restoredOutbox.size()
		|| QueueFreshnessResponseOnce({
			.conversationId = conversationId,
			.challengeObjectId = challengeObjectId,
			.challengePayloadHash = FilledId<Digest>(59),
			.responseEnvelope = response,
		}, restoredOutbox, restoredJournal)
			!= FreshnessResponseQueueResult::ObjectIdConflict) {
		return Fail("freshness response replay survived a restart");
	}
	auto publishedOutboxBlob = MemoryBlobStore();
	auto publishedJournalBlob = MemoryBlobStore();
	auto publishedOutbox = PersistentOutboxStore(
		publishedOutboxBlob,
		protector);
	auto publishedJournal = PersistentInboundJournal(
		publishedJournalBlob,
		protector,
		InboundJournalDomain::Control);
	if (publishedOutbox.load() != PersistentOutboxLoadResult::Empty
		|| publishedJournal.load() != InboundJournalLoadResult::Missing
		|| !publishedOutbox.appendSealed(response)
		|| QueueFreshnessResponseOnce({
			.conversationId = conversationId,
			.challengeObjectId = challengeObjectId,
			.challengePayloadHash = challengeHash,
			.responseEnvelope = response,
			.responseAlreadyPublished = true,
		}, publishedOutbox, publishedJournal)
			!= FreshnessResponseQueueResult::AlreadyPublished
		|| publishedOutbox.size()
		|| publishedOutbox.revision() != 2
		|| publishedJournal.lookup(
			conversationId,
			challengeObjectId,
			challengeHash) != InboundJournalLookup::Accepted) {
		return Fail("published freshness response was queued again");
	}
	auto failedOutboxBlob = MemoryBlobStore();
	auto failedJournalBlob = MemoryBlobStore();
	auto failedOutbox = PersistentOutboxStore(failedOutboxBlob, protector);
	auto failedJournal = PersistentInboundJournal(
		failedJournalBlob,
		protector,
		InboundJournalDomain::Control);
	if (failedOutbox.load() != PersistentOutboxLoadResult::Empty
		|| failedJournal.load() != InboundJournalLoadResult::Missing) {
		return Fail("freshness replay failure fixture did not load");
	}
	failedJournalBlob.writeError = true;
	if (QueueFreshnessResponseOnce({
			.conversationId = conversationId,
			.challengeObjectId = challengeObjectId,
			.challengePayloadHash = challengeHash,
			.responseEnvelope = response,
		}, failedOutbox, failedJournal)
			!= FreshnessResponseQueueResult::PersistenceFailed
		|| !failedOutbox.contains(response.objectId)) {
		return Fail("freshness replay journal failure lost the response");
	}
	failedJournalBlob.writeError = false;
	if (QueueFreshnessResponseOnce({
			.conversationId = conversationId,
			.challengeObjectId = challengeObjectId,
			.challengePayloadHash = challengeHash,
			.responseEnvelope = response,
		}, failedOutbox, failedJournal)
			!= FreshnessResponseQueueResult::AlreadyQueued
		|| failedJournal.lookup(
			conversationId,
			challengeObjectId,
			challengeHash) != InboundJournalLookup::Accepted) {
		return Fail("freshness replay journal did not recover atomically");
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
	if (store.load()
			!= PersistentOutboxLoadResult::AuthenticationFailed
		|| store.loaded()
		|| store.size()
		|| store.revision()) {
		return Fail(
			"corrupted outbox reload retained pending plaintext");
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
	auto journalBlob = MemoryBlobStore();
	auto mls = PersistentMlsStateStore(mlsBlob, protector);
	auto outbox = PersistentOutboxStore(outboxBlob, protector);
	auto journal = PersistentInboundJournal(journalBlob, protector);
	const auto envelopeCodec = EnvelopeCodecV1();
	const auto envelope = Envelope();
	const auto encoded = envelopeCodec.encode(envelope);
	const auto conversationId = envelope.conversationId;
	const auto receipt = encoded
		? std::optional<MlsOperationReceipt>(MlsOperationReceipt{
			.objectId = envelope.objectId,
			.requestHash = FilledId<Digest>(20),
			.envelope = *encoded,
		})
		: std::nullopt;
	if (mls.load(conversationId) != MlsStateLoadResult::Missing
		|| !receipt
		|| mls.initialize(
			QByteArray("openmls-0.8.1-0e99bc88-rustcrypto-v1"),
			QByteArray("reconcile state"))
			!= MlsStateCommitResult::Committed
		|| mls.commit({
			.baseRevision = mls.revision(),
			.engineState = QByteArray("reconcile advanced state"),
			.receipt = *receipt,
			.inboundApplication = std::nullopt,
			.removalTombstone = std::nullopt,
		}) != MlsStateCommitResult::Committed
		|| outbox.load() != PersistentOutboxLoadResult::Empty
		|| journal.load() != InboundJournalLoadResult::Missing
		|| !outbox.append({
			.conversationId = conversationId,
			.objectId = receipt->objectId,
			.plaintext = QByteArray("descriptor"),
			.authenticatedData = {},
		})) {
		return Fail("MLS receipt reconciliation setup failed");
	}
	if (ReconcileMlsOutboxReceipts(
			mls,
			outbox,
			envelopeCodec,
			journal)
			!= MlsReceiptReconcileResult::NothingToDo
		|| mls.receiptCount() != 1
		|| !outbox.remove(receipt->objectId)
		|| ReconcileMlsOutboxReceipts(
			mls,
			outbox,
			envelopeCodec,
			journal)
			!= MlsReceiptReconcileResult::Reconciled
		|| mls.receiptCount()
		|| journal.lookup(
			envelope.conversationId,
			envelope.objectId,
			envelope.payloadHash) != InboundJournalLookup::Accepted) {
		return Fail("MLS receipt was not tied to durable outbox delivery");
	}
	return 0;
}

[[nodiscard]] int ScenarioObservedMlsReceiptCrashRecovery() {
	enum class JournalPhase {
		Missing,
		Pending,
		Accepted,
	};
	enum class Failure {
		None,
		Journal,
		MlsState,
		Substitution,
	};
	const auto run = [&](JournalPhase phase, Failure failure) {
		auto key = LocalRecordKey();
		key.fill(21);
		const auto protector = AesGcmLocalRecordProtector(std::move(key));
		const auto envelopeCodec = EnvelopeCodecV1();
		const auto envelope = Envelope();
		const auto encoded = envelopeCodec.encode(envelope);
		auto mlsBlob = MemoryBlobStore();
		auto journalBlob = MemoryBlobStore();
		auto mlsState = PersistentMlsStateStore(mlsBlob, protector);
		auto journal = PersistentInboundJournal(journalBlob, protector);
		if (!encoded
			|| mlsState.load(envelope.conversationId)
				!= MlsStateLoadResult::Missing
			|| mlsState.initialize(
				QByteArray("test-engine"),
				QByteArray("initial state"))
				!= MlsStateCommitResult::Committed
			|| mlsState.commit({
				.baseRevision = mlsState.revision(),
				.engineState = QByteArray("state after local seal"),
				.receipt = MlsOperationReceipt{
					.objectId = envelope.objectId,
					.requestHash = FilledId<Digest>(22),
					.envelope = *encoded,
				},
				.inboundApplication = std::nullopt,
				.removalTombstone = std::nullopt,
			}) != MlsStateCommitResult::Committed
			|| journal.load() != InboundJournalLoadResult::Missing) {
			return false;
		}
		if (phase != JournalPhase::Missing && !journal.begin(envelope)) {
			return false;
		}
		if (phase == JournalPhase::Accepted
			&& !journal.accept(
				envelope.conversationId,
				envelope.objectId)) {
			return false;
		}
		auto observed = envelope;
		if (failure == Failure::Journal) {
			journalBlob.writeError = true;
		} else if (failure == Failure::MlsState) {
			mlsBlob.writeError = true;
		} else if (failure == Failure::Substitution) {
			observed.authenticationData.append('x');
		}
		const auto first = ReconcileObservedMlsReceipt(
			observed,
			envelopeCodec,
			mlsState,
			journal);
		if (failure == Failure::Substitution) {
			return first
					== ObservedMlsReceiptReconcileResult::ObjectIdConflict
				&& mlsState.receiptCount() == 1
				&& journal.lookup(
					envelope.conversationId,
					envelope.objectId,
					envelope.payloadHash) == InboundJournalLookup::Missing;
		}
		const auto failed = failure == Failure::Journal
			? ObservedMlsReceiptReconcileResult::JournalFailure
			: ObservedMlsReceiptReconcileResult::MlsStateFailure;
		if (failure != Failure::None) {
			if (first != failed || mlsState.receiptCount() != 1) {
				return false;
			}
			journalBlob.writeError = false;
			mlsBlob.writeError = false;
			if (ReconcileObservedMlsReceipt(
					envelope,
					envelopeCodec,
					mlsState,
					journal)
					!= ObservedMlsReceiptReconcileResult::Reconciled) {
				return false;
			}
		} else if (first
				!= ObservedMlsReceiptReconcileResult::Reconciled) {
			return false;
		}
		return !mlsState.receiptCount()
			&& journal.lookup(
				envelope.conversationId,
				envelope.objectId,
				envelope.payloadHash) == InboundJournalLookup::Accepted;
	};
	if (!run(JournalPhase::Missing, Failure::None)
		|| !run(JournalPhase::Pending, Failure::None)
		|| !run(JournalPhase::Accepted, Failure::None)
		|| !run(JournalPhase::Pending, Failure::Journal)
		|| !run(JournalPhase::Accepted, Failure::MlsState)
		|| !run(JournalPhase::Missing, Failure::Substitution)) {
		return Fail("observed MLS receipt did not close every crash window");
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
	auto concurrent = envelope;
	concurrent.objectId = FilledId<ObjectId>(6);
	concurrent.payloadHash = FilledId<Digest>(7);
	if (!journal.begin(concurrent)
		|| journal.lookup(
			concurrent.conversationId,
			concurrent.objectId,
			concurrent.payloadHash) != InboundJournalLookup::Pending
		|| !journal.abort(
			concurrent.conversationId,
			concurrent.objectId)
		|| journal.lookup(
			concurrent.conversationId,
			concurrent.objectId,
			concurrent.payloadHash) != InboundJournalLookup::Missing) {
		return Fail("inbound journal could not recover independent operations");
	}
	auto pending = PersistentInboundJournal(blob, protector);
	if (pending.load() != InboundJournalLoadResult::Loaded
		|| pending.lookup(
			envelope.conversationId,
			envelope.objectId,
			envelope.payloadHash) != InboundJournalLookup::Pending
		|| !pending.accept(envelope.conversationId, envelope.objectId)
		|| pending.revision() != 4) {
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
	if (journal.load()
			!= InboundJournalLoadResult::AuthenticationFailed
		|| journal.size()
		|| journal.revision()
		|| journal.lookup(
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
	const auto telegramUserIdBinding = std::uint64_t(7001);
	auto identity = GenerateAccountPrivateIdentity();
	const auto accountId = identity
		? DeriveAccountId(identity->credential, sha256)
		: std::nullopt;
	if (!identity || !accountId) {
		return Fail("KeyPackage pool identity setup failed");
	}
	const auto makeEntry = [&](const char *package) {
		const auto keyPackage = QByteArray(package);
		const auto objectId = DeriveClientKeyPackageObjectId(
			conversationId,
			*accountId,
			clientId,
			generation,
			telegramUserIdBinding,
			identity->credential,
			keyPackage,
			sha256);
		const auto authorization = objectId
			? CreateClientAuthorizationProof({
			.conversationId = conversationId,
			.authorizationId = *objectId,
			.accountId = *accountId,
			.clientId = clientId,
			.requestedAfterGeneration = generation,
			.createdAt = createdAt,
			.accountCredential = &identity->credential,
			.accountSigningPrivateKey = &identity->signingPrivateKey,
			.keyPackage = keyPackage,
		}, sha256)
			: std::nullopt;
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
				.objectId = *objectId,
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
	auto first = makeEntry("first-public-package");
	auto second = makeEntry("replacement-public-package");
	const auto observed = first
		? VerifyObservedClientKeyPackage({
			.bytes = first->publicationEnvelope.bytes,
			.observedTelegramPeerIdBinding = peerBinding,
			.observedSenderTelegramUserIdBinding = telegramUserIdBinding,
			.observedMessageId = 91,
		},
		conversationId,
		peerBinding,
		generation,
		createdAt,
		envelopeCodec,
		sha256)
		: VerifyObservedClientKeyPackageOutcome();
	const auto substitutedAuthor = first
		? VerifyObservedClientKeyPackage({
			.bytes = first->publicationEnvelope.bytes,
			.observedTelegramPeerIdBinding = peerBinding,
			.observedSenderTelegramUserIdBinding
				= telegramUserIdBinding + 1,
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
			.observedSenderTelegramUserIdBinding = telegramUserIdBinding,
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
		|| observed.verified->telegramUserIdBinding
			!= telegramUserIdBinding
		|| observed.verified->publication.authorization.clientId != clientId
		|| substitutedAuthor.status
			!= ObservedClientKeyPackageStatus::InvalidTelegramAuthorBinding
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
		ScenarioAtomicBlobRejectsOversizedFile,
		ScenarioConversationRecordKeyDerivation,
		ScenarioContentSyncBoundarySurvivesRestart,
		ScenarioControlObservationStateSurvivesRestart,
		ScenarioLegacyControlBoundaryMigrates,
		ScenarioContentStoreReloadFailureClearsPlaintext,
		ScenarioContentStoreAcceptsCarrierDuplicates,
		ScenarioContentStorePagesAndMigratesLegacyIndex,
		ScenarioFileTransferSurvivesRestart,
		ScenarioLegacyFileTransferPublishesManifestFirst,
		ScenarioConversationMetadataRoundTrip,
		ScenarioFreshnessTrustSurvivesRestart,
		ScenarioFreshnessResponseReplayIsPersistent,
		ScenarioPersistentDraftRoundTrip,
		ScenarioOutboxPlaintextCleanup,
		ScenarioSealedRetrySurvivesRestart,
		ScenarioCorruptionFailsClosed,
		ScenarioMlsStateTransaction,
		ScenarioMlsStateBindingAndCorruption,
		ScenarioMlsReceiptOutboxReconciliation,
		ScenarioObservedMlsReceiptCrashRecovery,
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
