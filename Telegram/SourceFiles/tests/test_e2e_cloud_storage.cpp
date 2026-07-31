/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "e2e_cloud/storage/aes_gcm_local_record_protector.h"
#include "e2e_cloud/storage/persistent_inbound_journal.h"
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

} // namespace

int main(int, char *[]) {
	for (const auto scenario : {
		ScenarioAeadProtection,
		ScenarioPersistentDraftRoundTrip,
		ScenarioSealedRetrySurvivesRestart,
		ScenarioCorruptionFailsClosed,
		ScenarioInboundJournalSurvivesRestart,
		ScenarioInboundJournalWriteFailureIsTransactional,
		ScenarioInboundJournalCorruptionFailsClosed,
	}) {
		if (const auto result = scenario()) {
			return result;
		}
	}
	return 0;
}
