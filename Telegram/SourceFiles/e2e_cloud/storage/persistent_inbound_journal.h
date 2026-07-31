/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#pragma once

#include "e2e_cloud/protocol/inbound_envelope_processor.h"
#include "e2e_cloud/storage/local_storage.h"

#include <cstdint>
#include <vector>

namespace E2ECloud {

enum class InboundJournalLoadResult {
	Loaded,
	Missing,
	ReadFailed,
	AuthenticationFailed,
	InvalidSnapshot,
};

class PersistentInboundJournal final : public InboundEnvelopeJournal {
public:
	PersistentInboundJournal(
		AtomicBlobStore &blobStore,
		const LocalRecordProtector &protector);

	[[nodiscard]] InboundJournalLoadResult load();
	[[nodiscard]] InboundJournalLookup lookup(
		ConversationId conversationId,
		ObjectId objectId,
		Digest payloadHash) const override;
	bool begin(const TransportEnvelope &envelope) override;
	bool accept(
		ConversationId conversationId,
		ObjectId objectId) override;
	bool abort(
		ConversationId conversationId,
		ObjectId objectId) override;

	[[nodiscard]] std::size_t size() const;
	[[nodiscard]] std::uint64_t revision() const;

private:
	struct Entry {
		ConversationId conversationId;
		ObjectId objectId;
		Digest payloadHash;
		bool accepted = false;
	};

	[[nodiscard]] bool persist(
		const std::vector<Entry> &entries,
		std::uint64_t revision) const;
	[[nodiscard]] static bool validEntries(const std::vector<Entry> &entries);

	AtomicBlobStore &_blobStore;
	const LocalRecordProtector &_protector;
	std::vector<Entry> _entries;
	std::uint64_t _revision = 0;
	bool _loaded = false;
	bool _storageError = false;

};

} // namespace E2ECloud
