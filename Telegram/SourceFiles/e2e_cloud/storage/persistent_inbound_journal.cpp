/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "e2e_cloud/storage/persistent_inbound_journal.h"

#include <openssl/crypto.h>

#include <algorithm>
#include <array>
#include <limits>
#include <set>
#include <utility>

namespace E2ECloud {
namespace {

inline constexpr auto kMagic = std::array<std::uint8_t, 8>{
	'T', 'D', 'E', '2', 'E', 'I', 'J', 'N',
};
inline constexpr auto kMaximumEntries = std::size_t(65536);
inline constexpr auto kEntrySize = 32 + 32 + 32 + 1;
inline constexpr auto kHeaderSize = 8 + 2 + 8 + 4;
inline constexpr auto kPurpose = "e2e-cloud-inbound-journal-v1";

void AppendUint16(QByteArray &result, std::uint16_t value) {
	result.append(char(value >> 8));
	result.append(char(value));
}

void AppendUint32(QByteArray &result, std::uint32_t value) {
	result.append(char(value >> 24));
	result.append(char(value >> 16));
	result.append(char(value >> 8));
	result.append(char(value));
}

void AppendUint64(QByteArray &result, std::uint64_t value) {
	for (auto shift = 56; shift >= 0; shift -= 8) {
		result.append(char(value >> shift));
	}
}

template <typename Array>
void AppendArray(QByteArray &result, const Array &value) {
	result.append(
		reinterpret_cast<const char*>(value.data()),
		value.size());
}

[[nodiscard]] std::uint16_t ReadUint16(const char *data) {
	const auto bytes = reinterpret_cast<const std::uint8_t*>(data);
	return (std::uint16_t(bytes[0]) << 8) | std::uint16_t(bytes[1]);
}

[[nodiscard]] std::uint32_t ReadUint32(const char *data) {
	const auto bytes = reinterpret_cast<const std::uint8_t*>(data);
	return (std::uint32_t(bytes[0]) << 24)
		| (std::uint32_t(bytes[1]) << 16)
		| (std::uint32_t(bytes[2]) << 8)
		| std::uint32_t(bytes[3]);
}

[[nodiscard]] std::uint64_t ReadUint64(const char *data) {
	auto result = std::uint64_t(0);
	for (auto i = 0; i != 8; ++i) {
		result = (result << 8) | std::uint8_t(data[i]);
	}
	return result;
}

template <typename Array>
void ReadArray(const char *data, Array &value) {
	std::copy_n(
		reinterpret_cast<const std::uint8_t*>(data),
		value.size(),
		value.begin());
}

void Cleanse(QByteArray &bytes) {
	if (!bytes.isEmpty()) {
		OPENSSL_cleanse(bytes.data(), bytes.size());
	}
	bytes.clear();
}

} // namespace

PersistentInboundJournal::PersistentInboundJournal(
		AtomicBlobStore &blobStore,
		const LocalRecordProtector &protector)
: _blobStore(blobStore)
, _protector(protector) {
}

InboundJournalLoadResult PersistentInboundJournal::load() {
	const auto stored = _blobStore.read();
	if (stored.status == BlobReadStatus::Missing) {
		_entries.clear();
		_revision = 0;
		_loaded = true;
		_storageError = false;
		return InboundJournalLoadResult::Missing;
	} else if (stored.status != BlobReadStatus::Found) {
		_storageError = true;
		return InboundJournalLoadResult::ReadFailed;
	}
	auto plaintext = _protector.open(QByteArray(kPurpose), stored.bytes);
	if (!plaintext) {
		_storageError = true;
		return InboundJournalLoadResult::AuthenticationFailed;
	}
	const auto fail = [&] {
		Cleanse(*plaintext);
		_storageError = true;
		return InboundJournalLoadResult::InvalidSnapshot;
	};
	if (plaintext->size() < kHeaderSize
		|| !std::equal(
			std::begin(kMagic),
			std::end(kMagic),
			reinterpret_cast<const std::uint8_t*>(plaintext->constData()))
		|| ReadUint16(plaintext->constData() + 8) != 1) {
		return fail();
	}
	const auto revision = ReadUint64(plaintext->constData() + 10);
	const auto count = ReadUint32(plaintext->constData() + 18);
	if (count > kMaximumEntries
		|| plaintext->size() != kHeaderSize + int(count) * kEntrySize) {
		return fail();
	}
	auto entries = std::vector<Entry>();
	entries.reserve(count);
	auto offset = kHeaderSize;
	for (auto i = std::uint32_t(0); i != count; ++i) {
		auto entry = Entry();
		ReadArray(
			plaintext->constData() + offset,
			entry.conversationId.bytes);
		offset += 32;
		ReadArray(plaintext->constData() + offset, entry.objectId.bytes);
		offset += 32;
		ReadArray(plaintext->constData() + offset, entry.payloadHash.bytes);
		offset += 32;
		const auto status = std::uint8_t((*plaintext)[offset++]);
		if (status > 1) {
			return fail();
		}
		entry.accepted = (status == 1);
		entries.push_back(entry);
	}
	if ((!entries.empty() && !revision) || !validEntries(entries)) {
		return fail();
	}
	Cleanse(*plaintext);
	_entries = std::move(entries);
	_revision = revision;
	_loaded = true;
	_storageError = false;
	return InboundJournalLoadResult::Loaded;
}

InboundJournalLookup PersistentInboundJournal::lookup(
		ConversationId conversationId,
		ObjectId objectId,
		Digest payloadHash) const {
	if (!_loaded || _storageError) {
		return InboundJournalLookup::StorageError;
	}
	const auto i = std::find_if(
		std::begin(_entries),
		std::end(_entries),
		[&](const Entry &entry) {
			return entry.conversationId == conversationId
				&& entry.objectId == objectId;
		});
	if (i == std::end(_entries)) {
		return InboundJournalLookup::Missing;
	} else if (i->payloadHash != payloadHash) {
		return InboundJournalLookup::ObjectIdConflict;
	}
	return i->accepted
		? InboundJournalLookup::Accepted
		: InboundJournalLookup::Pending;
}

bool PersistentInboundJournal::begin(const TransportEnvelope &envelope) {
	if (!_loaded
		|| _storageError
		|| !envelope.conversationId
		|| !envelope.objectId
		|| !envelope.payloadHash
		|| lookup(
			envelope.conversationId,
			envelope.objectId,
			envelope.payloadHash) != InboundJournalLookup::Missing
		|| _revision == std::numeric_limits<std::uint64_t>::max()) {
		return false;
	}
	auto entries = _entries;
	if (entries.size() == kMaximumEntries) {
		const auto accepted = std::find_if(
			std::begin(entries),
			std::end(entries),
			[](const Entry &entry) { return entry.accepted; });
		if (accepted == std::end(entries)) {
			return false;
		}
		entries.erase(accepted);
	}
	entries.push_back({
		.conversationId = envelope.conversationId,
		.objectId = envelope.objectId,
		.payloadHash = envelope.payloadHash,
		.accepted = false,
	});
	const auto revision = _revision + 1;
	if (!persist(entries, revision)) {
		return false;
	}
	_entries = std::move(entries);
	_revision = revision;
	return true;
}

bool PersistentInboundJournal::accept(
		ConversationId conversationId,
		ObjectId objectId) {
	if (!_loaded
		|| _storageError
		|| !conversationId
		|| !objectId
		|| _revision == std::numeric_limits<std::uint64_t>::max()) {
		return false;
	}
	auto entries = _entries;
	const auto i = std::find_if(
		std::begin(entries),
		std::end(entries),
		[&](const Entry &entry) {
			return entry.conversationId == conversationId
				&& entry.objectId == objectId;
		});
	if (i == std::end(entries) || i->accepted) {
		return false;
	}
	i->accepted = true;
	const auto revision = _revision + 1;
	if (!persist(entries, revision)) {
		return false;
	}
	_entries = std::move(entries);
	_revision = revision;
	return true;
}

bool PersistentInboundJournal::abort(
		ConversationId conversationId,
		ObjectId objectId) {
	if (!_loaded
		|| _storageError
		|| !conversationId
		|| !objectId
		|| _revision == std::numeric_limits<std::uint64_t>::max()) {
		return false;
	}
	auto entries = _entries;
	const auto i = std::find_if(
		std::begin(entries),
		std::end(entries),
		[&](const Entry &entry) {
			return entry.conversationId == conversationId
				&& entry.objectId == objectId;
		});
	if (i == std::end(entries) || i->accepted) {
		return false;
	}
	entries.erase(i);
	const auto revision = _revision + 1;
	if (!persist(entries, revision)) {
		return false;
	}
	_entries = std::move(entries);
	_revision = revision;
	return true;
}

std::size_t PersistentInboundJournal::size() const {
	return _entries.size();
}

std::uint64_t PersistentInboundJournal::revision() const {
	return _revision;
}

bool PersistentInboundJournal::persist(
		const std::vector<Entry> &entries,
		std::uint64_t revision) const {
	if (entries.size() > kMaximumEntries
		|| entries.size() > std::numeric_limits<std::uint32_t>::max()
		|| (!entries.empty() && !revision)
		|| !validEntries(entries)) {
		return false;
	}
	auto plaintext = QByteArray();
	plaintext.reserve(kHeaderSize + int(entries.size()) * kEntrySize);
	AppendArray(plaintext, kMagic);
	AppendUint16(plaintext, 1);
	AppendUint64(plaintext, revision);
	AppendUint32(plaintext, std::uint32_t(entries.size()));
	for (const auto &entry : entries) {
		AppendArray(plaintext, entry.conversationId.bytes);
		AppendArray(plaintext, entry.objectId.bytes);
		AppendArray(plaintext, entry.payloadHash.bytes);
		plaintext.append(char(entry.accepted ? 1 : 0));
	}
	auto protectedBytes = _protector.seal(
		QByteArray(kPurpose),
		plaintext);
	Cleanse(plaintext);
	if (!protectedBytes) {
		return false;
	}
	return _blobStore.writeAtomic(*protectedBytes);
}

bool PersistentInboundJournal::validEntries(
		const std::vector<Entry> &entries) {
	auto identifiers = std::set<std::pair<ConversationId, ObjectId>>();
	for (const auto &entry : entries) {
		if (!entry.conversationId || !entry.objectId || !entry.payloadHash) {
			return false;
		} else if (!identifiers.emplace(
				entry.conversationId,
				entry.objectId).second) {
			return false;
		}
	}
	return true;
}

} // namespace E2ECloud
