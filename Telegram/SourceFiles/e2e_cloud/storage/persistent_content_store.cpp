/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "e2e_cloud/storage/persistent_content_store.h"

#include "e2e_cloud/core/interfaces.h"
#include "e2e_cloud/identity/account_identity.h"
#include "e2e_cloud/storage/file_atomic_blob_store.h"

#include <openssl/crypto.h>

#include <QtCore/QDir>
#include <QtCore/QFileInfo>
#include <QtCore/QScopeGuard>

#include <algorithm>
#include <array>
#include <limits>
#include <set>
#include <utility>

namespace E2ECloud {
namespace {

inline constexpr auto kIndexMagic = std::array<std::uint8_t, 8>{
	'T', 'D', 'E', '2', 'E', 'C', 'I', 'X',
};
inline constexpr auto kRecordMagic = std::array<std::uint8_t, 8>{
	'T', 'D', 'E', '2', 'E', 'C', 'R', 'D',
};
inline constexpr auto kIndexPurpose = "e2e-cloud-content-index-v1";
inline constexpr auto kMaximumRecords = std::size_t(1'000'000);
inline constexpr auto kMaximumRecordPlaintextSize = 16 * 1024 * 1024;
inline constexpr auto kIndexHeaderSize = 8 + 2 + 32 + 8 + 4;
inline constexpr auto kIndexEntrySizeV1 = 32 + 32;
inline constexpr auto kIndexEntrySizeV2 = 32 + 32 + 2 + 8;
inline constexpr auto kIndexEntrySize = 32 + 32 + 2 + 8 + 8;
inline constexpr auto kRecordHeaderSize = 8 + 2 + 32 + 32 + 32 + 2
	+ 8 + 32 + 16 + 8 + 8 + 4;

struct Reader {
	const QByteArray &bytes;
	int offset = 0;
};

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
		int(value.size()));
}

[[nodiscard]] bool ReadUint16(Reader &reader, std::uint16_t &value) {
	if (reader.bytes.size() - reader.offset < 2) {
		return false;
	}
	const auto data = reinterpret_cast<const std::uint8_t*>(
		reader.bytes.constData() + reader.offset);
	value = (std::uint16_t(data[0]) << 8) | std::uint16_t(data[1]);
	reader.offset += 2;
	return true;
}

[[nodiscard]] bool ReadUint32(Reader &reader, std::uint32_t &value) {
	if (reader.bytes.size() - reader.offset < 4) {
		return false;
	}
	const auto data = reinterpret_cast<const std::uint8_t*>(
		reader.bytes.constData() + reader.offset);
	value = (std::uint32_t(data[0]) << 24)
		| (std::uint32_t(data[1]) << 16)
		| (std::uint32_t(data[2]) << 8)
		| std::uint32_t(data[3]);
	reader.offset += 4;
	return true;
}

[[nodiscard]] bool ReadUint64(Reader &reader, std::uint64_t &value) {
	if (reader.bytes.size() - reader.offset < 8) {
		return false;
	}
	const auto data = reinterpret_cast<const std::uint8_t*>(
		reader.bytes.constData() + reader.offset);
	value = 0;
	for (auto i = 0; i != 8; ++i) {
		value = (value << 8) | std::uint64_t(data[i]);
	}
	reader.offset += 8;
	return true;
}

template <typename Array>
[[nodiscard]] bool ReadArray(Reader &reader, Array &value) {
	const auto size = int(value.size());
	if (reader.bytes.size() - reader.offset < size) {
		return false;
	}
	std::copy_n(
		reinterpret_cast<const std::uint8_t*>(
			reader.bytes.constData() + reader.offset),
		size,
		value.data());
	reader.offset += size;
	return true;
}

void Cleanse(QByteArray &bytes) {
	if (!bytes.isEmpty()) {
		OPENSSL_cleanse(bytes.data(), bytes.size());
	}
	bytes.clear();
}

[[nodiscard]] bool ValidKind(ObjectKind kind) {
	return kind == ObjectKind::EncryptedMessageBody
		|| kind == ObjectKind::EncryptedFileManifest;
}

[[nodiscard]] bool ValidRecord(const ProtectedContentRecord &record) {
	return record.conversationId
		&& record.eventObjectId
		&& record.contentObjectId
		&& record.eventObjectId != record.contentObjectId
		&& ValidKind(record.objectKind)
		&& record.groupGeneration
		&& record.senderAccountId
		&& record.senderClientId
		&& record.unixTime
		&& record.unixTime
			<= std::uint64_t(std::numeric_limits<std::int64_t>::max())
		&& record.observedTelegramMessageId >= 0
		&& !record.plaintext.isEmpty()
		&& record.plaintext.size() <= kMaximumRecordPlaintextSize;
}

[[nodiscard]] bool SameProtectedContent(
		const ProtectedContentRecord &a,
		const ProtectedContentRecord &b) {
	return a.conversationId == b.conversationId
		&& a.eventObjectId == b.eventObjectId
		&& a.contentObjectId == b.contentObjectId
		&& a.objectKind == b.objectKind
		&& a.groupGeneration == b.groupGeneration
		&& a.senderAccountId == b.senderAccountId
		&& a.senderClientId == b.senderClientId
		&& a.unixTime == b.unixTime
		&& a.plaintext == b.plaintext;
}

[[nodiscard]] std::int64_t EarliestObservedMessageId(
		std::int64_t a,
		std::int64_t b) {
	return (a <= 0)
		? b
		: (b <= 0)
		? a
		: std::min(a, b);
}

[[nodiscard]] std::optional<QByteArray> EncodeRecord(
		const ProtectedContentRecord &record) {
	if (!ValidRecord(record)) {
		return std::nullopt;
	}
	auto result = QByteArray();
	result.reserve(kRecordHeaderSize + record.plaintext.size());
	AppendArray(result, kRecordMagic);
	AppendUint16(result, 1);
	AppendArray(result, record.conversationId.bytes);
	AppendArray(result, record.eventObjectId.bytes);
	AppendArray(result, record.contentObjectId.bytes);
	AppendUint16(result, std::uint16_t(record.objectKind));
	AppendUint64(result, record.groupGeneration);
	AppendArray(result, record.senderAccountId.bytes);
	AppendArray(result, record.senderClientId.bytes);
	AppendUint64(result, record.unixTime);
	AppendUint64(
		result,
		std::uint64_t(record.observedTelegramMessageId));
	AppendUint32(result, std::uint32_t(record.plaintext.size()));
	result.append(record.plaintext);
	return result;
}

[[nodiscard]] std::optional<ProtectedContentRecord> DecodeRecord(
		const QByteArray &bytes) {
	if (bytes.size() <= kRecordHeaderSize
		|| bytes.size() > kRecordHeaderSize + kMaximumRecordPlaintextSize) {
		return std::nullopt;
	}
	auto reader = Reader{ bytes };
	auto magic = std::array<std::uint8_t, 8>();
	auto version = std::uint16_t();
	auto kind = std::uint16_t();
	auto observedMessageId = std::uint64_t();
	auto size = std::uint32_t();
	auto result = ProtectedContentRecord();
	if (!ReadArray(reader, magic)
		|| !ReadUint16(reader, version)
		|| !ReadArray(reader, result.conversationId.bytes)
		|| !ReadArray(reader, result.eventObjectId.bytes)
		|| !ReadArray(reader, result.contentObjectId.bytes)
		|| !ReadUint16(reader, kind)
		|| !ReadUint64(reader, result.groupGeneration)
		|| !ReadArray(reader, result.senderAccountId.bytes)
		|| !ReadArray(reader, result.senderClientId.bytes)
		|| !ReadUint64(reader, result.unixTime)
		|| !ReadUint64(reader, observedMessageId)
		|| !ReadUint32(reader, size)
		|| size > kMaximumRecordPlaintextSize
		|| observedMessageId
			> std::uint64_t(std::numeric_limits<std::int64_t>::max())
		|| reader.bytes.size() - reader.offset != int(size)
		|| magic != kRecordMagic
		|| version != 1) {
		return std::nullopt;
	}
	result.objectKind = ObjectKind(kind);
	result.observedTelegramMessageId = std::int64_t(observedMessageId);
	result.plaintext = QByteArray(
		reader.bytes.constData() + reader.offset,
		int(size));
	return ValidRecord(result)
		? std::optional<ProtectedContentRecord>(std::move(result))
		: std::nullopt;
}

} // namespace

PersistentContentStore::PersistentContentStore(
		ConversationId conversationId,
		QString recordsDirectory,
		AtomicBlobStore &indexBlobStore,
		const LocalRecordProtector &protector,
		const Sha256Provider &sha256)
: _conversationId(conversationId)
, _recordsDirectory(std::move(recordsDirectory))
, _indexBlobStore(indexBlobStore)
, _protector(protector)
, _sha256(sha256) {
}

PersistentContentStore::~PersistentContentStore() = default;

ContentStoreLoadResult PersistentContentStore::load() {
	_entries.clear();
	_orderedEntries.clear();
	_revision = 0;
	_loaded = false;
	if (!_conversationId || _recordsDirectory.isEmpty()) {
		return ContentStoreLoadResult::InvalidSnapshot;
	}
	const auto stored = _indexBlobStore.read();
	if (stored.status == BlobReadStatus::Missing) {
		_loaded = true;
		return ContentStoreLoadResult::Missing;
	} else if (stored.status != BlobReadStatus::Found) {
		return ContentStoreLoadResult::ReadFailed;
	}
	auto plaintext = _protector.open(QByteArray(kIndexPurpose), stored.bytes);
	if (!plaintext) {
		return ContentStoreLoadResult::AuthenticationFailed;
	}
	const auto fail = [&] {
		Cleanse(*plaintext);
		return ContentStoreLoadResult::InvalidSnapshot;
	};
	auto reader = Reader{ *plaintext };
	auto magic = std::array<std::uint8_t, 8>();
	auto version = std::uint16_t();
	auto conversationId = ConversationId();
	auto revision = std::uint64_t();
	auto count = std::uint32_t();
	if (!ReadArray(reader, magic)
		|| !ReadUint16(reader, version)
		|| !ReadArray(reader, conversationId.bytes)
		|| !ReadUint64(reader, revision)
		|| !ReadUint32(reader, count)
		|| magic != kIndexMagic
		|| (version != 1 && version != 2 && version != 3)
		|| conversationId != _conversationId
		|| count > kMaximumRecords
		|| (count && !revision)) {
		return fail();
	}
	const auto entrySize = (version == 1)
		? kIndexEntrySizeV1
		: (version == 2)
		? kIndexEntrySizeV2
		: kIndexEntrySize;
	if (reader.bytes.size() - reader.offset != int(count) * entrySize) {
		return fail();
	}
	auto entries = std::vector<IndexEntry>();
	auto identifiers = std::set<ObjectId>();
	entries.reserve(count);
	for (auto index = std::uint32_t(); index != count; ++index) {
		auto entry = IndexEntry();
		if (!ReadArray(reader, entry.eventObjectId.bytes)
			|| !ReadArray(reader, entry.recordHash.bytes)
			|| !entry.eventObjectId
			|| !entry.recordHash
			|| !identifiers.emplace(entry.eventObjectId).second) {
			return fail();
		}
		if (version >= 2) {
			auto kind = std::uint16_t();
			if (!ReadUint16(reader, kind)
				|| !ReadUint64(reader, entry.unixTime)) {
				return fail();
			}
			entry.objectKind = ObjectKind(kind);
			if (!ValidKind(entry.objectKind)
				|| !entry.unixTime
				|| entry.unixTime > std::uint64_t(
					std::numeric_limits<std::int64_t>::max())
				|| !QFileInfo(recordPath(entry.eventObjectId)).isFile()) {
				return fail();
			}
		}
		if (version == 3) {
			auto observedMessageId = std::uint64_t();
			if (!ReadUint64(reader, observedMessageId)
				|| observedMessageId > std::uint64_t(
					std::numeric_limits<std::int64_t>::max())) {
				return fail();
			}
			entry.observedTelegramMessageId
				= std::int64_t(observedMessageId);
		}
		entries.push_back(entry);
	}
	Cleanse(*plaintext);
	if (version != 3) {
		for (auto &entry : entries) {
			auto record = readRecord(entry);
			if (!record) {
				return ContentStoreLoadResult::InvalidSnapshot;
			}
			if (version == 1) {
				entry.objectKind = record->objectKind;
				entry.unixTime = record->unixTime;
			}
			entry.observedTelegramMessageId
				= (record->objectKind == ObjectKind::EncryptedFileManifest
					&& record->observedTelegramMessageId > 0)
				? 1
				: record->observedTelegramMessageId;
			Cleanse(record->plaintext);
		}
	}
	_entries = std::move(entries);
	_revision = revision;
	_loaded = true;
	rebuildOrderedEntries();
	if (version != 3) {
		(void)persistIndex(_entries, _revision);
	}
	return ContentStoreLoadResult::Loaded;
}

ContentStoreAppendResult PersistentContentStore::append(
		ProtectedContentRecord record) {
	const auto guard = qScopeGuard([&] {
		Cleanse(record.plaintext);
	});
	if (!_loaded
		|| record.conversationId != _conversationId
		|| !ValidRecord(record)) {
		return ContentStoreAppendResult::InvalidRecord;
	}
	const auto existing = std::find_if(
		begin(_entries),
		end(_entries),
		[&](const IndexEntry &value) {
			return value.eventObjectId == record.eventObjectId;
		});
	if (existing != end(_entries)) {
		auto stored = readRecord(*existing);
		const auto storedGuard = qScopeGuard([&] {
			if (stored) {
				Cleanse(stored->plaintext);
			}
		});
		if (!stored) {
			return ContentStoreAppendResult::PersistenceFailed;
		}
		if (!SameProtectedContent(*stored, record)) {
			return ContentStoreAppendResult::Conflict;
		}
		const auto observedMessageId = EarliestObservedMessageId(
			stored->observedTelegramMessageId,
			record.observedTelegramMessageId);
		if (observedMessageId == stored->observedTelegramMessageId) {
			return ContentStoreAppendResult::AlreadyStored;
		} else if (_revision == std::numeric_limits<std::uint64_t>::max()) {
			return ContentStoreAppendResult::PersistenceFailed;
		}
		auto entries = _entries;
		entries[std::size_t(existing - begin(_entries))]
			.observedTelegramMessageId = observedMessageId;
		const auto revision = _revision + 1;
		if (!persistIndex(entries, revision)) {
			return ContentStoreAppendResult::PersistenceFailed;
		}
		_entries = std::move(entries);
		_revision = revision;
		return ContentStoreAppendResult::AlreadyStored;
	} else if (_entries.size() == kMaximumRecords
		|| _revision == std::numeric_limits<std::uint64_t>::max()) {
		return ContentStoreAppendResult::PersistenceFailed;
	}
	auto encoded = EncodeRecord(record);
	if (!encoded) {
		return ContentStoreAppendResult::InvalidRecord;
	}
	const auto recordHash = _sha256.digest(*encoded);
	auto protectedBytes = _protector.seal(
		recordPurpose(record.eventObjectId),
		*encoded);
	Cleanse(*encoded);
	if (!recordHash
		|| !protectedBytes
		|| !FileAtomicBlobStore(recordPath(record.eventObjectId))
			.writeAtomic(*protectedBytes)) {
		return ContentStoreAppendResult::PersistenceFailed;
	}
	auto entries = _entries;
	entries.push_back({
		.eventObjectId = record.eventObjectId,
		.recordHash = recordHash,
		.objectKind = record.objectKind,
		.unixTime = record.unixTime,
		.observedTelegramMessageId = record.observedTelegramMessageId,
	});
	const auto revision = _revision + 1;
	if (!persistIndex(entries, revision)) {
		return ContentStoreAppendResult::PersistenceFailed;
	}
	_entries = std::move(entries);
	const auto newIndex = _entries.size() - 1;
	const auto position = std::lower_bound(
		begin(_orderedEntries),
		end(_orderedEntries),
		newIndex,
		[&](std::size_t a, std::size_t b) {
			const auto &left = _entries[a];
			const auto &right = _entries[b];
			return (left.unixTime != right.unixTime)
				? left.unixTime < right.unixTime
				: left.eventObjectId < right.eventObjectId;
		});
	_orderedEntries.insert(position, newIndex);
	_revision = revision;
	return ContentStoreAppendResult::Stored;
}

std::optional<ProtectedContentRecord> PersistentContentStore::record(
		ObjectId eventObjectId) const {
	const auto i = std::find_if(
		begin(_entries),
		end(_entries),
		[&](const IndexEntry &entry) {
			return entry.eventObjectId == eventObjectId;
		});
	return (i != end(_entries)) ? readRecord(*i) : std::nullopt;
}

std::vector<ProtectedContentRecord> PersistentContentStore::records(
		std::size_t offset,
		std::size_t limit,
		std::optional<ObjectKind> kind) const {
	auto result = std::vector<ProtectedContentRecord>();
	if (!_loaded || !limit || (kind && !ValidKind(*kind))) {
		return result;
	}
	result.reserve(std::min(limit, _entries.size()));
	auto skipped = std::size_t();
	for (const auto index : _orderedEntries) {
		const auto &entry = _entries[index];
		if (kind && entry.objectKind != *kind) {
			continue;
		} else if (skipped != offset) {
			++skipped;
			continue;
		}
		auto value = readRecord(entry);
		if (!value) {
			for (auto &record : result) {
				Cleanse(record.plaintext);
			}
			return {};
		}
		result.push_back(std::move(*value));
		if (result.size() == limit) {
			break;
		}
	}
	return result;
}

std::size_t PersistentContentStore::size(
		std::optional<ObjectKind> kind) const {
	return kind
		? std::count_if(
			begin(_entries),
			end(_entries),
			[&](const IndexEntry &entry) {
				return entry.objectKind == *kind;
			})
		: _entries.size();
}

std::uint64_t PersistentContentStore::revision() const {
	return _revision;
}

bool PersistentContentStore::loaded() const {
	return _loaded;
}

QString PersistentContentStore::recordPath(ObjectId eventObjectId) const {
	const auto bytes = QByteArray(
		reinterpret_cast<const char*>(eventObjectId.bytes.data()),
		int(eventObjectId.bytes.size()));
	return QDir(_recordsDirectory).filePath(
		QString::fromLatin1(bytes.toHex())
		+ QString::fromLatin1(".content"));
}

QByteArray PersistentContentStore::recordPurpose(
		ObjectId eventObjectId) const {
	auto result = QByteArray("e2e-cloud-content-record-v1");
	result.append(char(0));
	AppendArray(result, _conversationId.bytes);
	AppendArray(result, eventObjectId.bytes);
	return result;
}

std::optional<ProtectedContentRecord> PersistentContentStore::readRecord(
		const IndexEntry &entry) const {
	const auto stored = FileAtomicBlobStore(
		recordPath(entry.eventObjectId)).read();
	if (stored.status != BlobReadStatus::Found) {
		return std::nullopt;
	}
	auto recordBytes = _protector.open(
		recordPurpose(entry.eventObjectId),
		stored.bytes);
	if (!recordBytes) {
		return std::nullopt;
	}
	const auto bytesGuard = qScopeGuard([&] {
		Cleanse(*recordBytes);
	});
	if (_sha256.digest(*recordBytes) != entry.recordHash) {
		return std::nullopt;
	}
	auto record = DecodeRecord(*recordBytes);
	if (!record
		|| record->conversationId != _conversationId
		|| record->eventObjectId != entry.eventObjectId
		|| (entry.unixTime && record->unixTime != entry.unixTime)
		|| (entry.unixTime && record->objectKind != entry.objectKind)) {
		if (record) {
			Cleanse(record->plaintext);
		}
		return std::nullopt;
	}
	if (entry.observedTelegramMessageId) {
		record->observedTelegramMessageId
			= *entry.observedTelegramMessageId;
	}
	return record;
}

void PersistentContentStore::rebuildOrderedEntries() {
	_orderedEntries.clear();
	_orderedEntries.reserve(_entries.size());
	for (auto index = std::size_t(); index != _entries.size(); ++index) {
		_orderedEntries.push_back(index);
	}
	std::sort(
		begin(_orderedEntries),
		end(_orderedEntries),
		[&](std::size_t a, std::size_t b) {
			const auto &left = _entries[a];
			const auto &right = _entries[b];
			return (left.unixTime != right.unixTime)
				? left.unixTime < right.unixTime
				: left.eventObjectId < right.eventObjectId;
		});
}

bool PersistentContentStore::persistIndex(
		const std::vector<IndexEntry> &entries,
		std::uint64_t revision) const {
	if (entries.size() > kMaximumRecords
		|| entries.size() > std::numeric_limits<std::uint32_t>::max()
		|| (!entries.empty() && !revision)) {
		return false;
	}
	auto plaintext = QByteArray();
	plaintext.reserve(
		kIndexHeaderSize + int(entries.size()) * kIndexEntrySize);
	AppendArray(plaintext, kIndexMagic);
	AppendUint16(plaintext, 3);
	AppendArray(plaintext, _conversationId.bytes);
	AppendUint64(plaintext, revision);
	AppendUint32(plaintext, std::uint32_t(entries.size()));
	for (const auto &entry : entries) {
		if (!entry.eventObjectId
			|| !entry.recordHash
			|| !ValidKind(entry.objectKind)
			|| !entry.unixTime
			|| !entry.observedTelegramMessageId
			|| *entry.observedTelegramMessageId < 0
			|| entry.unixTime > std::uint64_t(
				std::numeric_limits<std::int64_t>::max())) {
			Cleanse(plaintext);
			return false;
		}
		AppendArray(plaintext, entry.eventObjectId.bytes);
		AppendArray(plaintext, entry.recordHash.bytes);
		AppendUint16(plaintext, std::uint16_t(entry.objectKind));
		AppendUint64(plaintext, entry.unixTime);
		AppendUint64(
			plaintext,
			std::uint64_t(*entry.observedTelegramMessageId));
	}
	const auto protectedBytes = _protector.seal(
		QByteArray(kIndexPurpose),
		plaintext);
	Cleanse(plaintext);
	return protectedBytes && _indexBlobStore.writeAtomic(*protectedBytes);
}

} // namespace E2ECloud
