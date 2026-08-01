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

#include <gsl/util>

#include <openssl/crypto.h>

#include <QtCore/QDir>

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
inline constexpr auto kIndexEntrySize = 32 + 32;
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
		&& record.observedTelegramMessageId >= 0
		&& !record.plaintext.isEmpty()
		&& record.plaintext.size() <= kMaximumRecordPlaintextSize;
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

PersistentContentStore::~PersistentContentStore() {
	for (auto &record : _records) {
		Cleanse(record.plaintext);
	}
}

ContentStoreLoadResult PersistentContentStore::load() {
	if (!_conversationId || _recordsDirectory.isEmpty()) {
		return ContentStoreLoadResult::InvalidSnapshot;
	}
	const auto stored = _indexBlobStore.read();
	if (stored.status == BlobReadStatus::Missing) {
		for (auto &record : _records) {
			Cleanse(record.plaintext);
		}
		_records.clear();
		_entries.clear();
		_revision = 0;
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
		|| version != 1
		|| conversationId != _conversationId
		|| count > kMaximumRecords
		|| reader.bytes.size() - reader.offset
			!= int(count) * kIndexEntrySize
		|| (count && !revision)) {
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
		entries.push_back(entry);
	}
	Cleanse(*plaintext);
	auto records = std::vector<ProtectedContentRecord>();
	const auto recordsGuard = gsl::finally([&] {
		for (auto &record : records) {
			Cleanse(record.plaintext);
		}
	});
	records.reserve(entries.size());
	for (const auto &entry : entries) {
		const auto storedRecord = FileAtomicBlobStore(
			recordPath(entry.eventObjectId)).read();
		if (storedRecord.status != BlobReadStatus::Found) {
			return ContentStoreLoadResult::InvalidSnapshot;
		}
		auto recordBytes = _protector.open(
			recordPurpose(entry.eventObjectId),
			storedRecord.bytes);
		if (!recordBytes) {
			return ContentStoreLoadResult::AuthenticationFailed;
		}
		if (_sha256.digest(*recordBytes) != entry.recordHash) {
			Cleanse(*recordBytes);
			return ContentStoreLoadResult::AuthenticationFailed;
		}
		auto record = DecodeRecord(*recordBytes);
		Cleanse(*recordBytes);
		if (!record
			|| record->conversationId != _conversationId
			|| record->eventObjectId != entry.eventObjectId) {
			if (record) {
				Cleanse(record->plaintext);
			}
			return ContentStoreLoadResult::InvalidSnapshot;
		}
		records.push_back(std::move(*record));
	}
	for (auto &record : _records) {
		Cleanse(record.plaintext);
	}
	_records = std::move(records);
	_entries = std::move(entries);
	_revision = revision;
	_loaded = true;
	return ContentStoreLoadResult::Loaded;
}

ContentStoreAppendResult PersistentContentStore::append(
		ProtectedContentRecord record) {
	const auto guard = gsl::finally([&] {
		Cleanse(record.plaintext);
	});
	if (!_loaded
		|| record.conversationId != _conversationId
		|| !ValidRecord(record)) {
		return ContentStoreAppendResult::InvalidRecord;
	}
	const auto existing = std::find_if(
		begin(_records),
		end(_records),
		[&](const ProtectedContentRecord &value) {
			return value.eventObjectId == record.eventObjectId;
		});
	if (existing != end(_records)) {
		return (*existing == record)
			? ContentStoreAppendResult::AlreadyStored
			: ContentStoreAppendResult::Conflict;
	} else if (_records.size() == kMaximumRecords
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
	});
	const auto revision = _revision + 1;
	if (!persistIndex(entries, revision)) {
		return ContentStoreAppendResult::PersistenceFailed;
	}
	_entries = std::move(entries);
	_records.push_back(std::move(record));
	_revision = revision;
	return ContentStoreAppendResult::Stored;
}

std::optional<ProtectedContentRecord> PersistentContentStore::record(
		ObjectId eventObjectId) const {
	const auto i = std::find_if(
		begin(_records),
		end(_records),
		[&](const ProtectedContentRecord &record) {
			return record.eventObjectId == eventObjectId;
		});
	return (i != end(_records))
		? std::optional<ProtectedContentRecord>(*i)
		: std::nullopt;
}

const std::vector<ProtectedContentRecord>
		&PersistentContentStore::records() const {
	return _records;
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
	AppendUint16(plaintext, 1);
	AppendArray(plaintext, _conversationId.bytes);
	AppendUint64(plaintext, revision);
	AppendUint32(plaintext, std::uint32_t(entries.size()));
	for (const auto &entry : entries) {
		if (!entry.eventObjectId || !entry.recordHash) {
			Cleanse(plaintext);
			return false;
		}
		AppendArray(plaintext, entry.eventObjectId.bytes);
		AppendArray(plaintext, entry.recordHash.bytes);
	}
	const auto protectedBytes = _protector.seal(
		QByteArray(kIndexPurpose),
		plaintext);
	Cleanse(plaintext);
	return protectedBytes && _indexBlobStore.writeAtomic(*protectedBytes);
}

} // namespace E2ECloud
