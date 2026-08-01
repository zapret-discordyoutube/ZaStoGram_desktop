/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "e2e_cloud/storage/persistent_outbox.h"

#include <algorithm>
#include <array>
#include <limits>
#include <set>
#include <utility>

namespace E2ECloud {
namespace {

inline constexpr auto kMagic = std::array<std::uint8_t, 8>{
	'T', 'D', 'E', '2', 'E', 'O', 'B', 'X',
};
inline constexpr auto kPurpose = "TDE2E/local-outbox/v1";
inline constexpr auto kMaximumItems = 4096;
inline constexpr auto kMaximumDraftSize = 4 * 1024 * 1024;
inline constexpr auto kMaximumAuthenticatedDataSize = 1024 * 1024;
inline constexpr auto kMaximumSealedEnvelopeSize = 18 * 1024 * 1024;
inline constexpr auto kMaximumSnapshotSize = 128 * 1024 * 1024;

struct Snapshot {
	std::uint64_t revision = 0;
	std::vector<OutboxItem> items;
};

struct Reader {
	const QByteArray &bytes;
	int offset = 0;
};

void AppendUint8(QByteArray &result, std::uint8_t value) {
	result.append(char(value));
}

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

void AppendBytes(QByteArray &result, const QByteArray &value) {
	AppendUint32(result, std::uint32_t(value.size()));
	result.append(value);
}

[[nodiscard]] bool ReadUint8(Reader &reader, std::uint8_t &value) {
	if (reader.offset == reader.bytes.size()) {
		return false;
	}
	value = std::uint8_t(reader.bytes[reader.offset++]);
	return true;
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

[[nodiscard]] bool ReadBytes(
		Reader &reader,
		int maximumSize,
		QByteArray &value) {
	auto size = std::uint32_t();
	if (!ReadUint32(reader, size)
		|| size > std::uint32_t(maximumSize)
		|| reader.bytes.size() - reader.offset < int(size)) {
		return false;
	}
	value = QByteArray(reader.bytes.constData() + reader.offset, int(size));
	reader.offset += int(size);
	return true;
}

[[nodiscard]] bool ValidItem(const OutboxItem &item) {
	if (!item.draft.conversationId || !item.draft.objectId) {
		return false;
	} else if (item.stage == OutboxItemStage::Draft) {
		return !item.sealed
			&& (!item.draft.plaintext.isEmpty()
				|| !item.draft.authenticatedData.isEmpty())
			&& item.draft.plaintext.size() <= kMaximumDraftSize
			&& item.draft.authenticatedData.size()
				<= kMaximumAuthenticatedDataSize;
	} else if (item.stage == OutboxItemStage::Sealed) {
		return item.sealed
			&& item.draft.plaintext.isEmpty()
			&& item.draft.authenticatedData.isEmpty()
			&& item.sealed->conversationId == item.draft.conversationId
			&& item.sealed->objectId == item.draft.objectId
			&& !item.sealed->bytes.isEmpty()
			&& item.sealed->bytes.size() <= kMaximumSealedEnvelopeSize;
	}
	return false;
}

[[nodiscard]] std::optional<QByteArray> EncodeSnapshot(
		const std::vector<OutboxItem> &items,
		std::uint64_t revision) {
	if (!revision || items.size() > kMaximumItems) {
		return std::nullopt;
	}
	auto encodedSize = std::uint64_t(8 + 2 + 8 + 4);
	for (const auto &item : items) {
		if (!ValidItem(item)) {
			return std::nullopt;
		}
		encodedSize += 32 + 32 + 1 + 4 + item.draft.plaintext.size()
			+ 4 + item.draft.authenticatedData.size() + 32 + 32 + 4
			+ (item.sealed ? item.sealed->bytes.size() : 0);
		if (encodedSize > kMaximumSnapshotSize) {
			return std::nullopt;
		}
	}
	auto result = QByteArray();
	result.reserve(int(encodedSize));
	result.append(
		reinterpret_cast<const char*>(kMagic.data()),
		kMagic.size());
	AppendUint16(result, 1);
	AppendUint64(result, revision);
	AppendUint32(result, std::uint32_t(items.size()));
	for (const auto &item : items) {
		AppendArray(result, item.draft.conversationId.bytes);
		AppendArray(result, item.draft.objectId.bytes);
		AppendUint8(result, std::uint8_t(item.stage));
		AppendBytes(result, item.draft.plaintext);
		AppendBytes(result, item.draft.authenticatedData);
		if (item.sealed) {
			AppendArray(result, item.sealed->conversationId.bytes);
			AppendArray(result, item.sealed->objectId.bytes);
			AppendBytes(result, item.sealed->bytes);
		} else {
			AppendArray(result, ConversationId().bytes);
			AppendArray(result, ObjectId().bytes);
			AppendUint32(result, 0);
		}
	}
	return result;
}

[[nodiscard]] std::optional<Snapshot> DecodeSnapshot(
		const QByteArray &bytes) {
	if (bytes.size() < 8 + 2 + 8 + 4
		|| bytes.size() > kMaximumSnapshotSize) {
		return std::nullopt;
	}
	auto reader = Reader{ bytes };
	auto magic = std::array<std::uint8_t, 8>();
	auto version = std::uint16_t();
	auto count = std::uint32_t();
	auto result = Snapshot();
	if (!ReadArray(reader, magic)
		|| !ReadUint16(reader, version)
		|| !ReadUint64(reader, result.revision)
		|| !ReadUint32(reader, count)
		|| magic != kMagic
		|| version != 1
		|| !result.revision
		|| count > kMaximumItems) {
		return std::nullopt;
	}
	result.items.reserve(count);
	auto objectIds = std::set<ObjectId>();
	for (auto index = std::uint32_t(); index != count; ++index) {
		auto item = OutboxItem();
		auto stage = std::uint8_t();
		auto sealed = EncodedEnvelope();
		if (!ReadArray(reader, item.draft.conversationId.bytes)
			|| !ReadArray(reader, item.draft.objectId.bytes)
			|| !ReadUint8(reader, stage)
			|| !ReadBytes(
				reader,
				kMaximumDraftSize,
				item.draft.plaintext)
			|| !ReadBytes(
				reader,
				kMaximumAuthenticatedDataSize,
				item.draft.authenticatedData)
			|| !ReadArray(reader, sealed.conversationId.bytes)
			|| !ReadArray(reader, sealed.objectId.bytes)
			|| !ReadBytes(
				reader,
				kMaximumSealedEnvelopeSize,
				sealed.bytes)
			|| stage > std::uint8_t(OutboxItemStage::Sealed)) {
			return std::nullopt;
		}
		item.stage = OutboxItemStage(stage);
		if (item.stage == OutboxItemStage::Sealed) {
			item.sealed = std::move(sealed);
		} else if (sealed.conversationId
			|| sealed.objectId
			|| !sealed.bytes.isEmpty()) {
			return std::nullopt;
		}
		if (!ValidItem(item) || !objectIds.emplace(item.draft.objectId).second) {
			return std::nullopt;
		}
		result.items.push_back(std::move(item));
	}
	return (reader.offset == bytes.size())
		? std::optional<Snapshot>(std::move(result))
		: std::nullopt;
}

} // namespace

PersistentOutboxStore::PersistentOutboxStore(
		AtomicBlobStore &blobStore,
		const LocalRecordProtector &protector)
: _blobStore(blobStore)
, _protector(protector) {
}

PersistentOutboxLoadResult PersistentOutboxStore::load() {
	_items.clear();
	_revision = 0;
	_loaded = false;
	const auto stored = _blobStore.read();
	if (stored.status == BlobReadStatus::Error) {
		return PersistentOutboxLoadResult::StorageError;
	} else if (stored.status == BlobReadStatus::Missing) {
		_items.clear();
		_revision = 0;
		_loaded = true;
		return PersistentOutboxLoadResult::Empty;
	}
	auto opened = _protector.open(QByteArray(kPurpose), stored.bytes);
	if (!opened) {
		return PersistentOutboxLoadResult::AuthenticationFailed;
	}
	const auto snapshot = DecodeSnapshot(*opened);
	std::fill_n(opened->data(), opened->size(), char(0));
	if (!snapshot) {
		return PersistentOutboxLoadResult::InvalidSnapshot;
	}
	_items = snapshot->items;
	_revision = snapshot->revision;
	_loaded = true;
	return PersistentOutboxLoadResult::Loaded;
}

bool PersistentOutboxStore::loaded() const {
	return _loaded;
}

std::uint64_t PersistentOutboxStore::revision() const {
	return _revision;
}

int PersistentOutboxStore::size() const {
	return int(_items.size());
}

std::optional<OutboxItem> PersistentOutboxStore::item(
		ObjectId objectId) const {
	const auto i = std::find_if(
		std::begin(_items),
		std::end(_items),
		[&](const OutboxItem &item) {
			return item.draft.objectId == objectId;
		});
	return (i == std::end(_items))
		? std::nullopt
		: std::optional<OutboxItem>(*i);
}

bool PersistentOutboxStore::append(PendingMessage message) {
	if (!_loaded
		|| _revision == std::numeric_limits<std::uint64_t>::max()
		|| contains(message.objectId)) {
		return false;
	}
	auto next = _items;
	next.push_back({
		.draft = std::move(message),
		.stage = OutboxItemStage::Draft,
		.sealed = std::nullopt,
	});
	const auto revision = _revision + 1;
	if (!validItem(next.back()) || !persist(next, revision)) {
		return false;
	}
	_items = std::move(next);
	_revision = revision;
	return true;
}

bool PersistentOutboxStore::appendSealed(EncodedEnvelope envelope) {
	if (!_loaded
		|| _revision == std::numeric_limits<std::uint64_t>::max()
		|| !envelope.conversationId
		|| !envelope.objectId
		|| envelope.bytes.isEmpty()) {
		return false;
	}
	const auto existing = std::find_if(
		begin(_items),
		end(_items),
		[&](const OutboxItem &item) {
			return item.draft.objectId == envelope.objectId;
		});
	if (existing != end(_items)) {
		return existing->stage == OutboxItemStage::Sealed
			&& existing->sealed == envelope;
	}
	auto next = _items;
	next.push_back({
		.draft = {
			.conversationId = envelope.conversationId,
			.objectId = envelope.objectId,
			.plaintext = {},
			.authenticatedData = {},
		},
		.stage = OutboxItemStage::Sealed,
		.sealed = std::move(envelope),
	});
	const auto revision = _revision + 1;
	if (!validItem(next.back()) || !persist(next, revision)) {
		return false;
	}
	_items = std::move(next);
	_revision = revision;
	return true;
}

bool PersistentOutboxStore::appendSealedThenDraft(
		EncodedEnvelope envelope,
		PendingMessage message) {
	if (!_loaded
		|| _revision == std::numeric_limits<std::uint64_t>::max()
		|| contains(envelope.objectId)
		|| contains(message.objectId)
		|| envelope.objectId == message.objectId
		|| envelope.conversationId != message.conversationId) {
		return false;
	}
	auto next = _items;
	next.push_back({
		.draft = {
			.conversationId = envelope.conversationId,
			.objectId = envelope.objectId,
			.plaintext = {},
			.authenticatedData = {},
		},
		.stage = OutboxItemStage::Sealed,
		.sealed = std::move(envelope),
	});
	next.push_back({
		.draft = std::move(message),
		.stage = OutboxItemStage::Draft,
		.sealed = std::nullopt,
	});
	const auto revision = _revision + 1;
	if (!validItem(next[next.size() - 2])
		|| !validItem(next.back())
		|| !persist(next, revision)) {
		return false;
	}
	_items = std::move(next);
	_revision = revision;
	return true;
}

std::optional<OutboxItem> PersistentOutboxStore::front(
		ConversationId conversationId) const {
	if (!_loaded) {
		return std::nullopt;
	}
	const auto i = std::find_if(
		begin(_items),
		end(_items),
		[&](const OutboxItem &item) {
			return item.draft.conversationId == conversationId;
		});
	return (i != end(_items))
		? std::optional<OutboxItem>(*i)
		: std::nullopt;
}

bool PersistentOutboxStore::replaceWithSealed(
		ObjectId objectId,
		EncodedEnvelope envelope) {
	if (!_loaded
		|| _revision == std::numeric_limits<std::uint64_t>::max()) {
		return false;
	}
	auto next = _items;
	const auto i = std::find_if(
		begin(next),
		end(next),
		[&](const OutboxItem &item) {
			return item.draft.objectId == objectId;
		});
	if (i == end(next) || i->stage != OutboxItemStage::Draft) {
		return false;
	}
	i->stage = OutboxItemStage::Sealed;
	i->sealed = std::move(envelope);
	i->draft.plaintext.clear();
	i->draft.authenticatedData.clear();
	const auto revision = _revision + 1;
	if (!validItem(*i) || !persist(next, revision)) {
		return false;
	}
	_items = std::move(next);
	_revision = revision;
	return true;
}

bool PersistentOutboxStore::remove(ObjectId objectId) {
	if (!_loaded
		|| _revision == std::numeric_limits<std::uint64_t>::max()) {
		return false;
	}
	auto next = _items;
	const auto i = std::find_if(
		begin(next),
		end(next),
		[&](const OutboxItem &item) {
			return item.draft.objectId == objectId;
		});
	if (i == end(next)) {
		return false;
	}
	next.erase(i);
	const auto revision = _revision + 1;
	if (!persist(next, revision)) {
		return false;
	}
	_items = std::move(next);
	_revision = revision;
	return true;
}

bool PersistentOutboxStore::persist(
		const std::vector<OutboxItem> &items,
		std::uint64_t revision) const {
	auto encoded = EncodeSnapshot(items, revision);
	if (!encoded) {
		return false;
	}
	const auto protectedBytes = _protector.seal(
		QByteArray(kPurpose),
		*encoded);
	std::fill_n(encoded->data(), encoded->size(), char(0));
	return protectedBytes && _blobStore.writeAtomic(*protectedBytes);
}

bool PersistentOutboxStore::validItem(const OutboxItem &item) const {
	return ValidItem(item);
}

bool PersistentOutboxStore::contains(ObjectId objectId) const {
	return std::any_of(
		begin(_items),
		end(_items),
		[&](const OutboxItem &item) {
			return item.draft.objectId == objectId;
		});
}

} // namespace E2ECloud
