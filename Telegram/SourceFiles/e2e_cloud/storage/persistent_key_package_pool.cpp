/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "e2e_cloud/storage/persistent_key_package_pool.h"

#include <openssl/crypto.h>

#include <algorithm>
#include <array>
#include <limits>
#include <set>
#include <utility>

namespace E2ECloud {
namespace {

inline constexpr auto kMagic = std::array<std::uint8_t, 8>{
	'T', 'D', 'E', '2', 'E', 'K', 'P', 'P',
};
inline constexpr auto kPurpose = "TDE2E/local-key-package-pool/v1";
inline constexpr auto kMaximumPrivateStateSize = 16 * 1024 * 1024;
inline constexpr auto kMaximumEnvelopeSize = 2 * 1024 * 1024;
inline constexpr auto kMaximumSnapshotSize = 72 * 1024 * 1024;

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
		|| size > std::uint32_t(std::numeric_limits<int>::max())
		|| reader.bytes.size() - reader.offset < int(size)) {
		return false;
	}
	value = QByteArray(reader.bytes.constData() + reader.offset, int(size));
	reader.offset += int(size);
	return true;
}

void Cleanse(QByteArray &bytes) {
	if (!bytes.isEmpty()) {
		OPENSSL_cleanse(bytes.data(), bytes.size());
	}
	bytes.clear();
}

void Cleanse(std::vector<StoredClientKeyPackage> &entries) {
	for (auto &entry : entries) {
		Cleanse(entry.privateEngineState);
	}
	entries.clear();
}

[[nodiscard]] QByteArray Purpose(
		ConversationId conversationId,
		std::uint64_t peerBinding) {
	auto result = QByteArray(kPurpose);
	result.append('/');
	AppendArray(result, conversationId.bytes);
	AppendUint64(result, peerBinding);
	return result;
}

} // namespace

PersistentKeyPackagePool::PersistentKeyPackagePool(
		AtomicBlobStore &blobStore,
		const LocalRecordProtector &protector,
		const EnvelopeCodec &envelopeCodec,
		const Sha256Provider &sha256)
: _blobStore(blobStore)
, _protector(protector)
, _envelopeCodec(envelopeCodec)
, _sha256(sha256) {
}

PersistentKeyPackagePool::~PersistentKeyPackagePool() {
	clear();
}

KeyPackagePoolLoadResult PersistentKeyPackagePool::load(
		ConversationId conversationId,
		std::uint64_t telegramPeerIdBinding) {
	clear();
	if (!conversationId || !telegramPeerIdBinding) {
		return KeyPackagePoolLoadResult::InvalidSnapshot;
	}
	_conversationId = conversationId;
	_telegramPeerIdBinding = telegramPeerIdBinding;
	const auto stored = _blobStore.read();
	if (stored.status == BlobReadStatus::Error) {
		return KeyPackagePoolLoadResult::StorageError;
	} else if (stored.status == BlobReadStatus::Missing) {
		_loaded = true;
		return KeyPackagePoolLoadResult::Empty;
	}
	auto opened = _protector.open(
		Purpose(conversationId, telegramPeerIdBinding),
		stored.bytes);
	if (!opened) {
		return KeyPackagePoolLoadResult::AuthenticationFailed;
	} else if (opened->size() > kMaximumSnapshotSize) {
		Cleanse(*opened);
		return KeyPackagePoolLoadResult::InvalidSnapshot;
	}
	auto reader = Reader{ *opened };
	auto magic = std::array<std::uint8_t, 8>();
	auto version = std::uint16_t();
	auto storedConversationId = ConversationId();
	auto storedPeerBinding = std::uint64_t();
	auto revision = std::uint64_t();
	auto count = std::uint32_t();
	if (!ReadArray(reader, magic)
		|| !ReadUint16(reader, version)
		|| !ReadArray(reader, storedConversationId.bytes)
		|| !ReadUint64(reader, storedPeerBinding)
		|| !ReadUint64(reader, revision)
		|| !ReadUint32(reader, count)
		|| magic != kMagic
		|| version != 1
		|| storedConversationId != conversationId
		|| storedPeerBinding != telegramPeerIdBinding
		|| !revision
		|| count > kMaximumKeyPackagePoolEntries) {
		Cleanse(*opened);
		return KeyPackagePoolLoadResult::InvalidSnapshot;
	}
	auto entries = std::vector<StoredClientKeyPackage>();
	entries.reserve(count);
	for (auto index = std::uint32_t(); index != count; ++index) {
		auto entry = StoredClientKeyPackage();
		auto queued = std::uint8_t();
		if (!ReadArray(reader, entry.keyPackageHash.bytes)
			|| !ReadUint64(reader, entry.createdAt)
			|| !ReadUint64(reader, entry.expiresAt)
			|| !ReadUint8(reader, queued)
			|| queued > 1
			|| !ReadBytes(
				reader,
				kMaximumPrivateStateSize,
				entry.privateEngineState)
			|| !ReadArray(reader, entry.publicationEnvelope.objectId.bytes)
			|| !ReadBytes(
				reader,
				kMaximumEnvelopeSize,
				entry.publicationEnvelope.bytes)) {
			Cleanse(entry.privateEngineState);
			Cleanse(entries);
			Cleanse(*opened);
			return KeyPackagePoolLoadResult::InvalidSnapshot;
		}
		entry.publicationEnvelope.conversationId = conversationId;
		entry.queued = queued != 0;
		if (!validEntry(entry)) {
			Cleanse(entry.privateEngineState);
			Cleanse(entries);
			Cleanse(*opened);
			return KeyPackagePoolLoadResult::InvalidSnapshot;
		}
		entries.push_back(std::move(entry));
	}
	const auto complete = reader.offset == reader.bytes.size();
	Cleanse(*opened);
	if (!complete) {
		Cleanse(entries);
		return KeyPackagePoolLoadResult::InvalidSnapshot;
	}
	auto objectIds = std::set<ObjectId>();
	auto hashes = std::set<Digest>();
	for (const auto &entry : entries) {
		if (!objectIds.emplace(entry.publicationEnvelope.objectId).second
			|| !hashes.emplace(entry.keyPackageHash).second) {
			Cleanse(entries);
			return KeyPackagePoolLoadResult::InvalidSnapshot;
		}
	}
	_entries = std::move(entries);
	_revision = revision;
	_loaded = true;
	return KeyPackagePoolLoadResult::Loaded;
}

KeyPackagePoolMutationResult PersistentKeyPackagePool::add(
		StoredClientKeyPackage entry) {
	if (!_loaded) {
		Cleanse(entry.privateEngineState);
		return KeyPackagePoolMutationResult::NotLoaded;
	} else if (!validEntry(entry)) {
		Cleanse(entry.privateEngineState);
		return KeyPackagePoolMutationResult::InvalidEntry;
	}
	const auto duplicate = std::find_if(
		begin(_entries),
		end(_entries),
		[&](const StoredClientKeyPackage &current) {
			return current.publicationEnvelope.objectId
				== entry.publicationEnvelope.objectId
				|| current.keyPackageHash == entry.keyPackageHash;
		});
	if (duplicate != end(_entries)) {
		const auto same = *duplicate == entry;
		Cleanse(entry.privateEngineState);
		return same
			? KeyPackagePoolMutationResult::AlreadyStored
			: KeyPackagePoolMutationResult::InvalidEntry;
	} else if (_entries.size() == kMaximumKeyPackagePoolEntries) {
		Cleanse(entry.privateEngineState);
		return KeyPackagePoolMutationResult::CapacityExceeded;
	} else if (_revision == std::numeric_limits<std::uint64_t>::max()) {
		Cleanse(entry.privateEngineState);
		return KeyPackagePoolMutationResult::RevisionExhausted;
	}
	auto entries = _entries;
	entries.push_back(std::move(entry));
	const auto revision = _revision + 1;
	if (!persist(entries, revision)) {
		Cleanse(entries);
		return KeyPackagePoolMutationResult::PersistenceFailed;
	}
	Cleanse(_entries);
	_entries = std::move(entries);
	_revision = revision;
	return KeyPackagePoolMutationResult::Committed;
}

KeyPackagePoolMutationResult PersistentKeyPackagePool::prune(
		std::uint64_t currentTime,
		std::uint64_t currentGeneration) {
	if (!_loaded) {
		return KeyPackagePoolMutationResult::NotLoaded;
	} else if (!currentTime || !currentGeneration) {
		return KeyPackagePoolMutationResult::InvalidEntry;
	}
	auto entries = _entries;
	entries.erase(std::remove_if(
		begin(entries),
		end(entries),
		[&](const StoredClientKeyPackage &entry) {
			const auto envelope = _envelopeCodec.decode(
				entry.publicationEnvelope);
			return entry.expiresAt <= currentTime
				|| !envelope
				|| envelope->epochOrGeneration != currentGeneration;
		}), end(entries));
	if (entries.size() == _entries.size()) {
		Cleanse(entries);
		return KeyPackagePoolMutationResult::AlreadyStored;
	} else if (_revision == std::numeric_limits<std::uint64_t>::max()) {
		Cleanse(entries);
		return KeyPackagePoolMutationResult::RevisionExhausted;
	}
	const auto revision = _revision + 1;
	if (!persist(entries, revision)) {
		Cleanse(entries);
		return KeyPackagePoolMutationResult::PersistenceFailed;
	}
	Cleanse(_entries);
	_entries = std::move(entries);
	_revision = revision;
	return KeyPackagePoolMutationResult::Committed;
}

KeyPackagePoolMutationResult PersistentKeyPackagePool::consume(
		Digest keyPackageHash) {
	if (!_loaded) {
		return KeyPackagePoolMutationResult::NotLoaded;
	} else if (!keyPackageHash) {
		return KeyPackagePoolMutationResult::InvalidEntry;
	}
	const auto present = std::any_of(
		begin(_entries),
		end(_entries),
		[&](const StoredClientKeyPackage &entry) {
			return entry.keyPackageHash == keyPackageHash;
		});
	if (!present) {
		return KeyPackagePoolMutationResult::InvalidEntry;
	} else if (_revision == std::numeric_limits<std::uint64_t>::max()) {
		return KeyPackagePoolMutationResult::RevisionExhausted;
	}
	const auto entries = std::vector<StoredClientKeyPackage>();
	const auto revision = _revision + 1;
	if (!persist(entries, revision)) {
		return KeyPackagePoolMutationResult::PersistenceFailed;
	}
	Cleanse(_entries);
	_revision = revision;
	return KeyPackagePoolMutationResult::Committed;
}

KeyPackagePoolEnqueueResult PersistentKeyPackagePool::enqueuePending(
		ProtectedOutboxStore &outbox,
		std::uint64_t currentTime) {
	if (!_loaded || !currentTime) {
		return KeyPackagePoolEnqueueResult::NotLoaded;
	}
	auto entries = _entries;
	auto changed = false;
	for (auto &entry : entries) {
		if (entry.queued || entry.expiresAt <= currentTime) {
			continue;
		}
		if (!outbox.appendSealed(entry.publicationEnvelope)) {
			Cleanse(entries);
			return KeyPackagePoolEnqueueResult::OutboxFailure;
		}
		entry.queued = true;
		changed = true;
	}
	if (!changed) {
		Cleanse(entries);
		return KeyPackagePoolEnqueueResult::NothingToDo;
	} else if (_revision == std::numeric_limits<std::uint64_t>::max()) {
		Cleanse(entries);
		return KeyPackagePoolEnqueueResult::PersistenceFailed;
	}
	const auto revision = _revision + 1;
	if (!persist(entries, revision)) {
		Cleanse(entries);
		return KeyPackagePoolEnqueueResult::PersistenceFailed;
	}
	Cleanse(_entries);
	_entries = std::move(entries);
	_revision = revision;
	return KeyPackagePoolEnqueueResult::Queued;
}

bool PersistentKeyPackagePool::needsRefresh(
		std::uint64_t currentTime,
		std::uint64_t currentGeneration) const {
	if (!_loaded || !currentTime || !currentGeneration) {
		return false;
	}
	return std::none_of(
		begin(_entries),
		end(_entries),
		[&](const StoredClientKeyPackage &entry) {
			const auto envelope = _envelopeCodec.decode(
				entry.publicationEnvelope);
			return envelope
				&& envelope->epochOrGeneration == currentGeneration
				&& entry.expiresAt > currentTime
				&& entry.expiresAt - currentTime
					> kOpenMlsKeyPackageRefreshLeadSeconds;
		});
}

const StoredClientKeyPackage *PersistentKeyPackagePool::find(
		Digest keyPackageHash,
		std::uint64_t currentTime) const {
	if (!_loaded || !keyPackageHash || !currentTime) {
		return nullptr;
	}
	const auto i = std::find_if(
		begin(_entries),
		end(_entries),
		[&](const StoredClientKeyPackage &entry) {
			return entry.keyPackageHash == keyPackageHash
				&& entry.expiresAt > currentTime;
		});
	return (i == end(_entries)) ? nullptr : &*i;
}

bool PersistentKeyPackagePool::loaded() const {
	return _loaded;
}

std::uint64_t PersistentKeyPackagePool::revision() const {
	return _revision;
}

const std::vector<StoredClientKeyPackage>
&PersistentKeyPackagePool::entries() const {
	return _entries;
}

bool PersistentKeyPackagePool::validEntry(
		const StoredClientKeyPackage &entry) const {
	if (!_conversationId
		|| !_telegramPeerIdBinding
		|| !entry.keyPackageHash
		|| !entry.createdAt
		|| entry.expiresAt <= entry.createdAt
		|| entry.expiresAt - entry.createdAt
			!= kOpenMlsKeyPackageLifetimeSeconds
		|| entry.privateEngineState.isEmpty()
		|| entry.privateEngineState.size() > kMaximumPrivateStateSize
		|| entry.publicationEnvelope.conversationId != _conversationId
		|| !entry.publicationEnvelope.objectId
		|| entry.publicationEnvelope.bytes.isEmpty()
		|| entry.publicationEnvelope.bytes.size() > kMaximumEnvelopeSize) {
		return false;
	}
	const auto envelope = _envelopeCodec.decode(entry.publicationEnvelope);
	if (!envelope) {
		return false;
	}
	const auto verified = VerifyClientKeyPackageEnvelope(
		*envelope,
		_conversationId,
		_telegramPeerIdBinding,
		envelope->epochOrGeneration,
		_sha256);
	return verified.result == ClientKeyPackageEnvelopeResult::Verified
		&& verified.publication
		&& verified.publication->authorization.createdAt == entry.createdAt
		&& verified.publication->authorization.expiresAt == entry.expiresAt
		&& _sha256.digest(verified.publication->keyPackage)
			== entry.keyPackageHash;
}

bool PersistentKeyPackagePool::persist(
		const std::vector<StoredClientKeyPackage> &entries,
		std::uint64_t revision) const {
	if (!_conversationId
		|| !_telegramPeerIdBinding
		|| !revision
		|| entries.size() > kMaximumKeyPackagePoolEntries) {
		return false;
	}
	auto result = QByteArray();
	AppendArray(result, kMagic);
	AppendUint16(result, 1);
	AppendArray(result, _conversationId.bytes);
	AppendUint64(result, _telegramPeerIdBinding);
	AppendUint64(result, revision);
	AppendUint32(result, std::uint32_t(entries.size()));
	for (const auto &entry : entries) {
		if (!validEntry(entry)) {
			Cleanse(result);
			return false;
		}
		AppendArray(result, entry.keyPackageHash.bytes);
		AppendUint64(result, entry.createdAt);
		AppendUint64(result, entry.expiresAt);
		AppendUint8(result, entry.queued ? 1 : 0);
		AppendBytes(result, entry.privateEngineState);
		AppendArray(result, entry.publicationEnvelope.objectId.bytes);
		AppendBytes(result, entry.publicationEnvelope.bytes);
		if (result.size() > kMaximumSnapshotSize) {
			Cleanse(result);
			return false;
		}
	}
	const auto encrypted = _protector.seal(
		Purpose(_conversationId, _telegramPeerIdBinding),
		result);
	Cleanse(result);
	return encrypted && _blobStore.writeAtomic(*encrypted);
}

void PersistentKeyPackagePool::clear() {
	Cleanse(_entries);
	_conversationId = {};
	_telegramPeerIdBinding = 0;
	_revision = 0;
	_loaded = false;
}

} // namespace E2ECloud
