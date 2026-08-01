/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "e2e_cloud/storage/persistent_control_observation_state.h"

#include <openssl/crypto.h>

#include <algorithm>
#include <array>
#include <limits>

namespace E2ECloud {
namespace {

inline constexpr auto kMagic = std::array<std::uint8_t, 8>{
	'T', 'D', 'E', '2', 'E', 'C', 'O', 'S',
};
inline constexpr auto kLegacyMagic = std::array<std::uint8_t, 8>{
	'T', 'D', 'E', '2', 'E', 'C', 'S', 'Y',
};
inline constexpr auto kFixedSize = 8 + 2 + 32 + 8 + 8 + 8 + 32 + 1 + 4;
inline constexpr auto kLegacySize = 8 + 2 + 32 + 8 + 8;
inline constexpr auto kMaximumWitnesses = std::size_t(4096);
inline constexpr auto kPurpose = "e2e-cloud-control-observation-state-v1";
inline constexpr auto kLegacyPurpose = "e2e-cloud-control-sync-state-v1";

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

[[nodiscard]] bool ValidWitnesses(
		const std::set<AccountId> &witnesses) {
	return !witnesses.empty()
		&& witnesses.size() <= kMaximumWitnesses
		&& std::all_of(
			begin(witnesses),
			end(witnesses),
			[](AccountId accountId) { return bool(accountId); });
}

} // namespace

PersistentControlObservationState::PersistentControlObservationState(
		AtomicBlobStore &blobStore,
		const LocalRecordProtector &protector)
: _blobStore(blobStore)
, _protector(protector) {
}

ControlObservationStateLoadResult
PersistentControlObservationState::load(ConversationId conversationId) {
	clear();
	if (!conversationId) {
		return ControlObservationStateLoadResult::InvalidSnapshot;
	}
	const auto stored = _blobStore.read();
	if (stored.status == BlobReadStatus::Missing) {
		_conversationId = conversationId;
		_loaded = true;
		return ControlObservationStateLoadResult::Missing;
	} else if (stored.status != BlobReadStatus::Found) {
		return ControlObservationStateLoadResult::ReadFailed;
	}
	auto plaintext = _protector.open(QByteArray(kPurpose), stored.bytes);
	if (!plaintext) {
		plaintext = _protector.open(QByteArray(kLegacyPurpose), stored.bytes);
		if (!plaintext) {
			return ControlObservationStateLoadResult::AuthenticationFailed;
		}
		if (plaintext->size() != kLegacySize) {
			Cleanse(*plaintext);
			return ControlObservationStateLoadResult::InvalidSnapshot;
		}
		auto reader = Reader{ *plaintext };
		auto magic = std::array<std::uint8_t, 8>();
		auto version = std::uint16_t();
		auto storedConversationId = ConversationId();
		auto revision = std::uint64_t();
		auto messageId = std::uint64_t();
		const auto decoded = ReadArray(reader, magic)
			&& ReadUint16(reader, version)
			&& ReadArray(reader, storedConversationId.bytes)
			&& ReadUint64(reader, revision)
			&& ReadUint64(reader, messageId)
			&& reader.offset == plaintext->size();
		Cleanse(*plaintext);
		if (!decoded
			|| magic != kLegacyMagic
			|| version != 1
			|| storedConversationId != conversationId
			|| !revision
			|| !messageId
			|| messageId > std::uint64_t(
				std::numeric_limits<std::int64_t>::max())) {
			return ControlObservationStateLoadResult::InvalidSnapshot;
		}
		_conversationId = conversationId;
		_newestObservedMessageId = std::int64_t(messageId);
		_revision = revision;
		_loaded = true;
		_legacy = true;
		return ControlObservationStateLoadResult::LegacyLoaded;
	}
	if (plaintext->size() < kFixedSize) {
		Cleanse(*plaintext);
		return ControlObservationStateLoadResult::InvalidSnapshot;
	}
	auto reader = Reader{ *plaintext };
	auto magic = std::array<std::uint8_t, 8>();
	auto version = std::uint16_t();
	auto storedConversationId = ConversationId();
	auto revision = std::uint64_t();
	auto messageId = std::uint64_t();
	auto generation = std::uint64_t();
	auto stateHash = Digest();
	auto ownObserved = std::uint8_t();
	auto count = std::uint32_t();
	if (!ReadArray(reader, magic)
		|| !ReadUint16(reader, version)
		|| !ReadArray(reader, storedConversationId.bytes)
		|| !ReadUint64(reader, revision)
		|| !ReadUint64(reader, messageId)
		|| !ReadUint64(reader, generation)
		|| !ReadArray(reader, stateHash.bytes)
		|| reader.bytes.size() - reader.offset < 1) {
		Cleanse(*plaintext);
		return ControlObservationStateLoadResult::InvalidSnapshot;
	}
	ownObserved = std::uint8_t(reader.bytes[reader.offset++]);
	if (!ReadUint32(reader, count)
		|| magic != kMagic
		|| version != 1
		|| storedConversationId != conversationId
		|| !revision
		|| !messageId
		|| messageId > std::uint64_t(
			std::numeric_limits<std::int64_t>::max())
		|| !generation
		|| !stateHash
		|| ownObserved > 1
		|| !count
		|| count > kMaximumWitnesses
		|| reader.bytes.size() - reader.offset != int(count) * 32) {
		Cleanse(*plaintext);
		return ControlObservationStateLoadResult::InvalidSnapshot;
	}
	auto witnesses = std::set<AccountId>();
	for (auto index = std::uint32_t(); index != count; ++index) {
		auto accountId = AccountId();
		if (!ReadArray(reader, accountId.bytes)
			|| !accountId
			|| !witnesses.emplace(accountId).second) {
			Cleanse(*plaintext);
			return ControlObservationStateLoadResult::InvalidSnapshot;
		}
	}
	Cleanse(*plaintext);
	_conversationId = conversationId;
	_newestObservedMessageId = std::int64_t(messageId);
	_checkpoint = {
		.conversationId = conversationId,
		.generation = generation,
		.stateHash = stateHash,
	};
	_safetyWitnesses = std::move(witnesses);
	_revision = revision;
	_ownSafetyGossipObserved = (ownObserved != 0);
	_loaded = true;
	return ControlObservationStateLoadResult::Loaded;
}

ControlObservationStateCommitResult
PersistentControlObservationState::advance(
		std::int64_t newestObservedMessageId,
		Checkpoint checkpoint,
		const std::set<AccountId> &safetyWitnesses,
		bool ownSafetyGossipObserved) {
	if (!_loaded
		|| newestObservedMessageId <= 0
		|| newestObservedMessageId < _newestObservedMessageId
		|| checkpoint.conversationId != _conversationId
		|| !checkpoint.generation
		|| !checkpoint.stateHash
		|| !ValidWitnesses(safetyWitnesses)) {
		return ControlObservationStateCommitResult::InvalidState;
	} else if (!_legacy
		&& newestObservedMessageId == _newestObservedMessageId
		&& checkpoint == _checkpoint
		&& safetyWitnesses == _safetyWitnesses
		&& ownSafetyGossipObserved == _ownSafetyGossipObserved) {
		return ControlObservationStateCommitResult::AlreadyCommitted;
	} else if (_revision == std::numeric_limits<std::uint64_t>::max()) {
		return ControlObservationStateCommitResult::PersistenceFailed;
	}
	const auto revision = _revision + 1;
	if (!persist(
			newestObservedMessageId,
			checkpoint,
			safetyWitnesses,
			ownSafetyGossipObserved,
			revision)) {
		return ControlObservationStateCommitResult::PersistenceFailed;
	}
	_newestObservedMessageId = newestObservedMessageId;
	_checkpoint = checkpoint;
	_safetyWitnesses = safetyWitnesses;
	_revision = revision;
	_ownSafetyGossipObserved = ownSafetyGossipObserved;
	_legacy = false;
	return ControlObservationStateCommitResult::Committed;
}

std::int64_t
PersistentControlObservationState::newestObservedMessageId() const {
	return _newestObservedMessageId;
}

Checkpoint PersistentControlObservationState::checkpoint() const {
	return _checkpoint;
}

const std::set<AccountId> &
PersistentControlObservationState::safetyWitnesses() const {
	return _safetyWitnesses;
}

bool PersistentControlObservationState::ownSafetyGossipObserved() const {
	return _ownSafetyGossipObserved;
}

std::uint64_t PersistentControlObservationState::revision() const {
	return _revision;
}

bool PersistentControlObservationState::loaded() const {
	return _loaded;
}

bool PersistentControlObservationState::legacy() const {
	return _legacy;
}

bool PersistentControlObservationState::persist(
		std::int64_t newestObservedMessageId,
		Checkpoint checkpoint,
		const std::set<AccountId> &safetyWitnesses,
		bool ownSafetyGossipObserved,
		std::uint64_t revision) const {
	auto plaintext = QByteArray();
	plaintext.reserve(kFixedSize + int(safetyWitnesses.size()) * 32);
	AppendArray(plaintext, kMagic);
	AppendUint16(plaintext, 1);
	AppendArray(plaintext, _conversationId.bytes);
	AppendUint64(plaintext, revision);
	AppendUint64(plaintext, std::uint64_t(newestObservedMessageId));
	AppendUint64(plaintext, checkpoint.generation);
	AppendArray(plaintext, checkpoint.stateHash.bytes);
	plaintext.append(char(ownSafetyGossipObserved ? 1 : 0));
	AppendUint32(plaintext, std::uint32_t(safetyWitnesses.size()));
	for (const auto accountId : safetyWitnesses) {
		AppendArray(plaintext, accountId.bytes);
	}
	const auto protectedBytes = _protector.seal(
		QByteArray(kPurpose),
		plaintext);
	Cleanse(plaintext);
	return protectedBytes && _blobStore.writeAtomic(*protectedBytes);
}

void PersistentControlObservationState::clear() {
	_conversationId = {};
	_newestObservedMessageId = 0;
	_checkpoint = {};
	_safetyWitnesses.clear();
	_revision = 0;
	_ownSafetyGossipObserved = false;
	_loaded = false;
	_legacy = false;
}

} // namespace E2ECloud
