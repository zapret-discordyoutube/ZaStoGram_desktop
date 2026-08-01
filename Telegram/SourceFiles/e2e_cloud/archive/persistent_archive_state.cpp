/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "e2e_cloud/archive/persistent_archive_state.h"

#include <openssl/crypto.h>

#include <algorithm>
#include <array>
#include <iterator>
#include <limits>
#include <set>
#include <utility>

namespace E2ECloud {
namespace {

inline constexpr auto kMagic = std::array<std::uint8_t, 8>{
	'T', 'D', 'E', '2', 'E', 'A', 'R', 'S',
};
inline constexpr auto kPurpose = "TDE2E/local-archive-state/v1";
inline constexpr auto kMaximumRetainedEpochs = 65'536;
inline constexpr auto kFixedSnapshotSize = 8 + 2 + 32 + 8 + 4;
inline constexpr auto kEpochEncodedSize = 8 + 8 + 32 + kArchiveKeySize;

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

[[nodiscard]] bool SameEpoch(
		const ArchiveEpochSecret &a,
		const ArchiveEpochSecret &b) {
	return a.generation == b.generation
		&& a.activationGroupGeneration == b.activationGroupGeneration
		&& a.activationEventId == b.activationEventId
		&& a.key.bytes() == b.key.bytes();
}

[[nodiscard]] bool ValidEpochs(
		const std::vector<ArchiveEpochSecret> &epochs,
		bool allowGaps) {
	if (epochs.empty() || epochs.size() > kMaximumRetainedEpochs) {
		return false;
	}
	auto previousGeneration = std::uint64_t();
	auto previousGroupGeneration = std::uint64_t();
	auto eventIds = std::set<ObjectId>();
	for (const auto &epoch : epochs) {
		if (!epoch.generation
			|| !epoch.activationGroupGeneration
			|| !epoch.activationEventId
			|| !epoch.key.valid()
			|| epoch.generation <= previousGeneration
			|| (!allowGaps
				&& previousGeneration
				&& epoch.generation != previousGeneration + 1)
			|| epoch.activationGroupGeneration < previousGroupGeneration
			|| !eventIds.emplace(epoch.activationEventId).second) {
			return false;
		}
		previousGeneration = epoch.generation;
		previousGroupGeneration = epoch.activationGroupGeneration;
	}
	return true;
}

[[nodiscard]] ArchiveEpochSecret CloneEpoch(
		const ArchiveEpochSecret &epoch) {
	auto key = epoch.key.bytes();
	return {
		.generation = epoch.generation,
		.activationGroupGeneration = epoch.activationGroupGeneration,
		.activationEventId = epoch.activationEventId,
		.key = ArchiveKey32(std::move(key)),
	};
}

[[nodiscard]] QByteArray Purpose(ConversationId conversationId) {
	auto result = QByteArray(kPurpose);
	result.append('/');
	AppendArray(result, conversationId.bytes);
	return result;
}

[[nodiscard]] std::optional<QByteArray> EncodeSnapshot(
		ConversationId conversationId,
		const std::vector<ArchiveEpochSecret> &epochs,
		std::uint64_t revision) {
	if (!conversationId || !revision || !ValidEpochs(epochs, true)) {
		return std::nullopt;
	}
	auto result = QByteArray();
	result.reserve(kFixedSnapshotSize + int(epochs.size()) * kEpochEncodedSize);
	AppendArray(result, kMagic);
	AppendUint16(result, 1);
	AppendArray(result, conversationId.bytes);
	AppendUint64(result, revision);
	AppendUint32(result, std::uint32_t(epochs.size()));
	for (const auto &epoch : epochs) {
		AppendUint64(result, epoch.generation);
		AppendUint64(result, epoch.activationGroupGeneration);
		AppendArray(result, epoch.activationEventId.bytes);
		AppendArray(result, epoch.key.bytes());
	}
	return result;
}

struct DecodedSnapshot {
	ConversationId conversationId;
	std::uint64_t revision = 0;
	std::vector<ArchiveEpochSecret> epochs;
};

[[nodiscard]] std::optional<DecodedSnapshot> DecodeSnapshot(
		const QByteArray &bytes) {
	auto reader = Reader{ bytes };
	auto magic = std::array<std::uint8_t, 8>();
	auto version = std::uint16_t();
	auto count = std::uint32_t();
	auto result = DecodedSnapshot();
	if (!ReadArray(reader, magic)
		|| !ReadUint16(reader, version)
		|| !ReadArray(reader, result.conversationId.bytes)
		|| !ReadUint64(reader, result.revision)
		|| !ReadUint32(reader, count)
		|| magic != kMagic
		|| version != 1
		|| !result.conversationId
		|| !result.revision
		|| !count
		|| count > kMaximumRetainedEpochs
		|| bytes.size() != kFixedSnapshotSize + int(count) * kEpochEncodedSize) {
		return std::nullopt;
	}
	result.epochs.reserve(count);
	for (auto index = std::uint32_t(); index != count; ++index) {
		auto generation = std::uint64_t();
		auto activationGroupGeneration = std::uint64_t();
		auto activationEventId = ObjectId();
		auto key = std::array<std::uint8_t, kArchiveKeySize>();
		if (!ReadUint64(reader, generation)
			|| !ReadUint64(reader, activationGroupGeneration)
			|| !ReadArray(reader, activationEventId.bytes)
			|| !ReadArray(reader, key)) {
			OPENSSL_cleanse(key.data(), key.size());
			return std::nullopt;
		}
		result.epochs.push_back({
			.generation = generation,
			.activationGroupGeneration = activationGroupGeneration,
			.activationEventId = activationEventId,
			.key = ArchiveKey32(std::move(key)),
		});
	}
	return (reader.offset == bytes.size() && ValidEpochs(result.epochs, true))
		? std::optional<DecodedSnapshot>(std::move(result))
		: std::nullopt;
}

} // namespace

PersistentArchiveState::PersistentArchiveState(
	AtomicBlobStore &blobStore,
	const LocalRecordProtector &protector)
: _blobStore(blobStore)
, _protector(protector) {
}

ArchiveStateLoadResult PersistentArchiveState::load(
		ConversationId conversationId) {
	clear();
	if (!conversationId) {
		return ArchiveStateLoadResult::InvalidSnapshot;
	}
	const auto read = _blobStore.read();
	if (read.status == BlobReadStatus::Error) {
		return ArchiveStateLoadResult::StorageError;
	} else if (read.status == BlobReadStatus::Missing) {
		_conversationId = conversationId;
		return ArchiveStateLoadResult::Missing;
	}
	auto plaintext = _protector.open(Purpose(conversationId), read.bytes);
	if (!plaintext) {
		return ArchiveStateLoadResult::AuthenticationFailed;
	}
	auto decoded = DecodeSnapshot(*plaintext);
	OPENSSL_cleanse(plaintext->data(), plaintext->size());
	if (!decoded || decoded->conversationId != conversationId) {
		return ArchiveStateLoadResult::InvalidSnapshot;
	}
	_conversationId = decoded->conversationId;
	_revision = decoded->revision;
	_epochs = std::move(decoded->epochs);
	_loaded = true;
	return ArchiveStateLoadResult::Loaded;
}

ArchiveStateCommitResult PersistentArchiveState::initialize(
		ArchiveEpochSecret firstEpoch) {
	auto epochs = std::vector<ArchiveEpochSecret>();
	epochs.push_back(std::move(firstEpoch));
	if (_loaded
		|| !_conversationId
		|| !ValidEpochs(epochs, false)) {
		return ArchiveStateCommitResult::InvalidMutation;
	}
	if (!persist(epochs, 1)) {
		return ArchiveStateCommitResult::PersistenceFailed;
	}
	_epochs = std::move(epochs);
	_revision = 1;
	_loaded = true;
	return ArchiveStateCommitResult::Committed;
}

ArchiveStateCommitResult PersistentArchiveState::appendEpoch(
		std::uint64_t baseRevision,
		ArchiveEpochSecret epoch,
		ArchiveEpochAppendMode mode) {
	if (!_loaded) {
		return ArchiveStateCommitResult::NotLoaded;
	}
	const auto existing = this->epoch(epoch.generation);
	if (existing) {
		return SameEpoch(*existing, epoch)
			? ArchiveStateCommitResult::AlreadyCommitted
			: ArchiveStateCommitResult::EpochConflict;
	}
	if (baseRevision != _revision) {
		return ArchiveStateCommitResult::RevisionConflict;
	}
	if (_revision == std::numeric_limits<std::uint64_t>::max()
		|| _epochs.size() >= kMaximumRetainedEpochs
		|| (mode == ArchiveEpochAppendMode::Contiguous
			? epoch.generation != _epochs.back().generation + 1
			: epoch.generation <= _epochs.back().generation + 1)) {
		return ArchiveStateCommitResult::InvalidMutation;
	}
	auto candidate = std::vector<ArchiveEpochSecret>();
	candidate.reserve(_epochs.size() + 1);
	for (const auto &value : _epochs) {
		candidate.push_back(CloneEpoch(value));
	}
	candidate.push_back(std::move(epoch));
	if (!ValidEpochs(
		candidate,
		mode == ArchiveEpochAppendMode::RejoinGap)) {
		return ArchiveStateCommitResult::InvalidMutation;
	}
	const auto revision = _revision + 1;
	if (!persist(candidate, revision)) {
		return ArchiveStateCommitResult::PersistenceFailed;
	}
	_epochs = std::move(candidate);
	_revision = revision;
	return ArchiveStateCommitResult::Committed;
}

ArchiveStateCommitResult
PersistentArchiveState::replaceForkEpochWithRecovery(
		std::uint64_t baseRevision,
		std::uint64_t resolvedGeneration,
		ArchiveEpochSecret recoveryEpoch) {
	if (!_loaded) {
		return ArchiveStateCommitResult::NotLoaded;
	}
	const auto existingRecovery = epoch(recoveryEpoch.generation);
	if (existingRecovery) {
		return SameEpoch(*existingRecovery, recoveryEpoch)
			? ArchiveStateCommitResult::AlreadyCommitted
			: ArchiveStateCommitResult::EpochConflict;
	}
	if (baseRevision != _revision) {
		return ArchiveStateCommitResult::RevisionConflict;
	}
	if (_revision == std::numeric_limits<std::uint64_t>::max()
		|| !resolvedGeneration
		|| recoveryEpoch.generation != resolvedGeneration + 1
		|| recoveryEpoch.activationGroupGeneration
			!= recoveryEpoch.generation
		|| _epochs.empty()
		|| _epochs.back().generation != resolvedGeneration) {
		return ArchiveStateCommitResult::InvalidMutation;
	}
	auto candidate = std::vector<ArchiveEpochSecret>();
	candidate.reserve(_epochs.size());
	for (const auto &value : _epochs) {
		if (value.generation < resolvedGeneration) {
			candidate.push_back(CloneEpoch(value));
		}
	}
	candidate.push_back(std::move(recoveryEpoch));
	if (!ValidEpochs(candidate, true)) {
		return ArchiveStateCommitResult::InvalidMutation;
	}
	const auto revision = _revision + 1;
	if (!persist(candidate, revision)) {
		return ArchiveStateCommitResult::PersistenceFailed;
	}
	_epochs = std::move(candidate);
	_revision = revision;
	return ArchiveStateCommitResult::Committed;
}

ArchiveStateCommitResult PersistentArchiveState::mergeHistoryGrant(
		std::uint64_t baseRevision,
		HistoryGrantPayload payload) {
	if (!_loaded) {
		return ArchiveStateCommitResult::NotLoaded;
	} else if (payload.conversationId != _conversationId
		|| !payload.grantId
		|| !payload.recipientAccountId
		|| !IsValidHistoryAccess(payload.historyAccess)
		|| payload.epochs.empty()
		|| !ValidEpochs(payload.epochs, true)) {
		return ArchiveStateCommitResult::InvalidMutation;
	}
	auto changed = false;
	auto additions = std::size_t();
	for (const auto &incoming : payload.epochs) {
		const auto existing = epoch(incoming.generation);
		if (existing && !SameEpoch(*existing, incoming)) {
			return ArchiveStateCommitResult::EpochConflict;
		}
		changed = changed || !existing;
		additions += existing ? 0 : 1;
	}
	if (!changed) {
		return ArchiveStateCommitResult::AlreadyCommitted;
	} else if (baseRevision != _revision) {
		return ArchiveStateCommitResult::RevisionConflict;
	} else if (_revision == std::numeric_limits<std::uint64_t>::max()
		|| _epochs.size() + additions
			> kMaximumRetainedEpochs) {
		return ArchiveStateCommitResult::InvalidMutation;
	}
	auto candidate = std::vector<ArchiveEpochSecret>();
	candidate.reserve(_epochs.size() + payload.epochs.size());
	for (const auto &value : _epochs) {
		candidate.push_back(CloneEpoch(value));
	}
	for (auto &incoming : payload.epochs) {
		if (!epoch(incoming.generation)) {
			candidate.push_back(std::move(incoming));
		}
	}
	std::sort(candidate.begin(), candidate.end(), [](const auto &a, const auto &b) {
		return a.generation < b.generation;
	});
	if (!ValidEpochs(candidate, true)) {
		return ArchiveStateCommitResult::EpochConflict;
	}
	const auto revision = _revision + 1;
	if (!persist(candidate, revision)) {
		return ArchiveStateCommitResult::PersistenceFailed;
	}
	_epochs = std::move(candidate);
	_revision = revision;
	return ArchiveStateCommitResult::Committed;
}

std::optional<std::vector<ArchiveEpochSecret>>
PersistentArchiveState::exportForGrant(
		const HistoryAccess &access,
		std::uint64_t joinedGroupGeneration) const {
	if (!_loaded || !IsValidHistoryAccess(access)) {
		return std::nullopt;
	}
	auto first = _epochs.end();
	switch (access.mode) {
	case HistoryAccessMode::None:
		return std::vector<ArchiveEpochSecret>();
	case HistoryAccessMode::Full:
		first = _epochs.begin();
		break;
	case HistoryAccessMode::FromJoin:
		if (!joinedGroupGeneration) {
			return std::nullopt;
		}
		first = std::find_if(
			_epochs.begin(),
			_epochs.end(),
			[=](const auto &epoch) {
				return epoch.activationGroupGeneration
					>= joinedGroupGeneration;
			});
		if (first == _epochs.end()
			|| first->activationGroupGeneration != joinedGroupGeneration) {
			return std::nullopt;
		}
		break;
	case HistoryAccessMode::Since:
		first = std::find_if(
			_epochs.begin(),
			_epochs.end(),
			[&](const auto &epoch) {
				return epoch.activationEventId == access.boundaryEventId;
			});
		if (first == _epochs.end()) {
			return std::nullopt;
		}
		break;
	}
	if (std::distance(first, _epochs.end())
		> kMaximumArchiveEpochsPerGrant) {
		return std::nullopt;
	}
	auto result = std::vector<ArchiveEpochSecret>();
	result.reserve(std::distance(first, _epochs.end()));
	for (auto i = first; i != _epochs.end(); ++i) {
		result.push_back(CloneEpoch(*i));
	}
	return result;
}

bool PersistentArchiveState::loaded() const {
	return _loaded;
}

ConversationId PersistentArchiveState::conversationId() const {
	return _conversationId;
}

std::uint64_t PersistentArchiveState::revision() const {
	return _revision;
}

int PersistentArchiveState::epochCount() const {
	return int(_epochs.size());
}

const ArchiveEpochSecret *PersistentArchiveState::epoch(
		std::uint64_t generation) const {
	const auto i = std::lower_bound(
		_epochs.begin(),
		_epochs.end(),
		generation,
		[](const auto &epoch, std::uint64_t value) {
			return epoch.generation < value;
		});
	return (i != _epochs.end() && i->generation == generation)
		? &*i
		: nullptr;
}

bool PersistentArchiveState::epochWasActiveAt(
		std::uint64_t epochGeneration,
		std::uint64_t groupGeneration) const {
	if (!_loaded || !epochGeneration || !groupGeneration) {
		return false;
	}
	const auto i = std::lower_bound(
		_epochs.begin(),
		_epochs.end(),
		epochGeneration,
		[](const auto &epoch, std::uint64_t value) {
			return epoch.generation < value;
		});
	if (i == _epochs.end()
		|| i->generation != epochGeneration
		|| groupGeneration != i->activationGroupGeneration) {
		return false;
	}
	return true;
}

const ArchiveEpochSecret *PersistentArchiveState::currentEpoch() const {
	return _epochs.empty() ? nullptr : &_epochs.back();
}

bool PersistentArchiveState::persist(
		const std::vector<ArchiveEpochSecret> &epochs,
		std::uint64_t revision) const {
	auto plaintext = EncodeSnapshot(_conversationId, epochs, revision);
	if (!plaintext) {
		return false;
	}
	auto encrypted = _protector.seal(Purpose(_conversationId), *plaintext);
	OPENSSL_cleanse(plaintext->data(), plaintext->size());
	return encrypted && _blobStore.writeAtomic(*encrypted);
}

void PersistentArchiveState::clear() {
	_conversationId = {};
	_epochs.clear();
	_revision = 0;
	_loaded = false;
}

} // namespace E2ECloud
