/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "e2e_cloud/storage/persistent_mls_state.h"

#include <algorithm>
#include <array>
#include <limits>
#include <set>
#include <utility>

namespace E2ECloud {
namespace {

inline constexpr auto kMagic = std::array<std::uint8_t, 8>{
	'T', 'D', 'E', '2', 'E', 'M', 'L', 'S',
};
inline constexpr auto kPurpose = "TDE2E/local-mls-state/v1";
inline constexpr auto kMaximumEngineIdSize = 64;
inline constexpr auto kMaximumEngineStateSize = 64 * 1024 * 1024;
inline constexpr auto kMaximumReceipts = 4096;
inline constexpr auto kMaximumInboundApplications = 512;
inline constexpr auto kMaximumEnvelopeSize = 18 * 1024 * 1024;
inline constexpr auto kMaximumApplicationSize = 1024 * 1024;
inline constexpr auto kMaximumApplicationContextSize = 1024 * 1024;
inline constexpr auto kMaximumSnapshotSize = 128 * 1024 * 1024;

void Cleanse(QByteArray &value) {
	std::fill_n(value.data(), value.size(), char(0));
}

void Cleanse(MlsInboundApplication &application) {
	Cleanse(application.plaintext);
	Cleanse(application.context);
}

void Cleanse(std::vector<MlsInboundApplication> &applications) {
	for (auto &application : applications) {
		Cleanse(application);
	}
}

struct Snapshot {
	Snapshot() = default;
	Snapshot(Snapshot &&) = default;
	Snapshot &operator=(Snapshot &&) = default;
	Snapshot(const Snapshot &) = delete;
	Snapshot &operator=(const Snapshot &) = delete;
	~Snapshot() {
		Cleanse(engineState);
		Cleanse(inboundApplications);
	}

	ConversationId conversationId;
	std::uint64_t revision = 0;
	QByteArray engineId;
	QByteArray engineState;
	std::vector<MlsOperationReceipt> receipts;
	std::vector<MlsInboundApplication> inboundApplications;
	std::optional<MlsRemovalTombstone> removalTombstone;
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

[[nodiscard]] bool ReadUint8(Reader &reader, std::uint8_t &value) {
	if (reader.offset == reader.bytes.size()) {
		return false;
	}
	value = std::uint8_t(reader.bytes[reader.offset++]);
	return true;
}

template <typename Array>
void AppendArray(QByteArray &result, const Array &value) {
	result.append(
		reinterpret_cast<const char*>(value.data()),
		int(value.size()));
}

void AppendBytes16(QByteArray &result, const QByteArray &value) {
	AppendUint16(result, std::uint16_t(value.size()));
	result.append(value);
}

void AppendBytes32(QByteArray &result, const QByteArray &value) {
	AppendUint32(result, std::uint32_t(value.size()));
	result.append(value);
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

[[nodiscard]] bool ReadBytes16(
		Reader &reader,
		int maximumSize,
		QByteArray &value) {
	auto size = std::uint16_t();
	if (!ReadUint16(reader, size)
		|| size > maximumSize
		|| reader.bytes.size() - reader.offset < int(size)) {
		return false;
	}
	value = QByteArray(reader.bytes.constData() + reader.offset, int(size));
	reader.offset += int(size);
	return true;
}

[[nodiscard]] bool ReadBytes32(
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

[[nodiscard]] bool ValidEngineId(const QByteArray &engineId) {
	if (engineId.isEmpty() || engineId.size() > kMaximumEngineIdSize) {
		return false;
	}
	for (auto i = 0; i != engineId.size(); ++i) {
		const auto byte = std::uint8_t(engineId[i]);
		if (byte < 0x21 || byte > 0x7E) {
			return false;
		}
	}
	return true;
}

[[nodiscard]] bool ValidEngineState(const QByteArray &engineState) {
	return !engineState.isEmpty()
		&& engineState.size() <= kMaximumEngineStateSize;
}

[[nodiscard]] bool ValidRemovalTombstone(
		const MlsRemovalTombstone &tombstone) {
	return tombstone.transitionId
		&& tombstone.generation
		&& tombstone.resultingStateHash
		&& tombstone.mlsCommitHash
		&& tombstone.removedAccountId
		&& tombstone.removedClientId;
}

[[nodiscard]] bool ValidReceipt(
		ConversationId conversationId,
		const MlsOperationReceipt &receipt) {
	return receipt.objectId
		&& receipt.requestHash
		&& receipt.envelope.conversationId == conversationId
		&& receipt.envelope.objectId == receipt.objectId
		&& !receipt.envelope.bytes.isEmpty()
		&& receipt.envelope.bytes.size() <= kMaximumEnvelopeSize;
}

[[nodiscard]] bool ValidInboundApplication(
		const MlsInboundApplication &application) {
	return application.objectId
		&& application.payloadHash
		&& application.senderAccountId
		&& application.senderClientId
		&& !application.plaintext.isEmpty()
		&& application.plaintext.size() <= kMaximumApplicationSize
		&& application.context.size() <= kMaximumApplicationContextSize;
}

[[nodiscard]] QByteArray Purpose(ConversationId conversationId) {
	auto result = QByteArray(kPurpose);
	result.append('/');
	result.append(
		reinterpret_cast<const char*>(conversationId.bytes.data()),
		conversationId.bytes.size());
	return result;
}

[[nodiscard]] std::optional<QByteArray> EncodeSnapshot(
		ConversationId conversationId,
		const QByteArray &engineId,
		const QByteArray &engineState,
		const std::vector<MlsOperationReceipt> &receipts,
		const std::vector<MlsInboundApplication> &inboundApplications,
		const std::optional<MlsRemovalTombstone> &removalTombstone,
		std::uint64_t revision) {
	if (!conversationId
		|| !revision
		|| !ValidEngineId(engineId)
		|| (removalTombstone
			? (!engineState.isEmpty()
				|| !receipts.empty()
				|| !inboundApplications.empty()
				|| !ValidRemovalTombstone(*removalTombstone))
			: !ValidEngineState(engineState))
		|| receipts.size() > kMaximumReceipts
		|| inboundApplications.size() > kMaximumInboundApplications) {
		return std::nullopt;
	}
	auto encodedSize = std::uint64_t(
		8 + 2 + 32 + 8 + 2 + engineId.size() + 4 + engineState.size()
		+ 1 + 32 + 8 + 32 + 32 + 32 + 16 + 4 + 4);
	auto objectIds = std::set<ObjectId>();
	for (const auto &receipt : receipts) {
		if (!ValidReceipt(conversationId, receipt)
			|| !objectIds.emplace(receipt.objectId).second) {
			return std::nullopt;
		}
		encodedSize += 32 + 32 + 32 + 32 + 4 + receipt.envelope.bytes.size();
		if (encodedSize > kMaximumSnapshotSize) {
			return std::nullopt;
		}
	}
	for (const auto &application : inboundApplications) {
		if (!ValidInboundApplication(application)
			|| !objectIds.emplace(application.objectId).second) {
			return std::nullopt;
		}
		encodedSize += 32 + 32 + 8 + 32 + 16 + 4 + 4
			+ application.plaintext.size() + 4 + application.context.size();
		if (encodedSize > kMaximumSnapshotSize) {
			return std::nullopt;
		}
	}
	auto result = QByteArray();
	result.reserve(int(encodedSize));
	result.append(
		reinterpret_cast<const char*>(kMagic.data()),
		kMagic.size());
	AppendUint16(result, 3);
	AppendArray(result, conversationId.bytes);
	AppendUint64(result, revision);
	AppendBytes16(result, engineId);
	AppendBytes32(result, engineState);
	AppendUint8(result, removalTombstone ? 1 : 0);
	if (removalTombstone) {
		AppendArray(result, removalTombstone->transitionId.bytes);
		AppendUint64(result, removalTombstone->generation);
		AppendArray(result, removalTombstone->resultingStateHash.bytes);
		AppendArray(result, removalTombstone->mlsCommitHash.bytes);
		AppendArray(result, removalTombstone->removedAccountId.bytes);
		AppendArray(result, removalTombstone->removedClientId.bytes);
	} else {
		auto zero = std::array<std::uint8_t, 32 + 8 + 32 + 32 + 32 + 16>();
		AppendArray(result, zero);
	}
	AppendUint32(result, std::uint32_t(receipts.size()));
	for (const auto &receipt : receipts) {
		AppendArray(result, receipt.objectId.bytes);
		AppendArray(result, receipt.requestHash.bytes);
		AppendArray(result, receipt.envelope.conversationId.bytes);
		AppendArray(result, receipt.envelope.objectId.bytes);
		AppendBytes32(result, receipt.envelope.bytes);
	}
	AppendUint32(result, std::uint32_t(inboundApplications.size()));
	for (const auto &application : inboundApplications) {
		AppendArray(result, application.objectId.bytes);
		AppendArray(result, application.payloadHash.bytes);
		AppendUint64(result, application.epoch);
		AppendArray(result, application.senderAccountId.bytes);
		AppendArray(result, application.senderClientId.bytes);
		AppendUint32(result, application.senderLeafIndex);
		AppendBytes32(result, application.plaintext);
		AppendBytes32(result, application.context);
	}
	return result;
}

[[nodiscard]] std::optional<Snapshot> DecodeSnapshot(
		const QByteArray &bytes) {
	if (bytes.size() < 8 + 2 + 32 + 8 + 2 + 4 + 4 + 4
		|| bytes.size() > kMaximumSnapshotSize) {
		return std::nullopt;
	}
	auto reader = Reader{ bytes };
	auto magic = std::array<std::uint8_t, 8>();
	auto version = std::uint16_t();
	auto count = std::uint32_t();
	auto tombstonePresent = std::uint8_t();
	auto result = Snapshot();
	if (!ReadArray(reader, magic)
		|| !ReadUint16(reader, version)
		|| !ReadArray(reader, result.conversationId.bytes)
		|| !ReadUint64(reader, result.revision)
		|| !ReadBytes16(reader, kMaximumEngineIdSize, result.engineId)
		|| !ReadBytes32(
			reader,
			kMaximumEngineStateSize,
			result.engineState)
		|| magic != kMagic
		|| (version != 2 && version != 3)
		|| !result.conversationId
		|| !result.revision
		|| !ValidEngineId(result.engineId)) {
		return std::nullopt;
	}
	if (version == 3) {
		auto tombstone = MlsRemovalTombstone();
		if (!ReadUint8(reader, tombstonePresent)
			|| tombstonePresent > 1
			|| !ReadArray(reader, tombstone.transitionId.bytes)
			|| !ReadUint64(reader, tombstone.generation)
			|| !ReadArray(reader, tombstone.resultingStateHash.bytes)
			|| !ReadArray(reader, tombstone.mlsCommitHash.bytes)
			|| !ReadArray(reader, tombstone.removedAccountId.bytes)
			|| !ReadArray(reader, tombstone.removedClientId.bytes)) {
			return std::nullopt;
		}
		if (tombstonePresent) {
			if (!ValidRemovalTombstone(tombstone)) {
				return std::nullopt;
			}
			result.removalTombstone = tombstone;
		} else if (tombstone.transitionId
			|| tombstone.generation
			|| tombstone.resultingStateHash
			|| tombstone.mlsCommitHash
			|| tombstone.removedAccountId
			|| tombstone.removedClientId) {
			return std::nullopt;
		}
	}
	if (!ReadUint32(reader, count)
		|| count > kMaximumReceipts
		|| (result.removalTombstone && count)
		|| (result.removalTombstone
			? !result.engineState.isEmpty()
			: !ValidEngineState(result.engineState))) {
		return std::nullopt;
	}
	result.receipts.reserve(count);
	auto objectIds = std::set<ObjectId>();
	for (auto index = std::uint32_t(); index != count; ++index) {
		auto receipt = MlsOperationReceipt();
		if (!ReadArray(reader, receipt.objectId.bytes)
			|| !ReadArray(reader, receipt.requestHash.bytes)
			|| !ReadArray(reader, receipt.envelope.conversationId.bytes)
			|| !ReadArray(reader, receipt.envelope.objectId.bytes)
			|| !ReadBytes32(
				reader,
				kMaximumEnvelopeSize,
				receipt.envelope.bytes)
			|| !ValidReceipt(result.conversationId, receipt)
			|| !objectIds.emplace(receipt.objectId).second) {
			return std::nullopt;
		}
		result.receipts.push_back(std::move(receipt));
	}
	if (!ReadUint32(reader, count)
		|| count > kMaximumInboundApplications
		|| (result.removalTombstone && count)) {
		return std::nullopt;
	}
	result.inboundApplications.reserve(count);
	for (auto index = std::uint32_t(); index != count; ++index) {
		auto application = MlsInboundApplication();
		if (!ReadArray(reader, application.objectId.bytes)
			|| !ReadArray(reader, application.payloadHash.bytes)
			|| !ReadUint64(reader, application.epoch)
			|| !ReadArray(reader, application.senderAccountId.bytes)
			|| !ReadArray(reader, application.senderClientId.bytes)
			|| !ReadUint32(reader, application.senderLeafIndex)
			|| !ReadBytes32(
				reader,
				kMaximumApplicationSize,
				application.plaintext)
			|| !ReadBytes32(
				reader,
				kMaximumApplicationContextSize,
				application.context)
			|| !ValidInboundApplication(application)
			|| !objectIds.emplace(application.objectId).second) {
			Cleanse(application);
			return std::nullopt;
		}
		result.inboundApplications.push_back(std::move(application));
	}
	return (reader.offset == bytes.size())
		? std::optional<Snapshot>(std::move(result))
		: std::nullopt;
}

} // namespace

PersistentMlsStateStore::PersistentMlsStateStore(
		AtomicBlobStore &blobStore,
		const LocalRecordProtector &protector)
: _blobStore(blobStore)
, _protector(protector) {
}

PersistentMlsStateStore::~PersistentMlsStateStore() {
	clear();
}

MlsStateLoadResult PersistentMlsStateStore::load(
		ConversationId conversationId) {
	clear();
	if (!conversationId) {
		return MlsStateLoadResult::InvalidSnapshot;
	}
	_conversationId = conversationId;
	const auto stored = _blobStore.read();
	if (stored.status == BlobReadStatus::Error) {
		return MlsStateLoadResult::StorageError;
	} else if (stored.status == BlobReadStatus::Missing) {
		_loaded = true;
		return MlsStateLoadResult::Missing;
	}
	auto opened = _protector.open(Purpose(conversationId), stored.bytes);
	if (!opened) {
		return MlsStateLoadResult::AuthenticationFailed;
	}
	auto snapshot = DecodeSnapshot(*opened);
	Cleanse(*opened);
	if (!snapshot || snapshot->conversationId != conversationId) {
		return MlsStateLoadResult::InvalidSnapshot;
	}
	_revision = snapshot->revision;
	_engineId = std::move(snapshot->engineId);
	_engineState = std::move(snapshot->engineState);
	_receipts = std::move(snapshot->receipts);
	_inboundApplications = std::move(snapshot->inboundApplications);
	_removalTombstone = snapshot->removalTombstone;
	_loaded = true;
	return MlsStateLoadResult::Loaded;
}

MlsStateCommitResult PersistentMlsStateStore::initialize(
		QByteArray engineId,
		QByteArray engineState) {
	if (!_loaded) {
		Cleanse(engineState);
		return MlsStateCommitResult::NotLoaded;
	} else if (_revision
		|| !ValidEngineId(engineId)
		|| !ValidEngineState(engineState)) {
		Cleanse(engineState);
		return MlsStateCommitResult::InvalidMutation;
	}
	const auto receipts = std::vector<MlsOperationReceipt>();
	const auto inboundApplications = std::vector<MlsInboundApplication>();
	if (!persist(
		engineId,
		engineState,
		receipts,
		inboundApplications,
		std::nullopt,
		1)) {
		Cleanse(engineState);
		return MlsStateCommitResult::PersistenceFailed;
	}
	_engineId = std::move(engineId);
	_engineState = std::move(engineState);
	_receipts.clear();
	Cleanse(_inboundApplications);
	_inboundApplications.clear();
	_removalTombstone.reset();
	_revision = 1;
	return MlsStateCommitResult::Committed;
}

MlsStateCommitResult PersistentMlsStateStore::replaceRemovedWithKeyPackage(
		std::uint64_t baseRevision,
		QByteArray engineState) {
	if (!_loaded) {
		Cleanse(engineState);
		return MlsStateCommitResult::NotLoaded;
	} else if (!_revision
		|| !_removalTombstone
		|| baseRevision != _revision
		|| _revision == std::numeric_limits<std::uint64_t>::max()
		|| !ValidEngineState(engineState)) {
		Cleanse(engineState);
		return (baseRevision != _revision)
			? MlsStateCommitResult::RevisionConflict
			: MlsStateCommitResult::InvalidMutation;
	}
	const auto receipts = std::vector<MlsOperationReceipt>();
	const auto inboundApplications = std::vector<MlsInboundApplication>();
	const auto revision = _revision + 1;
	if (!persist(
		_engineId,
		engineState,
		receipts,
		inboundApplications,
		std::nullopt,
		revision)) {
		Cleanse(engineState);
		return MlsStateCommitResult::PersistenceFailed;
	}
	Cleanse(_engineState);
	Cleanse(_inboundApplications);
	_engineState = std::move(engineState);
	_receipts.clear();
	_inboundApplications.clear();
	_removalTombstone.reset();
	_revision = revision;
	return MlsStateCommitResult::Committed;
}

MlsStateCommitResult PersistentMlsStateStore::replacePendingKeyPackage(
		std::uint64_t baseRevision,
		QByteArray engineState) {
	if (!_loaded) {
		Cleanse(engineState);
		return MlsStateCommitResult::NotLoaded;
	} else if (!_revision
		|| _removalTombstone
		|| !_receipts.empty()
		|| !_inboundApplications.empty()
		|| baseRevision != _revision
		|| _revision == std::numeric_limits<std::uint64_t>::max()
		|| !ValidEngineState(engineState)) {
		Cleanse(engineState);
		return (baseRevision != _revision)
			? MlsStateCommitResult::RevisionConflict
			: MlsStateCommitResult::InvalidMutation;
	}
	const auto revision = _revision + 1;
	if (!persist(
		_engineId,
		engineState,
		_receipts,
		_inboundApplications,
		std::nullopt,
		revision)) {
		Cleanse(engineState);
		return MlsStateCommitResult::PersistenceFailed;
	}
	Cleanse(_engineState);
	_engineState = std::move(engineState);
	_revision = revision;
	return MlsStateCommitResult::Committed;
}

MlsStateCommitResult PersistentMlsStateStore::commit(
		MlsStateMutation mutation) {
	const auto cleanseMutation = [&] {
		Cleanse(mutation.engineState);
		if (mutation.inboundApplication) {
			Cleanse(*mutation.inboundApplication);
		}
	};
	if (!_loaded) {
		cleanseMutation();
		return MlsStateCommitResult::NotLoaded;
	} else if (!_revision
		|| (mutation.removalTombstone
			? (!mutation.engineState.isEmpty()
				|| mutation.receipt
				|| mutation.inboundApplication
				|| !ValidRemovalTombstone(*mutation.removalTombstone))
			: !ValidEngineState(mutation.engineState))
		|| (mutation.receipt
			&& !ValidReceipt(_conversationId, *mutation.receipt))
		|| (mutation.inboundApplication
			&& !ValidInboundApplication(*mutation.inboundApplication))
		|| (mutation.receipt && mutation.inboundApplication)
		|| _removalTombstone) {
		cleanseMutation();
		return MlsStateCommitResult::InvalidMutation;
	}
	if (mutation.receipt) {
		const auto existing = receipt(mutation.receipt->objectId);
		if (existing) {
			cleanseMutation();
			return (*existing == *mutation.receipt)
				? MlsStateCommitResult::AlreadyCommitted
				: MlsStateCommitResult::InvalidMutation;
		}
	}
	if (mutation.inboundApplication) {
		const auto existing = inboundApplication(
			mutation.inboundApplication->objectId);
		if (existing) {
			cleanseMutation();
			return (*existing == *mutation.inboundApplication)
				? MlsStateCommitResult::AlreadyCommitted
				: MlsStateCommitResult::InvalidMutation;
		}
	}
	const auto operationId = mutation.receipt
		? mutation.receipt->objectId
		: mutation.inboundApplication
		? mutation.inboundApplication->objectId
		: ObjectId();
	if (operationId
		&& (receipt(operationId) || inboundApplication(operationId))) {
		cleanseMutation();
		return MlsStateCommitResult::InvalidMutation;
	}
	if (mutation.baseRevision != _revision) {
		cleanseMutation();
		return MlsStateCommitResult::RevisionConflict;
	} else if (_revision == std::numeric_limits<std::uint64_t>::max()) {
		cleanseMutation();
		return MlsStateCommitResult::InvalidMutation;
	}
	auto receipts = _receipts;
	auto inboundApplications = _inboundApplications;
	if (mutation.removalTombstone) {
		receipts.clear();
		Cleanse(inboundApplications);
		inboundApplications.clear();
	} else if (mutation.receipt) {
		receipts.push_back(std::move(*mutation.receipt));
	} else if (mutation.inboundApplication) {
		inboundApplications.push_back(
			std::move(*mutation.inboundApplication));
	}
	const auto revision = _revision + 1;
	if (!persist(
			_engineId,
		mutation.engineState,
		receipts,
		inboundApplications,
		mutation.removalTombstone,
		revision)) {
		Cleanse(inboundApplications);
		cleanseMutation();
		return MlsStateCommitResult::PersistenceFailed;
	}
	Cleanse(_engineState);
	Cleanse(_inboundApplications);
	_engineState = std::move(mutation.engineState);
	_receipts = std::move(receipts);
	_inboundApplications = std::move(inboundApplications);
	_removalTombstone = mutation.removalTombstone;
	_revision = revision;
	return MlsStateCommitResult::Committed;
}

bool PersistentMlsStateStore::acknowledgeReceipt(ObjectId objectId) {
	if (!receipt(objectId)) {
		return false;
	}
	return acknowledgeReceipts({ objectId });
}

bool PersistentMlsStateStore::acknowledgeReceipts(
		const std::vector<ObjectId> &objectIds) {
	if (!_loaded
		|| !_revision
		|| _revision == std::numeric_limits<std::uint64_t>::max()
		|| objectIds.empty()) {
		return false;
	}
	auto requested = std::set<ObjectId>();
	for (const auto &objectId : objectIds) {
		if (!objectId || !requested.emplace(objectId).second) {
			return false;
		}
	}
	auto receipts = _receipts;
	receipts.erase(
		std::remove_if(
			begin(receipts),
			end(receipts),
			[&](const MlsOperationReceipt &receipt) {
				return requested.contains(receipt.objectId);
			}),
		end(receipts));
	if (receipts.size() == _receipts.size()) {
		return true;
	}
	const auto revision = _revision + 1;
	if (!persist(
		_engineId,
		_engineState,
		receipts,
		_inboundApplications,
		_removalTombstone,
		revision)) {
		return false;
	}
	_receipts = std::move(receipts);
	_revision = revision;
	return true;
}

bool PersistentMlsStateStore::acknowledgeInboundApplication(
		ObjectId objectId) {
	if (!_loaded
		|| !_revision
		|| _revision == std::numeric_limits<std::uint64_t>::max()) {
		return false;
	}
	auto applications = _inboundApplications;
	const auto i = std::find_if(
		begin(applications),
		end(applications),
		[&](const MlsInboundApplication &application) {
			return application.objectId == objectId;
		});
	if (i == end(applications)) {
		Cleanse(applications);
		return false;
	}
	Cleanse(*i);
	applications.erase(i);
	const auto revision = _revision + 1;
	if (!persist(
		_engineId,
		_engineState,
		_receipts,
		applications,
		_removalTombstone,
		revision)) {
		Cleanse(applications);
		return false;
	}
	Cleanse(_inboundApplications);
	_inboundApplications = std::move(applications);
	_revision = revision;
	return true;
}

bool PersistentMlsStateStore::loaded() const {
	return _loaded;
}

ConversationId PersistentMlsStateStore::conversationId() const {
	return _conversationId;
}

std::uint64_t PersistentMlsStateStore::revision() const {
	return _revision;
}

const QByteArray &PersistentMlsStateStore::engineId() const {
	return _engineId;
}

const QByteArray &PersistentMlsStateStore::engineState() const {
	return _engineState;
}

bool PersistentMlsStateStore::removed() const {
	return _removalTombstone.has_value();
}

const std::optional<MlsRemovalTombstone>
		&PersistentMlsStateStore::removalTombstone() const {
	return _removalTombstone;
}

int PersistentMlsStateStore::receiptCount() const {
	return int(_receipts.size());
}

const std::vector<MlsOperationReceipt>
		&PersistentMlsStateStore::receipts() const {
	return _receipts;
}

std::optional<MlsOperationReceipt> PersistentMlsStateStore::receipt(
		ObjectId objectId) const {
	const auto i = std::find_if(
		begin(_receipts),
		end(_receipts),
		[&](const MlsOperationReceipt &receipt) {
			return receipt.objectId == objectId;
		});
	return (i != end(_receipts))
		? std::optional<MlsOperationReceipt>(*i)
		: std::nullopt;
}

int PersistentMlsStateStore::inboundApplicationCount() const {
	return int(_inboundApplications.size());
}

std::optional<MlsInboundApplication>
PersistentMlsStateStore::inboundApplication(ObjectId objectId) const {
	const auto i = std::find_if(
		begin(_inboundApplications),
		end(_inboundApplications),
		[&](const MlsInboundApplication &application) {
			return application.objectId == objectId;
		});
	return (i != end(_inboundApplications))
		? std::optional<MlsInboundApplication>(*i)
		: std::nullopt;
}

const std::vector<MlsInboundApplication>
		&PersistentMlsStateStore::inboundApplications() const {
	return _inboundApplications;
}

bool PersistentMlsStateStore::persist(
		const QByteArray &engineId,
		const QByteArray &engineState,
		const std::vector<MlsOperationReceipt> &receipts,
		const std::vector<MlsInboundApplication> &inboundApplications,
		const std::optional<MlsRemovalTombstone> &removalTombstone,
		std::uint64_t revision) const {
	auto encoded = EncodeSnapshot(
		_conversationId,
		engineId,
		engineState,
		receipts,
		inboundApplications,
		removalTombstone,
		revision);
	if (!encoded) {
		return false;
	}
	const auto protectedBytes = _protector.seal(
		Purpose(_conversationId),
		*encoded);
	Cleanse(*encoded);
	return protectedBytes && _blobStore.writeAtomic(*protectedBytes);
}

void PersistentMlsStateStore::clear() {
	Cleanse(_engineState);
	_conversationId = {};
	_engineId.clear();
	_engineState.clear();
	_receipts.clear();
	Cleanse(_inboundApplications);
	_inboundApplications.clear();
	_removalTombstone.reset();
	_revision = 0;
	_loaded = false;
}

} // namespace E2ECloud
