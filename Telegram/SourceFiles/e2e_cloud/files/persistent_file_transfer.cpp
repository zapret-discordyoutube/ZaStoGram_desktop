/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "e2e_cloud/files/persistent_file_transfer.h"

#include "e2e_cloud/files/private_file_manifest.h"

#include <openssl/crypto.h>

#include <algorithm>
#include <array>
#include <limits>

namespace E2ECloud {
namespace {

inline constexpr auto kMagic = std::array<std::uint8_t, 8>{
	'T', 'D', 'E', '2', 'E', 'F', 'T', 'R',
};
inline constexpr auto kPurpose = "e2e-cloud-file-transfer-v1";
inline constexpr auto kMaximumSourcePathSize = 16 * 1024;
inline constexpr auto kMaximumManifestSize
	= kMaximumPrivateFilePreviewSize + 2 * 1024;
inline constexpr auto kHeaderSize = 8 + 2 + 32 + 8 + 1;
inline constexpr auto kPendingFixedSizeV1 = 32 + 32 + 8 + 4 + 4 + 4;
inline constexpr auto kPendingFixedSizeV2
	= 32 + 32 + 8 + 8 + 1 + 4 + 4 + 4;
inline constexpr auto kPendingFixedSizeV3
	= 32 + 32 + 8 + 8 + 1 + 1 + 4 + 4 + 4;

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
		int maximum,
		QByteArray &value) {
	auto size = std::uint32_t();
	if (!ReadUint32(reader, size)
		|| size > std::uint32_t(maximum)
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

void Cleanse(PendingFileTransfer &transfer) {
	Cleanse(transfer.sourcePathUtf8);
	Cleanse(transfer.manifestPlaintext);
}

} // namespace

PersistentFileTransfer::PersistentFileTransfer(
		AtomicBlobStore &blobStore,
		const LocalRecordProtector &protector)
: _blobStore(blobStore)
, _protector(protector) {
}

PersistentFileTransfer::~PersistentFileTransfer() {
	if (_pending) {
		Cleanse(*_pending);
	}
}

FileTransferLoadResult PersistentFileTransfer::load(
		ConversationId conversationId) {
	_conversationId = {};
	if (_pending) {
		Cleanse(*_pending);
	}
	_pending.reset();
	_revision = 0;
	_loaded = false;
	if (!conversationId) {
		return FileTransferLoadResult::InvalidSnapshot;
	}
	const auto stored = _blobStore.read();
	if (stored.status == BlobReadStatus::Missing) {
		_conversationId = conversationId;
		_loaded = true;
		return FileTransferLoadResult::Empty;
	} else if (stored.status != BlobReadStatus::Found) {
		return FileTransferLoadResult::ReadFailed;
	}
	auto plaintext = _protector.open(QByteArray(kPurpose), stored.bytes);
	if (!plaintext) {
		return FileTransferLoadResult::AuthenticationFailed;
	}
	auto pending = std::optional<PendingFileTransfer>();
	const auto fail = [&] {
		if (pending) {
			Cleanse(*pending);
		}
		Cleanse(*plaintext);
		return FileTransferLoadResult::InvalidSnapshot;
	};
	if (plaintext->size() < kHeaderSize) {
		return fail();
	}
	auto reader = Reader{ *plaintext };
	auto magic = std::array<std::uint8_t, 8>();
	auto version = std::uint16_t();
	auto storedConversationId = ConversationId();
	auto revision = std::uint64_t();
	auto present = std::uint8_t();
	if (!ReadArray(reader, magic)
		|| !ReadUint16(reader, version)
		|| !ReadArray(reader, storedConversationId.bytes)
		|| !ReadUint64(reader, revision)
		|| !ReadUint8(reader, present)
		|| magic != kMagic
		|| (version != 1 && version != 2 && version != 3)
		|| storedConversationId != conversationId
		|| present > 1
		|| (!revision && present)) {
		return fail();
	}
	if (present) {
		auto value = PendingFileTransfer{
			.conversationId = conversationId,
			.eventObjectId = {},
			.contentObjectId = {},
			.groupGeneration = 0,
			.archiveEpochGeneration = 0,
			.manifestPublished = false,
			.cancelRequested = false,
			.nextChunkIndex = 0,
			.sourcePathUtf8 = {},
			.manifestPlaintext = {},
		};
		auto manifestPublished = std::uint8_t();
		auto cancelRequested = std::uint8_t();
		auto parsed = reader.bytes.size() - reader.offset
				>= ((version == 1)
					? kPendingFixedSizeV1
					: (version == 2)
					? kPendingFixedSizeV2
					: kPendingFixedSizeV3)
			&& ReadArray(reader, value.eventObjectId.bytes)
			&& ReadArray(reader, value.contentObjectId.bytes)
			&& ReadUint64(reader, value.groupGeneration)
			&& (version == 1 || ReadUint64(
				reader,
				value.archiveEpochGeneration))
			&& (version == 1 || (ReadUint8(reader, manifestPublished)
				&& manifestPublished <= 1))
			&& (version != 3 || (ReadUint8(reader, cancelRequested)
				&& cancelRequested <= 1))
			&& ReadUint32(reader, value.nextChunkIndex)
			&& ReadBytes(
				reader,
				kMaximumSourcePathSize,
				value.sourcePathUtf8)
			&& ReadBytes(
				reader,
				kMaximumManifestSize,
				value.manifestPlaintext);
		value.manifestPublished = (manifestPublished != 0);
		value.cancelRequested = (cancelRequested != 0);
		parsed = parsed && valid(value, conversationId);
		if (!parsed) {
			Cleanse(value);
			return fail();
		}
		pending = std::move(value);
	}
	if (reader.offset != plaintext->size()) {
		return fail();
	}
	Cleanse(*plaintext);
	_conversationId = conversationId;
	_pending = std::move(pending);
	_revision = revision;
	_loaded = true;
	return _pending
		? FileTransferLoadResult::Loaded
		: FileTransferLoadResult::Empty;
}

FileTransferCommitResult PersistentFileTransfer::begin(
		PendingFileTransfer transfer) {
	if (!_loaded
		|| _pending
		|| transfer.cancelRequested
		|| transfer.conversationId != _conversationId
		|| !valid(transfer, _conversationId)
		|| _revision == std::numeric_limits<std::uint64_t>::max()) {
		Cleanse(transfer);
		return FileTransferCommitResult::InvalidMutation;
	}
	const auto revision = _revision + 1;
	if (!persist(&transfer, revision)) {
		Cleanse(transfer);
		return FileTransferCommitResult::PersistenceFailed;
	}
	_pending = std::move(transfer);
	_revision = revision;
	return FileTransferCommitResult::Committed;
}

FileTransferCommitResult PersistentFileTransfer::replace(
		PendingFileTransfer transfer) {
	if (!_loaded
		|| !_pending
		|| transfer.cancelRequested
		|| transfer.conversationId != _conversationId
		|| !valid(transfer, _conversationId)
		|| _revision == std::numeric_limits<std::uint64_t>::max()) {
		Cleanse(transfer);
		return FileTransferCommitResult::InvalidMutation;
	}
	const auto revision = _revision + 1;
	if (!persist(&transfer, revision)) {
		Cleanse(transfer);
		return FileTransferCommitResult::PersistenceFailed;
	}
	Cleanse(*_pending);
	_pending = std::move(transfer);
	_revision = revision;
	return FileTransferCommitResult::Committed;
}

FileTransferCommitResult PersistentFileTransfer::markManifestPublished(
		std::uint64_t archiveEpochGeneration) {
	if (!_loaded
		|| !_pending
		|| !archiveEpochGeneration
		|| (_pending->archiveEpochGeneration
			&& _pending->archiveEpochGeneration != archiveEpochGeneration)) {
		return FileTransferCommitResult::InvalidMutation;
	} else if (_pending->manifestPublished) {
		return FileTransferCommitResult::AlreadyCommitted;
	} else if (_revision == std::numeric_limits<std::uint64_t>::max()) {
		return FileTransferCommitResult::PersistenceFailed;
	}
	auto next = *_pending;
	next.archiveEpochGeneration = archiveEpochGeneration;
	next.manifestPublished = true;
	const auto revision = _revision + 1;
	if (!persist(&next, revision)) {
		Cleanse(next);
		return FileTransferCommitResult::PersistenceFailed;
	}
	Cleanse(*_pending);
	_pending = std::move(next);
	_revision = revision;
	return FileTransferCommitResult::Committed;
}

FileTransferCommitResult PersistentFileTransfer::requestCancel() {
	if (!_loaded || !_pending) {
		return FileTransferCommitResult::InvalidMutation;
	} else if (_pending->cancelRequested) {
		return FileTransferCommitResult::AlreadyCommitted;
	} else if (_revision == std::numeric_limits<std::uint64_t>::max()) {
		return FileTransferCommitResult::PersistenceFailed;
	}
	auto next = *_pending;
	next.cancelRequested = true;
	const auto revision = _revision + 1;
	if (!persist(&next, revision)) {
		Cleanse(next);
		return FileTransferCommitResult::PersistenceFailed;
	}
	Cleanse(*_pending);
	_pending = std::move(next);
	_revision = revision;
	return FileTransferCommitResult::Committed;
}

FileTransferCommitResult PersistentFileTransfer::advance(
		std::uint32_t completedChunkIndex) {
	if (!_loaded || !_pending) {
		return FileTransferCommitResult::InvalidMutation;
	}
	const auto manifest = PrivateFileManifestCodecV1().decodePlaintext(
		_pending->manifestPlaintext);
	if (!manifest
		|| !_pending->manifestPublished
		|| _pending->cancelRequested
		|| completedChunkIndex != _pending->nextChunkIndex
		|| completedChunkIndex >= manifest->context.chunkCount
		|| _revision == std::numeric_limits<std::uint64_t>::max()) {
		return FileTransferCommitResult::InvalidMutation;
	}
	auto next = *_pending;
	++next.nextChunkIndex;
	const auto revision = _revision + 1;
	if (!persist(&next, revision)) {
		Cleanse(next);
		return FileTransferCommitResult::PersistenceFailed;
	}
	Cleanse(*_pending);
	_pending = std::move(next);
	_revision = revision;
	return FileTransferCommitResult::Committed;
}

FileTransferCommitResult PersistentFileTransfer::clear() {
	if (!_loaded || !_pending) {
		return FileTransferCommitResult::AlreadyCommitted;
	} else if (_revision == std::numeric_limits<std::uint64_t>::max()) {
		return FileTransferCommitResult::PersistenceFailed;
	}
	const auto revision = _revision + 1;
	if (!persist(nullptr, revision)) {
		return FileTransferCommitResult::PersistenceFailed;
	}
	Cleanse(*_pending);
	_pending.reset();
	_revision = revision;
	return FileTransferCommitResult::Committed;
}

const PendingFileTransfer *PersistentFileTransfer::pending() const {
	return _pending ? &*_pending : nullptr;
}

std::uint64_t PersistentFileTransfer::revision() const {
	return _revision;
}

bool PersistentFileTransfer::loaded() const {
	return _loaded;
}

bool PersistentFileTransfer::persist(
		const PendingFileTransfer *pending,
		std::uint64_t revision) const {
	if (!_conversationId
		|| !revision
		|| (pending && !valid(*pending, _conversationId))) {
		return false;
	}
	auto plaintext = QByteArray();
	plaintext.reserve(kHeaderSize + (pending
		? kPendingFixedSizeV3
			+ pending->sourcePathUtf8.size()
			+ pending->manifestPlaintext.size()
		: 0));
	AppendArray(plaintext, kMagic);
	AppendUint16(plaintext, 3);
	AppendArray(plaintext, _conversationId.bytes);
	AppendUint64(plaintext, revision);
	AppendUint8(plaintext, pending ? 1 : 0);
	if (pending) {
		AppendArray(plaintext, pending->eventObjectId.bytes);
		AppendArray(plaintext, pending->contentObjectId.bytes);
		AppendUint64(plaintext, pending->groupGeneration);
		AppendUint64(plaintext, pending->archiveEpochGeneration);
		AppendUint8(plaintext, pending->manifestPublished ? 1 : 0);
		AppendUint8(plaintext, pending->cancelRequested ? 1 : 0);
		AppendUint32(plaintext, pending->nextChunkIndex);
		AppendUint32(
			plaintext,
			std::uint32_t(pending->sourcePathUtf8.size()));
		plaintext.append(pending->sourcePathUtf8);
		AppendUint32(
			plaintext,
			std::uint32_t(pending->manifestPlaintext.size()));
		plaintext.append(pending->manifestPlaintext);
	}
	const auto protectedBytes = _protector.seal(
		QByteArray(kPurpose),
		plaintext);
	Cleanse(plaintext);
	return protectedBytes && _blobStore.writeAtomic(*protectedBytes);
}

bool PersistentFileTransfer::valid(
		const PendingFileTransfer &transfer,
		ConversationId conversationId) const {
	const auto manifest = PrivateFileManifestCodecV1().decodePlaintext(
		transfer.manifestPlaintext);
	return conversationId
		&& transfer.conversationId == conversationId
		&& transfer.eventObjectId
		&& transfer.contentObjectId
		&& transfer.eventObjectId != transfer.contentObjectId
		&& transfer.groupGeneration
		&& (!transfer.manifestPublished
			|| transfer.archiveEpochGeneration)
		&& !transfer.sourcePathUtf8.isEmpty()
		&& transfer.sourcePathUtf8.size() <= kMaximumSourcePathSize
		&& transfer.manifestPlaintext.size() <= kMaximumManifestSize
		&& manifest
		&& manifest->context.conversationId == transfer.conversationId
		&& transfer.nextChunkIndex <= manifest->context.chunkCount;
}

} // namespace E2ECloud
