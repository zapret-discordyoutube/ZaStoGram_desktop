/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "e2e_cloud/files/file_chunk_file_store.h"

#include <QtCore/QDir>
#include <QtCore/QFile>
#include <QtCore/QFileInfo>
#include <QtCore/QLockFile>
#include <QtCore/QSaveFile>

#include <algorithm>
#include <array>
#include <utility>

namespace E2ECloud {
namespace {

inline constexpr auto kMagic = std::array<std::uint8_t, 8>{
	'T', 'D', 'E', '2', 'E', 'F', 'C', 'L',
};
inline constexpr auto kHeaderSize = 8 + 2 + 32 + 32 + 4 + 32 + 4;
inline constexpr auto kMaximumCiphertextSize = 4 * 1024 * 1024 + 122;
inline constexpr auto kPurpose = "e2e-cloud-file-chunk-ledger-v1";

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

template <typename Array>
void ReadArray(const char *data, Array &value) {
	std::copy_n(
		reinterpret_cast<const std::uint8_t*>(data),
		value.size(),
		value.begin());
}

[[nodiscard]] QByteArray IdentifierBytes(const auto &identifier) {
	return QByteArray(
		reinterpret_cast<const char*>(identifier.bytes.data()),
		identifier.bytes.size());
}

} // namespace

FileChunkFileStore::FileChunkFileStore(
		QString rootPath,
		const LocalRecordProtector &protector)
: _rootPath(std::move(rootPath))
, _protector(protector) {
}

FileChunkReadResult FileChunkFileStore::read(
		ConversationId conversationId,
		FileId fileId,
		std::uint32_t chunkIndex) const {
	if (!conversationId || !fileId) {
		return { .status = FileChunkReadStatus::Error, .chunk = {} };
	}
	auto file = QFile(path(conversationId, fileId, chunkIndex));
	if (!file.exists()) {
		return { .status = FileChunkReadStatus::Missing, .chunk = {} };
	} else if (!file.open(QIODevice::ReadOnly)) {
		return { .status = FileChunkReadStatus::Error, .chunk = {} };
	}
	const auto protectedBytes = file.readAll();
	const auto plaintext = _protector.open(QByteArray(kPurpose), protectedBytes);
	if (!plaintext
		|| plaintext->size() < kHeaderSize
		|| !std::equal(
			begin(kMagic),
			end(kMagic),
			reinterpret_cast<const std::uint8_t*>(plaintext->constData()))
		|| ReadUint16(plaintext->constData() + 8) != 1) {
		return { .status = FileChunkReadStatus::Error, .chunk = {} };
	}
	auto storedConversationId = ConversationId();
	auto storedFileId = FileId();
	auto hash = Digest();
	ReadArray(plaintext->constData() + 10, storedConversationId.bytes);
	ReadArray(plaintext->constData() + 42, storedFileId.bytes);
	const auto storedIndex = ReadUint32(plaintext->constData() + 74);
	ReadArray(plaintext->constData() + 78, hash.bytes);
	const auto ciphertextSize = ReadUint32(plaintext->constData() + 110);
	if (storedConversationId != conversationId
		|| storedFileId != fileId
		|| storedIndex != chunkIndex
		|| !hash
		|| !ciphertextSize
		|| ciphertextSize > kMaximumCiphertextSize
		|| plaintext->size() != kHeaderSize + int(ciphertextSize)) {
		return { .status = FileChunkReadStatus::Error, .chunk = {} };
	}
	return {
		.status = FileChunkReadStatus::Found,
		.chunk = {
			.plaintextHash = hash,
			.exactCiphertext = QByteArray(
				plaintext->constData() + kHeaderSize,
				ciphertextSize),
		},
	};
}

FileChunkStoreResult FileChunkFileStore::storeIfAbsent(
		ConversationId conversationId,
		FileId fileId,
		std::uint32_t chunkIndex,
		StoredFileChunk chunk) {
	if (!conversationId
		|| !fileId
		|| !chunk.plaintextHash
		|| chunk.exactCiphertext.isEmpty()
		|| chunk.exactCiphertext.size() > kMaximumCiphertextSize) {
		return FileChunkStoreResult::Error;
	}
	const auto target = path(conversationId, fileId, chunkIndex);
	const auto directory = QFileInfo(target).absoluteDir();
	if (!directory.exists() && !QDir().mkpath(directory.absolutePath())) {
		return FileChunkStoreResult::Error;
	}
	auto lock = QLockFile(target + QString::fromLatin1(".lock"));
	if (!lock.tryLock(5000)) {
		return FileChunkStoreResult::Error;
	} else if (QFile::exists(target)) {
		return FileChunkStoreResult::AlreadyExists;
	}
	auto plaintext = QByteArray();
	plaintext.reserve(kHeaderSize + chunk.exactCiphertext.size());
	AppendArray(plaintext, kMagic);
	AppendUint16(plaintext, 1);
	AppendArray(plaintext, conversationId.bytes);
	AppendArray(plaintext, fileId.bytes);
	AppendUint32(plaintext, chunkIndex);
	AppendArray(plaintext, chunk.plaintextHash.bytes);
	AppendUint32(plaintext, std::uint32_t(chunk.exactCiphertext.size()));
	plaintext.append(chunk.exactCiphertext);
	const auto protectedBytes = _protector.seal(
		QByteArray(kPurpose),
		plaintext);
	if (!protectedBytes) {
		return FileChunkStoreResult::Error;
	}
	auto file = QSaveFile(target);
	if (!file.open(QIODevice::WriteOnly)) {
		return FileChunkStoreResult::Error;
	}
	file.setPermissions(QFileDevice::ReadOwner | QFileDevice::WriteOwner);
	if (file.write(*protectedBytes) != protectedBytes->size()) {
		file.cancelWriting();
		return FileChunkStoreResult::Error;
	}
	return file.commit()
		? FileChunkStoreResult::Stored
		: FileChunkStoreResult::Error;
}

QString FileChunkFileStore::path(
		ConversationId conversationId,
		FileId fileId,
		std::uint32_t chunkIndex) const {
	return QDir(_rootPath).filePath(
		QString::fromLatin1(IdentifierBytes(conversationId).toHex())
		+ QString::fromLatin1("/")
		+ QString::fromLatin1(IdentifierBytes(fileId).toHex())
		+ QString::fromLatin1("/")
		+ QString::number(chunkIndex)
		+ QString::fromLatin1(".fcl"));
}

} // namespace E2ECloud
