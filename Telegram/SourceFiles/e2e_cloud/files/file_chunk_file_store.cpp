/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "e2e_cloud/files/file_chunk_file_store.h"

#include <openssl/crypto.h>

#include <QtCore/QDir>
#include <QtCore/QDirIterator>
#include <QtCore/QFile>
#include <QtCore/QFileInfo>
#include <QtCore/QLockFile>
#include <QtCore/QSaveFile>
#include <QtCore/QScopeGuard>
#include <QtCore/QStorageInfo>

#include <algorithm>
#include <array>
#include <limits>
#include <utility>

namespace E2ECloud {
namespace {

inline constexpr auto kMagic = std::array<std::uint8_t, 8>{
	'T', 'D', 'E', '2', 'E', 'F', 'C', 'L',
};
inline constexpr auto kAuthorizationMagic = std::array<std::uint8_t, 8>{
	'T', 'D', 'E', '2', 'E', 'F', 'C', 'A',
};
inline constexpr auto kHeaderSize = 8 + 2 + 32 + 32 + 4 + 32 + 4;
inline constexpr auto kAuthorizationSize
	= 8 + 2 + 32 + 32 + 8 + 4 + 4 + 8 + 32 + 16 + 32 + 32 + 8;
inline constexpr auto kMaximumCiphertextSize = 4 * 1024 * 1024 + 122;
inline constexpr auto kMaximumProtectedSize = qint64(
	kHeaderSize + kMaximumCiphertextSize + 42);
inline constexpr auto kMaximumAuthorizationProtectedSize
	= qint64(kAuthorizationSize + 42);
inline constexpr auto kPurpose = "e2e-cloud-file-chunk-ledger-v1";
inline constexpr auto kAuthorizationPurpose
	= "e2e-cloud-file-chunk-authorization-v1";
inline constexpr auto kMinimumFreeBytes
	= std::uint64_t(1024) * 1024 * 1024;

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

[[nodiscard]] QByteArray IdentifierBytes(const auto &identifier) {
	return QByteArray(
		reinterpret_cast<const char*>(identifier.bytes.data()),
		identifier.bytes.size());
}

void Cleanse(QByteArray &bytes) {
	if (!bytes.isEmpty()) {
		OPENSSL_cleanse(bytes.data(), bytes.size());
	}
	bytes.clear();
}

[[nodiscard]] std::uint64_t StoredBytes(const QString &rootPath) {
	auto result = std::uint64_t(0);
	auto iterator = QDirIterator(
		rootPath,
		QDir::Files | QDir::NoSymLinks,
		QDirIterator::Subdirectories);
	while (iterator.hasNext()) {
		iterator.next();
		const auto size = iterator.fileInfo().size();
		if (size <= 0) {
			continue;
		}
		const auto unsignedSize = std::uint64_t(size);
		if (result > std::numeric_limits<std::uint64_t>::max()
				- unsignedSize) {
			return std::numeric_limits<std::uint64_t>::max();
		}
		result += unsignedSize;
	}
	return result;
}

[[nodiscard]] std::optional<QByteArray> EncodeAuthorization(
		const FileChunkAuthorization &authorization) {
	if (!IsValidFileChunkContext(authorization.context)
		|| !authorization.senderAccountId
		|| !authorization.senderClientId
		|| !authorization.manifestEventObjectId
		|| !authorization.manifestDigest
		|| !authorization.groupGeneration) {
		return std::nullopt;
	}
	auto result = QByteArray();
	result.reserve(kAuthorizationSize);
	AppendArray(result, kAuthorizationMagic);
	AppendUint16(result, 1);
	AppendArray(result, authorization.context.conversationId.bytes);
	AppendArray(result, authorization.context.fileId.bytes);
	AppendUint64(result, authorization.context.plaintextSize);
	AppendUint32(result, authorization.context.chunkSize);
	AppendUint32(result, authorization.context.chunkCount);
	AppendArray(result, authorization.context.noncePrefix);
	AppendArray(result, authorization.senderAccountId.bytes);
	AppendArray(result, authorization.senderClientId.bytes);
	AppendArray(result, authorization.manifestEventObjectId.bytes);
	AppendArray(result, authorization.manifestDigest.bytes);
	AppendUint64(result, authorization.groupGeneration);
	return result.size() == kAuthorizationSize
		? std::optional<QByteArray>(std::move(result))
		: std::nullopt;
}

[[nodiscard]] std::optional<FileChunkAuthorization> DecodeAuthorization(
		const QByteArray &bytes) {
	if (bytes.size() != kAuthorizationSize
		|| !std::equal(
			begin(kAuthorizationMagic),
			end(kAuthorizationMagic),
			reinterpret_cast<const std::uint8_t*>(bytes.constData()))
		|| ReadUint16(bytes.constData() + 8) != 1) {
		return std::nullopt;
	}
	auto result = FileChunkAuthorization();
	ReadArray(bytes.constData() + 10, result.context.conversationId.bytes);
	ReadArray(bytes.constData() + 42, result.context.fileId.bytes);
	result.context.plaintextSize = ReadUint64(bytes.constData() + 74);
	result.context.chunkSize = ReadUint32(bytes.constData() + 82);
	result.context.chunkCount = ReadUint32(bytes.constData() + 86);
	ReadArray(bytes.constData() + 90, result.context.noncePrefix);
	ReadArray(bytes.constData() + 98, result.senderAccountId.bytes);
	ReadArray(bytes.constData() + 130, result.senderClientId.bytes);
	ReadArray(bytes.constData() + 146, result.manifestEventObjectId.bytes);
	ReadArray(bytes.constData() + 178, result.manifestDigest.bytes);
	result.groupGeneration = ReadUint64(bytes.constData() + 210);
	return IsValidFileChunkContext(result.context)
		&& result.senderAccountId
		&& result.senderClientId
		&& result.manifestEventObjectId
		&& result.manifestDigest
		&& result.groupGeneration
		? std::optional<FileChunkAuthorization>(std::move(result))
		: std::nullopt;
}

} // namespace

FileChunkFileStore::FileChunkFileStore(
		QString rootPath,
		const LocalRecordProtector &protector,
		std::uint64_t maximumStoredBytes)
: _rootPath(std::move(rootPath))
, _protector(protector)
, _maximumStoredBytes(maximumStoredBytes)
, _storedBytes(StoredBytes(_rootPath)) {
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
	const auto size = file.size();
	if (size <= 0 || size > kMaximumProtectedSize) {
		return { .status = FileChunkReadStatus::Error, .chunk = {} };
	}
	const auto protectedBytes = file.read(size);
	if (protectedBytes.size() != size) {
		return { .status = FileChunkReadStatus::Error, .chunk = {} };
	}
	auto plaintext = _protector.open(QByteArray(kPurpose), protectedBytes);
	const auto fail = [&] {
		if (plaintext) {
			Cleanse(*plaintext);
		}
		return FileChunkReadResult{
			.status = FileChunkReadStatus::Error,
			.chunk = {},
		};
	};
	if (!plaintext
		|| plaintext->size() < kHeaderSize
		|| !std::equal(
			begin(kMagic),
			end(kMagic),
			reinterpret_cast<const std::uint8_t*>(plaintext->constData()))
		|| ReadUint16(plaintext->constData() + 8) != 1) {
		return fail();
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
		return fail();
	}
	auto result = FileChunkReadResult{
		.status = FileChunkReadStatus::Found,
		.chunk = {
			.plaintextHash = hash,
			.exactCiphertext = QByteArray(
				plaintext->constData() + kHeaderSize,
				ciphertextSize),
		},
	};
	Cleanse(*plaintext);
	return result;
}

FileChunkAuthorizationReadResult FileChunkFileStore::authorization(
		ConversationId conversationId,
		FileId fileId) const {
	if (!conversationId || !fileId) {
		return {
			.status = FileChunkAuthorizationReadStatus::Error,
			.authorization = {},
		};
	}
	auto file = QFile(authorizationPath(conversationId, fileId));
	if (!file.exists()) {
		return {
			.status = FileChunkAuthorizationReadStatus::Missing,
			.authorization = {},
		};
	} else if (!file.open(QIODevice::ReadOnly)
		|| file.size() <= 0
		|| file.size() > kMaximumAuthorizationProtectedSize) {
		return {
			.status = FileChunkAuthorizationReadStatus::Error,
			.authorization = {},
		};
	}
	const auto size = file.size();
	const auto protectedBytes = file.read(size);
	if (protectedBytes.size() != size) {
		return {
			.status = FileChunkAuthorizationReadStatus::Error,
			.authorization = {},
		};
	}
	auto plaintext = _protector.open(
		QByteArray(kAuthorizationPurpose),
		protectedBytes);
	const auto result = plaintext
		? DecodeAuthorization(*plaintext)
		: std::nullopt;
	if (plaintext) {
		Cleanse(*plaintext);
	}
	if (!result
		|| result->context.conversationId != conversationId
		|| result->context.fileId != fileId) {
		return {
			.status = FileChunkAuthorizationReadStatus::Error,
			.authorization = {},
		};
	}
	return {
		.status = FileChunkAuthorizationReadStatus::Found,
		.authorization = *result,
	};
}

FileChunkAuthorizeResult FileChunkFileStore::authorize(
		FileChunkAuthorization authorization) {
	auto plaintext = EncodeAuthorization(authorization);
	if (!plaintext) {
		return FileChunkAuthorizeResult::Error;
	}
	const auto target = authorizationPath(
		authorization.context.conversationId,
		authorization.context.fileId);
	const auto directory = QFileInfo(target).absoluteDir();
	if (!directory.exists() && !QDir().mkpath(directory.absolutePath())) {
		return FileChunkAuthorizeResult::Error;
	}
	auto lock = QLockFile(target + QString::fromLatin1(".lock"));
	if (!lock.tryLock(5000)) {
		return FileChunkAuthorizeResult::Error;
	} else if (QFile::exists(target)) {
		const auto existing = this->authorization(
			authorization.context.conversationId,
			authorization.context.fileId);
		if (existing.status != FileChunkAuthorizationReadStatus::Found) {
			return FileChunkAuthorizeResult::Error;
		}
		return IsSameFileChunkAuthorization(
			existing.authorization,
			authorization)
			? FileChunkAuthorizeResult::AlreadyAuthorized
			: FileChunkAuthorizeResult::Conflict;
	}
	auto protectedBytes = _protector.seal(
		QByteArray(kAuthorizationPurpose),
		*plaintext);
	Cleanse(*plaintext);
	if (!protectedBytes) {
		return FileChunkAuthorizeResult::Error;
	}
	const auto protectedSize = std::uint64_t(protectedBytes->size());
	if (!reserveStorage(target, protectedSize)) {
		return FileChunkAuthorizeResult::QuotaExceeded;
	}
	auto reservation = qScopeGuard([&] {
		releaseStorage(protectedSize);
	});
	auto file = QSaveFile(target);
	if (!file.open(QIODevice::WriteOnly)) {
		return FileChunkAuthorizeResult::Error;
	}
	file.setPermissions(QFileDevice::ReadOwner | QFileDevice::WriteOwner);
	if (file.write(*protectedBytes) != protectedBytes->size()) {
		file.cancelWriting();
		return FileChunkAuthorizeResult::Error;
	} else if (!file.commit()) {
		return FileChunkAuthorizeResult::Error;
	}
	reservation.dismiss();
	return FileChunkAuthorizeResult::Authorized;
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
	Cleanse(plaintext);
	if (!protectedBytes) {
		return FileChunkStoreResult::Error;
	}
	const auto protectedSize = std::uint64_t(protectedBytes->size());
	if (!reserveStorage(target, protectedSize)) {
		return FileChunkStoreResult::QuotaExceeded;
	}
	auto reservation = qScopeGuard([&] {
		releaseStorage(protectedSize);
	});
	auto file = QSaveFile(target);
	if (!file.open(QIODevice::WriteOnly)) {
		return FileChunkStoreResult::Error;
	}
	file.setPermissions(QFileDevice::ReadOwner | QFileDevice::WriteOwner);
	if (file.write(*protectedBytes) != protectedBytes->size()) {
		file.cancelWriting();
		return FileChunkStoreResult::Error;
	}
	if (!file.commit()) {
		return FileChunkStoreResult::Error;
	}
	reservation.dismiss();
	return FileChunkStoreResult::Stored;
}

bool FileChunkFileStore::removeChunk(
		ConversationId conversationId,
		FileId fileId,
		std::uint32_t chunkIndex) {
	if (!conversationId || !fileId) {
		return false;
	}
	const auto target = path(conversationId, fileId, chunkIndex);
	const auto directory = QFileInfo(target).absoluteDir();
	if (!directory.exists()) {
		return true;
	}
	auto lock = QLockFile(target + QString::fromLatin1(".lock"));
	if (!lock.tryLock(5000)) {
		return false;
	}
	const auto info = QFileInfo(target);
	if (!info.exists()) {
		return true;
	}
	const auto size = info.size();
	if (!info.isFile() || info.isSymLink() || !QFile::remove(target)) {
		return false;
	}
	if (size > 0) {
		releaseStorage(std::uint64_t(size));
	}
	return true;
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

QString FileChunkFileStore::authorizationPath(
		ConversationId conversationId,
		FileId fileId) const {
	return QDir(_rootPath).filePath(
		QString::fromLatin1(IdentifierBytes(conversationId).toHex())
		+ QString::fromLatin1("/")
		+ QString::fromLatin1(IdentifierBytes(fileId).toHex())
		+ QString::fromLatin1("/manifest.fca"));
}

bool FileChunkFileStore::reserveStorage(
		const QString &target,
		std::uint64_t size) {
	if (!size
		|| size > _maximumStoredBytes
		|| _storedBytes > _maximumStoredBytes - size) {
		return false;
	}
	auto storage = QStorageInfo(QFileInfo(target).absolutePath());
	storage.refresh();
	if (storage.isValid() && storage.isReady()) {
		const auto available = storage.bytesAvailable();
		if (available < 0
			|| std::uint64_t(available) < size
			|| std::uint64_t(available) - size < kMinimumFreeBytes) {
			return false;
		}
	}
	_storedBytes += size;
	return true;
}

void FileChunkFileStore::releaseStorage(std::uint64_t size) {
	_storedBytes = (_storedBytes >= size) ? (_storedBytes - size) : 0;
}

} // namespace E2ECloud
