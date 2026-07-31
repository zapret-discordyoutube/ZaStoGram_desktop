/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#pragma once

#include "e2e_cloud/files/file_chunk_crypto.h"

#include <QtCore/QByteArray>

#include <cstdint>
#include <optional>

namespace E2ECloud {

enum class FileChunkReadStatus {
	Missing,
	Found,
	Error,
};

struct StoredFileChunk {
	Digest plaintextHash;
	QByteArray exactCiphertext;
};

struct FileChunkReadResult {
	FileChunkReadStatus status = FileChunkReadStatus::Missing;
	StoredFileChunk chunk;
};

enum class FileChunkStoreResult {
	Stored,
	AlreadyExists,
	Error,
};

class FileChunkCiphertextStore {
public:
	virtual ~FileChunkCiphertextStore() = default;

	[[nodiscard]] virtual FileChunkReadResult read(
		ConversationId conversationId,
		FileId fileId,
		std::uint32_t chunkIndex) const = 0;
	virtual FileChunkStoreResult storeIfAbsent(
		ConversationId conversationId,
		FileId fileId,
		std::uint32_t chunkIndex,
		StoredFileChunk chunk) = 0;
};

enum class FileChunkPrepareResult {
	Ready,
	SourceChanged,
	InvalidInput,
	EncryptionFailed,
	StorageFailed,
};

struct PreparedFileChunk {
	FileChunkPrepareResult result = FileChunkPrepareResult::InvalidInput;
	std::optional<QByteArray> exactCiphertext;
};

class IdempotentFileChunkProtector final {
public:
	IdempotentFileChunkProtector(
		const AesGcmFileChunkCipher &cipher,
		FileChunkCiphertextStore &store);

	[[nodiscard]] PreparedFileChunk prepare(
		const FileEncryptionKey &key,
		const FileChunkContext &context,
		std::uint32_t chunkIndex,
		const QByteArray &plaintext);

private:
	[[nodiscard]] PreparedFileChunk fromStored(
		const FileEncryptionKey &key,
		const FileChunkContext &context,
		std::uint32_t chunkIndex,
		const QByteArray &plaintext,
		Digest plaintextHash,
		FileChunkReadResult stored) const;

	const AesGcmFileChunkCipher &_cipher;
	FileChunkCiphertextStore &_store;
};

} // namespace E2ECloud
