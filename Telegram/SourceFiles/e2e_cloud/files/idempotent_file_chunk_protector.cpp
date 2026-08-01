/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "e2e_cloud/files/idempotent_file_chunk_protector.h"

#include <openssl/crypto.h>
#include <openssl/evp.h>

#include <utility>

namespace E2ECloud {
namespace {

[[nodiscard]] Digest PlaintextHash(const QByteArray &plaintext) {
	auto result = Digest();
	auto size = 0U;
	if (plaintext.isEmpty()
		|| EVP_Digest(
			reinterpret_cast<const unsigned char*>(plaintext.constData()),
			plaintext.size(),
			result.bytes.data(),
			&size,
			EVP_sha256(),
			nullptr) != 1
		|| size != result.bytes.size()) {
		result.bytes.fill(0);
	}
	return result;
}

void Cleanse(QByteArray &bytes) {
	if (!bytes.isEmpty()) {
		OPENSSL_cleanse(bytes.data(), bytes.size());
	}
	bytes.clear();
}

} // namespace

bool HasExactFileChunkCiphertext(
		const FileChunkReadResult &stored,
		const QByteArray &ciphertext) {
	return stored.status == FileChunkReadStatus::Found
		&& stored.chunk.exactCiphertext == ciphertext;
}

bool IsSameFileChunkAuthorization(
		const FileChunkAuthorization &a,
		const FileChunkAuthorization &b) {
	return a.context.conversationId == b.context.conversationId
		&& a.context.fileId == b.context.fileId
		&& a.context.plaintextSize == b.context.plaintextSize
		&& a.context.chunkSize == b.context.chunkSize
		&& a.context.chunkCount == b.context.chunkCount
		&& a.context.noncePrefix == b.context.noncePrefix
		&& a.senderAccountId == b.senderAccountId
		&& a.senderClientId == b.senderClientId
		&& a.manifestEventObjectId == b.manifestEventObjectId
		&& a.manifestDigest == b.manifestDigest
		&& a.groupGeneration == b.groupGeneration;
}

IdempotentFileChunkProtector::IdempotentFileChunkProtector(
		const AesGcmFileChunkCipher &cipher,
		FileChunkCiphertextStore &store)
: _cipher(cipher)
, _store(store) {
}

PreparedFileChunk IdempotentFileChunkProtector::prepare(
		const FileEncryptionKey &key,
		const FileChunkContext &context,
		std::uint32_t chunkIndex,
		const QByteArray &plaintext) {
	if (!key.valid()
		|| !IsValidFileChunkContext(context)
		|| chunkIndex >= context.chunkCount) {
		return {
			.result = FileChunkPrepareResult::InvalidInput,
			.exactCiphertext = std::nullopt,
		};
	}
	const auto expectedSize = (chunkIndex < context.chunkCount - 1)
		? context.chunkSize
		: context.plaintextSize
			- std::uint64_t(context.chunkSize) * (context.chunkCount - 1);
	const auto hash = PlaintextHash(plaintext);
	if (!hash || plaintext.size() != int(expectedSize)) {
		return {
			.result = FileChunkPrepareResult::InvalidInput,
			.exactCiphertext = std::nullopt,
		};
	}
	auto stored = _store.read(
		context.conversationId,
		context.fileId,
		chunkIndex);
	if (stored.status != FileChunkReadStatus::Missing) {
		return fromStored(
			key,
			context,
			chunkIndex,
			plaintext,
			hash,
			std::move(stored));
	}
	auto encrypted = _cipher.encrypt(key, context, chunkIndex, plaintext);
	if (!encrypted) {
		return {
			.result = FileChunkPrepareResult::EncryptionFailed,
			.exactCiphertext = std::nullopt,
		};
	}
	const auto storedResult = _store.storeIfAbsent(
		context.conversationId,
		context.fileId,
		chunkIndex,
		{
			.plaintextHash = hash,
			.exactCiphertext = *encrypted,
		});
	if (storedResult == FileChunkStoreResult::Stored) {
		return {
			.result = FileChunkPrepareResult::Ready,
			.exactCiphertext = std::move(encrypted),
		};
	} else if (storedResult != FileChunkStoreResult::AlreadyExists) {
		return {
			.result = FileChunkPrepareResult::StorageFailed,
			.exactCiphertext = std::nullopt,
		};
	}
	return fromStored(
		key,
		context,
		chunkIndex,
		plaintext,
		hash,
		_store.read(
			context.conversationId,
			context.fileId,
			chunkIndex));
}

PreparedFileChunk IdempotentFileChunkProtector::fromStored(
		const FileEncryptionKey &key,
		const FileChunkContext &context,
		std::uint32_t chunkIndex,
		const QByteArray &plaintext,
		Digest plaintextHash,
		FileChunkReadResult stored) const {
	if (stored.status == FileChunkReadStatus::Error
		|| stored.status == FileChunkReadStatus::Missing
		|| !stored.chunk.plaintextHash
		|| stored.chunk.exactCiphertext.isEmpty()) {
		return {
			.result = FileChunkPrepareResult::StorageFailed,
			.exactCiphertext = std::nullopt,
		};
	} else if (stored.chunk.plaintextHash != plaintextHash) {
		return {
			.result = FileChunkPrepareResult::SourceChanged,
			.exactCiphertext = std::nullopt,
		};
	}
	auto opened = _cipher.decrypt(
		key,
		context,
		chunkIndex,
		stored.chunk.exactCiphertext);
	const auto matches = opened && *opened == plaintext;
	if (opened) {
		Cleanse(*opened);
	}
	if (!matches) {
		return {
			.result = FileChunkPrepareResult::StorageFailed,
			.exactCiphertext = std::nullopt,
		};
	}
	return {
		.result = FileChunkPrepareResult::Ready,
		.exactCiphertext = std::move(stored.chunk.exactCiphertext),
	};
}

} // namespace E2ECloud
