/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#pragma once

#include "e2e_cloud/core/types.h"

#include <QtCore/QByteArray>

#include <array>
#include <cstdint>
#include <optional>

namespace E2ECloud {

class FileEncryptionKey final {
public:
	FileEncryptionKey();
	explicit FileEncryptionKey(std::array<std::uint8_t, 32> &&bytes);
	FileEncryptionKey(const FileEncryptionKey &) = delete;
	FileEncryptionKey &operator=(const FileEncryptionKey &) = delete;
	FileEncryptionKey(FileEncryptionKey &&other) noexcept;
	FileEncryptionKey &operator=(FileEncryptionKey &&other) noexcept;
	~FileEncryptionKey();

	[[nodiscard]] bool valid() const;
	[[nodiscard]] const std::array<std::uint8_t, 32> &bytes() const;

private:
	std::array<std::uint8_t, 32> _bytes = {};
};

struct FileEncryptionMaterial {
	FileId fileId;
	FileEncryptionKey key;
	std::array<std::uint8_t, 8> noncePrefix = {};
};

struct FileChunkContext {
	ConversationId conversationId;
	FileId fileId;
	std::uint64_t plaintextSize = 0;
	std::uint32_t chunkSize = 0;
	std::uint32_t chunkCount = 0;
	std::array<std::uint8_t, 8> noncePrefix = {};
};

[[nodiscard]] std::optional<FileEncryptionMaterial>
	GenerateFileEncryptionMaterial();
[[nodiscard]] bool IsValidFileChunkContext(const FileChunkContext &context);

class AesGcmFileChunkCipher final {
public:
	[[nodiscard]] std::optional<QByteArray> encrypt(
		const FileEncryptionKey &key,
		const FileChunkContext &context,
		std::uint32_t chunkIndex,
		const QByteArray &plaintext) const;
	[[nodiscard]] std::optional<QByteArray> decrypt(
		const FileEncryptionKey &key,
		const FileChunkContext &context,
		std::uint32_t expectedChunkIndex,
		const QByteArray &encoded) const;
};

} // namespace E2ECloud
