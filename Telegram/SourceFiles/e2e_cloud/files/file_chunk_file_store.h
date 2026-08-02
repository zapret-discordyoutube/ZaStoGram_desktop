/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#pragma once

#include "e2e_cloud/files/idempotent_file_chunk_protector.h"
#include "e2e_cloud/storage/local_storage.h"

#include <QtCore/QString>

namespace E2ECloud {

class FileChunkFileStore final : public FileChunkCiphertextStore {
public:
	FileChunkFileStore(
		QString rootPath,
		const LocalRecordProtector &protector,
		std::uint64_t maximumStoredBytes
			= std::uint64_t(8) * 1024 * 1024 * 1024);

	[[nodiscard]] FileChunkReadResult read(
		ConversationId conversationId,
		FileId fileId,
		std::uint32_t chunkIndex) const override;
	[[nodiscard]] FileChunkAuthorizationReadResult authorization(
		ConversationId conversationId,
		FileId fileId) const override;
	FileChunkAuthorizeResult authorize(
		FileChunkAuthorization authorization) override;
	FileChunkStoreResult storeIfAbsent(
		ConversationId conversationId,
		FileId fileId,
		std::uint32_t chunkIndex,
		StoredFileChunk chunk) override;
	[[nodiscard]] bool removeChunk(
		ConversationId conversationId,
		FileId fileId,
		std::uint32_t chunkIndex);

private:
	[[nodiscard]] QString path(
		ConversationId conversationId,
		FileId fileId,
		std::uint32_t chunkIndex) const;
	[[nodiscard]] QString authorizationPath(
		ConversationId conversationId,
		FileId fileId) const;
	[[nodiscard]] bool reserveStorage(
		const QString &target,
		std::uint64_t size);
	void releaseStorage(std::uint64_t size);

	QString _rootPath;
	const LocalRecordProtector &_protector;
	std::uint64_t _maximumStoredBytes = 0;
	std::uint64_t _storedBytes = 0;
};

} // namespace E2ECloud
