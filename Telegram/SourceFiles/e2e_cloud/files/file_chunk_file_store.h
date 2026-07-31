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
		const LocalRecordProtector &protector);

	[[nodiscard]] FileChunkReadResult read(
		ConversationId conversationId,
		FileId fileId,
		std::uint32_t chunkIndex) const override;
	FileChunkStoreResult storeIfAbsent(
		ConversationId conversationId,
		FileId fileId,
		std::uint32_t chunkIndex,
		StoredFileChunk chunk) override;

private:
	[[nodiscard]] QString path(
		ConversationId conversationId,
		FileId fileId,
		std::uint32_t chunkIndex) const;

	QString _rootPath;
	const LocalRecordProtector &_protector;
};

} // namespace E2ECloud
