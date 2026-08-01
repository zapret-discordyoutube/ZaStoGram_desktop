/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#pragma once

#include "e2e_cloud/core/types.h"
#include "e2e_cloud/storage/local_storage.h"

#include <QtCore/QByteArray>

#include <cstdint>
#include <optional>

namespace E2ECloud {

struct PendingFileTransfer {
	ConversationId conversationId;
	ObjectId eventObjectId;
	ObjectId contentObjectId;
	std::uint64_t groupGeneration = 0;
	std::uint32_t nextChunkIndex = 0;
	QByteArray sourcePathUtf8;
	QByteArray manifestPlaintext;

	friend inline bool operator==(
		const PendingFileTransfer &,
		const PendingFileTransfer &) = default;
};

enum class FileTransferLoadResult {
	Loaded,
	Empty,
	ReadFailed,
	AuthenticationFailed,
	InvalidSnapshot,
};

enum class FileTransferCommitResult {
	Committed,
	AlreadyCommitted,
	InvalidMutation,
	PersistenceFailed,
};

class PersistentFileTransfer final {
public:
	PersistentFileTransfer(
		AtomicBlobStore &blobStore,
		const LocalRecordProtector &protector);
	~PersistentFileTransfer();

	[[nodiscard]] FileTransferLoadResult load(
		ConversationId conversationId);
	[[nodiscard]] FileTransferCommitResult begin(PendingFileTransfer transfer);
	[[nodiscard]] FileTransferCommitResult replace(
		PendingFileTransfer transfer);
	[[nodiscard]] FileTransferCommitResult advance(
		std::uint32_t completedChunkIndex);
	[[nodiscard]] FileTransferCommitResult clear();
	[[nodiscard]] const PendingFileTransfer *pending() const;
	[[nodiscard]] std::uint64_t revision() const;
	[[nodiscard]] bool loaded() const;

private:
	[[nodiscard]] bool persist(
		const PendingFileTransfer *pending,
		std::uint64_t revision) const;
	[[nodiscard]] bool valid(
		const PendingFileTransfer &transfer,
		ConversationId conversationId) const;

	AtomicBlobStore &_blobStore;
	const LocalRecordProtector &_protector;
	ConversationId _conversationId;
	std::optional<PendingFileTransfer> _pending;
	std::uint64_t _revision = 0;
	bool _loaded = false;
};

} // namespace E2ECloud
