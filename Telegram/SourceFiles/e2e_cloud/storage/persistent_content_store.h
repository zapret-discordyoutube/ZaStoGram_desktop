/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#pragma once

#include "e2e_cloud/core/envelope.h"
#include "e2e_cloud/storage/local_storage.h"

#include <QtCore/QByteArray>
#include <QtCore/QString>

#include <cstddef>
#include <cstdint>
#include <optional>
#include <vector>

namespace E2ECloud {

class Sha256Provider;

struct ProtectedContentRecord {
	ConversationId conversationId;
	ObjectId eventObjectId;
	ObjectId contentObjectId;
	ObjectKind objectKind = ObjectKind::EncryptedMessageBody;
	std::uint64_t groupGeneration = 0;
	AccountId senderAccountId;
	ClientId senderClientId;
	std::uint64_t unixTime = 0;
	std::int64_t observedTelegramMessageId = 0;
	QByteArray plaintext;

	friend inline bool operator==(
		const ProtectedContentRecord &,
		const ProtectedContentRecord &) = default;
};

enum class ContentStoreLoadResult {
	Loaded,
	Missing,
	ReadFailed,
	AuthenticationFailed,
	InvalidSnapshot,
};

enum class ContentStoreAppendResult {
	Stored,
	AlreadyStored,
	Conflict,
	InvalidRecord,
	PersistenceFailed,
};

class PersistentContentStore final {
public:
	PersistentContentStore(
		ConversationId conversationId,
		QString recordsDirectory,
		AtomicBlobStore &indexBlobStore,
		const LocalRecordProtector &protector,
		const Sha256Provider &sha256);
	~PersistentContentStore();

	[[nodiscard]] ContentStoreLoadResult load();
	[[nodiscard]] ContentStoreAppendResult append(
		ProtectedContentRecord record);
	[[nodiscard]] std::optional<ProtectedContentRecord> record(
		ObjectId eventObjectId) const;
	[[nodiscard]] std::vector<ProtectedContentRecord> records(
		std::size_t offset,
		std::size_t limit,
		std::optional<ObjectKind> kind = std::nullopt) const;
	[[nodiscard]] std::size_t size(
		std::optional<ObjectKind> kind = std::nullopt) const;
	[[nodiscard]] std::uint64_t revision() const;
	[[nodiscard]] bool loaded() const;

private:
	struct IndexEntry {
		ObjectId eventObjectId;
		Digest recordHash;
		ObjectKind objectKind = ObjectKind::EncryptedMessageBody;
		std::uint64_t unixTime = 0;
		std::optional<std::int64_t> observedTelegramMessageId;
	};

	[[nodiscard]] QString recordPath(ObjectId eventObjectId) const;
	[[nodiscard]] QByteArray recordPurpose(ObjectId eventObjectId) const;
	[[nodiscard]] std::optional<ProtectedContentRecord> readRecord(
		const IndexEntry &entry) const;
	void rebuildOrderedEntries();
	[[nodiscard]] bool persistIndex(
		const std::vector<IndexEntry> &entries,
		std::uint64_t revision) const;

	ConversationId _conversationId;
	QString _recordsDirectory;
	AtomicBlobStore &_indexBlobStore;
	const LocalRecordProtector &_protector;
	const Sha256Provider &_sha256;
	std::vector<IndexEntry> _entries;
	std::vector<std::size_t> _orderedEntries;
	std::uint64_t _revision = 0;
	bool _loaded = false;
};

} // namespace E2ECloud
