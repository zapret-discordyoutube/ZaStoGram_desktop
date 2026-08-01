/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#pragma once

#include "e2e_cloud/core/interfaces.h"
#include "e2e_cloud/storage/local_storage.h"

#include <cstdint>
#include <optional>
#include <vector>

namespace E2ECloud {

struct MlsOperationReceipt {
	ObjectId objectId;
	Digest requestHash;
	EncodedEnvelope envelope;

	friend inline bool operator==(
		const MlsOperationReceipt &,
		const MlsOperationReceipt &) = default;
};

struct MlsInboundApplication {
	ObjectId objectId;
	Digest payloadHash;
	std::uint64_t epoch = 0;
	AccountId senderAccountId;
	ClientId senderClientId;
	std::uint32_t senderLeafIndex = 0;
	QByteArray plaintext;
	QByteArray context;

	friend inline bool operator==(
		const MlsInboundApplication &,
		const MlsInboundApplication &) = default;
};

struct MlsRemovalTombstone {
	ObjectId transitionId;
	std::uint64_t generation = 0;
	Digest resultingStateHash;
	Digest mlsCommitHash;
	AccountId removedAccountId;
	ClientId removedClientId;

	friend inline bool operator==(
		const MlsRemovalTombstone &,
		const MlsRemovalTombstone &) = default;
};

struct MlsStateMutation {
	std::uint64_t baseRevision = 0;
	QByteArray engineState;
	std::optional<MlsOperationReceipt> receipt;
	std::optional<MlsInboundApplication> inboundApplication;
	std::optional<MlsRemovalTombstone> removalTombstone;
};

enum class MlsStateLoadResult {
	Loaded,
	Missing,
	StorageError,
	AuthenticationFailed,
	InvalidSnapshot,
};

enum class MlsStateCommitResult {
	Committed,
	AlreadyCommitted,
	NotLoaded,
	InvalidMutation,
	RevisionConflict,
	PersistenceFailed,
};

class PersistentMlsStateStore final {
public:
	PersistentMlsStateStore(
		AtomicBlobStore &blobStore,
		const LocalRecordProtector &protector);
	~PersistentMlsStateStore();

	[[nodiscard]] MlsStateLoadResult load(ConversationId conversationId);
	[[nodiscard]] MlsStateCommitResult initialize(
		QByteArray engineId,
		QByteArray engineState);
	[[nodiscard]] MlsStateCommitResult replaceRemovedWithKeyPackage(
		std::uint64_t baseRevision,
		QByteArray engineState);
	[[nodiscard]] MlsStateCommitResult replacePendingKeyPackage(
		std::uint64_t baseRevision,
		QByteArray engineState);
	[[nodiscard]] MlsStateCommitResult commit(MlsStateMutation mutation);
	[[nodiscard]] bool acknowledgeReceipt(ObjectId objectId);
	[[nodiscard]] bool acknowledgeReceipts(
		const std::vector<ObjectId> &objectIds);
	[[nodiscard]] bool acknowledgeInboundApplication(ObjectId objectId);

	[[nodiscard]] bool loaded() const;
	[[nodiscard]] ConversationId conversationId() const;
	[[nodiscard]] std::uint64_t revision() const;
	[[nodiscard]] const QByteArray &engineId() const;
	[[nodiscard]] const QByteArray &engineState() const;
	[[nodiscard]] bool removed() const;
	[[nodiscard]] const std::optional<MlsRemovalTombstone>
		&removalTombstone() const;
	[[nodiscard]] int receiptCount() const;
	[[nodiscard]] const std::vector<MlsOperationReceipt> &receipts() const;
	[[nodiscard]] std::optional<MlsOperationReceipt> receipt(
		ObjectId objectId) const;
	[[nodiscard]] int inboundApplicationCount() const;
	[[nodiscard]] std::optional<MlsInboundApplication> inboundApplication(
		ObjectId objectId) const;
	[[nodiscard]] const std::vector<MlsInboundApplication>
		&inboundApplications() const;

private:
	[[nodiscard]] bool persist(
		const QByteArray &engineId,
		const QByteArray &engineState,
		const std::vector<MlsOperationReceipt> &receipts,
		const std::vector<MlsInboundApplication> &inboundApplications,
		const std::optional<MlsRemovalTombstone> &removalTombstone,
		std::uint64_t revision) const;
	void clear();

	AtomicBlobStore &_blobStore;
	const LocalRecordProtector &_protector;
	ConversationId _conversationId;
	QByteArray _engineId;
	QByteArray _engineState;
	std::vector<MlsOperationReceipt> _receipts;
	std::vector<MlsInboundApplication> _inboundApplications;
	std::optional<MlsRemovalTombstone> _removalTombstone;
	std::uint64_t _revision = 0;
	bool _loaded = false;

};

} // namespace E2ECloud
