/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#pragma once

#include "e2e_cloud/core/interfaces.h"
#include "e2e_cloud/core/outbox.h"
#include "e2e_cloud/mls/client_key_package.h"
#include "e2e_cloud/storage/local_storage.h"

#include <cstddef>
#include <cstdint>
#include <optional>
#include <vector>

namespace E2ECloud {

inline constexpr auto kMaximumKeyPackagePoolEntries = std::size_t(4);

struct StoredClientKeyPackage {
	Digest keyPackageHash;
	std::uint64_t createdAt = 0;
	std::uint64_t expiresAt = 0;
	QByteArray privateEngineState;
	EncodedEnvelope publicationEnvelope;
	bool queued = false;

	friend inline bool operator==(
		const StoredClientKeyPackage &,
		const StoredClientKeyPackage &) = default;
};

enum class KeyPackagePoolLoadResult {
	Loaded,
	Empty,
	StorageError,
	AuthenticationFailed,
	InvalidSnapshot,
};

enum class KeyPackagePoolMutationResult {
	Committed,
	AlreadyStored,
	NotLoaded,
	InvalidEntry,
	CapacityExceeded,
	RevisionExhausted,
	PersistenceFailed,
};

enum class KeyPackagePoolEnqueueResult {
	Queued,
	NothingToDo,
	NotLoaded,
	OutboxFailure,
	PersistenceFailed,
};

class PersistentKeyPackagePool final {
public:
	PersistentKeyPackagePool(
		AtomicBlobStore &blobStore,
		const LocalRecordProtector &protector,
		const EnvelopeCodec &envelopeCodec,
		const Sha256Provider &sha256);
	~PersistentKeyPackagePool();

	[[nodiscard]] KeyPackagePoolLoadResult load(
		ConversationId conversationId,
		std::uint64_t telegramPeerIdBinding);
	[[nodiscard]] KeyPackagePoolMutationResult add(
		StoredClientKeyPackage entry);
	[[nodiscard]] KeyPackagePoolMutationResult prune(
		std::uint64_t currentTime,
		std::uint64_t currentGeneration);
	[[nodiscard]] KeyPackagePoolMutationResult consume(
		Digest keyPackageHash);
	[[nodiscard]] KeyPackagePoolEnqueueResult enqueuePending(
		ProtectedOutboxStore &outbox,
		std::uint64_t currentTime);

	[[nodiscard]] bool needsRefresh(
		std::uint64_t currentTime,
		std::uint64_t currentGeneration) const;
	[[nodiscard]] const StoredClientKeyPackage *find(
		Digest keyPackageHash,
		std::uint64_t currentTime) const;
	[[nodiscard]] bool loaded() const;
	[[nodiscard]] std::uint64_t revision() const;
	[[nodiscard]] const std::vector<StoredClientKeyPackage> &entries() const;

private:
	[[nodiscard]] bool validEntry(
		const StoredClientKeyPackage &entry) const;
	[[nodiscard]] bool persist(
		const std::vector<StoredClientKeyPackage> &entries,
		std::uint64_t revision) const;
	void clear();

	AtomicBlobStore &_blobStore;
	const LocalRecordProtector &_protector;
	const EnvelopeCodec &_envelopeCodec;
	const Sha256Provider &_sha256;
	ConversationId _conversationId;
	std::uint64_t _telegramPeerIdBinding = 0;
	std::uint64_t _revision = 0;
	std::vector<StoredClientKeyPackage> _entries;
	bool _loaded = false;
};

} // namespace E2ECloud
