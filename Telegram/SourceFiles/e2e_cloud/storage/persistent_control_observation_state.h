/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#pragma once

#include "e2e_cloud/core/types.h"
#include "e2e_cloud/storage/local_storage.h"

#include <cstdint>
#include <set>

namespace E2ECloud {

enum class ControlObservationStateLoadResult {
	Loaded,
	LegacyLoaded,
	Missing,
	ReadFailed,
	AuthenticationFailed,
	InvalidSnapshot,
};

enum class ControlObservationStateCommitResult {
	Committed,
	AlreadyCommitted,
	InvalidState,
	PersistenceFailed,
};

class PersistentControlObservationState final {
public:
	PersistentControlObservationState(
		AtomicBlobStore &blobStore,
		const LocalRecordProtector &protector);

	[[nodiscard]] ControlObservationStateLoadResult load(
		ConversationId conversationId);
	[[nodiscard]] ControlObservationStateCommitResult advance(
		std::int64_t newestObservedMessageId,
		Checkpoint checkpoint,
		const std::set<AccountId> &safetyWitnesses,
		bool ownSafetyGossipObserved);
	[[nodiscard]] std::int64_t newestObservedMessageId() const;
	[[nodiscard]] Checkpoint checkpoint() const;
	[[nodiscard]] const std::set<AccountId> &safetyWitnesses() const;
	[[nodiscard]] bool ownSafetyGossipObserved() const;
	[[nodiscard]] std::uint64_t revision() const;
	[[nodiscard]] bool loaded() const;
	[[nodiscard]] bool legacy() const;

private:
	[[nodiscard]] bool persist(
		std::int64_t newestObservedMessageId,
		Checkpoint checkpoint,
		const std::set<AccountId> &safetyWitnesses,
		bool ownSafetyGossipObserved,
		std::uint64_t revision) const;
	void clear();

	AtomicBlobStore &_blobStore;
	const LocalRecordProtector &_protector;
	ConversationId _conversationId;
	std::int64_t _newestObservedMessageId = 0;
	Checkpoint _checkpoint;
	std::set<AccountId> _safetyWitnesses;
	std::uint64_t _revision = 0;
	bool _ownSafetyGossipObserved = false;
	bool _loaded = false;
	bool _legacy = false;

};

} // namespace E2ECloud
