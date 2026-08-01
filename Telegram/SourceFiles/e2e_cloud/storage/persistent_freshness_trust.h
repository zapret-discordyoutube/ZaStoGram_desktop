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

namespace E2ECloud {

enum class FreshnessTrustLoadResult {
	Loaded,
	Missing,
	StorageError,
	AuthenticationFailed,
	InvalidSnapshot,
};

enum class FreshnessTrustCommitResult {
	Committed,
	AlreadyCommitted,
	NotLoaded,
	InvalidMutation,
	PersistenceFailed,
};

class PersistentFreshnessTrust final {
public:
	PersistentFreshnessTrust(
		AtomicBlobStore &blobStore,
		const LocalRecordProtector &protector);

	[[nodiscard]] FreshnessTrustLoadResult load(
		ConversationId conversationId);
	[[nodiscard]] FreshnessTrustCommitResult initialize(bool trusted);
	[[nodiscard]] FreshnessTrustCommitResult confirm();

	[[nodiscard]] bool loaded() const;
	[[nodiscard]] bool trusted() const;
	[[nodiscard]] std::uint64_t revision() const;

private:
	[[nodiscard]] bool persist(bool trusted, std::uint64_t revision) const;
	void reset();

	AtomicBlobStore &_blobStore;
	const LocalRecordProtector &_protector;
	ConversationId _conversationId;
	std::uint64_t _revision = 0;
	bool _trusted = false;
	bool _loaded = false;
};

} // namespace E2ECloud
