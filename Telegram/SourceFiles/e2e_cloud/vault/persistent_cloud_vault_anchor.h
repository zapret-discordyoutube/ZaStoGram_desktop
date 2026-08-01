/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#pragma once

#include "e2e_cloud/storage/local_storage.h"
#include "e2e_cloud/vault/cloud_vault_selection.h"

#include <cstdint>
#include <optional>

namespace E2ECloud {

enum class CloudVaultAnchorLoadResult {
	Loaded,
	Missing,
	StorageError,
	InvalidSnapshot,
};

enum class CloudVaultAnchorCommitResult {
	Committed,
	AlreadyCommitted,
	NotLoaded,
	InvalidAnchor,
	Conflict,
	PersistenceFailed,
};

class PersistentCloudVaultAnchor final {
public:
	PersistentCloudVaultAnchor(
		AtomicBlobStore &blobStore,
		std::uint64_t telegramUserIdBinding);

	[[nodiscard]] CloudVaultAnchorLoadResult load();
	[[nodiscard]] CloudVaultAnchorCommitResult commit(
		CloudVaultAnchor anchor);

	[[nodiscard]] bool loaded() const;
	[[nodiscard]] const std::optional<CloudVaultAnchor> &anchor() const;

private:
	AtomicBlobStore &_blobStore;
	std::uint64_t _telegramUserIdBinding = 0;
	std::optional<CloudVaultAnchor> _anchor;
	bool _loaded = false;
};

} // namespace E2ECloud
