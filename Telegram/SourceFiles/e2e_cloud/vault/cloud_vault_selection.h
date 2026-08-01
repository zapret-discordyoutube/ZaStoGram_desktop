/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#pragma once

#include "e2e_cloud/vault/cloud_vault.h"

#include <QtCore/QByteArray>

#include <cstdint>
#include <optional>
#include <vector>

namespace E2ECloud {

struct CloudVaultAnchor {
	std::uint64_t generation = 0;
	Digest blobDigest;
	AccountId accountId;

	friend inline bool operator==(
		const CloudVaultAnchor &,
		const CloudVaultAnchor &) = default;
};

enum class CloudVaultSelectionStatus {
	Selected,
	Missing,
	Unreadable,
	CapacityExceeded,
	IdentityConflict,
	ForkDetected,
	RollbackDetected,
	ChainGap,
};

struct CloudVaultSelectionResult {
	CloudVaultSelectionStatus status = CloudVaultSelectionStatus::Missing;
	std::optional<UnlockedCloudVault> vault;
};

class CloudVaultSelector final {
public:
	CloudVaultSelector(
		const CloudVaultCodecV1 &codec,
		const Sha256Provider &sha256);

	[[nodiscard]] CloudVaultSelectionResult select(
		std::vector<QByteArray> candidates,
		QByteArray password,
		std::uint64_t telegramUserIdBinding,
		std::optional<CloudVaultAnchor> localAnchor = std::nullopt) const;

private:
	const CloudVaultCodecV1 &_codec;
	const Sha256Provider &_sha256;
};

} // namespace E2ECloud
