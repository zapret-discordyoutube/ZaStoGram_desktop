/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "e2e_cloud/vault/cloud_vault_selection.h"

#include <openssl/crypto.h>

#include <algorithm>
#include <limits>
#include <map>
#include <set>
#include <utility>

namespace E2ECloud {
namespace {

inline constexpr auto kMaximumCandidates = std::size_t(256);
inline constexpr auto kMaximumCandidateBytes = std::uint64_t(64 * 1024 * 1024);

void Cleanse(QByteArray &bytes) {
	if (!bytes.isEmpty()) {
		OPENSSL_cleanse(bytes.data(), bytes.size());
	}
	bytes.clear();
}

} // namespace

CloudVaultSelector::CloudVaultSelector(
		const CloudVaultCodecV1 &codec,
		const Sha256Provider &sha256)
: _codec(codec)
, _sha256(sha256) {
}

CloudVaultSelectionResult CloudVaultSelector::select(
		std::vector<QByteArray> candidates,
		QByteArray password,
		std::uint64_t telegramUserIdBinding,
		std::optional<CloudVaultAnchor> localAnchor) const {
	auto totalBytes = std::uint64_t();
	for (const auto &candidate : candidates) {
		if (candidate.size() < 0
			|| totalBytes > kMaximumCandidateBytes
				- std::uint64_t(candidate.size())) {
			Cleanse(password);
			return {
				.status = CloudVaultSelectionStatus::CapacityExceeded,
				.vault = std::nullopt,
			};
		}
		totalBytes += std::uint64_t(candidate.size());
	}
	if (candidates.size() > kMaximumCandidates
		|| totalBytes > kMaximumCandidateBytes) {
		Cleanse(password);
		return {
			.status = CloudVaultSelectionStatus::CapacityExceeded,
			.vault = std::nullopt,
		};
	} else if (candidates.empty()) {
		Cleanse(password);
		return {
			.status = localAnchor
				? CloudVaultSelectionStatus::RollbackDetected
				: CloudVaultSelectionStatus::Missing,
			.vault = std::nullopt,
		};
	}
	auto opened = std::vector<UnlockedCloudVault>();
	auto seenDigests = std::set<Digest>();
	for (const auto &candidate : candidates) {
		auto value = _codec.unlock(
			candidate,
			password,
			telegramUserIdBinding);
		if (value && seenDigests.emplace(value->blobDigest).second) {
			opened.push_back(std::move(*value));
		}
	}
	Cleanse(password);
	if (opened.empty()) {
		return {
			.status = CloudVaultSelectionStatus::Unreadable,
			.vault = std::nullopt,
		};
	}
	auto accountId = AccountId();
	for (const auto &value : opened) {
		const auto candidateAccountId = DeriveAccountId(
			value.identity.credential,
			_sha256);
		if (!candidateAccountId) {
			return {
				.status = CloudVaultSelectionStatus::Unreadable,
				.vault = std::nullopt,
			};
		} else if (!accountId) {
			accountId = *candidateAccountId;
		} else if (accountId != *candidateAccountId) {
			return {
				.status = CloudVaultSelectionStatus::IdentityConflict,
				.vault = std::nullopt,
			};
		}
	}
	std::sort(
		std::begin(opened),
		std::end(opened),
		[](const auto &a, const auto &b) {
			return (a.generation != b.generation)
				? (a.generation < b.generation)
				: (a.blobDigest < b.blobDigest);
		});
	for (auto i = std::size_t(1); i != opened.size(); ++i) {
		if (opened[i - 1].generation == opened[i].generation) {
			return {
				.status = CloudVaultSelectionStatus::ForkDetected,
				.vault = std::nullopt,
			};
		}
	}
	if (localAnchor) {
		if (!localAnchor->generation
			|| !localAnchor->blobDigest
			|| localAnchor->accountId != accountId) {
			return {
				.status = CloudVaultSelectionStatus::IdentityConflict,
				.vault = std::nullopt,
			};
		}
		const auto newestGeneration = opened.back().generation;
		if (newestGeneration < localAnchor->generation) {
			return {
				.status = CloudVaultSelectionStatus::RollbackDetected,
				.vault = std::nullopt,
			};
		}
		auto expectedGeneration = localAnchor->generation;
		auto expectedDigest = localAnchor->blobDigest;
		for (const auto &value : opened) {
			if (value.generation < expectedGeneration) {
				continue;
			} else if (value.generation == expectedGeneration) {
				if (value.blobDigest != expectedDigest) {
					return {
						.status = CloudVaultSelectionStatus::RollbackDetected,
						.vault = std::nullopt,
					};
				}
				continue;
			} else if (value.generation != expectedGeneration + 1
				|| value.previousBlobDigest != expectedDigest) {
				return {
					.status = CloudVaultSelectionStatus::ChainGap,
					.vault = std::nullopt,
				};
			}
			expectedGeneration = value.generation;
			expectedDigest = value.blobDigest;
		}
		if (expectedGeneration != newestGeneration) {
			return {
				.status = CloudVaultSelectionStatus::ChainGap,
				.vault = std::nullopt,
			};
		}
	}
	return {
		.status = CloudVaultSelectionStatus::Selected,
		.vault = std::move(opened.back()),
	};
}

} // namespace E2ECloud
