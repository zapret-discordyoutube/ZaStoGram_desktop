/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#pragma once

#include "e2e_cloud/core/types.h"
#include "e2e_cloud/identity/openssl_account_crypto.h"
#include "e2e_cloud/vault/password_vault.h"

#include <QtCore/QByteArray>

#include <cstdint>
#include <optional>
#include <vector>

namespace E2ECloud {

struct CloudVaultConversation {
	ConversationId conversationId;
	std::uint64_t telegramPeerIdBinding = 0;
	Checkpoint checkpoint;
	AccountId ownerAccountId;

	friend inline bool operator==(
		const CloudVaultConversation &,
		const CloudVaultConversation &) = default;
};

struct UnlockedCloudVault {
	std::uint64_t telegramUserIdBinding = 0;
	std::uint64_t generation = 0;
	Digest previousBlobDigest;
	Digest blobDigest;
	SecureKey32 masterKey;
	QByteArray wrappedMasterKey;
	AccountPrivateIdentity identity;
	std::vector<CloudVaultConversation> conversations;
};

struct CreatedCloudVault {
	QByteArray encoded;
	UnlockedCloudVault unlocked;
};

struct PreparedCloudVaultUpdate {
	QByteArray encoded;
	std::uint64_t generation = 0;
	Digest previousBlobDigest;
	Digest blobDigest;
	std::vector<CloudVaultConversation> conversations;
};

struct CloudVaultBlobHeader {
	std::uint64_t telegramUserIdBinding = 0;
	std::uint64_t generation = 0;
	QByteArray wrappedMasterKey;
};

class CloudVaultCodecV1 final {
public:
	CloudVaultCodecV1(
		const PasswordKdf &passwordKdf,
		const Sha256Provider &sha256);

	[[nodiscard]] std::optional<CreatedCloudVault> create(
		std::uint64_t telegramUserIdBinding,
		AccountPrivateIdentity &&identity,
		QByteArray password,
		Argon2idConfig config,
		std::vector<CloudVaultConversation> conversations = {}) const;
	[[nodiscard]] std::optional<UnlockedCloudVault> unlock(
		const QByteArray &encoded,
		QByteArray password,
		std::uint64_t expectedTelegramUserIdBinding) const;
	[[nodiscard]] std::optional<CloudVaultBlobHeader> inspect(
		const QByteArray &encoded) const;
	[[nodiscard]] std::optional<SecureKey32> unlockMasterKey(
		const QByteArray &wrappedMasterKey,
		QByteArray password) const;
	[[nodiscard]] std::optional<UnlockedCloudVault> unlockWithMasterKey(
		const QByteArray &encoded,
		const SecureKey32 &masterKey,
		std::uint64_t expectedTelegramUserIdBinding) const;
	[[nodiscard]] std::optional<PreparedCloudVaultUpdate> prepareUpdate(
		const UnlockedCloudVault &vault,
		std::vector<CloudVaultConversation> conversations) const;
	[[nodiscard]] bool applyPublished(
		UnlockedCloudVault &vault,
		PreparedCloudVaultUpdate &&update) const;

private:
	[[nodiscard]] std::optional<QByteArray> encode(
		std::uint64_t telegramUserIdBinding,
		std::uint64_t generation,
		Digest previousBlobDigest,
		const SecureKey32 &masterKey,
		const QByteArray &wrappedMasterKey,
		const AccountPrivateIdentity &identity,
		const std::vector<CloudVaultConversation> &conversations) const;

	PasswordVault _passwordVault;
	const Sha256Provider &_sha256;
};

} // namespace E2ECloud
