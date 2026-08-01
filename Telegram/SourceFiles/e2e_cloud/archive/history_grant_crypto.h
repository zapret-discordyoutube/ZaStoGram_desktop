/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#pragma once

#include "e2e_cloud/archive/archive_epoch_crypto.h"
#include "e2e_cloud/identity/openssl_account_crypto.h"

#include <QtCore/QByteArray>

#include <array>
#include <cstdint>
#include <optional>
#include <vector>

namespace E2ECloud {

class OpenMlsBridge;

inline constexpr auto kMaximumArchiveEpochsPerGrant = 4096;
inline constexpr auto kMaximumEncryptedHistoryGrantSize = 1024 * 1024;

struct ArchiveEpochSecret {
	std::uint64_t generation = 0;
	std::uint64_t activationGroupGeneration = 0;
	ObjectId activationEventId;
	ArchiveKey32 key;
};

struct HistoryGrantPayload {
	ConversationId conversationId;
	ObjectId grantId;
	AccountId recipientAccountId;
	HistoryAccess historyAccess;
	std::vector<ArchiveEpochSecret> epochs;
};

struct EncryptedHistoryGrant {
	ConversationId conversationId;
	ObjectId grantId;
	AccountId issuerAccountId;
	ClientId issuerClientId;
	AccountId recipientAccountId;
	std::uint64_t telegramPeerIdBinding = 0;
	std::uint64_t groupGeneration = 0;
	HistoryAccess historyAccess;
	std::array<std::uint8_t, 32> encapsulatedKey = {};
	QByteArray ciphertext;
	AccountSignature signature = {};

	friend inline bool operator==(
		const EncryptedHistoryGrant &,
		const EncryptedHistoryGrant &) = default;
};

struct CreateHistoryGrantArgs {
	ConversationId conversationId;
	ObjectId grantId;
	AccountId issuerAccountId;
	ClientId issuerClientId;
	AccountId recipientAccountId;
	std::uint64_t telegramPeerIdBinding = 0;
	std::uint64_t groupGeneration = 0;
	HistoryAccess historyAccess;
	std::array<std::uint8_t, 32> recipientArchivePublicKey = {};
	const SecureKey32 *issuerSigningPrivateKey = nullptr;
	const std::vector<ArchiveEpochSecret> *epochs = nullptr;
};

class EncryptedHistoryGrantCodecV1 final {
public:
	[[nodiscard]] std::optional<QByteArray> encode(
		const EncryptedHistoryGrant &grant) const;
	[[nodiscard]] std::optional<EncryptedHistoryGrant> decode(
		const QByteArray &bytes) const;

};

[[nodiscard]] std::optional<EncryptedHistoryGrant> CreateHistoryGrant(
	const CreateHistoryGrantArgs &args,
	const OpenMlsBridge &bridge);
[[nodiscard]] bool VerifyEncryptedHistoryGrantSignature(
	const EncryptedHistoryGrant &grant,
	const AccountCredentialPublic &issuerCredential,
	const Sha256Provider &sha256);
[[nodiscard]] std::optional<HistoryGrantPayload> OpenHistoryGrant(
	const EncryptedHistoryGrant &grant,
	AccountId expectedRecipientAccountId,
	const SecureKey32 &recipientArchivePrivateKey,
	const AccountCredentialPublic &issuerCredential,
	const Sha256Provider &sha256,
	const OpenMlsBridge &bridge);

} // namespace E2ECloud
