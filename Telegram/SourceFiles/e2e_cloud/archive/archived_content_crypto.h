/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#pragma once

#include "e2e_cloud/archive/archive_epoch_crypto.h"
#include "e2e_cloud/core/envelope.h"
#include "e2e_cloud/identity/openssl_account_crypto.h"

#include <QtCore/QByteArray>

#include <array>
#include <cstdint>
#include <optional>

namespace E2ECloud {

inline constexpr auto kMaximumArchivedContentSize = 16 * 1024 * 1024;
inline constexpr auto kArchivedContentDescriptorEncodedSize = 188;

struct EncryptedArchivedContent {
	ConversationId conversationId;
	ObjectId eventObjectId;
	ObjectId contentObjectId;
	ObjectKind objectKind = ObjectKind::EncryptedMessageBody;
	std::uint64_t groupGeneration = 0;
	AccountId senderAccountId;
	ClientId senderClientId;
	ArchiveContentKeyEnvelope wrappedContentKey;
	std::array<std::uint8_t, 12> nonce = {};
	QByteArray ciphertext;
	std::array<std::uint8_t, 16> authenticationTag = {};
	AccountSignature signature = {};

	friend inline bool operator==(
		const EncryptedArchivedContent &,
		const EncryptedArchivedContent &) = default;
};

struct PreparedArchivedContent {
	ArchiveKey32 contentKey;
	EncryptedArchivedContent encrypted;
};

struct ArchivedContentDescriptor {
	ConversationId conversationId;
	ObjectId eventObjectId;
	ObjectId contentObjectId;
	ObjectKind objectKind = ObjectKind::EncryptedMessageBody;
	std::uint64_t groupGeneration = 0;
	std::uint64_t archiveEpochGeneration = 0;
	Digest encodedContentHash;
	ArchiveKey32 contentKey;
};

struct PrepareArchivedContentArgs {
	ConversationId conversationId;
	ObjectId eventObjectId;
	ObjectId contentObjectId;
	ObjectKind objectKind = ObjectKind::EncryptedMessageBody;
	std::uint64_t groupGeneration = 0;
	AccountId senderAccountId;
	ClientId senderClientId;
	std::uint64_t archiveEpochGeneration = 0;
	const ArchiveKey32 *archiveEpochKey = nullptr;
	const SecureKey32 *senderSigningPrivateKey = nullptr;
	QByteArray plaintext;
};

class EncryptedArchivedContentCodecV1 final {
public:
	[[nodiscard]] std::optional<QByteArray> encode(
		const EncryptedArchivedContent &content) const;
	[[nodiscard]] std::optional<EncryptedArchivedContent> decode(
		const QByteArray &bytes) const;
};

class ArchivedContentDescriptorCodecV1 final {
public:
	[[nodiscard]] std::optional<QByteArray> encodePlaintext(
		const ArchivedContentDescriptor &descriptor) const;
	[[nodiscard]] std::optional<ArchivedContentDescriptor> decodePlaintext(
		const QByteArray &bytes) const;
};

[[nodiscard]] std::optional<PreparedArchivedContent> PrepareArchivedContent(
	PrepareArchivedContentArgs args,
	const ArchiveEpochCrypto &archiveCrypto);
[[nodiscard]] std::optional<QByteArray> OpenArchivedContentWithContentKey(
	const EncryptedArchivedContent &content,
	const ArchiveKey32 &contentKey,
	const AccountCredentialPublic &senderCredential,
	const Sha256Provider &sha256);
[[nodiscard]] std::optional<QByteArray> OpenArchivedContentWithEpochKey(
	const EncryptedArchivedContent &content,
	const ArchiveKey32 &archiveEpochKey,
	const AccountCredentialPublic &senderCredential,
	const Sha256Provider &sha256,
	const ArchiveEpochCrypto &archiveCrypto);

} // namespace E2ECloud
