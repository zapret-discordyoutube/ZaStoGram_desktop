/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#pragma once

#include "e2e_cloud/core/interfaces.h"
#include "e2e_cloud/identity/openssl_account_crypto.h"

#include <QtCore/QByteArray>

#include <cstdint>
#include <optional>

namespace E2ECloud {

struct FileChunkEnvelopeMetadata {
	FileId fileId;
	std::uint32_t chunkIndex = 0;
	std::uint32_t chunkCount = 0;
	AccountSignature signature = {};
};

struct PrepareFileChunkEnvelopeArgs {
	ConversationId conversationId;
	AccountId senderAccountId;
	ClientId senderClientId;
	std::uint64_t telegramPeerIdBinding = 0;
	std::uint64_t groupGeneration = 0;
	FileId fileId;
	std::uint32_t chunkIndex = 0;
	std::uint32_t chunkCount = 0;
	const SecureKey32 *senderSigningPrivateKey = nullptr;
	QByteArray exactCiphertext;
};

struct PreparedFileChunkEnvelope {
	TransportEnvelope envelope;
	EncodedEnvelope encoded;
};

struct VerifiedFileChunkEnvelope {
	FileId fileId;
	std::uint32_t chunkIndex = 0;
	std::uint32_t chunkCount = 0;
};

[[nodiscard]] ObjectId DeriveFileChunkObjectId(
	ConversationId conversationId,
	FileId fileId,
	std::uint32_t chunkIndex,
	Digest ciphertextHash,
	const Sha256Provider &sha256);
[[nodiscard]] std::optional<PreparedFileChunkEnvelope>
PrepareFileChunkEnvelope(
	PrepareFileChunkEnvelopeArgs args,
	const EnvelopeCodec &envelopeCodec,
	const Sha256Provider &sha256);
[[nodiscard]] std::optional<VerifiedFileChunkEnvelope>
VerifyFileChunkEnvelope(
	const TransportEnvelope &envelope,
	const AccountCredentialPublic &senderCredential,
	const Sha256Provider &sha256);

} // namespace E2ECloud
