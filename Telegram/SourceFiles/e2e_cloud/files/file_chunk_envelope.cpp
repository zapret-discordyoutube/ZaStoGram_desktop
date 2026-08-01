/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "e2e_cloud/files/file_chunk_envelope.h"

#include "e2e_cloud/identity/account_identity.h"

#include <algorithm>
#include <array>
#include <utility>

namespace E2ECloud {
namespace {

inline constexpr auto kAuthenticationMagic = std::array<std::uint8_t, 8>{
	'T', 'D', 'E', '2', 'E', 'F', 'C', 'E',
};
inline constexpr auto kMaximumFileChunkCiphertextSize = 4 * 1024 * 1024 + 122;
inline constexpr auto kAuthenticationHeaderSize = 8 + 2 + 32 + 4 + 4;
inline constexpr auto kAuthenticationDataSize = kAuthenticationHeaderSize + 64;

struct Reader {
	const QByteArray &bytes;
	int offset = 0;
};

void AppendUint16(QByteArray &result, std::uint16_t value) {
	result.append(char(value >> 8));
	result.append(char(value));
}

void AppendUint32(QByteArray &result, std::uint32_t value) {
	result.append(char(value >> 24));
	result.append(char(value >> 16));
	result.append(char(value >> 8));
	result.append(char(value));
}

void AppendUint64(QByteArray &result, std::uint64_t value) {
	for (auto shift = 56; shift >= 0; shift -= 8) {
		result.append(char(value >> shift));
	}
}

template <typename Array>
void AppendArray(QByteArray &result, const Array &value) {
	result.append(
		reinterpret_cast<const char*>(value.data()),
		int(value.size()));
}

[[nodiscard]] bool ReadUint16(Reader &reader, std::uint16_t &value) {
	if (reader.bytes.size() - reader.offset < 2) {
		return false;
	}
	const auto data = reinterpret_cast<const std::uint8_t*>(
		reader.bytes.constData() + reader.offset);
	value = (std::uint16_t(data[0]) << 8) | std::uint16_t(data[1]);
	reader.offset += 2;
	return true;
}

[[nodiscard]] bool ReadUint32(Reader &reader, std::uint32_t &value) {
	if (reader.bytes.size() - reader.offset < 4) {
		return false;
	}
	const auto data = reinterpret_cast<const std::uint8_t*>(
		reader.bytes.constData() + reader.offset);
	value = (std::uint32_t(data[0]) << 24)
		| (std::uint32_t(data[1]) << 16)
		| (std::uint32_t(data[2]) << 8)
		| std::uint32_t(data[3]);
	reader.offset += 4;
	return true;
}

template <typename Array>
[[nodiscard]] bool ReadArray(Reader &reader, Array &value) {
	const auto size = int(value.size());
	if (reader.bytes.size() - reader.offset < size) {
		return false;
	}
	std::copy_n(
		reinterpret_cast<const std::uint8_t*>(
			reader.bytes.constData() + reader.offset),
		size,
		value.data());
	reader.offset += size;
	return true;
}

[[nodiscard]] QByteArray EncodeAuthenticationHeader(
		const FileChunkEnvelopeMetadata &metadata) {
	auto result = QByteArray();
	result.reserve(kAuthenticationHeaderSize);
	AppendArray(result, kAuthenticationMagic);
	AppendUint16(result, 1);
	AppendArray(result, metadata.fileId.bytes);
	AppendUint32(result, metadata.chunkIndex);
	AppendUint32(result, metadata.chunkCount);
	return result;
}

[[nodiscard]] std::optional<FileChunkEnvelopeMetadata>
DecodeAuthenticationData(const QByteArray &bytes) {
	if (bytes.size() != kAuthenticationDataSize) {
		return std::nullopt;
	}
	auto reader = Reader{ bytes };
	auto magic = std::array<std::uint8_t, 8>();
	auto version = std::uint16_t();
	auto result = FileChunkEnvelopeMetadata();
	if (!ReadArray(reader, magic)
		|| !ReadUint16(reader, version)
		|| !ReadArray(reader, result.fileId.bytes)
		|| !ReadUint32(reader, result.chunkIndex)
		|| !ReadUint32(reader, result.chunkCount)
		|| !ReadArray(reader, result.signature)
		|| reader.offset != bytes.size()
		|| magic != kAuthenticationMagic
		|| version != 1
		|| !result.fileId
		|| !result.chunkCount
		|| result.chunkIndex >= result.chunkCount) {
		return std::nullopt;
	}
	return result;
}

[[nodiscard]] QByteArray SignatureInput(
		const TransportEnvelope &envelope,
		const FileChunkEnvelopeMetadata &metadata) {
	auto result = QByteArray("TDE2E/file-chunk-envelope/v1");
	result.append(char(0));
	AppendArray(result, envelope.conversationId.bytes);
	AppendArray(result, envelope.senderAccountId.bytes);
	AppendArray(result, envelope.senderClientId.bytes);
	AppendUint64(result, envelope.telegramPeerIdBinding);
	AppendUint64(result, envelope.epochOrGeneration);
	AppendArray(result, envelope.objectId.bytes);
	AppendArray(result, envelope.payloadHash.bytes);
	result.append(EncodeAuthenticationHeader(metadata));
	return result;
}

} // namespace

std::optional<FileChunkEnvelopeMetadata> DecodeFileChunkEnvelopeMetadata(
		const TransportEnvelope &envelope) {
	return (envelope.objectKind == ObjectKind::EncryptedFileChunk)
		? DecodeAuthenticationData(envelope.authenticationData)
		: std::nullopt;
}

ObjectId DeriveFileChunkObjectId(
		ConversationId conversationId,
		FileId fileId,
		std::uint32_t chunkIndex,
		Digest ciphertextHash,
		const Sha256Provider &sha256) {
	if (!conversationId || !fileId || !ciphertextHash) {
		return {};
	}
	auto input = QByteArray("TDE2E/file-chunk-object/v1");
	input.append(char(0));
	AppendArray(input, conversationId.bytes);
	AppendArray(input, fileId.bytes);
	AppendUint32(input, chunkIndex);
	AppendArray(input, ciphertextHash.bytes);
	return ObjectId{ sha256.digest(input).bytes };
}

std::optional<PreparedFileChunkEnvelope> PrepareFileChunkEnvelope(
		PrepareFileChunkEnvelopeArgs args,
		const EnvelopeCodec &envelopeCodec,
		const Sha256Provider &sha256) {
	if (!args.conversationId
		|| !args.senderAccountId
		|| !args.senderClientId
		|| !args.telegramPeerIdBinding
		|| !args.groupGeneration
		|| !args.fileId
		|| !args.chunkCount
		|| args.chunkIndex >= args.chunkCount
		|| !args.senderSigningPrivateKey
		|| !args.senderSigningPrivateKey->valid()
		|| args.exactCiphertext.isEmpty()
		|| args.exactCiphertext.size() > kMaximumFileChunkCiphertextSize) {
		return std::nullopt;
	}
	const auto payloadHash = sha256.digest(args.exactCiphertext);
	const auto objectId = DeriveFileChunkObjectId(
		args.conversationId,
		args.fileId,
		args.chunkIndex,
		payloadHash,
		sha256);
	if (!payloadHash || !objectId) {
		return std::nullopt;
	}
	auto metadata = FileChunkEnvelopeMetadata{
		.fileId = args.fileId,
		.chunkIndex = args.chunkIndex,
		.chunkCount = args.chunkCount,
		.signature = {},
	};
	auto envelope = TransportEnvelope{
		.conversationId = args.conversationId,
		.objectKind = ObjectKind::EncryptedFileChunk,
		.senderAccountId = args.senderAccountId,
		.senderClientId = args.senderClientId,
		.telegramPeerIdBinding = args.telegramPeerIdBinding,
		.epochOrGeneration = args.groupGeneration,
		.objectId = objectId,
		.payloadHash = payloadHash,
		.payload = std::move(args.exactCiphertext),
		.authenticationData = {},
	};
	const auto signature = SignAccountData(
		*args.senderSigningPrivateKey,
		AccountSignatureDomain::FileChunk,
		SignatureInput(envelope, metadata));
	if (!signature) {
		return std::nullopt;
	}
	metadata.signature = *signature;
	envelope.authenticationData = EncodeAuthenticationHeader(metadata);
	AppendArray(envelope.authenticationData, metadata.signature);
	const auto encoded = envelopeCodec.encode(envelope);
	return encoded
		? std::optional<PreparedFileChunkEnvelope>({
			.envelope = std::move(envelope),
			.encoded = *encoded,
		})
		: std::nullopt;
}

std::optional<VerifiedFileChunkEnvelope> VerifyFileChunkEnvelope(
		const TransportEnvelope &envelope,
		const AccountCredentialPublic &senderCredential,
		const Sha256Provider &sha256) {
	const auto metadata = DecodeFileChunkEnvelopeMetadata(envelope);
	const auto accountId = DeriveAccountId(senderCredential, sha256);
	if (!metadata
		|| envelope.objectKind != ObjectKind::EncryptedFileChunk
		|| envelope.payload.isEmpty()
		|| envelope.payload.size() > kMaximumFileChunkCiphertextSize
		|| !accountId
		|| *accountId != envelope.senderAccountId
		|| sha256.digest(envelope.payload) != envelope.payloadHash
		|| DeriveFileChunkObjectId(
			envelope.conversationId,
			metadata->fileId,
			metadata->chunkIndex,
			envelope.payloadHash,
			sha256) != envelope.objectId
		|| !VerifyAccountSignature(
			senderCredential,
			AccountSignatureDomain::FileChunk,
			SignatureInput(envelope, *metadata),
			metadata->signature)) {
		return std::nullopt;
	}
	return VerifiedFileChunkEnvelope{
		.fileId = metadata->fileId,
		.chunkIndex = metadata->chunkIndex,
		.chunkCount = metadata->chunkCount,
	};
}

} // namespace E2ECloud
