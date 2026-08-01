/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "e2e_cloud/archive/archived_content_crypto.h"

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#include <algorithm>
#include <array>
#include <limits>
#include <utility>

namespace E2ECloud {
namespace {

inline constexpr auto kContentMagic = std::array<std::uint8_t, 8>{
	'T', 'D', 'E', '2', 'E', 'A', 'C', 'O',
};
inline constexpr auto kDescriptorMagic = std::array<std::uint8_t, 8>{
	'T', 'D', 'E', '2', 'E', 'A', 'C', 'D',
};
inline constexpr auto kContentHeaderSize = 8 + 2 + 32 + 32 + 32 + 2
	+ 8 + 32 + 16 + kArchiveContentKeyEnvelopeEncodedSize + 12;
inline constexpr auto kContentFixedSize = kContentHeaderSize + 4 + 16 + 64;

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

[[nodiscard]] bool ReadUint64(Reader &reader, std::uint64_t &value) {
	if (reader.bytes.size() - reader.offset < 8) {
		return false;
	}
	const auto data = reinterpret_cast<const std::uint8_t*>(
		reader.bytes.constData() + reader.offset);
	value = 0;
	for (auto i = 0; i != 8; ++i) {
		value = (value << 8) | std::uint64_t(data[i]);
	}
	reader.offset += 8;
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

[[nodiscard]] bool Nonzero(const auto &value) {
	return std::any_of(begin(value), end(value), [](std::uint8_t byte) {
		return byte != 0;
	});
}

[[nodiscard]] bool ValidKind(ObjectKind kind) {
	return kind == ObjectKind::EncryptedMessageBody
		|| kind == ObjectKind::EncryptedFileManifest;
}

[[nodiscard]] bool ValidContent(const EncryptedArchivedContent &content) {
	return content.conversationId
		&& content.eventObjectId
		&& content.contentObjectId
		&& ValidKind(content.objectKind)
		&& content.groupGeneration
		&& content.senderAccountId
		&& content.senderClientId
		&& content.wrappedContentKey.conversationId == content.conversationId
		&& content.wrappedContentKey.eventObjectId == content.eventObjectId
		&& content.wrappedContentKey.contentObjectId == content.contentObjectId
		&& Nonzero(content.nonce)
		&& !content.ciphertext.isEmpty()
		&& content.ciphertext.size() <= kMaximumArchivedContentSize
		&& Nonzero(content.authenticationTag)
		&& Nonzero(content.signature);
}

[[nodiscard]] QByteArray EncodeHeader(
		const EncryptedArchivedContent &content) {
	const auto wrapped = ArchiveContentKeyEnvelopeCodecV1().encode(
		content.wrappedContentKey);
	if (!wrapped) {
		return {};
	}
	auto result = QByteArray();
	result.reserve(kContentHeaderSize);
	AppendArray(result, kContentMagic);
	AppendUint16(result, 1);
	AppendArray(result, content.conversationId.bytes);
	AppendArray(result, content.eventObjectId.bytes);
	AppendArray(result, content.contentObjectId.bytes);
	AppendUint16(result, std::uint16_t(content.objectKind));
	AppendUint64(result, content.groupGeneration);
	AppendArray(result, content.senderAccountId.bytes);
	AppendArray(result, content.senderClientId.bytes);
	result.append(*wrapped);
	AppendArray(result, content.nonce);
	return result;
}

[[nodiscard]] QByteArray SignatureInput(
		const EncryptedArchivedContent &content) {
	auto result = EncodeHeader(content);
	if (result.isEmpty()) {
		return {};
	}
	AppendUint32(result, std::uint32_t(content.ciphertext.size()));
	result.append(content.ciphertext);
	AppendArray(result, content.authenticationTag);
	return result;
}

[[nodiscard]] std::optional<QByteArray> Encrypt(
		const ArchiveKey32 &key,
		const QByteArray &aad,
		const QByteArray &plaintext,
		const std::array<std::uint8_t, 12> &nonce,
		std::array<std::uint8_t, 16> &tag) {
	auto context = EVP_CIPHER_CTX_new();
	if (!context) {
		return std::nullopt;
	}
	auto ciphertext = QByteArray();
	ciphertext.resize(plaintext.size());
	auto aadLength = 0;
	auto outputLength = 0;
	auto finalLength = 0;
	const auto ok = EVP_EncryptInit_ex(
		context,
		EVP_aes_256_gcm(),
		nullptr,
		nullptr,
		nullptr) == 1
		&& EVP_CIPHER_CTX_ctrl(
			context,
			EVP_CTRL_GCM_SET_IVLEN,
			nonce.size(),
			nullptr) == 1
		&& EVP_EncryptInit_ex(
			context,
			nullptr,
			nullptr,
			key.bytes().data(),
			nonce.data()) == 1
		&& EVP_EncryptUpdate(
			context,
			nullptr,
			&aadLength,
			reinterpret_cast<const unsigned char*>(aad.constData()),
			aad.size()) == 1
		&& EVP_EncryptUpdate(
			context,
			reinterpret_cast<unsigned char*>(ciphertext.data()),
			&outputLength,
			reinterpret_cast<const unsigned char*>(plaintext.constData()),
			plaintext.size()) == 1
		&& EVP_EncryptFinal_ex(
			context,
			reinterpret_cast<unsigned char*>(ciphertext.data()) + outputLength,
			&finalLength) == 1
		&& EVP_CIPHER_CTX_ctrl(
			context,
			EVP_CTRL_GCM_GET_TAG,
			tag.size(),
			tag.data()) == 1;
	EVP_CIPHER_CTX_free(context);
	if (!ok || outputLength + finalLength != plaintext.size()) {
		OPENSSL_cleanse(ciphertext.data(), ciphertext.size());
		return std::nullopt;
	}
	return ciphertext;
}

[[nodiscard]] std::optional<QByteArray> Decrypt(
		const ArchiveKey32 &key,
		const QByteArray &aad,
		const EncryptedArchivedContent &content) {
	auto context = EVP_CIPHER_CTX_new();
	if (!context) {
		return std::nullopt;
	}
	auto plaintext = QByteArray();
	plaintext.resize(content.ciphertext.size());
	auto aadLength = 0;
	auto outputLength = 0;
	auto finalLength = 0;
	const auto ok = EVP_DecryptInit_ex(
		context,
		EVP_aes_256_gcm(),
		nullptr,
		nullptr,
		nullptr) == 1
		&& EVP_CIPHER_CTX_ctrl(
			context,
			EVP_CTRL_GCM_SET_IVLEN,
			content.nonce.size(),
			nullptr) == 1
		&& EVP_DecryptInit_ex(
			context,
			nullptr,
			nullptr,
			key.bytes().data(),
			content.nonce.data()) == 1
		&& EVP_DecryptUpdate(
			context,
			nullptr,
			&aadLength,
			reinterpret_cast<const unsigned char*>(aad.constData()),
			aad.size()) == 1
		&& EVP_DecryptUpdate(
			context,
			reinterpret_cast<unsigned char*>(plaintext.data()),
			&outputLength,
			reinterpret_cast<const unsigned char*>(
				content.ciphertext.constData()),
			content.ciphertext.size()) == 1
		&& EVP_CIPHER_CTX_ctrl(
			context,
			EVP_CTRL_GCM_SET_TAG,
			content.authenticationTag.size(),
			const_cast<std::uint8_t*>(content.authenticationTag.data())) == 1
		&& EVP_DecryptFinal_ex(
			context,
			reinterpret_cast<unsigned char*>(plaintext.data()) + outputLength,
			&finalLength) == 1;
	EVP_CIPHER_CTX_free(context);
	if (!ok || outputLength + finalLength != content.ciphertext.size()) {
		OPENSSL_cleanse(plaintext.data(), plaintext.size());
		return std::nullopt;
	}
	return plaintext;
}

} // namespace

std::optional<QByteArray> EncryptedArchivedContentCodecV1::encode(
		const EncryptedArchivedContent &content) const {
	if (!ValidContent(content)) {
		return std::nullopt;
	}
	auto result = SignatureInput(content);
	AppendArray(result, content.signature);
	return result;
}

std::optional<EncryptedArchivedContent>
EncryptedArchivedContentCodecV1::decode(const QByteArray &bytes) const {
	if (bytes.size() <= kContentFixedSize
		|| bytes.size() > kContentFixedSize + kMaximumArchivedContentSize) {
		return std::nullopt;
	}
	auto reader = Reader{ bytes };
	auto magic = std::array<std::uint8_t, 8>();
	auto version = std::uint16_t();
	auto kind = std::uint16_t();
	auto ciphertextSize = std::uint32_t();
	auto wrappedBytes = QByteArray();
	auto result = EncryptedArchivedContent();
	if (!ReadArray(reader, magic)
		|| !ReadUint16(reader, version)
		|| !ReadArray(reader, result.conversationId.bytes)
		|| !ReadArray(reader, result.eventObjectId.bytes)
		|| !ReadArray(reader, result.contentObjectId.bytes)
		|| !ReadUint16(reader, kind)
		|| !ReadUint64(reader, result.groupGeneration)
		|| !ReadArray(reader, result.senderAccountId.bytes)
		|| !ReadArray(reader, result.senderClientId.bytes)
		|| reader.bytes.size() - reader.offset
			< kArchiveContentKeyEnvelopeEncodedSize) {
		return std::nullopt;
	}
	wrappedBytes = QByteArray(
		reader.bytes.constData() + reader.offset,
		kArchiveContentKeyEnvelopeEncodedSize);
	reader.offset += kArchiveContentKeyEnvelopeEncodedSize;
	const auto wrapped = ArchiveContentKeyEnvelopeCodecV1().decode(wrappedBytes);
	if (!wrapped
		|| !ReadArray(reader, result.nonce)
		|| !ReadUint32(reader, ciphertextSize)
		|| !ciphertextSize
		|| ciphertextSize > kMaximumArchivedContentSize
		|| reader.bytes.size() - reader.offset
			!= int(ciphertextSize)
				+ int(result.authenticationTag.size())
				+ int(result.signature.size())
		|| magic != kContentMagic
		|| version != 1) {
		return std::nullopt;
	}
	result.objectKind = ObjectKind(kind);
	result.wrappedContentKey = *wrapped;
	result.ciphertext = QByteArray(
		reader.bytes.constData() + reader.offset,
		int(ciphertextSize));
	reader.offset += int(ciphertextSize);
	if (!ReadArray(reader, result.authenticationTag)
		|| !ReadArray(reader, result.signature)
		|| reader.offset != bytes.size()
		|| !ValidContent(result)) {
		return std::nullopt;
	}
	return result;
}

std::optional<QByteArray> ArchivedContentDescriptorCodecV1::encodePlaintext(
		const ArchivedContentDescriptor &descriptor) const {
	if (!descriptor.conversationId
		|| !descriptor.eventObjectId
		|| !descriptor.contentObjectId
		|| !ValidKind(descriptor.objectKind)
		|| !descriptor.groupGeneration
		|| !descriptor.archiveEpochGeneration
		|| !descriptor.encodedContentHash
		|| !descriptor.contentKey.valid()) {
		return std::nullopt;
	}
	auto result = QByteArray();
	result.reserve(kArchivedContentDescriptorEncodedSize);
	AppendArray(result, kDescriptorMagic);
	AppendUint16(result, 1);
	AppendArray(result, descriptor.conversationId.bytes);
	AppendArray(result, descriptor.eventObjectId.bytes);
	AppendArray(result, descriptor.contentObjectId.bytes);
	AppendUint16(result, std::uint16_t(descriptor.objectKind));
	AppendUint64(result, descriptor.groupGeneration);
	AppendUint64(result, descriptor.archiveEpochGeneration);
	AppendArray(result, descriptor.encodedContentHash.bytes);
	AppendArray(result, descriptor.contentKey.bytes());
	return result;
}

std::optional<ArchivedContentDescriptor>
ArchivedContentDescriptorCodecV1::decodePlaintext(
		const QByteArray &bytes) const {
	if (bytes.size() != kArchivedContentDescriptorEncodedSize) {
		return std::nullopt;
	}
	auto reader = Reader{ bytes };
	auto magic = std::array<std::uint8_t, 8>();
	auto version = std::uint16_t();
	auto kind = std::uint16_t();
	auto key = std::array<std::uint8_t, kArchiveKeySize>();
	auto result = ArchivedContentDescriptor();
	if (!ReadArray(reader, magic)
		|| !ReadUint16(reader, version)
		|| !ReadArray(reader, result.conversationId.bytes)
		|| !ReadArray(reader, result.eventObjectId.bytes)
		|| !ReadArray(reader, result.contentObjectId.bytes)
		|| !ReadUint16(reader, kind)
		|| !ReadUint64(reader, result.groupGeneration)
		|| !ReadUint64(reader, result.archiveEpochGeneration)
		|| !ReadArray(reader, result.encodedContentHash.bytes)
		|| !ReadArray(reader, key)
		|| reader.offset != bytes.size()
		|| magic != kDescriptorMagic
		|| version != 1) {
		OPENSSL_cleanse(key.data(), key.size());
		return std::nullopt;
	}
	result.objectKind = ObjectKind(kind);
	result.contentKey = ArchiveKey32(std::move(key));
	return result.conversationId
		&& result.eventObjectId
		&& result.contentObjectId
		&& ValidKind(result.objectKind)
		&& result.groupGeneration
		&& result.archiveEpochGeneration
		&& result.encodedContentHash
		&& result.contentKey.valid()
		? std::optional<ArchivedContentDescriptor>(std::move(result))
		: std::nullopt;
}

std::optional<PreparedArchivedContent> PrepareArchivedContent(
		PrepareArchivedContentArgs args,
		const ArchiveEpochCrypto &archiveCrypto) {
	if (!args.conversationId
		|| !args.eventObjectId
		|| !args.contentObjectId
		|| !ValidKind(args.objectKind)
		|| !args.senderAccountId
		|| !args.senderClientId
		|| !args.groupGeneration
		|| !args.archiveEpochGeneration
		|| !args.archiveEpochKey
		|| !args.archiveEpochKey->valid()
		|| !args.senderSigningPrivateKey
		|| !args.senderSigningPrivateKey->valid()
		|| args.plaintext.isEmpty()
		|| args.plaintext.size() > kMaximumArchivedContentSize) {
		return std::nullopt;
	}
	auto contentKey = archiveCrypto.generateKey();
	if (!contentKey) {
		return std::nullopt;
	}
	auto wrapped = archiveCrypto.wrapContentKey(
		args.conversationId,
		args.archiveEpochGeneration,
		args.eventObjectId,
		args.contentObjectId,
		*args.archiveEpochKey,
		*contentKey);
	if (!wrapped) {
		return std::nullopt;
	}
	auto encrypted = EncryptedArchivedContent{
		.conversationId = args.conversationId,
		.eventObjectId = args.eventObjectId,
		.contentObjectId = args.contentObjectId,
		.objectKind = args.objectKind,
		.groupGeneration = args.groupGeneration,
		.senderAccountId = args.senderAccountId,
		.senderClientId = args.senderClientId,
		.wrappedContentKey = *wrapped,
		.nonce = {},
		.ciphertext = {},
		.authenticationTag = {},
		.signature = {},
	};
	if (RAND_bytes(encrypted.nonce.data(), encrypted.nonce.size()) != 1) {
		return std::nullopt;
	}
	const auto aad = EncodeHeader(encrypted);
	auto ciphertext = Encrypt(
		*contentKey,
		aad,
		args.plaintext,
		encrypted.nonce,
		encrypted.authenticationTag);
	OPENSSL_cleanse(args.plaintext.data(), args.plaintext.size());
	if (!ciphertext) {
		return std::nullopt;
	}
	encrypted.ciphertext = std::move(*ciphertext);
	const auto signature = SignAccountData(
		*args.senderSigningPrivateKey,
		AccountSignatureDomain::ArchivedContent,
		SignatureInput(encrypted));
	if (!signature) {
		return std::nullopt;
	}
	encrypted.signature = *signature;
	return ValidContent(encrypted)
		? std::optional<PreparedArchivedContent>({
			.contentKey = std::move(*contentKey),
			.encrypted = std::move(encrypted),
		})
		: std::nullopt;
}

std::optional<QByteArray> OpenArchivedContentWithContentKey(
		const EncryptedArchivedContent &content,
		const ArchiveKey32 &contentKey,
		const AccountCredentialPublic &senderCredential,
		const Sha256Provider &sha256) {
	const auto accountId = DeriveAccountId(senderCredential, sha256);
	const auto signatureInput = SignatureInput(content);
	if (!ValidContent(content)
		|| !contentKey.valid()
		|| !accountId
		|| *accountId != content.senderAccountId
		|| !VerifyAccountSignature(
			senderCredential,
			AccountSignatureDomain::ArchivedContent,
			signatureInput,
			content.signature)) {
		return std::nullopt;
	}
	return Decrypt(contentKey, EncodeHeader(content), content);
}

std::optional<QByteArray> OpenArchivedContentWithEpochKey(
		const EncryptedArchivedContent &content,
		const ArchiveKey32 &archiveEpochKey,
		const AccountCredentialPublic &senderCredential,
		const Sha256Provider &sha256,
		const ArchiveEpochCrypto &archiveCrypto) {
	auto contentKey = archiveCrypto.unwrapContentKey(
		archiveEpochKey,
		content.wrappedContentKey);
	return contentKey
		? OpenArchivedContentWithContentKey(
			content,
			*contentKey,
			senderCredential,
			sha256)
		: std::nullopt;
}

} // namespace E2ECloud
