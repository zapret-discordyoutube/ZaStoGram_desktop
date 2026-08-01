/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "e2e_cloud/archive/archive_epoch_crypto.h"

#include "e2e_cloud/identity/account_identity.h"

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#include <algorithm>
#include <array>
#include <utility>

namespace E2ECloud {
namespace {

inline constexpr auto kMagic = std::array<std::uint8_t, 8>{
	'T', 'D', 'E', '2', 'E', 'A', 'C', 'K',
};
inline constexpr auto kCommitmentMagic = std::array<std::uint8_t, 8>{
	'T', 'D', 'E', '2', 'E', 'A', 'E', 'K',
};
inline constexpr auto kAadSize = 8 + 2 + 32 + 8 + 32 + 32 + 12;

struct Reader {
	const QByteArray &bytes;
	int offset = 0;
};

void AppendUint16(QByteArray &result, std::uint16_t value) {
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

[[nodiscard]] bool Valid(const ArchiveContentKeyEnvelope &envelope) {
	return envelope.conversationId
		&& envelope.epochGeneration
		&& envelope.eventObjectId
		&& envelope.contentObjectId
		&& Nonzero(envelope.nonce)
		&& Nonzero(envelope.ciphertext)
		&& Nonzero(envelope.authenticationTag);
}

[[nodiscard]] QByteArray AuthenticatedData(
		const ArchiveContentKeyEnvelope &envelope) {
	auto result = QByteArray();
	result.reserve(kAadSize);
	AppendArray(result, kMagic);
	AppendUint16(result, 1);
	AppendArray(result, envelope.conversationId.bytes);
	AppendUint64(result, envelope.epochGeneration);
	AppendArray(result, envelope.eventObjectId.bytes);
	AppendArray(result, envelope.contentObjectId.bytes);
	AppendArray(result, envelope.nonce);
	return result;
}

} // namespace

ArchiveKey32::ArchiveKey32() = default;

ArchiveKey32::ArchiveKey32(
		std::array<std::uint8_t, kArchiveKeySize> &&bytes)
: _bytes(bytes) {
	OPENSSL_cleanse(bytes.data(), bytes.size());
}

ArchiveKey32::ArchiveKey32(ArchiveKey32 &&other) noexcept
: _bytes(other._bytes) {
	OPENSSL_cleanse(other._bytes.data(), other._bytes.size());
}

ArchiveKey32 &ArchiveKey32::operator=(ArchiveKey32 &&other) noexcept {
	if (this != &other) {
		OPENSSL_cleanse(_bytes.data(), _bytes.size());
		_bytes = other._bytes;
		OPENSSL_cleanse(other._bytes.data(), other._bytes.size());
	}
	return *this;
}

ArchiveKey32::~ArchiveKey32() {
	OPENSSL_cleanse(_bytes.data(), _bytes.size());
}

bool ArchiveKey32::valid() const {
	return Nonzero(_bytes);
}

const std::array<std::uint8_t, kArchiveKeySize> &ArchiveKey32::bytes() const {
	return _bytes;
}

ArchiveKey32 ArchiveKey32::clone() const {
	auto bytes = _bytes;
	return ArchiveKey32(std::move(bytes));
}

std::optional<QByteArray> ArchiveContentKeyEnvelopeCodecV1::encode(
		const ArchiveContentKeyEnvelope &envelope) const {
	if (!Valid(envelope)) {
		return std::nullopt;
	}
	auto result = AuthenticatedData(envelope);
	result.reserve(kArchiveContentKeyEnvelopeEncodedSize);
	AppendArray(result, envelope.ciphertext);
	AppendArray(result, envelope.authenticationTag);
	return result;
}

std::optional<ArchiveContentKeyEnvelope>
ArchiveContentKeyEnvelopeCodecV1::decode(const QByteArray &bytes) const {
	if (bytes.size() != kArchiveContentKeyEnvelopeEncodedSize) {
		return std::nullopt;
	}
	auto reader = Reader{ bytes };
	auto magic = std::array<std::uint8_t, 8>();
	auto version = std::uint16_t();
	auto result = ArchiveContentKeyEnvelope();
	if (!ReadArray(reader, magic)
		|| !ReadUint16(reader, version)
		|| !ReadArray(reader, result.conversationId.bytes)
		|| !ReadUint64(reader, result.epochGeneration)
		|| !ReadArray(reader, result.eventObjectId.bytes)
		|| !ReadArray(reader, result.contentObjectId.bytes)
		|| !ReadArray(reader, result.nonce)
		|| !ReadArray(reader, result.ciphertext)
		|| !ReadArray(reader, result.authenticationTag)
		|| reader.offset != bytes.size()
		|| magic != kMagic
		|| version != 1
		|| !Valid(result)) {
		return std::nullopt;
	}
	return result;
}

std::optional<ArchiveKey32> ArchiveEpochCrypto::generateKey() const {
	auto bytes = std::array<std::uint8_t, kArchiveKeySize>();
	if (RAND_bytes(bytes.data(), bytes.size()) != 1 || !Nonzero(bytes)) {
		OPENSSL_cleanse(bytes.data(), bytes.size());
		return std::nullopt;
	}
	return ArchiveKey32(std::move(bytes));
}

std::optional<ArchiveContentKeyEnvelope>
ArchiveEpochCrypto::wrapContentKey(
		ConversationId conversationId,
		std::uint64_t epochGeneration,
		ObjectId eventObjectId,
		ObjectId contentObjectId,
		const ArchiveKey32 &epochKey,
		const ArchiveKey32 &contentKey) const {
	if (!conversationId
		|| !epochGeneration
		|| !eventObjectId
		|| !contentObjectId
		|| !epochKey.valid()
		|| !contentKey.valid()) {
		return std::nullopt;
	}
	auto result = ArchiveContentKeyEnvelope{
		.conversationId = conversationId,
		.epochGeneration = epochGeneration,
		.eventObjectId = eventObjectId,
		.contentObjectId = contentObjectId,
	};
	if (RAND_bytes(result.nonce.data(), result.nonce.size()) != 1
		|| !Nonzero(result.nonce)) {
		return std::nullopt;
	}
	const auto aad = AuthenticatedData(result);
	const auto context = EVP_CIPHER_CTX_new();
	auto written = 0;
	auto finalWritten = 0;
	const auto ok = context
		&& EVP_EncryptInit_ex(context, EVP_aes_256_gcm(), nullptr, nullptr, nullptr)
			== 1
		&& EVP_CIPHER_CTX_ctrl(
			context,
			EVP_CTRL_GCM_SET_IVLEN,
			result.nonce.size(),
			nullptr) == 1
		&& EVP_EncryptInit_ex(
			context,
			nullptr,
			nullptr,
			epochKey.bytes().data(),
			result.nonce.data()) == 1
		&& EVP_EncryptUpdate(
			context,
			nullptr,
			&written,
			reinterpret_cast<const unsigned char*>(aad.constData()),
			aad.size()) == 1
		&& EVP_EncryptUpdate(
			context,
			result.ciphertext.data(),
			&written,
			contentKey.bytes().data(),
			contentKey.bytes().size()) == 1
		&& written == result.ciphertext.size()
		&& EVP_EncryptFinal_ex(
			context,
			result.ciphertext.data() + written,
			&finalWritten) == 1
		&& !finalWritten
		&& EVP_CIPHER_CTX_ctrl(
			context,
			EVP_CTRL_GCM_GET_TAG,
			result.authenticationTag.size(),
			result.authenticationTag.data()) == 1;
	EVP_CIPHER_CTX_free(context);
	return ok ? std::optional<ArchiveContentKeyEnvelope>(result) : std::nullopt;
}

std::optional<ArchiveKey32> ArchiveEpochCrypto::unwrapContentKey(
		const ArchiveKey32 &epochKey,
		const ArchiveContentKeyEnvelope &envelope) const {
	if (!epochKey.valid() || !Valid(envelope)) {
		return std::nullopt;
	}
	const auto aad = AuthenticatedData(envelope);
	const auto context = EVP_CIPHER_CTX_new();
	auto plaintext = std::array<std::uint8_t, kArchiveKeySize>();
	auto written = 0;
	auto finalWritten = 0;
	const auto initialized = context
		&& EVP_DecryptInit_ex(context, EVP_aes_256_gcm(), nullptr, nullptr, nullptr)
			== 1
		&& EVP_CIPHER_CTX_ctrl(
			context,
			EVP_CTRL_GCM_SET_IVLEN,
			envelope.nonce.size(),
			nullptr) == 1
		&& EVP_DecryptInit_ex(
			context,
			nullptr,
			nullptr,
			epochKey.bytes().data(),
			envelope.nonce.data()) == 1
		&& EVP_DecryptUpdate(
			context,
			nullptr,
			&written,
			reinterpret_cast<const unsigned char*>(aad.constData()),
			aad.size()) == 1
		&& EVP_DecryptUpdate(
			context,
			plaintext.data(),
			&written,
			envelope.ciphertext.data(),
			envelope.ciphertext.size()) == 1
		&& written == plaintext.size()
		&& EVP_CIPHER_CTX_ctrl(
			context,
			EVP_CTRL_GCM_SET_TAG,
			envelope.authenticationTag.size(),
			const_cast<std::uint8_t*>(envelope.authenticationTag.data())) == 1;
	const auto authenticated = initialized
		&& EVP_DecryptFinal_ex(
			context,
			plaintext.data() + written,
			&finalWritten) == 1
		&& !finalWritten;
	EVP_CIPHER_CTX_free(context);
	if (!authenticated || !Nonzero(plaintext)) {
		OPENSSL_cleanse(plaintext.data(), plaintext.size());
		return std::nullopt;
	}
	return ArchiveKey32(std::move(plaintext));
}

std::optional<Digest> DeriveArchiveKeyCommitment(
		ConversationId conversationId,
		std::uint64_t archiveEpochGeneration,
		std::uint64_t activationGroupGeneration,
		ObjectId activationEventId,
		const ArchiveKey32 &key,
		const Sha256Provider &sha256) {
	if (!conversationId
		|| !archiveEpochGeneration
		|| !activationGroupGeneration
		|| !activationEventId
		|| !key.valid()) {
		return std::nullopt;
	}
	auto input = QByteArray();
	input.reserve(8 + 2 + 32 + 8 + 8 + 32 + kArchiveKeySize);
	AppendArray(input, kCommitmentMagic);
	AppendUint16(input, 1);
	AppendArray(input, conversationId.bytes);
	AppendUint64(input, archiveEpochGeneration);
	AppendUint64(input, activationGroupGeneration);
	AppendArray(input, activationEventId.bytes);
	AppendArray(input, key.bytes());
	return sha256.digest(input);
}

} // namespace E2ECloud
