/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "e2e_cloud/files/file_chunk_crypto.h"

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#include <algorithm>
#include <array>
#include <limits>
#include <utility>

namespace E2ECloud {
namespace {

inline constexpr auto kMagic = std::array<std::uint8_t, 8>{
	'T', 'D', 'E', '2', 'E', 'C', 'H', 'K',
};
inline constexpr auto kHeaderSize = 106;
inline constexpr auto kTagSize = 16;
inline constexpr auto kMinimumChunkSize = 64 * 1024;
inline constexpr auto kMaximumChunkSize = 4 * 1024 * 1024;

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
		value.size());
}

[[nodiscard]] std::uint16_t ReadUint16(const char *data) {
	const auto bytes = reinterpret_cast<const std::uint8_t*>(data);
	return (std::uint16_t(bytes[0]) << 8) | std::uint16_t(bytes[1]);
}

[[nodiscard]] std::uint32_t ReadUint32(const char *data) {
	const auto bytes = reinterpret_cast<const std::uint8_t*>(data);
	return (std::uint32_t(bytes[0]) << 24)
		| (std::uint32_t(bytes[1]) << 16)
		| (std::uint32_t(bytes[2]) << 8)
		| std::uint32_t(bytes[3]);
}

[[nodiscard]] std::uint64_t ReadUint64(const char *data) {
	auto result = std::uint64_t(0);
	for (auto i = 0; i != 8; ++i) {
		result = (result << 8) | std::uint8_t(data[i]);
	}
	return result;
}

template <typename Array>
[[nodiscard]] bool EqualArray(const char *data, const Array &value) {
	return std::equal(
		std::begin(value),
		std::end(value),
		reinterpret_cast<const std::uint8_t*>(data));
}

[[nodiscard]] std::uint32_t ExpectedPlaintextSize(
		const FileChunkContext &context,
		std::uint32_t index) {
	if (index + 1 < context.chunkCount) {
		return context.chunkSize;
	}
	const auto consumed = std::uint64_t(context.chunkSize)
		* (context.chunkCount - 1);
	return std::uint32_t(context.plaintextSize - consumed);
}

[[nodiscard]] std::array<std::uint8_t, 12> MakeNonce(
		const FileChunkContext &context,
		std::uint32_t index) {
	auto result = std::array<std::uint8_t, 12>();
	std::copy(
		std::begin(context.noncePrefix),
		std::end(context.noncePrefix),
		result.begin());
	result[8] = std::uint8_t(index >> 24);
	result[9] = std::uint8_t(index >> 16);
	result[10] = std::uint8_t(index >> 8);
	result[11] = std::uint8_t(index);
	return result;
}

void Cleanse(QByteArray &bytes) {
	if (!bytes.isEmpty()) {
		OPENSSL_cleanse(bytes.data(), bytes.size());
	}
	bytes.clear();
}

} // namespace

FileEncryptionKey::FileEncryptionKey() = default;

FileEncryptionKey::FileEncryptionKey(
		std::array<std::uint8_t, 32> &&bytes)
: _bytes(bytes) {
	OPENSSL_cleanse(bytes.data(), bytes.size());
}

FileEncryptionKey::FileEncryptionKey(FileEncryptionKey &&other) noexcept
: _bytes(other._bytes) {
	OPENSSL_cleanse(other._bytes.data(), other._bytes.size());
}

FileEncryptionKey &FileEncryptionKey::operator=(
		FileEncryptionKey &&other) noexcept {
	if (this != &other) {
		OPENSSL_cleanse(_bytes.data(), _bytes.size());
		_bytes = other._bytes;
		OPENSSL_cleanse(other._bytes.data(), other._bytes.size());
	}
	return *this;
}

FileEncryptionKey::~FileEncryptionKey() {
	OPENSSL_cleanse(_bytes.data(), _bytes.size());
}

bool FileEncryptionKey::valid() const {
	return std::any_of(begin(_bytes), end(_bytes), [](std::uint8_t byte) {
		return byte != 0;
	});
}

const std::array<std::uint8_t, 32> &FileEncryptionKey::bytes() const {
	return _bytes;
}

std::optional<FileEncryptionMaterial> GenerateFileEncryptionMaterial() {
	auto fileId = FileId();
	auto key = std::array<std::uint8_t, 32>();
	auto prefix = std::array<std::uint8_t, 8>();
	const auto generated = RAND_bytes(fileId.bytes.data(), fileId.bytes.size()) == 1
		&& RAND_bytes(key.data(), key.size()) == 1
		&& RAND_bytes(prefix.data(), prefix.size()) == 1;
	if (!generated || !fileId) {
		OPENSSL_cleanse(key.data(), key.size());
		return std::nullopt;
	}
	auto result = FileEncryptionMaterial{
		.fileId = fileId,
		.key = FileEncryptionKey(std::move(key)),
		.noncePrefix = prefix,
	};
	return (result.key.valid()
		&& std::any_of(
			begin(result.noncePrefix),
			end(result.noncePrefix),
			[](std::uint8_t byte) { return byte != 0; }))
		? std::optional<FileEncryptionMaterial>(std::move(result))
		: std::nullopt;
}

bool IsValidFileChunkContext(const FileChunkContext &context) {
	if (!context.conversationId
		|| !context.fileId
		|| context.chunkSize < kMinimumChunkSize
		|| context.chunkSize > kMaximumChunkSize
		|| !std::any_of(
			begin(context.noncePrefix),
			end(context.noncePrefix),
			[](std::uint8_t byte) { return byte != 0; })) {
		return false;
	}
	if (!context.plaintextSize) {
		return !context.chunkCount;
	} else if (!context.chunkCount) {
		return false;
	}
	const auto expected = 1
		+ ((context.plaintextSize - 1) / context.chunkSize);
	return expected == context.chunkCount
		&& expected <= std::numeric_limits<std::uint32_t>::max();
}

std::optional<QByteArray> AesGcmFileChunkCipher::encrypt(
		const FileEncryptionKey &key,
		const FileChunkContext &context,
		std::uint32_t chunkIndex,
		const QByteArray &plaintext) const {
	if (!key.valid()
		|| !IsValidFileChunkContext(context)
		|| chunkIndex >= context.chunkCount
		|| plaintext.size() != int(ExpectedPlaintextSize(context, chunkIndex))) {
		return std::nullopt;
	}
	const auto nonce = MakeNonce(context, chunkIndex);
	auto result = QByteArray();
	result.reserve(kHeaderSize + plaintext.size() + kTagSize);
	AppendArray(result, kMagic);
	AppendUint16(result, 1);
	AppendArray(result, context.conversationId.bytes);
	AppendArray(result, context.fileId.bytes);
	AppendUint32(result, chunkIndex);
	AppendUint32(result, context.chunkCount);
	AppendUint64(result, context.plaintextSize);
	AppendUint32(result, context.chunkSize);
	AppendArray(result, context.noncePrefix);
	AppendUint32(result, std::uint32_t(plaintext.size()));
	const auto header = result;
	result.resize(kHeaderSize + plaintext.size() + kTagSize);
	const auto cipher = EVP_CIPHER_CTX_new();
	if (!cipher) {
		Cleanse(result);
		return std::nullopt;
	}
	auto outputLength = 0;
	auto totalLength = 0;
	auto ok = EVP_EncryptInit_ex(
		cipher,
		EVP_aes_256_gcm(),
		nullptr,
		nullptr,
		nullptr) == 1
		&& EVP_CIPHER_CTX_ctrl(
			cipher,
			EVP_CTRL_GCM_SET_IVLEN,
			nonce.size(),
			nullptr) == 1
		&& EVP_EncryptInit_ex(
			cipher,
			nullptr,
			nullptr,
			key.bytes().data(),
			nonce.data()) == 1
		&& EVP_EncryptUpdate(
			cipher,
			nullptr,
			&outputLength,
			reinterpret_cast<const unsigned char*>(header.constData()),
			header.size()) == 1
		&& EVP_EncryptUpdate(
			cipher,
			reinterpret_cast<unsigned char*>(result.data() + kHeaderSize),
			&outputLength,
			reinterpret_cast<const unsigned char*>(plaintext.constData()),
			plaintext.size()) == 1;
	totalLength = outputLength;
	ok = ok
		&& EVP_EncryptFinal_ex(
			cipher,
			reinterpret_cast<unsigned char*>(
				result.data() + kHeaderSize + totalLength),
			&outputLength) == 1
		&& totalLength + outputLength == plaintext.size()
		&& EVP_CIPHER_CTX_ctrl(
			cipher,
			EVP_CTRL_GCM_GET_TAG,
			kTagSize,
			result.data() + kHeaderSize + plaintext.size()) == 1;
	EVP_CIPHER_CTX_free(cipher);
	if (!ok) {
		Cleanse(result);
		return std::nullopt;
	}
	return result;
}

std::optional<QByteArray> AesGcmFileChunkCipher::decrypt(
		const FileEncryptionKey &key,
		const FileChunkContext &context,
		std::uint32_t expectedChunkIndex,
		const QByteArray &encoded) const {
	if (!key.valid()
		|| !IsValidFileChunkContext(context)
		|| expectedChunkIndex >= context.chunkCount
		|| encoded.size() < kHeaderSize + kTagSize
		|| !EqualArray(encoded.constData(), kMagic)
		|| ReadUint16(encoded.constData() + 8) != 1
		|| !EqualArray(encoded.constData() + 10, context.conversationId.bytes)
		|| !EqualArray(encoded.constData() + 42, context.fileId.bytes)
		|| ReadUint32(encoded.constData() + 74) != expectedChunkIndex
		|| ReadUint32(encoded.constData() + 78) != context.chunkCount
		|| ReadUint64(encoded.constData() + 82) != context.plaintextSize
		|| ReadUint32(encoded.constData() + 90) != context.chunkSize
		|| !EqualArray(encoded.constData() + 94, context.noncePrefix)) {
		return std::nullopt;
	}
	const auto plaintextSize = ReadUint32(encoded.constData() + 102);
	if (plaintextSize != ExpectedPlaintextSize(context, expectedChunkIndex)
		|| plaintextSize > kMaximumChunkSize
		|| encoded.size() != kHeaderSize + int(plaintextSize) + kTagSize) {
		return std::nullopt;
	}
	const auto nonce = MakeNonce(context, expectedChunkIndex);
	auto result = QByteArray();
	result.resize(plaintextSize);
	const auto cipher = EVP_CIPHER_CTX_new();
	if (!cipher) {
		return std::nullopt;
	}
	auto outputLength = 0;
	auto totalLength = 0;
	auto ok = EVP_DecryptInit_ex(
		cipher,
		EVP_aes_256_gcm(),
		nullptr,
		nullptr,
		nullptr) == 1
		&& EVP_CIPHER_CTX_ctrl(
			cipher,
			EVP_CTRL_GCM_SET_IVLEN,
			nonce.size(),
			nullptr) == 1
		&& EVP_DecryptInit_ex(
			cipher,
			nullptr,
			nullptr,
			key.bytes().data(),
			nonce.data()) == 1
		&& EVP_DecryptUpdate(
			cipher,
			nullptr,
			&outputLength,
			reinterpret_cast<const unsigned char*>(encoded.constData()),
			kHeaderSize) == 1
		&& EVP_DecryptUpdate(
			cipher,
			reinterpret_cast<unsigned char*>(result.data()),
			&outputLength,
			reinterpret_cast<const unsigned char*>(
				encoded.constData() + kHeaderSize),
			plaintextSize) == 1;
	totalLength = outputLength;
	ok = ok
		&& EVP_CIPHER_CTX_ctrl(
			cipher,
			EVP_CTRL_GCM_SET_TAG,
			kTagSize,
			const_cast<char*>(encoded.constData())
				+ kHeaderSize + plaintextSize) == 1
		&& EVP_DecryptFinal_ex(
			cipher,
			reinterpret_cast<unsigned char*>(result.data() + totalLength),
			&outputLength) == 1
		&& totalLength + outputLength == int(plaintextSize);
	EVP_CIPHER_CTX_free(cipher);
	if (!ok) {
		Cleanse(result);
		return std::nullopt;
	}
	return result;
}

} // namespace E2ECloud
