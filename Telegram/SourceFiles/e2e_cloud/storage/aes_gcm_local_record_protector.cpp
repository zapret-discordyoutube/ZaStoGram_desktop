/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "e2e_cloud/storage/aes_gcm_local_record_protector.h"

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
	'T', 'D', 'E', '2', 'E', 'L', 'C', 'L',
};
inline constexpr auto kHeaderSize = 8 + 2 + 12 + 4;
inline constexpr auto kTagSize = 16;
inline constexpr auto kMaximumPlaintextSize = 128 * 1024 * 1024;
inline constexpr auto kMaximumPurposeSize = 256;

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

[[nodiscard]] QByteArray AdditionalData(
		const QByteArray &purpose,
		const QByteArray &header) {
	auto result = purpose;
	result.append(char(0));
	result.append(header);
	return result;
}

void Cleanse(QByteArray &bytes) {
	if (!bytes.isEmpty()) {
		OPENSSL_cleanse(bytes.data(), bytes.size());
	}
	bytes.clear();
}

} // namespace

AesGcmLocalRecordProtector::AesGcmLocalRecordProtector(LocalRecordKey &&key)
: _key(key)
, _valid(std::any_of(begin(key), end(key), [](std::uint8_t byte) {
	return byte != 0;
})) {
	OPENSSL_cleanse(key.data(), key.size());
}

AesGcmLocalRecordProtector::~AesGcmLocalRecordProtector() {
	OPENSSL_cleanse(_key.data(), _key.size());
}

std::optional<QByteArray> AesGcmLocalRecordProtector::seal(
		const QByteArray &purpose,
		const QByteArray &plaintext) const {
	if (!_valid
		|| purpose.isEmpty()
		|| purpose.size() > kMaximumPurposeSize
		|| plaintext.isEmpty()
		|| plaintext.size() > kMaximumPlaintextSize
		|| plaintext.size() > std::numeric_limits<int>::max()) {
		return std::nullopt;
	}
	auto nonce = std::array<std::uint8_t, 12>();
	if (RAND_bytes(nonce.data(), nonce.size()) != 1) {
		return std::nullopt;
	}
	auto result = QByteArray();
	result.reserve(kHeaderSize + plaintext.size() + kTagSize);
	result.append(
		reinterpret_cast<const char*>(kMagic.data()),
		kMagic.size());
	AppendUint16(result, 1);
	result.append(
		reinterpret_cast<const char*>(nonce.data()),
		nonce.size());
	AppendUint32(result, std::uint32_t(plaintext.size()));
	const auto header = result;
	const auto additionalData = AdditionalData(purpose, header);
	result.resize(kHeaderSize + plaintext.size() + kTagSize);
	const auto context = EVP_CIPHER_CTX_new();
	if (!context) {
		Cleanse(result);
		return std::nullopt;
	}
	auto outputLength = 0;
	auto totalLength = 0;
	auto ok = (EVP_EncryptInit_ex(
		context,
		EVP_aes_256_gcm(),
		nullptr,
		nullptr,
		nullptr) == 1)
		&& (EVP_CIPHER_CTX_ctrl(
			context,
			EVP_CTRL_GCM_SET_IVLEN,
			nonce.size(),
			nullptr) == 1)
		&& (EVP_EncryptInit_ex(
			context,
			nullptr,
			nullptr,
			_key.data(),
			nonce.data()) == 1)
		&& (EVP_EncryptUpdate(
			context,
			nullptr,
			&outputLength,
			reinterpret_cast<const unsigned char*>(
				additionalData.constData()),
			additionalData.size()) == 1)
		&& (EVP_EncryptUpdate(
			context,
			reinterpret_cast<unsigned char*>(result.data() + kHeaderSize),
			&outputLength,
			reinterpret_cast<const unsigned char*>(plaintext.constData()),
			plaintext.size()) == 1);
	totalLength = outputLength;
	ok = ok
		&& (EVP_EncryptFinal_ex(
			context,
			reinterpret_cast<unsigned char*>(
				result.data() + kHeaderSize + totalLength),
			&outputLength) == 1)
		&& (totalLength + outputLength == plaintext.size())
		&& (EVP_CIPHER_CTX_ctrl(
			context,
			EVP_CTRL_GCM_GET_TAG,
			kTagSize,
			result.data() + kHeaderSize + plaintext.size()) == 1);
	EVP_CIPHER_CTX_free(context);
	if (!ok) {
		Cleanse(result);
		return std::nullopt;
	}
	return result;
}

std::optional<QByteArray> AesGcmLocalRecordProtector::open(
		const QByteArray &purpose,
		const QByteArray &ciphertext) const {
	if (!_valid
		|| purpose.isEmpty()
		|| purpose.size() > kMaximumPurposeSize
		|| ciphertext.size() < kHeaderSize + kTagSize
		|| !std::equal(
			begin(kMagic),
			end(kMagic),
			reinterpret_cast<const std::uint8_t*>(ciphertext.constData()))
		|| ReadUint16(ciphertext.constData() + 8) != 1) {
		return std::nullopt;
	}
	const auto plaintextSize = ReadUint32(ciphertext.constData() + 22);
	if (!plaintextSize
		|| plaintextSize > kMaximumPlaintextSize
		|| plaintextSize > std::uint32_t(std::numeric_limits<int>::max())
		|| ciphertext.size() != kHeaderSize + int(plaintextSize) + kTagSize) {
		return std::nullopt;
	}
	const auto header = QByteArray(ciphertext.constData(), kHeaderSize);
	const auto additionalData = AdditionalData(purpose, header);
	const auto nonce = reinterpret_cast<const unsigned char*>(
		ciphertext.constData() + 10);
	auto result = QByteArray();
	result.resize(plaintextSize);
	const auto context = EVP_CIPHER_CTX_new();
	if (!context) {
		return std::nullopt;
	}
	auto outputLength = 0;
	auto totalLength = 0;
	auto ok = (EVP_DecryptInit_ex(
		context,
		EVP_aes_256_gcm(),
		nullptr,
		nullptr,
		nullptr) == 1)
		&& (EVP_CIPHER_CTX_ctrl(
			context,
			EVP_CTRL_GCM_SET_IVLEN,
			12,
			nullptr) == 1)
		&& (EVP_DecryptInit_ex(
			context,
			nullptr,
			nullptr,
			_key.data(),
			nonce) == 1)
		&& (EVP_DecryptUpdate(
			context,
			nullptr,
			&outputLength,
			reinterpret_cast<const unsigned char*>(
				additionalData.constData()),
			additionalData.size()) == 1)
		&& (EVP_DecryptUpdate(
			context,
			reinterpret_cast<unsigned char*>(result.data()),
			&outputLength,
			reinterpret_cast<const unsigned char*>(
				ciphertext.constData() + kHeaderSize),
			plaintextSize) == 1);
	totalLength = outputLength;
	ok = ok
		&& (EVP_CIPHER_CTX_ctrl(
			context,
			EVP_CTRL_GCM_SET_TAG,
			kTagSize,
			const_cast<char*>(ciphertext.constData())
				+ kHeaderSize + plaintextSize) == 1)
		&& (EVP_DecryptFinal_ex(
			context,
			reinterpret_cast<unsigned char*>(result.data() + totalLength),
			&outputLength) == 1)
		&& (totalLength + outputLength == int(plaintextSize));
	EVP_CIPHER_CTX_free(context);
	if (!ok) {
		Cleanse(result);
		return std::nullopt;
	}
	return result;
}

} // namespace E2ECloud
