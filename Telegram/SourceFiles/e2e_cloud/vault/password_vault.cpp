/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "e2e_cloud/vault/password_vault.h"

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#include <algorithm>
#include <array>
#include <limits>

namespace E2ECloud {
namespace {

inline constexpr auto kMagic = std::array<std::uint8_t, 8>{
	'T', 'D', 'E', '2', 'E', 'V', 'L', 'T',
};
inline constexpr auto kHeaderSize = 8 + 2 + 2 + 2 + 4 + 4 + 4 + 16 + 12 + 8 + 4;
inline constexpr auto kMasterKeySize = 32;
inline constexpr auto kTagSize = 16;
inline constexpr auto kWrappedSize = kHeaderSize + kMasterKeySize + kTagSize;
inline constexpr auto kMaximumPasswordSize = 4096;

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

void Cleanse(QByteArray &bytes) {
	if (!bytes.isEmpty()) {
		OPENSSL_cleanse(bytes.data(), bytes.size());
	}
	bytes.clear();
}

template <typename Value>
void Cleanse(Value &value) {
	OPENSSL_cleanse(value.data(), value.size());
}

[[nodiscard]] bool ValidPassword(const QByteArray &password) {
	return !password.isEmpty() && password.size() <= kMaximumPasswordSize;
}

[[nodiscard]] bool EncryptMasterKey(
		const PasswordDerivedKey &key,
		const std::array<std::uint8_t, 12> &nonce,
		const QByteArray &header,
		const VaultMasterKey &masterKey,
		QByteArray &result) {
	const auto context = EVP_CIPHER_CTX_new();
	if (!context) {
		return false;
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
			key.data(),
			nonce.data()) == 1)
		&& (EVP_EncryptUpdate(
			context,
			nullptr,
			&outputLength,
			reinterpret_cast<const unsigned char*>(header.constData()),
			header.size()) == 1)
		&& (EVP_EncryptUpdate(
			context,
			reinterpret_cast<unsigned char*>(result.data() + kHeaderSize),
			&outputLength,
			masterKey.data(),
			masterKey.size()) == 1);
	totalLength = outputLength;
	ok = ok
		&& (EVP_EncryptFinal_ex(
			context,
			reinterpret_cast<unsigned char*>(
				result.data() + kHeaderSize + totalLength),
			&outputLength) == 1)
		&& (totalLength + outputLength == kMasterKeySize)
		&& (EVP_CIPHER_CTX_ctrl(
			context,
			EVP_CTRL_GCM_GET_TAG,
			kTagSize,
			result.data() + kHeaderSize + kMasterKeySize) == 1);
	EVP_CIPHER_CTX_free(context);
	return ok;
}

[[nodiscard]] bool DecryptMasterKey(
		const PasswordDerivedKey &key,
		const QByteArray &wrapped,
		VaultMasterKey &masterKey) {
	const auto nonce = reinterpret_cast<const unsigned char*>(
		wrapped.constData() + 42);
	const auto context = EVP_CIPHER_CTX_new();
	if (!context) {
		return false;
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
			key.data(),
			nonce) == 1)
		&& (EVP_DecryptUpdate(
			context,
			nullptr,
			&outputLength,
			reinterpret_cast<const unsigned char*>(wrapped.constData()),
			kHeaderSize) == 1)
		&& (EVP_DecryptUpdate(
			context,
			masterKey.data(),
			&outputLength,
			reinterpret_cast<const unsigned char*>(
				wrapped.constData() + kHeaderSize),
			kMasterKeySize) == 1);
	totalLength = outputLength;
	ok = ok
		&& (EVP_CIPHER_CTX_ctrl(
			context,
			EVP_CTRL_GCM_SET_TAG,
			kTagSize,
			const_cast<char*>(wrapped.constData())
				+ kHeaderSize + kMasterKeySize) == 1)
		&& (EVP_DecryptFinal_ex(
			context,
			masterKey.data() + totalLength,
			&outputLength) == 1)
		&& (totalLength + outputLength == kMasterKeySize);
	EVP_CIPHER_CTX_free(context);
	return ok;
}

} // namespace

PasswordVault::PasswordVault(const PasswordKdf &kdf) : _kdf(kdf) {
}

std::optional<QByteArray> PasswordVault::wrap(
		VaultMasterKey &&masterKey,
		QByteArray password,
		Argon2idConfig config,
		std::uint64_t generation) const {
	if (!ValidPassword(password)
		|| !generation
		|| !IsValidArgon2idConfig(config)
		|| !std::any_of(
			begin(masterKey),
			end(masterKey),
			[](std::uint8_t byte) { return byte != 0; })) {
		Cleanse(password);
		Cleanse(masterKey);
		return std::nullopt;
	}
	auto parameters = Argon2idParameters{
		.parameterVersion = config.parameterVersion,
		.memoryKibibytes = config.memoryKibibytes,
		.iterations = config.iterations,
		.parallelism = config.parallelism,
		.salt = {},
	};
	if (RAND_bytes(parameters.salt.data(), parameters.salt.size()) != 1) {
		Cleanse(password);
		Cleanse(masterKey);
		return std::nullopt;
	}
	auto key = _kdf.deriveArgon2id(password, parameters);
	Cleanse(password);
	if (!key) {
		Cleanse(masterKey);
		return std::nullopt;
	}
	auto nonce = std::array<std::uint8_t, 12>();
	if (RAND_bytes(nonce.data(), nonce.size()) != 1) {
		Cleanse(*key);
		Cleanse(masterKey);
		return std::nullopt;
	}
	auto result = QByteArray();
	result.reserve(kWrappedSize);
	result.append(
		reinterpret_cast<const char*>(kMagic.data()),
		kMagic.size());
	AppendUint16(result, 1);
	AppendUint16(result, 1);
	AppendUint16(result, parameters.parameterVersion);
	AppendUint32(result, parameters.memoryKibibytes);
	AppendUint32(result, parameters.iterations);
	AppendUint32(result, parameters.parallelism);
	result.append(
		reinterpret_cast<const char*>(parameters.salt.data()),
		parameters.salt.size());
	result.append(
		reinterpret_cast<const char*>(nonce.data()),
		nonce.size());
	AppendUint64(result, generation);
	AppendUint32(result, kMasterKeySize);
	const auto header = result;
	result.resize(kWrappedSize);
	const auto encrypted = EncryptMasterKey(
		*key,
		nonce,
		header,
		masterKey,
		result);
	Cleanse(*key);
	Cleanse(masterKey);
	if (!encrypted) {
		Cleanse(result);
		return std::nullopt;
	}
	return result;
}

std::optional<UnwrappedVaultKey> PasswordVault::unwrap(
		const QByteArray &wrapped,
		QByteArray password) const {
	if (!ValidPassword(password)
		|| wrapped.size() != kWrappedSize
		|| !std::equal(
			begin(kMagic),
			end(kMagic),
			reinterpret_cast<const std::uint8_t*>(wrapped.constData()))
		|| ReadUint16(wrapped.constData() + 8) != 1
		|| ReadUint16(wrapped.constData() + 10) != 1
		|| ReadUint32(wrapped.constData() + 62) != kMasterKeySize) {
		Cleanse(password);
		return std::nullopt;
	}
	auto parameters = Argon2idParameters{
		.parameterVersion = ReadUint16(wrapped.constData() + 12),
		.memoryKibibytes = ReadUint32(wrapped.constData() + 14),
		.iterations = ReadUint32(wrapped.constData() + 18),
		.parallelism = ReadUint32(wrapped.constData() + 22),
		.salt = {},
	};
	std::copy_n(
		reinterpret_cast<const std::uint8_t*>(wrapped.constData() + 26),
		parameters.salt.size(),
		parameters.salt.begin());
	const auto generation = ReadUint64(wrapped.constData() + 54);
	if (!generation || !IsValidArgon2idParameters(parameters)) {
		Cleanse(password);
		return std::nullopt;
	}
	auto key = _kdf.deriveArgon2id(password, parameters);
	Cleanse(password);
	if (!key) {
		return std::nullopt;
	}
	auto masterKey = VaultMasterKey();
	const auto decrypted = DecryptMasterKey(*key, wrapped, masterKey);
	Cleanse(*key);
	if (!decrypted) {
		Cleanse(masterKey);
		return std::nullopt;
	}
	return UnwrappedVaultKey{
		.masterKey = masterKey,
		.generation = generation,
		.parameters = parameters,
	};
}

} // namespace E2ECloud
