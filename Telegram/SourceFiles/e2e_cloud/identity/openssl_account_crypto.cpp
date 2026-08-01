/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "e2e_cloud/identity/openssl_account_crypto.h"

#include <openssl/crypto.h>
#include <openssl/evp.h>

#include <algorithm>
#include <utility>

namespace E2ECloud {
namespace {

inline constexpr auto kMaximumSignedDataSize = 16 * 1024 * 1024;

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

void Cleanse(QByteArray &bytes) {
	if (!bytes.isEmpty()) {
		OPENSSL_cleanse(bytes.data(), bytes.size());
	}
	bytes.clear();
}

[[nodiscard]] bool ValidDomain(AccountSignatureDomain domain) {
	switch (domain) {
	case AccountSignatureDomain::GroupTransition:
	case AccountSignatureDomain::ClientAuthorization:
	case AccountSignatureDomain::SafetyGossip:
	case AccountSignatureDomain::FreshnessResponse:
	case AccountSignatureDomain::HistoryGrant:
	case AccountSignatureDomain::VaultCheckpoint:
	case AccountSignatureDomain::ArchivedContent:
	case AccountSignatureDomain::GroupGenesis:
	case AccountSignatureDomain::ForkRecovery:
	case AccountSignatureDomain::FreshnessChallenge:
	case AccountSignatureDomain::FileChunk:
		return true;
	}
	return false;
}

[[nodiscard]] std::optional<QByteArray> SignatureInput(
		AccountSignatureDomain domain,
		const QByteArray &data) {
	if (!ValidDomain(domain)
		|| data.isEmpty()
		|| data.size() > kMaximumSignedDataSize) {
		return std::nullopt;
	}
	auto result = QByteArray("TDE2E/account-signature/v1");
	result.append(char(0));
	AppendUint16(result, std::uint16_t(domain));
	AppendUint32(result, std::uint32_t(data.size()));
	result.append(data);
	return result;
}

[[nodiscard]] bool GenerateRawKey(
		int type,
		std::array<std::uint8_t, 32> &privateKey,
		std::array<std::uint8_t, 32> &publicKey) {
	const auto context = EVP_PKEY_CTX_new_id(type, nullptr);
	if (!context) {
		return false;
	}
	auto key = static_cast<EVP_PKEY*>(nullptr);
	auto privateSize = privateKey.size();
	auto publicSize = publicKey.size();
	const auto ok = EVP_PKEY_keygen_init(context) == 1
		&& EVP_PKEY_keygen(context, &key) == 1
		&& EVP_PKEY_get_raw_private_key(
			key,
			privateKey.data(),
			&privateSize) == 1
		&& privateSize == privateKey.size()
		&& EVP_PKEY_get_raw_public_key(
			key,
			publicKey.data(),
			&publicSize) == 1
		&& publicSize == publicKey.size();
	EVP_PKEY_free(key);
	EVP_PKEY_CTX_free(context);
	return ok;
}

[[nodiscard]] bool PublicKeyFromPrivate(
		int type,
		const SecureKey32 &privateKey,
		std::array<std::uint8_t, 32> &publicKey) {
	if (!privateKey.valid()) {
		return false;
	}
	const auto key = EVP_PKEY_new_raw_private_key(
		type,
		nullptr,
		privateKey.bytes().data(),
		privateKey.bytes().size());
	auto publicSize = publicKey.size();
	const auto result = key
		&& EVP_PKEY_get_raw_public_key(
			key,
			publicKey.data(),
			&publicSize) == 1
		&& publicSize == publicKey.size();
	EVP_PKEY_free(key);
	return result;
}

} // namespace

SecureKey32::SecureKey32() = default;

SecureKey32::SecureKey32(std::array<std::uint8_t, 32> &&bytes)
: _bytes(bytes) {
	OPENSSL_cleanse(bytes.data(), bytes.size());
}

SecureKey32::SecureKey32(SecureKey32 &&other) noexcept
: _bytes(other._bytes) {
	OPENSSL_cleanse(other._bytes.data(), other._bytes.size());
}

SecureKey32 &SecureKey32::operator=(SecureKey32 &&other) noexcept {
	if (this != &other) {
		OPENSSL_cleanse(_bytes.data(), _bytes.size());
		_bytes = other._bytes;
		OPENSSL_cleanse(other._bytes.data(), other._bytes.size());
	}
	return *this;
}

SecureKey32::~SecureKey32() {
	OPENSSL_cleanse(_bytes.data(), _bytes.size());
}

bool SecureKey32::valid() const {
	return std::any_of(begin(_bytes), end(_bytes), [](std::uint8_t byte) {
		return byte != 0;
	});
}

const std::array<std::uint8_t, 32> &SecureKey32::bytes() const {
	return _bytes;
}

Digest OpenSslSha256Provider::digest(const QByteArray &bytes) const {
	auto result = Digest();
	if (bytes.isEmpty()) {
		return result;
	}
	auto size = 0U;
	if (EVP_Digest(
			reinterpret_cast<const unsigned char*>(bytes.constData()),
			bytes.size(),
			result.bytes.data(),
			&size,
			EVP_sha256(),
			nullptr) != 1
		|| size != result.bytes.size()) {
		result.bytes.fill(0);
	}
	return result;
}

std::optional<AccountPrivateIdentity> GenerateAccountPrivateIdentity() {
	auto signingPrivate = std::array<std::uint8_t, 32>();
	auto archivePrivate = std::array<std::uint8_t, 32>();
	auto credential = AccountCredentialPublic();
	const auto generated = GenerateRawKey(
		EVP_PKEY_ED25519,
		signingPrivate,
		credential.signingPublicKey)
		&& GenerateRawKey(
			EVP_PKEY_X25519,
			archivePrivate,
			credential.archiveHpkePublicKey);
	if (!generated) {
		OPENSSL_cleanse(signingPrivate.data(), signingPrivate.size());
		OPENSSL_cleanse(archivePrivate.data(), archivePrivate.size());
		return std::nullopt;
	}
	return AccountPrivateIdentity{
		.signingPrivateKey = SecureKey32(std::move(signingPrivate)),
		.archiveHpkePrivateKey = SecureKey32(std::move(archivePrivate)),
		.credential = credential,
	};
}

bool ValidateAccountPrivateIdentity(
		const AccountPrivateIdentity &identity) {
	auto signingPublic = std::array<std::uint8_t, 32>();
	auto archivePublic = std::array<std::uint8_t, 32>();
	return AccountCredentialCodecV1().encode(identity.credential).has_value()
		&& PublicKeyFromPrivate(
			EVP_PKEY_ED25519,
			identity.signingPrivateKey,
			signingPublic)
		&& PublicKeyFromPrivate(
			EVP_PKEY_X25519,
			identity.archiveHpkePrivateKey,
			archivePublic)
		&& signingPublic == identity.credential.signingPublicKey
		&& archivePublic == identity.credential.archiveHpkePublicKey;
}

std::optional<AccountSignature> SignAccountData(
		const SecureKey32 &privateKey,
		AccountSignatureDomain domain,
		const QByteArray &data) {
	auto input = SignatureInput(domain, data);
	if (!privateKey.valid() || !input) {
		if (input) {
			Cleanse(*input);
		}
		return std::nullopt;
	}
	const auto key = EVP_PKEY_new_raw_private_key(
		EVP_PKEY_ED25519,
		nullptr,
		privateKey.bytes().data(),
		privateKey.bytes().size());
	const auto context = EVP_MD_CTX_new();
	if (!key || !context) {
		EVP_MD_CTX_free(context);
		EVP_PKEY_free(key);
		Cleanse(*input);
		return std::nullopt;
	}
	auto result = AccountSignature();
	auto resultSize = result.size();
	const auto ok = EVP_DigestSignInit(
		context,
		nullptr,
		nullptr,
		nullptr,
		key) == 1
		&& EVP_DigestSign(
			context,
			result.data(),
			&resultSize,
			reinterpret_cast<const unsigned char*>(input->constData()),
			input->size()) == 1
		&& resultSize == result.size();
	EVP_MD_CTX_free(context);
	EVP_PKEY_free(key);
	Cleanse(*input);
	return ok ? std::optional<AccountSignature>(result) : std::nullopt;
}

bool VerifyAccountSignature(
		const AccountCredentialPublic &credential,
		AccountSignatureDomain domain,
		const QByteArray &data,
		const AccountSignature &signature) {
	auto input = SignatureInput(domain, data);
	if (!input || !AccountCredentialCodecV1().encode(credential)) {
		if (input) {
			Cleanse(*input);
		}
		return false;
	}
	const auto key = EVP_PKEY_new_raw_public_key(
		EVP_PKEY_ED25519,
		nullptr,
		credential.signingPublicKey.data(),
		credential.signingPublicKey.size());
	const auto context = EVP_MD_CTX_new();
	if (!key || !context) {
		EVP_MD_CTX_free(context);
		EVP_PKEY_free(key);
		Cleanse(*input);
		return false;
	}
	const auto result = EVP_DigestVerifyInit(
		context,
		nullptr,
		nullptr,
		nullptr,
		key) == 1
		&& EVP_DigestVerify(
			context,
			signature.data(),
			signature.size(),
			reinterpret_cast<const unsigned char*>(input->constData()),
			input->size()) == 1;
	EVP_MD_CTX_free(context);
	EVP_PKEY_free(key);
	Cleanse(*input);
	return result;
}

} // namespace E2ECloud
