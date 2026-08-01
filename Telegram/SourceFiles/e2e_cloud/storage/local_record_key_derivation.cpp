/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "e2e_cloud/storage/local_record_key_derivation.h"

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>

#include <array>

namespace E2ECloud {
namespace {

inline constexpr auto kSalt = std::array<std::uint8_t, 32>{
	0x20, 0xc9, 0x85, 0x1f, 0xf2, 0x76, 0x6b, 0x42,
	0x89, 0x3c, 0x8a, 0xa9, 0x7f, 0x6d, 0x44, 0x8d,
	0x04, 0xe1, 0x91, 0x33, 0x79, 0x11, 0xa8, 0xbd,
	0xe0, 0xb8, 0xf2, 0x58, 0x77, 0xd3, 0xc0, 0x9e,
};

[[nodiscard]] QByteArray DerivationInfo(
		std::uint64_t telegramUserIdBinding,
		ConversationId conversationId) {
	auto result = QByteArray("TDE2E/local-record-key/conversation/v1");
	result.append(char(0));
	for (auto shift = 56; shift >= 0; shift -= 8) {
		result.append(char(telegramUserIdBinding >> shift));
	}
	result.append(
		reinterpret_cast<const char*>(conversationId.bytes.data()),
		int(conversationId.bytes.size()));
	return result;
}

} // namespace

std::optional<LocalRecordKey> DeriveConversationLocalRecordKey(
		const SecureKey32 &vaultMasterKey,
		std::uint64_t telegramUserIdBinding,
		ConversationId conversationId) {
	if (!vaultMasterKey.valid()
		|| !telegramUserIdBinding
		|| !conversationId) {
		return std::nullopt;
	}
	auto result = LocalRecordKey();
	const auto info = DerivationInfo(
		telegramUserIdBinding,
		conversationId);
	const auto context = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, nullptr);
	if (!context) {
		return std::nullopt;
	}
	auto size = result.size();
	const auto &masterKey = vaultMasterKey.bytes();
	const auto ok = EVP_PKEY_derive_init(context) > 0
		&& EVP_PKEY_CTX_set_hkdf_md(context, EVP_sha256()) > 0
		&& EVP_PKEY_CTX_set1_hkdf_salt(
			context,
			kSalt.data(),
			int(kSalt.size())) > 0
		&& EVP_PKEY_CTX_set1_hkdf_key(
			context,
			masterKey.data(),
			int(masterKey.size())) > 0
		&& EVP_PKEY_CTX_add1_hkdf_info(
			context,
			reinterpret_cast<const std::uint8_t*>(info.constData()),
			info.size()) > 0
		&& EVP_PKEY_derive(context, result.data(), &size) > 0
		&& size == result.size();
	EVP_PKEY_CTX_free(context);
	if (!ok) {
		OPENSSL_cleanse(result.data(), result.size());
		return std::nullopt;
	}
	return result;
}

} // namespace E2ECloud
