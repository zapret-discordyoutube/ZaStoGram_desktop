/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "e2e_cloud/vault/argon2id_password_kdf.h"

#include <argon2.h>
#include <openssl/crypto.h>

namespace E2ECloud {

std::optional<PasswordDerivedKey> Argon2idPasswordKdf::deriveArgon2id(
		const QByteArray &password,
		const Argon2idParameters &parameters) const {
	if (password.isEmpty() || !IsValidArgon2idParameters(parameters)) {
		return std::nullopt;
	}
	auto result = PasswordDerivedKey();
	const auto status = argon2id_hash_raw(
		parameters.iterations,
		parameters.memoryKibibytes,
		parameters.parallelism,
		password.constData(),
		password.size(),
		parameters.salt.data(),
		parameters.salt.size(),
		result.data(),
		result.size());
	if (status != ARGON2_OK) {
		OPENSSL_cleanse(result.data(), result.size());
		return std::nullopt;
	}
	return result;
}

} // namespace E2ECloud
