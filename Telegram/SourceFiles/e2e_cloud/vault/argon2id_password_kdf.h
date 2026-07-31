/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#pragma once

#include "e2e_cloud/vault/password_kdf.h"

namespace E2ECloud {

class Argon2idPasswordKdf final : public PasswordKdf {
public:
	[[nodiscard]] std::optional<PasswordDerivedKey> deriveArgon2id(
		const QByteArray &password,
		const Argon2idParameters &parameters) const override;
};

} // namespace E2ECloud
