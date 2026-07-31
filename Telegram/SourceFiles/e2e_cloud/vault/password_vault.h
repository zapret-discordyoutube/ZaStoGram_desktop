/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#pragma once

#include "e2e_cloud/vault/password_kdf.h"

#include <QtCore/QByteArray>

#include <array>
#include <cstdint>
#include <optional>

namespace E2ECloud {

using VaultMasterKey = std::array<std::uint8_t, 32>;

struct UnwrappedVaultKey {
	VaultMasterKey masterKey = {};
	std::uint64_t generation = 0;
	Argon2idParameters parameters;
};

class PasswordVault final {
public:
	explicit PasswordVault(const PasswordKdf &kdf);

	[[nodiscard]] std::optional<QByteArray> wrap(
		VaultMasterKey &&masterKey,
		QByteArray password,
		Argon2idConfig config,
		std::uint64_t generation) const;
	[[nodiscard]] std::optional<UnwrappedVaultKey> unwrap(
		const QByteArray &wrapped,
		QByteArray password) const;

private:
	const PasswordKdf &_kdf;

};

} // namespace E2ECloud
