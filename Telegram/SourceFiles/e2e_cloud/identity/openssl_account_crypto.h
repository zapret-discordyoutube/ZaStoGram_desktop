/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#pragma once

#include "e2e_cloud/identity/account_identity.h"

#include <QtCore/QByteArray>

#include <array>
#include <cstdint>
#include <optional>

namespace E2ECloud {

class SecureKey32 final {
public:
	SecureKey32();
	explicit SecureKey32(std::array<std::uint8_t, 32> &&bytes);
	SecureKey32(const SecureKey32 &) = delete;
	SecureKey32 &operator=(const SecureKey32 &) = delete;
	SecureKey32(SecureKey32 &&other) noexcept;
	SecureKey32 &operator=(SecureKey32 &&other) noexcept;
	~SecureKey32();

	[[nodiscard]] bool valid() const;
	[[nodiscard]] const std::array<std::uint8_t, 32> &bytes() const;

private:
	std::array<std::uint8_t, 32> _bytes = {};

};

struct AccountPrivateIdentity {
	SecureKey32 signingPrivateKey;
	SecureKey32 archiveHpkePrivateKey;
	AccountCredentialPublic credential;
};

enum class AccountSignatureDomain : std::uint16_t {
	GroupTransition = 1,
	ClientAuthorization = 2,
	SafetyGossip = 3,
	FreshnessResponse = 4,
	HistoryGrant = 5,
	VaultCheckpoint = 6,
};

using AccountSignature = std::array<std::uint8_t, 64>;

class OpenSslSha256Provider final : public Sha256Provider {
public:
	[[nodiscard]] Digest digest(const QByteArray &bytes) const override;
};

[[nodiscard]] std::optional<AccountPrivateIdentity>
	GenerateAccountPrivateIdentity();
[[nodiscard]] std::optional<AccountSignature> SignAccountData(
	const SecureKey32 &privateKey,
	AccountSignatureDomain domain,
	const QByteArray &data);
[[nodiscard]] bool VerifyAccountSignature(
	const AccountCredentialPublic &credential,
	AccountSignatureDomain domain,
	const QByteArray &data,
	const AccountSignature &signature);

} // namespace E2ECloud
