/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#pragma once

#include "e2e_cloud/core/types.h"

#include <QtCore/QByteArray>
#include <QtCore/QString>

#include <array>
#include <cstdint>
#include <optional>
#include <vector>

namespace E2ECloud {

inline constexpr auto kMlsCipherSuiteV1 = std::uint16_t(0x0001);
inline constexpr auto kAccountCredentialEncodedSize = 76;

struct AccountCredentialPublic {
	std::uint16_t version = 1;
	std::uint16_t mlsCipherSuite = kMlsCipherSuiteV1;
	std::array<std::uint8_t, 32> signingPublicKey = {};
	std::array<std::uint8_t, 32> archiveHpkePublicKey = {};

	friend inline bool operator==(
		const AccountCredentialPublic &,
		const AccountCredentialPublic &) = default;
};

class Sha256Provider {
public:
	virtual ~Sha256Provider() = default;

	[[nodiscard]] virtual Digest digest(const QByteArray &bytes) const = 0;

};

class AccountCredentialCodecV1 final {
public:
	[[nodiscard]] std::optional<QByteArray> encode(
		const AccountCredentialPublic &credential) const;
	[[nodiscard]] std::optional<AccountCredentialPublic> decode(
		const QByteArray &bytes) const;

};

[[nodiscard]] std::optional<AccountId> DeriveAccountId(
	const AccountCredentialPublic &credential,
	const Sha256Provider &sha256);
[[nodiscard]] std::optional<Digest> DerivePairwiseSafetyDigest(
	AccountId first,
	AccountId second,
	const Sha256Provider &sha256);
[[nodiscard]] std::optional<Digest> DeriveGroupSafetyDigest(
	ConversationId conversationId,
	AccountId ownerAccountId,
	std::vector<AccountId> memberAccountIds,
	const Sha256Provider &sha256);
[[nodiscard]] std::optional<QString> FormatSafetyCode(Digest digest);

} // namespace E2ECloud
