/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#pragma once

#include <QtCore/QByteArray>

#include <array>
#include <cstdint>
#include <optional>

namespace E2ECloud {

struct Argon2idConfig {
	std::uint16_t parameterVersion = 1;
	std::uint32_t memoryKibibytes = 0;
	std::uint32_t iterations = 0;
	std::uint32_t parallelism = 0;

	friend inline bool operator==(
		const Argon2idConfig &,
		const Argon2idConfig &) = default;
};

struct Argon2idParameters {
	std::uint16_t parameterVersion = 1;
	std::uint32_t memoryKibibytes = 0;
	std::uint32_t iterations = 0;
	std::uint32_t parallelism = 0;
	std::array<std::uint8_t, 16> salt = {};

	friend inline bool operator==(
		const Argon2idParameters &,
		const Argon2idParameters &) = default;
};

using PasswordDerivedKey = std::array<std::uint8_t, 32>;

class PasswordKdf {
public:
	virtual ~PasswordKdf() = default;

	[[nodiscard]] virtual std::optional<PasswordDerivedKey> deriveArgon2id(
		const QByteArray &password,
		const Argon2idParameters &parameters) const = 0;

};

[[nodiscard]] bool IsValidArgon2idParameters(
	const Argon2idParameters &parameters);
[[nodiscard]] bool IsValidArgon2idConfig(const Argon2idConfig &config);

} // namespace E2ECloud
