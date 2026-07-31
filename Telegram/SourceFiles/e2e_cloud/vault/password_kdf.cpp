/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "e2e_cloud/vault/password_kdf.h"

#include <algorithm>

namespace E2ECloud {

bool IsValidArgon2idConfig(const Argon2idConfig &config) {
	return config.parameterVersion == 1
		&& config.parallelism >= 1
		&& config.parallelism <= 16
		&& config.memoryKibibytes >= 8 * config.parallelism
		&& config.memoryKibibytes <= 1024 * 1024
		&& config.iterations >= 1
		&& config.iterations <= 64;
}

bool IsValidArgon2idParameters(const Argon2idParameters &parameters) {
	return IsValidArgon2idConfig({
			.parameterVersion = parameters.parameterVersion,
			.memoryKibibytes = parameters.memoryKibibytes,
			.iterations = parameters.iterations,
			.parallelism = parameters.parallelism,
		})
		&& std::any_of(
			begin(parameters.salt),
			end(parameters.salt),
			[](std::uint8_t byte) { return byte != 0; });
}

bool IsSecureArgon2idConfigForNewVault(const Argon2idConfig &config) {
	return IsValidArgon2idConfig(config)
		&& config.memoryKibibytes >= 64 * 1024
		&& config.iterations >= 3;
}

} // namespace E2ECloud
