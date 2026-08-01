/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "e2e_cloud/vault/password_kdf.h"

#include <algorithm>

namespace E2ECloud {
namespace {

inline constexpr auto kMaximumMemoryKibibytes = std::uint32_t(128 * 1024);
inline constexpr auto kMaximumIterations = std::uint32_t(4);
inline constexpr auto kMaximumParallelism = std::uint32_t(4);
inline constexpr auto kMaximumWorkKibibytes = std::uint64_t(256 * 1024);

} // namespace

bool IsValidArgon2idConfig(const Argon2idConfig &config) {
	return config.parameterVersion == 1
		&& config.parallelism >= 1
		&& config.parallelism <= kMaximumParallelism
		&& config.memoryKibibytes >= 8 * config.parallelism
		&& config.memoryKibibytes <= kMaximumMemoryKibibytes
		&& config.iterations >= 1
		&& config.iterations <= kMaximumIterations
		&& std::uint64_t(config.memoryKibibytes) * config.iterations
			<= kMaximumWorkKibibytes;
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
