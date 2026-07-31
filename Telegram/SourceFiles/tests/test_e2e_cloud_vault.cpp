/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "e2e_cloud/vault/argon2id_password_kdf.h"
#include "e2e_cloud/vault/password_kdf.h"
#include "e2e_cloud/vault/password_vault.h"

#include <algorithm>
#include <cstdio>
#include <optional>

namespace {

using namespace E2ECloud;

[[nodiscard]] int Fail(const char *message) {
	std::fprintf(stderr, "%s\n", message);
	return 1;
}

[[nodiscard]] Argon2idConfig MakeConfig() {
	return {
		.parameterVersion = 1,
		.memoryKibibytes = 64 * 1024,
		.iterations = 3,
		.parallelism = 1,
	};
}

[[nodiscard]] VaultMasterKey MakeMasterKey() {
	auto result = VaultMasterKey();
	for (auto i = std::size_t(0); i != result.size(); ++i) {
		result[i] = std::uint8_t(i + 1);
	}
	return result;
}

class TestPasswordKdf final : public PasswordKdf {
public:
	[[nodiscard]] std::optional<PasswordDerivedKey> deriveArgon2id(
			const QByteArray &password,
			const Argon2idParameters &parameters) const override {
		++calls;
		lastParameters = parameters;
		if (fail || password.isEmpty()) {
			return std::nullopt;
		}
		auto result = PasswordDerivedKey();
		for (auto i = std::size_t(0); i != result.size(); ++i) {
			result[i] = std::uint8_t(parameters.salt[i % 16]
				+ std::uint8_t(password.constData()[i % password.size()])
				+ i);
		}
		return result;
	}

	mutable int calls = 0;
	mutable Argon2idParameters lastParameters;
	bool fail = false;

};

[[nodiscard]] int ScenarioVaultRoundTrip() {
	auto kdf = TestPasswordKdf();
	const auto vault = PasswordVault(kdf);
	const auto expected = MakeMasterKey();
	auto input = expected;
	const auto wrapped = vault.wrap(
		std::move(input),
		QByteArray("correct horse battery staple"),
		MakeConfig(),
		9);
	if (!wrapped
		|| wrapped->size() != 114
		|| input != VaultMasterKey()
		|| kdf.calls != 1) {
		return Fail("vault key was not wrapped with a consumed master key");
	}
	const auto opened = vault.unwrap(
		*wrapped,
		QByteArray("correct horse battery staple"));
	if (!opened
		|| opened->masterKey != expected
		|| opened->generation != 9
		|| opened->parameters != kdf.lastParameters
		|| opened->parameters.memoryKibibytes
			!= MakeConfig().memoryKibibytes
		|| opened->parameters.iterations != MakeConfig().iterations
		|| opened->parameters.parallelism != MakeConfig().parallelism) {
		return Fail("vault key did not survive an authenticated round trip");
	}
	return 0;
}

[[nodiscard]] int ScenarioVaultRejectsWrongPasswordAndTampering() {
	auto kdf = TestPasswordKdf();
	const auto vault = PasswordVault(kdf);
	auto key = MakeMasterKey();
	const auto wrapped = vault.wrap(
		std::move(key),
		QByteArray("password one"),
		MakeConfig(),
		4);
	if (!wrapped
		|| vault.unwrap(*wrapped, QByteArray("password two"))) {
		return Fail("vault accepted the wrong password");
	}
	for (const auto offset : { 0, 14, 42, 54, 66, 113 }) {
		auto tampered = *wrapped;
		tampered[offset] = char(std::uint8_t(tampered[offset]) ^ 1);
		if (vault.unwrap(tampered, QByteArray("password one"))) {
			return Fail("vault accepted tampered parameters or ciphertext");
		}
	}
	return 0;
}

[[nodiscard]] int ScenarioVaultUsesFreshNonce() {
	auto kdf = TestPasswordKdf();
	const auto vault = PasswordVault(kdf);
	auto firstKey = MakeMasterKey();
	auto secondKey = MakeMasterKey();
	const auto first = vault.wrap(
		std::move(firstKey),
		QByteArray("same password"),
		MakeConfig(),
		1);
	const auto second = vault.wrap(
		std::move(secondKey),
		QByteArray("same password"),
		MakeConfig(),
		1);
	const auto firstOpened = first
		? vault.unwrap(*first, QByteArray("same password"))
		: std::nullopt;
	const auto secondOpened = second
		? vault.unwrap(*second, QByteArray("same password"))
		: std::nullopt;
	if (!first
		|| !second
		|| first == second
		|| !firstOpened
		|| !secondOpened
		|| firstOpened->parameters.salt == secondOpened->parameters.salt) {
		return Fail("vault wrapping reused deterministic ciphertext");
	}
	return 0;
}

[[nodiscard]] int ScenarioVaultBoundsKdfBeforeDerivation() {
	auto kdf = TestPasswordKdf();
	const auto vault = PasswordVault(kdf);
	auto key = MakeMasterKey();
	auto config = MakeConfig();
	config.memoryKibibytes = 32 * 1024;
	if (vault.wrap(
			std::move(key),
			QByteArray("password"),
			config,
			1)
		|| kdf.calls) {
		return Fail("vault created a record with weak password work factors");
	}
	return 0;
}

[[nodiscard]] int ScenarioArgon2idReferenceVector() {
	auto parameters = Argon2idParameters{
		.parameterVersion = 1,
		.memoryKibibytes = 256,
		.iterations = 2,
		.parallelism = 1,
		.salt = {},
	};
	const auto salt = QByteArray("somesalt12345678");
	std::copy_n(
		reinterpret_cast<const std::uint8_t*>(salt.constData()),
		parameters.salt.size(),
		parameters.salt.begin());
	const auto result = Argon2idPasswordKdf().deriveArgon2id(
		QByteArray("password"),
		parameters);
	const auto expected = PasswordDerivedKey{
		0x81, 0x10, 0xe1, 0x16, 0x5e, 0xb0, 0xe1, 0x11,
		0x4e, 0xe3, 0x7d, 0x5f, 0xf0, 0x17, 0x57, 0x3b,
		0xa0, 0x08, 0x4b, 0x83, 0x66, 0xb4, 0x10, 0x8d,
		0xb4, 0x47, 0x49, 0x95, 0x4b, 0x8d, 0x98, 0x71,
	};
	if (!result || *result != expected) {
		return Fail("Argon2id provider did not match the reference vector");
	}
	return 0;
}

} // namespace

int main(int, char *[]) {
	for (const auto scenario : {
		ScenarioVaultRoundTrip,
		ScenarioVaultRejectsWrongPasswordAndTampering,
		ScenarioVaultUsesFreshNonce,
		ScenarioVaultBoundsKdfBeforeDerivation,
		ScenarioArgon2idReferenceVector,
	}) {
		if (const auto result = scenario()) {
			return result;
		}
	}
	return 0;
}
