/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#pragma once

#include "base/bytes.h"

#include <cstddef>

namespace openssl {
class BigNum;
} // namespace openssl

namespace MTP {

class SecureBytes final {
public:
	SecureBytes() = default;
	explicit SecureBytes(std::size_t size);
	explicit SecureBytes(bytes::vector &&data);
	SecureBytes(SecureBytes &&other) noexcept;
	SecureBytes &operator=(SecureBytes &&other) noexcept;
	SecureBytes(const SecureBytes &other) = delete;
	SecureBytes &operator=(const SecureBytes &other) = delete;
	~SecureBytes();

	[[nodiscard]] bool empty() const;
	[[nodiscard]] std::size_t size() const;
	[[nodiscard]] bytes::type *data();
	[[nodiscard]] const bytes::type *data() const;
	[[nodiscard]] bytes::span bytes();
	[[nodiscard]] bytes::const_span bytes() const;
	void resize(std::size_t size);
	void clear();
	[[nodiscard]] bytes::type &operator[](std::size_t index);
	[[nodiscard]] const bytes::type &operator[](std::size_t index) const;

private:
	bytes::vector _data;

};

struct ModExpFirst {
	static constexpr auto kRandomPowerSize = 256;

	bytes::vector modexp;
	SecureBytes randomPower;
};

[[nodiscard]] bool IsPrimeAndGood(bytes::const_span primeBytes, int g);
[[nodiscard]] bool IsGoodModExpFirst(
	const openssl::BigNum &modexp,
	const openssl::BigNum &prime);
[[nodiscard]] ModExpFirst CreateModExp(
	int g,
	bytes::const_span primeBytes,
	bytes::const_span randomSeed);
[[nodiscard]] SecureBytes CreateAuthKey(
	bytes::const_span firstBytes,
	bytes::const_span randomBytes,
	bytes::const_span primeBytes);

} // namespace MTP
