/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#pragma once

#include "e2e_cloud/storage/local_storage.h"

#include <array>
#include <cstdint>

namespace E2ECloud {

using LocalRecordKey = std::array<std::uint8_t, 32>;

class AesGcmLocalRecordProtector final : public LocalRecordProtector {
public:
	explicit AesGcmLocalRecordProtector(LocalRecordKey &&key);
	~AesGcmLocalRecordProtector();

	AesGcmLocalRecordProtector(const AesGcmLocalRecordProtector&) = delete;
	AesGcmLocalRecordProtector &operator=(
		const AesGcmLocalRecordProtector&) = delete;

	[[nodiscard]] std::optional<QByteArray> seal(
		const QByteArray &purpose,
		const QByteArray &plaintext) const override;
	[[nodiscard]] std::optional<QByteArray> open(
		const QByteArray &purpose,
		const QByteArray &ciphertext) const override;

private:
	LocalRecordKey _key;
	bool _valid = false;

};

} // namespace E2ECloud
