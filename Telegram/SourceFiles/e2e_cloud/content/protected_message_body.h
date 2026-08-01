/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#pragma once

#include <QtCore/QByteArray>

#include <cstdint>
#include <optional>

namespace E2ECloud {

inline constexpr auto kMaximumProtectedMessageTextSize = 256 * 1024;

struct ProtectedMessageBody {
	std::uint64_t unixTime = 0;
	QByteArray textUtf8;

	friend inline bool operator==(
		const ProtectedMessageBody &,
		const ProtectedMessageBody &) = default;
};

class ProtectedMessageBodyCodecV1 final {
public:
	[[nodiscard]] std::optional<QByteArray> encodePlaintext(
		const ProtectedMessageBody &body) const;
	[[nodiscard]] std::optional<ProtectedMessageBody> decodePlaintext(
		const QByteArray &bytes) const;
};

} // namespace E2ECloud
