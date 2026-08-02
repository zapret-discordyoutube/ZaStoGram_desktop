/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#pragma once

#include "e2e_cloud/core/types.h"

#include <QtCore/QByteArray>

#include <cstdint>
#include <optional>

namespace E2ECloud {

inline constexpr auto kMaximumProtectedMessageTextSize = 256 * 1024;

enum class ProtectedMessageAction : std::uint8_t {
	Create = 0,
	Edit = 1,
	Delete = 2,
};

struct ProtectedMessageBody {
	ProtectedMessageAction action = ProtectedMessageAction::Create;
	std::uint64_t unixTime = 0;
	ObjectId targetEventObjectId;
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
