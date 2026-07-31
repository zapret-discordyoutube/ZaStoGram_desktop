/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#pragma once

#include "e2e_cloud/group/group_state.h"

#include <QtCore/QByteArray>

#include <optional>

namespace E2ECloud {

inline constexpr auto kGroupTransitionEncodedSize = 185;

[[nodiscard]] bool IsValidGroupTransitionStructure(
	const GroupTransition &transition);

class GroupTransitionCodecV1 final {
public:
	[[nodiscard]] std::optional<QByteArray> encode(
		const GroupTransition &transition) const;
	[[nodiscard]] std::optional<GroupTransition> decode(
		const QByteArray &bytes) const;

};

} // namespace E2ECloud
