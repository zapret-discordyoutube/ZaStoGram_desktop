/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#pragma once

#include "e2e_cloud/group/group_state.h"
#include "e2e_cloud/mls/mls_context_codec.h"

#include <QtCore/QByteArray>

#include <cstdint>
#include <optional>
#include <vector>

namespace E2ECloud {

inline constexpr auto kMaximumMlsRosterMembers = 4096;

struct MlsRosterMember {
	std::uint32_t leafIndex = 0;
	MlsClientCredential credential;
	QByteArray signatureKey;
	QByteArray encryptionKey;

	friend inline bool operator==(
		const MlsRosterMember &,
		const MlsRosterMember &) = default;
};

struct MlsRoster {
	ConversationId conversationId;
	std::uint64_t epoch = 0;
	std::vector<MlsRosterMember> members;

	friend inline bool operator==(
		const MlsRoster &,
		const MlsRoster &) = default;
};

class MlsRosterCodecV1 final {
public:
	[[nodiscard]] std::optional<MlsRoster> decode(
		const QByteArray &bytes,
		const MlsContextCodecV1 &contextCodec) const;
};

[[nodiscard]] bool MlsRosterMatchesGroupState(
	const MlsRoster &roster,
	const ProtectedGroupState &state);

} // namespace E2ECloud
