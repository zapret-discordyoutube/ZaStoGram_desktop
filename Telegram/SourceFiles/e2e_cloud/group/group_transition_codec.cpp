/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "e2e_cloud/group/group_transition_codec.h"

#include <algorithm>
#include <array>
#include <cstdint>
#include <limits>

namespace E2ECloud {
namespace {

inline constexpr auto kGroupTransitionMagic = std::array<std::uint8_t, 8>{
	'T', 'D', 'E', '2', 'E', 'G', 'S', 'T',
};

struct Reader {
	const QByteArray &bytes;
	int offset = 0;
};

void AppendUint8(QByteArray &result, std::uint8_t value) {
	result.append(char(value));
}

void AppendUint16(QByteArray &result, std::uint16_t value) {
	result.append(char(value >> 8));
	result.append(char(value));
}

void AppendUint32(QByteArray &result, std::uint32_t value) {
	result.append(char(value >> 24));
	result.append(char(value >> 16));
	result.append(char(value >> 8));
	result.append(char(value));
}

void AppendUint64(QByteArray &result, std::uint64_t value) {
	for (auto shift = 56; shift >= 0; shift -= 8) {
		result.append(char(value >> shift));
	}
}

template <typename Array>
void AppendArray(QByteArray &result, const Array &value) {
	result.append(
		reinterpret_cast<const char*>(value.data()),
		int(value.size()));
}

[[nodiscard]] bool ReadUint8(Reader &reader, std::uint8_t &value) {
	if (reader.offset == reader.bytes.size()) {
		return false;
	}
	value = std::uint8_t(reader.bytes[reader.offset++]);
	return true;
}

[[nodiscard]] bool ReadUint16(Reader &reader, std::uint16_t &value) {
	if (reader.bytes.size() - reader.offset < 2) {
		return false;
	}
	const auto data = reinterpret_cast<const std::uint8_t*>(
		reader.bytes.constData() + reader.offset);
	value = (std::uint16_t(data[0]) << 8) | std::uint16_t(data[1]);
	reader.offset += 2;
	return true;
}

[[nodiscard]] bool ReadUint32(Reader &reader, std::uint32_t &value) {
	if (reader.bytes.size() - reader.offset < 4) {
		return false;
	}
	const auto data = reinterpret_cast<const std::uint8_t*>(
		reader.bytes.constData() + reader.offset);
	value = (std::uint32_t(data[0]) << 24)
		| (std::uint32_t(data[1]) << 16)
		| (std::uint32_t(data[2]) << 8)
		| std::uint32_t(data[3]);
	reader.offset += 4;
	return true;
}

[[nodiscard]] bool ReadUint64(Reader &reader, std::uint64_t &value) {
	if (reader.bytes.size() - reader.offset < 8) {
		return false;
	}
	const auto data = reinterpret_cast<const std::uint8_t*>(
		reader.bytes.constData() + reader.offset);
	value = 0;
	for (auto i = 0; i != 8; ++i) {
		value = (value << 8) | std::uint64_t(data[i]);
	}
	reader.offset += 8;
	return true;
}

template <typename Array>
[[nodiscard]] bool ReadArray(Reader &reader, Array &value) {
	const auto size = int(value.size());
	if (reader.bytes.size() - reader.offset < size) {
		return false;
	}
	std::copy_n(
		reinterpret_cast<const std::uint8_t*>(
			reader.bytes.constData() + reader.offset),
		size,
		value.data());
	reader.offset += size;
	return true;
}

[[nodiscard]] bool IsKnownTransitionKind(GroupTransitionKind kind) {
	switch (kind) {
	case GroupTransitionKind::AddMember:
	case GroupTransitionKind::RemoveMember:
	case GroupTransitionKind::AddClient:
	case GroupTransitionKind::RemoveClient:
	case GroupTransitionKind::SetRole:
	case GroupTransitionKind::TransferOwnership:
	case GroupTransitionKind::SetDefaultHistory:
	case GroupTransitionKind::SetMemberHistory:
		return true;
	}
	return false;
}

[[nodiscard]] bool DefaultHistoryField(const HistoryAccess &access) {
	return access == HistoryAccess{
		.mode = HistoryAccessMode::FromJoin,
		.boundaryEventId = {},
	};
}

[[nodiscard]] bool DefaultRoleFields(const GroupTransition &transition) {
	return transition.targetRole == GroupRole::Member
		&& !transition.targetAdminPermissions;
}

[[nodiscard]] bool EmptyClientFields(const GroupTransition &transition) {
	return !transition.targetClientId
		&& !transition.targetTelegramUserIdBinding;
}

} // namespace

bool IsValidGroupTransitionStructure(const GroupTransition &transition) {
	if (!transition.conversationId
		|| !transition.transitionId
		|| !IsKnownTransitionKind(transition.kind)
		|| transition.previousGeneration
			== std::numeric_limits<std::uint64_t>::max()
		|| transition.generation != transition.previousGeneration + 1) {
		return false;
	}
	switch (transition.kind) {
	case GroupTransitionKind::AddMember:
		return transition.targetAccountId
			&& transition.targetClientId
			&& transition.targetTelegramUserIdBinding
			&& DefaultRoleFields(transition)
			&& IsValidHistoryAccess(transition.historyAccess);
	case GroupTransitionKind::RemoveMember:
	case GroupTransitionKind::TransferOwnership:
		return transition.targetAccountId
			&& EmptyClientFields(transition)
			&& DefaultRoleFields(transition)
			&& DefaultHistoryField(transition.historyAccess);
	case GroupTransitionKind::AddClient:
	case GroupTransitionKind::RemoveClient:
		return transition.targetAccountId
			&& transition.targetClientId
			&& !transition.targetTelegramUserIdBinding
			&& DefaultRoleFields(transition)
			&& DefaultHistoryField(transition.historyAccess);
	case GroupTransitionKind::SetRole:
		return transition.targetAccountId
			&& EmptyClientFields(transition)
			&& (transition.targetRole == GroupRole::Member
				|| transition.targetRole == GroupRole::Administrator)
			&& !(transition.targetAdminPermissions & ~kAllAdminPermissions)
			&& (transition.targetRole == GroupRole::Administrator
				|| !transition.targetAdminPermissions)
			&& DefaultHistoryField(transition.historyAccess);
	case GroupTransitionKind::SetDefaultHistory:
		return !transition.targetAccountId
			&& EmptyClientFields(transition)
			&& DefaultRoleFields(transition)
			&& IsValidHistoryAccess(transition.historyAccess);
	case GroupTransitionKind::SetMemberHistory:
		return transition.targetAccountId
			&& EmptyClientFields(transition)
			&& DefaultRoleFields(transition)
			&& IsValidHistoryAccess(transition.historyAccess);
	}
	return false;
}

std::optional<QByteArray> GroupTransitionCodecV1::encode(
		const GroupTransition &transition) const {
	if (!IsValidGroupTransitionStructure(transition)) {
		return std::nullopt;
	}
	auto result = QByteArray();
	result.reserve(kGroupTransitionEncodedSize);
	AppendArray(result, kGroupTransitionMagic);
	AppendUint16(result, 1);
	AppendArray(result, transition.conversationId.bytes);
	AppendArray(result, transition.transitionId.bytes);
	AppendUint64(result, transition.previousGeneration);
	AppendUint64(result, transition.generation);
	AppendUint8(result, std::uint8_t(transition.kind));
	AppendArray(result, transition.targetAccountId.bytes);
	AppendArray(result, transition.targetClientId.bytes);
	AppendUint64(result, transition.targetTelegramUserIdBinding);
	AppendUint8(result, std::uint8_t(transition.targetRole));
	AppendUint32(result, transition.targetAdminPermissions);
	AppendUint8(result, std::uint8_t(transition.historyAccess.mode));
	AppendArray(result, transition.historyAccess.boundaryEventId.bytes);
	return result;
}

std::optional<GroupTransition> GroupTransitionCodecV1::decode(
		const QByteArray &bytes) const {
	if (bytes.size() != kGroupTransitionEncodedSize) {
		return std::nullopt;
	}
	auto reader = Reader{ bytes };
	auto magic = std::array<std::uint8_t, 8>();
	auto version = std::uint16_t();
	auto kind = std::uint8_t();
	auto role = std::uint8_t();
	auto historyMode = std::uint8_t();
	auto result = GroupTransition();
	if (!ReadArray(reader, magic)
		|| !ReadUint16(reader, version)
		|| !ReadArray(reader, result.conversationId.bytes)
		|| !ReadArray(reader, result.transitionId.bytes)
		|| !ReadUint64(reader, result.previousGeneration)
		|| !ReadUint64(reader, result.generation)
		|| !ReadUint8(reader, kind)
		|| !ReadArray(reader, result.targetAccountId.bytes)
		|| !ReadArray(reader, result.targetClientId.bytes)
		|| !ReadUint64(reader, result.targetTelegramUserIdBinding)
		|| !ReadUint8(reader, role)
		|| !ReadUint32(reader, result.targetAdminPermissions)
		|| !ReadUint8(reader, historyMode)
		|| !ReadArray(reader, result.historyAccess.boundaryEventId.bytes)
		|| reader.offset != bytes.size()
		|| magic != kGroupTransitionMagic
		|| version != 1) {
		return std::nullopt;
	}
	result.kind = GroupTransitionKind(kind);
	result.targetRole = GroupRole(role);
	result.historyAccess.mode = HistoryAccessMode(historyMode);
	return IsValidGroupTransitionStructure(result)
		? std::optional<GroupTransition>(result)
		: std::nullopt;
}

} // namespace E2ECloud
