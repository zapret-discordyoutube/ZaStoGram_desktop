/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "e2e_cloud/group/group_state_codec.h"

#include <algorithm>
#include <array>
#include <cstdint>

namespace E2ECloud {
namespace {

inline constexpr auto kMagic = std::array<std::uint8_t, 8>{
	'T', 'D', 'E', '2', 'E', 'G', 'S', 'T',
};
inline constexpr auto kMaximumMembers = 4096;
inline constexpr auto kMaximumClientsPerMember = 256;
inline constexpr auto kMaximumTransitions = 65'536;
inline constexpr auto kMaximumEncodedSize = 16 * 1024 * 1024;

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

void AppendHistory(QByteArray &result, const HistoryAccess &access) {
	AppendUint8(result, std::uint8_t(access.mode));
	AppendArray(result, access.boundaryEventId.bytes);
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

[[nodiscard]] bool ReadHistory(Reader &reader, HistoryAccess &access) {
	auto mode = std::uint8_t();
	if (!ReadUint8(reader, mode)
		|| !ReadArray(reader, access.boundaryEventId.bytes)) {
		return false;
	}
	access.mode = HistoryAccessMode(mode);
	return IsValidHistoryAccess(access);
}

} // namespace

std::optional<QByteArray> ProtectedGroupStateCodecV1::encode(
		const ProtectedGroupState &state) const {
	const auto snapshot = state.snapshot();
	if (!ProtectedGroupState::Restore(snapshot)
		|| snapshot.members.size() > kMaximumMembers
		|| snapshot.appliedTransitionIds.size() > kMaximumTransitions) {
		return std::nullopt;
	}
	auto result = QByteArray();
	result.reserve(1024);
	AppendArray(result, kMagic);
	AppendUint16(result, 1);
	AppendArray(result, snapshot.conversationId.bytes);
	AppendUint64(result, snapshot.generation);
	AppendArray(result, snapshot.lastTransitionId.bytes);
	AppendHistory(result, snapshot.policy.defaultHistoryAccess);
	AppendUint32(result, std::uint32_t(snapshot.members.size()));
	for (const auto &member : snapshot.members) {
		if (member.clients.size() > kMaximumClientsPerMember) {
			return std::nullopt;
		}
		AppendArray(result, member.accountId.bytes);
		AppendUint64(result, member.telegramUserIdBinding);
		AppendUint8(result, std::uint8_t(member.role));
		AppendUint32(result, member.adminPermissions);
		AppendHistory(result, member.historyAccess);
		AppendUint64(result, member.joinedGeneration);
		AppendUint32(result, std::uint32_t(member.clients.size()));
		for (const auto &clientId : member.clients) {
			AppendArray(result, clientId.bytes);
		}
	}
	AppendUint32(
		result,
		std::uint32_t(snapshot.appliedTransitionIds.size()));
	for (const auto &transitionId : snapshot.appliedTransitionIds) {
		AppendArray(result, transitionId.bytes);
	}
	return (result.size() <= kMaximumEncodedSize)
		? std::optional<QByteArray>(std::move(result))
		: std::nullopt;
}

std::optional<ProtectedGroupState> ProtectedGroupStateCodecV1::decode(
		const QByteArray &bytes) const {
	if (bytes.size() < 8 + 2 + 32 + 8 + 32 + 33 + 4 + 4
		|| bytes.size() > kMaximumEncodedSize) {
		return std::nullopt;
	}
	auto reader = Reader{ bytes };
	auto magic = std::array<std::uint8_t, 8>();
	auto version = std::uint16_t();
	auto memberCount = std::uint32_t();
	auto snapshot = ProtectedGroupStateSnapshot();
	if (!ReadArray(reader, magic)
		|| !ReadUint16(reader, version)
		|| !ReadArray(reader, snapshot.conversationId.bytes)
		|| !ReadUint64(reader, snapshot.generation)
		|| !ReadArray(reader, snapshot.lastTransitionId.bytes)
		|| !ReadHistory(reader, snapshot.policy.defaultHistoryAccess)
		|| !ReadUint32(reader, memberCount)
		|| magic != kMagic
		|| version != 1
		|| !memberCount
		|| memberCount > kMaximumMembers) {
		return std::nullopt;
	}
	snapshot.members.reserve(memberCount);
	for (auto index = std::uint32_t(); index != memberCount; ++index) {
		auto member = GroupMember();
		auto role = std::uint8_t();
		auto clientCount = std::uint32_t();
		if (!ReadArray(reader, member.accountId.bytes)
			|| !ReadUint64(reader, member.telegramUserIdBinding)
			|| !ReadUint8(reader, role)
			|| !ReadUint32(reader, member.adminPermissions)
			|| !ReadHistory(reader, member.historyAccess)
			|| !ReadUint64(reader, member.joinedGeneration)
			|| !ReadUint32(reader, clientCount)
			|| !clientCount
			|| clientCount > kMaximumClientsPerMember) {
			return std::nullopt;
		}
		member.role = GroupRole(role);
		member.clients.reserve(clientCount);
		for (auto client = std::uint32_t(); client != clientCount; ++client) {
			auto clientId = ClientId();
			if (!ReadArray(reader, clientId.bytes)) {
				return std::nullopt;
			}
			member.clients.push_back(clientId);
		}
		snapshot.members.push_back(std::move(member));
	}
	auto transitionCount = std::uint32_t();
	if (!ReadUint32(reader, transitionCount)
		|| transitionCount > kMaximumTransitions) {
		return std::nullopt;
	}
	snapshot.appliedTransitionIds.reserve(transitionCount);
	for (auto index = std::uint32_t(); index != transitionCount; ++index) {
		auto transitionId = ObjectId();
		if (!ReadArray(reader, transitionId.bytes)) {
			return std::nullopt;
		}
		snapshot.appliedTransitionIds.push_back(transitionId);
	}
	return (reader.offset == bytes.size())
		? ProtectedGroupState::Restore(std::move(snapshot))
		: std::nullopt;
}

} // namespace E2ECloud
