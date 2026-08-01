/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "e2e_cloud/mls/mls_roster_codec.h"

#include <algorithm>
#include <array>
#include <set>

namespace E2ECloud {
namespace {

inline constexpr auto kMagic = std::array<std::uint8_t, 8>{
	'T', 'D', 'E', '2', 'E', 'R', 'O', 'S',
};
inline constexpr auto kMaximumRosterSize = 16 * 1024 * 1024;
inline constexpr auto kMaximumIdentitySize = 16 * 1024;
inline constexpr auto kMlsPublicKeySize = 32;

struct Reader {
	const QByteArray &bytes;
	int offset = 0;
};

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

[[nodiscard]] bool ReadBytes32(
		Reader &reader,
		int maximumSize,
		QByteArray &value) {
	auto size = std::uint32_t();
	if (!ReadUint32(reader, size)
		|| size > std::uint32_t(maximumSize)
		|| reader.bytes.size() - reader.offset < int(size)) {
		return false;
	}
	value = QByteArray(reader.bytes.constData() + reader.offset, int(size));
	reader.offset += int(size);
	return true;
}

[[nodiscard]] bool ReadBytes16(
		Reader &reader,
		int maximumSize,
		QByteArray &value) {
	auto size = std::uint16_t();
	if (!ReadUint16(reader, size)
		|| size > maximumSize
		|| reader.bytes.size() - reader.offset < int(size)) {
		return false;
	}
	value = QByteArray(reader.bytes.constData() + reader.offset, int(size));
	reader.offset += int(size);
	return true;
}

} // namespace

std::optional<MlsRoster> MlsRosterCodecV1::decode(
		const QByteArray &bytes,
		const MlsContextCodecV1 &contextCodec) const {
	if (bytes.size() < 8 + 2 + 32 + 8 + 4
		|| bytes.size() > kMaximumRosterSize) {
		return std::nullopt;
	}
	auto reader = Reader{ bytes };
	auto magic = std::array<std::uint8_t, 8>();
	auto version = std::uint16_t();
	auto count = std::uint32_t();
	auto result = MlsRoster();
	if (!ReadArray(reader, magic)
		|| !ReadUint16(reader, version)
		|| !ReadArray(reader, result.conversationId.bytes)
		|| !ReadUint64(reader, result.epoch)
		|| !ReadUint32(reader, count)
		|| magic != kMagic
		|| version != 1
		|| !result.conversationId
		|| !count
		|| count > kMaximumMlsRosterMembers) {
		return std::nullopt;
	}
	result.members.reserve(count);
	auto leafIndices = std::set<std::uint32_t>();
	auto clients = std::set<ClientId>();
	for (auto index = std::uint32_t(); index != count; ++index) {
		auto identity = QByteArray();
		auto member = MlsRosterMember();
		if (!ReadUint32(reader, member.leafIndex)
			|| !ReadBytes32(reader, kMaximumIdentitySize, identity)
			|| !ReadBytes16(
				reader,
				kMlsPublicKeySize,
				member.signatureKey)
			|| !ReadBytes16(
				reader,
				kMlsPublicKeySize,
				member.encryptionKey)
			|| member.signatureKey.size() != kMlsPublicKeySize
			|| member.encryptionKey.size() != kMlsPublicKeySize
			|| !leafIndices.emplace(member.leafIndex).second) {
			return std::nullopt;
		}
		const auto credential = contextCodec.decodeCredential(identity);
		if (!credential
			|| credential->conversationId != result.conversationId
			|| !clients.emplace(credential->clientId).second) {
			return std::nullopt;
		}
		member.credential = *credential;
		result.members.push_back(std::move(member));
	}
	return reader.offset == bytes.size()
		? std::optional<MlsRoster>(std::move(result))
		: std::nullopt;
}

bool MlsRosterMatchesGroupState(
		const MlsRoster &roster,
		const ProtectedGroupState &state) {
	if (roster.conversationId != state.conversationId()) {
		return false;
	}
	auto expected = std::set<std::pair<AccountId, ClientId>>();
	for (const auto &member : state.members()) {
		for (const auto &clientId : member.clients) {
			expected.emplace(member.accountId, clientId);
		}
	}
	if (expected.size() != roster.members.size()) {
		return false;
	}
	for (const auto &member : roster.members) {
		if (!expected.erase({
				member.credential.accountId,
				member.credential.clientId })) {
			return false;
		}
	}
	return expected.empty();
}

} // namespace E2ECloud
