/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>

namespace E2ECloud {

template <std::size_t Size, typename Tag>
struct OpaqueId {
	std::array<std::uint8_t, Size> bytes = {};

	explicit operator bool() const {
		for (const auto byte : bytes) {
			if (byte) {
				return true;
			}
		}
		return false;
	}

	friend inline auto operator<=>(
		const OpaqueId &,
		const OpaqueId &) = default;
	friend inline bool operator==(
		const OpaqueId &,
		const OpaqueId &) = default;
};

struct AccountIdTag;
struct ChallengeNonceTag;
struct ClientIdTag;
struct ConversationIdTag;
struct DigestTag;
struct FileIdTag;
struct ObjectIdTag;

using AccountId = OpaqueId<32, AccountIdTag>;
using ChallengeNonce = OpaqueId<32, ChallengeNonceTag>;
using ClientId = OpaqueId<16, ClientIdTag>;
using ConversationId = OpaqueId<32, ConversationIdTag>;
using Digest = OpaqueId<32, DigestTag>;
using FileId = OpaqueId<32, FileIdTag>;
using ObjectId = OpaqueId<32, ObjectIdTag>;

struct Checkpoint {
	ConversationId conversationId;
	std::uint64_t generation = 0;
	Digest stateHash;

	friend inline bool operator==(
		const Checkpoint &,
		const Checkpoint &) = default;
};

enum class HistoryAccessMode : std::uint8_t {
	None,
	FromJoin,
	Since,
	Full,
};

struct HistoryAccess {
	HistoryAccessMode mode = HistoryAccessMode::FromJoin;
	ObjectId boundaryEventId;

	friend inline bool operator==(
		const HistoryAccess &,
		const HistoryAccess &) = default;
};

[[nodiscard]] bool IsValidHistoryAccess(const HistoryAccess &access);

} // namespace E2ECloud
