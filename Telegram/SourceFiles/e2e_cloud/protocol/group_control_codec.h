/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#pragma once

#include "e2e_cloud/group/signed_group_transition.h"

#include <QtCore/QByteArray>

#include <cstdint>
#include <optional>

namespace E2ECloud {

inline constexpr auto kGroupChangePreludeEncodedSize = 646;
inline constexpr auto kArchiveEpochDistributionEncodedSize = 154;

struct GroupChangePrelude {
	GroupTransition transition;
	AccountId actorAccountId;
	ClientId actorClientId;
	Digest previousStateHash;
	ObjectId mlsCommitObjectId;
	ObjectId archiveDistributionObjectId;
	Digest archiveKeyCommitment;
	std::optional<ClientAuthorizationProof> targetClientAuthorization;

	friend inline bool operator==(
		const GroupChangePrelude &,
		const GroupChangePrelude &) = default;
};

struct ArchiveEpochDistribution {
	ConversationId conversationId;
	ObjectId transitionId;
	std::uint64_t groupGeneration = 0;
	std::uint64_t archiveEpochGeneration = 0;
	ObjectId activationEventId;
	ArchiveKey32 key;
};

class GroupControlCodecV1 final {
public:
	[[nodiscard]] std::optional<QByteArray> encodePrelude(
		const GroupChangePrelude &prelude) const;
	[[nodiscard]] std::optional<GroupChangePrelude> decodePrelude(
		const QByteArray &bytes) const;
	[[nodiscard]] std::optional<QByteArray> encodeArchiveDistribution(
		const ArchiveEpochDistribution &distribution) const;
	[[nodiscard]] std::optional<ArchiveEpochDistribution>
		decodeArchiveDistribution(const QByteArray &bytes) const;
};

[[nodiscard]] bool GroupChangePreludeMatchesSignedTransition(
	const GroupChangePrelude &prelude,
	const SignedGroupTransition &transition);

} // namespace E2ECloud
