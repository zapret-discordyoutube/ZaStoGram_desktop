/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#pragma once

#include "e2e_cloud/core/interfaces.h"
#include "e2e_cloud/group/signed_group_genesis.h"

#include <cstdint>
#include <optional>
#include <vector>

namespace E2ECloud {

enum class PublicGroupBootstrapStatus {
	Verified,
	Missing,
	CapacityExceeded,
	ObjectConflict,
	Ambiguous,
};

struct VerifiedPublicGroupBootstrap {
	SignedGroupGenesis genesis;
	AccountCredentialPublic ownerCredential;
	QByteArray initialMlsPublicObject;
	ProtectedGroupState state;
	Checkpoint checkpoint;
	std::int64_t genesisTelegramMessageId = 0;
};

struct PublicGroupBootstrapOutcome {
	PublicGroupBootstrapStatus status = PublicGroupBootstrapStatus::Missing;
	std::optional<VerifiedPublicGroupBootstrap> verified;
};

[[nodiscard]] bool IsPublicGroupBootstrapCandidate(
	const TelegramTransport::UntrustedObject &object,
	std::uint64_t expectedTelegramPeerIdBinding,
	std::optional<ConversationId> expectedConversationId,
	const EnvelopeCodec &envelopeCodec);
[[nodiscard]] PublicGroupBootstrapOutcome VerifyPublicGroupBootstrap(
	const std::vector<TelegramTransport::UntrustedObject> &objects,
	std::uint64_t expectedTelegramPeerIdBinding,
	std::optional<ConversationId> expectedConversationId,
	std::optional<AccountId> expectedOwnerAccountId,
	const EnvelopeCodec &envelopeCodec,
	const Sha256Provider &sha256);

} // namespace E2ECloud
