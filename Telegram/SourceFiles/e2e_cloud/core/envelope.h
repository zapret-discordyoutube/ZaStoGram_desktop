/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#pragma once

#include "e2e_cloud/core/types.h"

#include <QtCore/QByteArray>

#include <array>
#include <cstdint>

namespace E2ECloud {

inline constexpr auto kApplicationProtocolVersion = std::uint32_t(1);
inline constexpr auto kEnvelopeMagic = std::array<std::uint8_t, 8>{
	'T', 'D', 'E', '2', 'E', 'C', 'L', 'D',
};

enum class ObjectKind : std::uint16_t {
	InitialGroupState = 1,
	AccountCredential = 2,
	ClientKeyPackage = 3,
	JoinRequest = 4,
	MlsProposal = 5,
	MlsCommit = 6,
	MlsWelcome = 7,
	MlsApplication = 8,
	EncryptedMessageBody = 9,
	EncryptedFileManifest = 10,
	EncryptedFileChunk = 11,
	ArchiveEpoch = 12,
	HistoryPolicy = 13,
	HistoryGrant = 14,
	RoleUpdate = 15,
	SafetyCodeGossip = 16,
	FreshnessChallenge = 17,
	FreshnessResponse = 18,
	ResynchronizationRequest = 19,
	SignedGroupTransition = 20,
	ForkRecoveryManifest = 21,
	MlsGroupInfo = 22,
};

struct TransportEnvelope {
	std::array<std::uint8_t, 8> magic = kEnvelopeMagic;
	std::uint32_t applicationProtocolVersion = kApplicationProtocolVersion;
	ConversationId conversationId;
	ObjectKind objectKind = ObjectKind::MlsApplication;
	AccountId senderAccountId;
	ClientId senderClientId;
	std::uint64_t telegramPeerIdBinding = 0;
	std::uint64_t epochOrGeneration = 0;
	ObjectId objectId;
	Digest payloadHash;
	QByteArray payload;
	QByteArray authenticationData;

	friend inline bool operator==(
		const TransportEnvelope &,
		const TransportEnvelope &) = default;
};

enum class EnvelopeValidationError {
	None,
	InvalidMagic,
	UnsupportedVersion,
	UnknownObjectKind,
	MissingConversationId,
	MissingSenderAccountId,
	MissingSenderClientId,
	MissingTelegramPeerBinding,
	MissingObjectId,
	MissingPayloadHash,
	MissingPayload,
	MissingAuthenticationData,
};

[[nodiscard]] bool IsKnownObjectKind(ObjectKind kind);
[[nodiscard]] EnvelopeValidationError ValidateEnvelope(
	const TransportEnvelope &envelope);

} // namespace E2ECloud
