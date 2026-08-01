/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#pragma once

#include "e2e_cloud/core/envelope.h"
#include "e2e_cloud/group/signed_group_transition.h"

#include <QtCore/QByteArray>

#include <cstdint>
#include <optional>

namespace E2ECloud {

inline constexpr auto kMaximumClientKeyPackageSize = 1024 * 1024;
inline constexpr auto kOpenMlsKeyPackageLifetimeSeconds
	= kClientAuthorizationLifetimeSeconds;
inline constexpr auto kOpenMlsKeyPackageRefreshLeadSeconds
	= std::uint64_t(60 * 60 * 24 * 7);

struct ClientKeyPackagePublication {
	AccountCredentialPublic accountCredential;
	ClientAuthorizationProof authorization;
	QByteArray keyPackage;

	friend inline bool operator==(
		const ClientKeyPackagePublication &,
		const ClientKeyPackagePublication &) = default;
};

class ClientKeyPackagePublicationCodecV1 final {
public:
	[[nodiscard]] std::optional<QByteArray> encode(
		const ClientKeyPackagePublication &publication) const;
	[[nodiscard]] std::optional<ClientKeyPackagePublication> decode(
		const QByteArray &bytes) const;
};

enum class ClientKeyPackageEnvelopeResult {
	Verified,
	InvalidEnvelope,
	WrongConversation,
	WrongCarrier,
	WrongGeneration,
	InvalidPublication,
	InvalidAuthorization,
};

struct VerifyClientKeyPackageEnvelopeOutcome {
	ClientKeyPackageEnvelopeResult result
		= ClientKeyPackageEnvelopeResult::InvalidEnvelope;
	std::optional<ClientKeyPackagePublication> publication;
};

[[nodiscard]] VerifyClientKeyPackageEnvelopeOutcome
	VerifyClientKeyPackageEnvelope(
		const TransportEnvelope &envelope,
		ConversationId expectedConversationId,
		std::uint64_t expectedTelegramPeerIdBinding,
		std::uint64_t expectedGeneration,
		const Sha256Provider &sha256);

} // namespace E2ECloud
