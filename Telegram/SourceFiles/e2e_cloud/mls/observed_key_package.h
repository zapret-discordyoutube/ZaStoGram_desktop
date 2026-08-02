/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#pragma once

#include "e2e_cloud/core/interfaces.h"
#include "e2e_cloud/mls/client_key_package.h"

#include <cstdint>
#include <optional>

namespace E2ECloud {

enum class ObservedClientKeyPackageStatus {
	Verified,
	InvalidTransportMetadata,
	InvalidEnvelope,
	InvalidPublication,
	InvalidTelegramAuthorBinding,
	NotCurrentlyUsable,
};

struct ObservedClientKeyPackage {
	TransportEnvelope envelope;
	ClientKeyPackagePublication publication;
	std::uint64_t telegramUserIdBinding = 0;
	std::int64_t telegramMessageId = 0;
};

struct VerifyObservedClientKeyPackageOutcome {
	ObservedClientKeyPackageStatus status
		= ObservedClientKeyPackageStatus::InvalidEnvelope;
	std::optional<ObservedClientKeyPackage> verified;
};

[[nodiscard]] VerifyObservedClientKeyPackageOutcome
VerifyObservedClientKeyPackage(
	const TelegramTransport::UntrustedObject &object,
	ConversationId expectedConversationId,
	std::uint64_t expectedTelegramPeerIdBinding,
	std::uint64_t expectedGroupGeneration,
	std::uint64_t currentTime,
	const EnvelopeCodec &envelopeCodec,
	const Sha256Provider &sha256);

} // namespace E2ECloud
