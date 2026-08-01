/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "e2e_cloud/mls/observed_key_package.h"

#include <utility>

namespace E2ECloud {

VerifyObservedClientKeyPackageOutcome VerifyObservedClientKeyPackage(
		const TelegramTransport::UntrustedObject &object,
		ConversationId expectedConversationId,
		std::uint64_t expectedTelegramPeerIdBinding,
		std::uint64_t expectedGroupGeneration,
		std::uint64_t currentTime,
		const EnvelopeCodec &envelopeCodec,
		const Sha256Provider &sha256) {
	if (!expectedConversationId
		|| !expectedTelegramPeerIdBinding
		|| !expectedGroupGeneration
		|| !currentTime
		|| object.bytes.isEmpty()
		|| object.observedTelegramPeerIdBinding
			!= expectedTelegramPeerIdBinding
		|| !object.observedSenderTelegramUserIdBinding
		|| object.observedMessageId <= 0) {
		return {
			.status = ObservedClientKeyPackageStatus::InvalidTransportMetadata,
			.verified = std::nullopt,
		};
	}
	auto envelope = envelopeCodec.decodeUntrusted(object.bytes);
	if (!envelope) {
		return {
			.status = ObservedClientKeyPackageStatus::InvalidEnvelope,
			.verified = std::nullopt,
		};
	}
	if (!envelope->epochOrGeneration
		|| envelope->epochOrGeneration > expectedGroupGeneration) {
		return {
			.status = ObservedClientKeyPackageStatus::InvalidPublication,
			.verified = std::nullopt,
		};
	}
	auto publication = VerifyClientKeyPackageEnvelope(
		*envelope,
		expectedConversationId,
		expectedTelegramPeerIdBinding,
		envelope->epochOrGeneration,
		sha256);
	if (publication.result != ClientKeyPackageEnvelopeResult::Verified
		|| !publication.publication) {
		return {
			.status = ObservedClientKeyPackageStatus::InvalidPublication,
			.verified = std::nullopt,
		};
	}
	if (!ClientAuthorizationUsableAt(
			publication.publication->authorization,
			currentTime)) {
		return {
			.status = ObservedClientKeyPackageStatus::NotCurrentlyUsable,
			.verified = std::nullopt,
		};
	}
	return {
		.status = ObservedClientKeyPackageStatus::Verified,
		.verified = ObservedClientKeyPackage{
			.envelope = std::move(*envelope),
			.publication = std::move(*publication.publication),
			.telegramUserIdBinding =
				object.observedSenderTelegramUserIdBinding,
			.telegramMessageId = object.observedMessageId,
		},
	};
}

} // namespace E2ECloud
