/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "e2e_cloud/protocol/public_group_bootstrap.h"

#include <algorithm>
#include <map>
#include <utility>

namespace E2ECloud {
namespace {

inline constexpr auto kMaximumObjects = std::size_t(65'536);
inline constexpr auto kMaximumBytes = std::uint64_t(512 * 1024 * 1024);

struct Candidate {
	TelegramTransport::UntrustedObject observed;
	TransportEnvelope envelope;
};

[[nodiscard]] bool SameOwnerEnvelope(
		const Candidate &candidate,
		const SignedGroupGenesis &genesis,
		ObjectKind kind,
		std::uint64_t generation) {
	return candidate.envelope.conversationId == genesis.conversationId
		&& candidate.envelope.objectKind == kind
		&& candidate.envelope.senderAccountId == genesis.ownerAccountId
		&& candidate.envelope.senderClientId == genesis.ownerClientId
		&& candidate.envelope.telegramPeerIdBinding
			== genesis.telegramPeerIdBinding
		&& candidate.envelope.epochOrGeneration == generation
		&& candidate.observed.observedTelegramPeerIdBinding
			== genesis.telegramPeerIdBinding
		&& candidate.observed.observedSenderTelegramUserIdBinding
			== genesis.ownerTelegramUserIdBinding
		&& candidate.observed.observedMessageId > 0
		&& candidate.envelope.authenticationData == QByteArray(
			reinterpret_cast<const char*>(genesis.ownerSignature.data()),
			int(genesis.ownerSignature.size()));
}

[[nodiscard]] bool BootstrapKind(const TransportEnvelope &envelope) {
	switch (envelope.objectKind) {
	case ObjectKind::InitialGroupState:
	case ObjectKind::AccountCredential:
		return envelope.epochOrGeneration == 1;
	case ObjectKind::MlsGroupInfo:
		return envelope.epochOrGeneration == 0;
	default:
		return false;
	}
}

} // namespace

bool IsPublicGroupBootstrapCandidate(
		const TelegramTransport::UntrustedObject &object,
		std::uint64_t expectedTelegramPeerIdBinding,
		std::optional<ConversationId> expectedConversationId,
		const EnvelopeCodec &envelopeCodec) {
	const auto envelope = envelopeCodec.decodeUntrusted(object.bytes);
	return expectedTelegramPeerIdBinding
		&& (!expectedConversationId || *expectedConversationId)
		&& envelope
		&& BootstrapKind(*envelope)
		&& envelope->telegramPeerIdBinding
			== expectedTelegramPeerIdBinding
		&& object.observedTelegramPeerIdBinding
			== expectedTelegramPeerIdBinding
		&& object.observedMessageId > 0
		&& (!expectedConversationId
			|| envelope->conversationId == *expectedConversationId);
}

bool PublicGroupBootstrapCanReachCheckpoint(
		const VerifiedPublicGroupBootstrap &verified,
		Checkpoint targetCheckpoint) {
	return targetCheckpoint.conversationId
			== verified.genesis.conversationId
		&& targetCheckpoint.generation
		&& targetCheckpoint.stateHash
		&& targetCheckpoint.generation >= verified.checkpoint.generation
		&& (targetCheckpoint.generation != verified.checkpoint.generation
			|| targetCheckpoint == verified.checkpoint);
}

PublicGroupBootstrapOutcome VerifyPublicGroupBootstrap(
		const std::vector<TelegramTransport::UntrustedObject> &objects,
		std::uint64_t expectedTelegramPeerIdBinding,
		std::optional<ConversationId> expectedConversationId,
		std::optional<AccountId> expectedOwnerAccountId,
		const EnvelopeCodec &envelopeCodec,
		const Sha256Provider &sha256) {
	if (!expectedTelegramPeerIdBinding
		|| (expectedConversationId && !*expectedConversationId)
		|| (expectedOwnerAccountId && !*expectedOwnerAccountId)) {
		return {
			.status = PublicGroupBootstrapStatus::CapacityExceeded,
			.verified = std::nullopt,
		};
	}
	auto totalBytes = std::uint64_t();
	auto unique = std::map<ObjectId, TelegramTransport::UntrustedObject>();
	auto candidates = std::vector<Candidate>();
	for (const auto &object : objects) {
		const auto envelope = envelopeCodec.decodeUntrusted(object.bytes);
		if (!envelope
			|| !BootstrapKind(*envelope)
			|| envelope->telegramPeerIdBinding
				!= expectedTelegramPeerIdBinding
			|| object.observedTelegramPeerIdBinding
				!= expectedTelegramPeerIdBinding
			|| object.observedMessageId <= 0
			|| (expectedConversationId
				&& envelope->conversationId
					!= *expectedConversationId)) {
			continue;
		}
		if (object.bytes.size() < 0
			|| unique.size() == kMaximumObjects
			|| totalBytes > kMaximumBytes
				- std::uint64_t(object.bytes.size())) {
			return {
				.status = PublicGroupBootstrapStatus::CapacityExceeded,
				.verified = std::nullopt,
			};
		}
		totalBytes += std::uint64_t(object.bytes.size());
		if (totalBytes > kMaximumBytes) {
			return {
				.status = PublicGroupBootstrapStatus::CapacityExceeded,
				.verified = std::nullopt,
			};
		}
		const auto i = unique.find(envelope->objectId);
		if (i != end(unique)) {
			if (i->second.bytes != object.bytes
				|| i->second.observedTelegramPeerIdBinding
					!= object.observedTelegramPeerIdBinding
				|| i->second.observedSenderTelegramUserIdBinding
					!= object.observedSenderTelegramUserIdBinding) {
				return {
					.status = PublicGroupBootstrapStatus::ObjectConflict,
					.verified = std::nullopt,
				};
			}
			continue;
		}
		unique.emplace(envelope->objectId, object);
		candidates.push_back({
			.observed = object,
			.envelope = *envelope,
		});
	}
	auto results = std::vector<VerifiedPublicGroupBootstrap>();
	for (const auto &genesisCandidate : candidates) {
		if (genesisCandidate.envelope.objectKind
				!= ObjectKind::InitialGroupState
			|| genesisCandidate.envelope.epochOrGeneration != 1
			|| genesisCandidate.envelope.payloadHash
				!= sha256.digest(genesisCandidate.envelope.payload)) {
			continue;
		}
		const auto genesis = SignedGroupGenesisCodecV1().decode(
			genesisCandidate.envelope.payload);
		if (!genesis
			|| genesisCandidate.envelope.objectId
				!= genesis->genesisObjectId
			|| (expectedOwnerAccountId
				&& genesis->ownerAccountId != *expectedOwnerAccountId)
			|| !SameOwnerEnvelope(
				genesisCandidate,
				*genesis,
				ObjectKind::InitialGroupState,
				1)) {
			continue;
		}
		const auto mls = std::find_if(
			begin(candidates),
			end(candidates),
			[&](const Candidate &candidate) {
				return candidate.envelope.objectId
					== genesis->initialMlsPublicObjectId;
			});
		if (mls == end(candidates)
			|| !SameOwnerEnvelope(
				*mls,
				*genesis,
				ObjectKind::MlsGroupInfo,
				0)
			|| mls->envelope.payloadHash
				!= sha256.digest(mls->envelope.payload)) {
			continue;
		}
		for (const auto &credentialCandidate : candidates) {
			if (!SameOwnerEnvelope(
					credentialCandidate,
					*genesis,
					ObjectKind::AccountCredential,
					1)
				|| credentialCandidate.envelope.payloadHash
					!= sha256.digest(credentialCandidate.envelope.payload)) {
				continue;
			}
			const auto credential = AccountCredentialCodecV1().decode(
				credentialCandidate.envelope.payload);
			if (!credential) {
				continue;
			}
			auto verified = VerifySignedGroupGenesisPublic({
				.genesis = &*genesis,
				.ownerCredential = &*credential,
				.genesisObjectId = genesisCandidate.envelope.objectId,
				.initialMlsPublicObjectId = mls->envelope.objectId,
				.initialMlsPublicObject = mls->envelope.payload,
				.initialArchiveKey = nullptr,
			}, sha256);
			if (!verified.verified) {
				continue;
			}
			results.push_back({
				.genesis = *genesis,
				.ownerCredential = *credential,
				.initialMlsPublicObject = mls->envelope.payload,
				.state = std::move(verified.verified->state),
				.checkpoint = verified.verified->checkpoint,
				.genesisTelegramMessageId =
					genesisCandidate.observed.observedMessageId,
			});
			break;
		}
	}
	if (results.empty()) {
		return {
			.status = PublicGroupBootstrapStatus::Missing,
			.verified = std::nullopt,
		};
	}
	const auto firstGenesis = SignedGroupGenesisCodecV1().encode(
		results.front().genesis);
	for (auto i = std::size_t(1); i != results.size(); ++i) {
		if (SignedGroupGenesisCodecV1().encode(results[i].genesis)
				!= firstGenesis) {
			return {
				.status = PublicGroupBootstrapStatus::Ambiguous,
				.verified = std::nullopt,
			};
		}
	}
	return {
		.status = PublicGroupBootstrapStatus::Verified,
		.verified = std::move(results.front()),
	};
}

} // namespace E2ECloud
