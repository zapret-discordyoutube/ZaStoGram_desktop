/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "e2e_cloud/protocol/freshness_protocol.h"

#include "e2e_cloud/core/envelope_codec.h"
#include "e2e_cloud/core/outbox.h"
#include "e2e_cloud/storage/persistent_inbound_journal.h"

#include <algorithm>

namespace E2ECloud {
namespace {

[[nodiscard]] QByteArray SignatureBytes(
		const AccountSignature &signature) {
	return QByteArray(
		reinterpret_cast<const char*>(signature.data()),
		int(signature.size()));
}

[[nodiscard]] std::optional<AccountSignature> DecodeSignature(
		const QByteArray &bytes) {
	if (bytes.size() != int(AccountSignature().size())) {
		return std::nullopt;
	}
	auto result = AccountSignature();
	std::copy_n(
		reinterpret_cast<const std::uint8_t*>(bytes.constData()),
		result.size(),
		result.data());
	return result;
}

[[nodiscard]] bool ValidObservedMetadata(
		const TelegramTransport::UntrustedObject &object,
		std::uint64_t telegramPeerIdBinding) {
	return telegramPeerIdBinding
		&& object.observedTelegramPeerIdBinding == telegramPeerIdBinding
		&& object.observedSenderTelegramUserIdBinding
		&& object.observedMessageId > 0;
}

} // namespace

FreshnessResponseQueueResult QueueFreshnessResponseOnce(
		QueueFreshnessResponseArgs args,
		ProtectedOutboxStore &outbox,
		PersistentInboundJournal &replayJournal) {
	if (!args.conversationId
		|| !args.challengeObjectId
		|| !args.challengePayloadHash
		|| args.responseEnvelope.conversationId != args.conversationId
		|| !args.responseEnvelope.objectId
		|| args.responseEnvelope.bytes.isEmpty()) {
		return FreshnessResponseQueueResult::InvalidArguments;
	}
	const auto lookup = replayJournal.lookup(
		args.conversationId,
		args.challengeObjectId,
		args.challengePayloadHash);
	if (lookup == InboundJournalLookup::Accepted) {
		return FreshnessResponseQueueResult::AlreadyResponded;
	} else if (lookup == InboundJournalLookup::ObjectIdConflict) {
		return FreshnessResponseQueueResult::ObjectIdConflict;
	} else if (lookup == InboundJournalLookup::StorageError) {
		return FreshnessResponseQueueResult::PersistenceFailed;
	}
	const auto alreadyQueued = outbox.contains(
		args.responseEnvelope.objectId);
	if (args.responseAlreadyPublished) {
		if (!outbox.appendSealed(args.responseEnvelope)
			|| !outbox.remove(args.responseEnvelope.objectId)) {
			return FreshnessResponseQueueResult::PersistenceFailed;
		}
	} else if (!outbox.appendSealed(args.responseEnvelope)) {
		return FreshnessResponseQueueResult::PersistenceFailed;
	}
	if (lookup == InboundJournalLookup::Missing) {
		if (!replayJournal.begin(
				args.conversationId,
				args.challengeObjectId,
				args.challengePayloadHash)) {
			return FreshnessResponseQueueResult::PersistenceFailed;
		}
	}
	if (!replayJournal.accept(
			args.conversationId,
			args.challengeObjectId)) {
		return FreshnessResponseQueueResult::PersistenceFailed;
	}
	return args.responseAlreadyPublished
		? FreshnessResponseQueueResult::AlreadyPublished
		: alreadyQueued
		? FreshnessResponseQueueResult::AlreadyQueued
		: FreshnessResponseQueueResult::Queued;
}

std::optional<EncodedEnvelope> PrepareFreshnessChallengeEnvelope(
		PrepareFreshnessChallengeEnvelopeArgs args,
		const EnvelopeCodec &envelopeCodec,
		const Sha256Provider &sha256) {
	const auto payload = FreshnessChallengeCodecV1().encode(args.challenge);
	const auto signature = (payload
		&& args.requesterSigningPrivateKey
		&& args.requesterSigningPrivateKey->valid())
		? SignAccountData(
			*args.requesterSigningPrivateKey,
			AccountSignatureDomain::FreshnessChallenge,
			*payload)
		: std::nullopt;
	return (payload
		&& signature
		&& args.requesterAccountId
		&& args.requesterClientId
		&& args.telegramPeerIdBinding
		&& args.objectId)
		? envelopeCodec.encode({
			.conversationId = args.challenge.conversationId,
			.objectKind = ObjectKind::FreshnessChallenge,
			.senderAccountId = args.requesterAccountId,
			.senderClientId = args.requesterClientId,
			.telegramPeerIdBinding = args.telegramPeerIdBinding,
			.epochOrGeneration =
				args.challenge.knownCheckpoint.generation,
			.objectId = args.objectId,
			.payloadHash = sha256.digest(*payload),
			.payload = *payload,
			.authenticationData = SignatureBytes(*signature),
		})
		: std::nullopt;
}

std::optional<EncodedEnvelope> PrepareFreshnessResponseEnvelope(
		PrepareFreshnessResponseEnvelopeArgs args,
		const EnvelopeCodec &envelopeCodec,
		const Sha256Provider &sha256) {
	const auto response = CreateFreshnessResponse({
		.challenge = std::move(args.challenge),
		.witnessCheckpoint = args.witnessCheckpoint,
		.witnessAccountId = args.witnessAccountId,
		.witnessClientId = args.witnessClientId,
		.witnessSigningPrivateKey = args.witnessSigningPrivateKey,
	});
	const auto payload = response
		? FreshnessResponseCodecV1().encode(*response)
		: std::nullopt;
	return (response
		&& payload
		&& args.telegramPeerIdBinding
		&& args.objectId)
		? envelopeCodec.encode({
			.conversationId = response->conversationId,
			.objectKind = ObjectKind::FreshnessResponse,
			.senderAccountId = response->witnessAccountId,
			.senderClientId = response->witnessClientId,
			.telegramPeerIdBinding = args.telegramPeerIdBinding,
			.epochOrGeneration = response->checkpoint.generation,
			.objectId = args.objectId,
			.payloadHash = sha256.digest(*payload),
			.payload = *payload,
			.authenticationData = response->authenticatedProof,
		})
		: std::nullopt;
}

std::optional<VerifiedObservedFreshnessChallenge>
VerifyObservedFreshnessChallenge(
		const TelegramTransport::UntrustedObject &object,
		ConversationId conversationId,
		std::uint64_t telegramPeerIdBinding,
		const EnvelopeCodec &envelopeCodec,
		const PersistentGroupLedger &groupLedger,
		const Sha256Provider &sha256) {
	if (!ValidObservedMetadata(object, telegramPeerIdBinding)
		|| !groupLedger.loaded()
		|| !groupLedger.state()) {
		return std::nullopt;
	}
	const auto envelope = envelopeCodec.decodeUntrusted(object.bytes);
	const auto challenge = envelope
		? FreshnessChallengeCodecV1().decode(envelope->payload)
		: std::nullopt;
	const auto checkpoint = challenge
		? groupLedger.checkpointAt(
			challenge->knownCheckpoint.generation)
		: std::nullopt;
	const auto requester = envelope
		? groupLedger.stateAt(envelope->epochOrGeneration)
		: std::nullopt;
	const auto requesterMember = (requester && envelope)
		? requester->memberByClient(envelope->senderClientId)
		: nullptr;
	const auto credential = envelope
		? groupLedger.credential(envelope->senderAccountId)
		: nullptr;
	const auto signature = envelope
		? DecodeSignature(envelope->authenticationData)
		: std::nullopt;
	if (!envelope
		|| !challenge
		|| !checkpoint
		|| challenge->conversationId != conversationId
		|| challenge->knownCheckpoint != *checkpoint
		|| envelope->conversationId != conversationId
		|| envelope->objectKind != ObjectKind::FreshnessChallenge
		|| envelope->telegramPeerIdBinding != telegramPeerIdBinding
		|| envelope->epochOrGeneration
			!= challenge->knownCheckpoint.generation
		|| envelope->payloadHash != sha256.digest(envelope->payload)
		|| !requesterMember
		|| requesterMember->accountId != envelope->senderAccountId
		|| requesterMember->telegramUserIdBinding
			!= object.observedSenderTelegramUserIdBinding
		|| !credential
		|| !signature
		|| !VerifyAccountSignature(
			*credential,
			AccountSignatureDomain::FreshnessChallenge,
			envelope->payload,
			*signature)) {
		return std::nullopt;
	}
	return VerifiedObservedFreshnessChallenge{
		.challenge = *challenge,
		.requesterAccountId = envelope->senderAccountId,
		.requesterClientId = envelope->senderClientId,
		.objectId = envelope->objectId,
		.payloadHash = envelope->payloadHash,
	};
}

std::optional<VerifiedObservedFreshnessResponse>
VerifyObservedFreshnessResponse(
		const TelegramTransport::UntrustedObject &object,
		ConversationId conversationId,
		std::uint64_t telegramPeerIdBinding,
		const EnvelopeCodec &envelopeCodec,
		const PersistentGroupLedger &groupLedger,
		const Sha256Provider &sha256) {
	if (!ValidObservedMetadata(object, telegramPeerIdBinding)) {
		return std::nullopt;
	}
	const auto envelope = envelopeCodec.decodeUntrusted(object.bytes);
	const auto response = envelope
		? FreshnessResponseCodecV1().decode(envelope->payload)
		: std::nullopt;
	const auto witnessState = response
		? groupLedger.stateAt(
			response->challengedCheckpoint.generation)
		: std::nullopt;
	const auto witness = (witnessState && response)
		? witnessState->memberByClient(response->witnessClientId)
		: nullptr;
	const auto verifier = AccountFreshnessResponseVerifier(groupLedger);
	if (!envelope
		|| !response
		|| response->conversationId != conversationId
		|| envelope->conversationId != conversationId
		|| envelope->objectKind != ObjectKind::FreshnessResponse
		|| envelope->senderAccountId != response->witnessAccountId
		|| envelope->senderClientId != response->witnessClientId
		|| envelope->telegramPeerIdBinding != telegramPeerIdBinding
		|| envelope->epochOrGeneration != response->checkpoint.generation
		|| envelope->payloadHash != sha256.digest(envelope->payload)
		|| envelope->authenticationData != response->authenticatedProof
		|| !witness
		|| witness->accountId != response->witnessAccountId
		|| witness->telegramUserIdBinding
			!= object.observedSenderTelegramUserIdBinding
		|| !verifier.verify(*response)) {
		return std::nullopt;
	}
	return VerifiedObservedFreshnessResponse{
		.response = *response,
		.objectId = envelope->objectId,
	};
}

} // namespace E2ECloud
