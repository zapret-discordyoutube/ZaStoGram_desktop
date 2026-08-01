/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#pragma once

#include "e2e_cloud/core/freshness_crypto.h"
#include "e2e_cloud/core/interfaces.h"

namespace E2ECloud {

class PersistentInboundJournal;
class ProtectedOutboxStore;

struct PrepareFreshnessChallengeEnvelopeArgs {
	FreshnessChallenge challenge;
	AccountId requesterAccountId;
	ClientId requesterClientId;
	std::uint64_t telegramPeerIdBinding = 0;
	ObjectId objectId;
	const SecureKey32 *requesterSigningPrivateKey = nullptr;
};

struct PrepareFreshnessResponseEnvelopeArgs {
	FreshnessChallenge challenge;
	Checkpoint witnessCheckpoint;
	AccountId witnessAccountId;
	ClientId witnessClientId;
	std::uint64_t telegramPeerIdBinding = 0;
	ObjectId objectId;
	const SecureKey32 *witnessSigningPrivateKey = nullptr;
};

struct VerifiedObservedFreshnessChallenge {
	FreshnessChallenge challenge;
	AccountId requesterAccountId;
	ClientId requesterClientId;
	ObjectId objectId;
	Digest payloadHash;
};

struct VerifiedObservedFreshnessResponse {
	FreshnessResponse response;
	ObjectId objectId;
};

enum class FreshnessResponseQueueResult {
	Queued,
	AlreadyQueued,
	AlreadyPublished,
	AlreadyResponded,
	InvalidArguments,
	ObjectIdConflict,
	PersistenceFailed,
};

struct QueueFreshnessResponseArgs {
	ConversationId conversationId;
	ObjectId challengeObjectId;
	Digest challengePayloadHash;
	EncodedEnvelope responseEnvelope;
	bool responseAlreadyPublished = false;
};

[[nodiscard]] FreshnessResponseQueueResult QueueFreshnessResponseOnce(
	QueueFreshnessResponseArgs args,
	ProtectedOutboxStore &outbox,
	PersistentInboundJournal &replayJournal);

[[nodiscard]] std::optional<EncodedEnvelope>
	PrepareFreshnessChallengeEnvelope(
		PrepareFreshnessChallengeEnvelopeArgs args,
		const EnvelopeCodec &envelopeCodec,
		const Sha256Provider &sha256);

[[nodiscard]] std::optional<EncodedEnvelope>
	PrepareFreshnessResponseEnvelope(
		PrepareFreshnessResponseEnvelopeArgs args,
		const EnvelopeCodec &envelopeCodec,
		const Sha256Provider &sha256);

[[nodiscard]] std::optional<VerifiedObservedFreshnessChallenge>
	VerifyObservedFreshnessChallenge(
		const TelegramTransport::UntrustedObject &object,
		ConversationId conversationId,
		std::uint64_t telegramPeerIdBinding,
		const EnvelopeCodec &envelopeCodec,
		const PersistentGroupLedger &groupLedger,
		const Sha256Provider &sha256);

[[nodiscard]] std::optional<VerifiedObservedFreshnessResponse>
	VerifyObservedFreshnessResponse(
		const TelegramTransport::UntrustedObject &object,
		ConversationId conversationId,
		std::uint64_t telegramPeerIdBinding,
		const EnvelopeCodec &envelopeCodec,
		const PersistentGroupLedger &groupLedger,
		const Sha256Provider &sha256);

} // namespace E2ECloud
