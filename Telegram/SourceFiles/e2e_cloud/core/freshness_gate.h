/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#pragma once

#include "e2e_cloud/core/types.h"

#include <QtCore/QByteArray>

#include <optional>

namespace E2ECloud {

struct FreshnessChallenge {
	ConversationId conversationId;
	Checkpoint knownCheckpoint;
	ChallengeNonce nonce;
};

struct FreshnessResponse {
	ConversationId conversationId;
	ChallengeNonce nonce;
	Checkpoint checkpoint;
	AccountId witnessAccountId;
	ClientId witnessClientId;
	QByteArray authenticatedProof;
};

class FreshnessResponseVerifier {
public:
	virtual ~FreshnessResponseVerifier() = default;

	[[nodiscard]] virtual bool verify(
		const FreshnessResponse &response) const = 0;

};

enum class FreshnessState {
	Required,
	WaitingForWitness,
	ResynchronizationRequired,
	Ready,
	Forked,
};

enum class FreshnessResponseResult {
	Accepted,
	NotWaiting,
	WrongConversation,
	WrongChallenge,
	InvalidWitness,
	InvalidProof,
	StaleResponse,
	ResynchronizationRequired,
	ForkDetected,
};

class FreshnessGate final {
public:
	explicit FreshnessGate(Checkpoint knownCheckpoint);

	[[nodiscard]] bool beginChallenge(ChallengeNonce nonce);
	[[nodiscard]] FreshnessResponseResult acceptResponse(
		const FreshnessResponse &response,
		const FreshnessResponseVerifier &verifier);
	[[nodiscard]] bool completeResynchronization(
		const Checkpoint &appliedCheckpoint);
	void requireFreshness(Checkpoint knownCheckpoint);

	[[nodiscard]] FreshnessState state() const;
	[[nodiscard]] bool sendingAllowed() const;
	[[nodiscard]] bool administrationAllowed() const;
	[[nodiscard]] const Checkpoint &knownCheckpoint() const;
	[[nodiscard]] std::optional<FreshnessChallenge> challenge() const;
	[[nodiscard]] std::optional<Checkpoint> resynchronizationTarget() const;

private:
	Checkpoint _knownCheckpoint;
	std::optional<FreshnessChallenge> _challenge;
	std::optional<Checkpoint> _resynchronizationTarget;
	FreshnessState _state = FreshnessState::Required;

};

} // namespace E2ECloud
