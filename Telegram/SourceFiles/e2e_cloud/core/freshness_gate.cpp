/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "e2e_cloud/core/freshness_gate.h"

#include <utility>

namespace E2ECloud {

FreshnessGate::FreshnessGate(
		Checkpoint knownCheckpoint,
		bool initiallyTrusted)
: _knownCheckpoint(std::move(knownCheckpoint))
, _state(initiallyTrusted ? FreshnessState::Ready : FreshnessState::Required) {
}

bool FreshnessGate::beginChallenge(ChallengeNonce nonce) {
	if (!nonce
		|| !_knownCheckpoint.conversationId
		|| !_knownCheckpoint.stateHash
		|| _state == FreshnessState::Forked) {
		return false;
	}
	_challenge = FreshnessChallenge{
		.conversationId = _knownCheckpoint.conversationId,
		.knownCheckpoint = _knownCheckpoint,
		.nonce = nonce,
	};
	_resynchronizationTarget.reset();
	_state = FreshnessState::WaitingForWitness;
	return true;
}

FreshnessResponseResult FreshnessGate::acceptResponse(
		const FreshnessResponse &response,
		const FreshnessResponseVerifier &verifier) {
	if (_state != FreshnessState::WaitingForWitness || !_challenge) {
		return FreshnessResponseResult::NotWaiting;
	} else if (response.conversationId != _challenge->conversationId
		|| response.challengedCheckpoint.conversationId
			!= _challenge->conversationId
		|| response.checkpoint.conversationId != _challenge->conversationId) {
		return FreshnessResponseResult::WrongConversation;
	} else if (response.nonce != _challenge->nonce) {
		return FreshnessResponseResult::WrongChallenge;
	} else if (response.challengedCheckpoint
			!= _challenge->knownCheckpoint) {
		return FreshnessResponseResult::WrongCheckpoint;
	} else if (!response.witnessAccountId || !response.witnessClientId) {
		return FreshnessResponseResult::InvalidWitness;
	} else if (!response.checkpoint.stateHash
		|| response.authenticatedProof.isEmpty()
		|| !verifier.verify(response)) {
		return FreshnessResponseResult::InvalidProof;
	} else if (response.checkpoint.generation
			< _knownCheckpoint.generation) {
		return FreshnessResponseResult::StaleResponse;
	} else if (response.checkpoint.generation
			== _knownCheckpoint.generation) {
		_challenge.reset();
		if (response.checkpoint.stateHash != _knownCheckpoint.stateHash) {
			_state = FreshnessState::Forked;
			return FreshnessResponseResult::ForkDetected;
		}
		_state = FreshnessState::Ready;
		return FreshnessResponseResult::Accepted;
	}
	_challenge.reset();
	_resynchronizationTarget = response.checkpoint;
	_state = FreshnessState::ResynchronizationRequired;
	return FreshnessResponseResult::ResynchronizationRequired;
}

bool FreshnessGate::completeResynchronization(
		const Checkpoint &appliedCheckpoint) {
	if (_state != FreshnessState::ResynchronizationRequired
		|| !_resynchronizationTarget
		|| appliedCheckpoint != *_resynchronizationTarget) {
		return false;
	}
	_knownCheckpoint = appliedCheckpoint;
	_resynchronizationTarget.reset();
	_state = FreshnessState::Ready;
	return true;
}

bool FreshnessGate::advanceTrustedCheckpoint(
		Checkpoint appliedCheckpoint) {
	if (_state != FreshnessState::Ready
		|| !appliedCheckpoint.conversationId
		|| !appliedCheckpoint.stateHash
		|| appliedCheckpoint.conversationId
			!= _knownCheckpoint.conversationId
		|| appliedCheckpoint.generation < _knownCheckpoint.generation
		|| (appliedCheckpoint.generation == _knownCheckpoint.generation
			&& appliedCheckpoint != _knownCheckpoint)) {
		return false;
	}
	_knownCheckpoint = std::move(appliedCheckpoint);
	return true;
}

void FreshnessGate::requireFreshness(Checkpoint knownCheckpoint) {
	_knownCheckpoint = std::move(knownCheckpoint);
	_challenge.reset();
	_resynchronizationTarget.reset();
	_state = FreshnessState::Required;
}

FreshnessState FreshnessGate::state() const {
	return _state;
}

bool FreshnessGate::sendingAllowed() const {
	return _state == FreshnessState::Ready;
}

bool FreshnessGate::administrationAllowed() const {
	return _state == FreshnessState::Ready;
}

const Checkpoint &FreshnessGate::knownCheckpoint() const {
	return _knownCheckpoint;
}

std::optional<FreshnessChallenge> FreshnessGate::challenge() const {
	return _challenge;
}

std::optional<Checkpoint> FreshnessGate::resynchronizationTarget() const {
	return _resynchronizationTarget;
}

} // namespace E2ECloud
