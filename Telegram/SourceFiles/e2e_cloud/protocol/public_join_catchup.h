/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#pragma once

#include "e2e_cloud/core/interfaces.h"
#include "e2e_cloud/group/persistent_group_ledger.h"
#include "e2e_cloud/storage/persistent_key_package_pool.h"

#include <cstdint>
#include <optional>
#include <vector>

namespace E2ECloud {

enum class PublicJoinCatchupStatus {
	Ready,
	Waiting,
	UpdatedWaiting,
	ForkDetected,
	InvalidState,
	PersistenceFailure,
};

struct VerifiedPublicJoinBundle {
	TransportEnvelope transitionEnvelope;
	TransportEnvelope commitEnvelope;
	TransportEnvelope welcomeEnvelope;
	TransportEnvelope archiveDistributionEnvelope;
	AccountCredentialPublic targetCredential;
	QByteArray targetKeyPackage;
};

struct PublicJoinCatchupOutcome {
	PublicJoinCatchupStatus status = PublicJoinCatchupStatus::InvalidState;
	std::optional<VerifiedPublicJoinBundle> bundle;
	std::uint64_t appliedTransitions = 0;
};

[[nodiscard]] PublicJoinCatchupOutcome CatchUpPublicJoin(
	const std::vector<TelegramTransport::UntrustedObject> &objects,
	ConversationId conversationId,
	std::uint64_t telegramPeerIdBinding,
	AccountId localAccountId,
	ClientId localClientId,
	const AccountCredentialPublic &localCredential,
	std::uint64_t currentTime,
	const EnvelopeCodec &envelopeCodec,
	const Sha256Provider &sha256,
	PersistentGroupLedger &groupLedger,
	const PersistentKeyPackagePool &keyPackages);

} // namespace E2ECloud
