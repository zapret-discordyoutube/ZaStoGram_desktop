/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#pragma once

#include "e2e_cloud/core/envelope_codec.h"
#include "e2e_cloud/group/signed_group_genesis.h"
#include "e2e_cloud/mls/mls_roster_codec.h"
#include "e2e_cloud/mls/openmls_bridge.h"

#include <QtCore/QByteArray>

#include <cstdint>
#include <optional>
#include <vector>

namespace E2ECloud {

struct ProtectedGroupBootstrapArgs {
	ConversationId conversationId;
	std::uint64_t telegramPeerIdBinding = 0;
	std::uint64_t ownerTelegramUserIdBinding = 0;
	ClientId ownerClientId;
	GroupPolicy policy;
	ObjectId genesisObjectId;
	ObjectId ownerCredentialObjectId;
	ObjectId initialMlsPublicObjectId;
	ObjectId archiveActivationEventId;
	ObjectId ownerHistoryGrantObjectId;
	const AccountPrivateIdentity *ownerIdentity = nullptr;
	const ArchiveKey32 *initialArchiveKey = nullptr;
};

enum class ProtectedGroupBootstrapStatus {
	Prepared,
	InvalidArgument,
	IdentityFailure,
	OpenMlsFailure,
	RosterMismatch,
	GenesisFailure,
	HistoryGrantFailure,
	EncodingFailure,
};

struct PreparedProtectedGroupBootstrap {
	ConversationId conversationId;
	AccountId ownerAccountId;
	ClientId ownerClientId;
	SignedGroupGenesis genesis;
	ProtectedGroupState groupState;
	Checkpoint checkpoint;
	ArchiveEpochSecret archiveEpoch;
	QByteArray mlsEngineState;
	QByteArray initialMlsPublicObject;
	std::vector<EncodedEnvelope> outboxEnvelopes;
};

struct ProtectedGroupBootstrapOutcome {
	ProtectedGroupBootstrapStatus status
		= ProtectedGroupBootstrapStatus::InvalidArgument;
	std::optional<PreparedProtectedGroupBootstrap> prepared;
};

[[nodiscard]] ProtectedGroupBootstrapOutcome PrepareProtectedGroupBootstrap(
	ProtectedGroupBootstrapArgs args,
	const OpenMlsBridge &bridge,
	const MlsContextCodecV1 &contextCodec,
	const MlsRosterCodecV1 &rosterCodec,
	const EnvelopeCodecV1 &envelopeCodec,
	const Sha256Provider &sha256);

} // namespace E2ECloud
