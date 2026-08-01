/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#pragma once

#include "e2e_cloud/mls/openmls_group_change_engine.h"

namespace E2ECloud {

struct OpenMlsInboundGroupChangeArgs {
	OpenMlsClientContext local;
	TransportEnvelope transitionEnvelope;
	TransportEnvelope commitEnvelope;
	TransportEnvelope archiveDistributionEnvelope;
	std::optional<AccountCredentialPublic> targetCredential;
	QByteArray targetKeyPackage;
};

struct OpenMlsInboundJoinArgs {
	OpenMlsClientContext local;
	TransportEnvelope transitionEnvelope;
	TransportEnvelope commitEnvelope;
	TransportEnvelope welcomeEnvelope;
	TransportEnvelope archiveDistributionEnvelope;
	std::optional<AccountCredentialPublic> targetCredential;
	QByteArray targetKeyPackage;
};

enum class OpenMlsInboundGroupChangeStatus {
	Prepared,
	InvalidArguments,
	StateUnavailable,
	InvalidEnvelope,
	MissingAdmissionMaterial,
	CommitDeferred,
	CommitRejected,
	LocalClientRemoved,
	DistributionDeferred,
	DistributionRejected,
	TransitionRejected,
	RosterMismatch,
};

struct PreparedOpenMlsInboundGroupChange {
	GroupChangeTransaction transaction;
	AppliedSignedGroupTransition applied;
	MlsRoster resultingRoster;
};

struct PrepareOpenMlsInboundGroupChangeOutcome {
	OpenMlsInboundGroupChangeStatus status
		= OpenMlsInboundGroupChangeStatus::InvalidArguments;
	std::optional<PreparedOpenMlsInboundGroupChange> prepared;
};

[[nodiscard]] PrepareOpenMlsInboundGroupChangeOutcome
	PrepareOpenMlsInboundGroupChange(
		OpenMlsInboundGroupChangeArgs args,
		const OpenMlsBridge &bridge,
		const MlsContextCodecV1 &contextCodec,
		const MlsRosterCodecV1 &rosterCodec,
		const GroupControlCodecV1 &controlCodec,
		const Sha256Provider &sha256,
		const PersistentMlsStateStore &mlsState,
		const PersistentArchiveState &archiveState,
		const PersistentGroupLedger &groupLedger);

[[nodiscard]] PrepareOpenMlsInboundGroupChangeOutcome
	PrepareOpenMlsInboundJoin(
		OpenMlsInboundJoinArgs args,
		const OpenMlsBridge &bridge,
		const MlsContextCodecV1 &contextCodec,
		const MlsRosterCodecV1 &rosterCodec,
		const GroupControlCodecV1 &controlCodec,
		const Sha256Provider &sha256,
		const PersistentMlsStateStore &mlsState,
		const PersistentArchiveState &archiveState,
		const PersistentGroupLedger &groupLedger);

} // namespace E2ECloud
