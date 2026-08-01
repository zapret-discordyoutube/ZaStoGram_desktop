/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#pragma once

#include "e2e_cloud/mls/openmls_fork_recovery_engine.h"

namespace E2ECloud {

enum class OpenMlsInboundForkRecoveryStatus {
	Prepared,
	InvalidArguments,
	StateUnavailable,
	InvalidEnvelope,
	InvalidManifest,
	InvalidCanonicalTransition,
	KeyPackageUnavailable,
	MlsFailure,
	ArchiveInvariantViolation,
	RosterMismatch,
};

struct PrepareOpenMlsInboundForkRecoveryArgs {
	OpenMlsClientContext local;
	TransportEnvelope manifestEnvelope;
	TransportEnvelope canonicalTransitionEnvelope;
	TransportEnvelope canonicalCommitEnvelope;
	TransportEnvelope canonicalArchiveDistributionEnvelope;
	TransportEnvelope recoveryCommitEnvelope;
	TransportEnvelope recoveryWelcomeEnvelope;
	TransportEnvelope recoveryArchiveDistributionEnvelope;
	std::vector<ForkRecoveryCandidate> observedCandidates;
	std::vector<TransportEnvelope> replacementKeyPackageEnvelopes;
	std::optional<AccountCredentialPublic> canonicalTargetCredential;
	QByteArray canonicalTargetKeyPackage;
	std::uint64_t currentTime = 0;
};

struct PreparedOpenMlsInboundForkRecovery {
	ForkRecoveryTransaction transaction;
	MlsRoster resultingRoster;
};

struct PrepareOpenMlsInboundForkRecoveryOutcome {
	OpenMlsInboundForkRecoveryStatus status
		= OpenMlsInboundForkRecoveryStatus::InvalidArguments;
	std::optional<PreparedOpenMlsInboundForkRecovery> prepared;
};

[[nodiscard]] PrepareOpenMlsInboundForkRecoveryOutcome
	PrepareOpenMlsInboundForkRecovery(
		PrepareOpenMlsInboundForkRecoveryArgs args,
		const OpenMlsBridge &bridge,
		const MlsContextCodecV1 &contextCodec,
		const MlsRosterCodecV1 &rosterCodec,
		const GroupControlCodecV1 &controlCodec,
		const Sha256Provider &sha256,
		const PersistentMlsStateStore &mlsState,
		const PersistentArchiveState &archiveState,
		const PersistentGroupLedger &groupLedger,
		const PersistentForkRecoveryLedger &forkLedger,
		const PersistentKeyPackagePool &keyPackagePool);

} // namespace E2ECloud
