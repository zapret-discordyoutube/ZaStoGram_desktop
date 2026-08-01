/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#pragma once

#include "e2e_cloud/core/interfaces.h"
#include "e2e_cloud/mls/openmls_inbound_group_change.h"

#include <cstdint>
#include <vector>

namespace E2ECloud {

enum class ObservedGroupChangeSyncStatus {
	NoChange,
	Updated,
	WaitingForObjects,
	ForkDetected,
	LocalClientRemoved,
	InvalidState,
	PersistenceFailure,
};

struct ObservedGroupChangeSyncOutcome {
	ObservedGroupChangeSyncStatus status
		= ObservedGroupChangeSyncStatus::InvalidState;
	std::uint64_t appliedTransitions = 0;
};

[[nodiscard]] ObservedGroupChangeSyncOutcome
	SynchronizeObservedGroupChanges(
		const std::vector<TelegramTransport::UntrustedObject> &objects,
		OpenMlsClientContext local,
		std::uint64_t currentTime,
		const EnvelopeCodec &envelopeCodec,
		const OpenMlsBridge &bridge,
		const MlsContextCodecV1 &contextCodec,
		const MlsRosterCodecV1 &rosterCodec,
		const GroupControlCodecV1 &controlCodec,
		const Sha256Provider &sha256,
		PersistentMlsStateStore &mlsState,
		PersistentArchiveState &archiveState,
		PersistentGroupLedger &groupLedger,
		PersistentGroupChangeJournal &journal);

} // namespace E2ECloud
