/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#pragma once

#include "e2e_cloud/core/interfaces.h"
#include "e2e_cloud/mls/openmls_application_engine.h"

#include <cstdint>
#include <vector>

namespace E2ECloud {

class FileChunkCiphertextStore;
class PersistentArchiveState;
class PersistentContentStore;
class PersistentGroupLedger;
class PersistentInboundJournal;
class PersistentMlsStateStore;
class Sha256Provider;

enum class ObservedContentProcessStatus {
	Processed,
	SecurityBlocked,
	PersistenceFailed,
	InvalidState,
};

struct ObservedContentProcessStats {
	std::uint64_t messagesStored = 0;
	std::uint64_t manifestsStored = 0;
	std::uint64_t chunksStored = 0;
	std::uint64_t applicationsProcessed = 0;
	std::uint64_t ignored = 0;
};

struct ObservedContentProcessOutcome {
	ObservedContentProcessStatus status
		= ObservedContentProcessStatus::InvalidState;
	ObservedContentProcessStats stats;
};

[[nodiscard]] ObservedContentProcessOutcome ProcessObservedContentPage(
	const std::vector<TelegramTransport::UntrustedObject> &objects,
	OpenMlsClientContext local,
	std::uint64_t localTelegramUserIdBinding,
	const EnvelopeCodec &envelopeCodec,
	const OpenMlsBridge &bridge,
	const MlsContextCodecV1 &contextCodec,
	const Sha256Provider &sha256,
	PersistentMlsStateStore &mlsState,
	PersistentArchiveState &archiveState,
	PersistentGroupLedger &groupLedger,
	PersistentInboundJournal &inboundJournal,
	PersistentContentStore &contentStore,
	FileChunkCiphertextStore &chunkStore);

} // namespace E2ECloud
