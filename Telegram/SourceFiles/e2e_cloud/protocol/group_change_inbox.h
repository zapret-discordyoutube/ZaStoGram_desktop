/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#pragma once

#include "e2e_cloud/group/persistent_group_ledger.h"
#include "e2e_cloud/mls/mls_context_codec.h"
#include "e2e_cloud/protocol/group_control_codec.h"
#include "e2e_cloud/protocol/inbound_envelope_processor.h"
#include "e2e_cloud/storage/persistent_fork_recovery_ledger.h"
#include "e2e_cloud/storage/local_storage.h"

#include <optional>
#include <vector>

namespace E2ECloud {

enum class GroupChangeInboxLoadResult {
	Loaded,
	Missing,
	StorageError,
	AuthenticationFailed,
	InvalidSnapshot,
};

enum class GroupChangeInboxStageResult {
	Staged,
	Duplicate,
	ObjectIdConflict,
	InvalidEnvelope,
	CapacityExceeded,
	NotLoaded,
	PersistenceFailed,
};

enum class GroupChangeInboxLookup {
	Missing,
	Present,
	ObjectIdConflict,
	Unavailable,
};

struct GroupChangeInboxBundle {
	SignedGroupTransition signedTransition;
	TransportEnvelope transitionEnvelope;
	TransportEnvelope commitEnvelope;
	TransportEnvelope archiveDistributionEnvelope;
};

enum class GroupChangeInboxReadyStatus {
	Ready,
	Incomplete,
	ForkDetected,
	Unavailable,
};

struct GroupChangeInboxReadyResult {
	GroupChangeInboxReadyStatus status
		= GroupChangeInboxReadyStatus::Unavailable;
	std::optional<GroupChangeInboxBundle> bundle;
};

struct StagedGroupChangeEnvelope {
	TransportEnvelope envelope;
	std::uint64_t observedSenderTelegramUserIdBinding = 0;

	friend inline bool operator==(
		const StagedGroupChangeEnvelope &,
		const StagedGroupChangeEnvelope &) = default;
};

class PersistentGroupChangeInbox final {
public:
	PersistentGroupChangeInbox(
		AtomicBlobStore &blobStore,
		const LocalRecordProtector &protector,
		const EnvelopeCodec &envelopeCodec,
		const Sha256Provider &sha256);

	[[nodiscard]] GroupChangeInboxLoadResult load(
		ConversationId conversationId);
	[[nodiscard]] GroupChangeInboxStageResult stage(
		const TransportEnvelope &envelope);
	[[nodiscard]] GroupChangeInboxStageResult stageObserved(
		const TransportEnvelope &envelope,
		std::uint64_t observedSenderTelegramUserIdBinding);
	[[nodiscard]] GroupChangeInboxLookup lookup(
		ObjectId objectId,
		Digest payloadHash) const;
	[[nodiscard]] GroupChangeInboxReadyResult ready(
		std::uint64_t previousGeneration) const;
	[[nodiscard]] std::vector<ForkRecoveryCandidate> candidates(
		std::uint64_t previousGeneration) const;
	bool discardBundle(ObjectId transitionId);
	bool discardAppliedTransitions(std::uint64_t generation);
	bool discardExpiredKeyPackages(std::uint64_t currentTime);
	bool discardJoinOnlyObjects();

	[[nodiscard]] bool loaded() const;
	[[nodiscard]] std::size_t size() const;
	[[nodiscard]] std::uint64_t revision() const;
	[[nodiscard]] auto records() const
	-> const std::vector<StagedGroupChangeEnvelope> &;

private:
	[[nodiscard]] GroupChangeInboxStageResult stageRecord(
		StagedGroupChangeEnvelope record);
	[[nodiscard]] bool persist(
		const std::vector<StagedGroupChangeEnvelope> &records,
		std::uint64_t revision) const;
	[[nodiscard]] bool validEnvelope(
		const TransportEnvelope &envelope) const;

	AtomicBlobStore &_blobStore;
	const LocalRecordProtector &_protector;
	const EnvelopeCodec &_envelopeCodec;
	const Sha256Provider &_sha256;
	ConversationId _conversationId;
	std::vector<StagedGroupChangeEnvelope> _records;
	std::uint64_t _revision = 0;
	bool _loaded = false;
};

class GroupChangeInboxApplier final : public InboundEnvelopeApplier {
public:
	explicit GroupChangeInboxApplier(
		PersistentGroupChangeInbox &inbox,
		const PersistentForkRecoveryLedger *forkLedger = nullptr);

	[[nodiscard]] InboundApplyResult apply(
		const TransportEnvelope &envelope) override;
	[[nodiscard]] InboundRecoveryResult recover(
		const TransportEnvelope &envelope) const override;

private:
	PersistentGroupChangeInbox &_inbox;
	const PersistentForkRecoveryLedger *_forkLedger = nullptr;
};

class OpenMlsGroupChangeEnvelopeAuthenticator final
	: public InboundEnvelopeAuthenticator {
public:
	OpenMlsGroupChangeEnvelopeAuthenticator(
		const MlsContextCodecV1 &contextCodec,
		const GroupControlCodecV1 &controlCodec,
		const PersistentGroupLedger &groupLedger,
		const Sha256Provider &sha256);

	[[nodiscard]] bool authenticate(
		const TransportEnvelope &envelope) const override;

private:
	const MlsContextCodecV1 &_contextCodec;
	const GroupControlCodecV1 &_controlCodec;
	const PersistentGroupLedger &_groupLedger;
	const Sha256Provider &_sha256;
};

} // namespace E2ECloud
