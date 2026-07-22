/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "mtproto/proxy/endpoint_live_pool.h"

#include <algorithm>

namespace MTP::details::MtProxy {
namespace {

constexpr auto kBackgroundMainLiveQuantum = crl::time(60 * 1000);

[[nodiscard]] bool ValidTicketOwner(const LiveSlotTicketOwner &owner) {
	return owner.key.runtimeId && owner.key.ticketId && owner.revision;
}

[[nodiscard]] bool ValidSlotKey(const LiveSlotKey &key) {
	return !key.endpointKey.isEmpty()
		&& key.index >= 0
		&& key.index < kEndpointLiveSlotCount
		&& key.incarnation;
}

[[nodiscard]] bool TicketOwnerMatches(
		const LiveSlotTicketOwner &owner,
		const LiveSlotTicketOwner &expected) {
	return owner == expected;
}

[[nodiscard]] bool AttemptOwnerMatches(
		const LiveSlotAttemptOwner &owner,
		const ProxyConnectionAttempt &attempt) {
	return owner.attempt == attempt;
}

[[nodiscard]] bool AttemptBelongsToTicket(
		const ProxyConnectionAttempt &attempt,
		const LiveSlotTicketOwner &owner) {
	return attempt.runtimeId == owner.key.runtimeId
		&& attempt.ticketId == owner.key.ticketId
		&& attempt.ticketKey == owner.key;
}

[[nodiscard]] bool OpeningOwnerMatches(
		const EndpointOpeningOwner &owner,
		const ProxyConnectionAttempt &expected) {
	const auto attempt = std::get_if<ProxyConnectionAttempt>(&owner);
	return attempt && *attempt == expected;
}

[[nodiscard]] bool SlotKeyMatches(
		const EndpointLiveSlot &slot,
		const LiveSlotKey &key) {
	return ValidSlotKey(key) && slot.incarnation == key.incarnation;
}

[[nodiscard]] EndpointLiveSlot *FindSlot(
		EndpointLivePool &pool,
		const LiveSlotKey &key) {
	if (!ValidSlotKey(key)) {
		return nullptr;
	}
	auto &slot = pool.slots[key.index];
	return SlotKeyMatches(slot, key) ? &slot : nullptr;
}

[[nodiscard]] LiveSlotKey SlotKey(
		const QString &endpointKey,
		int index,
		const EndpointLiveSlot &slot) {
	return {
		.endpointKey = endpointKey,
		.index = index,
		.incarnation = slot.incarnation,
	};
}

[[nodiscard]] uint64 NextIncarnation(uint64 value) {
	const auto next = value + 1;
	return next ? next : 1;
}

[[nodiscard]] bool IsTransfer(EndpointUse use) {
	return use == EndpointUse::Media || use == EndpointUse::Upload;
}

[[nodiscard]] bool ValidRuntimeGeneration(
		const RuntimeGenerationKey &key) {
	return key.runtimeId && key.proxyGeneration;
}

[[nodiscard]] bool ContinuationIdentityValid(
		const DemandTransferContinuation &continuation) {
	return ValidSlotKey(continuation.sourceKey)
		&& ValidTicketOwner(continuation.successor)
		&& ValidRuntimeGeneration(continuation.runtimeGeneration)
		&& IsTransfer(continuation.use)
		&& continuation.successor.key.runtimeId
			== continuation.runtimeGeneration.runtimeId
		&& continuation.sourceAttempt.runtimeId
			== continuation.runtimeGeneration.runtimeId
		&& continuation.sourceAttempt.proxyGeneration
			== continuation.runtimeGeneration.proxyGeneration
		&& continuation.sourceAttempt.use == EndpointUse::Main
		&& continuation.sourceAttempt.attemptId;
}

[[nodiscard]] bool ContinuationSuccessorMatches(
		const DemandTransferContinuation &continuation,
		const QString &endpointKey,
		const LiveSlotTicketOwner &successor,
		RuntimeGenerationKey runtimeGeneration,
		EndpointUse use,
		DemandTransferContinuationStage stage) {
	return ContinuationIdentityValid(continuation)
		&& continuation.sourceKey.endpointKey == endpointKey
		&& continuation.successor == successor
		&& continuation.runtimeGeneration == runtimeGeneration
		&& continuation.use == use
		&& continuation.stage == stage;
}

[[nodiscard]] bool ContinuationSourceMatches(
		const DemandTransferContinuation &continuation,
		const LiveSlotKey &key,
		const ProxyConnectionAttempt &attempt) {
	return continuation.sourceKey == key
		&& continuation.sourceAttempt == attempt;
}

[[nodiscard]] bool ReclaimMatchesContinuation(
		const EndpointReclaim &reclaim,
		const DemandTransferContinuation &continuation) {
	return ContinuationIdentityValid(continuation)
		&& reclaim.key == continuation.sourceKey
		&& reclaim.incumbent == continuation.sourceAttempt
		&& reclaim.successor
		&& *reclaim.successor == continuation.successor;
}

[[nodiscard]] bool TransferAdmissionMatches(
		const EndpointLivePool &pool,
		const QString &endpointKey,
		const LiveSlotTicketOwner &owner,
		RuntimeGenerationKey runtimeGeneration,
		EndpointUse use,
		TransferAdmissionBasis basis) {
	if (!IsTransfer(use)) {
		return basis == TransferAdmissionBasis::None;
	}
	if (!ValidRuntimeGeneration(runtimeGeneration)
		|| runtimeGeneration.runtimeId != owner.key.runtimeId) {
		return false;
	}
	switch (basis) {
	case TransferAdmissionBasis::None:
		return false;
	case TransferAdmissionBasis::MainRelayProof:
		return true;
	case TransferAdmissionBasis::ReleasedContinuation:
		return pool.demandTransferContinuation
			&& ContinuationSuccessorMatches(
				*pool.demandTransferContinuation,
				endpointKey,
				owner,
				runtimeGeneration,
				use,
				DemandTransferContinuationStage::Released);
	}
	return false;
}

[[nodiscard]] bool IsCapacityPressureTerminal(FailureReason reason) {
	switch (reason) {
	case FailureReason::TcpConnectTimeout:
	case FailureReason::ClientHelloSentNoServerHello:
	case FailureReason::ServerHelloOkNoAppData:
	case FailureReason::ServerHelloOkNoMtprotoData:
	case FailureReason::ConnectedNoMtprotoData:
		return true;
	case FailureReason::None:
	case FailureReason::DnsFailed:
	case FailureReason::TcpConnectedNoClientHelloWrite:
	case FailureReason::TlsAlertAfterClientHello:
	case FailureReason::ServerHelloHmacMismatch:
	case FailureReason::AppDataRemoteClosed:
	case FailureReason::MtpReceiveTimeoutAfterData:
	case FailureReason::Network:
	case FailureReason::ProxyProtocolBadResponse:
		return false;
	}
	return false;
}

[[nodiscard]] std::vector<LiveSlotKey> CompleteLiveBaseline(
		const EndpointLivePool &pool,
		const QString &endpointKey) {
	auto result = std::vector<LiveSlotKey>();
	result.reserve(pool.slots.size());
	for (auto index = 0; index != int(pool.slots.size()); ++index) {
		const auto &slot = pool.slots[index];
		if (slot.phase != LiveSlotPhase::Live
			|| !std::get_if<LiveSlotAttemptOwner>(&slot.owner)) {
			continue;
		}
		result.push_back(SlotKey(endpointKey, index, slot));
	}
	std::sort(begin(result), end(result));
	return result;
}

[[nodiscard]] bool CompleteBaselineMatches(
		const EndpointLivePool &pool,
		const CapacityProbe &probe) {
	if (probe.baseline.empty()) {
		return false;
	}
	auto expected = probe.baseline;
	std::sort(begin(expected), end(expected));
	return expected == CompleteLiveBaseline(pool, probe.key.endpointKey);
}

[[nodiscard]] int NonemptySlotCount(const EndpointLivePool &pool) {
	return int(std::count_if(
		begin(pool.slots),
		end(pool.slots),
		[](const EndpointLiveSlot &slot) {
			return slot.phase != LiveSlotPhase::Empty;
		}));
}

[[nodiscard]] int FirstEmptySlot(const EndpointLivePool &pool) {
	const auto i = std::find_if(
		begin(pool.slots),
		end(pool.slots),
		[](const EndpointLiveSlot &slot) {
			return slot.phase == LiveSlotPhase::Empty;
		});
	return (i == end(pool.slots))
		? -1
		: int(i - begin(pool.slots));
}

[[nodiscard]] bool AllSlotsEmpty(const EndpointLivePool &pool) {
	return std::all_of(
		begin(pool.slots),
		end(pool.slots),
		[](const EndpointLiveSlot &slot) {
			return slot.phase == LiveSlotPhase::Empty;
		});
}

[[nodiscard]] bool HasClosingSlot(const EndpointLivePool &pool) {
	return std::any_of(
		begin(pool.slots),
		end(pool.slots),
		[](const EndpointLiveSlot &slot) {
			return slot.phase == LiveSlotPhase::Closing;
		});
}

void ResetLearningIfEmpty(EndpointLivePool &pool) {
	if (!AllSlotsEmpty(pool) || pool.demandTransferContinuation) {
		return;
	}
	pool.provenLowerBound = 0;
	pool.learnedLimit.reset();
	pool.capacityProbe.reset();
	pool.reclaim.reset();
}

[[nodiscard]] bool ReclaimSuccessorMatches(
		const EndpointLivePool &pool,
		const LiveSlotTicketOwner &owner) {
	return pool.reclaim
		&& pool.reclaim->successor
		&& TicketOwnerMatches(*pool.reclaim->successor, owner);
}

[[nodiscard]] bool ContinuationSuccessorMatches(
		const EndpointLivePool &pool,
		const LiveSlotTicketOwner &owner) {
	return pool.demandTransferContinuation
		&& pool.demandTransferContinuation->successor == owner;
}

[[nodiscard]] LivePoolWaitReason ReservationWaitReason(
		const EndpointLivePool &pool,
		const LiveSlotReserveRequest &request) {
	if (pool.reclaim) {
		return ReclaimSuccessorMatches(pool, request.owner)
			? LivePoolWaitReason::Closing
			: LivePoolWaitReason::Slot;
	}
	if (pool.demandTransferContinuation
		&& !ContinuationSuccessorMatches(pool, request.owner)) {
		return LivePoolWaitReason::Slot;
	}
	if (pool.demandTransferContinuation
		&& pool.demandTransferContinuation->stage
			!= DemandTransferContinuationStage::Released) {
		return LivePoolWaitReason::Closing;
	}
	if (pool.opening || !pool.openings.pending.empty()) {
		return LivePoolWaitReason::Slot;
	}
	if (FirstEmptySlot(pool) < 0) {
		return LivePoolWaitReason::Slot;
	}
	const auto occupied = NonemptySlotCount(pool);
	const auto proven = std::clamp(
		pool.provenLowerBound,
		0,
		kEndpointLiveSlotCount);
	if (occupied < proven) {
		return LivePoolWaitReason::None;
	}
	if (!proven && !occupied) {
		return LivePoolWaitReason::None;
	}
	if (pool.learnedLimit && occupied >= *pool.learnedLimit) {
		return LivePoolWaitReason::Capacity;
	}
	if (pool.capacityProbe || proven >= kEndpointLiveSlotCount) {
		return LivePoolWaitReason::Capacity;
	}
	const auto baseline = CompleteLiveBaseline(pool, request.endpointKey);
	return (occupied == proven && int(baseline.size()) == proven)
		? LivePoolWaitReason::None
		: LivePoolWaitReason::Capacity;
}

void ClearMatchingProbe(
		EndpointLivePool &pool,
		const LiveSlotKey &key,
		const ProxyConnectionAttempt &attempt) {
	if (pool.capacityProbe
		&& pool.capacityProbe->key == key
		&& pool.capacityProbe->attempt == attempt) {
		pool.capacityProbe.reset();
	}
}

[[nodiscard]] bool CancelReservationInPlace(
		EndpointLivePool &pool,
		const LiveSlotKey &key,
		const LiveSlotTicketOwner &owner,
		uint64 reservationId) {
	auto slot = FindSlot(pool, key);
	const auto opening = pool.opening
		? std::get_if<LiveSlotTicketOwner>(&*pool.opening)
		: nullptr;
	if (!slot
		|| slot->phase != LiveSlotPhase::Reserved
		|| !opening
		|| !TicketOwnerMatches(*opening, owner)) {
		return false;
	}
	const auto slotOwner = std::get_if<LiveSlotTicketOwner>(&slot->owner);
	if (!slotOwner
		|| !TicketOwnerMatches(*slotOwner, owner)
		|| !reservationId) {
		return false;
	}
	const auto cancelled = CancelOpenSlot(pool.openings, reservationId);
	if (!cancelled.applied) {
		return false;
	}
	pool.openings = cancelled.schedule;
	pool.opening.reset();
	slot->phase = LiveSlotPhase::Empty;
	slot->owner = std::monostate();
	ResetLearningIfEmpty(pool);
	return true;
}

[[nodiscard]] bool CancelKnownReservationInPlace(
		EndpointLivePool &pool,
		const QString &endpointKey,
		const LiveSlotTicketOwner &owner) {
	if (pool.openings.pending.size() != 1) {
		return false;
	}
	for (auto index = 0; index != int(pool.slots.size()); ++index) {
		const auto &slot = pool.slots[index];
		const auto slotOwner = std::get_if<LiveSlotTicketOwner>(&slot.owner);
		if (slot.phase != LiveSlotPhase::Reserved
			|| !slotOwner
			|| !TicketOwnerMatches(*slotOwner, owner)) {
			continue;
		}
		return CancelReservationInPlace(
			pool,
			SlotKey(endpointKey, index, slot),
			owner,
			pool.openings.pending.front().id);
	}
	return false;
}

[[nodiscard]] bool CancelSuccessorInPlace(
		EndpointLivePool &pool,
		const LiveSlotTicketOwner &owner) {
	auto applied = false;
	if (ReclaimSuccessorMatches(pool, owner)) {
		pool.reclaim->successor.reset();
		applied = true;
	}
	if (ContinuationSuccessorMatches(pool, owner)) {
		pool.demandTransferContinuation.reset();
		applied = true;
	}
	if (applied) {
		ResetLearningIfEmpty(pool);
	}
	return applied;
}

[[nodiscard]] LiveSlotCloseReduction BeginClose(
		const EndpointLivePool &pool,
		const LiveSlotCloseRequest &request) {
	auto result = LiveSlotCloseReduction{ .pool = pool };
	auto slot = FindSlot(result.pool, request.key);
	if (!slot
		|| (slot->phase != LiveSlotPhase::Opening
			&& slot->phase != LiveSlotPhase::Live)) {
		return result;
	}
	const auto owner = std::get_if<LiveSlotAttemptOwner>(&slot->owner);
	if (!owner || !AttemptOwnerMatches(*owner, request.attempt)) {
		return result;
	}
	if (request.resumePurpose
		&& (result.pool.reclaim
			|| result.pool.demandTransferContinuation)) {
		result.waitReason = LivePoolWaitReason::Closing;
		return result;
	}
	if (request.successor && !ValidTicketOwner(*request.successor)) {
		return result;
	}
	if (request.successor && !request.resumePurpose) {
		return result;
	}
	slot->phase = LiveSlotPhase::Closing;
	ClearMatchingProbe(result.pool, request.key, request.attempt);
	if (request.resumePurpose) {
		result.pool.reclaim = EndpointReclaim{
			.key = request.key,
			.incumbent = request.attempt,
			.successor = request.successor,
			.stage = EndpointReclaimStage::Requested,
			.continuationRequired = false,
		};
	}
	result.close = LivePoolCloseAction{
		.key = request.key,
		.attempt = request.attempt,
		.resumePurpose = request.resumePurpose,
	};
	result.applied = true;
	return result;
}

[[nodiscard]] bool HasExactMainRelayAttempt(
		const DemandTransferReservationRequest &request,
		const ProxyConnectionAttempt &attempt) {
	return attempt.use == EndpointUse::Main
		&& attempt.runtimeId == request.runtimeGeneration.runtimeId
		&& attempt.proxyGeneration
			== request.runtimeGeneration.proxyGeneration
		&& std::find(
			begin(request.mainRelayAttempts),
			end(request.mainRelayAttempts),
			attempt) != end(request.mainRelayAttempts);
}

[[nodiscard]] int SelectDemandTransferMainVictim(
		const EndpointLivePool &pool,
		const DemandTransferReservationRequest &request,
		bool ownRuntime) {
	for (auto index = 0; index != int(pool.slots.size()); ++index) {
		const auto &slot = pool.slots[index];
		const auto owner = std::get_if<LiveSlotAttemptOwner>(&slot.owner);
		if (slot.phase != LiveSlotPhase::Live
			|| !owner
			|| owner->use != EndpointUse::Main
			|| owner->attempt.runtimeId
				== request.facts.foregroundRuntimeId
			|| (owner->attempt.runtimeId
					== request.successor.key.runtimeId) != ownRuntime
			|| (ownRuntime
				&& !HasExactMainRelayAttempt(request, owner->attempt))) {
			continue;
		}
		return index;
	}
	return -1;
}

[[nodiscard]] int SelectMainReplacementVictim(
		const EndpointLivePool &pool,
		const MainReplacementRequest &request) {
	auto result = -1;
	for (auto index = 0; index != int(pool.slots.size()); ++index) {
		const auto &slot = pool.slots[index];
		const auto owner = std::get_if<LiveSlotAttemptOwner>(&slot.owner);
		if (slot.phase != LiveSlotPhase::Live
			|| !owner
			|| owner->use != EndpointUse::Main
			|| owner->attempt.runtimeId
				== request.facts.foregroundRuntimeId
			|| owner->attempt.runtimeId
				== request.successor.key.runtimeId
			|| (request.purpose == MainReplacementPurpose::BackgroundDuty
				&& owner->liveSince + kBackgroundMainLiveQuantum
					> request.facts.now)) {
			continue;
		}
		if (result < 0) {
			result = index;
			continue;
		}
		const auto &selected = std::get<LiveSlotAttemptOwner>(
			pool.slots[result].owner);
		if (owner->liveSince < selected.liveSince) {
			result = index;
		}
	}
	return result;
}

template <typename Predicate>
[[nodiscard]] LiveSlotsCloseReduction CloseMatchingSlots(
		const EndpointLivePool &pool,
		const QString &endpointKey,
		Predicate predicate) {
	auto result = LiveSlotsCloseReduction{ .pool = pool };
	for (auto index = 0; index != int(result.pool.slots.size()); ++index) {
		auto &slot = result.pool.slots[index];
		if (slot.phase != LiveSlotPhase::Opening
			&& slot.phase != LiveSlotPhase::Live) {
			continue;
		}
		const auto owner = std::get_if<LiveSlotAttemptOwner>(&slot.owner);
		if (!owner || !predicate(owner->attempt)) {
			continue;
		}
		const auto key = SlotKey(endpointKey, index, slot);
		const auto attempt = owner->attempt;
		slot.phase = LiveSlotPhase::Closing;
		ClearMatchingProbe(result.pool, key, attempt);
		result.closes.push_back({
			.key = key,
			.attempt = attempt,
			.resumePurpose = std::nullopt,
		});
		result.applied = true;
	}
	return result;
}

template <typename Predicate>
void ClearMatchingClosingReclaim(
		EndpointLivePool &pool,
		Predicate matches,
		bool &applied) {
	if (!pool.reclaim || !matches(pool.reclaim->incumbent)) {
		return;
	}
	if (pool.demandTransferContinuation
		&& ReclaimMatchesContinuation(
			*pool.reclaim,
			*pool.demandTransferContinuation)) {
		pool.demandTransferContinuation.reset();
	}
	pool.reclaim.reset();
	applied = true;
}

} // namespace

LiveSlotReserveReduction ReserveLiveSlot(
		const EndpointLivePool &pool,
		const LiveSlotReserveRequest &request) {
	auto result = LiveSlotReserveReduction{ .pool = pool };
	if (request.endpointKey.isEmpty()
		|| !ValidTicketOwner(request.owner)
		|| !TransferAdmissionMatches(
			result.pool,
			request.endpointKey,
			request.owner,
			request.runtimeGeneration,
			request.use,
			request.transferAdmissionBasis)) {
		return result;
	}
	result.waitReason = ReservationWaitReason(result.pool, request);
	if (result.waitReason != LivePoolWaitReason::None) {
		return result;
	}
	const auto index = FirstEmptySlot(result.pool);
	if (index < 0) {
		result.waitReason = LivePoolWaitReason::Slot;
		return result;
	}
	const auto reserved = ReserveOpenSlot(
		result.pool.openings,
		{
			.now = request.now,
			.earliestOpenAt = request.earliestOpenAt,
			.spacing = request.spacing,
			.jitter = request.jitter,
		});
	if (!reserved.applied || !reserved.assignment) {
		return result;
	}
	result.pool.openings = reserved.schedule;
	result.pool.lastIncarnation = NextIncarnation(
		result.pool.lastIncarnation);
	auto &slot = result.pool.slots[index];
	slot.phase = LiveSlotPhase::Reserved;
	slot.incarnation = result.pool.lastIncarnation;
	slot.owner = request.owner;
	result.pool.opening = request.owner;
	result.key = SlotKey(request.endpointKey, index, slot);
	result.reservation = reserved.assignment;
	result.applied = true;
	return result;
}

LiveSlotReflowReduction ReflowLiveSlotReservation(
		const EndpointLivePool &pool,
		const LiveSlotReflowRequest &request) {
	auto result = LiveSlotReflowReduction{ .pool = pool };
	const auto slot = FindSlot(result.pool, request.key);
	const auto opening = result.pool.opening
		? std::get_if<LiveSlotTicketOwner>(&*result.pool.opening)
		: nullptr;
	const auto owner = slot
		? std::get_if<LiveSlotTicketOwner>(&slot->owner)
		: nullptr;
	if (!slot
		|| slot->phase != LiveSlotPhase::Reserved
		|| !opening
		|| !owner
		|| !TicketOwnerMatches(*opening, request.owner)
		|| !TicketOwnerMatches(*owner, request.owner)
		|| !request.reservationId) {
		return result;
	}
	const auto requests = std::vector<OpenSlotReflowRequest>{
		{
			.id = request.reservationId,
			.earliestOpenAt = request.earliestOpenAt,
			.spacing = request.spacing,
			.jitter = request.jitter,
		},
	};
	const auto reflowed = ReflowOpenSlots(
		result.pool.openings,
		requests,
		request.now);
	if (!reflowed.applied || reflowed.assignments.size() != 1) {
		return result;
	}
	result.pool.openings = reflowed.schedule;
	result.reservation = reflowed.assignments.front();
	result.applied = true;
	return result;
}

LiveSlotCancelReduction CancelLiveSlotReservation(
		const EndpointLivePool &pool,
		const LiveSlotReservationCancelRequest &request) {
	auto result = LiveSlotCancelReduction{ .pool = pool };
	const auto reservation = CancelReservationInPlace(
		result.pool,
		request.key,
		request.owner,
		request.reservationId);
	const auto continuation = reservation
		&& ContinuationSuccessorMatches(result.pool, request.owner);
	if (continuation) {
		result.pool.demandTransferContinuation.reset();
		ResetLearningIfEmpty(result.pool);
	}
	result.applied = reservation || continuation;
	return result;
}

LiveSlotCancelReduction CancelLiveSlotSuccessor(
		const EndpointLivePool &pool,
		const LiveSlotSuccessorCancelRequest &request) {
	auto result = LiveSlotCancelReduction{ .pool = pool };
	result.applied = CancelSuccessorInPlace(result.pool, request.owner);
	return result;
}

LiveSlotCommitReduction CommitLiveSlotOpening(
		const EndpointLivePool &pool,
		const LiveSlotCommitRequest &request) {
	auto result = LiveSlotCommitReduction{ .pool = pool };
	auto slot = FindSlot(result.pool, request.key);
	const auto opening = result.pool.opening
		? std::get_if<LiveSlotTicketOwner>(&*result.pool.opening)
		: nullptr;
	const auto owner = slot
		? std::get_if<LiveSlotTicketOwner>(&slot->owner)
		: nullptr;
	if (!slot
		|| slot->phase != LiveSlotPhase::Reserved
		|| !opening
		|| !owner
		|| !TicketOwnerMatches(*opening, request.owner)
		|| !TicketOwnerMatches(*owner, request.owner)
		|| !AttemptBelongsToTicket(request.attempt, request.owner)
		|| request.use != request.attempt.use
		|| (IsTransfer(request.use)
			&& (request.attempt.runtimeId
					!= request.runtimeGeneration.runtimeId
				|| request.attempt.proxyGeneration
					!= request.runtimeGeneration.proxyGeneration))
		|| !TransferAdmissionMatches(
			result.pool,
			request.key.endpointKey,
			request.owner,
			request.runtimeGeneration,
			request.use,
			request.transferAdmissionBasis)
		|| !request.reservationId) {
		return result;
	}
	const auto committed = CommitOpenSlot(
		result.pool.openings,
		request.reservationId);
	if (!committed.applied) {
		return result;
	}
	const auto occupiedBefore = NonemptySlotCount(result.pool) - 1;
	const auto baseline = CompleteLiveBaseline(
		result.pool,
		request.key.endpointKey);
	const auto target = result.pool.provenLowerBound + 1;
	const auto continuationAdmission = request.transferAdmissionBasis
		== TransferAdmissionBasis::ReleasedContinuation;
	const auto expansion = !continuationAdmission
		&& result.pool.provenLowerBound > 0
		&& target <= kEndpointLiveSlotCount
		&& occupiedBefore == result.pool.provenLowerBound
		&& int(baseline.size()) == result.pool.provenLowerBound
		&& !result.pool.capacityProbe
		&& (!result.pool.learnedLimit
			|| target <= *result.pool.learnedLimit);
	result.pool.openings = committed.schedule;
	slot->phase = LiveSlotPhase::Opening;
	slot->owner = LiveSlotAttemptOwner{
		.attempt = request.attempt,
		.use = request.use,
		.liveSince = 0,
	};
	result.pool.opening = request.attempt;
	if (continuationAdmission) {
		result.pool.demandTransferContinuation.reset();
	}
	if (expansion) {
		result.pool.capacityProbe = CapacityProbe{
			.key = request.key,
			.attempt = request.attempt,
			.target = target,
			.baseline = baseline,
		};
	}
	result.applied = true;
	return result;
}

LiveSlotRelayReadyReduction MarkLiveSlotRelayReady(
		const EndpointLivePool &pool,
		const LiveSlotRelayReadyRequest &request) {
	auto result = LiveSlotRelayReadyReduction{ .pool = pool };
	auto slot = FindSlot(result.pool, request.key);
	const auto opening = result.pool.opening
		? std::get_if<ProxyConnectionAttempt>(&*result.pool.opening)
		: nullptr;
	const auto owner = slot
		? std::get_if<LiveSlotAttemptOwner>(&slot->owner)
		: nullptr;
	if (!slot
		|| slot->phase != LiveSlotPhase::Opening
		|| !opening
		|| !owner
		|| *opening != request.attempt
		|| !AttemptOwnerMatches(*owner, request.attempt)) {
		return result;
	}
	const auto probeMatches = result.pool.capacityProbe
		&& result.pool.capacityProbe->key == request.key
		&& result.pool.capacityProbe->attempt == request.attempt;
	const auto stableProbe = probeMatches
		&& result.pool.capacityProbe->target
			== result.pool.provenLowerBound + 1
		&& CompleteBaselineMatches(
			result.pool,
			*result.pool.capacityProbe);
	const auto bootstrap = !result.pool.provenLowerBound
		&& CompleteLiveBaseline(
			result.pool,
			request.key.endpointKey).empty();
	slot->phase = LiveSlotPhase::Live;
	owner->liveSince = request.now;
	result.pool.opening.reset();
	if (stableProbe) {
		result.pool.provenLowerBound = result.pool.capacityProbe->target;
	} else if (bootstrap) {
		result.pool.provenLowerBound = 1;
	}
	if (probeMatches) {
		result.pool.capacityProbe.reset();
	}
	result.applied = true;
	return result;
}

LiveSlotTerminalReduction MarkLiveSlotCapacityTerminal(
		const EndpointLivePool &pool,
		const LiveSlotTerminalRequest &request) {
	auto result = LiveSlotTerminalReduction{ .pool = pool };
	if (!request.finalEndpointTerminal
		|| !IsCapacityPressureTerminal(request.reason)) {
		return result;
	}
	auto slot = FindSlot(result.pool, request.key);
	const auto owner = slot
		? std::get_if<LiveSlotAttemptOwner>(&slot->owner)
		: nullptr;
	if (slot
		&& slot->phase == LiveSlotPhase::Closing
		&& owner
		&& AttemptOwnerMatches(*owner, request.attempt)
		&& result.pool.demandTransferContinuation
		&& result.pool.demandTransferContinuation->stage
			!= DemandTransferContinuationStage::Released
		&& ContinuationSourceMatches(
			*result.pool.demandTransferContinuation,
			request.key,
			request.attempt)) {
		result.pool.demandTransferContinuation.reset();
		ResetLearningIfEmpty(result.pool);
		result.applied = true;
		return result;
	}
	const auto opening = result.pool.opening
		? std::get_if<ProxyConnectionAttempt>(&*result.pool.opening)
		: nullptr;
	if (!slot
		|| slot->phase != LiveSlotPhase::Opening
		|| !opening
		|| !owner
		|| *opening != request.attempt
		|| !AttemptOwnerMatches(*owner, request.attempt)) {
		return result;
	}
	const auto probeMatches = result.pool.capacityProbe
		&& result.pool.capacityProbe->key == request.key
		&& result.pool.capacityProbe->attempt == request.attempt;
	const auto stableProbe = probeMatches
		&& result.pool.capacityProbe->target
			== result.pool.provenLowerBound + 1
		&& int(result.pool.capacityProbe->baseline.size())
			== result.pool.provenLowerBound
		&& CompleteBaselineMatches(
			result.pool,
			*result.pool.capacityProbe);
	if (stableProbe && request.attempt.use == EndpointUse::Main) {
		result.pool.learnedLimit = int(
			result.pool.capacityProbe->baseline.size());
	}
	if (probeMatches) {
		result.pool.capacityProbe.reset();
	}
	slot->phase = LiveSlotPhase::Closing;
	result.applied = true;
	return result;
}

LiveSlotCloseReduction BeginLiveSlotClose(
		const EndpointLivePool &pool,
		const LiveSlotCloseRequest &request) {
	return BeginClose(pool, request);
}

auto AuthorizeLiveSlotReclaim(
		const EndpointLivePool &pool,
		const LiveSlotReclaimAuthorizationRequest &request)
-> LiveSlotReclaimAuthorizationReduction {
	auto result = LiveSlotReclaimAuthorizationReduction{
		.pool = pool,
	};
	const auto slot = FindSlot(result.pool, request.key);
	const auto owner = slot
		? std::get_if<LiveSlotAttemptOwner>(&slot->owner)
		: nullptr;
	const auto reclaim = result.pool.reclaim
		? &*result.pool.reclaim
		: nullptr;
	if (!slot
		|| slot->phase != LiveSlotPhase::Closing
		|| !owner
		|| !AttemptOwnerMatches(*owner, request.attempt)
		|| !reclaim
		|| reclaim->stage != EndpointReclaimStage::Requested
		|| reclaim->key != request.key
		|| reclaim->incumbent != request.attempt) {
		return result;
	}
	const auto continuation = result.pool.demandTransferContinuation
		? &*result.pool.demandTransferContinuation
		: nullptr;
	const auto continuationMatches = continuation
		&& continuation->stage
			== DemandTransferContinuationStage::Requested
		&& ReclaimMatchesContinuation(*reclaim, *continuation);
	const auto authorized = request.callbackReady
		&& request.attempt.runtimeId != request.foregroundRuntimeId
		&& reclaim->successor
		&& (!reclaim->continuationRequired || continuationMatches)
		&& (!continuation || continuationMatches);
	if (authorized) {
		result.pool.reclaim->stage = EndpointReclaimStage::Authorized;
		if (continuationMatches) {
			result.pool.demandTransferContinuation->stage
				= DemandTransferContinuationStage::AwaitingRelease;
		}
		result.authorized = true;
	} else {
		slot->phase = LiveSlotPhase::Live;
		if (continuationMatches
			|| (continuation
				&& ContinuationSourceMatches(
					*continuation,
					request.key,
					request.attempt))) {
			result.pool.demandTransferContinuation.reset();
		}
		result.pool.reclaim.reset();
		ResetLearningIfEmpty(result.pool);
	}
	result.applied = true;
	return result;
}

auto PlanDemandTransferReservation(
		const EndpointLivePool &pool,
		const DemandTransferReservationRequest &request)
-> DemandTransferReservationReduction {
	auto result = DemandTransferReservationReduction{ .pool = pool };
	if (request.endpointKey.isEmpty()
		|| !ValidTicketOwner(request.successor)
		|| !IsTransfer(request.use)
		|| !request.facts.admissibleTransferWaiting
		|| !TransferAdmissionMatches(
			result.pool,
			request.endpointKey,
			request.successor,
			request.runtimeGeneration,
			request.use,
			request.transferAdmissionBasis)) {
		return result;
	}
	const auto reservationWait = ReservationWaitReason(
		result.pool,
		{
			.endpointKey = request.endpointKey,
			.owner = request.successor,
			.use = request.use,
			.runtimeGeneration = request.runtimeGeneration,
			.transferAdmissionBasis = request.transferAdmissionBasis,
			.now = request.facts.now,
		});
	result.waitReason = reservationWait;
	if (result.pool.reclaim || HasClosingSlot(result.pool)) {
		result.waitReason = LivePoolWaitReason::Closing;
		return result;
	}
	if (result.pool.opening || !result.pool.openings.pending.empty()) {
		result.waitReason = LivePoolWaitReason::Slot;
		return result;
	}
	if (request.transferAdmissionBasis
			== TransferAdmissionBasis::ReleasedContinuation) {
		if (reservationWait == LivePoolWaitReason::None) {
			result.action = DemandTransferReservationAction::Reserve;
		}
		return result;
	}
	if (request.transferAdmissionBasis
			!= TransferAdmissionBasis::MainRelayProof
		|| result.pool.demandTransferContinuation) {
		return result;
	}
	const auto occupied = NonemptySlotCount(result.pool);
	const auto proven = std::clamp(
		result.pool.provenLowerBound,
		0,
		kEndpointLiveSlotCount);
	const auto bootstrap = !proven && !occupied;
	const auto replenishment = occupied < proven;
	const auto baseline = CompleteLiveBaseline(
		result.pool,
		request.endpointKey);
	const auto stableFrontier = proven > 0
		&& occupied == proven
		&& FirstEmptySlot(result.pool) >= 0
		&& int(baseline.size()) == proven;
	if (reservationWait == LivePoolWaitReason::None
		&& (bootstrap || replenishment)) {
		result.action = DemandTransferReservationAction::Reserve;
		return result;
	}
	if (reservationWait == LivePoolWaitReason::None && !stableFrontier) {
		result.waitReason = LivePoolWaitReason::Slot;
		return result;
	}
	if (reservationWait != LivePoolWaitReason::None
		&& reservationWait != LivePoolWaitReason::Slot
		&& reservationWait != LivePoolWaitReason::Capacity) {
		return result;
	}
	auto ownRuntime = false;
	auto victim = SelectDemandTransferMainVictim(
		result.pool,
		request,
		false);
	if (victim < 0) {
		victim = SelectDemandTransferMainVictim(
			result.pool,
			request,
			true);
		ownRuntime = (victim >= 0);
	}
	if (victim < 0) {
		if (reservationWait == LivePoolWaitReason::None) {
			result.action = DemandTransferReservationAction::Reserve;
		}
		return result;
	}
	const auto &slot = result.pool.slots[victim];
	const auto &owner = std::get<LiveSlotAttemptOwner>(slot.owner);
	const auto close = BeginClose(
		result.pool,
		{
			.key = SlotKey(request.endpointKey, victim, slot),
			.attempt = owner.attempt,
			.successor = request.successor,
			.resumePurpose = AdmissionPurpose::ReclaimedMainResume,
		});
	if (!close.applied || !close.close) {
		result.waitReason = (reservationWait == LivePoolWaitReason::None)
			? LivePoolWaitReason::Slot
			: reservationWait;
		return result;
	}
	result.pool = close.pool;
	if (ownRuntime) {
		result.pool.reclaim->continuationRequired = true;
		result.pool.demandTransferContinuation
			= DemandTransferContinuation{
				.sourceKey = close.close->key,
				.sourceAttempt = close.close->attempt,
				.successor = request.successor,
				.runtimeGeneration = request.runtimeGeneration,
				.use = request.use,
				.stage = DemandTransferContinuationStage::Requested,
			};
	}
	result.action = DemandTransferReservationAction::Reclaim;
	result.close = close.close;
	return result;
}

LiveSlotCloseReduction PlanMainReplacement(
		const EndpointLivePool &pool,
		const MainReplacementRequest &request) {
	auto result = LiveSlotCloseReduction{ .pool = pool };
	if (request.endpointKey.isEmpty()
		|| !ValidTicketOwner(request.successor)
		|| (request.purpose == MainReplacementPurpose::ForegroundRecovery
			&& request.successor.key.runtimeId
				!= request.facts.foregroundRuntimeId)
		|| (request.purpose != MainReplacementPurpose::ForegroundRecovery
			&& request.successor.key.runtimeId
				== request.facts.foregroundRuntimeId)
		|| (request.purpose == MainReplacementPurpose::BackgroundDuty
			&& (request.facts.admissibleTransferWaiting
				|| request.facts.transferActive))
		|| result.pool.opening
		|| result.pool.reclaim
		|| result.pool.demandTransferContinuation
		|| HasClosingSlot(result.pool)) {
		return result;
	}
	const auto wait = ReservationWaitReason(
		result.pool,
		{
			.endpointKey = request.endpointKey,
			.owner = request.successor,
			.use = EndpointUse::Main,
			.now = request.facts.now,
		});
	const auto occupied = NonemptySlotCount(result.pool);
	const auto proven = std::clamp(
		result.pool.provenLowerBound,
		0,
		kEndpointLiveSlotCount);
	const auto baseline = CompleteLiveBaseline(
		result.pool,
		request.endpointKey);
	if ((wait != LivePoolWaitReason::Slot
			&& wait != LivePoolWaitReason::Capacity)
		|| !proven
		|| occupied != proven
		|| int(baseline.size()) != proven) {
		return result;
	}
	const auto victim = SelectMainReplacementVictim(result.pool, request);
	if (victim < 0) {
		return result;
	}
	const auto &slot = result.pool.slots[victim];
	const auto &owner = std::get<LiveSlotAttemptOwner>(slot.owner);
	return BeginClose(
		result.pool,
		{
			.key = SlotKey(request.endpointKey, victim, slot),
			.attempt = owner.attempt,
			.successor = request.successor,
			.resumePurpose = AdmissionPurpose::ReclaimedMainResume,
		});
}

LiveSlotsCloseReduction CloseRuntimeLiveSlots(
		const EndpointLivePool &pool,
		const LiveSlotsRuntimeCloseRequest &request) {
	auto result = LiveSlotsCloseReduction{ .pool = pool };
	if (request.endpointKey.isEmpty() || !request.runtimeId) {
		return result;
	}
	const auto ticket = result.pool.opening
		? std::get_if<LiveSlotTicketOwner>(&*result.pool.opening)
		: nullptr;
	if (ticket && ticket->key.runtimeId == request.runtimeId) {
		result.applied = CancelKnownReservationInPlace(
			result.pool,
			request.endpointKey,
			*ticket);
	}
	if (result.pool.reclaim
		&& result.pool.reclaim->successor
		&& result.pool.reclaim->successor->key.runtimeId
			== request.runtimeId) {
		result.pool.reclaim->successor.reset();
		result.applied = true;
	}
	if (result.pool.demandTransferContinuation
		&& (result.pool.demandTransferContinuation
				->runtimeGeneration.runtimeId == request.runtimeId
			|| result.pool.demandTransferContinuation
				->sourceAttempt.runtimeId == request.runtimeId
			|| result.pool.demandTransferContinuation
				->successor.key.runtimeId == request.runtimeId)) {
		result.pool.demandTransferContinuation.reset();
		result.applied = true;
	}
	const auto closed = CloseMatchingSlots(
		result.pool,
		request.endpointKey,
		[&](const ProxyConnectionAttempt &attempt) {
			return attempt.runtimeId == request.runtimeId;
		});
	result.pool = closed.pool;
	result.closes = closed.closes;
	result.applied = result.applied || closed.applied;
	ClearMatchingClosingReclaim(
		result.pool,
		[&](const ProxyConnectionAttempt &attempt) {
			return attempt.runtimeId == request.runtimeId;
		},
		result.applied);
	ResetLearningIfEmpty(result.pool);
	return result;
}

LiveSlotsCloseReduction CloseLiveSlotsBeforeGeneration(
		const EndpointLivePool &pool,
		const LiveSlotsBeforeGenerationCloseRequest &request) {
	auto result = LiveSlotsCloseReduction{ .pool = pool };
	if (request.endpointKey.isEmpty()
		|| !request.runtimeId
		|| !request.proxyGeneration) {
		return result;
	}
	for (const auto &owner : request.cancelledTickets) {
		if (owner.key.runtimeId != request.runtimeId) {
			continue;
		}
		result.applied = CancelSuccessorInPlace(result.pool, owner)
			|| result.applied;
		result.applied = CancelKnownReservationInPlace(
			result.pool,
			request.endpointKey,
			owner) || result.applied;
	}
	if (result.pool.demandTransferContinuation) {
		const auto &continuation = *result.pool.demandTransferContinuation;
		if ((continuation.runtimeGeneration.runtimeId == request.runtimeId
				&& continuation.runtimeGeneration.proxyGeneration
					< request.proxyGeneration)
			|| (continuation.sourceAttempt.runtimeId == request.runtimeId
				&& continuation.sourceAttempt.proxyGeneration
					< request.proxyGeneration)) {
			result.pool.demandTransferContinuation.reset();
			result.applied = true;
		}
	}
	const auto matches = [&](const ProxyConnectionAttempt &attempt) {
		return attempt.runtimeId == request.runtimeId
			&& attempt.proxyGeneration < request.proxyGeneration;
	};
	const auto closed = CloseMatchingSlots(
		result.pool,
		request.endpointKey,
		matches);
	result.pool = closed.pool;
	result.closes = closed.closes;
	result.applied = result.applied || closed.applied;
	ClearMatchingClosingReclaim(
		result.pool,
		matches,
		result.applied);
	ResetLearningIfEmpty(result.pool);
	return result;
}

LiveSlotReleaseReduction ReleaseLiveSlot(
		const EndpointLivePool &pool,
		const LiveSlotReleaseRequest &request) {
	auto result = LiveSlotReleaseReduction{ .pool = pool };
	auto slot = FindSlot(result.pool, request.key);
	if (!slot
		|| (slot->phase != LiveSlotPhase::Opening
			&& slot->phase != LiveSlotPhase::Live
			&& slot->phase != LiveSlotPhase::Closing)) {
		return result;
	}
	const auto owner = std::get_if<LiveSlotAttemptOwner>(&slot->owner);
	if (!owner || !AttemptOwnerMatches(*owner, request.attempt)) {
		return result;
	}
	const auto reclaimMatches = result.pool.reclaim
		&& result.pool.reclaim->key == request.key
		&& result.pool.reclaim->incumbent == request.attempt;
	const auto authorizedReclaim = reclaimMatches
		&& result.pool.reclaim->stage == EndpointReclaimStage::Authorized;
	const auto continuationSourceMatches
		= result.pool.demandTransferContinuation
		&& result.pool.demandTransferContinuation->stage
			!= DemandTransferContinuationStage::Released
		&& ContinuationSourceMatches(
			*result.pool.demandTransferContinuation,
			request.key,
			request.attempt);
	const auto continuationReclaimMatches = authorizedReclaim
		&& continuationSourceMatches
		&& result.pool.demandTransferContinuation->stage
			== DemandTransferContinuationStage::AwaitingRelease
		&& ReclaimMatchesContinuation(
			*result.pool.reclaim,
			*result.pool.demandTransferContinuation);
	if (result.pool.opening
		&& OpeningOwnerMatches(*result.pool.opening, request.attempt)) {
		result.pool.opening.reset();
	}
	ClearMatchingProbe(result.pool, request.key, request.attempt);
	if (reclaimMatches) {
		if (continuationReclaimMatches
			&& result.pool.reclaim->continuationRequired) {
			result.pool.demandTransferContinuation->stage
				= DemandTransferContinuationStage::Released;
			result.successor = result.pool.reclaim->successor;
			result.continuationChanged = true;
		} else if (continuationSourceMatches) {
			result.pool.demandTransferContinuation.reset();
			result.continuationChanged = true;
		} else if (authorizedReclaim
			&& !result.pool.reclaim->continuationRequired
			&& !result.pool.demandTransferContinuation) {
			result.successor = result.pool.reclaim->successor;
		}
		result.pool.reclaim.reset();
	} else if (continuationSourceMatches) {
		result.pool.demandTransferContinuation.reset();
		result.continuationChanged = true;
	}
	if (slot->phase != LiveSlotPhase::Closing) {
		slot->phase = LiveSlotPhase::Closing;
	}
	slot->phase = LiveSlotPhase::Empty;
	slot->owner = std::monostate();
	ResetLearningIfEmpty(result.pool);
	result.slotReleased = true;
	return result;
}

std::optional<crl::time> NextLivePoolWakeAt(
		const EndpointLivePool &pool,
		const LivePoolSelectionFacts &facts,
		bool backgroundDutyWaiting) {
	if (!backgroundDutyWaiting
		|| facts.admissibleTransferWaiting
		|| facts.transferActive
		|| pool.opening
		|| pool.reclaim
		|| HasClosingSlot(pool)) {
		return std::nullopt;
	}
	auto result = std::optional<crl::time>();
	for (const auto &slot : pool.slots) {
		const auto owner = std::get_if<LiveSlotAttemptOwner>(&slot.owner);
		if (slot.phase != LiveSlotPhase::Live
			|| !owner
			|| owner->use != EndpointUse::Main
			|| owner->attempt.runtimeId == facts.foregroundRuntimeId) {
			continue;
		}
		const auto deadline = owner->liveSince
			+ kBackgroundMainLiveQuantum;
		if (!result || deadline < *result) {
			result = deadline;
		}
	}
	return result;
}

} // namespace MTP::details::MtProxy
