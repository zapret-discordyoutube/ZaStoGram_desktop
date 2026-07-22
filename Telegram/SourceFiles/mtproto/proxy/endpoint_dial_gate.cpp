/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "mtproto/proxy/endpoint_dial_gate.h"

namespace MTP::details::MtProxy {
namespace {

[[nodiscard]] bool ValidTicketOwner(const DialSlotTicketOwner &owner) {
	return owner.key.runtimeId && owner.key.ticketId && owner.revision;
}

[[nodiscard]] bool ValidSlotKey(const DialSlotKey &key) {
	return !key.endpointKey.isEmpty() && key.incarnation;
}

[[nodiscard]] bool TicketOwnerMatches(
		const DialSlotTicketOwner &owner,
		const DialSlotTicketOwner &expected) {
	return owner == expected;
}

[[nodiscard]] bool AttemptOwnerMatches(
		const DialSlotAttemptOwner &owner,
		const ProxyConnectionAttempt &attempt) {
	return owner.attempt == attempt;
}

[[nodiscard]] bool AttemptBelongsToTicket(
		const ProxyConnectionAttempt &attempt,
		const DialSlotTicketOwner &owner) {
	return attempt.runtimeId == owner.key.runtimeId
		&& attempt.ticketId == owner.key.ticketId
		&& attempt.ticketKey == owner.key;
}

[[nodiscard]] bool SlotKeyMatches(
		const EndpointDialSlot &slot,
		const DialSlotKey &key) {
	return ValidSlotKey(key) && slot.incarnation == key.incarnation;
}

[[nodiscard]] EndpointDialSlot *FindSlot(
		EndpointDialGate &gate,
		const DialSlotKey &key) {
	if (!ValidSlotKey(key)) {
		return nullptr;
	}
	auto &slot = gate.slot;
	return SlotKeyMatches(slot, key) ? &slot : nullptr;
}

[[nodiscard]] DialSlotKey SlotKey(
		const QString &endpointKey,
		const EndpointDialSlot &slot) {
	return {
		.endpointKey = endpointKey,
		.incarnation = slot.incarnation,
	};
}

[[nodiscard]] uint64 NextIncarnation(uint64 value) {
	const auto next = value + 1;
	return next ? next : 1;
}

[[nodiscard]] DialGateWaitReason ReservationWaitReason(
		const EndpointDialGate &gate) {
	return (gate.openings.pending.empty()
		&& gate.slot.phase == DialSlotPhase::Empty)
		? DialGateWaitReason::None
		: DialGateWaitReason::Slot;
}

[[nodiscard]] bool CancelReservationInPlace(
		EndpointDialGate &gate,
		const DialSlotKey &key,
		const DialSlotTicketOwner &owner,
		uint64 reservationId) {
	auto slot = FindSlot(gate, key);
	const auto slotOwner = slot
		? std::get_if<DialSlotTicketOwner>(&slot->owner)
		: nullptr;
	if (!slot
		|| slot->phase != DialSlotPhase::Reserved
		|| !slotOwner
		|| !TicketOwnerMatches(*slotOwner, owner)
		|| !reservationId) {
		return false;
	}
	const auto cancelled = CancelOpenSlot(gate.openings, reservationId);
	if (!cancelled.applied) {
		return false;
	}
	gate.openings = cancelled.schedule;
	slot->phase = DialSlotPhase::Empty;
	slot->owner = std::monostate();
	return true;
}

[[nodiscard]] bool CancelKnownReservationInPlace(
		EndpointDialGate &gate,
		const QString &endpointKey,
		const DialSlotTicketOwner &owner) {
	if (gate.openings.pending.size() != 1) {
		return false;
	}
	const auto slotOwner = std::get_if<DialSlotTicketOwner>(
		&gate.slot.owner);
	if (gate.slot.phase != DialSlotPhase::Reserved
		|| !slotOwner
		|| !TicketOwnerMatches(*slotOwner, owner)) {
		return false;
	}
	return CancelReservationInPlace(
		gate,
		SlotKey(endpointKey, gate.slot),
		owner,
		gate.openings.pending.front().id);
}

template <typename Predicate>
[[nodiscard]] bool ReleaseOpeningInPlace(
		EndpointDialGate &gate,
		Predicate predicate) {
	auto &slot = gate.slot;
	const auto owner = std::get_if<DialSlotAttemptOwner>(&slot.owner);
	if (slot.phase != DialSlotPhase::Opening
		|| !owner
		|| !predicate(owner->attempt)) {
		return false;
	}
	slot.phase = DialSlotPhase::Empty;
	slot.owner = std::monostate();
	return true;
}

} // namespace

DialSlotReserveReduction ReserveDialSlot(
		const EndpointDialGate &gate,
		const DialSlotReserveRequest &request) {
	auto result = DialSlotReserveReduction{ .gate = gate };
	if (request.endpointKey.isEmpty()
		|| !ValidTicketOwner(request.owner)) {
		return result;
	}
	result.waitReason = ReservationWaitReason(result.gate);
	if (result.waitReason != DialGateWaitReason::None) {
		return result;
	}
	const auto reserved = ReserveOpenSlot(
		result.gate.openings,
		{
			.now = request.now,
			.earliestOpenAt = request.earliestOpenAt,
			.spacing = request.spacing,
			.jitter = request.jitter,
		});
	if (!reserved.applied || !reserved.assignment) {
		return result;
	}
	result.gate.openings = reserved.schedule;
	result.gate.lastIncarnation = NextIncarnation(
		result.gate.lastIncarnation);
	auto &slot = result.gate.slot;
	slot.phase = DialSlotPhase::Reserved;
	slot.incarnation = result.gate.lastIncarnation;
	slot.owner = request.owner;
	result.key = SlotKey(request.endpointKey, slot);
	result.reservation = reserved.assignment;
	result.applied = true;
	return result;
}

DialSlotReflowReduction ReflowDialSlotReservation(
		const EndpointDialGate &gate,
		const DialSlotReflowRequest &request) {
	auto result = DialSlotReflowReduction{ .gate = gate };
	const auto slot = FindSlot(result.gate, request.key);
	const auto owner = slot
		? std::get_if<DialSlotTicketOwner>(&slot->owner)
		: nullptr;
	if (!slot
		|| slot->phase != DialSlotPhase::Reserved
		|| !owner
		|| !TicketOwnerMatches(*owner, request.owner)
		|| !request.reservationId) {
		return result;
	}
	const auto reflowed = ReflowOpenSlots(
		result.gate.openings,
		{
			{
				.id = request.reservationId,
				.earliestOpenAt = request.earliestOpenAt,
				.spacing = request.spacing,
				.jitter = request.jitter,
			},
		},
		request.now);
	if (!reflowed.applied || reflowed.assignments.size() != 1) {
		return result;
	}
	result.gate.openings = reflowed.schedule;
	result.reservation = reflowed.assignments.front();
	result.applied = true;
	return result;
}

DialSlotCancelReduction CancelDialSlotReservation(
		const EndpointDialGate &gate,
		const DialSlotReservationCancelRequest &request) {
	auto result = DialSlotCancelReduction{ .gate = gate };
	result.applied = CancelReservationInPlace(
		result.gate,
		request.key,
		request.owner,
		request.reservationId);
	return result;
}

DialSlotCommitReduction CommitDialSlotOpening(
		const EndpointDialGate &gate,
		const DialSlotCommitRequest &request) {
	auto result = DialSlotCommitReduction{ .gate = gate };
	auto slot = FindSlot(result.gate, request.key);
	const auto owner = slot
		? std::get_if<DialSlotTicketOwner>(&slot->owner)
		: nullptr;
	if (!slot
		|| slot->phase != DialSlotPhase::Reserved
		|| !owner
		|| !TicketOwnerMatches(*owner, request.owner)
		|| !AttemptBelongsToTicket(request.attempt, request.owner)
		|| !request.reservationId) {
		return result;
	}
	const auto committed = CommitOpenSlot(
		result.gate.openings,
		request.reservationId);
	if (!committed.applied) {
		return result;
	}
	result.gate.openings = committed.schedule;
	slot->phase = DialSlotPhase::Opening;
	slot->owner = DialSlotAttemptOwner{
		.attempt = request.attempt,
	};
	result.applied = true;
	return result;
}

DialSlotRelayReadyReduction MarkDialSlotRelayReady(
		const EndpointDialGate &gate,
		const DialSlotRelayReadyRequest &request) {
	auto result = DialSlotRelayReadyReduction{ .gate = gate };
	auto slot = FindSlot(result.gate, request.key);
	const auto owner = slot
		? std::get_if<DialSlotAttemptOwner>(&slot->owner)
		: nullptr;
	if (!slot
		|| slot->phase != DialSlotPhase::Opening
		|| !owner
		|| !AttemptOwnerMatches(*owner, request.attempt)) {
		return result;
	}
	slot->phase = DialSlotPhase::Empty;
	slot->owner = std::monostate();
	result.applied = true;
	return result;
}

DialSlotTerminalReduction MarkDialSlotOpeningTerminal(
		const EndpointDialGate &gate,
		const DialSlotTerminalRequest &request) {
	auto result = DialSlotTerminalReduction{ .gate = gate };
	if (!request.finalEndpointTerminal) {
		return result;
	}
	auto slot = FindSlot(result.gate, request.key);
	const auto owner = slot
		? std::get_if<DialSlotAttemptOwner>(&slot->owner)
		: nullptr;
	if (!slot
		|| slot->phase != DialSlotPhase::Opening
		|| !owner
		|| !AttemptOwnerMatches(*owner, request.attempt)) {
		return result;
	}
	slot->phase = DialSlotPhase::Empty;
	slot->owner = std::monostate();
	result.applied = true;
	return result;
}

DialSlotsCloseReduction CloseRuntimeDialSlots(
		const EndpointDialGate &gate,
		const DialSlotsRuntimeCloseRequest &request) {
	auto result = DialSlotsCloseReduction{ .gate = gate };
	if (request.endpointKey.isEmpty() || !request.runtimeId) {
		return result;
	}
	const auto ticket = std::get_if<DialSlotTicketOwner>(
		&result.gate.slot.owner);
	if (ticket && ticket->key.runtimeId == request.runtimeId) {
		result.applied = CancelKnownReservationInPlace(
			result.gate,
			request.endpointKey,
			*ticket);
	}
	result.applied = ReleaseOpeningInPlace(
		result.gate,
		[&](const ProxyConnectionAttempt &attempt) {
			return attempt.runtimeId == request.runtimeId;
		}) || result.applied;
	return result;
}

DialSlotsCloseReduction CloseDialSlotsBeforeGeneration(
		const EndpointDialGate &gate,
		const DialSlotsBeforeGenerationCloseRequest &request) {
	auto result = DialSlotsCloseReduction{ .gate = gate };
	if (request.endpointKey.isEmpty()
		|| !request.runtimeId
		|| !request.proxyGeneration) {
		return result;
	}
	for (const auto &owner : request.cancelledTickets) {
		if (owner.key.runtimeId == request.runtimeId) {
			result.applied = CancelKnownReservationInPlace(
				result.gate,
				request.endpointKey,
				owner) || result.applied;
		}
	}
	result.applied = ReleaseOpeningInPlace(
		result.gate,
		[&](const ProxyConnectionAttempt &attempt) {
			return attempt.runtimeId == request.runtimeId
				&& attempt.proxyGeneration < request.proxyGeneration;
		}) || result.applied;
	return result;
}

DialSlotReleaseReduction ReleaseDialSlot(
		const EndpointDialGate &gate,
		const DialSlotReleaseRequest &request) {
	auto result = DialSlotReleaseReduction{ .gate = gate };
	auto slot = FindSlot(result.gate, request.key);
	if (!slot || slot->phase != DialSlotPhase::Opening) {
		return result;
	}
	const auto owner = std::get_if<DialSlotAttemptOwner>(&slot->owner);
	if (!owner || !AttemptOwnerMatches(*owner, request.attempt)) {
		return result;
	}
	slot->phase = DialSlotPhase::Empty;
	slot->owner = std::monostate();
	result.slotReleased = true;
	return result;
}

} // namespace MTP::details::MtProxy
