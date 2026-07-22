/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#pragma once

#include "base/basic_types.h"
#include "mtproto/proxy/mtproxy/open_scheduler.h"
#include "mtproto/runtime/connection_status_types.h"
#include "mtproto/runtime/proxy_endpoint.h"

#include <optional>
#include <variant>
#include <vector>

namespace MTP::details::MtProxy {

struct DialSlotKey {
	QString endpointKey;
	uint64 incarnation = 0;

	bool operator==(const DialSlotKey &other) const = default;
	friend inline bool operator<(
			const DialSlotKey &a,
			const DialSlotKey &b) {
		if (a.endpointKey != b.endpointKey) {
			return a.endpointKey < b.endpointKey;
		}
		return a.incarnation < b.incarnation;
	}
};

enum class DialSlotPhase {
	Empty,
	Reserved,
	Opening,
};

struct DialSlotTicketOwner {
	AdmissionTicketKey key;
	uint64 revision = 0;

	bool operator==(const DialSlotTicketOwner &other) const = default;
};

struct DialSlotAttemptOwner {
	ProxyConnectionAttempt attempt;

	bool operator==(const DialSlotAttemptOwner &other) const = default;
};

using DialSlotOwner = std::variant<
	std::monostate,
	DialSlotTicketOwner,
	DialSlotAttemptOwner>;

struct EndpointDialSlot {
	DialSlotPhase phase = DialSlotPhase::Empty;
	uint64 incarnation = 0;
	DialSlotOwner owner;

	bool operator==(const EndpointDialSlot &other) const = default;
};

struct EndpointDialGate {
	EndpointDialSlot slot;
	uint64 lastIncarnation = 0;
	OpenSlotSchedule openings;

	bool operator==(const EndpointDialGate &other) const = default;
};

enum class DialGateWaitReason {
	None,
	Slot,
};

struct DialSlotReserveRequest {
	QString endpointKey;
	DialSlotTicketOwner owner;
	crl::time now = 0;
	crl::time earliestOpenAt = 0;
	crl::time spacing = 0;
	crl::time jitter = 0;
};

struct DialSlotReflowRequest {
	DialSlotKey key;
	DialSlotTicketOwner owner;
	crl::time now = 0;
	crl::time earliestOpenAt = 0;
	crl::time spacing = 0;
	crl::time jitter = 0;
	uint64 reservationId = 0;
};

struct DialSlotReservationCancelRequest {
	DialSlotKey key;
	DialSlotTicketOwner owner;
	uint64 reservationId = 0;
};

struct DialSlotCommitRequest {
	DialSlotKey key;
	DialSlotTicketOwner owner;
	ProxyConnectionAttempt attempt;
	uint64 reservationId = 0;
};

struct DialSlotRelayReadyRequest {
	DialSlotKey key;
	ProxyConnectionAttempt attempt;
};

struct DialSlotTerminalRequest {
	DialSlotKey key;
	ProxyConnectionAttempt attempt;
	bool finalEndpointTerminal = false;
};

struct DialSlotReleaseRequest {
	DialSlotKey key;
	ProxyConnectionAttempt attempt;
};

struct DialSlotsRuntimeCloseRequest {
	QString endpointKey;
	ProxyRuntimeId runtimeId = 0;
};

struct DialSlotsBeforeGenerationCloseRequest {
	QString endpointKey;
	ProxyRuntimeId runtimeId = 0;
	uint64 proxyGeneration = 0;
	std::vector<DialSlotTicketOwner> cancelledTickets;
};

struct DialSlotReserveReduction {
	EndpointDialGate gate;
	std::optional<DialSlotKey> key;
	std::optional<OpenSlotAssignment> reservation;
	DialGateWaitReason waitReason = DialGateWaitReason::None;
	bool applied = false;
};

struct DialSlotReflowReduction {
	EndpointDialGate gate;
	std::optional<OpenSlotAssignment> reservation;
	bool applied = false;
};

struct DialSlotCancelReduction {
	EndpointDialGate gate;
	bool applied = false;
};

struct DialSlotCommitReduction {
	EndpointDialGate gate;
	bool applied = false;
};

struct DialSlotRelayReadyReduction {
	EndpointDialGate gate;
	bool applied = false;
};

struct DialSlotTerminalReduction {
	EndpointDialGate gate;
	bool applied = false;
};

struct DialSlotsCloseReduction {
	EndpointDialGate gate;
	bool applied = false;
};

struct DialSlotReleaseReduction {
	EndpointDialGate gate;
	bool slotReleased = false;
};

[[nodiscard]] DialSlotReserveReduction ReserveDialSlot(
	const EndpointDialGate &gate,
	const DialSlotReserveRequest &request);
[[nodiscard]] DialSlotReflowReduction ReflowDialSlotReservation(
	const EndpointDialGate &gate,
	const DialSlotReflowRequest &request);
[[nodiscard]] DialSlotCancelReduction CancelDialSlotReservation(
	const EndpointDialGate &gate,
	const DialSlotReservationCancelRequest &request);
[[nodiscard]] DialSlotCommitReduction CommitDialSlotOpening(
	const EndpointDialGate &gate,
	const DialSlotCommitRequest &request);
[[nodiscard]] DialSlotRelayReadyReduction MarkDialSlotRelayReady(
	const EndpointDialGate &gate,
	const DialSlotRelayReadyRequest &request);
[[nodiscard]] DialSlotTerminalReduction MarkDialSlotOpeningTerminal(
	const EndpointDialGate &gate,
	const DialSlotTerminalRequest &request);
[[nodiscard]] DialSlotsCloseReduction CloseRuntimeDialSlots(
	const EndpointDialGate &gate,
	const DialSlotsRuntimeCloseRequest &request);
[[nodiscard]] DialSlotsCloseReduction CloseDialSlotsBeforeGeneration(
	const EndpointDialGate &gate,
	const DialSlotsBeforeGenerationCloseRequest &request);
[[nodiscard]] DialSlotReleaseReduction ReleaseDialSlot(
	const EndpointDialGate &gate,
	const DialSlotReleaseRequest &request);
} // namespace MTP::details::MtProxy
