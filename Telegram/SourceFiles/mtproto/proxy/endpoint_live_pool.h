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

#include <array>
#include <optional>
#include <variant>
#include <vector>

namespace MTP::details::MtProxy {

inline constexpr auto kEndpointLiveSlotCount = 4;

using EndpointUse = ProxyConnectionUse;

enum class AdmissionPurpose {
	Ordinary,
	ReclaimedMainResume,
};

struct LiveSlotKey {
	QString endpointKey;
	int index = -1;
	uint64 incarnation = 0;

	bool operator==(const LiveSlotKey &other) const = default;
	friend inline bool operator<(
			const LiveSlotKey &a,
			const LiveSlotKey &b) {
		if (a.endpointKey != b.endpointKey) {
			return a.endpointKey < b.endpointKey;
		}
		if (a.index != b.index) {
			return a.index < b.index;
		}
		return a.incarnation < b.incarnation;
	}
};

enum class LiveSlotPhase {
	Empty,
	Reserved,
	Opening,
	Live,
	Closing,
};

struct LiveSlotTicketOwner {
	AdmissionTicketKey key;
	uint64 revision = 0;

	bool operator==(const LiveSlotTicketOwner &other) const = default;
};

struct LiveSlotAttemptOwner {
	ProxyConnectionAttempt attempt;
	EndpointUse use = EndpointUse::Main;
	crl::time liveSince = 0;

	bool operator==(const LiveSlotAttemptOwner &other) const = default;
};

using LiveSlotOwner = std::variant<
	std::monostate,
	LiveSlotTicketOwner,
	LiveSlotAttemptOwner>;

struct EndpointLiveSlot {
	LiveSlotPhase phase = LiveSlotPhase::Empty;
	uint64 incarnation = 0;
	LiveSlotOwner owner;

	bool operator==(const EndpointLiveSlot &other) const = default;
};

using EndpointOpeningOwner = std::variant<
	LiveSlotTicketOwner,
	ProxyConnectionAttempt>;

struct CapacityProbe {
	LiveSlotKey key;
	ProxyConnectionAttempt attempt;
	int target = 0;
	std::vector<LiveSlotKey> baseline;

	bool operator==(const CapacityProbe &other) const = default;
};

struct EndpointReclaim {
	LiveSlotKey key;
	ProxyConnectionAttempt incumbent;
	std::optional<LiveSlotTicketOwner> successor;

	bool operator==(const EndpointReclaim &other) const = default;
};

struct EndpointLivePool {
	std::array<EndpointLiveSlot, kEndpointLiveSlotCount> slots;
	std::optional<EndpointOpeningOwner> opening;
	std::optional<CapacityProbe> capacityProbe;
	std::optional<EndpointReclaim> reclaim;
	int provenLowerBound = 0;
	std::optional<int> learnedLimit;
	uint64 lastIncarnation = 0;
	OpenSlotSchedule openings;

	bool operator==(const EndpointLivePool &other) const = default;
};

enum class LivePoolWaitReason {
	None,
	Slot,
	Capacity,
	Closing,
};

struct LivePoolSelectionFacts {
	ProxyRuntimeId foregroundRuntimeId = 0;
	bool foregroundTransferWaiting = false;
	bool foregroundTransferActive = false;
	crl::time now = 0;
};

struct LiveSlotReserveRequest {
	QString endpointKey;
	LiveSlotTicketOwner owner;
	EndpointUse use = EndpointUse::Main;
	AdmissionPurpose purpose = AdmissionPurpose::Ordinary;
	bool foreground = false;
	bool mainRelayProven = false;
	crl::time now = 0;
	crl::time earliestOpenAt = 0;
	crl::time spacing = 0;
	crl::time jitter = 0;
};

struct LiveSlotReflowRequest {
	LiveSlotKey key;
	LiveSlotTicketOwner owner;
	crl::time now = 0;
	crl::time earliestOpenAt = 0;
	crl::time spacing = 0;
	crl::time jitter = 0;
	uint64 reservationId = 0;
};

struct LiveSlotReservationCancelRequest {
	LiveSlotKey key;
	LiveSlotTicketOwner owner;
	uint64 reservationId = 0;
};

struct LiveSlotSuccessorCancelRequest {
	LiveSlotTicketOwner owner;
};

struct LiveSlotCommitRequest {
	LiveSlotKey key;
	LiveSlotTicketOwner owner;
	ProxyConnectionAttempt attempt;
	EndpointUse use = EndpointUse::Main;
	crl::time now = 0;
	uint64 reservationId = 0;
};

struct LiveSlotRelayReadyRequest {
	LiveSlotKey key;
	ProxyConnectionAttempt attempt;
	crl::time now = 0;
};

struct LiveSlotTerminalRequest {
	LiveSlotKey key;
	ProxyConnectionAttempt attempt;
	FailureReason reason = FailureReason::None;
	bool finalEndpointTerminal = false;
};

struct LiveSlotCloseRequest {
	LiveSlotKey key;
	ProxyConnectionAttempt attempt;
	std::optional<LiveSlotTicketOwner> successor;
	std::optional<AdmissionPurpose> resumePurpose;
};

struct LiveSlotReleaseRequest {
	LiveSlotKey key;
	ProxyConnectionAttempt attempt;
};

struct ForegroundTransferReclaimRequest {
	QString endpointKey;
	LiveSlotTicketOwner successor;
	LivePoolSelectionFacts facts;
};

struct BackgroundMainRotationRequest {
	QString endpointKey;
	LiveSlotTicketOwner successor;
	LivePoolSelectionFacts facts;
};

struct LiveSlotsRuntimeCloseRequest {
	QString endpointKey;
	ProxyRuntimeId runtimeId = 0;
};

struct LiveSlotsBeforeGenerationCloseRequest {
	QString endpointKey;
	ProxyRuntimeId runtimeId = 0;
	uint64 proxyGeneration = 0;
	std::vector<LiveSlotTicketOwner> cancelledTickets;
};

struct LivePoolCloseAction {
	LiveSlotKey key;
	ProxyConnectionAttempt attempt;
	std::optional<AdmissionPurpose> resumePurpose;

	bool operator==(const LivePoolCloseAction &other) const = default;
};

struct LiveSlotReserveReduction {
	EndpointLivePool pool;
	std::optional<LiveSlotKey> key;
	std::optional<OpenSlotAssignment> reservation;
	LivePoolWaitReason waitReason = LivePoolWaitReason::None;
	bool applied = false;
};

struct LiveSlotReflowReduction {
	EndpointLivePool pool;
	std::optional<OpenSlotAssignment> reservation;
	bool applied = false;
};

struct LiveSlotCancelReduction {
	EndpointLivePool pool;
	bool applied = false;
};

struct LiveSlotCommitReduction {
	EndpointLivePool pool;
	bool applied = false;
};

struct LiveSlotRelayReadyReduction {
	EndpointLivePool pool;
	bool applied = false;
};

struct LiveSlotTerminalReduction {
	EndpointLivePool pool;
	bool applied = false;
};

struct LiveSlotCloseReduction {
	EndpointLivePool pool;
	std::optional<LivePoolCloseAction> close;
	LivePoolWaitReason waitReason = LivePoolWaitReason::None;
	bool applied = false;
};

struct LiveSlotsCloseReduction {
	EndpointLivePool pool;
	std::vector<LivePoolCloseAction> closes;
	bool applied = false;
};

struct LiveSlotReleaseReduction {
	EndpointLivePool pool;
	std::optional<LiveSlotTicketOwner> successor;
	bool applied = false;
};

[[nodiscard]] LiveSlotReserveReduction ReserveLiveSlot(
	const EndpointLivePool &pool,
	const LiveSlotReserveRequest &request);
[[nodiscard]] LiveSlotReflowReduction ReflowLiveSlotReservation(
	const EndpointLivePool &pool,
	const LiveSlotReflowRequest &request);
[[nodiscard]] LiveSlotCancelReduction CancelLiveSlotReservation(
	const EndpointLivePool &pool,
	const LiveSlotReservationCancelRequest &request);
[[nodiscard]] LiveSlotCancelReduction CancelLiveSlotSuccessor(
	const EndpointLivePool &pool,
	const LiveSlotSuccessorCancelRequest &request);
[[nodiscard]] LiveSlotCommitReduction CommitLiveSlotOpening(
	const EndpointLivePool &pool,
	const LiveSlotCommitRequest &request);
[[nodiscard]] LiveSlotRelayReadyReduction MarkLiveSlotRelayReady(
	const EndpointLivePool &pool,
	const LiveSlotRelayReadyRequest &request);
[[nodiscard]] LiveSlotTerminalReduction MarkLiveSlotCapacityTerminal(
	const EndpointLivePool &pool,
	const LiveSlotTerminalRequest &request);
[[nodiscard]] LiveSlotCloseReduction BeginLiveSlotClose(
	const EndpointLivePool &pool,
	const LiveSlotCloseRequest &request);
[[nodiscard]] LiveSlotCloseReduction SelectForegroundTransferReclaim(
	const EndpointLivePool &pool,
	const ForegroundTransferReclaimRequest &request);
[[nodiscard]] LiveSlotCloseReduction SelectBackgroundMainRotation(
	const EndpointLivePool &pool,
	const BackgroundMainRotationRequest &request);
[[nodiscard]] LiveSlotsCloseReduction CloseRuntimeLiveSlots(
	const EndpointLivePool &pool,
	const LiveSlotsRuntimeCloseRequest &request);
[[nodiscard]] LiveSlotsCloseReduction CloseLiveSlotsBeforeGeneration(
	const EndpointLivePool &pool,
	const LiveSlotsBeforeGenerationCloseRequest &request);
[[nodiscard]] LiveSlotReleaseReduction ReleaseLiveSlot(
	const EndpointLivePool &pool,
	const LiveSlotReleaseRequest &request);
[[nodiscard]] std::optional<crl::time> NextLivePoolWakeAt(
	const EndpointLivePool &pool,
	const LivePoolSelectionFacts &facts,
	bool backgroundMainWaiting);

} // namespace MTP::details::MtProxy
