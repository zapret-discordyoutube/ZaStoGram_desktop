/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "mtproto/proxy/endpoint_admission_arbiter.h"

#include "mtproto/proxy/mtproxy/endpoint_health_policy.h"
#include "mtproto/proxy/mtproxy/open_scheduler.h"
#include "mtproto/proxy/proxy_endpoint_context.h"
#include "mtproto/proxy/proxy_endpoint_context_p.h"

#include <QtCore/QMutexLocker>

#include <algorithm>
#include <array>
#include <atomic>
#include <deque>
#include <map>
#include <optional>
#include <set>
#include <tuple>
#include <utility>
#include <vector>

namespace MTP::details {
namespace {

constexpr auto kAgingStep = crl::time(15 * 1000);
constexpr auto kMinimumOpenSpacing = crl::time(500);
constexpr auto kOpenSpacingJitter = crl::time(125);
constexpr auto kLaneCommandAckTimeout = crl::time(5 * 1000);

enum class PriorityClass {
	ForegroundMain,
	UrgentMain,
	ForegroundTransfer,
	OrdinaryMain,
	Maintenance,
	Auxiliary,
	ProxyCheck,
	Background,
	Count,
};

enum class CapacityDecisionKind {
	Blocked,
	Ordinary,
	Probe,
};

struct CandidateCapacityDecision {
	CapacityDecisionKind kind = CapacityDecisionKind::Blocked;
	crl::time retryAt = 0;
};

struct TicketCallbacks {
	Fn<void(EndpointAdmissionUpdate)> status;
	Fn<void(EndpointAdmissionGrant)> grant;
};

struct Ticket {
	AdmissionTicketKey key;
	uint64 revision = 0;
	uint64 transition = 0;
	uint64 sequence = 0;
	uint64 proxyGeneration = 0;
	ProxyTraceId traceId = 0;
	MtProxy::EndpointId endpoint;
	QString endpointKey;
	MtProxy::EndpointUse use = MtProxy::EndpointUse::Main;
	MtProxy::MainRecoveryToken acceptedRecoveryToken;
	MtProxy::AdmissionRequest admissionRequest;
	QPointer<QObject> owner;
	QMetaObject::Connection ownerDestroyed;
	std::shared_ptr<Fn<void(MtProxy::EndpointLaneCommand)>> laneControl;
	std::shared_ptr<TicketCallbacks> callbacks;
	ProxySchedulerLifecycle lifecycle = ProxySchedulerLifecycle::None;
	crl::time enqueuedAt = 0;
	crl::time notBeforeAt = 0;
	crl::time scheduledOpenAt = 0;
	crl::time nextOpenAt = 0;
	crl::time retryAt = 0;
	crl::time reevaluateAt = 0;
	crl::time retryAfter = 0;
	crl::time spacing = 0;
	crl::time jitter = 0;
	MtProxy::FailureReason blockedBy = MtProxy::FailureReason::None;
	uint64 reservationId = 0;
};

[[nodiscard]] RuntimeGenerationKey TicketRuntimeGeneration(
		const Ticket &ticket) {
	return {
		.runtimeId = ticket.key.runtimeId,
		.proxyGeneration = ticket.proxyGeneration,
	};
}

[[nodiscard]] const MtProxy::EndpointVerdict *TicketVerdict(
		const Ticket &ticket,
		const MtProxy::EndpointState &state) {
	const auto key = RuntimeGenerationKey{
		.runtimeId = ticket.key.runtimeId,
		.proxyGeneration = ticket.proxyGeneration,
	};
	const auto i = state.canonicalVerdicts.find(key);
	return (i != end(state.canonicalVerdicts)) ? &i->second : nullptr;
}

[[nodiscard]] crl::time TicketRetryUntil(
		const Ticket &ticket,
		const MtProxy::EndpointState &state,
		ProxyRuntimeId foregroundRuntimeId) {
	const auto runtimeGeneration = RuntimeGenerationKey{
		.runtimeId = ticket.key.runtimeId,
		.proxyGeneration = ticket.proxyGeneration,
	};
	const auto verdict = TicketVerdict(ticket, state);
	auto result = std::max(
		state.opening.bootstrap.retryUntil,
		verdict ? verdict->retryUntil : crl::time());
	const auto expansion = MtProxy::FindEndpointExpansionFailure(
		state,
		runtimeGeneration,
		ticket.use);
	const auto foregroundTransfer = (ticket.use == MtProxy::EndpointUse::Media
			|| ticket.use == MtProxy::EndpointUse::Upload)
		&& ticket.key.runtimeId == foregroundRuntimeId;
	if (expansion) {
		result = std::max(result, expansion->retryUntil);
	}
	if (!foregroundTransfer && ticket.use != MtProxy::EndpointUse::Main) {
		result = std::max(result, state.opening.expansion.retryUntil);
	}
	return result;
}

[[nodiscard]] MtProxy::FailureReason TicketFailureReason(
		const Ticket &ticket,
		const MtProxy::EndpointState &state) {
	const auto verdict = TicketVerdict(ticket, state);
	if (verdict) {
		return verdict->reason;
	}
	const auto expansion = MtProxy::FindEndpointExpansionFailure(
		state,
		{
			.runtimeId = ticket.key.runtimeId,
			.proxyGeneration = ticket.proxyGeneration,
		},
		ticket.use);
	return expansion ? expansion->reason : MtProxy::FailureReason::None;
}

[[nodiscard]] bool WaitingForHandoff(ProxySchedulerLifecycle lifecycle) {
	return lifecycle == ProxySchedulerLifecycle::Queued
		|| lifecycle == ProxySchedulerLifecycle::Scheduled
		|| lifecycle == ProxySchedulerLifecycle::Granted;
}

struct FairnessState {
	std::array<ProxyRuntimeId, int(PriorityClass::Count)> lastRuntime = {};
	std::map<ProxyRuntimeId, MtProxy::EndpointUse> nextBackground;
};

struct EndpointSchedule {
	std::deque<AdmissionTicketKey> order;
	FairnessState fairness;
};

enum class LaneReclaimKind {
	Opening,
	Capacity,
};

enum class LanePreemptionStage {
	Requested,
	Authorized,
};

enum class LanePreemptionTerminal {
	VictimLost,
	DeliveryFailed,
	Retry,
	Applied,
	NotApplicable,
	Expired,
};

struct LanePreemption {
	uint64 token = 0;
	crl::time deadlineAt = 0;
	LaneReclaimKind reclaim = LaneReclaimKind::Opening;
	AdmissionTicketKey beneficiary;
	MtProxy::RelayProofIdentity victim;
	AdmissionTicketKey victimTicketKey;
	MtProxy::EndpointUse victimUse = MtProxy::EndpointUse::Media;
	QPointer<QObject> owner;
	QMetaObject::Connection ownerDestroyed;
	std::shared_ptr<Fn<void(MtProxy::EndpointLaneCommand)>> laneControl;
	LanePreemptionStage stage = LanePreemptionStage::Requested;
	bool demanded = false;
};

struct LaneVictim {
	MtProxy::RelayProofIdentity identity;
	AdmissionTicketKey ticketKey;
	MtProxy::EndpointUse use = MtProxy::EndpointUse::Media;
	QPointer<QObject> owner;
	QMetaObject::Connection ownerDestroyed;
	std::shared_ptr<Fn<void(MtProxy::EndpointLaneCommand)>> laneControl;
	crl::time startedAt = 0;
	bool foreground = false;
	bool durable = false;
};

struct SuspendedLane {
	uint64 token = 0;
	crl::time commandDeadlineAt = 0;
	MtProxy::RelayProofIdentity identity;
	AdmissionTicketKey ticketKey;
	MtProxy::EndpointUse use = MtProxy::EndpointUse::Media;
	QPointer<QObject> owner;
	QMetaObject::Connection ownerDestroyed;
	std::shared_ptr<Fn<void(MtProxy::EndpointLaneCommand)>> laneControl;
	AdmissionTicketKey successorTicketKey;
	bool demanded = false;
};

struct EndpointLaneSchedule {
	std::optional<LanePreemption> preemption;
	std::optional<AdmissionTicketKey> handoffBeneficiary;
	std::deque<SuspendedLane> suspended;
	std::optional<SuspendedLane> resuming;
};

struct RuntimeInput {
	std::vector<crl::time> jitters;
	std::size_t nextJitter = 0;
	bool fastProxyWarmup = false;
};

struct DrainInputs {
	std::map<ProxyRuntimeId, RuntimeInput> runtimes;
	crl::time now = 0;

	[[nodiscard]] crl::time takeJitter(ProxyRuntimeId runtimeId);
	[[nodiscard]] bool fastWarmup(ProxyRuntimeId runtimeId) const;
};

struct PostAction {
	std::shared_ptr<const EndpointAdmissionRuntimeDispatch> dispatch;
	QPointer<QObject> target;
	crl::time delay = 0;
	Fn<void()> callback;
	Fn<void()> missing;

	void run();
};

struct GrantAction {
	std::weak_ptr<ProxyEndpointContext> context;
	std::unique_ptr<Ticket> ticket;
	EndpointAdmissionGrant grant;

	void run();
};

struct Actions {
	std::vector<std::unique_ptr<Ticket>> removed;
	std::vector<GrantAction> grants;
	std::vector<PostAction> posts;
	std::vector<std::shared_ptr<const EndpointAdmissionRuntimeDispatch>> retired;
	std::weak_ptr<ProxyEndpointContext> context;
	std::vector<std::pair<
		MtProxy::EndpointId,
		RuntimeGenerationKey>> invalidations;

	void run();
};

void InvalidateRuntimeDispatch(
		const std::shared_ptr<const EndpointAdmissionRuntimeDispatch> &dispatch) {
	if (dispatch && dispatch->registrationLive) {
		dispatch->registrationLive->store(false, std::memory_order_release);
	}
}

crl::time DrainInputs::takeJitter(ProxyRuntimeId runtimeId) {
	const auto i = runtimes.find(runtimeId);
	if (i == end(runtimes)
		|| i->second.nextJitter >= i->second.jitters.size()) {
		return 0;
	}
	return i->second.jitters[i->second.nextJitter++];
}

bool DrainInputs::fastWarmup(ProxyRuntimeId runtimeId) const {
	const auto i = runtimes.find(runtimeId);
	return i != end(runtimes) && i->second.fastProxyWarmup;
}

void PostAction::run() {
	if (!dispatch
		|| !dispatch->dispatcher
		|| !dispatch->singleShot
		|| !dispatch->registrationLive
		|| !dispatch->registrationLive->load(std::memory_order_acquire)
		|| !target) {
		if (missing) {
			missing();
		}
		return;
	}
	const auto registrationLive = dispatch->registrationLive;
	const auto dispatcher = dispatch->dispatcher;
	const auto guardedTarget = target;
	auto guardedCallback = std::move(callback);
	auto guardedMissing = std::move(missing);
	dispatch->singleShot(
		std::max(crl::time(), delay),
		guardedTarget,
		[
			registrationLive,
			dispatcher,
			guardedTarget,
			callback = std::move(guardedCallback),
			missing = std::move(guardedMissing)
		]() mutable {
			if (!registrationLive->load(std::memory_order_acquire)
				|| !dispatcher
				|| !guardedTarget) {
				if (missing) {
					missing();
				}
				return;
			}
			callback();
		});
}

void GrantAction::run() {
	if (!ticket) {
		return;
	}
	if (ticket->owner
		&& ticket->callbacks
		&& ticket->callbacks->grant) {
		ticket->callbacks->grant(std::move(grant));
	} else {
		if (const auto strong = context.lock()) {
			(void)strong->finishTrace(grant.attempt.traceId);
		}
		grant.admission.lease.release();
	}
}

void Actions::run() {
	if (const auto strong = context.lock()) {
		auto emitted = std::set<std::tuple<QString, uint64, uint64>>();
		for (const auto &[endpoint, runtimeGeneration] : invalidations) {
			const auto key = std::tuple(
				MtProxy::EndpointKey(endpoint),
				runtimeGeneration.runtimeId,
				runtimeGeneration.proxyGeneration);
			if (emitted.emplace(key).second) {
				strong->notifyEndpointViewChanged(
					endpoint,
					runtimeGeneration);
			}
		}
	}
	invalidations.clear();
	context.reset();
	for (const auto &ticket : removed) {
		QObject::disconnect(ticket->ownerDestroyed);
	}
	for (auto &grant : grants) {
		grant.run();
	}
	grants.clear();
	removed.clear();
	for (auto &post : posts) {
		post.run();
	}
	posts.clear();
	retired.clear();
}

[[nodiscard]] int PriorityIndex(PriorityClass value) {
	return int(value);
}

[[nodiscard]] bool IsBackground(MtProxy::EndpointUse use) {
	return use == MtProxy::EndpointUse::Media
		|| use == MtProxy::EndpointUse::Upload;
}

[[nodiscard]] int ProvenEndpointCapacity(
		const MtProxy::EndpointState &state) {
	return std::max(
		state.liveBudget.learnedLimit,
		state.liveBudget.provenLowerBound);
}

[[nodiscard]] bool IsUrgentMainPriority(PriorityClass priority) {
	return priority == PriorityClass::ForegroundMain
		|| priority == PriorityClass::UrgentMain;
}

[[nodiscard]] bool IsUrgentMainBeneficiary(
		const Ticket &ticket,
		PriorityClass priority) {
	return ticket.use == MtProxy::EndpointUse::Main
		&& (priority == PriorityClass::ForegroundMain
			|| priority == PriorityClass::UrgentMain);
}

[[nodiscard]] MtProxy::EndpointUse NextBackgroundUse(
		const FairnessState &fairness,
		ProxyRuntimeId runtimeId) {
	const auto i = fairness.nextBackground.find(runtimeId);
	return (i == end(fairness.nextBackground))
		? MtProxy::EndpointUse::Media
		: i->second;
}

void AdvanceFairness(
		FairnessState &fairness,
		const Ticket &ticket,
		PriorityClass priority) {
	fairness.lastRuntime[PriorityIndex(priority)] = ticket.key.runtimeId;
	if (ticket.use == MtProxy::EndpointUse::Media) {
		fairness.nextBackground[ticket.key.runtimeId]
			= MtProxy::EndpointUse::Upload;
	} else if (ticket.use == MtProxy::EndpointUse::Upload) {
		fairness.nextBackground[ticket.key.runtimeId]
			= MtProxy::EndpointUse::Media;
	}
}

} // namespace

class EndpointAdmissionArbiter::Private final {
public:
	explicit Private(MtProxy::EndpointContextStorage &storage);
	~Private();

	void bindRuntime(
		ProxyRuntimeId runtimeId,
		EndpointAdmissionRuntimeDispatch dispatch);
	void unregisterRuntime(ProxyRuntimeId runtimeId);
	void cancelRuntime(ProxyRuntimeId runtimeId);
	[[nodiscard]] EndpointAdmissionEnqueueResult enqueue(
		std::weak_ptr<ProxyEndpointContext> context,
		EndpointAdmissionRequest request);
	void cancel(AdmissionTicketKey key, uint64 revision);
	void ownerDestroyed(AdmissionTicketKey key);
	void cancelBeforeGeneration(
		ProxyRuntimeId runtimeId,
		uint64 proxyGeneration);
	[[nodiscard]] bool authorizeLaneSuspension(
		const QString &endpointKey,
		uint64 token,
		ProxyRuntimeId runtimeId,
		uint64 proxyGeneration,
		uint64 attemptId);
	void demandLaneResume(
		const QString &endpointKey,
		uint64 token,
		ProxyRuntimeId runtimeId,
		uint64 proxyGeneration,
		uint64 attemptId);
	void acknowledgeLaneSuspension(
		const QString &endpointKey,
		uint64 token,
		ProxyRuntimeId runtimeId,
		uint64 proxyGeneration,
		uint64 attemptId,
		MtProxy::EndpointLaneCommandResult result,
		bool delivered);
	void acknowledgeLaneResume(
		const QString &endpointKey,
		uint64 token,
		ProxyRuntimeId runtimeId,
		uint64 proxyGeneration,
		uint64 attemptId,
		crl::time deadlineAt,
		MtProxy::EndpointLaneCommandResult result,
		bool delivered);
	void drainEndpoint(const QString &endpointKey);
	void composeEndpointViewLocked(
		const MtProxy::EndpointId &endpoint,
		RuntimeGenerationKey runtimeGeneration,
		MtProxy::ProxyEndpointView &view) const;
	void wake(uint64 token);
	void deliverStatus(
		AdmissionTicketKey key,
		uint64 revision,
		uint64 transition,
		ProxySchedulerLifecycle lifecycle);
	void deliverGrant(
		AdmissionTicketKey key,
		uint64 revision,
		uint64 transition,
		ProxySchedulerLifecycle lifecycle);

private:
	[[nodiscard]] DrainInputs prepareInputs() const;
	[[nodiscard]] bool runtimeLiveLocked(ProxyRuntimeId runtimeId) const;
	[[nodiscard]] bool ticketCurrentLocked(
		const Ticket &ticket,
		const MtProxy::EndpointState &state) const;
	[[nodiscard]] bool ownsMainRecoveryLocked(const Ticket &ticket) const;
	[[nodiscard]] PriorityClass priorityForLocked(
		const Ticket &ticket,
		const MtProxy::EndpointState &state,
		crl::time now) const;
	[[nodiscard]] Ticket *selectLocked(
		const std::vector<Ticket*> &pool,
		const std::set<AdmissionTicketKey> &eligible,
		const MtProxy::EndpointState &state,
		crl::time now,
		const FairnessState &fairness) const;
	[[nodiscard]] std::vector<Ticket*> orderLocked(
		std::vector<Ticket*> pool,
		const MtProxy::EndpointState &state,
		crl::time now,
		FairnessState fairness) const;
	[[nodiscard]] MtProxy::EndpointUseCounts activeCountsLocked(
		const MtProxy::EndpointState &state) const;
	[[nodiscard]] MtProxy::EndpointUseCounts scheduledCountsLocked(
		const QString &endpointKey) const;
	[[nodiscard]] int urgentWaitersLocked(
		const QString &endpointKey,
		const MtProxy::EndpointState &state,
		crl::time now) const;
	[[nodiscard]] MtProxy::EndpointConcurrencyPolicy policyLocked(
		const Ticket &ticket,
		const MtProxy::EndpointState &state,
		const MtProxy::EndpointUseCounts &active,
		const MtProxy::EndpointUseCounts &scheduled,
		int urgentWaiters,
		const DrainInputs &inputs,
		bool ignoreExpansionRetry = false) const;
	[[nodiscard]] bool baseEligibleLocked(
		const Ticket &ticket,
		const MtProxy::EndpointState &state,
		int urgentWaiters,
		crl::time now,
		bool ignoreTicketRetry = false) const;
	[[nodiscard]] CandidateCapacityDecision capacityDecisionLocked(
		const Ticket &candidate,
		const MtProxy::EndpointState &state,
		const MtProxy::EndpointUseCounts &scheduled,
		int urgentWaiters,
		crl::time now,
		std::optional<AdmissionTicketKey> noVictimUrgentClaimant) const;
	[[nodiscard]] auto requestLanePreemptionLocked(
		const QString &endpointKey,
		MtProxy::EndpointState &state,
		DrainInputs &inputs,
		Actions &actions)
	-> std::optional<AdmissionTicketKey>;
	void resumeSuspendedLaneLocked(
		const QString &endpointKey,
		MtProxy::EndpointState &state,
		DrainInputs &inputs,
		Actions &actions);
	void postStatusLocked(Ticket &ticket, Actions &actions);
	void postGenerationCancelledStatusLocked(
		const Ticket &ticket,
		Actions &actions);
	void postGrantLocked(Ticket &ticket, Actions &actions);
	void invalidateTicketLocked(Ticket &ticket, Actions &actions);
	void cancelTicketLocked(
		AdmissionTicketKey key,
		uint64 revision,
		Actions &actions);
	void demoteTicketLocked(Ticket &ticket, Actions &actions);
	void releaseReservedCapacityProbeLocked(const Ticket &ticket);
	void detachLanePreemptionBeneficiaryLocked(
		const QString &endpointKey,
		AdmissionTicketKey key);
	void finishLanePreemptionLocked(
		const QString &endpointKey,
		MtProxy::EndpointState *state,
		uint64 token,
		const MtProxy::RelayProofIdentity &identity,
		LanePreemptionTerminal terminal);
	void expireLaneCommandsLocked(
		const QString &endpointKey,
		MtProxy::EndpointState &state,
		crl::time now);
	[[nodiscard]] std::unique_ptr<Ticket> takeTicketLocked(
		AdmissionTicketKey key);
	void purgeEndpointLocked(
		const QString &endpointKey,
		MtProxy::EndpointState &state,
		Actions &actions);
	void revalidateReservationsLocked(
		const QString &endpointKey,
		MtProxy::EndpointState &state,
		DrainInputs &inputs,
		Actions &actions);
	void assignReservationsLocked(
		const QString &endpointKey,
		MtProxy::EndpointState &state,
		DrainInputs &inputs,
		Actions &actions,
		std::optional<AdmissionTicketKey> noVictimUrgentClaimant);
	void grantDueLocked(
		const QString &endpointKey,
		crl::time now,
		Actions &actions);
	void drainEndpointLocked(
		const QString &endpointKey,
		DrainInputs &inputs,
		Actions &actions);
	[[nodiscard]] bool wakeOwnerLiveLocked() const;
	void clearWakeLocked(bool invalidateToken);
	void updateWakeLocked(const DrainInputs &inputs, Actions &actions);

	MtProxy::EndpointContextStorage &_storage;
	std::map<AdmissionTicketKey, std::unique_ptr<Ticket>> _tickets;
	std::map<QString, EndpointSchedule> _endpoints;
	std::map<QString, EndpointLaneSchedule> _laneSchedules;
	std::map<
		ProxyRuntimeId,
		std::shared_ptr<const EndpointAdmissionRuntimeDispatch>> _runtimes;
	std::weak_ptr<ProxyEndpointContext> _context;
	std::atomic<uint64> _lastRevision = 0;
	uint64 _lastSequence = 0;
	uint64 _lastLaneToken = 0;
	uint64 _wakeToken = 0;
	ProxyRuntimeId _wakeDriver = 0;
	crl::time _wakeAt = 0;
	std::shared_ptr<std::atomic<bool>> _wakeRegistrationLive;
	bool _wakeArmed = false;

};

EndpointAdmissionArbiter::Private::Private(
	MtProxy::EndpointContextStorage &storage)
: _storage(storage) {
}

EndpointAdmissionArbiter::Private::~Private() {
	auto actions = Actions();
	{
		QMutexLocker lock(&_storage.mutex);
		clearWakeLocked(true);
		for (auto &entry : _tickets) {
			auto &ticket = entry.second;
			releaseReservedCapacityProbeLocked(*ticket);
			if (ticket->reservationId) {
				const auto state = _storage.openStates.find(
					ticket->endpointKey);
				if (state != end(_storage.openStates)) {
					static_cast<void>(MtProxy::CancelOpenSlotLocked(
						state->second,
						ticket->reservationId));
				}
			}
			actions.removed.push_back(std::move(ticket));
		}
		_tickets.clear();
		_endpoints.clear();
		_laneSchedules.clear();
		for (auto &entry : _runtimes) {
			auto &dispatch = entry.second;
			InvalidateRuntimeDispatch(dispatch);
			actions.retired.push_back(std::move(dispatch));
		}
		_runtimes.clear();
	}
	actions.run();
}

DrainInputs EndpointAdmissionArbiter::Private::prepareInputs() const {
	auto records = std::vector<std::pair<
		ProxyRuntimeId,
		std::shared_ptr<const EndpointAdmissionRuntimeDispatch>>>();
	auto counts = std::map<ProxyRuntimeId, std::size_t>();
	{
		QMutexLocker lock(&_storage.mutex);
		records.reserve(_runtimes.size());
		for (const auto &[runtimeId, dispatch] : _runtimes) {
			records.emplace_back(runtimeId, dispatch);
		}
		for (const auto &entry : _tickets) {
			++counts[entry.first.runtimeId];
		}
	}
	auto result = DrainInputs();
	auto hasNow = false;
	for (const auto &[runtimeId, dispatch] : records) {
		if (!dispatch
			|| !dispatch->dispatcher
			|| !dispatch->now
			|| !dispatch->singleShot) {
			continue;
		}
		auto input = RuntimeInput();
		input.fastProxyWarmup = dispatch->fastProxyWarmup
			? dispatch->fastProxyWarmup()
			: false;
		const auto count = counts[runtimeId] + 1;
		input.jitters.reserve(count);
		for (auto i = std::size_t(); i != count; ++i) {
			const auto value = dispatch->randomIndex
				? dispatch->randomIndex(int(kOpenSpacingJitter) + 1)
				: 0;
			input.jitters.push_back(crl::time(std::clamp(
				value,
				0,
				int(kOpenSpacingJitter))));
		}
		if (!hasNow) {
			result.now = dispatch->now();
			hasNow = true;
		}
		result.runtimes.emplace(runtimeId, std::move(input));
	}
	return result;
}

bool EndpointAdmissionArbiter::Private::runtimeLiveLocked(
		ProxyRuntimeId runtimeId) const {
	const auto i = _runtimes.find(runtimeId);
	return i != end(_runtimes)
		&& i->second
		&& i->second->dispatcher
		&& i->second->now
		&& i->second->singleShot;
}

bool EndpointAdmissionArbiter::Private::ticketCurrentLocked(
		const Ticket &ticket,
		const MtProxy::EndpointState &state) const {
	const auto generation = _storage.runtimeGenerations.find(
		ticket.key.runtimeId);
	return runtimeLiveLocked(ticket.key.runtimeId)
		&& generation != end(_storage.runtimeGenerations)
		&& (!generation->second
			|| generation->second == ticket.proxyGeneration)
		&& ticket.owner
		&& !MtProxy::RuntimeProxyGenerationIsStale(
			state,
			ticket.key.runtimeId,
			ticket.proxyGeneration);
}

void EndpointAdmissionArbiter::Private::composeEndpointViewLocked(
		const MtProxy::EndpointId &endpoint,
		RuntimeGenerationKey runtimeGeneration,
		MtProxy::ProxyEndpointView &view) const {
	if (view.admissionPhase != ProxyAdmissionPhase::Idle) {
		return;
	}
	const auto endpointKey = MtProxy::EndpointKey(endpoint);
	const auto schedule = _endpoints.find(endpointKey);
	if (schedule == end(_endpoints)) {
		return;
	}
	const auto rank = [](ProxySchedulerLifecycle lifecycle) {
		switch (lifecycle) {
		case ProxySchedulerLifecycle::Granted:
			return 0;
		case ProxySchedulerLifecycle::Scheduled:
			return 1;
		case ProxySchedulerLifecycle::Queued:
			return 2;
		case ProxySchedulerLifecycle::None:
		case ProxySchedulerLifecycle::HandedOff:
		case ProxySchedulerLifecycle::Cancelled:
			return 3;
		}
		return 3;
	};
	auto selected = static_cast<const Ticket*>(nullptr);
	for (const auto &ticketKey : schedule->second.order) {
		const auto i = _tickets.find(ticketKey);
		if (i == end(_tickets)) {
			continue;
		}
		const auto &ticket = *i->second;
		if (ticket.key.runtimeId != runtimeGeneration.runtimeId
			|| ticket.proxyGeneration != runtimeGeneration.proxyGeneration
			|| ticket.use != MtProxy::EndpointUse::Main
			|| rank(ticket.lifecycle) >= 3) {
			continue;
		}
		if (!selected
			|| rank(ticket.lifecycle) < rank(selected->lifecycle)
			|| (rank(ticket.lifecycle) == rank(selected->lifecycle)
				&& ticket.sequence < selected->sequence)) {
			selected = &ticket;
		}
	}
	if (!selected) {
		return;
	}
	view.mainAttempt = {
		.runtimeId = selected->key.runtimeId,
		.ticketId = selected->key.ticketId,
		.proxyGeneration = selected->proxyGeneration,
		.use = selected->use,
		.ticketKey = selected->key,
	};
	view.ticketKey = selected->key;
	view.schedulerLifecycle = selected->lifecycle;
	view.admissionPhase = (selected->lifecycle
			== ProxySchedulerLifecycle::Queued)
		? ProxyAdmissionPhase::Queued
		: ProxyAdmissionPhase::Scheduled;
	view.enqueuedAt = selected->enqueuedAt;
	view.scheduledOpenAt = selected->scheduledOpenAt;
}

bool EndpointAdmissionArbiter::Private::ownsMainRecoveryLocked(
		const Ticket &ticket) const {
	const auto runtimeGeneration = RuntimeGenerationKey{
		.runtimeId = ticket.key.runtimeId,
		.proxyGeneration = ticket.proxyGeneration,
	};
	const auto recovery = MtProxy::ComposeMainRecoveryViewLocked(
		_storage,
		ticket.endpointKey,
		runtimeGeneration);
	return ticket.use == MtProxy::EndpointUse::Main
		&& ticket.acceptedRecoveryToken
		&& recovery
		&& recovery->token == ticket.acceptedRecoveryToken
		&& (recovery->stage == MtProxy::MainRecoveryStage::AdmissionTicket
			|| recovery->stage
				== MtProxy::MainRecoveryStage::ReplacementAttempt)
		&& recovery->adoptedTicketKey == ticket.key;
}

PriorityClass EndpointAdmissionArbiter::Private::priorityForLocked(
		const Ticket &ticket,
		const MtProxy::EndpointState &state,
		crl::time now) const {
	const auto foreground = ticket.key.runtimeId
		== _storage.foregroundRuntimeId;
	const auto runtimeGeneration = RuntimeGenerationKey{
		.runtimeId = ticket.key.runtimeId,
		.proxyGeneration = ticket.proxyGeneration,
	};
	const auto hasMainProof = MtProxy::HasCurrentMainRelayProof(
		state,
		runtimeGeneration);
	auto result = PriorityClass::Background;
	if (ticket.use == MtProxy::EndpointUse::Main) {
		result = hasMainProof
			? PriorityClass::OrdinaryMain
			: foreground
			? PriorityClass::ForegroundMain
			: PriorityClass::UrgentMain;
	} else if (foreground && IsBackground(ticket.use)) {
		result = PriorityClass::ForegroundTransfer;
	} else if (ticket.use == MtProxy::EndpointUse::Maintenance) {
		result = PriorityClass::Maintenance;
	} else if (ticket.use == MtProxy::EndpointUse::Auxiliary) {
		result = PriorityClass::Auxiliary;
	} else if (ticket.use == MtProxy::EndpointUse::ProxyCheck) {
		result = PriorityClass::ProxyCheck;
	}
	if (result == PriorityClass::ForegroundMain
		|| result == PriorityClass::ForegroundTransfer
		|| result == PriorityClass::UrgentMain
		|| result == PriorityClass::OrdinaryMain) {
		return result;
	}
	const auto age = std::max(crl::time(), now - ticket.enqueuedAt);
	const auto improvement = int(age / kAgingStep);
	const auto improved = std::max(
		PriorityIndex(PriorityClass::OrdinaryMain),
		PriorityIndex(result) - improvement);
	return PriorityClass(improved);
}

Ticket *EndpointAdmissionArbiter::Private::selectLocked(
		const std::vector<Ticket*> &pool,
		const std::set<AdmissionTicketKey> &eligible,
		const MtProxy::EndpointState &state,
		crl::time now,
		const FairnessState &fairness) const {
	auto heads = std::vector<Ticket*>();
	for (const auto ticket : pool) {
		auto head = true;
		const auto ownsRecovery = ownsMainRecoveryLocked(*ticket);
		const auto priority = priorityForLocked(*ticket, state, now);
		for (const auto other : pool) {
			if (other->key.runtimeId != ticket->key.runtimeId
				|| other->use != ticket->use) {
				continue;
			}
			const auto otherOwnsRecovery = ownsMainRecoveryLocked(*other);
			const auto otherPriority = priorityForLocked(*other, state, now);
			if ((otherOwnsRecovery && !ownsRecovery)
				|| (otherOwnsRecovery == ownsRecovery
					&& (otherPriority < priority
						|| (otherPriority == priority
							&& other->sequence < ticket->sequence)))) {
				head = false;
				break;
			}
		}
		if (head && eligible.contains(ticket->key)) {
			heads.push_back(ticket);
		}
	}
	if (heads.empty()) {
		return nullptr;
	}
	const auto lane = _laneSchedules.find(heads.front()->endpointKey);
	if (lane != end(_laneSchedules) && lane->second.handoffBeneficiary) {
		const auto handoff = ranges::find_if(
			heads,
			[&](const Ticket *ticket) {
				const auto priority = priorityForLocked(
					*ticket,
					state,
					now);
				return ticket->key == *lane->second.handoffBeneficiary
					&& IsUrgentMainBeneficiary(*ticket, priority);
			});
		if (handoff != end(heads)) {
			return *handoff;
		}
	}
	auto best = PriorityClass::Count;
	for (const auto ticket : heads) {
		best = std::min(best, priorityForLocked(*ticket, state, now));
	}
	auto runtimes = std::set<ProxyRuntimeId>();
	for (const auto ticket : heads) {
		if (priorityForLocked(*ticket, state, now) == best) {
			runtimes.emplace(ticket->key.runtimeId);
		}
	}
	const auto last = fairness.lastRuntime[PriorityIndex(best)];
	auto runtime = runtimes.upper_bound(last);
	if (runtime == end(runtimes)) {
		runtime = begin(runtimes);
	}
	const auto desired = NextBackgroundUse(fairness, *runtime);
	const auto desiredAvailable = ranges::find_if(
		heads,
		[&](const Ticket *ticket) {
			return ticket->key.runtimeId == *runtime
				&& priorityForLocked(*ticket, state, now) == best
				&& ticket->use == desired;
		}) != end(heads);
	auto result = static_cast<Ticket*>(nullptr);
	for (const auto ticket : heads) {
		if (ticket->key.runtimeId != *runtime
			|| priorityForLocked(*ticket, state, now) != best
			|| (desiredAvailable
				&& IsBackground(ticket->use)
				&& ticket->use != desired)) {
			continue;
		}
		if (!result
			|| ticket->enqueuedAt < result->enqueuedAt
			|| (ticket->enqueuedAt == result->enqueuedAt
				&& ticket->sequence < result->sequence)) {
			result = ticket;
			continue;
		}
	}
	return result;
}

std::vector<Ticket*> EndpointAdmissionArbiter::Private::orderLocked(
		std::vector<Ticket*> pool,
		const MtProxy::EndpointState &state,
		crl::time now,
		FairnessState fairness) const {
	auto result = std::vector<Ticket*>();
	result.reserve(pool.size());
	while (!pool.empty()) {
		auto eligible = std::set<AdmissionTicketKey>();
		for (const auto ticket : pool) {
			eligible.emplace(ticket->key);
		}
		const auto selected = selectLocked(
			pool,
			eligible,
			state,
			now,
			fairness);
		if (!selected) {
			break;
		}
		result.push_back(selected);
		AdvanceFairness(
			fairness,
			*selected,
			priorityForLocked(*selected, state, now));
		pool.erase(std::find(begin(pool), end(pool), selected));
	}
	return result;
}

auto EndpointAdmissionArbiter::Private::activeCountsLocked(
		const MtProxy::EndpointState &state) const
-> MtProxy::EndpointUseCounts {
	auto result = MtProxy::EndpointUseCounts();
	for (const auto &entry : state.attemptStarts) {
		const auto &attempt = entry.second;
		if (attempt.admissionActive) {
			result = MtProxy::BeginEndpointAdmission(result, attempt.use);
		}
	}
	return result;
}

auto EndpointAdmissionArbiter::Private::scheduledCountsLocked(
		const QString &endpointKey) const
-> MtProxy::EndpointUseCounts {
	auto result = MtProxy::EndpointUseCounts();
	const auto schedule = _endpoints.find(endpointKey);
	if (schedule == end(_endpoints)) {
		return result;
	}
	for (const auto &key : schedule->second.order) {
		const auto i = _tickets.find(key);
		if (i != end(_tickets)
			&& (i->second->lifecycle == ProxySchedulerLifecycle::Scheduled
				|| i->second->lifecycle
					== ProxySchedulerLifecycle::Granted)) {
			result = MtProxy::BeginEndpointAdmission(
				result,
				i->second->use);
		}
	}
	return result;
}

int EndpointAdmissionArbiter::Private::urgentWaitersLocked(
		const QString &endpointKey,
		const MtProxy::EndpointState &state,
		crl::time now) const {
	const auto schedule = _endpoints.find(endpointKey);
	if (schedule == end(_endpoints)) {
		return 0;
	}
	auto representatives = std::map<RuntimeGenerationKey, const Ticket*>();
	for (const auto &key : schedule->second.order) {
		const auto i = _tickets.find(key);
		if (i == end(_tickets)
			|| i->second->use != MtProxy::EndpointUse::Main
			|| !WaitingForHandoff(i->second->lifecycle)
			|| !ticketCurrentLocked(*i->second, state)) {
			continue;
		}
		const auto candidate = i->second.get();
		const auto runtimeGeneration = TicketRuntimeGeneration(*candidate);
		const auto selected = representatives.find(runtimeGeneration);
		if (selected == end(representatives)) {
			representatives.emplace(runtimeGeneration, candidate);
			continue;
		}
		const auto candidateRecovery = ownsMainRecoveryLocked(*candidate);
		const auto selectedRecovery = ownsMainRecoveryLocked(*selected->second);
		const auto candidatePriority = priorityForLocked(
			*candidate,
			state,
			now);
		const auto selectedPriority = priorityForLocked(
			*selected->second,
			state,
			now);
		if ((candidateRecovery && !selectedRecovery)
			|| (candidateRecovery == selectedRecovery
				&& (candidatePriority < selectedPriority
					|| (candidatePriority == selectedPriority
						&& candidate->sequence
							< selected->second->sequence)))) {
			selected->second = candidate;
		}
	}
	auto urgent = std::set<RuntimeGenerationKey>();
	for (const auto &[runtimeGeneration, ticket] : representatives) {
		if (IsUrgentMainPriority(priorityForLocked(*ticket, state, now))) {
			urgent.emplace(runtimeGeneration);
		}
	}
	return int(urgent.size());
}

auto EndpointAdmissionArbiter::Private::policyLocked(
		const Ticket &ticket,
		const MtProxy::EndpointState &state,
		const MtProxy::EndpointUseCounts &active,
		const MtProxy::EndpointUseCounts &scheduled,
		int urgentWaiters,
		const DrainInputs &inputs,
		bool ignoreExpansionRetry) const
-> MtProxy::EndpointConcurrencyPolicy {
	const auto foregroundTransfer = IsBackground(ticket.use)
		&& ticket.key.runtimeId == _storage.foregroundRuntimeId;
	const auto mainProof = MtProxy::CurrentMainRelayProof(state, {
		.runtimeId = ticket.key.runtimeId,
		.proxyGeneration = ticket.proxyGeneration,
	});
	const auto endpointMainProof = MtProxy::EndpointMainRelayProof(state);
	const auto bootstrap = (ticket.use == MtProxy::EndpointUse::Main)
		&& (endpointMainProof.strength
			== MtProxy::MainRelayProofStrength::None);
	const auto expansion = MtProxy::FindEndpointExpansionFailure(
		state,
		{
			.runtimeId = ticket.key.runtimeId,
			.proxyGeneration = ticket.proxyGeneration,
		},
		ticket.use);
	const auto &opening = bootstrap
		? state.opening.bootstrap
		: expansion
		? *expansion
		: state.opening.expansion;
	const auto verdict = TicketVerdict(ticket, state);
	return MtProxy::EvaluateEndpointAdmission({
		.active = active,
		.scheduled = scheduled,
		.use = ticket.use,
		.mainProof = mainProof.strength,
		.endpointMainProof = endpointMainProof.strength,
		.lastFailure = opening.reason,
		.urgentMainDemand = urgentWaiters,
		.retryUntil = ignoreExpansionRetry
			? std::max(
				state.opening.bootstrap.retryUntil,
				verdict ? verdict->retryUntil : crl::time())
			: TicketRetryUntil(
				ticket,
				state,
				_storage.foregroundRuntimeId),
		.nextHandshakeAt = state.nextHandshakeAt,
		.lastRelaySuccessAt = std::max(
			endpointMainProof.provenAt,
			endpointMainProof.lastPayloadAt),
		.now = inputs.now,
		.endpointRelayProven = endpointMainProof.strength
			!= MtProxy::MainRelayProofStrength::None,
		.healthy = state.healthy,
		.fastWarmup = inputs.fastWarmup(ticket.key.runtimeId),
		.foregroundTransfer = foregroundTransfer,
		.bootstrapFailure = bootstrap,
	});
}

bool EndpointAdmissionArbiter::Private::baseEligibleLocked(
		const Ticket &ticket,
		const MtProxy::EndpointState &state,
		int urgentWaiters,
		crl::time now,
		bool ignoreTicketRetry) const {
	if (!ticketCurrentLocked(ticket, state)
		|| (!ignoreTicketRetry && ticket.retryAt > now)) {
		return false;
	}
	if (ticket.use == MtProxy::EndpointUse::Maintenance) {
		return !urgentWaiters;
	}
	if (!IsBackground(ticket.use)) {
		if (ticket.use != MtProxy::EndpointUse::Auxiliary) {
			return true;
		}
	}
	const auto foregroundTransfer = IsBackground(ticket.use)
		&& ticket.key.runtimeId == _storage.foregroundRuntimeId;
	const auto canShareUrgentMain = foregroundTransfer
		&& ProvenEndpointCapacity(state) > 1;
	const auto hasMainProof = MtProxy::HasCurrentMainRelayProof(state, {
		.runtimeId = ticket.key.runtimeId,
		.proxyGeneration = ticket.proxyGeneration,
	});
	return (!urgentWaiters || canShareUrgentMain) && hasMainProof;
}

auto EndpointAdmissionArbiter::Private::capacityDecisionLocked(
		const Ticket &candidate,
		const MtProxy::EndpointState &state,
		const MtProxy::EndpointUseCounts &scheduled,
		int urgentWaiters,
		crl::time now,
		std::optional<AdmissionTicketKey> noVictimUrgentClaimant) const
-> CandidateCapacityDecision {
	const auto limit = state.liveBudget.learnedLimit;
	const auto scheduledCount = MtProxy::TotalEndpointUseCount(scheduled);
	const auto commitmentCount = MtProxy::EndpointCapacityCommitmentCount(state)
		+ scheduledCount;
	if (!limit || commitmentCount < limit) {
		return { .kind = CapacityDecisionKind::Ordinary };
	}
	const auto &probe = state.liveBudget.capacityProbe;
	const auto blocked = CandidateCapacityDecision{
		.kind = CapacityDecisionKind::Blocked,
		.retryAt = (probe.stage == MtProxy::CapacityProbeStage::Cooldown)
			? probe.retryAt
			: crl::time(),
	};
	if (commitmentCount > limit
		|| scheduledCount
		|| MtProxy::ActiveEndpointAdmissionCount(state)) {
		return blocked;
	}
	const auto runtimeGeneration = TicketRuntimeGeneration(candidate);
	const auto reserved = MtProxy::CapacityProbeReservedFor(
		state.liveBudget,
		candidate.key,
		runtimeGeneration);
	const auto retained = reserved
		&& (candidate.lifecycle == ProxySchedulerLifecycle::Scheduled
			|| candidate.lifecycle == ProxySchedulerLifecycle::Granted);
	const auto urgentMain = IsUrgentMainBeneficiary(
		candidate,
		priorityForLocked(candidate, state, now));
	const auto urgentProbeAllowed = !urgentWaiters
		|| (urgentMain
			&& (retained
				|| (noVictimUrgentClaimant
					&& *noVictimUrgentClaimant == candidate.key)));
	if (!urgentProbeAllowed) {
		return blocked;
	}
	if (candidate.lifecycle == ProxySchedulerLifecycle::Queued) {
		return (probe.stage == MtProxy::CapacityProbeStage::Idle)
			? CandidateCapacityDecision{
				.kind = CapacityDecisionKind::Probe,
			}
			: blocked;
	}
	return retained
		? CandidateCapacityDecision{
			.kind = CapacityDecisionKind::Probe,
		}
		: blocked;
}

auto EndpointAdmissionArbiter::Private::requestLanePreemptionLocked(
		const QString &endpointKey,
		MtProxy::EndpointState &state,
		DrainInputs &inputs,
		Actions &actions)
-> std::optional<AdmissionTicketKey> {
	auto &laneSchedule = _laneSchedules[endpointKey];
	if (laneSchedule.preemption || laneSchedule.resuming) {
		return std::nullopt;
	}
	const auto schedule = _endpoints.find(endpointKey);
	if (schedule == end(_endpoints)) {
		return std::nullopt;
	}
	if (laneSchedule.handoffBeneficiary) {
		const auto key = *laneSchedule.handoffBeneficiary;
		const auto ticket = _tickets.find(key);
		const auto priority = (ticket != end(_tickets))
			? priorityForLocked(*ticket->second, state, inputs.now)
			: PriorityClass::Count;
		if (ticket == end(_tickets)
			|| !WaitingForHandoff(ticket->second->lifecycle)
			|| !ticketCurrentLocked(*ticket->second, state)
			|| !IsUrgentMainBeneficiary(*ticket->second, priority)) {
			detachLanePreemptionBeneficiaryLocked(endpointKey, key);
		}
	}
	auto pool = std::vector<Ticket*>();
	auto eligible = std::set<AdmissionTicketKey>();
	for (const auto &key : schedule->second.order) {
		const auto i = _tickets.find(key);
		if (i == end(_tickets)
			|| i->second->lifecycle != ProxySchedulerLifecycle::Queued) {
			continue;
		}
		auto &ticket = *i->second;
		const auto priority = priorityForLocked(ticket, state, inputs.now);
		if (!IsUrgentMainBeneficiary(ticket, priority)) {
			continue;
		}
		const auto verdict = TicketVerdict(ticket, state);
		const auto boundary = std::max({
			ticket.notBeforeAt,
			state.opening.bootstrap.retryUntil,
			verdict ? verdict->retryUntil : crl::time(),
			state.nextHandshakeAt,
		});
		if (boundary > inputs.now
			|| !baseEligibleLocked(
				ticket,
				state,
				urgentWaitersLocked(endpointKey, state, inputs.now),
				inputs.now,
				true)) {
			continue;
		}
		pool.push_back(&ticket);
		eligible.emplace(ticket.key);
	}
	const auto beneficiary = selectLocked(
		pool,
		eligible,
		state,
		inputs.now,
		schedule->second.fairness);
	if (!beneficiary) {
		return std::nullopt;
	}
	const auto beneficiaryPriority = priorityForLocked(
		*beneficiary,
		state,
		inputs.now);
	for (const auto &key : schedule->second.order) {
		const auto i = _tickets.find(key);
		if (i != end(_tickets)
			&& (i->second->lifecycle == ProxySchedulerLifecycle::Scheduled
				|| i->second->lifecycle == ProxySchedulerLifecycle::Granted)
			&& priorityForLocked(*i->second, state, inputs.now)
				> beneficiaryPriority) {
			demoteTicketLocked(*i->second, actions);
		}
	}
	const auto active = activeCountsLocked(state);
	const auto scheduled = scheduledCountsLocked(endpointKey);
	const auto urgentWaiters = urgentWaitersLocked(
		endpointKey,
		state,
		inputs.now);
	if (!baseEligibleLocked(
			*beneficiary,
			state,
			urgentWaiters,
			inputs.now,
			true)) {
		return std::nullopt;
	}
	const auto openingPolicy = policyLocked(
		*beneficiary,
		state,
		active,
		scheduled,
		urgentWaiters,
		inputs,
		true);
	auto victim = std::optional<LaneVictim>();
	const auto considerVictim = [&](LaneVictim candidate) {
		if (!victim
			|| std::tie(
				candidate.durable,
				candidate.foreground,
				candidate.startedAt,
				candidate.identity)
				< std::tie(
					victim->durable,
					victim->foreground,
					victim->startedAt,
					victim->identity)) {
			victim = std::move(candidate);
		}
	};
	const auto attemptCurrent = [&](const MtProxy::EndpointAttemptState &attempt) {
		return IsBackground(attempt.use)
			&& !attempt.preempting
			&& !attempt.terminalVerdict
			&& attempt.ticketKey.ticketId
			&& attempt.ticketKey.runtimeId == attempt.runtimeId
			&& attempt.owner
			&& attempt.laneControl
			&& runtimeLiveLocked(attempt.runtimeId)
			&& MtProxy::RuntimeGenerationIsCurrent(state, {
				.runtimeId = attempt.runtimeId,
				.proxyGeneration = attempt.proxyGeneration,
			});
	};
	auto reclaim = std::optional<LaneReclaimKind>();
	if (!openingPolicy.admissionAllowed) {
		for (const auto &[attemptId, attempt] : state.attemptStarts) {
			if (!attempt.admissionActive || !attemptCurrent(attempt)) {
				continue;
			}
			const auto withoutVictim = MtProxy::ReleaseEndpointAdmission(
				active,
				attempt.use);
			if (!policyLocked(
					*beneficiary,
					state,
					withoutVictim,
					scheduled,
					urgentWaiters,
					inputs,
					true).admissionAllowed) {
				continue;
			}
			considerVictim({
				.identity = {
					.runtimeId = attempt.runtimeId,
					.proxyGeneration = attempt.proxyGeneration,
					.attemptId = attemptId,
				},
				.ticketKey = attempt.ticketKey,
				.use = attempt.use,
				.owner = attempt.owner,
				.ownerDestroyed = attempt.ownerDestroyed,
				.laneControl = attempt.laneControl,
				.startedAt = attempt.attemptStartedAt,
				.foreground = attempt.runtimeId
					== _storage.foregroundRuntimeId,
			});
		}
		if (victim) {
			reclaim = LaneReclaimKind::Opening;
		}
	} else {
		const auto limit = state.liveBudget.learnedLimit;
		const auto commitmentCount
			= MtProxy::EndpointCapacityCommitmentCount(state)
			+ MtProxy::TotalEndpointUseCount(scheduled);
		if (!limit || commitmentCount != limit) {
			return std::nullopt;
		}
		for (const auto &[attemptId, attempt] : state.attemptStarts) {
			if (!attemptCurrent(attempt)) {
				continue;
			}
			considerVictim({
				.identity = {
					.runtimeId = attempt.runtimeId,
					.proxyGeneration = attempt.proxyGeneration,
					.attemptId = attemptId,
				},
				.ticketKey = attempt.ticketKey,
				.use = attempt.use,
				.owner = attempt.owner,
				.ownerDestroyed = attempt.ownerDestroyed,
				.laneControl = attempt.laneControl,
				.startedAt = attempt.attemptStartedAt,
				.foreground = attempt.runtimeId
					== _storage.foregroundRuntimeId,
			});
		}
		for (const auto &[identity, lane] : state.liveLanes) {
			const auto proof = state.relayProofs.find(identity);
			if (!IsBackground(lane.use)
				|| lane.preempting
				|| (proof != end(state.relayProofs)
					&& proof->second.preempting)
				|| !lane.ticketKey.ticketId
				|| lane.ticketKey.runtimeId != identity.runtimeId
				|| !lane.owner
				|| !lane.laneControl
				|| !runtimeLiveLocked(identity.runtimeId)
				|| !MtProxy::RuntimeGenerationIsCurrent(state, {
					.runtimeId = identity.runtimeId,
					.proxyGeneration = identity.proxyGeneration,
				})) {
				continue;
			}
			considerVictim({
				.identity = identity,
				.ticketKey = lane.ticketKey,
				.use = lane.use,
				.owner = lane.owner,
				.ownerDestroyed = lane.ownerDestroyed,
				.laneControl = lane.laneControl,
				.startedAt = lane.attemptStartedAt,
				.foreground = identity.runtimeId
					== _storage.foregroundRuntimeId,
				.durable = true,
			});
		}
		if (victim) {
			reclaim = LaneReclaimKind::Capacity;
		}
	}
	if (!victim || !reclaim) {
		if (!openingPolicy.admissionAllowed) {
			return std::nullopt;
		}
		const auto capacity = capacityDecisionLocked(
			*beneficiary,
			state,
			scheduled,
			urgentWaiters,
			inputs.now,
			beneficiary->key);
		return (capacity.kind == CapacityDecisionKind::Probe)
			? std::optional<AdmissionTicketKey>(beneficiary->key)
			: std::nullopt;
	}
	const auto victimIdentity = victim->identity;
	const auto runtime = _runtimes.find(victimIdentity.runtimeId);
	if (runtime == end(_runtimes)) {
		return std::nullopt;
	}
	const auto token = ++_lastLaneToken;
	const auto deadlineAt = inputs.now + kLaneCommandAckTimeout;
	const auto proof = state.relayProofs.find(victimIdentity);
	if (proof != end(state.relayProofs)) {
		proof->second.preempting = true;
	}
	const auto attempt = state.attemptStarts.find(victimIdentity.attemptId);
	if (attempt != end(state.attemptStarts)
		&& attempt->second.runtimeId == victimIdentity.runtimeId
		&& attempt->second.proxyGeneration
			== victimIdentity.proxyGeneration) {
		attempt->second.preempting = true;
	}
	const auto liveLane = state.liveLanes.find(victimIdentity);
	if (liveLane != end(state.liveLanes)) {
		liveLane->second.preempting = true;
	}
	laneSchedule.preemption = LanePreemption{
		.token = token,
		.deadlineAt = deadlineAt,
		.reclaim = *reclaim,
		.beneficiary = beneficiary->key,
		.victim = victimIdentity,
		.victimTicketKey = victim->ticketKey,
		.victimUse = victim->use,
		.owner = victim->owner,
		.ownerDestroyed = victim->ownerDestroyed,
		.laneControl = victim->laneControl,
	};
	const auto weak = _context;
	actions.posts.push_back({
		.dispatch = runtime->second,
		.target = victim->owner,
		.callback = [
			weak,
			endpointKey,
			token,
			deadlineAt,
			victimIdentity,
			laneControl = victim->laneControl
		]() mutable {
			(*laneControl)({
				.type = MtProxy::EndpointLaneCommandType::Suspend,
				.token = token,
				.attemptId = victimIdentity.attemptId,
				.deadlineAt = deadlineAt,
				.authorize = [weak, endpointKey, token, victimIdentity] {
					if (const auto context = weak.lock()) {
						return context->endpointAdmissionArbiter(
						).authorizeLaneSuspension(
							endpointKey,
							token,
							victimIdentity.runtimeId,
							victimIdentity.proxyGeneration,
							victimIdentity.attemptId);
					}
					return false;
				},
				.demand = [weak, endpointKey, token, victimIdentity] {
					if (const auto context = weak.lock()) {
						context->endpointAdmissionArbiter().demandLaneResume(
							endpointKey,
							token,
							victimIdentity.runtimeId,
							victimIdentity.proxyGeneration,
							victimIdentity.attemptId);
					}
				},
				.done = [
					weak,
					endpointKey,
					token,
					victimIdentity
				](MtProxy::EndpointLaneCommandResult result) {
					if (const auto context = weak.lock()) {
						context->endpointAdmissionArbiter(
						).acknowledgeLaneSuspension(
							endpointKey,
							token,
							victimIdentity.runtimeId,
							victimIdentity.proxyGeneration,
							victimIdentity.attemptId,
							result,
							true);
					}
				},
			});
		},
		.missing = [weak, endpointKey, token, victimIdentity] {
			if (const auto context = weak.lock()) {
				context->endpointAdmissionArbiter(
				).acknowledgeLaneSuspension(
					endpointKey,
					token,
					victimIdentity.runtimeId,
					victimIdentity.proxyGeneration,
					victimIdentity.attemptId,
					MtProxy::EndpointLaneCommandResult::Retry,
					false);
			}
		},
	});
	return std::nullopt;
}

void EndpointAdmissionArbiter::Private::resumeSuspendedLaneLocked(
		const QString &endpointKey,
		MtProxy::EndpointState &state,
		DrainInputs &inputs,
		Actions &actions) {
	const auto lane = _laneSchedules.find(endpointKey);
	if (lane == end(_laneSchedules)) {
		return;
	}
	auto &suspended = lane->second.suspended;
	for (auto i = begin(suspended); i != end(suspended);) {
		if (!IsBackground(i->use)
			|| !i->token
			|| !i->identity.runtimeId
			|| !i->identity.proxyGeneration
			|| !i->identity.attemptId
			|| !i->ticketKey.ticketId
			|| i->ticketKey.runtimeId != i->identity.runtimeId
			|| !i->owner
			|| !i->laneControl
			|| !runtimeLiveLocked(i->identity.runtimeId)
			|| !MtProxy::RuntimeGenerationIsCurrent(state, {
				.runtimeId = i->identity.runtimeId,
				.proxyGeneration = i->identity.proxyGeneration,
			})) {
			QObject::disconnect(i->ownerDestroyed);
			i = suspended.erase(i);
		} else {
			++i;
		}
	}
	if (lane->second.resuming) {
		const auto &entry = *lane->second.resuming;
		if (!IsBackground(entry.use)
			|| !entry.token
			|| !entry.identity.runtimeId
			|| !entry.identity.proxyGeneration
			|| !entry.identity.attemptId
			|| !entry.ticketKey.ticketId
			|| entry.ticketKey.runtimeId != entry.identity.runtimeId
			|| !entry.owner
			|| !entry.laneControl
			|| !runtimeLiveLocked(entry.identity.runtimeId)
			|| !MtProxy::RuntimeGenerationIsCurrent(state, {
				.runtimeId = entry.identity.runtimeId,
				.proxyGeneration = entry.identity.proxyGeneration,
			})) {
			QObject::disconnect(entry.ownerDestroyed);
			lane->second.resuming.reset();
		}
	}
	if (lane->second.preemption || lane->second.resuming) {
		return;
	}
	if (lane->second.handoffBeneficiary) {
		const auto key = *lane->second.handoffBeneficiary;
		const auto successor = _tickets.find(key);
		const auto priority = (successor != end(_tickets))
			? priorityForLocked(*successor->second, state, inputs.now)
			: PriorityClass::Count;
		if (successor == end(_tickets)
			|| !WaitingForHandoff(successor->second->lifecycle)
			|| !ticketCurrentLocked(*successor->second, state)
			|| !IsUrgentMainBeneficiary(*successor->second, priority)) {
			detachLanePreemptionBeneficiaryLocked(endpointKey, key);
		}
	}
	if (suspended.empty()) {
		_laneSchedules.erase(lane);
		return;
	}
	const auto resumable = [&](const SuspendedLane &entry) {
		const auto runtimeGeneration = RuntimeGenerationKey{
			.runtimeId = entry.identity.runtimeId,
			.proxyGeneration = entry.identity.proxyGeneration,
		};
		const auto successor = _tickets.find(entry.successorTicketKey);
		const auto successorPriority = successor != end(_tickets)
			? priorityForLocked(*successor->second, state, inputs.now)
			: PriorityClass::Count;
		const auto successorPending = entry.successorTicketKey.ticketId
			&& ((lane->second.handoffBeneficiary
					&& *lane->second.handoffBeneficiary
						== entry.successorTicketKey)
				|| (successor != end(_tickets)
					&& WaitingForHandoff(successor->second->lifecycle)
					&& ticketCurrentLocked(*successor->second, state)
					&& IsUrgentMainBeneficiary(
						*successor->second,
						successorPriority)));
		return entry.demanded
			&& !successorPending
			&& MtProxy::HasCurrentMainRelayProof(state, runtimeGeneration);
	};
	auto selected = ranges::find_if(suspended, [&](const SuspendedLane &entry) {
		return entry.identity.runtimeId == _storage.foregroundRuntimeId
			&& resumable(entry);
	});
	if (selected == end(suspended)) {
		selected = ranges::find_if(suspended, resumable);
	}
	if (selected == end(suspended)) {
		return;
	}
	lane->second.resuming = std::move(*selected);
	suspended.erase(selected);
	lane->second.resuming->commandDeadlineAt
		= inputs.now + kLaneCommandAckTimeout;
	const auto &value = *lane->second.resuming;
	const auto runtime = _runtimes.find(value.identity.runtimeId);
	if (runtime == end(_runtimes)) {
		QObject::disconnect(value.ownerDestroyed);
		lane->second.resuming.reset();
		return;
	}
	const auto identity = value.identity;
	const auto token = value.token;
	const auto deadlineAt = value.commandDeadlineAt;
	const auto weak = _context;
	actions.posts.push_back({
		.dispatch = runtime->second,
		.target = value.owner,
		.callback = [
			weak,
			endpointKey,
			identity,
			control = value.laneControl,
			token,
			deadlineAt
		]() mutable {
			(*control)({
				.type = MtProxy::EndpointLaneCommandType::Resume,
				.token = token,
				.deadlineAt = deadlineAt,
				.demandRequired = true,
				.done = [
					weak,
					endpointKey,
					identity,
					token,
					deadlineAt
				](MtProxy::EndpointLaneCommandResult result) {
					if (const auto context = weak.lock()) {
						context->endpointAdmissionArbiter(
						).acknowledgeLaneResume(
							endpointKey,
							token,
							identity.runtimeId,
							identity.proxyGeneration,
							identity.attemptId,
							deadlineAt,
							result,
							true);
					}
				},
			});
		},
		.missing = [weak, endpointKey, identity, token, deadlineAt] {
			if (const auto context = weak.lock()) {
				context->endpointAdmissionArbiter(
				).acknowledgeLaneResume(
					endpointKey,
					token,
					identity.runtimeId,
					identity.proxyGeneration,
					identity.attemptId,
					deadlineAt,
					MtProxy::EndpointLaneCommandResult::Retry,
					false);
			}
		},
	});
}

void EndpointAdmissionArbiter::Private::invalidateTicketLocked(
		Ticket &ticket,
		Actions &actions) {
	actions.context = _context;
	actions.invalidations.emplace_back(
		ticket.endpoint,
		RuntimeGenerationKey{
			.runtimeId = ticket.key.runtimeId,
			.proxyGeneration = ticket.proxyGeneration,
		});
}

void EndpointAdmissionArbiter::Private::postStatusLocked(
		Ticket &ticket,
		Actions &actions) {
	invalidateTicketLocked(ticket, actions);
	if (!ticket.callbacks || !ticket.callbacks->status) {
		return;
	}
	const auto runtime = _runtimes.find(ticket.key.runtimeId);
	if (runtime == end(_runtimes)) {
		return;
	}
	const auto weak = _context;
	const auto key = ticket.key;
	const auto revision = ticket.revision;
	const auto transition = ticket.transition;
	const auto lifecycle = ticket.lifecycle;
	actions.posts.push_back({
		.dispatch = runtime->second,
		.target = ticket.owner,
		.callback = [weak, key, revision, transition, lifecycle] {
			if (const auto context = weak.lock()) {
				context->endpointAdmissionArbiter().deliverStatus(
					key,
					revision,
					transition,
					lifecycle);
			}
		},
		.missing = [weak, key, revision] {
			if (const auto context = weak.lock()) {
				context->endpointAdmissionArbiter().cancel(key, revision);
			}
		},
	});
}

void EndpointAdmissionArbiter::Private::postGenerationCancelledStatusLocked(
		const Ticket &ticket,
		Actions &actions) {
	if (!ticket.callbacks || !ticket.callbacks->status) {
		return;
	}
	const auto runtime = _runtimes.find(ticket.key.runtimeId);
	if (runtime == end(_runtimes)) {
		return;
	}
	const auto callbacks = ticket.callbacks;
	const auto update = EndpointAdmissionUpdate{
		.key = ticket.key,
		.revision = ticket.revision,
		.lifecycle = ProxySchedulerLifecycle::Cancelled,
		.use = ticket.use,
		.enqueuedAt = ticket.enqueuedAt,
		.scheduledOpenAt = ticket.scheduledOpenAt,
		.retryAfter = ticket.retryAfter,
		.blockedBy = ticket.blockedBy,
	};
	actions.posts.push_back({
		.dispatch = runtime->second,
		.target = ticket.owner,
		.callback = [callbacks, update]() mutable {
			if (callbacks->status) {
				callbacks->status(std::move(update));
			}
		},
	});
}

void EndpointAdmissionArbiter::Private::postGrantLocked(
		Ticket &ticket,
		Actions &actions) {
	const auto runtime = _runtimes.find(ticket.key.runtimeId);
	if (runtime == end(_runtimes)) {
		return;
	}
	const auto weak = _context;
	const auto key = ticket.key;
	const auto revision = ticket.revision;
	const auto transition = ticket.transition;
	const auto lifecycle = ticket.lifecycle;
	actions.posts.push_back({
		.dispatch = runtime->second,
		.target = ticket.owner,
		.callback = [weak, key, revision, transition, lifecycle] {
			if (const auto context = weak.lock()) {
				context->endpointAdmissionArbiter().deliverGrant(
					key,
					revision,
					transition,
					lifecycle);
			}
		},
		.missing = [weak, key, revision] {
			if (const auto context = weak.lock()) {
				context->endpointAdmissionArbiter().cancel(key, revision);
			}
		},
	});
}

auto EndpointAdmissionArbiter::Private::takeTicketLocked(
		AdmissionTicketKey key)
-> std::unique_ptr<Ticket> {
	const auto i = _tickets.find(key);
	if (i == end(_tickets)) {
		return nullptr;
	}
	auto result = std::move(i->second);
	_tickets.erase(i);
	detachLanePreemptionBeneficiaryLocked(result->endpointKey, key);
	const auto schedule = _endpoints.find(result->endpointKey);
	if (schedule != end(_endpoints)) {
		auto &order = schedule->second.order;
		order.erase(std::remove(begin(order), end(order), key), end(order));
		if (order.empty()) {
			_endpoints.erase(schedule);
		}
	}
	return result;
}

void EndpointAdmissionArbiter::Private::releaseReservedCapacityProbeLocked(
		const Ticket &ticket) {
	const auto state = _storage.states.find(ticket.endpointKey);
	if (state == end(_storage.states)) {
		return;
	}
	static_cast<void>(MtProxy::ReleaseReservedCapacityProbe(
		state->second.liveBudget,
		ticket.key,
		TicketRuntimeGeneration(ticket)));
}

void EndpointAdmissionArbiter::Private::detachLanePreemptionBeneficiaryLocked(
		const QString &endpointKey,
		AdmissionTicketKey key) {
	const auto lane = _laneSchedules.find(endpointKey);
	if (lane == end(_laneSchedules)) {
		return;
	}
	if (lane->second.handoffBeneficiary
		&& *lane->second.handoffBeneficiary == key) {
		lane->second.handoffBeneficiary.reset();
	}
	if (lane->second.preemption
		&& lane->second.preemption->beneficiary == key) {
		lane->second.preemption->beneficiary = {};
	}
	for (auto &entry : lane->second.suspended) {
		if (entry.successorTicketKey == key) {
			entry.successorTicketKey = {};
		}
	}
	if (lane->second.resuming
		&& lane->second.resuming->successorTicketKey == key) {
		lane->second.resuming->successorTicketKey = {};
	}
}

void EndpointAdmissionArbiter::Private::cancelTicketLocked(
		AdmissionTicketKey key,
		uint64 revision,
		Actions &actions) {
	const auto i = _tickets.find(key);
	if (i == end(_tickets)
		|| (revision && i->second->revision != revision)) {
		return;
	}
	auto &ticket = *i->second;
	if (ticket.acceptedRecoveryToken) {
		static_cast<void>(
			MtProxy::FinishMainRecoveryByAdmissionTicketLocked(
				_storage,
				ticket.endpointKey,
				{
					.runtimeId = ticket.key.runtimeId,
					.proxyGeneration = ticket.proxyGeneration,
				},
				ticket.use,
				ticket.acceptedRecoveryToken,
				ticket.key));
	}
	detachLanePreemptionBeneficiaryLocked(ticket.endpointKey, key);
	releaseReservedCapacityProbeLocked(ticket);
	if (ticket.reservationId) {
		const auto state = _storage.openStates.find(ticket.endpointKey);
		if (state != end(_storage.openStates)) {
			static_cast<void>(MtProxy::CancelOpenSlotLocked(
				state->second,
				ticket.reservationId));
		}
	}
	if (ticket.traceId) {
		_storage.activeTraces.erase(ticket.traceId);
	}
	ticket.lifecycle = ProxySchedulerLifecycle::Cancelled;
	++ticket.transition;
	invalidateTicketLocked(ticket, actions);
	actions.removed.push_back(takeTicketLocked(key));
}

void EndpointAdmissionArbiter::Private::demoteTicketLocked(
		Ticket &ticket,
		Actions &actions) {
	detachLanePreemptionBeneficiaryLocked(
		ticket.endpointKey,
		ticket.key);
	releaseReservedCapacityProbeLocked(ticket);
	if (ticket.reservationId) {
		const auto state = _storage.openStates.find(ticket.endpointKey);
		if (state != end(_storage.openStates)) {
			static_cast<void>(MtProxy::CancelOpenSlotLocked(
				state->second,
				ticket.reservationId));
		}
	}
	ticket.reservationId = 0;
	ticket.scheduledOpenAt = 0;
	ticket.nextOpenAt = 0;
	ticket.reevaluateAt = 0;
	ticket.retryAfter = 0;
	ticket.lifecycle = ProxySchedulerLifecycle::Queued;
	++ticket.transition;
	postStatusLocked(ticket, actions);
}

void EndpointAdmissionArbiter::Private::finishLanePreemptionLocked(
		const QString &endpointKey,
		MtProxy::EndpointState *state,
		uint64 token,
		const MtProxy::RelayProofIdentity &identity,
		LanePreemptionTerminal terminal) {
	const auto lane = _laneSchedules.find(endpointKey);
	if (lane == end(_laneSchedules)
		|| !lane->second.preemption
		|| lane->second.preemption->token != token
		|| lane->second.preemption->victim != identity) {
		return;
	}
	auto preemption = std::move(*lane->second.preemption);
	lane->second.preemption.reset();
	const auto authorized = preemption.stage
		== LanePreemptionStage::Authorized;
	const auto preserveSuspended = authorized
		&& (terminal == LanePreemptionTerminal::Applied
			|| terminal == LanePreemptionTerminal::Expired);
	const auto retireWithoutSuspension
		= terminal == LanePreemptionTerminal::VictimLost
		|| terminal == LanePreemptionTerminal::NotApplicable;
	if (!state) {
		QObject::disconnect(preemption.ownerDestroyed);
		return;
	}
	const auto proof = state->relayProofs.find(identity);
	const auto proofMatches = proof != end(state->relayProofs)
		&& proof->second.ticketKey == preemption.victimTicketKey
		&& proof->second.use == preemption.victimUse;
	const auto attempt = state->attemptStarts.find(identity.attemptId);
	const auto attemptMatches = attempt != end(state->attemptStarts)
		&& attempt->second.runtimeId == identity.runtimeId
		&& attempt->second.proxyGeneration == identity.proxyGeneration
		&& attempt->second.ticketKey == preemption.victimTicketKey
		&& attempt->second.use == preemption.victimUse;
	const auto liveLane = state->liveLanes.find(identity);
	const auto liveLaneMatches = liveLane != end(state->liveLanes)
		&& liveLane->second.ticketKey == preemption.victimTicketKey
		&& liveLane->second.use == preemption.victimUse;
	const auto victimPresent = attemptMatches || liveLaneMatches;
	if (!preserveSuspended && !retireWithoutSuspension) {
		if (proofMatches) {
			proof->second.preempting = false;
		}
		if (attemptMatches) {
			attempt->second.preempting = false;
		}
		if (liveLaneMatches) {
			liveLane->second.preempting = false;
		}
		if (!attemptMatches && !liveLaneMatches) {
			QObject::disconnect(preemption.ownerDestroyed);
		}
		return;
	}
	static_cast<void>(MtProxy::ReleaseActiveCapacityProbe(
		state->liveBudget,
		identity));
	if (proofMatches) {
		static_cast<void>(MtProxy::RetireRelayProof(*state, identity));
	}
	if (attemptMatches) {
		state->attemptStarts.erase(attempt);
	}
	if (liveLaneMatches) {
		state->liveLanes.erase(liveLane);
	}
	MtProxy::SynchronizeEndpointAdmissionAggregate(*state);
	const auto canPreserve = preserveSuspended
		&& victimPresent
		&& IsBackground(preemption.victimUse)
		&& preemption.victimTicketKey.ticketId
		&& preemption.victimTicketKey.runtimeId == identity.runtimeId
		&& preemption.owner
		&& preemption.laneControl
		&& runtimeLiveLocked(identity.runtimeId)
		&& MtProxy::RuntimeGenerationIsCurrent(*state, {
			.runtimeId = identity.runtimeId,
			.proxyGeneration = identity.proxyGeneration,
		});
	if (!canPreserve) {
		QObject::disconnect(preemption.ownerDestroyed);
		return;
	}
	auto successor = AdmissionTicketKey();
	auto successorGeneration = uint64();
	const auto beneficiary = _tickets.find(preemption.beneficiary);
	if (beneficiary != end(_tickets)
		&& WaitingForHandoff(beneficiary->second->lifecycle)
		&& ticketCurrentLocked(*beneficiary->second, *state)
		&& beneficiary->second->use == MtProxy::EndpointUse::Main
		&& !MtProxy::HasCurrentMainRelayProof(
			*state,
			TicketRuntimeGeneration(*beneficiary->second))) {
		successor = beneficiary->second->key;
		successorGeneration = beneficiary->second->proxyGeneration;
	}
	if (successor.ticketId) {
		lane->second.handoffBeneficiary = successor;
		MtProxy::RemoveEndpointExpansionFailure(
			*state,
			{
				.runtimeId = successor.runtimeId,
				.proxyGeneration = successorGeneration,
			},
			MtProxy::EndpointUse::Main);
	} else {
		detachLanePreemptionBeneficiaryLocked(
			endpointKey,
			preemption.beneficiary);
	}
	const auto existing = ranges::find_if(
		lane->second.suspended,
		[&](const SuspendedLane &entry) {
			return entry.identity == identity;
		});
	if (existing != end(lane->second.suspended)) {
		existing->token = preemption.token;
		existing->commandDeadlineAt = 0;
		existing->ticketKey = preemption.victimTicketKey;
		existing->use = preemption.victimUse;
		existing->owner = preemption.owner;
		existing->ownerDestroyed = preemption.ownerDestroyed;
		existing->laneControl = preemption.laneControl;
		existing->successorTicketKey = successor;
		existing->demanded = existing->demanded || preemption.demanded;
	} else {
		lane->second.suspended.push_back({
			.token = preemption.token,
			.identity = identity,
			.ticketKey = preemption.victimTicketKey,
			.use = preemption.victimUse,
			.owner = preemption.owner,
			.ownerDestroyed = preemption.ownerDestroyed,
			.laneControl = preemption.laneControl,
			.successorTicketKey = successor,
			.demanded = preemption.demanded,
		});
	}
}

void EndpointAdmissionArbiter::Private::expireLaneCommandsLocked(
		const QString &endpointKey,
		MtProxy::EndpointState &state,
		crl::time now) {
	const auto lane = _laneSchedules.find(endpointKey);
	if (lane == end(_laneSchedules)) {
		return;
	}
	if (lane->second.preemption
		&& lane->second.preemption->deadlineAt
		&& lane->second.preemption->deadlineAt <= now) {
		const auto token = lane->second.preemption->token;
		const auto identity = lane->second.preemption->victim;
		finishLanePreemptionLocked(
			endpointKey,
			&state,
			token,
			identity,
			LanePreemptionTerminal::Expired);
	}
	if (lane->second.resuming
		&& lane->second.resuming->commandDeadlineAt
		&& lane->second.resuming->commandDeadlineAt <= now) {
		auto value = std::move(*lane->second.resuming);
		lane->second.resuming.reset();
		value.commandDeadlineAt = 0;
		if (IsBackground(value.use)
			&& value.ticketKey.ticketId
			&& value.ticketKey.runtimeId == value.identity.runtimeId
			&& value.owner
			&& value.laneControl
			&& runtimeLiveLocked(value.identity.runtimeId)
			&& MtProxy::RuntimeGenerationIsCurrent(state, {
				.runtimeId = value.identity.runtimeId,
				.proxyGeneration = value.identity.proxyGeneration,
			})) {
			lane->second.suspended.push_front(std::move(value));
		} else {
			QObject::disconnect(value.ownerDestroyed);
		}
	}
}

void EndpointAdmissionArbiter::Private::purgeEndpointLocked(
		const QString &endpointKey,
		MtProxy::EndpointState &state,
		Actions &actions) {
	const auto schedule = _endpoints.find(endpointKey);
	if (schedule == end(_endpoints) || schedule->second.order.empty()) {
		return;
	}
	auto stale = std::vector<AdmissionTicketKey>();
	for (const auto &key : schedule->second.order) {
		const auto i = _tickets.find(key);
		if (i == end(_tickets) || !ticketCurrentLocked(*i->second, state)) {
			stale.push_back(key);
		}
	}
	for (const auto &key : stale) {
		cancelTicketLocked(key, 0, actions);
	}
}

void EndpointAdmissionArbiter::Private::revalidateReservationsLocked(
		const QString &endpointKey,
		MtProxy::EndpointState &state,
		DrainInputs &inputs,
		Actions &actions) {
	const auto schedule = _endpoints.find(endpointKey);
	if (schedule == end(_endpoints)) {
		return;
	}
	auto candidates = std::vector<Ticket*>();
	for (const auto &key : schedule->second.order) {
		const auto i = _tickets.find(key);
		if (i != end(_tickets)
			&& (i->second->lifecycle == ProxySchedulerLifecycle::Scheduled
				|| i->second->lifecycle
					== ProxySchedulerLifecycle::Granted)) {
			candidates.push_back(i->second.get());
		}
	}
	const auto urgentWaiters = urgentWaitersLocked(
		endpointKey,
		state,
		inputs.now);
	auto pool = std::vector<Ticket*>();
	for (const auto ticket : candidates) {
		if (baseEligibleLocked(
				*ticket,
				state,
				urgentWaiters,
				inputs.now)) {
			pool.push_back(ticket);
		} else {
			demoteTicketLocked(*ticket, actions);
		}
	}
	auto ordered = orderLocked(
		std::move(pool),
		state,
		inputs.now,
		schedule->second.fairness);
	const auto active = activeCountsLocked(state);
	auto keptCounts = MtProxy::EndpointUseCounts();
	auto kept = std::vector<Ticket*>();
	for (const auto ticket : ordered) {
		const auto policy = policyLocked(
			*ticket,
			state,
			active,
			keptCounts,
			urgentWaiters,
			inputs);
		const auto capacity = capacityDecisionLocked(
			*ticket,
			state,
			keptCounts,
			urgentWaiters,
			inputs.now,
			std::nullopt);
		if (policy.admissionAllowed
			&& capacity.kind != CapacityDecisionKind::Blocked) {
			if (capacity.kind == CapacityDecisionKind::Ordinary) {
				releaseReservedCapacityProbeLocked(*ticket);
			}
			keptCounts = MtProxy::BeginEndpointAdmission(
				keptCounts,
				ticket->use);
			kept.push_back(ticket);
		} else {
			demoteTicketLocked(*ticket, actions);
		}
	}
	auto requests = std::vector<MtProxy::OpenSlotReflowRequest>();
	auto openTickets = std::vector<Ticket*>();
	auto &openState = _storage.openStates[endpointKey];
	for (const auto ticket : kept) {
		if (!ticket->reservationId) {
			continue;
		}
		const auto plan = MtProxy::BuildAttemptPlan(
			ticket->admissionRequest,
			state.recipeLevel);
		ticket->spacing = std::max({
			kMinimumOpenSpacing,
			MtProxy::OpenConnectionSpacing(
				plan.stealth.connectionPattern),
			openState.adaptiveSpacing,
		});
		openTickets.push_back(ticket);
		requests.push_back({
			.id = ticket->reservationId,
			.earliestOpenAt = ticket->notBeforeAt,
			.spacing = ticket->spacing,
			.jitter = ticket->jitter,
		});
	}
	if (requests.empty()) {
		return;
	}
	const auto assignments = MtProxy::ReflowOpenSlotsLocked(
		openState,
		requests,
		inputs.now);
	if (assignments.size() != openTickets.size()) {
		return;
	}
	for (auto i = std::size_t(); i != assignments.size(); ++i) {
		auto &ticket = *openTickets[i];
		const auto changed = ticket.scheduledOpenAt != assignments[i].openAt;
		ticket.scheduledOpenAt = assignments[i].openAt;
		ticket.nextOpenAt = assignments[i].nextOpenAt;
		ticket.retryAfter = std::max(
			crl::time(),
			assignments[i].openAt - inputs.now);
		if (changed) {
			if (ticket.lifecycle == ProxySchedulerLifecycle::Granted) {
				ticket.lifecycle = ProxySchedulerLifecycle::Scheduled;
			}
			++ticket.transition;
			postStatusLocked(ticket, actions);
		}
	}
}

void EndpointAdmissionArbiter::Private::assignReservationsLocked(
		const QString &endpointKey,
		MtProxy::EndpointState &state,
		DrainInputs &inputs,
		Actions &actions,
		std::optional<AdmissionTicketKey> noVictimUrgentClaimant) {
	const auto initialSchedule = _endpoints.find(endpointKey);
	if (initialSchedule == end(_endpoints)) {
		return;
	}
	const auto laneSchedule = _laneSchedules.find(endpointKey);
	if (laneSchedule != end(_laneSchedules)
		&& laneSchedule->second.preemption) {
		return;
	}
	auto fairness = initialSchedule->second.fairness;
	auto planned = std::vector<Ticket*>();
	for (const auto &key : initialSchedule->second.order) {
		const auto i = _tickets.find(key);
		if (i != end(_tickets)
			&& (i->second->lifecycle
					== ProxySchedulerLifecycle::Scheduled
				|| i->second->lifecycle
					== ProxySchedulerLifecycle::Granted)) {
			planned.push_back(i->second.get());
		}
	}
	std::sort(begin(planned), end(planned), [](Ticket *a, Ticket *b) {
		return std::tie(a->scheduledOpenAt, a->sequence)
			< std::tie(b->scheduledOpenAt, b->sequence);
	});
	for (const auto ticket : planned) {
		AdvanceFairness(
			fairness,
			*ticket,
			priorityForLocked(*ticket, state, inputs.now));
	}
	while (true) {
		const auto schedule = _endpoints.find(endpointKey);
		if (schedule == end(_endpoints)) {
			return;
		}
		auto pool = std::vector<Ticket*>();
		for (const auto &key : schedule->second.order) {
			const auto i = _tickets.find(key);
			if (i != end(_tickets)
				&& i->second->lifecycle == ProxySchedulerLifecycle::Queued) {
				pool.push_back(i->second.get());
			}
		}
		if (pool.empty()) {
			return;
		}
		const auto active = activeCountsLocked(state);
		const auto scheduled = scheduledCountsLocked(endpointKey);
		const auto urgentWaiters = urgentWaitersLocked(
			endpointKey,
			state,
			inputs.now);
		auto eligible = std::set<AdmissionTicketKey>();
		auto capacityDecisions = std::map<
			AdmissionTicketKey,
			CandidateCapacityDecision>();
		for (const auto ticket : pool) {
			const auto boundary = std::max(
				TicketRetryUntil(
					*ticket,
					state,
					_storage.foregroundRuntimeId),
				state.nextHandshakeAt);
			ticket->retryAt = (boundary > inputs.now)
				? boundary
				: crl::time();
			const auto policy = policyLocked(
				*ticket,
				state,
				active,
				scheduled,
				urgentWaiters,
				inputs);
			const auto capacity = capacityDecisionLocked(
				*ticket,
				state,
				scheduled,
				urgentWaiters,
				inputs.now,
				noVictimUrgentClaimant);
			capacityDecisions.emplace(ticket->key, capacity);
			if (baseEligibleLocked(
					*ticket,
					state,
					urgentWaiters,
					inputs.now)
				&& policy.admissionAllowed
				&& capacity.kind != CapacityDecisionKind::Blocked) {
				eligible.emplace(ticket->key);
			} else {
				ticket->blockedBy = TicketFailureReason(*ticket, state);
				ticket->retryAfter = policy.retryAfter;
				if (capacity.retryAt) {
					ticket->retryAt = std::max(
						ticket->retryAt,
						capacity.retryAt);
				}
				if (ticket->use == MtProxy::EndpointUse::Main) {
					ticket->reevaluateAt = 0;
				} else {
					const auto base = (ticket->use
							== MtProxy::EndpointUse::ProxyCheck)
						? PriorityIndex(PriorityClass::ProxyCheck)
						: PriorityIndex(PriorityClass::Background);
					const auto age = std::max(
						crl::time(),
						inputs.now - ticket->enqueuedAt);
					const auto improvement = int(age / kAgingStep);
					ticket->reevaluateAt = (base - improvement
							> PriorityIndex(PriorityClass::OrdinaryMain))
						? (ticket->enqueuedAt
							+ crl::time(improvement + 1) * kAgingStep)
						: crl::time();
				}
			}
		}
		const auto selected = selectLocked(
			pool,
			eligible,
			state,
			inputs.now,
			fairness);
		if (!selected) {
			return;
		}
		selected->retryAt = 0;
		selected->reevaluateAt = 0;
		selected->blockedBy = MtProxy::FailureReason::None;
		const auto selectedCapacity = capacityDecisions.find(selected->key);
		Assert(selectedCapacity != end(capacityDecisions));
		if (selectedCapacity->second.kind == CapacityDecisionKind::Probe) {
			if (!MtProxy::ReserveCapacityProbe(
					state.liveBudget,
					selected->key,
					TicketRuntimeGeneration(*selected))) {
				return;
			}
		} else {
			releaseReservedCapacityProbeLocked(*selected);
		}
		if (selected->use == MtProxy::EndpointUse::ProxyCheck) {
			selected->scheduledOpenAt = std::max(
				inputs.now,
				selected->notBeforeAt);
			selected->nextOpenAt = selected->scheduledOpenAt;
		} else {
			auto &openState = _storage.openStates[endpointKey];
			const auto plan = MtProxy::BuildAttemptPlan(
				selected->admissionRequest,
				state.recipeLevel);
			selected->spacing = std::max({
				kMinimumOpenSpacing,
				MtProxy::OpenConnectionSpacing(
					plan.stealth.connectionPattern),
				openState.adaptiveSpacing,
			});
			selected->jitter = inputs.takeJitter(selected->key.runtimeId);
			const auto reservation = MtProxy::ReserveOpenSlotLocked(
				openState,
				{
					.now = inputs.now,
					.earliestOpenAt = selected->notBeforeAt,
					.spacing = selected->spacing,
					.jitter = selected->jitter,
				});
			if (!reservation.id) {
				releaseReservedCapacityProbeLocked(*selected);
				return;
			}
			selected->reservationId = reservation.id;
			selected->scheduledOpenAt = reservation.openAt;
			selected->nextOpenAt = reservation.nextOpenAt;
		}
		selected->lifecycle = ProxySchedulerLifecycle::Scheduled;
		selected->retryAfter = std::max(
			crl::time(),
			selected->scheduledOpenAt - inputs.now);
		++selected->transition;
		AdvanceFairness(
			fairness,
			*selected,
			priorityForLocked(*selected, state, inputs.now));
		postStatusLocked(*selected, actions);
	}
}

void EndpointAdmissionArbiter::Private::grantDueLocked(
		const QString &endpointKey,
		crl::time now,
		Actions &actions) {
	const auto schedule = _endpoints.find(endpointKey);
	if (schedule == end(_endpoints)) {
		return;
	}
	for (const auto &key : schedule->second.order) {
		const auto i = _tickets.find(key);
		if (i == end(_tickets)
			|| i->second->lifecycle != ProxySchedulerLifecycle::Scheduled
			|| i->second->scheduledOpenAt > now) {
			continue;
		}
		auto &ticket = *i->second;
		ticket.lifecycle = ProxySchedulerLifecycle::Granted;
		ticket.retryAfter = 0;
		++ticket.transition;
		postStatusLocked(ticket, actions);
		postGrantLocked(ticket, actions);
	}
}

void EndpointAdmissionArbiter::Private::drainEndpointLocked(
		const QString &endpointKey,
		DrainInputs &inputs,
		Actions &actions) {
	const auto schedule = _endpoints.find(endpointKey);
	if (schedule == end(_endpoints) || schedule->second.order.empty()) {
		const auto state = _storage.states.find(endpointKey);
		if (state != end(_storage.states)) {
			MtProxy::PruneExpiredEndpointState(state->second, inputs.now);
			expireLaneCommandsLocked(
				endpointKey,
				state->second,
				inputs.now);
			resumeSuspendedLaneLocked(
				endpointKey,
				state->second,
				inputs,
				actions);
		}
		return;
	}
	const auto first = _tickets.find(schedule->second.order.front());
	if (first != end(_tickets)
		&& MtProxy::EndpointEmpty(first->second->endpoint)) {
		auto state = MtProxy::EndpointState();
		purgeEndpointLocked(endpointKey, state, actions);
		const auto current = _endpoints.find(endpointKey);
		if (current == end(_endpoints)) {
			return;
		}
		for (const auto &key : current->second.order) {
			const auto i = _tickets.find(key);
			if (i == end(_tickets)
				|| i->second->lifecycle
					!= ProxySchedulerLifecycle::Queued) {
				continue;
			}
			auto &ticket = *i->second;
			ticket.scheduledOpenAt = std::max(
				inputs.now,
				ticket.notBeforeAt);
			ticket.nextOpenAt = ticket.scheduledOpenAt;
			ticket.retryAfter = std::max(
				crl::time(),
				ticket.scheduledOpenAt - inputs.now);
			ticket.lifecycle = ProxySchedulerLifecycle::Scheduled;
			++ticket.transition;
			postStatusLocked(ticket, actions);
		}
		grantDueLocked(endpointKey, inputs.now, actions);
		return;
	}
	auto &state = _storage.states[endpointKey];
	if (!schedule->second.order.empty()) {
		const auto ticket = _tickets.find(schedule->second.order.front());
		if (ticket != end(_tickets)) {
			state.endpoint = ticket->second->endpoint;
		}
	}
	MtProxy::PruneExpiredEndpointState(state, inputs.now);
	expireLaneCommandsLocked(endpointKey, state, inputs.now);
	purgeEndpointLocked(endpointKey, state, actions);
	if (!_endpoints.contains(endpointKey)) {
		resumeSuspendedLaneLocked(
			endpointKey,
			state,
			inputs,
			actions);
		return;
	}
	revalidateReservationsLocked(endpointKey, state, inputs, actions);
	resumeSuspendedLaneLocked(endpointKey, state, inputs, actions);
	const auto noVictimUrgentClaimant = requestLanePreemptionLocked(
		endpointKey,
		state,
		inputs,
		actions);
	assignReservationsLocked(
		endpointKey,
		state,
		inputs,
		actions,
		noVictimUrgentClaimant);
	grantDueLocked(endpointKey, inputs.now, actions);
}

bool EndpointAdmissionArbiter::Private::wakeOwnerLiveLocked() const {
	if (!_wakeArmed
		|| !_wakeDriver
		|| !_wakeRegistrationLive
		|| !_wakeRegistrationLive->load(std::memory_order_acquire)) {
		return false;
	}
	const auto runtime = _runtimes.find(_wakeDriver);
	return runtime != end(_runtimes)
		&& runtimeLiveLocked(_wakeDriver)
		&& runtime->second->registrationLive == _wakeRegistrationLive;
}

void EndpointAdmissionArbiter::Private::clearWakeLocked(
		bool invalidateToken) {
	if (invalidateToken && _wakeArmed) {
		++_wakeToken;
	}
	_wakeArmed = false;
	_wakeDriver = 0;
	_wakeAt = 0;
	_wakeRegistrationLive.reset();
}

void EndpointAdmissionArbiter::Private::updateWakeLocked(
		const DrainInputs &inputs,
		Actions &actions) {
	if (_wakeArmed && !wakeOwnerLiveLocked()) {
		clearWakeLocked(true);
	}
	if (_wakeArmed
		&& _wakeAt
		&& _wakeAt <= inputs.now
		&& wakeOwnerLiveLocked()) {
		return;
	}
	auto wakeAt = crl::time();
	const auto considerBoundary = [&](crl::time boundary) {
		if (boundary > inputs.now
			&& (!wakeAt || boundary < wakeAt)) {
			wakeAt = boundary;
		}
	};
	for (const auto &entry : _tickets) {
		const auto &ticket = entry.second;
		auto boundary = (ticket->lifecycle
				== ProxySchedulerLifecycle::Scheduled)
			? ticket->scheduledOpenAt
			: (ticket->lifecycle == ProxySchedulerLifecycle::Queued)
			? ticket->retryAt
			: crl::time();
		if (ticket->lifecycle == ProxySchedulerLifecycle::Queued
			&& ticket->reevaluateAt > inputs.now
			&& (!boundary || ticket->reevaluateAt < boundary)) {
			boundary = ticket->reevaluateAt;
		}
		considerBoundary(boundary);
	}
	for (const auto &entry : _laneSchedules) {
		const auto &lane = entry.second;
		const auto preemptionAt = lane.preemption
			? lane.preemption->deadlineAt
			: crl::time();
		const auto resumeAt = lane.resuming
			? lane.resuming->commandDeadlineAt
			: crl::time();
		for (const auto boundary : { preemptionAt, resumeAt }) {
			considerBoundary(boundary);
		}
	}
	if (!wakeAt) {
		clearWakeLocked(true);
		return;
	}
	const auto dispatchLive = [&](ProxyRuntimeId runtimeId) {
		const auto runtime = _runtimes.find(runtimeId);
		return runtime != end(_runtimes)
			&& runtimeLiveLocked(runtimeId)
			&& runtime->second->registrationLive
			&& runtime->second->registrationLive->load(
				std::memory_order_acquire);
	};
	auto driver = _wakeDriver;
	if (!dispatchLive(driver)) {
		driver = 0;
		for (const auto &entry : _runtimes) {
			const auto runtimeId = entry.first;
			if (dispatchLive(runtimeId)) {
				driver = runtimeId;
				break;
			}
		}
	}
	if (!driver) {
		clearWakeLocked(true);
		return;
	}
	if (_wakeArmed
		&& _wakeDriver == driver
		&& _wakeAt == wakeAt
		&& wakeOwnerLiveLocked()) {
		return;
	}
	const auto dispatch = _runtimes.find(driver)->second;
	const auto token = ++_wakeToken;
	_wakeArmed = true;
	_wakeDriver = driver;
	_wakeAt = wakeAt;
	_wakeRegistrationLive = dispatch->registrationLive;
	const auto weak = _context;
	actions.posts.push_back({
		.dispatch = dispatch,
		.target = dispatch->dispatcher,
		.delay = wakeAt - inputs.now,
		.callback = [weak, token] {
			if (const auto context = weak.lock()) {
				context->endpointAdmissionArbiter().wake(token);
			}
		},
		.missing = [weak, token] {
			if (const auto context = weak.lock()) {
				context->endpointAdmissionArbiter().wake(token);
			}
		},
	});
}

void EndpointAdmissionArbiter::Private::bindRuntime(
		ProxyRuntimeId runtimeId,
		EndpointAdmissionRuntimeDispatch dispatch) {
	if (!runtimeId) {
		return;
	}
	dispatch.registrationLive = std::make_shared<std::atomic<bool>>(true);
	const auto bound = std::make_shared<
		const EndpointAdmissionRuntimeDispatch>(std::move(dispatch));
	auto actions = Actions();
	{
		QMutexLocker lock(&_storage.mutex);
		if (!_storage.runtimes.contains(runtimeId)) {
			return;
		}
		const auto i = _runtimes.find(runtimeId);
		if (i == end(_runtimes)) {
			_runtimes.emplace(runtimeId, bound);
		} else {
			const auto registrationLive = i->second->registrationLive;
			InvalidateRuntimeDispatch(i->second);
			if (_wakeArmed
				&& _wakeDriver == runtimeId
				&& _wakeRegistrationLive == registrationLive) {
				clearWakeLocked(true);
			}
			actions.retired.push_back(std::move(i->second));
			i->second = bound;
		}
	}
	auto inputs = prepareInputs();
	{
		QMutexLocker lock(&_storage.mutex);
		const auto current = _runtimes.find(runtimeId);
		if (current != end(_runtimes) && current->second == bound) {
			auto endpoints = std::set<QString>();
			for (const auto &entry : _endpoints) {
				endpoints.emplace(entry.first);
			}
			for (const auto &entry : _laneSchedules) {
				endpoints.emplace(entry.first);
			}
			for (const auto &endpointKey : endpoints) {
				drainEndpointLocked(endpointKey, inputs, actions);
			}
			updateWakeLocked(inputs, actions);
		}
	}
	actions.run();
}

void EndpointAdmissionArbiter::Private::cancelRuntime(
		ProxyRuntimeId runtimeId) {
	if (!runtimeId) {
		return;
	}
	auto actions = Actions();
	auto affected = std::set<QString>();
	{
		QMutexLocker lock(&_storage.mutex);
		if (!_storage.runtimes.contains(runtimeId)) {
			return;
		}
		auto cancelled = std::vector<AdmissionTicketKey>();
		for (const auto &[key, ticket] : _tickets) {
			if (key.runtimeId == runtimeId) {
				cancelled.push_back(key);
				affected.emplace(ticket->endpointKey);
			}
		}
		for (const auto &key : cancelled) {
			cancelTicketLocked(key, 0, actions);
		}
	}
	actions.run();
	for (const auto &endpointKey : affected) {
		drainEndpoint(endpointKey);
	}
}

void EndpointAdmissionArbiter::Private::unregisterRuntime(
		ProxyRuntimeId runtimeId) {
	if (!runtimeId) {
		return;
	}
	auto actions = Actions();
	auto affected = std::set<QString>();
	{
		QMutexLocker lock(&_storage.mutex);
		_storage.runtimes.erase(runtimeId);
		_storage.runtimeGenerations.erase(runtimeId);
		if (_storage.foregroundRuntimeId == runtimeId) {
			_storage.foregroundRuntimeId = 0;
		}
		const auto dispatch = _runtimes.find(runtimeId);
		if (dispatch != end(_runtimes)) {
			InvalidateRuntimeDispatch(dispatch->second);
			actions.retired.push_back(std::move(dispatch->second));
			_runtimes.erase(dispatch);
		}
		for (const auto &[key, ticket] : _tickets) {
			if (key.runtimeId == runtimeId) {
				affected.emplace(ticket->endpointKey);
			}
		}
		auto cancelled = std::vector<AdmissionTicketKey>();
		for (const auto &entry : _tickets) {
			if (entry.first.runtimeId == runtimeId) {
				cancelled.push_back(entry.first);
			}
		}
		for (const auto &key : cancelled) {
			cancelTicketLocked(key, 0, actions);
		}
		for (auto &entry : _endpoints) {
			auto &schedule = entry.second;
			for (auto &cursor : schedule.fairness.lastRuntime) {
				if (cursor == runtimeId) {
					cursor = 0;
				}
			}
			schedule.fairness.nextBackground.erase(runtimeId);
		}
		for (auto i = begin(_laneSchedules); i != end(_laneSchedules);) {
			auto detached = std::set<AdmissionTicketKey>();
			if (i->second.handoffBeneficiary
				&& i->second.handoffBeneficiary->runtimeId == runtimeId) {
				detached.emplace(*i->second.handoffBeneficiary);
			}
			if (i->second.preemption
				&& i->second.preemption->beneficiary.runtimeId
					== runtimeId) {
				detached.emplace(i->second.preemption->beneficiary);
			}
			for (const auto &entry : i->second.suspended) {
				if (entry.successorTicketKey.runtimeId == runtimeId) {
					detached.emplace(entry.successorTicketKey);
				}
			}
			if (i->second.resuming
				&& i->second.resuming->successorTicketKey.runtimeId
					== runtimeId) {
				detached.emplace(
					i->second.resuming->successorTicketKey);
			}
			for (const auto &key : detached) {
				detachLanePreemptionBeneficiaryLocked(i->first, key);
			}
			if (i->second.preemption
				&& i->second.preemption->victim.runtimeId == runtimeId) {
				const auto state = _storage.states.find(i->first);
				const auto token = i->second.preemption->token;
				const auto victim = i->second.preemption->victim;
				finishLanePreemptionLocked(
					i->first,
					(state != end(_storage.states))
						? &state->second
						: nullptr,
					token,
					victim,
					LanePreemptionTerminal::VictimLost);
			}
			auto &suspended = i->second.suspended;
			suspended.erase(std::remove_if(
				begin(suspended),
				end(suspended),
				[=](const SuspendedLane &lane) {
					const auto matches
						= lane.identity.runtimeId == runtimeId;
					if (matches) {
						QObject::disconnect(lane.ownerDestroyed);
					}
					return matches;
				}), end(suspended));
			if (i->second.resuming
				&& i->second.resuming->identity.runtimeId == runtimeId) {
				QObject::disconnect(
					i->second.resuming->ownerDestroyed);
				i->second.resuming.reset();
			}
			if (suspended.empty()
				&& !i->second.preemption
				&& !i->second.resuming) {
				i = _laneSchedules.erase(i);
			} else {
				++i;
			}
		}
		for (auto i = begin(_storage.activeTraces);
				i != end(_storage.activeTraces);) {
			if (i->second.runtimeId == runtimeId) {
				i = _storage.activeTraces.erase(i);
			} else {
				++i;
			}
		}
		for (auto &[endpointKey, state] : _storage.states) {
			affected.emplace(endpointKey);
			state.generations.erase(runtimeId);
			for (auto i = begin(state.attemptStarts);
					i != end(state.attemptStarts);) {
				if (i->second.runtimeId == runtimeId) {
					static_cast<void>(MtProxy::ReleaseActiveCapacityProbe(
						state.liveBudget,
						{
							.runtimeId = i->second.runtimeId,
							.proxyGeneration = i->second.proxyGeneration,
							.attemptId = i->first,
						}));
					QObject::disconnect(i->second.ownerDestroyed);
					i = state.attemptStarts.erase(i);
				} else {
					++i;
				}
			}
			for (auto i = begin(state.liveLanes);
					i != end(state.liveLanes);) {
				if (i->first.runtimeId == runtimeId) {
					QObject::disconnect(i->second.ownerDestroyed);
					i = state.liveLanes.erase(i);
				} else {
					++i;
				}
			}
			MtProxy::SynchronizeEndpointAdmissionAggregate(state);
			MtProxy::RemoveRelayProofsForRuntime(state, runtimeId);
			MtProxy::RemoveEndpointExpansionFailuresForRuntime(
				state,
				runtimeId);
		}
		clearWakeLocked(true);
		for (const auto &entry : _endpoints) {
			affected.emplace(entry.first);
		}
	}
	actions.run();
	for (const auto &endpointKey : affected) {
		drainEndpoint(endpointKey);
	}
}

EndpointAdmissionEnqueueResult EndpointAdmissionArbiter::Private::enqueue(
		std::weak_ptr<ProxyEndpointContext> context,
		EndpointAdmissionRequest request) {
	if (!request.key.runtimeId
		|| !request.key.ticketId
		|| !request.owner
		|| !request.ownerDestroyed
		|| !request.grant) {
		return {};
	}
	const auto revision = ++_lastRevision;
	const auto key = request.key;
	const auto ownerDestroyed = request.ownerDestroyed;
	auto inputs = prepareInputs();
	auto ticket = std::make_unique<Ticket>();
	ticket->key = key;
	ticket->revision = revision;
	ticket->transition = 1;
	ticket->proxyGeneration = request.proxyGeneration;
	ticket->traceId = request.traceId;
	ticket->endpoint = request.endpoint;
	ticket->endpointKey = MtProxy::EndpointKey(request.endpoint);
	if (ticket->endpointKey.isEmpty()) {
		ticket->endpointKey = u"unscoped:"_q
			+ QString::number(key.runtimeId)
			+ u":"_q
			+ QString::number(key.ticketId);
	}
	ticket->use = request.use;
	ticket->admissionRequest = {
		.endpoint = request.endpoint,
		.use = request.use,
		.runtimeId = key.runtimeId,
		.stealth = request.stealth,
		.configuredTlsProfile = request.configuredTlsProfile,
		.proxyGeneration = request.proxyGeneration,
	};
	ticket->owner = request.owner;
	ticket->ownerDestroyed = ownerDestroyed;
	if (request.laneControl) {
		ticket->laneControl = std::make_shared<
			Fn<void(MtProxy::EndpointLaneCommand)>>(
				std::move(request.laneControl));
	}
	ticket->callbacks = std::make_shared<TicketCallbacks>(TicketCallbacks{
		.status = std::move(request.status),
		.grant = std::move(request.grant),
	});
	ticket->lifecycle = ProxySchedulerLifecycle::Queued;
	ticket->enqueuedAt = (request.waitStartedAt > 0)
		? std::min(request.waitStartedAt, inputs.now)
		: inputs.now;
	ticket->notBeforeAt = inputs.now
		+ std::max(crl::time(), request.notBefore);
	auto actions = Actions();
	auto result = EndpointAdmissionEnqueueResult();
	{
		QMutexLocker lock(&_storage.mutex);
		_context = context;
		const auto state = _storage.states.find(ticket->endpointKey);
		const auto runtimeGeneration = _storage.runtimeGenerations.find(
			key.runtimeId);
		const auto staleRuntime = runtimeGeneration
			!= end(_storage.runtimeGenerations)
			&& runtimeGeneration->second
			&& runtimeGeneration->second != request.proxyGeneration;
		const auto staleEndpoint = state != end(_storage.states)
			&& MtProxy::RuntimeProxyGenerationIsStale(
				state->second,
				key.runtimeId,
				request.proxyGeneration);
		const auto traceCurrent = MtProxy::EndpointEmpty(request.endpoint)
			|| (request.traceId
				&& _storage.activeTraces.contains(request.traceId));
		if (!_tickets.contains(key)
			&& runtimeLiveLocked(key.runtimeId)
			&& ticket->owner
			&& traceCurrent
			&& !staleRuntime
			&& !staleEndpoint) {
			const auto runtimeGenerationKey = RuntimeGenerationKey{
				.runtimeId = key.runtimeId,
				.proxyGeneration = request.proxyGeneration,
			};
			if (request.requestedRecoveryToken
				&& MtProxy::AdoptMainRecoveryAdmissionTicketLocked(
					_storage,
					ticket->endpointKey,
					runtimeGenerationKey,
					ticket->use,
					request.requestedRecoveryToken,
					key)) {
				ticket->acceptedRecoveryToken
					= request.requestedRecoveryToken;
				result.acceptedRecoveryToken
					= request.requestedRecoveryToken;
			}
			ticket->sequence = ++_lastSequence;
			auto &schedule = _endpoints[ticket->endpointKey];
			schedule.order.push_back(key);
			auto &stored = *_tickets.emplace(key, std::move(ticket)).first->second;
			postStatusLocked(stored, actions);
			drainEndpointLocked(stored.endpointKey, inputs, actions);
			updateWakeLocked(inputs, actions);
			result.accepted = true;
		}
	}
	if (!result.accepted) {
		QObject::disconnect(ownerDestroyed);
	}
	actions.run();
	return result;
}

void EndpointAdmissionArbiter::Private::cancel(
		AdmissionTicketKey key,
		uint64 revision) {
	if (!key.runtimeId || !key.ticketId) {
		return;
	}
	auto inputs = prepareInputs();
	auto actions = Actions();
	{
		QMutexLocker lock(&_storage.mutex);
		const auto i = _tickets.find(key);
		if (i == end(_tickets)
			|| (revision && i->second->revision != revision)) {
			return;
		}
		const auto endpointKey = i->second->endpointKey;
		cancelTicketLocked(key, revision, actions);
		drainEndpointLocked(endpointKey, inputs, actions);
		updateWakeLocked(inputs, actions);
	}
	actions.run();
}

void EndpointAdmissionArbiter::Private::ownerDestroyed(
		AdmissionTicketKey key) {
	if (!key.runtimeId || !key.ticketId) {
		return;
	}
	auto inputs = prepareInputs();
	auto actions = Actions();
	{
		QMutexLocker lock(&_storage.mutex);
		auto affected = std::set<QString>();
		const auto ticket = _tickets.find(key);
		if (ticket != end(_tickets)) {
			affected.emplace(ticket->second->endpointKey);
			cancelTicketLocked(key, 0, actions);
		}
		for (auto &[endpointKey, state] : _storage.states) {
			auto identities = std::set<MtProxy::RelayProofIdentity>();
			for (const auto &[attemptId, attempt] : state.attemptStarts) {
				if (attempt.ticketKey == key) {
					identities.emplace(MtProxy::RelayProofIdentity{
						.runtimeId = attempt.runtimeId,
						.proxyGeneration = attempt.proxyGeneration,
						.attemptId = attemptId,
					});
				}
			}
			for (const auto &[identity, lane] : state.liveLanes) {
				if (lane.ticketKey == key) {
					identities.emplace(identity);
				}
			}
			for (const auto &[identity, proof] : state.relayProofs) {
				if (proof.ticketKey == key) {
					identities.emplace(identity);
				}
			}
			const auto laneSchedule = _laneSchedules.find(endpointKey);
			if (laneSchedule != end(_laneSchedules)
				&& laneSchedule->second.preemption
				&& laneSchedule->second.preemption->victimTicketKey == key) {
				identities.emplace(
					laneSchedule->second.preemption->victim);
			}
			if (identities.empty()) {
				continue;
			}
			affected.emplace(endpointKey);
			actions.context = _context;
			for (const auto &identity : identities) {
				if (laneSchedule != end(_laneSchedules)
					&& laneSchedule->second.preemption
					&& laneSchedule->second.preemption->victim
						== identity) {
					finishLanePreemptionLocked(
						endpointKey,
						&state,
						laneSchedule->second.preemption->token,
						identity,
						LanePreemptionTerminal::VictimLost);
				}
				const auto attempt = state.attemptStarts.find(
					identity.attemptId);
				const auto attemptMatches
					= attempt != end(state.attemptStarts)
					&& attempt->second.runtimeId == identity.runtimeId
					&& attempt->second.proxyGeneration
						== identity.proxyGeneration;
				const auto lane = state.liveLanes.find(identity);
				if (attemptMatches || lane != end(state.liveLanes)) {
					const auto use = attemptMatches
						? attempt->second.use
						: lane->second.use;
					static_cast<void>(
						MtProxy::FinishMainRecoveryByReplacementAttemptLocked(
							_storage,
							endpointKey,
							{
								.runtimeId = identity.runtimeId,
								.proxyGeneration
									= identity.proxyGeneration,
							},
							use,
							identity.attemptId));
				}
				static_cast<void>(MtProxy::ReleaseActiveCapacityProbe(
					state.liveBudget,
					identity));
				static_cast<void>(MtProxy::RetireRelayProof(
					state,
					identity));
				if (attemptMatches) {
					state.attemptStarts.erase(attempt);
				}
				state.liveLanes.erase(identity);
				actions.invalidations.emplace_back(
					state.endpoint,
					RuntimeGenerationKey{
						.runtimeId = identity.runtimeId,
						.proxyGeneration = identity.proxyGeneration,
					});
			}
			MtProxy::SynchronizeEndpointAdmissionAggregate(state);
		}
		for (auto &[endpointKey, laneSchedule] : _laneSchedules) {
			const auto detached = (laneSchedule.handoffBeneficiary
					&& *laneSchedule.handoffBeneficiary == key)
				|| (laneSchedule.preemption
					&& laneSchedule.preemption->beneficiary == key)
				|| (ranges::find_if(
					laneSchedule.suspended,
					[=](const SuspendedLane &entry) {
						return entry.successorTicketKey == key;
					}) != end(laneSchedule.suspended))
				|| (laneSchedule.resuming
					&& laneSchedule.resuming->successorTicketKey == key);
			if (detached) {
				detachLanePreemptionBeneficiaryLocked(endpointKey, key);
				affected.emplace(endpointKey);
			}
			auto &suspended = laneSchedule.suspended;
			const auto before = suspended.size();
			suspended.erase(std::remove_if(
				begin(suspended),
				end(suspended),
				[=](const SuspendedLane &lane) {
					const auto matches = lane.ticketKey == key;
					if (matches) {
						QObject::disconnect(lane.ownerDestroyed);
					}
					return matches;
				}), end(suspended));
			if (suspended.size() != before) {
				affected.emplace(endpointKey);
			}
			if (laneSchedule.resuming
				&& laneSchedule.resuming->ticketKey == key) {
				QObject::disconnect(
					laneSchedule.resuming->ownerDestroyed);
				laneSchedule.resuming.reset();
				affected.emplace(endpointKey);
			}
		}
		for (auto i = begin(_storage.activeTraces);
			i != end(_storage.activeTraces);) {
			if (i->second.ticketKey == key) {
				i = _storage.activeTraces.erase(i);
			} else {
				++i;
			}
		}
		for (const auto &endpointKey : affected) {
			drainEndpointLocked(endpointKey, inputs, actions);
		}
		updateWakeLocked(inputs, actions);
	}
	actions.run();
}

void EndpointAdmissionArbiter::Private::cancelBeforeGeneration(
		ProxyRuntimeId runtimeId,
		uint64 proxyGeneration) {
	if (!runtimeId) {
		return;
	}
	auto actions = Actions();
	auto affected = std::set<QString>();
	{
		QMutexLocker lock(&_storage.mutex);
		if (!_storage.runtimes.contains(runtimeId)) {
			return;
		}
		auto &runtimeGeneration = _storage.runtimeGenerations[runtimeId];
		if (proxyGeneration < runtimeGeneration) {
			return;
		}
		runtimeGeneration = proxyGeneration;
		auto cancelled = std::vector<AdmissionTicketKey>();
		for (auto &[endpointKey, state] : _storage.states) {
			const auto current = state.generations.find(runtimeId);
			const auto changes = (current == end(state.generations))
				|| (proxyGeneration > current->second);
			if (!changes) {
				continue;
			}
			const auto lane = _laneSchedules.find(endpointKey);
			if (lane != end(_laneSchedules)
				&& lane->second.preemption
				&& lane->second.preemption->victim.runtimeId == runtimeId
				&& lane->second.preemption->victim.proxyGeneration
					< proxyGeneration) {
				const auto token = lane->second.preemption->token;
				const auto victim = lane->second.preemption->victim;
				finishLanePreemptionLocked(
					endpointKey,
					&state,
					token,
					victim,
					LanePreemptionTerminal::VictimLost);
			}
			MtProxy::ApplyRuntimeProxyGeneration(
				state,
				runtimeId,
				proxyGeneration);
			const auto currentLane = _laneSchedules.find(endpointKey);
			if (currentLane != end(_laneSchedules)) {
				auto detached = std::set<AdmissionTicketKey>();
				if (currentLane->second.handoffBeneficiary
					&& currentLane->second.handoffBeneficiary->runtimeId
						== runtimeId) {
					detached.emplace(
						*currentLane->second.handoffBeneficiary);
				}
				if (currentLane->second.preemption
					&& currentLane->second.preemption->beneficiary.runtimeId
						== runtimeId) {
					detached.emplace(
						currentLane->second.preemption->beneficiary);
				}
				auto &suspended = currentLane->second.suspended;
				for (const auto &entry : suspended) {
					if (entry.successorTicketKey.runtimeId == runtimeId) {
						detached.emplace(entry.successorTicketKey);
					}
				}
				if (currentLane->second.resuming
					&& currentLane->second.resuming
						->successorTicketKey.runtimeId == runtimeId) {
					detached.emplace(
						currentLane->second.resuming->successorTicketKey);
				}
				for (const auto &key : detached) {
					detachLanePreemptionBeneficiaryLocked(
						endpointKey,
						key);
				}
				suspended.erase(std::remove_if(
					begin(suspended),
					end(suspended),
					[=](const SuspendedLane &entry) {
						const auto matches
							= entry.identity.runtimeId == runtimeId
							&& entry.identity.proxyGeneration
								< proxyGeneration;
						if (matches) {
							QObject::disconnect(entry.ownerDestroyed);
						}
						return matches;
					}), end(suspended));
				if (currentLane->second.resuming
					&& currentLane->second.resuming->identity.runtimeId
						== runtimeId
					&& currentLane->second.resuming->identity.proxyGeneration
						< proxyGeneration) {
					QObject::disconnect(
						currentLane->second.resuming->ownerDestroyed);
					currentLane->second.resuming.reset();
				}
			}
			affected.emplace(endpointKey);
		}
		for (auto i = begin(_storage.activeTraces);
				i != end(_storage.activeTraces);) {
			if (i->second.runtimeId == runtimeId
				&& i->second.proxyGeneration < proxyGeneration) {
				i = _storage.activeTraces.erase(i);
			} else {
				++i;
			}
		}
		for (const auto &[key, ticket] : _tickets) {
			if (key.runtimeId == runtimeId
				&& ticket->proxyGeneration < proxyGeneration) {
				cancelled.push_back(key);
				affected.emplace(ticket->endpointKey);
			}
		}
		for (const auto &key : cancelled) {
			const auto ticket = _tickets.find(key);
			if (ticket != end(_tickets)
				&& (ticket->second->lifecycle
						== ProxySchedulerLifecycle::Queued
					|| ticket->second->lifecycle
						== ProxySchedulerLifecycle::Scheduled
					|| ticket->second->lifecycle
						== ProxySchedulerLifecycle::Granted)) {
				postGenerationCancelledStatusLocked(
					*ticket->second,
					actions);
			}
			cancelTicketLocked(key, 0, actions);
		}
	}
	actions.run();
	for (const auto &endpointKey : affected) {
		drainEndpoint(endpointKey);
	}
}

bool EndpointAdmissionArbiter::Private::authorizeLaneSuspension(
		const QString &endpointKey,
		uint64 token,
		ProxyRuntimeId runtimeId,
		uint64 proxyGeneration,
		uint64 attemptId) {
	if (endpointKey.isEmpty()
		|| !token
		|| !runtimeId
		|| !proxyGeneration
		|| !attemptId) {
		return false;
	}
	const auto inputs = prepareInputs();
	QMutexLocker lock(&_storage.mutex);
	const auto lane = _laneSchedules.find(endpointKey);
	const auto state = _storage.states.find(endpointKey);
	const auto identity = MtProxy::RelayProofIdentity{
		.runtimeId = runtimeId,
		.proxyGeneration = proxyGeneration,
		.attemptId = attemptId,
	};
	if (lane == end(_laneSchedules)
		|| !lane->second.preemption
		|| state == end(_storage.states)) {
		return false;
	}
	auto &preemption = *lane->second.preemption;
	const auto beneficiary = _tickets.find(preemption.beneficiary);
	const auto priority = (beneficiary != end(_tickets))
		? priorityForLocked(*beneficiary->second, state->second, inputs.now)
		: PriorityClass::Count;
	const auto verdict = (beneficiary != end(_tickets))
		? TicketVerdict(*beneficiary->second, state->second)
		: nullptr;
	const auto boundary = (beneficiary != end(_tickets))
		? std::max({
			beneficiary->second->notBeforeAt,
			state->second.opening.bootstrap.retryUntil,
			verdict ? verdict->retryUntil : crl::time(),
			state->second.nextHandshakeAt,
		})
		: crl::time();
	auto victim = static_cast<const MtProxy::EndpointAttemptState*>(nullptr);
	auto admissionActiveVictim = false;
	const auto opening = state->second.attemptStarts.find(attemptId);
	if (opening != end(state->second.attemptStarts)
		&& opening->second.runtimeId == runtimeId
		&& opening->second.proxyGeneration == proxyGeneration) {
		victim = &opening->second;
		admissionActiveVictim = opening->second.admissionActive;
	} else {
		const auto live = state->second.liveLanes.find(identity);
		if (live != end(state->second.liveLanes)) {
			victim = &live->second;
		}
	}
	if (preemption.token != token
		|| preemption.victim != identity
		|| preemption.stage != LanePreemptionStage::Requested
		|| !preemption.owner
		|| !preemption.laneControl
		|| preemption.deadlineAt <= inputs.now
		|| beneficiary == end(_tickets)
		|| !WaitingForHandoff(beneficiary->second->lifecycle)
		|| !ticketCurrentLocked(*beneficiary->second, state->second)
		|| !IsUrgentMainBeneficiary(*beneficiary->second, priority)
		|| boundary > inputs.now
		|| !baseEligibleLocked(
			*beneficiary->second,
			state->second,
			urgentWaitersLocked(
				endpointKey,
				state->second,
				inputs.now),
			inputs.now,
			true)
		|| !victim
		|| !IsBackground(victim->use)
		|| victim->ticketKey != preemption.victimTicketKey
		|| victim->use != preemption.victimUse
		|| victim->owner != preemption.owner
		|| victim->laneControl != preemption.laneControl
		|| !victim->preempting
		|| victim->terminalVerdict
		|| !runtimeLiveLocked(runtimeId)
		|| !MtProxy::RuntimeGenerationIsCurrent(state->second, {
			.runtimeId = runtimeId,
			.proxyGeneration = proxyGeneration,
		})) {
		return false;
	}
	const auto active = activeCountsLocked(state->second);
	const auto scheduled = scheduledCountsLocked(endpointKey);
	const auto urgentWaiters = urgentWaitersLocked(
		endpointKey,
		state->second,
		inputs.now);
	const auto openingPolicy = policyLocked(
		*beneficiary->second,
		state->second,
		active,
		scheduled,
		urgentWaiters,
		inputs,
		true);
	const auto openingReclaim = preemption.reclaim
			== LaneReclaimKind::Opening
		&& admissionActiveVictim
		&& !openingPolicy.admissionAllowed
		&& policyLocked(
			*beneficiary->second,
			state->second,
			MtProxy::ReleaseEndpointAdmission(
				active,
				victim->use),
			scheduled,
			urgentWaiters,
			inputs,
			true).admissionAllowed;
	const auto limit = state->second.liveBudget.learnedLimit;
	const auto commitmentCount
		= MtProxy::EndpointCapacityCommitmentCount(state->second)
		+ MtProxy::TotalEndpointUseCount(scheduled);
	const auto capacityReclaim = preemption.reclaim
			== LaneReclaimKind::Capacity
		&& openingPolicy.admissionAllowed
		&& limit
		&& commitmentCount >= limit
		&& (commitmentCount - 1) < limit;
	if (!openingReclaim && !capacityReclaim) {
		return false;
	}
	preemption.stage = LanePreemptionStage::Authorized;
	return true;
}

void EndpointAdmissionArbiter::Private::demandLaneResume(
		const QString &endpointKey,
		uint64 token,
		ProxyRuntimeId runtimeId,
		uint64 proxyGeneration,
		uint64 attemptId) {
	if (endpointKey.isEmpty()
		|| !token
		|| !runtimeId
		|| !proxyGeneration
		|| !attemptId) {
		return;
	}
	auto inputs = prepareInputs();
	auto actions = Actions();
	auto changed = false;
	{
		QMutexLocker lock(&_storage.mutex);
		const auto lane = _laneSchedules.find(endpointKey);
		const auto state = _storage.states.find(endpointKey);
		if (lane == end(_laneSchedules) || state == end(_storage.states)) {
			return;
		}
		if (!runtimeLiveLocked(runtimeId)
			|| !MtProxy::RuntimeGenerationIsCurrent(state->second, {
				.runtimeId = runtimeId,
				.proxyGeneration = proxyGeneration,
			})) {
			return;
		}
		const auto identity = MtProxy::RelayProofIdentity{
			.runtimeId = runtimeId,
			.proxyGeneration = proxyGeneration,
			.attemptId = attemptId,
		};
		if (lane->second.preemption
			&& lane->second.preemption->token == token
			&& lane->second.preemption->victim == identity
			&& lane->second.preemption->stage
				== LanePreemptionStage::Authorized
			&& lane->second.preemption->deadlineAt > inputs.now
			&& IsBackground(lane->second.preemption->victimUse)
			&& lane->second.preemption->victimTicketKey.ticketId
			&& lane->second.preemption->victimTicketKey.runtimeId == runtimeId
			&& lane->second.preemption->owner
			&& lane->second.preemption->laneControl) {
			lane->second.preemption->demanded = true;
			changed = true;
		} else {
			const auto suspended = ranges::find_if(
				lane->second.suspended,
				[&](const SuspendedLane &entry) {
					return entry.token == token
						&& entry.identity == identity
						&& IsBackground(entry.use)
						&& entry.ticketKey.ticketId
						&& entry.ticketKey.runtimeId == runtimeId
						&& entry.owner
						&& entry.laneControl;
				});
			if (suspended != end(lane->second.suspended)) {
				suspended->demanded = true;
				changed = true;
			} else if (lane->second.resuming
				&& lane->second.resuming->token == token
				&& lane->second.resuming->identity == identity
				&& IsBackground(lane->second.resuming->use)
				&& lane->second.resuming->ticketKey.ticketId
				&& lane->second.resuming->ticketKey.runtimeId == runtimeId
				&& lane->second.resuming->owner
				&& lane->second.resuming->laneControl) {
				lane->second.resuming->demanded = true;
				changed = true;
			}
		}
		if (changed) {
			drainEndpointLocked(endpointKey, inputs, actions);
			updateWakeLocked(inputs, actions);
		}
	}
	actions.run();
}

void EndpointAdmissionArbiter::Private::acknowledgeLaneSuspension(
		const QString &endpointKey,
		uint64 token,
		ProxyRuntimeId runtimeId,
		uint64 proxyGeneration,
		uint64 attemptId,
		MtProxy::EndpointLaneCommandResult result,
		bool delivered) {
	if (endpointKey.isEmpty()
		|| !token
		|| !runtimeId
		|| !proxyGeneration
		|| !attemptId) {
		return;
	}
	auto inputs = prepareInputs();
	auto actions = Actions();
	{
		QMutexLocker lock(&_storage.mutex);
		const auto lane = _laneSchedules.find(endpointKey);
		const auto state = _storage.states.find(endpointKey);
		if (lane == end(_laneSchedules)
			|| !lane->second.preemption
			|| state == end(_storage.states)) {
			return;
		}
		const auto &preemption = *lane->second.preemption;
		const auto identity = MtProxy::RelayProofIdentity{
			.runtimeId = runtimeId,
			.proxyGeneration = proxyGeneration,
			.attemptId = attemptId,
		};
		if (preemption.token != token || preemption.victim != identity) {
			return;
		}
		auto terminal = LanePreemptionTerminal::Retry;
		if (delivered
			&& result == MtProxy::EndpointLaneCommandResult::NotApplicable) {
			terminal = LanePreemptionTerminal::NotApplicable;
		} else if (preemption.deadlineAt <= inputs.now) {
			terminal = LanePreemptionTerminal::Expired;
		} else if (!delivered) {
			terminal = LanePreemptionTerminal::DeliveryFailed;
		} else if (result == MtProxy::EndpointLaneCommandResult::Applied) {
			terminal = LanePreemptionTerminal::Applied;
		}
		finishLanePreemptionLocked(
			endpointKey,
			&state->second,
			token,
			identity,
			terminal);
		drainEndpointLocked(endpointKey, inputs, actions);
		updateWakeLocked(inputs, actions);
	}
	actions.run();
}

void EndpointAdmissionArbiter::Private::acknowledgeLaneResume(
		const QString &endpointKey,
		uint64 token,
		ProxyRuntimeId runtimeId,
		uint64 proxyGeneration,
		uint64 attemptId,
		crl::time deadlineAt,
		MtProxy::EndpointLaneCommandResult result,
		bool delivered) {
	if (endpointKey.isEmpty()
		|| !token
		|| !runtimeId
		|| !proxyGeneration
		|| !attemptId) {
		return;
	}
	auto inputs = prepareInputs();
	auto actions = Actions();
	{
		QMutexLocker lock(&_storage.mutex);
		const auto lane = _laneSchedules.find(endpointKey);
		const auto state = _storage.states.find(endpointKey);
		if (lane == end(_laneSchedules)
			|| !lane->second.resuming
			|| state == end(_storage.states)) {
			return;
		}
		const auto identity = MtProxy::RelayProofIdentity{
			.runtimeId = runtimeId,
			.proxyGeneration = proxyGeneration,
			.attemptId = attemptId,
		};
		const auto &resuming = *lane->second.resuming;
		if (resuming.token != token
			|| resuming.identity != identity
			|| resuming.commandDeadlineAt != deadlineAt
			|| !IsBackground(resuming.use)
			|| !resuming.ticketKey.ticketId
			|| resuming.ticketKey.runtimeId != runtimeId) {
			return;
		}
		auto value = std::move(*lane->second.resuming);
		lane->second.resuming.reset();
		const auto noDemand = delivered
			&& result == MtProxy::EndpointLaneCommandResult::NoDemand;
		const auto retry = !delivered
			|| result == MtProxy::EndpointLaneCommandResult::Retry;
		const auto keepSuspended = (retry || noDemand)
			&& IsBackground(value.use)
			&& value.ticketKey.ticketId
			&& value.ticketKey.runtimeId == value.identity.runtimeId
			&& value.owner
			&& value.laneControl
			&& runtimeLiveLocked(value.identity.runtimeId)
			&& MtProxy::RuntimeGenerationIsCurrent(state->second, {
				.runtimeId = value.identity.runtimeId,
				.proxyGeneration = value.identity.proxyGeneration,
			});
		if (keepSuspended) {
			if (noDemand) {
				value.demanded = false;
			}
			lane->second.suspended.push_front(std::move(value));
		} else {
			QObject::disconnect(value.ownerDestroyed);
		}
		drainEndpointLocked(endpointKey, inputs, actions);
		updateWakeLocked(inputs, actions);
	}
	actions.run();
}

void EndpointAdmissionArbiter::Private::drainEndpoint(
		const QString &endpointKey) {
	if (endpointKey.isEmpty()) {
		return;
	}
	auto inputs = prepareInputs();
	auto actions = Actions();
	{
		QMutexLocker lock(&_storage.mutex);
		drainEndpointLocked(endpointKey, inputs, actions);
		updateWakeLocked(inputs, actions);
	}
	actions.run();
}

void EndpointAdmissionArbiter::Private::wake(uint64 token) {
	if (!token) {
		return;
	}
	auto inputs = prepareInputs();
	auto actions = Actions();
	{
		QMutexLocker lock(&_storage.mutex);
		if (!_wakeArmed
			|| token != _wakeToken
			|| !wakeOwnerLiveLocked()) {
			return;
		}
		clearWakeLocked(false);
		auto endpoints = std::set<QString>();
		for (const auto &entry : _endpoints) {
			endpoints.emplace(entry.first);
		}
		for (const auto &entry : _laneSchedules) {
			endpoints.emplace(entry.first);
		}
		for (const auto &endpointKey : endpoints) {
			drainEndpointLocked(endpointKey, inputs, actions);
		}
		updateWakeLocked(inputs, actions);
	}
	actions.run();
}

void EndpointAdmissionArbiter::Private::deliverStatus(
		AdmissionTicketKey key,
		uint64 revision,
		uint64 transition,
		ProxySchedulerLifecycle lifecycle) {
	auto callbacks = std::shared_ptr<TicketCallbacks>();
	auto update = EndpointAdmissionUpdate();
	{
		QMutexLocker lock(&_storage.mutex);
		const auto i = _tickets.find(key);
		if (i == end(_tickets)
			|| i->second->revision != revision
			|| i->second->transition != transition
			|| i->second->lifecycle != lifecycle
			|| !runtimeLiveLocked(key.runtimeId)
			|| !i->second->owner) {
			return;
		}
		const auto &ticket = *i->second;
		callbacks = ticket.callbacks;
		update = {
			.key = key,
			.revision = revision,
			.lifecycle = ticket.lifecycle,
			.use = ticket.use,
			.enqueuedAt = ticket.enqueuedAt,
			.scheduledOpenAt = ticket.scheduledOpenAt,
			.retryAfter = ticket.retryAfter,
			.blockedBy = ticket.blockedBy,
		};
	}
	if (callbacks && callbacks->status) {
		callbacks->status(std::move(update));
	}
}

void EndpointAdmissionArbiter::Private::deliverGrant(
		AdmissionTicketKey key,
		uint64 revision,
		uint64 transition,
		ProxySchedulerLifecycle lifecycle) {
	auto inputs = prepareInputs();
	auto actions = Actions();
	auto context = std::shared_ptr<ProxyEndpointContext>();
	auto rejectedAdmission = std::optional<MtProxy::Admission>();
	{
		QMutexLocker lock(&_storage.mutex);
		context = _context.lock();
		const auto i = _tickets.find(key);
		if (i == end(_tickets)
			|| i->second->revision != revision
			|| i->second->transition != transition
			|| i->second->lifecycle != lifecycle
			|| i->second->lifecycle != ProxySchedulerLifecycle::Granted) {
			return;
		}
		auto &ticket = *i->second;
		const auto endpointKey = ticket.endpointKey;
		const auto unscoped = MtProxy::EndpointEmpty(ticket.endpoint);
		const auto state = _storage.states.find(endpointKey);
		const auto trace = ticket.traceId
			? _storage.activeTraces.find(ticket.traceId)
			: end(_storage.activeTraces);
		const auto traceCurrent = unscoped
			|| (trace != end(_storage.activeTraces)
				&& trace->second.runtimeId == key.runtimeId
				&& trace->second.ticketId == key.ticketId
				&& trace->second.proxyGeneration
					== ticket.proxyGeneration
				&& trace->second.use == ticket.use
				&& trace->second.ticketKey == key);
		const auto current = unscoped
			|| (state != end(_storage.states)
				&& ticketCurrentLocked(ticket, state->second));
		auto capacity = CandidateCapacityDecision{
			.kind = unscoped
				? CapacityDecisionKind::Ordinary
				: CapacityDecisionKind::Blocked,
		};
		auto finalEligible = unscoped;
		if (!unscoped && state != end(_storage.states) && current) {
			auto scheduled = scheduledCountsLocked(endpointKey);
			scheduled = MtProxy::ReleaseEndpointAdmission(
				scheduled,
				ticket.use);
			const auto urgentWaiters = urgentWaitersLocked(
				endpointKey,
				state->second,
				inputs.now);
			const auto policy = policyLocked(
				ticket,
				state->second,
				activeCountsLocked(state->second),
				scheduled,
				urgentWaiters,
				inputs);
			capacity = capacityDecisionLocked(
				ticket,
				state->second,
				scheduled,
				urgentWaiters,
				inputs.now,
				std::nullopt);
			finalEligible = baseEligibleLocked(
				ticket,
				state->second,
				urgentWaiters,
				inputs.now)
				&& policy.admissionAllowed
				&& capacity.kind != CapacityDecisionKind::Blocked;
		}
		const auto grantContextCurrent = context
			&& ticket.owner
			&& runtimeLiveLocked(key.runtimeId)
			&& traceCurrent
			&& current;
		if (grantContextCurrent
			&& finalEligible
			&& !unscoped
			&& capacity.kind == CapacityDecisionKind::Ordinary) {
			releaseReservedCapacityProbeLocked(ticket);
		}
		if (!grantContextCurrent) {
			cancelTicketLocked(key, revision, actions);
			drainEndpointLocked(endpointKey, inputs, actions);
			updateWakeLocked(inputs, actions);
		} else if (!finalEligible) {
			ticket.blockedBy = TicketFailureReason(ticket, state->second);
			demoteTicketLocked(ticket, actions);
			drainEndpointLocked(endpointKey, inputs, actions);
			updateWakeLocked(inputs, actions);
		} else if (ticket.scheduledOpenAt > inputs.now) {
			ticket.lifecycle = ProxySchedulerLifecycle::Scheduled;
			++ticket.transition;
			postStatusLocked(ticket, actions);
			drainEndpointLocked(endpointKey, inputs, actions);
			updateWakeLocked(inputs, actions);
		} else {
			const auto openCommitted = unscoped
				? !ticket.reservationId
				: IsProxyCheck(ticket.use)
				? !ticket.reservationId
				: ticket.reservationId
					&& MtProxy::CommitOpenSlotLocked(
					_storage.openStates[ticket.endpointKey],
					ticket.reservationId);
			if (!openCommitted) {
				cancelTicketLocked(key, revision, actions);
				drainEndpointLocked(endpointKey, inputs, actions);
				updateWakeLocked(inputs, actions);
			} else {
				auto admission = unscoped
					? std::optional<MtProxy::Admission>(
						MtProxy::Admission())
					: MtProxy::EndpointHealth::BeginScheduledAttemptLocked(
						_storage,
						context,
						ticket.admissionRequest,
						key,
						ticket.traceId,
						ticket.enqueuedAt,
						ticket.scheduledOpenAt,
						inputs.now);
				if (!admission) {
					cancelTicketLocked(key, revision, actions);
					drainEndpointLocked(endpointKey, inputs, actions);
					updateWakeLocked(inputs, actions);
				} else if (capacity.kind == CapacityDecisionKind::Probe
					&& !MtProxy::ActivateCapacityProbe(
						state->second.liveBudget,
						key,
						{
							.runtimeId = admission->runtimeId,
							.proxyGeneration
								= admission->proxyGeneration,
							.attemptId = admission->attemptId,
						})) {
					rejectedAdmission.emplace(std::move(*admission));
					cancelTicketLocked(key, revision, actions);
					drainEndpointLocked(endpointKey, inputs, actions);
					updateWakeLocked(inputs, actions);
				} else {
					auto acceptedRecoveryToken
						= MtProxy::MainRecoveryToken();
					if (!unscoped && ticket.acceptedRecoveryToken) {
						const auto runtimeGeneration
							= RuntimeGenerationKey{
								.runtimeId = key.runtimeId,
								.proxyGeneration
									= ticket.proxyGeneration,
							};
						if (MtProxy::AdoptMainRecoveryReplacementAttemptLocked(
								_storage,
								ticket.endpointKey,
								runtimeGeneration,
								ticket.use,
								ticket.acceptedRecoveryToken,
								key,
								admission->attemptId)) {
							acceptedRecoveryToken
								= ticket.acceptedRecoveryToken;
						} else {
							static_cast<void>(
								MtProxy::FinishMainRecoveryByAdmissionTicketLocked(
									_storage,
									ticket.endpointKey,
									runtimeGeneration,
									ticket.use,
									ticket.acceptedRecoveryToken,
									key));
							ticket.acceptedRecoveryToken = {};
						}
					}
					if (!unscoped) {
						const auto lane = state->second.attemptStarts.find(
							admission->attemptId);
						Assert(lane != end(state->second.attemptStarts));
						lane->second.owner = ticket.owner;
						lane->second.ownerDestroyed
							= ticket.ownerDestroyed;
						lane->second.laneControl = ticket.laneControl;
					}
					auto attempt = ProxyConnectionAttempt{
						.runtimeId = key.runtimeId,
						.traceId = ticket.traceId,
						.ticketId = key.ticketId,
						.proxyGeneration = ticket.proxyGeneration,
						.proxyEpoch = admission->proxyEpoch,
						.successEpoch = admission->successEpoch,
						.attemptId = admission->attemptId,
						.use = ticket.use,
						.ticketKey = key,
					};
					if (trace != end(_storage.activeTraces)) {
						trace->second = attempt;
					}
					if (!unscoped) {
						const auto schedule = _endpoints.find(
							ticket.endpointKey);
						if (schedule != end(_endpoints)) {
							AdvanceFairness(
								schedule->second.fairness,
								ticket,
								priorityForLocked(
									ticket,
									state->second,
									inputs.now));
						}
					}
					if (unscoped) {
						QObject::disconnect(ticket.ownerDestroyed);
					}
					ticket.reservationId = 0;
					ticket.lifecycle = ProxySchedulerLifecycle::HandedOff;
					++ticket.transition;
					invalidateTicketLocked(ticket, actions);
					auto grant = EndpointAdmissionGrant{
						.key = key,
						.revision = revision,
						.proxyGeneration = ticket.proxyGeneration,
						.endpoint = ticket.endpoint,
						.use = ticket.use,
						.acceptedRecoveryToken
							= acceptedRecoveryToken,
						.enqueuedAt = ticket.enqueuedAt,
						.scheduledOpenAt = ticket.scheduledOpenAt,
						.admission = std::move(*admission),
						.attempt = std::move(attempt),
					};
					actions.grants.push_back({
						.context = _context,
						.ticket = takeTicketLocked(key),
						.grant = std::move(grant),
					});
					drainEndpointLocked(endpointKey, inputs, actions);
					updateWakeLocked(inputs, actions);
				}
			}
		}
	}
	if (rejectedAdmission) {
		rejectedAdmission->lease.release();
	}
	actions.run();
}

EndpointAdmissionArbiter::EndpointAdmissionArbiter(
		MtProxy::EndpointContextStorage &storage)
: _private(std::make_unique<Private>(storage)) {
}

EndpointAdmissionArbiter::~EndpointAdmissionArbiter() = default;

void EndpointAdmissionArbiter::bindRuntime(
		ProxyRuntimeId runtimeId,
		EndpointAdmissionRuntimeDispatch dispatch) {
	_private->bindRuntime(runtimeId, std::move(dispatch));
}

void EndpointAdmissionArbiter::unregisterRuntime(
		ProxyRuntimeId runtimeId) {
	_private->unregisterRuntime(runtimeId);
}

void EndpointAdmissionArbiter::cancelRuntime(
		ProxyRuntimeId runtimeId) {
	_private->cancelRuntime(runtimeId);
}

EndpointAdmissionEnqueueResult EndpointAdmissionArbiter::enqueue(
		std::weak_ptr<ProxyEndpointContext> context,
		EndpointAdmissionRequest request) {
	return _private->enqueue(std::move(context), std::move(request));
}

void EndpointAdmissionArbiter::cancel(
		AdmissionTicketKey key,
		uint64 revision) {
	_private->cancel(key, revision);
}

void EndpointAdmissionArbiter::ownerDestroyed(
		AdmissionTicketKey key) {
	_private->ownerDestroyed(key);
}

void EndpointAdmissionArbiter::cancelBeforeGeneration(
		ProxyRuntimeId runtimeId,
		uint64 proxyGeneration) {
	_private->cancelBeforeGeneration(runtimeId, proxyGeneration);
}

bool EndpointAdmissionArbiter::authorizeLaneSuspension(
		const QString &endpointKey,
		uint64 token,
		ProxyRuntimeId runtimeId,
		uint64 proxyGeneration,
		uint64 attemptId) {
	return _private->authorizeLaneSuspension(
		endpointKey,
		token,
		runtimeId,
		proxyGeneration,
		attemptId);
}

void EndpointAdmissionArbiter::demandLaneResume(
		const QString &endpointKey,
		uint64 token,
		ProxyRuntimeId runtimeId,
		uint64 proxyGeneration,
		uint64 attemptId) {
	_private->demandLaneResume(
		endpointKey,
		token,
		runtimeId,
		proxyGeneration,
		attemptId);
}

void EndpointAdmissionArbiter::acknowledgeLaneSuspension(
		const QString &endpointKey,
		uint64 token,
		ProxyRuntimeId runtimeId,
		uint64 proxyGeneration,
		uint64 attemptId,
		MtProxy::EndpointLaneCommandResult result,
		bool delivered) {
	_private->acknowledgeLaneSuspension(
		endpointKey,
		token,
		runtimeId,
		proxyGeneration,
		attemptId,
		result,
		delivered);
}

void EndpointAdmissionArbiter::acknowledgeLaneResume(
		const QString &endpointKey,
		uint64 token,
		ProxyRuntimeId runtimeId,
		uint64 proxyGeneration,
		uint64 attemptId,
		crl::time deadlineAt,
		MtProxy::EndpointLaneCommandResult result,
		bool delivered) {
	_private->acknowledgeLaneResume(
		endpointKey,
		token,
		runtimeId,
		proxyGeneration,
		attemptId,
		deadlineAt,
		result,
		delivered);
}

void EndpointAdmissionArbiter::drainEndpoint(
		const QString &endpointKey) {
	_private->drainEndpoint(endpointKey);
}

void EndpointAdmissionArbiter::composeEndpointViewLocked(
		const MtProxy::EndpointId &endpoint,
		RuntimeGenerationKey runtimeGeneration,
		MtProxy::ProxyEndpointView &view) const {
	_private->composeEndpointViewLocked(
		endpoint,
		runtimeGeneration,
		view);
}

void EndpointAdmissionArbiter::wake(uint64 token) {
	_private->wake(token);
}

void EndpointAdmissionArbiter::deliverStatus(
		AdmissionTicketKey key,
		uint64 revision,
		uint64 transition,
		ProxySchedulerLifecycle lifecycle) {
	_private->deliverStatus(key, revision, transition, lifecycle);
}

void EndpointAdmissionArbiter::deliverGrant(
		AdmissionTicketKey key,
		uint64 revision,
		uint64 transition,
		ProxySchedulerLifecycle lifecycle) {
	_private->deliverGrant(key, revision, transition, lifecycle);
}

} // namespace MTP::details
