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
constexpr auto kExpansionProbeQuietWindow = crl::time(30 * 1000);
constexpr auto kLaneCommandAckTimeout = crl::time(5 * 1000);
constexpr auto kTransferOpeningGrace = crl::time(15 * 1000);
constexpr auto kTransferServiceQuantum = crl::time(15 * 1000);

enum class PriorityClass {
	ForegroundMain,
	ForegroundTransfer,
	UrgentMain,
	OrdinaryMain,
	Maintenance,
	Auxiliary,
	ProxyCheck,
	Background,
	Count,
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
	bool expansionProbe = false;
};

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

struct LanePreemption {
	uint64 token = 0;
	crl::time deadlineAt = 0;
	bool claimed = false;
	AdmissionTicketKey beneficiary;
	MtProxy::RelayProofIdentity victim;
	AdmissionTicketKey victimTicketKey;
	MtProxy::EndpointUse victimUse = MtProxy::EndpointUse::Main;
	QPointer<QObject> owner;
	QMetaObject::Connection ownerDestroyed;
	std::shared_ptr<Fn<void(MtProxy::EndpointLaneCommand)>> laneControl;
	MtProxy::MainRelayProofView mainContinuityProof;
	bool demanded = false;
};

struct LaneVictim {
	MtProxy::RelayProofIdentity identity;
	AdmissionTicketKey ticketKey;
	MtProxy::EndpointUse use = MtProxy::EndpointUse::Main;
	QPointer<QObject> owner;
	QMetaObject::Connection ownerDestroyed;
	std::shared_ptr<Fn<void(MtProxy::EndpointLaneCommand)>> laneControl;
	crl::time startedAt = 0;
	int rank = 0;
	bool durable = false;
};

struct SuspendedLane {
	uint64 token = 0;
	crl::time commandDeadlineAt = 0;
	MtProxy::RelayProofIdentity identity;
	AdmissionTicketKey ticketKey;
	MtProxy::EndpointUse use = MtProxy::EndpointUse::Main;
	QPointer<QObject> owner;
	QMetaObject::Connection ownerDestroyed;
	std::shared_ptr<Fn<void(MtProxy::EndpointLaneCommand)>> laneControl;
	crl::time suspendedAt = 0;
	crl::time resumeAfter = 0;
	AdmissionTicketKey successorTicketKey;
	ProxyRuntimeId foregroundRuntimeIdAtSuspension = 0;
	MtProxy::MainRelayProofView mainContinuityProof;
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

struct ForegroundTransferAdmission {
	int effectiveCap = 0;
	bool natural = false;
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
	} else if (const auto strong = context.lock()) {
		(void)strong->finishTrace(grant.attempt.traceId);
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

[[nodiscard]] bool IsMainDemandPriority(
		const Ticket &ticket,
		PriorityClass priority) {
	return ticket.use == MtProxy::EndpointUse::Main
		&& (priority == PriorityClass::ForegroundMain
			|| priority == PriorityClass::UrgentMain
			|| priority == PriorityClass::OrdinaryMain);
}

[[nodiscard]] bool IsLanePreemptionPriority(
		const Ticket &ticket,
		PriorityClass priority) {
	return priority == PriorityClass::ForegroundTransfer
		|| IsMainDemandPriority(ticket, priority);
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
	[[nodiscard]] bool enqueue(
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
	[[nodiscard]] PriorityClass priorityForLocked(
		const Ticket &ticket,
		const MtProxy::EndpointState &state,
		crl::time now) const;
	[[nodiscard]] ForegroundTransferAdmission foregroundTransferAdmissionLocked(
		const Ticket &ticket,
		const MtProxy::EndpointState &state,
		const DrainInputs &inputs) const;
	[[nodiscard]] bool priorityConflictLocked(
		const Ticket &ticket,
		const MtProxy::EndpointState &state,
		ProxyRuntimeId runtimeId,
		uint64 proxyGeneration,
		AdmissionTicketKey victimTicketKey,
		MtProxy::EndpointUse use,
		crl::time transferServiceUntil,
		const DrainInputs &inputs) const;
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
		const MtProxy::EndpointState &state) const;
	[[nodiscard]] int foregroundMainWaitersLocked(
		const QString &endpointKey,
		const MtProxy::EndpointState &state,
		crl::time now) const;
	[[nodiscard]] MtProxy::MainRelayProofView mainContinuityProofLocked(
		const Ticket &ticket,
		const MtProxy::EndpointState &state) const;
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
	[[nodiscard]] bool liveBudgetAllowsLocked(
		const MtProxy::EndpointState &state,
		const MtProxy::EndpointUseCounts &scheduled,
		crl::time now,
		bool allowExpansionProbe) const;
	void requestLanePreemptionLocked(
		const QString &endpointKey,
		MtProxy::EndpointState &state,
		DrainInputs &inputs,
		Actions &actions);
	void resumeSuspendedLaneLocked(
		const QString &endpointKey,
		MtProxy::EndpointState &state,
		DrainInputs &inputs,
		Actions &actions);
	void refreshTransferServiceLocked(
		const QString &endpointKey,
		MtProxy::EndpointState &state);
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
	void clearLanePreemptionLocked(
		const QString &endpointKey,
		MtProxy::EndpointState &state,
		const MtProxy::RelayProofIdentity &identity);
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
		Actions &actions);
	void grantDueLocked(
		const QString &endpointKey,
		crl::time now,
		Actions &actions);
	void drainEndpointLocked(
		const QString &endpointKey,
		DrainInputs &inputs,
		Actions &actions);
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
		++_wakeToken;
		_wakeArmed = false;
		_wakeDriver = 0;
		_wakeAt = 0;
		for (auto &entry : _tickets) {
			auto &ticket = entry.second;
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

PriorityClass EndpointAdmissionArbiter::Private::priorityForLocked(
		const Ticket &ticket,
		const MtProxy::EndpointState &state,
		crl::time now) const {
	const auto foreground = ticket.key.runtimeId
		== _storage.foregroundRuntimeId;
	const auto hasMainProof = MtProxy::HasCurrentMainRelayProof(state, {
			.runtimeId = ticket.key.runtimeId,
			.proxyGeneration = ticket.proxyGeneration,
		});
	const auto endpointHasMainProof = MtProxy::EndpointMainRelayProof(state)
		.strength != MtProxy::MainRelayProofStrength::None;
	auto result = (ticket.use == MtProxy::EndpointUse::Main)
		? (foreground && !hasMainProof
			? PriorityClass::ForegroundMain
		: hasMainProof
			? PriorityClass::OrdinaryMain
		: endpointHasMainProof
			? PriorityClass::OrdinaryMain
			: PriorityClass::UrgentMain)
		: (foreground && IsBackground(ticket.use))
		? PriorityClass::ForegroundTransfer
		: (ticket.use == MtProxy::EndpointUse::Maintenance)
		? PriorityClass::Maintenance
		: (ticket.use == MtProxy::EndpointUse::Auxiliary)
		? PriorityClass::Auxiliary
		: (ticket.use == MtProxy::EndpointUse::ProxyCheck)
		? PriorityClass::ProxyCheck
		: PriorityClass::Background;
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

bool EndpointAdmissionArbiter::Private::priorityConflictLocked(
		const Ticket &ticket,
		const MtProxy::EndpointState &state,
		ProxyRuntimeId runtimeId,
		uint64 proxyGeneration,
		AdmissionTicketKey victimTicketKey,
		MtProxy::EndpointUse use,
		crl::time transferServiceUntil,
		const DrainInputs &inputs) const {
	const auto priority = priorityForLocked(ticket, state, inputs.now);
	const auto transferAdmission = (priority
			== PriorityClass::ForegroundTransfer)
		? foregroundTransferAdmissionLocked(ticket, state, inputs)
		: ForegroundTransferAdmission();
	const auto laneSchedule = _laneSchedules.find(ticket.endpointKey);
	const auto protectedMainHandoff = use == MtProxy::EndpointUse::Main
		&& victimTicketKey.ticketId
		&& laneSchedule != end(_laneSchedules)
		&& ranges::find_if(
			laneSchedule->second.suspended,
			[&](const SuspendedLane &entry) {
				return IsBackground(entry.use)
					&& entry.successorTicketKey == victimTicketKey
					&& entry.foregroundRuntimeIdAtSuspension
						== _storage.foregroundRuntimeId
					&& entry.resumeAfter > inputs.now;
			}) != end(laneSchedule->second.suspended);
	return (priority == PriorityClass::ForegroundMain)
		? (use != MtProxy::EndpointUse::Main
			|| runtimeId != ticket.key.runtimeId
			|| proxyGeneration != ticket.proxyGeneration)
		: (priority == PriorityClass::ForegroundTransfer)
		? ((IsBackground(use)
				&& (runtimeId != _storage.foregroundRuntimeId
					|| proxyGeneration != ticket.proxyGeneration
					|| transferServiceUntil <= inputs.now))
			|| (use == MtProxy::EndpointUse::Main
				&& !transferAdmission.natural
				&& (runtimeId != _storage.foregroundRuntimeId
					|| transferAdmission.effectiveCap == 1)
				&& !protectedMainHandoff))
		: (priority == PriorityClass::UrgentMain)
		? ((use != MtProxy::EndpointUse::Main
				&& !(IsBackground(use)
					&& runtimeId == _storage.foregroundRuntimeId
					&& MtProxy::RuntimeGenerationIsCurrent(state, {
						.runtimeId = runtimeId,
						.proxyGeneration = proxyGeneration,
					})
					&& ProvenEndpointCapacity(state) > 1
					&& transferServiceUntil > inputs.now))
			|| (use == MtProxy::EndpointUse::Main
				&& !MtProxy::RuntimeGenerationIsCurrent(state, {
					.runtimeId = runtimeId,
					.proxyGeneration = proxyGeneration,
				})))
		: (priority == PriorityClass::OrdinaryMain
			&& ticket.use == MtProxy::EndpointUse::Main)
		? (use != MtProxy::EndpointUse::Main
			&& (!IsBackground(use)
				|| transferServiceUntil <= inputs.now))
		: false;
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
		for (const auto other : pool) {
			if (other->key.runtimeId == ticket->key.runtimeId
				&& other->use == ticket->use
				&& other->sequence < ticket->sequence) {
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
	const auto foregroundMainAvailable = ranges::find_if(
		heads,
		[&](const Ticket *ticket) {
			return priorityForLocked(*ticket, state, now)
				== PriorityClass::ForegroundMain;
		}) != end(heads);
	if (!foregroundMainAvailable) {
		const auto lane = _laneSchedules.find(heads.front()->endpointKey);
		if (lane != end(_laneSchedules) && lane->second.handoffBeneficiary) {
			const auto handoff = ranges::find_if(
				heads,
				[&](const Ticket *ticket) {
					const auto priority = priorityForLocked(
						*ticket,
						state,
						now);
					return ticket->key
							== *lane->second.handoffBeneficiary
						&& IsLanePreemptionPriority(*ticket, priority);
				});
			if (handoff != end(heads)) {
				return *handoff;
			}
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
		const MtProxy::EndpointState &state) const {
	const auto schedule = _endpoints.find(endpointKey);
	if (schedule == end(_endpoints)) {
		return 0;
	}
	auto result = 0;
	for (const auto &key : schedule->second.order) {
		const auto i = _tickets.find(key);
		if (i != end(_tickets)
			&& WaitingForHandoff(i->second->lifecycle)
			&& IsUrgentMainPriority(priorityForLocked(
				*i->second,
				state,
				i->second->enqueuedAt))) {
			++result;
		}
	}
	return result;
}

int EndpointAdmissionArbiter::Private::foregroundMainWaitersLocked(
		const QString &endpointKey,
		const MtProxy::EndpointState &state,
		crl::time now) const {
	const auto schedule = _endpoints.find(endpointKey);
	if (schedule == end(_endpoints)) {
		return 0;
	}
	auto result = 0;
	for (const auto &key : schedule->second.order) {
		const auto i = _tickets.find(key);
		if (i != end(_tickets)
			&& WaitingForHandoff(i->second->lifecycle)
			&& priorityForLocked(*i->second, state, now)
				== PriorityClass::ForegroundMain) {
			++result;
		}
	}
	return result;
}

auto EndpointAdmissionArbiter::Private::mainContinuityProofLocked(
		const Ticket &ticket,
		const MtProxy::EndpointState &state) const
-> MtProxy::MainRelayProofView {
	if (!IsBackground(ticket.use)
		|| ticket.key.runtimeId != _storage.foregroundRuntimeId
		|| !WaitingForHandoff(ticket.lifecycle)
		|| !MtProxy::RuntimeGenerationIsCurrent(state, {
			.runtimeId = ticket.key.runtimeId,
			.proxyGeneration = ticket.proxyGeneration,
		})) {
		return {};
	}
	const auto schedule = _laneSchedules.find(ticket.endpointKey);
	if (schedule == end(_laneSchedules)) {
		return {};
	}
	const auto i = ranges::find_if(
		schedule->second.suspended,
		[&](const SuspendedLane &entry) {
			return entry.use == MtProxy::EndpointUse::Main
				&& entry.identity.runtimeId == ticket.key.runtimeId
				&& entry.identity.proxyGeneration == ticket.proxyGeneration
				&& entry.successorTicketKey == ticket.key
				&& entry.owner
				&& entry.laneControl
				&& entry.mainContinuityProof.strength
					!= MtProxy::MainRelayProofStrength::None;
		});
	return (i == end(schedule->second.suspended))
		? MtProxy::MainRelayProofView()
		: i->mainContinuityProof;
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
	auto mainProof = MtProxy::CurrentMainRelayProof(state, {
		.runtimeId = ticket.key.runtimeId,
		.proxyGeneration = ticket.proxyGeneration,
	});
	auto endpointMainProof = MtProxy::EndpointMainRelayProof(state);
	const auto continuityProof = mainContinuityProofLocked(ticket, state);
	const auto effectiveUrgentWaiters = (continuityProof.strength
			!= MtProxy::MainRelayProofStrength::None)
		? foregroundMainWaitersLocked(ticket.endpointKey, state, inputs.now)
		: urgentWaiters;
	if (mainProof.strength == MtProxy::MainRelayProofStrength::None) {
		mainProof = continuityProof;
	}
	if (endpointMainProof.strength == MtProxy::MainRelayProofStrength::None) {
		endpointMainProof = continuityProof;
	}
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
		.urgentMainDemand = effectiveUrgentWaiters,
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
			std::max(
				endpointMainProof.provenAt,
				endpointMainProof.lastPayloadAt),
			std::max(
				continuityProof.provenAt,
				continuityProof.lastPayloadAt)),
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
	const auto continuityProof = mainContinuityProofLocked(ticket, state);
	const auto effectiveUrgentWaiters = (continuityProof.strength
			!= MtProxy::MainRelayProofStrength::None)
		? foregroundMainWaitersLocked(ticket.endpointKey, state, now)
		: urgentWaiters;
	const auto hasMainProof = MtProxy::HasCurrentMainRelayProof(state, {
		.runtimeId = ticket.key.runtimeId,
		.proxyGeneration = ticket.proxyGeneration,
	}) || (continuityProof.strength
			!= MtProxy::MainRelayProofStrength::None);
	return (!effectiveUrgentWaiters || canShareUrgentMain) && hasMainProof;
}

bool EndpointAdmissionArbiter::Private::liveBudgetAllowsLocked(
		const MtProxy::EndpointState &state,
		const MtProxy::EndpointUseCounts &scheduled,
		crl::time now,
		bool allowExpansionProbe) const {
	const auto limit = state.liveBudget.learnedLimit;
	if (!limit) {
		return true;
	}
	const auto scheduledCount = MtProxy::TotalEndpointUseCount(scheduled);
	const auto occupancy = MtProxy::CurrentEndpointLiveLaneCount(state)
		+ scheduledCount;
	if (occupancy < limit) {
		return true;
	}
	return occupancy == limit
		&& !scheduledCount
		&& (MtProxy::ActiveEndpointAdmissionCount(state) == 0)
		&& allowExpansionProbe
		&& state.liveBudget.expansionProbeAfter
		&& state.liveBudget.expansionProbeAfter <= now;
}

auto EndpointAdmissionArbiter::Private::foregroundTransferAdmissionLocked(
		const Ticket &ticket,
		const MtProxy::EndpointState &state,
		const DrainInputs &inputs) const
-> ForegroundTransferAdmission {
	auto scheduled = scheduledCountsLocked(ticket.endpointKey);
	if (ticket.lifecycle == ProxySchedulerLifecycle::Scheduled
		|| ticket.lifecycle == ProxySchedulerLifecycle::Granted) {
		scheduled = MtProxy::ReleaseEndpointAdmission(
			scheduled,
			ticket.use);
	}
	const auto urgentWaiters = urgentWaitersLocked(ticket.endpointKey, state);
	const auto policy = policyLocked(
		ticket,
		state,
		activeCountsLocked(state),
		scheduled,
		urgentWaiters,
		inputs,
		true);
	const auto learnedLimit = state.liveBudget.learnedLimit;
	const auto effectiveCap = learnedLimit
		? std::min(policy.activeCap, learnedLimit)
		: policy.activeCap;
	const auto occupancy = MtProxy::CurrentEndpointLiveLaneCount(state)
		+ MtProxy::TotalEndpointUseCount(scheduled);
	const auto liveAllowed = liveBudgetAllowsLocked(
		state,
		scheduled,
		inputs.now,
		!urgentWaiters);
	return {
		.effectiveCap = effectiveCap,
		.natural = policy.admissionAllowed
			&& occupancy < policy.activeCap
			&& liveAllowed
			&& (MtProxy::EndpointTransferLaneCount(state) == 0),
	};
}

void EndpointAdmissionArbiter::Private::requestLanePreemptionLocked(
		const QString &endpointKey,
		MtProxy::EndpointState &state,
		DrainInputs &inputs,
		Actions &actions) {
	const auto limit = state.liveBudget.learnedLimit;
	auto &laneSchedule = _laneSchedules[endpointKey];
	if (laneSchedule.preemption || laneSchedule.resuming) {
		return;
	}
	const auto schedule = _endpoints.find(endpointKey);
	if (schedule == end(_endpoints)) {
		return;
	}
	const auto active = activeCountsLocked(state);
	const auto scheduled = scheduledCountsLocked(endpointKey);
	const auto urgentWaiters = urgentWaitersLocked(endpointKey, state);
	const auto openingPriorityConflict = [&](const Ticket &ticket) {
		return ranges::find_if(
			state.attemptStarts,
			[&](const auto &entry) {
				const auto &attempt = entry.second;
				return priorityConflictLocked(
						ticket,
						state,
						attempt.runtimeId,
						attempt.proxyGeneration,
						attempt.ticketKey,
						attempt.use,
						attempt.transferServiceUntil,
						inputs)
					&& !attempt.preempting
					&& !attempt.terminalVerdict
					&& attempt.owner
					&& attempt.laneControl;
			}) != end(state.attemptStarts);
	};
	const auto livePriorityConflict = [&](const Ticket &ticket) {
		return ranges::find_if(
			state.liveLanes,
			[&](const auto &entry) {
				const auto &identity = entry.first;
				const auto &lane = entry.second;
				return priorityConflictLocked(
						ticket,
						state,
						identity.runtimeId,
						identity.proxyGeneration,
						lane.ticketKey,
						lane.use,
						lane.transferServiceUntil,
						inputs)
					&& !lane.preempting
					&& lane.owner
					&& lane.laneControl;
			}) != end(state.liveLanes);
	};
	const auto reservationPriorityConflict = [&](const Ticket &ticket) {
		const auto priority = priorityForLocked(ticket, state, inputs.now);
		return ranges::find_if(
			schedule->second.order,
			[&](const AdmissionTicketKey &key) {
				const auto i = _tickets.find(key);
				return i != end(_tickets)
					&& (i->second->lifecycle
							== ProxySchedulerLifecycle::Scheduled
						|| i->second->lifecycle
							== ProxySchedulerLifecycle::Granted)
					&& priorityForLocked(
						*i->second,
						state,
						inputs.now) > priority;
			}) != end(schedule->second.order);
	};
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
		if (!IsLanePreemptionPriority(ticket, priority)) {
			continue;
		}
		pool.push_back(&ticket);
		const auto verdict = TicketVerdict(ticket, state);
		const auto boundary = std::max({
			state.opening.bootstrap.retryUntil,
			verdict ? verdict->retryUntil : crl::time(),
			state.nextHandshakeAt,
		});
		if (boundary > inputs.now) {
			continue;
		}
		const auto policy = policyLocked(
			ticket,
			state,
			active,
			MtProxy::EndpointUseCounts(),
			urgentWaiters,
			inputs,
			true);
		if (baseEligibleLocked(
				ticket,
				state,
				urgentWaiters,
				inputs.now,
				true)
			&& (policy.admissionAllowed
				|| openingPriorityConflict(ticket)
				|| livePriorityConflict(ticket)
				|| reservationPriorityConflict(ticket))) {
			eligible.emplace(ticket.key);
		}
	}
	auto mainPool = std::vector<Ticket*>();
	for (const auto ticket : pool) {
		if (ticket->use == MtProxy::EndpointUse::Main) {
			mainPool.push_back(ticket);
		}
	}
	const auto mainBeneficiary = selectLocked(
		mainPool,
		eligible,
		state,
		inputs.now,
		schedule->second.fairness);
	const auto beneficiary = mainBeneficiary
		? mainBeneficiary
		: selectLocked(
			pool,
			eligible,
			state,
			inputs.now,
			schedule->second.fairness);
	if (!beneficiary) {
		return;
	}
	const auto openingConflict = openingPriorityConflict(*beneficiary);
	const auto liveConflict = livePriorityConflict(*beneficiary);
	const auto reservationConflict = reservationPriorityConflict(*beneficiary);
	auto transferConflict = false;
	if (IsBackground(beneficiary->use)) {
		for (const auto &entry : state.liveLanes) {
			if (IsBackground(entry.second.use)) {
				transferConflict = true;
				break;
			}
		}
		if (!transferConflict) {
			for (const auto &entry : state.attemptStarts) {
				const auto &attempt = entry.second;
				if (IsBackground(attempt.use)) {
					transferConflict = true;
					break;
				}
			}
		}
	}
	if (IsBackground(beneficiary->use)
		&& MtProxy::EndpointTransferLaneCount(state) > 0
		&& !transferConflict) {
		return;
	}
	const auto capacityPressure = limit
		&& (MtProxy::CurrentEndpointLiveLaneCount(state)
			+ MtProxy::TotalEndpointUseCount(scheduled) >= limit);
	if (!transferConflict
		&& !capacityPressure
		&& !openingConflict
		&& !liveConflict
		&& !reservationConflict) {
		return;
	}
	const auto beneficiaryPriority = priorityForLocked(
		*beneficiary,
		state,
		inputs.now);
	auto demotedReservation = false;
	for (const auto &key : schedule->second.order) {
		const auto i = _tickets.find(key);
		if (i != end(_tickets)
			&& (i->second->lifecycle == ProxySchedulerLifecycle::Scheduled
				|| i->second->lifecycle == ProxySchedulerLifecycle::Granted)
			&& priorityForLocked(*i->second, state, inputs.now)
				> beneficiaryPriority) {
			demoteTicketLocked(*i->second, actions);
			demotedReservation = true;
		}
	}
	const auto capacityAfterDemotion = limit
		&& (MtProxy::CurrentEndpointLiveLaneCount(state)
			+ MtProxy::TotalEndpointUseCount(
				scheduledCountsLocked(endpointKey)) >= limit);
	if (demotedReservation
		&& !transferConflict
		&& !openingConflict
		&& !liveConflict
		&& !capacityAfterDemotion) {
		return;
	}
	const auto actualPolicy = policyLocked(
		*beneficiary,
		state,
		active,
		scheduledCountsLocked(endpointKey),
		urgentWaiters,
		inputs,
		true);
	const auto staleSameRuntimeMain = [=](
			ProxyRuntimeId runtimeId,
			uint64 proxyGeneration,
			MtProxy::EndpointUse use) {
		return beneficiaryPriority == PriorityClass::ForegroundMain
			&& use == MtProxy::EndpointUse::Main
			&& runtimeId == beneficiary->key.runtimeId
			&& proxyGeneration != beneficiary->proxyGeneration;
	};
	const auto hasStaleSameRuntimeMain = ranges::any_of(
		state.attemptStarts,
		[&](const auto &entry) {
			const auto &attempt = entry.second;
			return staleSameRuntimeMain(
				attempt.runtimeId,
				attempt.proxyGeneration,
				attempt.use);
		}) || ranges::any_of(
		state.liveLanes,
		[&](const auto &entry) {
			return staleSameRuntimeMain(
				entry.first.runtimeId,
				entry.first.proxyGeneration,
				entry.second.use);
		});
	const auto scheduledAfterDemotion = scheduledCountsLocked(endpointKey);
	const auto provenCapacity = ProvenEndpointCapacity(state);
	const auto occupancyAfterDemotion
		= MtProxy::CurrentEndpointLiveLaneCount(state)
		+ MtProxy::TotalEndpointUseCount(scheduledAfterDemotion);
	const auto hasProvenSpare = provenCapacity
		&& occupancyAfterDemotion < provenCapacity;
	if (actualPolicy.admissionAllowed
		&& hasProvenSpare
		&& !transferConflict
		&& !hasStaleSameRuntimeMain) {
		return;
	}
	if (!actualPolicy.admissionAllowed
		&& !transferConflict
		&& !openingConflict
		&& !liveConflict) {
		return;
	}
	auto victim = std::optional<LaneVictim>();
	const auto victimRank = [&](
			MtProxy::EndpointUse use,
			ProxyRuntimeId runtimeId,
			uint64 proxyGeneration) {
		if (staleSameRuntimeMain(runtimeId, proxyGeneration, use)) {
			return -2;
		}
		if (beneficiaryPriority == PriorityClass::ForegroundMain
			&& use == MtProxy::EndpointUse::Main) {
			return -1;
		}
		const auto foreground = runtimeId == _storage.foregroundRuntimeId;
		return (use == MtProxy::EndpointUse::Maintenance
				|| use == MtProxy::EndpointUse::Auxiliary
				|| use == MtProxy::EndpointUse::ProxyCheck)
			? 0
			: (IsBackground(use) && !foreground)
			? 1
			: IsBackground(use)
			? 2
			: (use != MtProxy::EndpointUse::Main)
			? 3
			: 4;
	};
	const auto considerVictim = [&](LaneVictim candidate) {
		if (!victim
			|| std::tie(
				candidate.rank,
				candidate.durable,
				candidate.startedAt,
				candidate.identity)
				< std::tie(
					victim->rank,
					victim->durable,
					victim->startedAt,
					victim->identity)) {
			victim = std::move(candidate);
		}
	};
	if (IsLanePreemptionPriority(*beneficiary, beneficiaryPriority)) {
		for (const auto &[attemptId, attempt] : state.attemptStarts) {
			const auto replaceableMain = beneficiaryPriority
					== PriorityClass::ForegroundMain
				&& attempt.use == MtProxy::EndpointUse::Main
				&& (attempt.runtimeId != beneficiary->key.runtimeId
					|| attempt.proxyGeneration
						!= beneficiary->proxyGeneration);
			const auto candidatePriorityConflict = priorityConflictLocked(
				*beneficiary,
				state,
				attempt.runtimeId,
				attempt.proxyGeneration,
				attempt.ticketKey,
				attempt.use,
				attempt.transferServiceUntil,
				inputs);
			const auto reclaimableMain = beneficiaryPriority
					== PriorityClass::ForegroundTransfer
				&& attempt.use == MtProxy::EndpointUse::Main
				&& attempt.runtimeId != beneficiary->key.runtimeId
				&& candidatePriorityConflict;
			if ((attempt.use == MtProxy::EndpointUse::Main
					&& !replaceableMain
					&& !reclaimableMain)
				|| !candidatePriorityConflict
				|| attempt.preempting
				|| attempt.terminalVerdict
				|| !attempt.owner
				|| !attempt.laneControl) {
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
				.rank = victimRank(
					attempt.use,
					attempt.runtimeId,
					attempt.proxyGeneration),
			});
		}
	}
	for (auto i = begin(state.liveLanes); i != end(state.liveLanes); ++i) {
		const auto &[identity, lane] = *i;
		const auto currentGeneration = MtProxy::RuntimeGenerationIsCurrent(
			state,
			{
				.runtimeId = identity.runtimeId,
				.proxyGeneration = identity.proxyGeneration,
			});
		const auto candidatePriorityConflict = priorityConflictLocked(
				*beneficiary,
				state,
				identity.runtimeId,
				identity.proxyGeneration,
				lane.ticketKey,
				lane.use,
				lane.transferServiceUntil,
				inputs);
		if (lane.preempting
			|| !lane.owner
			|| !lane.laneControl
			|| (transferConflict && !IsBackground(lane.use))
			|| !candidatePriorityConflict
			|| (beneficiaryPriority != PriorityClass::ForegroundTransfer
				&& identity.runtimeId == beneficiary->key.runtimeId
				&& lane.use == MtProxy::EndpointUse::Main
				&& currentGeneration)
			|| (beneficiaryPriority != PriorityClass::ForegroundTransfer
				&& lane.use == MtProxy::EndpointUse::Main
				&& identity.runtimeId == _storage.foregroundRuntimeId
				&& currentGeneration)
			|| (beneficiaryPriority == PriorityClass::UrgentMain
				&& lane.use == MtProxy::EndpointUse::Main
				&& currentGeneration)) {
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
			.rank = victimRank(
				lane.use,
				identity.runtimeId,
				identity.proxyGeneration),
			.durable = true,
		});
	}
	if (!victim) {
		return;
	}
	const auto victimIdentity = victim->identity;
	const auto victimUse = victim->use;
	const auto victimOwner = victim->owner;
	const auto victimOwnerDestroyed = victim->ownerDestroyed;
	const auto laneControl = victim->laneControl;
	const auto runtime = _runtimes.find(victimIdentity.runtimeId);
	if (runtime == end(_runtimes)) {
		return;
	}
	const auto token = ++_lastLaneToken;
	const auto deadlineAt = inputs.now + kLaneCommandAckTimeout;
	const auto proof = state.relayProofs.find(victimIdentity);
	if (proof != end(state.relayProofs)) {
		proof->second.preempting = true;
	}
	const auto attempt = state.attemptStarts.find(victimIdentity.attemptId);
	if (attempt != end(state.attemptStarts)) {
		attempt->second.preempting = true;
	}
	const auto liveLane = state.liveLanes.find(victimIdentity);
	if (liveLane != end(state.liveLanes)) {
		liveLane->second.preempting = true;
	}
	laneSchedule.preemption = LanePreemption{
		.token = token,
		.deadlineAt = deadlineAt,
		.beneficiary = beneficiary->key,
		.victim = victimIdentity,
		.victimTicketKey = victim->ticketKey,
		.victimUse = victimUse,
		.owner = victimOwner,
		.ownerDestroyed = victimOwnerDestroyed,
		.laneControl = laneControl,
	};
	const auto weak = _context;
	actions.posts.push_back({
		.dispatch = runtime->second,
		.target = victimOwner,
		.callback = [
			weak,
			endpointKey,
			token,
			deadlineAt,
			victimIdentity,
			laneControl
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
}

void EndpointAdmissionArbiter::Private::resumeSuspendedLaneLocked(
		const QString &endpointKey,
		MtProxy::EndpointState &state,
		DrainInputs &inputs,
		Actions &actions) {
	const auto lane = _laneSchedules.find(endpointKey);
	if (lane == end(_laneSchedules)
		|| lane->second.preemption
		|| lane->second.resuming) {
		return;
	}
	auto &suspended = lane->second.suspended;
	for (auto i = begin(suspended); i != end(suspended);) {
		if (!i->owner
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
	if (suspended.empty()) {
		_laneSchedules.erase(lane);
		return;
	}
	const auto schedule = _endpoints.find(endpointKey);
	auto foregroundMainWaiting = false;
	auto urgentMainWaiting = false;
	auto ordinaryMainWaiting = false;
	if (schedule != end(_endpoints)) {
		for (const auto &key : schedule->second.order) {
			const auto ticket = _tickets.find(key);
			if (ticket != end(_tickets)
				&& WaitingForHandoff(ticket->second->lifecycle)) {
				const auto priority = priorityForLocked(
					*ticket->second,
					state,
					inputs.now);
				foregroundMainWaiting = foregroundMainWaiting
					|| priority == PriorityClass::ForegroundMain;
				urgentMainWaiting = urgentMainWaiting
					|| priority == PriorityClass::UrgentMain;
				ordinaryMainWaiting = ordinaryMainWaiting
					|| (ticket->second->use == MtProxy::EndpointUse::Main
						&& priority == PriorityClass::OrdinaryMain);
			}
		}
	}
	auto foregroundTransferActive = false;
	auto foregroundTransferServiceUntil = crl::time();
	for (const auto &attempt : state.attemptStarts) {
		if (IsBackground(attempt.second.use)
			&& attempt.second.runtimeId == _storage.foregroundRuntimeId
			&& MtProxy::RuntimeGenerationIsCurrent(state, {
				.runtimeId = attempt.second.runtimeId,
				.proxyGeneration = attempt.second.proxyGeneration,
			})) {
			foregroundTransferActive = true;
			foregroundTransferServiceUntil = std::max(
				foregroundTransferServiceUntil,
				attempt.second.transferServiceUntil);
		}
	}
	for (const auto &[identity, activeLane] : state.liveLanes) {
		if (IsBackground(activeLane.use)
			&& identity.runtimeId == _storage.foregroundRuntimeId
			&& MtProxy::RuntimeGenerationIsCurrent(state, {
				.runtimeId = identity.runtimeId,
				.proxyGeneration = identity.proxyGeneration,
			})) {
			foregroundTransferActive = true;
			foregroundTransferServiceUntil = std::max(
				foregroundTransferServiceUntil,
				activeLane.transferServiceUntil);
		}
	}
	const auto resumable = [&](const SuspendedLane &entry) {
		const auto runtimeGeneration = RuntimeGenerationKey{
			.runtimeId = entry.identity.runtimeId,
			.proxyGeneration = entry.identity.proxyGeneration,
		};
		const auto foreground = entry.identity.runtimeId
			== _storage.foregroundRuntimeId;
		if (foregroundMainWaiting) {
			return false;
		}
		if (urgentMainWaiting
			&& !(foreground && entry.use == MtProxy::EndpointUse::Main)
			&& !(foreground
				&& IsBackground(entry.use)
				&& ProvenEndpointCapacity(state) > 1)) {
			return false;
		}
		if (ordinaryMainWaiting
			&& entry.use != MtProxy::EndpointUse::Main) {
			return false;
		}
		const auto accountSwitchedToEntry = foreground
			&& entry.foregroundRuntimeIdAtSuspension
			&& entry.foregroundRuntimeIdAtSuspension
				!= _storage.foregroundRuntimeId;
		const auto successor = _tickets.find(entry.successorTicketKey);
		const auto successorPriority = successor != end(_tickets)
			? priorityForLocked(*successor->second, state, inputs.now)
			: PriorityClass::Count;
		if (!accountSwitchedToEntry
			&& successor != end(_tickets)
			&& WaitingForHandoff(successor->second->lifecycle)
			&& ticketCurrentLocked(*successor->second, state)
			&& IsLanePreemptionPriority(
				*successor->second,
				successorPriority)) {
			return false;
		}
		const auto successorAttemptActive = entry.successorTicketKey.ticketId
			&& (ranges::find_if(
				state.attemptStarts,
				[&](const auto &attempt) {
					return attempt.second.ticketKey
						== entry.successorTicketKey;
				}) != end(state.attemptStarts)
				|| ranges::find_if(
					state.liveLanes,
					[&](const auto &active) {
						return active.second.ticketKey
							== entry.successorTicketKey;
					}) != end(state.liveLanes));
		if (!accountSwitchedToEntry
			&& successorAttemptActive
			&& entry.resumeAfter > inputs.now) {
			return false;
		}
		if (entry.use == MtProxy::EndpointUse::Main) {
			return !foregroundTransferActive
				|| foregroundTransferServiceUntil <= inputs.now;
		}
		if (IsBackground(entry.use) && !entry.demanded) {
			return false;
		}
		if ((IsBackground(entry.use)
				|| entry.use == MtProxy::EndpointUse::Auxiliary)
			&& !MtProxy::HasCurrentMainRelayProof(
				state,
				runtimeGeneration)) {
			return false;
		}
		const auto hasMatchingTransfer = ranges::find_if(
			state.attemptStarts,
			[&](const auto &attempt) {
				return IsBackground(attempt.second.use)
					&& attempt.second.runtimeId
						== entry.identity.runtimeId
					&& attempt.second.proxyGeneration
						== entry.identity.proxyGeneration;
			}) != end(state.attemptStarts)
			|| ranges::find_if(
				state.liveLanes,
				[&](const auto &lane) {
					return IsBackground(lane.second.use)
						&& lane.first.runtimeId
							== entry.identity.runtimeId
						&& lane.first.proxyGeneration
							== entry.identity.proxyGeneration;
				}) != end(state.liveLanes);
		return !IsBackground(entry.use)
			|| (MtProxy::EndpointTransferLaneCount(state) == 0)
			|| (foreground && !hasMatchingTransfer)
			|| (entry.resumeAfter && entry.resumeAfter <= inputs.now);
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
	const auto demandRequired = IsBackground(value.use);
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
			deadlineAt,
			demandRequired
		]() mutable {
			(*control)({
				.type = MtProxy::EndpointLaneCommandType::Resume,
				.token = token,
				.deadlineAt = deadlineAt,
				.demandRequired = demandRequired,
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

void EndpointAdmissionArbiter::Private::refreshTransferServiceLocked(
		const QString &endpointKey,
		MtProxy::EndpointState &state) {
	const auto schedule = _laneSchedules.find(endpointKey);
	for (auto &[identity, lane] : state.liveLanes) {
		if (!IsBackground(lane.use)) {
			continue;
		}
		const auto proof = state.relayProofs.find(identity);
		if (proof == end(state.relayProofs)) {
			continue;
		}
		const auto serviceUntil = proof->second.provenAt
			+ kTransferServiceQuantum;
		if (lane.transferServiceUntil >= serviceUntil) {
			continue;
		}
		lane.transferServiceUntil = serviceUntil;
		if (schedule != end(_laneSchedules)) {
			for (auto &entry : schedule->second.suspended) {
				if (entry.successorTicketKey == lane.ticketKey) {
					entry.resumeAfter = serviceUntil;
				}
			}
		}
	}
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
	const auto lane = _laneSchedules.find(result->endpointKey);
	if (lane != end(_laneSchedules)
		&& lane->second.handoffBeneficiary
		&& *lane->second.handoffBeneficiary == key) {
		lane->second.handoffBeneficiary.reset();
	}
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
	const auto lane = _laneSchedules.find(ticket.endpointKey);
	if (lane != end(_laneSchedules)) {
		if (lane->second.handoffBeneficiary
			&& *lane->second.handoffBeneficiary == key) {
			lane->second.handoffBeneficiary.reset();
		}
		if (lane->second.preemption
			&& lane->second.preemption->beneficiary == key
			&& !lane->second.preemption->claimed) {
			const auto state = _storage.states.find(ticket.endpointKey);
			if (state != end(_storage.states)) {
				clearLanePreemptionLocked(
					ticket.endpointKey,
					state->second,
					lane->second.preemption->victim);
			} else {
				QObject::disconnect(
					lane->second.preemption->ownerDestroyed);
				lane->second.preemption.reset();
			}
		}
		for (auto &entry : lane->second.suspended) {
			if (entry.successorTicketKey == key) {
				entry.successorTicketKey = {};
			}
		}
	}
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
	const auto lane = _laneSchedules.find(ticket.endpointKey);
	if (lane != end(_laneSchedules)) {
		if (lane->second.handoffBeneficiary
			&& *lane->second.handoffBeneficiary == ticket.key) {
			lane->second.handoffBeneficiary.reset();
		}
		for (auto &entry : lane->second.suspended) {
			if (entry.successorTicketKey == ticket.key) {
				entry.successorTicketKey = {};
			}
		}
	}
	if (ticket.reservationId) {
		const auto state = _storage.openStates.find(ticket.endpointKey);
		if (state != end(_storage.openStates)) {
			static_cast<void>(MtProxy::CancelOpenSlotLocked(
				state->second,
				ticket.reservationId));
		}
	}
	ticket.reservationId = 0;
	ticket.expansionProbe = false;
	ticket.scheduledOpenAt = 0;
	ticket.nextOpenAt = 0;
	ticket.reevaluateAt = 0;
	ticket.retryAfter = 0;
	ticket.lifecycle = ProxySchedulerLifecycle::Queued;
	++ticket.transition;
	postStatusLocked(ticket, actions);
}

void EndpointAdmissionArbiter::Private::clearLanePreemptionLocked(
		const QString &endpointKey,
		MtProxy::EndpointState &state,
		const MtProxy::RelayProofIdentity &identity) {
	const auto lane = _laneSchedules.find(endpointKey);
	if (lane == end(_laneSchedules)
		|| !lane->second.preemption
		|| lane->second.preemption->victim != identity) {
		return;
	}
	const auto ownerDestroyed = lane->second.preemption->ownerDestroyed;
	const auto proof = state.relayProofs.find(identity);
	if (proof != end(state.relayProofs)) {
		proof->second.preempting = false;
	}
	const auto attempt = state.attemptStarts.find(identity.attemptId);
	if (attempt != end(state.attemptStarts)
		&& attempt->second.runtimeId == identity.runtimeId
		&& attempt->second.proxyGeneration == identity.proxyGeneration) {
		attempt->second.preempting = false;
	}
	const auto liveLane = state.liveLanes.find(identity);
	if (liveLane != end(state.liveLanes)) {
		liveLane->second.preempting = false;
	}
	lane->second.preemption.reset();
	if ((attempt == end(state.attemptStarts)
			|| attempt->second.runtimeId != identity.runtimeId
			|| attempt->second.proxyGeneration != identity.proxyGeneration)
		&& liveLane == end(state.liveLanes)) {
		QObject::disconnect(ownerDestroyed);
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
		&& !lane->second.preemption->claimed
		&& lane->second.preemption->deadlineAt
		&& lane->second.preemption->deadlineAt <= now) {
		const auto identity = lane->second.preemption->victim;
		clearLanePreemptionLocked(endpointKey, state, identity);
	}
	if (lane->second.resuming
		&& lane->second.resuming->commandDeadlineAt
		&& lane->second.resuming->commandDeadlineAt <= now) {
		auto value = std::move(*lane->second.resuming);
		lane->second.resuming.reset();
		value.commandDeadlineAt = 0;
		if (value.owner
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
	const auto urgentWaiters = urgentWaitersLocked(endpointKey, state);
	auto foregroundDemand = false;
	for (const auto &key : schedule->second.order) {
		const auto i = _tickets.find(key);
		if (i != end(_tickets)
			&& WaitingForHandoff(i->second->lifecycle)) {
			const auto priority = priorityForLocked(
				*i->second,
				state,
				inputs.now);
			if (IsMainDemandPriority(*i->second, priority)) {
				foregroundDemand = true;
				break;
			}
		}
	}
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
		const auto liveAllowed = liveBudgetAllowsLocked(
			state,
			keptCounts,
			inputs.now,
			!foregroundDemand);
		const auto transferAllowed = !IsBackground(ticket->use)
			|| (MtProxy::EndpointTransferLaneCount(state) == 0);
		if (policy.admissionAllowed && liveAllowed && transferAllowed) {
			ticket->expansionProbe = state.liveBudget.learnedLimit
				&& (MtProxy::CurrentEndpointLiveLaneCount(state)
					+ MtProxy::TotalEndpointUseCount(keptCounts)
					>= state.liveBudget.learnedLimit);
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
		Actions &actions) {
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
	auto foregroundDemand = false;
	for (const auto &key : initialSchedule->second.order) {
		const auto i = _tickets.find(key);
		if (i != end(_tickets)
			&& WaitingForHandoff(i->second->lifecycle)) {
			const auto priority = priorityForLocked(
				*i->second,
				state,
				inputs.now);
			if (IsMainDemandPriority(*i->second, priority)) {
				foregroundDemand = true;
				break;
			}
		}
	}
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
		const auto urgentWaiters = urgentWaitersLocked(endpointKey, state);
		auto eligible = std::set<AdmissionTicketKey>();
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
			const auto liveAllowed = liveBudgetAllowsLocked(
				state,
				scheduled,
				inputs.now,
				!foregroundDemand);
			const auto transferAllowed = !IsBackground(ticket->use)
				|| (MtProxy::EndpointTransferLaneCount(state) == 0);
			if (baseEligibleLocked(
					*ticket,
					state,
					urgentWaiters,
					inputs.now)
				&& policy.admissionAllowed
				&& liveAllowed
				&& transferAllowed) {
				eligible.emplace(ticket->key);
			} else {
				ticket->blockedBy = TicketFailureReason(*ticket, state);
				ticket->retryAfter = policy.retryAfter;
				if (!foregroundDemand
					&& state.liveBudget.learnedLimit
					&& state.liveBudget.expansionProbeAfter > inputs.now
					&& MtProxy::CurrentEndpointLiveLaneCount(state)
						+ MtProxy::TotalEndpointUseCount(scheduled)
						>= state.liveBudget.learnedLimit) {
					ticket->retryAt = std::max(
						ticket->retryAt,
						state.liveBudget.expansionProbeAfter);
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
		selected->expansionProbe = state.liveBudget.learnedLimit
			&& (MtProxy::CurrentEndpointLiveLaneCount(state)
				+ MtProxy::TotalEndpointUseCount(
					scheduledCountsLocked(endpointKey))
				>= state.liveBudget.learnedLimit);
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
			refreshTransferServiceLocked(endpointKey, state->second);
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
	refreshTransferServiceLocked(endpointKey, state);
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
	requestLanePreemptionLocked(endpointKey, state, inputs, actions);
	assignReservationsLocked(endpointKey, state, inputs, actions);
	grantDueLocked(endpointKey, inputs.now, actions);
}

void EndpointAdmissionArbiter::Private::updateWakeLocked(
		const DrainInputs &inputs,
		Actions &actions) {
	if (_wakeArmed
		&& _wakeAt
		&& _wakeAt <= inputs.now
		&& runtimeLiveLocked(_wakeDriver)) {
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
		const auto preemptionAt = (lane.preemption
			&& !lane.preemption->claimed)
			? lane.preemption->deadlineAt
			: crl::time();
		const auto resumeAt = lane.resuming
			? lane.resuming->commandDeadlineAt
			: crl::time();
		for (const auto boundary : { preemptionAt, resumeAt }) {
			considerBoundary(boundary);
		}
		for (const auto &suspended : lane.suspended) {
			if (suspended.demanded
				|| (suspended.use == MtProxy::EndpointUse::Main
					&& suspended.successorTicketKey.ticketId)) {
				considerBoundary(suspended.resumeAfter);
			}
		}
	}
	for (const auto &entry : _storage.states) {
		const auto &state = entry.second;
		for (const auto &attempt : state.attemptStarts) {
			considerBoundary(attempt.second.transferServiceUntil);
		}
		for (const auto &lane : state.liveLanes) {
			considerBoundary(lane.second.transferServiceUntil);
		}
	}
	if (!wakeAt) {
		if (_wakeArmed) {
			++_wakeToken;
		}
		_wakeArmed = false;
		_wakeDriver = 0;
		_wakeAt = 0;
		return;
	}
	auto driver = _wakeDriver;
	if (!runtimeLiveLocked(driver)) {
		driver = 0;
		for (const auto &entry : _runtimes) {
			const auto runtimeId = entry.first;
			if (runtimeLiveLocked(runtimeId)) {
				driver = runtimeId;
				break;
			}
		}
	}
	if (!driver) {
		if (_wakeArmed) {
			++_wakeToken;
		}
		_wakeArmed = false;
		_wakeDriver = 0;
		_wakeAt = 0;
		return;
	}
	if (_wakeArmed && _wakeDriver == driver && _wakeAt == wakeAt) {
		return;
	}
	const auto token = ++_wakeToken;
	_wakeArmed = true;
	_wakeDriver = driver;
	_wakeAt = wakeAt;
	const auto dispatch = _runtimes.find(driver)->second;
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
	auto retired = std::shared_ptr<const EndpointAdmissionRuntimeDispatch>();
	{
		QMutexLocker lock(&_storage.mutex);
		if (!_storage.runtimes.contains(runtimeId)) {
			return;
		}
		const auto i = _runtimes.find(runtimeId);
		if (i == end(_runtimes)) {
			_runtimes.emplace(runtimeId, bound);
		} else {
			InvalidateRuntimeDispatch(i->second);
			retired = std::move(i->second);
			i->second = bound;
		}
	}
	retired.reset();
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
			if (i->second.preemption
				&& i->second.preemption->victim.runtimeId == runtimeId) {
				const auto state = _storage.states.find(i->first);
				if (state != end(_storage.states)) {
					clearLanePreemptionLocked(
						i->first,
						state->second,
						i->second.preemption->victim);
				} else {
					i->second.preemption.reset();
				}
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
		++_wakeToken;
		_wakeArmed = false;
		_wakeDriver = 0;
		_wakeAt = 0;
		for (const auto &entry : _endpoints) {
			affected.emplace(entry.first);
		}
	}
	actions.run();
	for (const auto &endpointKey : affected) {
		drainEndpoint(endpointKey);
	}
}

bool EndpointAdmissionArbiter::Private::enqueue(
		std::weak_ptr<ProxyEndpointContext> context,
		EndpointAdmissionRequest request) {
	if (!request.key.runtimeId
		|| !request.key.ticketId
		|| !request.owner
		|| !request.ownerDestroyed
		|| !request.grant) {
		return false;
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
	ticket->enqueuedAt = inputs.now;
	ticket->notBeforeAt = inputs.now
		+ std::max(crl::time(), request.notBefore);
	auto actions = Actions();
	auto accepted = false;
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
			ticket->sequence = ++_lastSequence;
			auto &schedule = _endpoints[ticket->endpointKey];
			schedule.order.push_back(key);
			auto &stored = *_tickets.emplace(key, std::move(ticket)).first->second;
			postStatusLocked(stored, actions);
			drainEndpointLocked(stored.endpointKey, inputs, actions);
			updateWakeLocked(inputs, actions);
			accepted = true;
		}
	}
	if (!accepted) {
		QObject::disconnect(ownerDestroyed);
	}
	actions.run();
	return accepted;
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
				clearLanePreemptionLocked(endpointKey, state, identity);
				static_cast<void>(MtProxy::RetireRelayProof(
					state,
					identity));
				const auto attempt = state.attemptStarts.find(
					identity.attemptId);
				if (attempt != end(state.attemptStarts)
					&& attempt->second.runtimeId == identity.runtimeId
					&& attempt->second.proxyGeneration
						== identity.proxyGeneration) {
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
				clearLanePreemptionLocked(
					endpointKey,
					state,
					lane->second.preemption->victim);
			}
			MtProxy::ApplyRuntimeProxyGeneration(
				state,
				runtimeId,
				proxyGeneration);
			const auto currentLane = _laneSchedules.find(endpointKey);
			if (currentLane != end(_laneSchedules)) {
				auto &suspended = currentLane->second.suspended;
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
	refreshTransferServiceLocked(endpointKey, state->second);
	auto &preemption = *lane->second.preemption;
	const auto beneficiary = _tickets.find(preemption.beneficiary);
	auto victim = static_cast<const MtProxy::EndpointAttemptState*>(nullptr);
	const auto opening = state->second.attemptStarts.find(attemptId);
	if (opening != end(state->second.attemptStarts)
		&& opening->second.runtimeId == runtimeId
		&& opening->second.proxyGeneration == proxyGeneration) {
		victim = &opening->second;
	} else {
		const auto live = state->second.liveLanes.find(identity);
		if (live != end(state->second.liveLanes)) {
			victim = &live->second;
		}
	}
	const auto priority = (beneficiary != end(_tickets))
		? priorityForLocked(*beneficiary->second, state->second, inputs.now)
		: PriorityClass::Count;
	const auto verdict = (beneficiary != end(_tickets))
		? TicketVerdict(*beneficiary->second, state->second)
		: nullptr;
	const auto boundary = (beneficiary != end(_tickets))
		? std::max({
			state->second.opening.bootstrap.retryUntil,
			verdict ? verdict->retryUntil : crl::time(),
			state->second.nextHandshakeAt,
		})
		: crl::time();
	const auto needsMainContinuity = beneficiary != end(_tickets)
		&& priority == PriorityClass::ForegroundTransfer
		&& victim
		&& victim->use == MtProxy::EndpointUse::Main
		&& identity.runtimeId == beneficiary->second->key.runtimeId
		&& identity.proxyGeneration == beneficiary->second->proxyGeneration;
	const auto relayProof = state->second.relayProofs.find(identity);
	if (preemption.token != token
		|| preemption.victim != identity
		|| preemption.claimed
		|| !preemption.owner
		|| preemption.deadlineAt <= inputs.now
		|| beneficiary == end(_tickets)
		|| !WaitingForHandoff(beneficiary->second->lifecycle)
		|| !ticketCurrentLocked(*beneficiary->second, state->second)
		|| !IsLanePreemptionPriority(*beneficiary->second, priority)
		|| boundary > inputs.now
		|| !baseEligibleLocked(
			*beneficiary->second,
			state->second,
			urgentWaitersLocked(endpointKey, state->second),
			inputs.now,
			true)
		|| !victim
		|| !victim->preempting
		|| !priorityConflictLocked(
			*beneficiary->second,
			state->second,
			identity.runtimeId,
			identity.proxyGeneration,
			victim->ticketKey,
			victim->use,
			victim->transferServiceUntil,
			inputs)
		|| (needsMainContinuity
			&& relayProof == end(state->second.relayProofs))
		|| !runtimeLiveLocked(runtimeId)) {
		return false;
	}
	preemption.mainContinuityProof = needsMainContinuity
		? MtProxy::CurrentMainRelayProof(
			state->second,
			{
				.runtimeId = identity.runtimeId,
				.proxyGeneration = identity.proxyGeneration,
			})
		: MtProxy::MainRelayProofView();
	preemption.claimed = true;
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
		const auto identity = MtProxy::RelayProofIdentity{
			.runtimeId = runtimeId,
			.proxyGeneration = proxyGeneration,
			.attemptId = attemptId,
		};
		if (lane->second.preemption
			&& lane->second.preemption->token == token
			&& lane->second.preemption->victim == identity
			&& (IsBackground(lane->second.preemption->victimUse)
				|| lane->second.preemption->victimUse
					== MtProxy::EndpointUse::Main)) {
			lane->second.preemption->demanded = true;
			changed = true;
		} else {
			const auto suspended = ranges::find_if(
				lane->second.suspended,
				[&](const SuspendedLane &entry) {
					return entry.token == token
						&& entry.identity == identity
						&& (IsBackground(entry.use)
							|| entry.use == MtProxy::EndpointUse::Main);
				});
			if (suspended != end(lane->second.suspended)) {
				suspended->demanded = true;
				changed = true;
			} else if (lane->second.resuming
				&& lane->second.resuming->token == token
				&& lane->second.resuming->identity == identity
				&& (IsBackground(lane->second.resuming->use)
					|| lane->second.resuming->use
						== MtProxy::EndpointUse::Main)) {
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
		auto &preemption = *lane->second.preemption;
		const auto identity = MtProxy::RelayProofIdentity{
			.runtimeId = runtimeId,
			.proxyGeneration = proxyGeneration,
			.attemptId = attemptId,
		};
		if (preemption.token != token || preemption.victim != identity) {
			return;
		}
		auto &endpointState = state->second;
		if (result == MtProxy::EndpointLaneCommandResult::Applied
			&& preemption.claimed) {
			static_cast<void>(MtProxy::RetireRelayProof(
				endpointState,
				identity));
			endpointState.attemptStarts.erase(attemptId);
			endpointState.liveLanes.erase(identity);
			MtProxy::SynchronizeEndpointAdmissionAggregate(endpointState);
			const auto beneficiary = _tickets.find(preemption.beneficiary);
			const auto beneficiaryPriority = beneficiary != end(_tickets)
				? priorityForLocked(
					*beneficiary->second,
					endpointState,
					inputs.now)
				: PriorityClass::Count;
			const auto protectedHandoff = beneficiary != end(_tickets)
				&& IsLanePreemptionPriority(
					*beneficiary->second,
					beneficiaryPriority);
			lane->second.handoffBeneficiary = protectedHandoff
				? std::optional<AdmissionTicketKey>(beneficiary->second->key)
				: std::nullopt;
			lane->second.suspended.push_back({
				.token = token,
				.identity = identity,
				.ticketKey = preemption.victimTicketKey,
				.use = preemption.victimUse,
				.owner = preemption.owner,
				.ownerDestroyed = preemption.ownerDestroyed,
				.laneControl = preemption.laneControl,
				.suspendedAt = inputs.now,
				.resumeAfter = (protectedHandoff
						|| IsBackground(preemption.victimUse))
					? inputs.now + kTransferServiceQuantum
					: crl::time(),
				.successorTicketKey = protectedHandoff
					? beneficiary->second->key
					: AdmissionTicketKey(),
				.foregroundRuntimeIdAtSuspension
					= _storage.foregroundRuntimeId,
				.mainContinuityProof = preemption.mainContinuityProof,
				.demanded = preemption.demanded,
			});
			if (beneficiary != end(_tickets)) {
				MtProxy::RemoveEndpointExpansionFailure(
					endpointState,
					{
						.runtimeId = beneficiary->second->key.runtimeId,
						.proxyGeneration
							= beneficiary->second->proxyGeneration,
					},
					beneficiary->second->use);
			}
		} else if (delivered
			&& result == MtProxy::EndpointLaneCommandResult::NotApplicable) {
			static_cast<void>(MtProxy::RetireRelayProof(
				endpointState,
				identity));
			endpointState.attemptStarts.erase(attemptId);
			endpointState.liveLanes.erase(identity);
			MtProxy::SynchronizeEndpointAdmissionAggregate(endpointState);
			QObject::disconnect(preemption.ownerDestroyed);
		} else {
			const auto proof = endpointState.relayProofs.find(identity);
			if (proof != end(endpointState.relayProofs)) {
				proof->second.preempting = false;
			}
			const auto attempt = endpointState.attemptStarts.find(attemptId);
			if (attempt != end(endpointState.attemptStarts)) {
				attempt->second.preempting = false;
			}
			const auto liveLane = endpointState.liveLanes.find(identity);
			if (liveLane != end(endpointState.liveLanes)) {
				liveLane->second.preempting = false;
			}
			if (attempt == end(endpointState.attemptStarts)
				&& liveLane == end(endpointState.liveLanes)) {
				QObject::disconnect(preemption.ownerDestroyed);
			}
		}
		lane->second.preemption.reset();
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
			|| resuming.commandDeadlineAt != deadlineAt) {
			return;
		}
		auto value = std::move(*lane->second.resuming);
		lane->second.resuming.reset();
		const auto noDemand = delivered
			&& result == MtProxy::EndpointLaneCommandResult::NoDemand;
		const auto retry = !delivered
			|| result == MtProxy::EndpointLaneCommandResult::Retry;
		const auto keepSuspended = (retry || noDemand)
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
		if (!_wakeArmed || token != _wakeToken) {
			return;
		}
		_wakeArmed = false;
		_wakeDriver = 0;
		_wakeAt = 0;
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
		auto foregroundDemand = false;
		const auto schedule = _endpoints.find(endpointKey);
		if (schedule != end(_endpoints) && state != end(_storage.states)) {
			for (const auto &candidateKey : schedule->second.order) {
				const auto candidate = _tickets.find(candidateKey);
				if (candidate != end(_tickets)
					&& candidateKey != key
					&& WaitingForHandoff(candidate->second->lifecycle)) {
					const auto priority = priorityForLocked(
						*candidate->second,
						state->second,
						inputs.now);
					if (IsMainDemandPriority(
							*candidate->second,
							priority)) {
						foregroundDemand = true;
						break;
					}
				}
			}
		}
		auto liveLaneCount = 0;
		auto liveLimit = 0;
		auto expansionProbeAllowed = false;
		auto transferAvailable = unscoped || !IsBackground(ticket.use);
		auto finalEligible = unscoped;
		if (!unscoped && state != end(_storage.states) && current) {
			auto scheduled = scheduledCountsLocked(endpointKey);
			scheduled = MtProxy::ReleaseEndpointAdmission(
				scheduled,
				ticket.use);
			const auto urgentWaiters = urgentWaitersLocked(
				endpointKey,
				state->second);
			const auto policy = policyLocked(
				ticket,
				state->second,
				activeCountsLocked(state->second),
				scheduled,
				urgentWaiters,
				inputs);
			const auto liveAllowed = liveBudgetAllowsLocked(
				state->second,
				scheduled,
				inputs.now,
				ticket.expansionProbe && !foregroundDemand);
			transferAvailable = !IsBackground(ticket.use)
				|| (MtProxy::EndpointTransferLaneCount(state->second) == 0);
			finalEligible = baseEligibleLocked(
				ticket,
				state->second,
				urgentWaiters,
				inputs.now)
				&& policy.admissionAllowed
				&& liveAllowed
				&& transferAvailable;
			liveLaneCount = MtProxy::CurrentEndpointLiveLaneCount(
				state->second);
			liveLimit = state->second.liveBudget.learnedLimit;
			expansionProbeAllowed = ticket.expansionProbe
				&& liveLimit
				&& liveLaneCount == liveLimit
				&& !foregroundDemand
				&& state->second.liveBudget.expansionProbeAfter
				&& state->second.liveBudget.expansionProbeAfter <= inputs.now;
		}
		if (!context
			|| !ticket.owner
			|| !runtimeLiveLocked(key.runtimeId)
			|| !traceCurrent
			|| !current) {
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
		} else if (!transferAvailable
			|| (liveLimit
			&& liveLaneCount >= liveLimit
			&& !expansionProbeAllowed)) {
			demoteTicketLocked(ticket, actions);
			drainEndpointLocked(endpointKey, inputs, actions);
			updateWakeLocked(inputs, actions);
		} else {
			if (expansionProbeAllowed) {
				state->second.liveBudget.expansionProbeAfter
					= inputs.now + kExpansionProbeQuietWindow;
			}
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
				} else {
					if (!unscoped) {
						const auto lane = state->second.attemptStarts.find(
							admission->attemptId);
						Assert(lane != end(state->second.attemptStarts));
						lane->second.owner = ticket.owner;
						lane->second.ownerDestroyed
							= ticket.ownerDestroyed;
						lane->second.laneControl = ticket.laneControl;
						if (IsBackground(ticket.use)) {
							lane->second.transferServiceUntil
								= inputs.now + kTransferOpeningGrace;
							const auto laneSchedule = _laneSchedules.find(
								ticket.endpointKey);
							if (laneSchedule != end(_laneSchedules)) {
								for (auto &entry
										: laneSchedule->second.suspended) {
									if (entry.successorTicketKey == key) {
										entry.resumeAfter = lane->second
											.transferServiceUntil;
									}
								}
							}
						}
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

bool EndpointAdmissionArbiter::enqueue(
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
