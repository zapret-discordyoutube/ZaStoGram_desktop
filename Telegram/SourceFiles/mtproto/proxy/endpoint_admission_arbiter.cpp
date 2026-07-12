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

enum class PriorityClass {
	UrgentMain,
	OrdinaryMain,
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

struct FairnessState {
	std::array<ProxyRuntimeId, int(PriorityClass::Count)> lastRuntime = {};
	std::map<ProxyRuntimeId, MtProxy::EndpointUse> nextBackground;
};

struct EndpointSchedule {
	std::deque<AdmissionTicketKey> order;
	FairnessState fairness;
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
	QObject::disconnect(ticket->ownerDestroyed);
	if (ticket->owner
		&& ticket->callbacks
		&& ticket->callbacks->grant) {
		ticket->callbacks->grant(std::move(grant));
	} else if (const auto strong = context.lock()) {
		strong->finishTrace(grant.attempt.traceId);
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
	void cancelBeforeGeneration(
		ProxyRuntimeId runtimeId,
		uint64 proxyGeneration);
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
	[[nodiscard]] MtProxy::EndpointConcurrencyPolicy policyLocked(
		const Ticket &ticket,
		const MtProxy::EndpointState &state,
		const MtProxy::EndpointUseCounts &active,
		const MtProxy::EndpointUseCounts &scheduled,
		int urgentWaiters,
		const DrainInputs &inputs) const;
	[[nodiscard]] bool baseEligibleLocked(
		const Ticket &ticket,
		const MtProxy::EndpointState &state,
		int urgentWaiters,
		crl::time now) const;
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
	std::map<
		ProxyRuntimeId,
		std::shared_ptr<const EndpointAdmissionRuntimeDispatch>> _runtimes;
	std::weak_ptr<ProxyEndpointContext> _context;
	std::atomic<uint64> _lastRevision = 0;
	uint64 _lastSequence = 0;
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
	return runtimeLiveLocked(ticket.key.runtimeId)
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
	auto result = (ticket.use == MtProxy::EndpointUse::Main)
		? (MtProxy::HasCurrentMainRelayProof(state, {
			.runtimeId = ticket.key.runtimeId,
			.proxyGeneration = ticket.proxyGeneration,
		})
			? PriorityClass::OrdinaryMain
			: PriorityClass::UrgentMain)
		: (ticket.use == MtProxy::EndpointUse::ProxyCheck)
		? PriorityClass::ProxyCheck
		: PriorityClass::Background;
	if (result == PriorityClass::UrgentMain
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
	auto result = static_cast<Ticket*>(nullptr);
	for (const auto ticket : heads) {
		if (ticket->key.runtimeId != *runtime
			|| priorityForLocked(*ticket, state, now) != best) {
			continue;
		}
		if (!result
			|| ticket->enqueuedAt < result->enqueuedAt
			|| (ticket->enqueuedAt == result->enqueuedAt
				&& ticket->sequence < result->sequence)) {
			result = ticket;
			continue;
		}
		if (ticket->enqueuedAt != result->enqueuedAt
			|| !IsBackground(ticket->use)
			|| !IsBackground(result->use)
			|| ticket->use == result->use) {
			continue;
		}
		const auto desired = NextBackgroundUse(fairness, *runtime);
		if (ticket->use == desired) {
			result = ticket;
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
			&& i->second->lifecycle == ProxySchedulerLifecycle::Queued
			&& priorityForLocked(
				*i->second,
				state,
				i->second->enqueuedAt) == PriorityClass::UrgentMain) {
			++result;
		}
	}
	return result;
}

auto EndpointAdmissionArbiter::Private::policyLocked(
		const Ticket &ticket,
		const MtProxy::EndpointState &state,
		const MtProxy::EndpointUseCounts &active,
		const MtProxy::EndpointUseCounts &scheduled,
		int urgentWaiters,
		const DrainInputs &inputs) const
-> MtProxy::EndpointConcurrencyPolicy {
	return MtProxy::EvaluateEndpointAdmission({
		.active = active,
		.scheduled = scheduled,
		.use = ticket.use,
		.mainProof = MtProxy::CurrentMainRelayProof(state, {
			.runtimeId = ticket.key.runtimeId,
			.proxyGeneration = ticket.proxyGeneration,
		}).strength,
		.lastFailure = state.lastFailure,
		.urgentMainDemand = urgentWaiters,
		.retryUntil = state.terminalUntil,
		.nextHandshakeAt = state.nextHandshakeAt,
		.lastRelaySuccessAt = state.lastRelaySuccessAt,
		.now = inputs.now,
		.endpointRelayProven = state.relayProven,
		.healthy = state.healthy,
		.fastWarmup = inputs.fastWarmup(ticket.key.runtimeId),
	});
}

bool EndpointAdmissionArbiter::Private::baseEligibleLocked(
		const Ticket &ticket,
		const MtProxy::EndpointState &state,
		int urgentWaiters,
		crl::time now) const {
	if (!ticketCurrentLocked(ticket, state) || ticket.retryAt > now) {
		return false;
	}
	if (!IsBackground(ticket.use)) {
		return true;
	}
	return !urgentWaiters
		&& MtProxy::HasCurrentMainRelayProof(state, {
			.runtimeId = ticket.key.runtimeId,
			.proxyGeneration = ticket.proxyGeneration,
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
		if (policy.admissionAllowed) {
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
				state.terminalUntil,
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
			if (baseEligibleLocked(
					*ticket,
					state,
					urgentWaiters,
					inputs.now)
				&& policy.admissionAllowed) {
				eligible.emplace(ticket->key);
			} else {
				ticket->blockedBy = state.lastFailure;
				ticket->retryAfter = policy.retryAfter;
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
			schedule->second.fairness);
		if (!selected) {
			return;
		}
		selected->retryAt = 0;
		selected->reevaluateAt = 0;
		selected->blockedBy = MtProxy::FailureReason::None;
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
			schedule->second.fairness,
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
	purgeEndpointLocked(endpointKey, state, actions);
	if (!_endpoints.contains(endpointKey)) {
		return;
	}
	revalidateReservationsLocked(endpointKey, state, inputs, actions);
	assignReservationsLocked(endpointKey, state, inputs, actions);
	grantDueLocked(endpointKey, inputs.now, actions);
}

void EndpointAdmissionArbiter::Private::updateWakeLocked(
		const DrainInputs &inputs,
		Actions &actions) {
	auto wakeAt = crl::time();
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
		if (boundary > inputs.now
			&& (!wakeAt || boundary < wakeAt)) {
			wakeAt = boundary;
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
					i = state.attemptStarts.erase(i);
				} else {
					++i;
				}
			}
			MtProxy::SynchronizeEndpointAdmissionAggregate(state);
			MtProxy::RemoveRelayProofsForRuntime(state, runtimeId);
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
		const auto stale = state != end(_storage.states)
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
			&& !stale) {
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
		auto cancelled = std::vector<AdmissionTicketKey>();
		for (auto &[endpointKey, state] : _storage.states) {
			const auto current = state.generations.find(runtimeId);
			const auto changes = (current == end(state.generations))
				|| (proxyGeneration > current->second);
			if (!changes) {
				continue;
			}
			MtProxy::ApplyRuntimeProxyGeneration(
				state,
				runtimeId,
				proxyGeneration);
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
		auto endpoints = std::vector<QString>();
		endpoints.reserve(_endpoints.size());
		for (const auto &entry : _endpoints) {
			endpoints.push_back(entry.first);
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
	const auto context = _context.lock();
	{
		QMutexLocker lock(&_storage.mutex);
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
		if (!context
			|| !ticket.owner
			|| !runtimeLiveLocked(key.runtimeId)
			|| !traceCurrent
			|| !current) {
			cancelTicketLocked(key, revision, actions);
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
				} else {
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

void EndpointAdmissionArbiter::cancelBeforeGeneration(
		ProxyRuntimeId runtimeId,
		uint64 proxyGeneration) {
	_private->cancelBeforeGeneration(runtimeId, proxyGeneration);
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
