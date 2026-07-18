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
constexpr auto kPressureWindow = crl::time(12 * 1000);
constexpr auto kRecoveryOpenSpacing = crl::time(6 * 1000);
constexpr auto kOpenDelays = std::array{
	crl::time(15 * 1000),
	crl::time(30 * 1000),
	crl::time(60 * 1000),
	crl::time(120 * 1000),
};

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

enum class TicketDelivery {
	Status,
	Grant,
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
	std::shared_ptr<TicketCallbacks> callbacks;
	ProxySchedulerLifecycle lifecycle = ProxySchedulerLifecycle::None;
	crl::time enqueuedAt = 0;
	crl::time notBeforeAt = 0;
	crl::time scheduledOpenAt = 0;
	crl::time nextOpenAt = 0;
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
};

struct DrainInputs {
	std::map<ProxyRuntimeId, RuntimeInput> runtimes;
	crl::time now = 0;

	[[nodiscard]] crl::time takeJitter(ProxyRuntimeId runtimeId);
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
	std::vector<QMetaObject::Connection> ownerConnections;
	std::weak_ptr<ProxyEndpointContext> context;
	std::vector<std::pair<
		MtProxy::EndpointId,
		RuntimeGenerationKey>> invalidations;

	void run();
};

void DeferEndpointCleanup(
		Actions &actions,
		MtProxy::EndpointDeferredCleanup cleanup) {
	for (auto &connection : cleanup.ownerConnections) {
		actions.ownerConnections.push_back(std::move(connection));
	}
}

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

[[nodiscard]] MtProxy::EndpointOpeningAttemptKey AttemptKeyFrom(
		const ProxyConnectionAttempt &attempt) {
	return {
		.runtimeId = attempt.runtimeId,
		.traceId = attempt.traceId,
		.ticketId = attempt.ticketId,
		.proxyGeneration = attempt.proxyGeneration,
		.proxyEpoch = attempt.proxyEpoch,
		.successEpoch = attempt.successEpoch,
		.attemptId = attempt.attemptId,
		.use = attempt.use,
		.ticketKey = attempt.ticketKey,
	};
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
			strong->endpointAdmissionArbiter().openingEvent(
				MtProxy::Cancelled{
					.identity = {
						.flow = {
							.endpoint = grant.endpoint.canonical,
							.runtimeId = grant.attempt.runtimeId,
							.proxyGeneration
								= grant.attempt.proxyGeneration,
							.use = grant.attempt.use,
						},
						.owner = AttemptKeyFrom(grant.attempt),
					},
				});
		}
		grant.admission.lease.release();
	}
}

void Actions::run() {
	for (const auto &connection : ownerConnections) {
		QObject::disconnect(connection);
	}
	ownerConnections.clear();
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

[[nodiscard]] bool AttemptIdentityConsistent(
		const MtProxy::EndpointOpeningAttemptIdentity &identity) {
	const auto &attempt = identity.key;
	return !MtProxy::EndpointEmpty(identity.flow.endpoint)
		&& identity.flow.runtimeId
		&& identity.flow.runtimeId == attempt.runtimeId
		&& identity.flow.proxyGeneration == attempt.proxyGeneration
		&& identity.flow.use == attempt.use
		&& attempt.attemptId
		&& attempt.ticketKey.runtimeId == attempt.runtimeId
		&& attempt.ticketKey.ticketId;
}

[[nodiscard]] bool OpeningIdentityMatches(
		const MtProxy::EndpointOpeningIdentity &a,
		const MtProxy::EndpointOpeningIdentity &b) {
	return a == b;
}

[[nodiscard]] bool AttemptIdentityMatches(
		const MtProxy::EndpointOpeningAttemptIdentity &a,
		const MtProxy::EndpointOpeningAttemptIdentity &b) {
	return a == b;
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
	void drainEndpoint(const QString &endpointKey);
	void openingEvent(MtProxy::EndpointOpeningEvent event);
	void requestImmediateScout(
		const MtProxy::CanonicalProxyEndpoint &endpoint,
		RuntimeGenerationKey requester);
	void composeEndpointViewLocked(
		const MtProxy::EndpointId &endpoint,
		RuntimeGenerationKey runtimeGeneration,
		MtProxy::ProxyEndpointView &view) const;
	void wake(uint64 token);
	void deliverStatus(
		AdmissionTicketKey key,
		uint64 revision,
		uint64 transition,
		ProxySchedulerLifecycle lifecycle,
		const std::shared_ptr<std::atomic<bool>> &registrationLive);
	void deliverGrant(
		AdmissionTicketKey key,
		uint64 revision,
		uint64 transition,
		ProxySchedulerLifecycle lifecycle,
		const std::shared_ptr<std::atomic<bool>> &registrationLive);
	void deliveryMissing(
		AdmissionTicketKey key,
		uint64 revision,
		uint64 transition,
		ProxySchedulerLifecycle lifecycle,
		const std::shared_ptr<std::atomic<bool>> &registrationLive,
		TicketDelivery delivery);

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
	[[nodiscard]] bool baseEligibleLocked(
		const Ticket &ticket,
		const MtProxy::EndpointState &state) const;
	[[nodiscard]] MtProxy::EndpointOpeningIdentity ticketIdentityLocked(
		const Ticket &ticket) const;
	[[nodiscard]] MtProxy::OpeningAdmissionDecision
	openingAdmissionDecisionLocked(
		const Ticket &ticket,
		const MtProxy::EndpointState &state,
		crl::time now) const;
	[[nodiscard]] int findPermitLocked(
		const MtProxy::EndpointOpenGateState &gate,
		const MtProxy::EndpointOpeningIdentity &identity) const;
	[[nodiscard]] int freePermitLocked(
		const MtProxy::EndpointOpenGateState &gate) const;
	[[nodiscard]] uint64 assignPermitLocked(
		MtProxy::EndpointOpenGateState &gate,
		const MtProxy::EndpointOpeningIdentity &identity,
		ProxySchedulerLifecycle lifecycle,
		uint64 reservationId);
	void retireOwnerLocked(
		MtProxy::EndpointOpenGateState &gate,
		const MtProxy::EndpointOpeningIdentity &identity);
	void retireAttemptsLocked(
		Fn<bool(const MtProxy::EndpointOpeningAttemptIdentity&)> matches);
	void retireScoutRequestsLocked(
		Fn<bool(const MtProxy::EndpointImmediateScoutRequest&)> matches);
	void retireMissingAttemptsLocked(
		const QString &endpointKey,
		const MtProxy::EndpointState &state);
	void advanceGateLocked(const QString &endpointKey, crl::time now);
	void openGateLocked(
		const QString &endpointKey,
		crl::time now,
		bool advanceRung,
		Actions &actions);
	void closeGateLocked(MtProxy::EndpointOpenGateState &gate);
	void tripGateLocked(
		const QString &endpointKey,
		crl::time now,
		Actions &actions);
	[[nodiscard]] bool transferPermitLocked(
		const QString &endpointKey,
		const MtProxy::EndpointOpeningIdentity &from,
		const MtProxy::EndpointOpeningAttemptIdentity &to);
	[[nodiscard]] bool attemptKnownLocked(
		const MtProxy::EndpointOpenGateState &gate,
		const MtProxy::EndpointOpeningAttemptIdentity &identity) const;
	[[nodiscard]] bool attemptTerminalLocked(
		const MtProxy::EndpointOpenGateState &gate,
		const MtProxy::EndpointOpeningAttemptIdentity &identity) const;
	void retireAttemptTerminalLocked(
		MtProxy::EndpointOpenGateState &gate,
		const MtProxy::EndpointOpeningAttemptIdentity &identity);
	void applyOpeningEventLocked(
		const MtProxy::TransportReady &event,
		crl::time now,
		Actions &actions);
	void applyOpeningEventLocked(
		const MtProxy::RelayReady &event,
		crl::time now,
		Actions &actions);
	void applyOpeningEventLocked(
		const MtProxy::PressureFailure &event,
		crl::time now,
		Actions &actions);
	void applyOpeningEventLocked(
		const MtProxy::Cancelled &event,
		crl::time now,
		Actions &actions);
	void invalidateTicketLocked(Ticket &ticket, Actions &actions);
	void postStatusLocked(Ticket &ticket, Actions &actions);
	void postGenerationCancelledStatusLocked(
		const Ticket &ticket,
		Actions &actions);
	void postGrantLocked(Ticket &ticket, Actions &actions);
	[[nodiscard]] bool deliveryRegistrationCurrentLocked(
		Ticket &ticket,
		const std::shared_ptr<std::atomic<bool>> &registrationLive,
		TicketDelivery delivery,
		DrainInputs &inputs,
		Actions &actions);
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
	[[nodiscard]] bool wakeOwnerLiveLocked() const;
	void clearWakeLocked(bool invalidateToken);
	void updateWakeLocked(const DrainInputs &inputs, Actions &actions);

	MtProxy::EndpointContextStorage &_storage;
	std::map<AdmissionTicketKey, std::unique_ptr<Ticket>> _tickets;
	std::map<QString, EndpointSchedule> _endpoints;
	std::map<QString, MtProxy::EndpointOpenGateState> _gates;
	std::map<
		ProxyRuntimeId,
		std::shared_ptr<const EndpointAdmissionRuntimeDispatch>> _runtimes;
	std::weak_ptr<ProxyEndpointContext> _context;
	std::atomic<uint64> _lastRevision = 0;
	uint64 _lastSequence = 0;
	uint64 _wakeToken = 0;
	ProxyRuntimeId _wakeDriver = 0;
	crl::time _wakeAt = 0;
	QString _wakeEndpointKey;
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
			actions.removed.push_back(std::move(entry.second));
		}
		_tickets.clear();
		_endpoints.clear();
		_gates.clear();
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
	const auto schedule = _endpoints.find(MtProxy::EndpointKey(endpoint));
	if (schedule == end(_endpoints)) {
		return;
	}
	const auto rank = [](ProxySchedulerLifecycle lifecycle) {
		switch (lifecycle) {
		case ProxySchedulerLifecycle::Granted: return 0;
		case ProxySchedulerLifecycle::Scheduled: return 1;
		case ProxySchedulerLifecycle::Queued: return 2;
		case ProxySchedulerLifecycle::None:
		case ProxySchedulerLifecycle::HandedOff:
		case ProxySchedulerLifecycle::Cancelled: return 3;
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
	const auto recovery = MtProxy::ComposeMainRecoveryViewLocked(
		_storage,
		ticket.endpointKey,
		{
			.runtimeId = ticket.key.runtimeId,
			.proxyGeneration = ticket.proxyGeneration,
		});
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
	const auto hasMainProof = MtProxy::HasCurrentMainRelayProof(state, {
		.runtimeId = ticket.key.runtimeId,
		.proxyGeneration = ticket.proxyGeneration,
	});
	const auto ownsMainRecovery = ownsMainRecoveryLocked(ticket);
	auto result = PriorityClass::Background;
	if (ticket.use == MtProxy::EndpointUse::Main) {
		result = (foreground || ownsMainRecovery)
			? PriorityClass::ForegroundMain
			: hasMainProof
			? PriorityClass::OrdinaryMain
			: PriorityClass::UrgentMain;
	} else if (foreground
		&& IsBackground(ticket.use)
		&& hasMainProof) {
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
		for (const auto other : pool) {
			if (other->key.runtimeId == ticket->key.runtimeId
				&& other->use == ticket->use
				&& ((ownsMainRecoveryLocked(*other) && !ownsRecovery)
					|| (ownsMainRecoveryLocked(*other) == ownsRecovery
						&& other->sequence < ticket->sequence))) {
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

bool EndpointAdmissionArbiter::Private::baseEligibleLocked(
		const Ticket &ticket,
		const MtProxy::EndpointState &state) const {
	if (!ticketCurrentLocked(ticket, state)) {
		return false;
	}
	if (!IsBackground(ticket.use)) {
		return true;
	}
	auto urgentWaiters = false;
	for (const auto &[key, candidate] : _tickets) {
		if (key.runtimeId == ticket.key.runtimeId
			&& candidate->proxyGeneration == ticket.proxyGeneration
			&& candidate->use == MtProxy::EndpointUse::Main
			&& ownsMainRecoveryLocked(*candidate)) {
			urgentWaiters = true;
			break;
		}
	}
	return !urgentWaiters
		&& MtProxy::HasCurrentMainRelayProof(state, {
			.runtimeId = ticket.key.runtimeId,
			.proxyGeneration = ticket.proxyGeneration,
		});
}

MtProxy::EndpointOpeningIdentity
EndpointAdmissionArbiter::Private::ticketIdentityLocked(
		const Ticket &ticket) const {
	return {
		.flow = {
			.endpoint = ticket.endpoint.canonical,
			.runtimeId = ticket.key.runtimeId,
			.proxyGeneration = ticket.proxyGeneration,
			.use = ticket.use,
		},
		.owner = MtProxy::EndpointOpeningTicketOwner{
			.key = ticket.key,
			.revision = ticket.revision,
		},
	};
}

MtProxy::OpeningAdmissionDecision
EndpointAdmissionArbiter::Private::openingAdmissionDecisionLocked(
		const Ticket &ticket,
		const MtProxy::EndpointState &state,
		crl::time now) const {
	auto result = MtProxy::OpeningAdmissionDecision{
		.identity = ticketIdentityLocked(ticket),
		.lifecycle = ticket.lifecycle,
		.openAt = std::max(ticket.notBeforeAt, ticket.scheduledOpenAt),
		.retryAt = ticket.reevaluateAt,
		.blockedBy = ticket.blockedBy,
		.reservationId = ticket.reservationId,
	};
	if (MtProxy::EndpointEmpty(ticket.endpoint)) {
		result.allowed = baseEligibleLocked(ticket, state);
		return result;
	}
	const auto gate = _gates.find(ticket.endpointKey);
	if (gate == end(_gates)) {
		result.stage = MtProxy::EndpointOpenGateStage::Closed;
		result.allowed = ticket.lifecycle
				== ProxySchedulerLifecycle::Queued
			&& baseEligibleLocked(ticket, state);
		return result;
	}
	const auto &current = gate->second;
	result.stage = current.stage;
	result.gateRevision = current.revision;
	const auto permitIndex = findPermitLocked(current, result.identity);
	const auto hasPermit = permitIndex >= 0;
	if (hasPermit) {
		const auto &permit = *current.permits[permitIndex];
		result.permitIndex = permitIndex;
		result.permitId = permit.id;
		if (permit.reservationId != ticket.reservationId
			|| permit.lifecycle != ticket.lifecycle) {
			return result;
		}
	}
	const auto queued = ticket.lifecycle == ProxySchedulerLifecycle::Queued;
	const auto planned = ticket.lifecycle
			== ProxySchedulerLifecycle::Scheduled
		|| ticket.lifecycle == ProxySchedulerLifecycle::Granted;
	if ((!queued && !planned)
		|| (queued && hasPermit)
		|| (planned && (!hasPermit || !ticket.reservationId))
		|| (planned && ticket.scheduledOpenAt < ticket.notBeforeAt)
		|| !baseEligibleLocked(ticket, state)) {
		return result;
	}
	const auto ownerMatches = current.stageOwner
		&& OpeningIdentityMatches(*current.stageOwner, result.identity);
	switch (current.stage) {
	case MtProxy::EndpointOpenGateStage::Closed:
		result.allowed = hasPermit || freePermitLocked(current) >= 0;
		break;
	case MtProxy::EndpointOpenGateStage::Open:
		result.retryAt = current.openDeadline;
		if (current.immediateScoutRequest) {
			const auto &request = *current.immediateScoutRequest;
			const auto generation = _storage.runtimeGenerations.find(
				request.requester.runtimeId);
			const auto requestLive = runtimeLiveLocked(
					request.requester.runtimeId)
				&& generation != end(_storage.runtimeGenerations)
				&& generation->second
					== request.requester.proxyGeneration;
			result.allowed = requestLive
				&& ticket.key.runtimeId == request.requester.runtimeId
				&& ticket.proxyGeneration
					== request.requester.proxyGeneration
				&& queued
				&& !current.stageOwner
				&& freePermitLocked(current) >= 0;
		}
		break;
	case MtProxy::EndpointOpenGateStage::HalfOpen:
		result.allowed = ownerMatches
			|| (!current.stageOwner
				&& (hasPermit || freePermitLocked(current) >= 0));
		break;
	case MtProxy::EndpointOpenGateStage::Recovering:
		result.retryAt = current.recoveryNextOpenAt;
		result.allowed = ownerMatches
			|| (!current.stageOwner
				&& now >= current.recoveryNextOpenAt
				&& (hasPermit || freePermitLocked(current) >= 0));
		break;
	}
	return result;
}

int EndpointAdmissionArbiter::Private::findPermitLocked(
		const MtProxy::EndpointOpenGateState &gate,
		const MtProxy::EndpointOpeningIdentity &identity) const {
	for (auto i = 0; i != int(gate.permits.size()); ++i) {
		if (gate.permits[i]
			&& OpeningIdentityMatches(gate.permits[i]->owner, identity)) {
			return i;
		}
	}
	return -1;
}

int EndpointAdmissionArbiter::Private::freePermitLocked(
		const MtProxy::EndpointOpenGateState &gate) const {
	for (auto i = 0; i != int(gate.permits.size()); ++i) {
		if (!gate.permits[i]) {
			return i;
		}
	}
	return -1;
}

uint64 EndpointAdmissionArbiter::Private::assignPermitLocked(
		MtProxy::EndpointOpenGateState &gate,
		const MtProxy::EndpointOpeningIdentity &identity,
		ProxySchedulerLifecycle lifecycle,
		uint64 reservationId) {
	const auto index = freePermitLocked(gate);
	if (index < 0) {
		return 0;
	}
	const auto id = ++gate.lastPermitId;
	gate.permits[index] = MtProxy::EndpointOpeningPermit{
		.id = id,
		.reservationId = reservationId,
		.owner = identity,
		.lifecycle = lifecycle,
	};
	++gate.revision;
	return id;
}

void EndpointAdmissionArbiter::Private::retireOwnerLocked(
		MtProxy::EndpointOpenGateState &gate,
		const MtProxy::EndpointOpeningIdentity &identity) {
	auto changed = false;
	const auto permit = findPermitLocked(gate, identity);
	if (permit >= 0) {
		gate.permits[permit].reset();
		changed = true;
	}
	if (gate.stageOwner
		&& OpeningIdentityMatches(*gate.stageOwner, identity)) {
		gate.stageOwner.reset();
		changed = true;
	}
	if (const auto attempt = std::get_if<
			MtProxy::EndpointOpeningAttemptKey>(&identity.owner)) {
		const auto exact = MtProxy::EndpointOpeningAttemptIdentity{
			.flow = identity.flow,
			.key = *attempt,
		};
		const auto removed = std::remove_if(
			begin(gate.proofPendingAttempts),
			end(gate.proofPendingAttempts),
			[&](const auto &value) {
				return AttemptIdentityMatches(value, exact);
			});
		if (removed != end(gate.proofPendingAttempts)) {
			gate.proofPendingAttempts.erase(
				removed,
				end(gate.proofPendingAttempts));
			changed = true;
		}
	}
	if (changed) {
		++gate.revision;
	}
}

void EndpointAdmissionArbiter::Private::retireAttemptsLocked(
		Fn<bool(const MtProxy::EndpointOpeningAttemptIdentity&)> matches) {
	for (auto &entry : _gates) {
		auto &gate = entry.second;
		auto identities = std::vector<MtProxy::EndpointOpeningAttemptIdentity>();
		for (const auto &permit : gate.permits) {
			if (!permit) {
				continue;
			}
			const auto owner = std::get_if<
				MtProxy::EndpointOpeningAttemptKey>(&permit->owner.owner);
			if (owner) {
				identities.push_back({
					.flow = permit->owner.flow,
					.key = *owner,
				});
			}
		}
		for (const auto &identity : gate.proofPendingAttempts) {
			identities.push_back(identity);
		}
		for (const auto &identity : identities) {
			if (matches(identity)) {
				retireOwnerLocked(gate, {
					.flow = identity.flow,
					.owner = identity.key,
				});
			}
		}
		const auto removed = std::remove_if(
			begin(gate.terminalAttempts),
			end(gate.terminalAttempts),
			[&](const auto &identity) {
				return matches(identity);
			});
		if (removed != end(gate.terminalAttempts)) {
			gate.terminalAttempts.erase(
				removed,
				end(gate.terminalAttempts));
			++gate.revision;
		}
	}
}

void EndpointAdmissionArbiter::Private::retireScoutRequestsLocked(
		Fn<bool(const MtProxy::EndpointImmediateScoutRequest&)> matches) {
	for (auto &entry : _gates) {
		auto &gate = entry.second;
		if (!gate.immediateScoutRequest
			|| !matches(*gate.immediateScoutRequest)) {
			continue;
		}
		gate.immediateScoutRequest.reset();
		++gate.revision;
	}
}

void EndpointAdmissionArbiter::Private::retireMissingAttemptsLocked(
		const QString &endpointKey,
		const MtProxy::EndpointState &state) {
	retireAttemptsLocked([&](
			const MtProxy::EndpointOpeningAttemptIdentity &identity) {
		if (MtProxy::EndpointKey(identity.flow.endpoint) != endpointKey) {
			return false;
		}
		const auto &attempt = identity.key;
		const auto opening = state.attemptStarts.find(attempt.attemptId);
		if (opening != end(state.attemptStarts)
			&& opening->second.runtimeId == attempt.runtimeId
			&& opening->second.proxyGeneration == attempt.proxyGeneration
			&& opening->second.ticketKey == attempt.ticketKey) {
			return false;
		}
		const auto proof = MtProxy::RelayProofIdentity{
			.runtimeId = attempt.runtimeId,
			.proxyGeneration = attempt.proxyGeneration,
			.attemptId = attempt.attemptId,
		};
		return !state.liveLanes.contains(proof)
			&& !state.relayProofs.contains(proof);
	});
}

void EndpointAdmissionArbiter::Private::advanceGateLocked(
		const QString &endpointKey,
		crl::time now) {
	const auto i = _gates.find(endpointKey);
	if (i == end(_gates)) {
		return;
	}
	auto &gate = i->second;
	if (gate.stage == MtProxy::EndpointOpenGateStage::Open
		&& !gate.stageOwner
		&& gate.openDeadline
		&& gate.openDeadline <= now) {
		gate.stage = MtProxy::EndpointOpenGateStage::HalfOpen;
		gate.openDeadline = 0;
		++gate.revision;
	}
}

void EndpointAdmissionArbiter::Private::openGateLocked(
		const QString &endpointKey,
		crl::time now,
		bool advanceRung,
		Actions &actions) {
	auto &gate = _gates[endpointKey];
	if (advanceRung) {
		gate.backoffRung = std::min(
			gate.backoffRung + 1,
			int(kOpenDelays.size()) - 1);
	}
	gate.stage = MtProxy::EndpointOpenGateStage::Open;
	gate.openDeadline = now + kOpenDelays[gate.backoffRung];
	gate.stageOwner.reset();
	gate.recoverySuccessCount = 0;
	gate.recoveryNextOpenAt = 0;
	++gate.revision;
	const auto schedule = _endpoints.find(endpointKey);
	if (schedule == end(_endpoints)) {
		return;
	}
	for (const auto &key : schedule->second.order) {
		const auto ticket = _tickets.find(key);
		if (ticket == end(_tickets)
			|| (ticket->second->lifecycle
					!= ProxySchedulerLifecycle::Scheduled
				&& ticket->second->lifecycle
					!= ProxySchedulerLifecycle::Granted)) {
			continue;
		}
		retireOwnerLocked(
			gate,
			ticketIdentityLocked(*ticket->second));
		ticket->second->revision = ++_lastRevision;
		demoteTicketLocked(*ticket->second, actions);
	}
}

void EndpointAdmissionArbiter::Private::closeGateLocked(
		MtProxy::EndpointOpenGateState &gate) {
	gate.stage = MtProxy::EndpointOpenGateStage::Closed;
	gate.pressureWindow.clear();
	gate.backoffRung = 0;
	gate.openDeadline = 0;
	gate.stageOwner.reset();
	gate.recoverySuccessCount = 0;
	gate.recoveryNextOpenAt = 0;
	gate.immediateScoutRequest.reset();
	++gate.revision;
}

void EndpointAdmissionArbiter::Private::tripGateLocked(
		const QString &endpointKey,
		crl::time now,
		Actions &actions) {
	openGateLocked(endpointKey, now, false, actions);
}

bool EndpointAdmissionArbiter::Private::transferPermitLocked(
		const QString &endpointKey,
		const MtProxy::EndpointOpeningIdentity &from,
		const MtProxy::EndpointOpeningAttemptIdentity &to) {
	const auto i = _gates.find(endpointKey);
	if (i == end(_gates)) {
		return false;
	}
	auto &gate = i->second;
	const auto permit = findPermitLocked(gate, from);
	if (permit < 0) {
		return false;
	}
	const auto owner = MtProxy::EndpointOpeningIdentity{
		.flow = to.flow,
		.owner = to.key,
	};
	gate.permits[permit]->owner = owner;
	gate.permits[permit]->lifecycle = ProxySchedulerLifecycle::HandedOff;
	if (gate.stageOwner
		&& OpeningIdentityMatches(*gate.stageOwner, from)) {
		gate.stageOwner = owner;
	}
	if (std::find_if(
			begin(gate.proofPendingAttempts),
			end(gate.proofPendingAttempts),
			[&](const auto &value) {
				return AttemptIdentityMatches(value, to);
			}) == end(gate.proofPendingAttempts)) {
		gate.proofPendingAttempts.push_back(to);
	}
	++gate.revision;
	return true;
}

bool EndpointAdmissionArbiter::Private::attemptKnownLocked(
		const MtProxy::EndpointOpenGateState &gate,
		const MtProxy::EndpointOpeningAttemptIdentity &identity) const {
	const auto owner = MtProxy::EndpointOpeningIdentity{
		.flow = identity.flow,
		.owner = identity.key,
	};
	return findPermitLocked(gate, owner) >= 0
		|| std::find_if(
			begin(gate.proofPendingAttempts),
			end(gate.proofPendingAttempts),
			[&](const auto &value) {
				return AttemptIdentityMatches(value, identity);
			})
			!= end(gate.proofPendingAttempts)
		|| (gate.stageOwner
			&& OpeningIdentityMatches(*gate.stageOwner, owner));
}

bool EndpointAdmissionArbiter::Private::attemptTerminalLocked(
		const MtProxy::EndpointOpenGateState &gate,
		const MtProxy::EndpointOpeningAttemptIdentity &identity) const {
	return std::find_if(
		begin(gate.terminalAttempts),
		end(gate.terminalAttempts),
		[&](const auto &value) {
			return AttemptIdentityMatches(value, identity);
		})
		!= end(gate.terminalAttempts);
}

void EndpointAdmissionArbiter::Private::retireAttemptTerminalLocked(
		MtProxy::EndpointOpenGateState &gate,
		const MtProxy::EndpointOpeningAttemptIdentity &identity) {
	retireOwnerLocked(gate, {
		.flow = identity.flow,
		.owner = identity.key,
	});
	if (!attemptTerminalLocked(gate, identity)) {
		gate.terminalAttempts.push_back(identity);
	}
}

void EndpointAdmissionArbiter::Private::applyOpeningEventLocked(
		const MtProxy::TransportReady &event,
		crl::time,
		Actions &) {
	if (!AttemptIdentityConsistent(event.identity)) {
		return;
	}
	const auto endpointKey = MtProxy::EndpointKey(event.identity.flow.endpoint);
	const auto i = _gates.find(endpointKey);
	if (i == end(_gates)
		|| attemptTerminalLocked(i->second, event.identity)
		|| !attemptKnownLocked(i->second, event.identity)) {
		return;
	}
	auto &gate = i->second;
	const auto owner = MtProxy::EndpointOpeningIdentity{
		.flow = event.identity.flow,
		.owner = event.identity.key,
	};
	const auto permit = findPermitLocked(gate, owner);
	if (permit >= 0) {
		gate.permits[permit].reset();
		++gate.revision;
	}
}

void EndpointAdmissionArbiter::Private::applyOpeningEventLocked(
		const MtProxy::RelayReady &event,
		crl::time now,
		Actions &) {
	if (!AttemptIdentityConsistent(event.identity)) {
		return;
	}
	const auto endpointKey = MtProxy::EndpointKey(event.identity.flow.endpoint);
	const auto i = _gates.find(endpointKey);
	if (i == end(_gates)
		|| attemptTerminalLocked(i->second, event.identity)
		|| !attemptKnownLocked(i->second, event.identity)) {
		return;
	}
	auto &gate = i->second;
	const auto owner = MtProxy::EndpointOpeningIdentity{
		.flow = event.identity.flow,
		.owner = event.identity.key,
	};
	const auto stage = gate.stage;
	const auto stageOwner = gate.stageOwner
		&& OpeningIdentityMatches(*gate.stageOwner, owner);
	retireAttemptTerminalLocked(gate, event.identity);
	if (!stageOwner) {
		return;
	}
	if (stage == MtProxy::EndpointOpenGateStage::HalfOpen) {
		gate.stage = MtProxy::EndpointOpenGateStage::Recovering;
		gate.recoverySuccessCount = 1;
		gate.recoveryNextOpenAt = now + kRecoveryOpenSpacing;
		++gate.revision;
	} else if (stage == MtProxy::EndpointOpenGateStage::Recovering) {
		++gate.recoverySuccessCount;
		if (gate.recoverySuccessCount >= 3) {
			closeGateLocked(gate);
		} else {
			gate.recoveryNextOpenAt = now + kRecoveryOpenSpacing;
			++gate.revision;
		}
	}
}

void EndpointAdmissionArbiter::Private::applyOpeningEventLocked(
		const MtProxy::PressureFailure &event,
		crl::time now,
		Actions &actions) {
	if (!AttemptIdentityConsistent(event.identity)) {
		return;
	}
	const auto endpointKey = MtProxy::EndpointKey(event.identity.flow.endpoint);
	const auto i = _gates.find(endpointKey);
	if (i == end(_gates)
		|| attemptTerminalLocked(i->second, event.identity)
		|| !attemptKnownLocked(i->second, event.identity)) {
		return;
	}
	auto &gate = i->second;
	const auto owner = MtProxy::EndpointOpeningIdentity{
		.flow = event.identity.flow,
		.owner = event.identity.key,
	};
	const auto stage = gate.stage;
	const auto stageOwner = gate.stageOwner
		&& OpeningIdentityMatches(*gate.stageOwner, owner);
	retireAttemptTerminalLocked(gate, event.identity);
	if ((stage == MtProxy::EndpointOpenGateStage::HalfOpen
			|| stage == MtProxy::EndpointOpenGateStage::Recovering)
		&& stageOwner) {
		openGateLocked(endpointKey, now, true, actions);
		return;
	}
	if (stage != MtProxy::EndpointOpenGateStage::Closed) {
		return;
	}
	const auto cutoff = now - kPressureWindow;
	while (!gate.pressureWindow.empty()
		&& gate.pressureWindow.front().observedAt < cutoff) {
		gate.pressureWindow.pop_front();
	}
	auto pressure = event;
	pressure.observedAt = now;
	gate.pressureWindow.push_back(std::move(pressure));
	auto flows = std::vector<MtProxy::EndpointOpeningFlowKey>();
	for (const auto &entry : gate.pressureWindow) {
		if (std::find(begin(flows), end(flows), entry.identity.flow)
			== end(flows)) {
			flows.push_back(entry.identity.flow);
		}
	}
	if (gate.pressureWindow.size() >= 3 && flows.size() >= 2) {
		tripGateLocked(endpointKey, now, actions);
	}
}

void EndpointAdmissionArbiter::Private::applyOpeningEventLocked(
		const MtProxy::Cancelled &event,
		crl::time,
		Actions &) {
	const auto endpointKey = MtProxy::EndpointKey(event.identity.flow.endpoint);
	const auto i = _gates.find(endpointKey);
	if (i == end(_gates)) {
		return;
	}
	auto &gate = i->second;
	if (const auto attempt = std::get_if<
			MtProxy::EndpointOpeningAttemptKey>(&event.identity.owner)) {
		const auto identity = MtProxy::EndpointOpeningAttemptIdentity{
			.flow = event.identity.flow,
			.key = *attempt,
		};
		if (!AttemptIdentityConsistent(identity)
			|| attemptTerminalLocked(gate, identity)
			|| !attemptKnownLocked(gate, identity)) {
			return;
		}
		retireAttemptTerminalLocked(gate, identity);
		return;
	}
	const auto ticket = std::get_if<
		MtProxy::EndpointOpeningTicketOwner>(&event.identity.owner);
	if (!ticket
		|| event.identity.flow.runtimeId != ticket->key.runtimeId
		|| !ticket->key.ticketId
		|| findPermitLocked(gate, event.identity) < 0) {
		return;
	}
	retireOwnerLocked(gate, event.identity);
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
	const auto registrationLive = runtime->second->registrationLive;
	actions.posts.push_back({
		.dispatch = runtime->second,
		.target = ticket.owner,
		.callback = [
			weak,
			key,
			revision,
			transition,
			lifecycle,
			registrationLive
		] {
			if (const auto context = weak.lock()) {
				context->endpointAdmissionArbiter().deliverStatus(
					key,
					revision,
					transition,
					lifecycle,
					registrationLive);
			}
		},
		.missing = [
			weak,
			key,
			revision,
			transition,
			lifecycle,
			registrationLive
		] {
			if (const auto context = weak.lock()) {
				context->endpointAdmissionArbiter().statusDeliveryMissing(
					key,
					revision,
					transition,
					lifecycle,
					registrationLive);
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
	const auto registrationLive = runtime->second->registrationLive;
	actions.posts.push_back({
		.dispatch = runtime->second,
		.target = ticket.owner,
		.callback = [
			weak,
			key,
			revision,
			transition,
			lifecycle,
			registrationLive
		] {
			if (const auto context = weak.lock()) {
				context->endpointAdmissionArbiter().deliverGrant(
					key,
					revision,
					transition,
					lifecycle,
					registrationLive);
			}
		},
		.missing = [
			weak,
			key,
			revision,
			transition,
			lifecycle,
			registrationLive
		] {
			if (const auto context = weak.lock()) {
				context->endpointAdmissionArbiter().grantDeliveryMissing(
					key,
					revision,
					transition,
					lifecycle,
					registrationLive);
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
	if (ticket.reservationId) {
		const auto gate = _gates.find(ticket.endpointKey);
		if (gate != end(_gates)) {
			gate->second.openings = MtProxy::CancelOpenSlot(
				gate->second.openings,
				ticket.reservationId).schedule;
		}
	}
	const auto gate = _gates.find(ticket.endpointKey);
	if (gate != end(_gates)) {
		retireOwnerLocked(gate->second, ticketIdentityLocked(ticket));
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
		const auto gate = _gates.find(ticket.endpointKey);
		if (gate != end(_gates)) {
			gate->second.openings = MtProxy::CancelOpenSlot(
				gate->second.openings,
				ticket.reservationId).schedule;
		}
	}
	const auto gate = _gates.find(ticket.endpointKey);
	if (gate != end(_gates)) {
		retireOwnerLocked(gate->second, ticketIdentityLocked(ticket));
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
	auto pool = std::vector<Ticket*>();
	for (const auto &key : schedule->second.order) {
		const auto i = _tickets.find(key);
		if (i == end(_tickets)
			|| (i->second->lifecycle != ProxySchedulerLifecycle::Scheduled
				&& i->second->lifecycle
					!= ProxySchedulerLifecycle::Granted)) {
			continue;
		}
		if (openingAdmissionDecisionLocked(
				*i->second,
				state,
				inputs.now).allowed) {
			pool.push_back(i->second.get());
		} else {
			demoteTicketLocked(*i->second, actions);
		}
	}
	auto ordered = orderLocked(
		std::move(pool),
		state,
		inputs.now,
		schedule->second.fairness);
	auto requests = std::vector<MtProxy::OpenSlotReflowRequest>();
	auto openTickets = std::vector<Ticket*>();
	auto &gate = _gates[endpointKey];
	for (const auto ticket : ordered) {
		if (!ticket->reservationId) {
			continue;
		}
		const auto plan = MtProxy::BuildAttemptPlan(
			ticket->admissionRequest,
			state.recipeLevel);
		ticket->spacing = std::max(
			kMinimumOpenSpacing,
			MtProxy::OpenConnectionSpacing(
				plan.stealth.connectionPattern));
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
	const auto reflow = MtProxy::ReflowOpenSlots(
		gate.openings,
		requests,
		inputs.now);
	if (!reflow.applied
		|| reflow.assignments.size() != openTickets.size()) {
		return;
	}
	gate.openings = reflow.schedule;
	++gate.revision;
	for (auto i = std::size_t(); i != reflow.assignments.size(); ++i) {
		auto &ticket = *openTickets[i];
		const auto changed = ticket.scheduledOpenAt
			!= reflow.assignments[i].openAt;
		ticket.scheduledOpenAt = reflow.assignments[i].openAt;
		ticket.nextOpenAt = reflow.assignments[i].nextOpenAt;
		ticket.retryAfter = std::max(
			crl::time(),
			reflow.assignments[i].openAt - inputs.now);
		if (changed) {
			if (ticket.lifecycle == ProxySchedulerLifecycle::Granted) {
				ticket.lifecycle = ProxySchedulerLifecycle::Scheduled;
				const auto permit = findPermitLocked(
					gate,
					ticketIdentityLocked(ticket));
				if (permit >= 0) {
					gate.permits[permit]->lifecycle
						= ProxySchedulerLifecycle::Scheduled;
					++gate.revision;
				}
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
	auto fairness = _endpoints[endpointKey].fairness;
	auto planned = std::vector<Ticket*>();
	for (const auto &key : _endpoints[endpointKey].order) {
		const auto i = _tickets.find(key);
		if (i != end(_tickets)
			&& (i->second->lifecycle == ProxySchedulerLifecycle::Scheduled
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
	auto &gate = _gates[endpointKey];
	while (freePermitLocked(gate) >= 0) {
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
		auto eligible = std::set<AdmissionTicketKey>();
		for (const auto ticket : pool) {
			const auto decision = openingAdmissionDecisionLocked(
				*ticket,
				state,
				inputs.now);
			if (decision.allowed) {
				eligible.emplace(ticket->key);
				continue;
			}
			const auto verdict = state.canonicalVerdicts.find({
				.runtimeId = ticket->key.runtimeId,
				.proxyGeneration = ticket->proxyGeneration,
			});
			ticket->blockedBy = (verdict != end(state.canonicalVerdicts))
				? verdict->second.reason
				: state.lastFailure;
			ticket->retryAfter = 0;
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
		const auto selected = selectLocked(
			pool,
			eligible,
			state,
			inputs.now,
			fairness);
		if (!selected) {
			return;
		}
		selected->reevaluateAt = 0;
		selected->blockedBy = MtProxy::FailureReason::None;
		const auto plan = MtProxy::BuildAttemptPlan(
			selected->admissionRequest,
			state.recipeLevel);
		selected->spacing = std::max(
			kMinimumOpenSpacing,
			MtProxy::OpenConnectionSpacing(
				plan.stealth.connectionPattern));
		selected->jitter = inputs.takeJitter(selected->key.runtimeId);
		const auto reduction = MtProxy::ReserveOpenSlot(
			gate.openings,
			{
				.now = inputs.now,
				.earliestOpenAt = selected->notBeforeAt,
				.spacing = selected->spacing,
				.jitter = selected->jitter,
			});
		if (!reduction.applied || !reduction.assignment) {
			return;
		}
		const auto reservation = *reduction.assignment;
		gate.openings = reduction.schedule;
		selected->reservationId = reservation.id;
		selected->scheduledOpenAt = reservation.openAt;
		selected->nextOpenAt = reservation.nextOpenAt;
		selected->lifecycle = ProxySchedulerLifecycle::Scheduled;
		const auto identity = ticketIdentityLocked(*selected);
		if (!assignPermitLocked(
				gate,
				identity,
				selected->lifecycle,
				selected->reservationId)) {
			gate.openings = MtProxy::CancelOpenSlot(
				gate.openings,
				selected->reservationId).schedule;
			selected->reservationId = 0;
			selected->scheduledOpenAt = 0;
			selected->nextOpenAt = 0;
			selected->lifecycle = ProxySchedulerLifecycle::Queued;
			return;
		}
		if (gate.stage == MtProxy::EndpointOpenGateStage::Open
			&& gate.immediateScoutRequest) {
			gate.stage = MtProxy::EndpointOpenGateStage::HalfOpen;
			gate.openDeadline = 0;
			++gate.revision;
		}
		if ((gate.stage == MtProxy::EndpointOpenGateStage::HalfOpen
				|| gate.stage
					== MtProxy::EndpointOpenGateStage::Recovering)
			&& !gate.stageOwner) {
			gate.stageOwner = identity;
			if (gate.stage == MtProxy::EndpointOpenGateStage::HalfOpen) {
				gate.immediateScoutRequest.reset();
			}
			++gate.revision;
		}
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
		const auto state = _storage.states.find(endpointKey);
		if (state == end(_storage.states)
			|| !openingAdmissionDecisionLocked(
				ticket,
				state->second,
				now).allowed) {
			continue;
		}
		ticket.lifecycle = ProxySchedulerLifecycle::Granted;
		const auto gate = _gates.find(endpointKey);
		if (gate == end(_gates)) {
			continue;
		}
		const auto permit = findPermitLocked(
			gate->second,
			ticketIdentityLocked(ticket));
		if (permit < 0) {
			ticket.lifecycle = ProxySchedulerLifecycle::Scheduled;
			continue;
		}
		gate->second.permits[permit]->lifecycle
			= ProxySchedulerLifecycle::Granted;
		++gate->second.revision;
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
	_gates.try_emplace(endpointKey);
	advanceGateLocked(endpointKey, inputs.now);
	DeferEndpointCleanup(
		actions,
		MtProxy::PruneExpiredEndpointStateDeferred(state, inputs.now));
	retireMissingAttemptsLocked(endpointKey, state);
	purgeEndpointLocked(endpointKey, state, actions);
	if (!_endpoints.contains(endpointKey)) {
		return;
	}
	revalidateReservationsLocked(endpointKey, state, inputs, actions);
	assignReservationsLocked(endpointKey, state, inputs, actions);
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
	const auto gate = _gates.find(_wakeEndpointKey);
	return runtime != end(_runtimes)
		&& runtimeLiveLocked(_wakeDriver)
		&& runtime->second->registrationLive == _wakeRegistrationLive
		&& gate != end(_gates)
		&& gate->second.wake
		&& gate->second.wake->token == _wakeToken
		&& gate->second.wake->driverRuntimeId == _wakeDriver
		&& gate->second.wake->gateRevision == gate->second.revision
		&& gate->second.wake->wakeAt == _wakeAt;
}

void EndpointAdmissionArbiter::Private::clearWakeLocked(
		bool invalidateToken) {
	if (invalidateToken && _wakeArmed) {
		++_wakeToken;
	}
	const auto gate = _gates.find(_wakeEndpointKey);
	if (gate != end(_gates)) {
		gate->second.wake.reset();
	}
	_wakeArmed = false;
	_wakeDriver = 0;
	_wakeAt = 0;
	_wakeEndpointKey.clear();
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
	auto wakeEndpointKey = QString();
	for (const auto &entry : _tickets) {
		const auto &ticket = entry.second;
		auto boundary = (ticket->lifecycle
				== ProxySchedulerLifecycle::Scheduled)
			? ticket->scheduledOpenAt
			: crl::time();
		if (ticket->lifecycle == ProxySchedulerLifecycle::Queued
			&& ticket->reevaluateAt > inputs.now
			&& (!boundary || ticket->reevaluateAt < boundary)) {
			boundary = ticket->reevaluateAt;
		}
		if (boundary > inputs.now
			&& (!wakeAt || boundary < wakeAt)) {
			wakeAt = boundary;
			wakeEndpointKey = ticket->endpointKey;
		}
	}
	for (const auto &[endpointKey, schedule] : _endpoints) {
		const auto hasDemand = ranges::find_if(
			schedule.order,
			[&](AdmissionTicketKey key) {
				const auto ticket = _tickets.find(key);
				return ticket != end(_tickets)
					&& (ticket->second->lifecycle
							== ProxySchedulerLifecycle::Queued
						|| ticket->second->lifecycle
							== ProxySchedulerLifecycle::Scheduled);
			}) != end(schedule.order);
		if (!hasDemand) {
			continue;
		}
		const auto state = _storage.states.find(endpointKey);
		if (state == end(_storage.states)) {
			continue;
		}
		for (const auto &entry : state->second.attemptStarts) {
			const auto boundary = std::max(
				inputs.now,
				MtProxy::EndpointAttemptHardDeadline(entry.second));
			if (!wakeAt || boundary < wakeAt) {
				wakeAt = boundary;
				wakeEndpointKey = endpointKey;
			}
		}
	}
	for (const auto &[endpointKey, gate] : _gates) {
		auto boundary = crl::time();
		if (gate.stage == MtProxy::EndpointOpenGateStage::Open) {
			boundary = gate.openDeadline;
		} else if (gate.stage
				== MtProxy::EndpointOpenGateStage::Recovering
			&& !gate.stageOwner) {
			boundary = gate.recoveryNextOpenAt;
		}
		if (boundary > inputs.now
			&& (!wakeAt || boundary < wakeAt)) {
			wakeAt = boundary;
			wakeEndpointKey = endpointKey;
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
			if (dispatchLive(entry.first)) {
				driver = entry.first;
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
		&& _wakeEndpointKey == wakeEndpointKey
		&& wakeOwnerLiveLocked()) {
		return;
	}
	const auto dispatch = _runtimes.find(driver)->second;
	const auto token = ++_wakeToken;
	_wakeArmed = true;
	_wakeDriver = driver;
	_wakeAt = wakeAt;
	_wakeEndpointKey = wakeEndpointKey;
	_wakeRegistrationLive = dispatch->registrationLive;
	auto &gate = _gates[wakeEndpointKey];
	auto endpoint = MtProxy::CanonicalProxyEndpoint();
	const auto state = _storage.states.find(wakeEndpointKey);
	if (state != end(_storage.states)) {
		endpoint = state->second.endpoint.canonical;
	} else {
		const auto schedule = _endpoints.find(wakeEndpointKey);
		if (schedule != end(_endpoints)
			&& !schedule->second.order.empty()) {
			const auto ticket = _tickets.find(
				schedule->second.order.front());
			if (ticket != end(_tickets)) {
				endpoint = ticket->second->endpoint.canonical;
			}
		}
	}
	gate.wake = MtProxy::EndpointOpeningWakeIdentity{
		.endpoint = endpoint,
		.driverRuntimeId = driver,
		.gateRevision = gate.revision,
		.token = token,
		.stage = gate.stage,
		.wakeAt = wakeAt,
	};
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
		retireAttemptsLocked([=](
				const MtProxy::EndpointOpeningAttemptIdentity &identity) {
			return identity.flow.runtimeId == runtimeId;
		});
		retireScoutRequestsLocked([=](
				const MtProxy::EndpointImmediateScoutRequest &request) {
			return request.requester.runtimeId == runtimeId;
		});
		for (const auto &entry : _gates) {
			affected.emplace(entry.first);
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
		retireAttemptsLocked([=](
				const MtProxy::EndpointOpeningAttemptIdentity &identity) {
			return identity.flow.runtimeId == runtimeId;
		});
		retireScoutRequestsLocked([=](
				const MtProxy::EndpointImmediateScoutRequest &request) {
			return request.requester.runtimeId == runtimeId;
		});
		for (auto &entry : _endpoints) {
			for (auto &cursor : entry.second.fairness.lastRuntime) {
				if (cursor == runtimeId) {
					cursor = 0;
				}
			}
			entry.second.fairness.nextBackground.erase(runtimeId);
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
					actions.ownerConnections.push_back(
						std::move(i->second.ownerDestroyed));
					i = state.attemptStarts.erase(i);
				} else {
					++i;
				}
			}
			for (auto i = begin(state.liveLanes);
					i != end(state.liveLanes);) {
				if (i->first.runtimeId == runtimeId) {
					actions.ownerConnections.push_back(
						std::move(i->second.ownerDestroyed));
					i = state.liveLanes.erase(i);
				} else {
					++i;
				}
			}
			MtProxy::RemoveRelayProofsForRuntime(state, runtimeId);
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
			if (identities.empty()) {
				continue;
			}
			affected.emplace(endpointKey);
			actions.context = _context;
			for (const auto &identity : identities) {
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
				static_cast<void>(MtProxy::RetireRelayProof(
					state,
					identity));
				if (attemptMatches) {
					actions.ownerConnections.push_back(
						std::move(attempt->second.ownerDestroyed));
					state.attemptStarts.erase(attempt);
				}
				if (lane != end(state.liveLanes)) {
					actions.ownerConnections.push_back(
						std::move(lane->second.ownerDestroyed));
					state.liveLanes.erase(lane);
				}
				actions.invalidations.emplace_back(
					state.endpoint,
					RuntimeGenerationKey{
						.runtimeId = identity.runtimeId,
						.proxyGeneration = identity.proxyGeneration,
					});
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
		retireAttemptsLocked([&](
				const MtProxy::EndpointOpeningAttemptIdentity &identity) {
			return identity.key.ticketKey == key;
		});
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
		for (auto &[endpointKey, state] : _storage.states) {
			const auto current = state.generations.find(runtimeId);
			if (current != end(state.generations)
				&& proxyGeneration <= current->second) {
				continue;
			}
			auto cleanup = MtProxy::EndpointDeferredCleanup();
			MtProxy::ApplyRuntimeProxyGeneration(
				state,
				runtimeId,
				proxyGeneration,
				&cleanup);
			DeferEndpointCleanup(actions, std::move(cleanup));
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
		auto cancelled = std::vector<AdmissionTicketKey>();
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
		retireAttemptsLocked([=](
				const MtProxy::EndpointOpeningAttemptIdentity &identity) {
			return identity.flow.runtimeId == runtimeId
				&& identity.flow.proxyGeneration < proxyGeneration;
		});
		retireScoutRequestsLocked([=](
				const MtProxy::EndpointImmediateScoutRequest &request) {
			return request.requester.runtimeId == runtimeId
				&& request.requester.proxyGeneration < proxyGeneration;
		});
		for (const auto &entry : _gates) {
			affected.emplace(entry.first);
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

void EndpointAdmissionArbiter::Private::openingEvent(
		MtProxy::EndpointOpeningEvent event) {
	auto inputs = prepareInputs();
	const auto endpointKey = std::visit([](const auto &value) {
		return MtProxy::EndpointKey(value.identity.flow.endpoint);
	}, event);
	const auto observedAt = std::visit([](const auto &value) {
		return value.observedAt;
	}, event);
	const auto now = observedAt
		? std::max(inputs.now, observedAt)
		: inputs.now;
	inputs.now = now;
	auto actions = Actions();
	{
		QMutexLocker lock(&_storage.mutex);
		std::visit([&](const auto &value) {
			applyOpeningEventLocked(value, now, actions);
		}, event);
		if (!endpointKey.isEmpty()) {
			drainEndpointLocked(endpointKey, inputs, actions);
		}
		updateWakeLocked(inputs, actions);
	}
	actions.run();
}

void EndpointAdmissionArbiter::Private::requestImmediateScout(
		const MtProxy::CanonicalProxyEndpoint &endpoint,
		RuntimeGenerationKey requester) {
	const auto endpointKey = MtProxy::EndpointKey(endpoint);
	if (endpointKey.isEmpty()
		|| !requester.runtimeId
		|| !requester.proxyGeneration) {
		return;
	}
	auto inputs = prepareInputs();
	auto actions = Actions();
	{
		QMutexLocker lock(&_storage.mutex);
		const auto gate = _gates.find(endpointKey);
		const auto generation = _storage.runtimeGenerations.find(
			requester.runtimeId);
		if (gate == end(_gates)
			|| gate->second.stage != MtProxy::EndpointOpenGateStage::Open
			|| gate->second.immediateScoutRequest
			|| !runtimeLiveLocked(requester.runtimeId)
			|| generation == end(_storage.runtimeGenerations)
			|| generation->second != requester.proxyGeneration) {
			return;
		}
		auto &current = gate->second;
		current.immediateScoutRequest = MtProxy::EndpointImmediateScoutRequest{
			.endpoint = endpoint,
			.requester = requester,
			.requestId = ++current.lastScoutRequestId,
			.requestedAt = inputs.now,
		};
		++current.revision;
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
		ProxySchedulerLifecycle lifecycle,
		const std::shared_ptr<std::atomic<bool>> &registrationLive) {
	auto inputs = prepareInputs();
	auto actions = Actions();
	auto callbacks = std::shared_ptr<TicketCallbacks>();
	auto update = EndpointAdmissionUpdate();
	{
		QMutexLocker lock(&_storage.mutex);
		const auto i = _tickets.find(key);
		if (i == end(_tickets)
			|| i->second->revision != revision
			|| i->second->transition != transition
			|| i->second->lifecycle != lifecycle) {
			return;
		}
		if (!deliveryRegistrationCurrentLocked(
				*i->second,
				registrationLive,
				TicketDelivery::Status,
				inputs,
				actions)) {
			lock.unlock();
			actions.run();
			return;
		}
		if (!i->second->owner) {
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
		ProxySchedulerLifecycle lifecycle,
		const std::shared_ptr<std::atomic<bool>> &registrationLive) {
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
		if (!deliveryRegistrationCurrentLocked(
				*i->second,
				registrationLive,
				TicketDelivery::Grant,
				inputs,
				actions)) {
			lock.unlock();
			actions.run();
			return;
		}
		auto &ticket = *i->second;
		const auto endpointKey = ticket.endpointKey;
		const auto unscoped = MtProxy::EndpointEmpty(ticket.endpoint);
		const auto state = _storage.states.find(endpointKey);
		if (!unscoped && state != end(_storage.states)) {
			DeferEndpointCleanup(
				actions,
				MtProxy::PruneExpiredEndpointStateDeferred(
					state->second,
					inputs.now));
		}
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
		const auto decision = unscoped
			? MtProxy::OpeningAdmissionDecision{
				.allowed = true,
			}
			: (state != end(_storage.states))
			? openingAdmissionDecisionLocked(
				ticket,
				state->second,
				inputs.now)
			: MtProxy::OpeningAdmissionDecision();
		const auto grantContextCurrent = context
			&& ticket.owner
			&& runtimeLiveLocked(key.runtimeId)
			&& traceCurrent
			&& current;
		if (!grantContextCurrent) {
			cancelTicketLocked(key, revision, actions);
			drainEndpointLocked(endpointKey, inputs, actions);
			updateWakeLocked(inputs, actions);
		} else if (!decision.allowed) {
			demoteTicketLocked(ticket, actions);
			drainEndpointLocked(endpointKey, inputs, actions);
			updateWakeLocked(inputs, actions);
		} else if (ticket.scheduledOpenAt > inputs.now) {
			ticket.lifecycle = ProxySchedulerLifecycle::Scheduled;
			const auto gate = _gates.find(endpointKey);
			if (gate != end(_gates)) {
				const auto permit = findPermitLocked(
					gate->second,
					ticketIdentityLocked(ticket));
				if (permit >= 0) {
					gate->second.permits[permit]->lifecycle
						= ProxySchedulerLifecycle::Scheduled;
					++gate->second.revision;
				}
			}
			++ticket.transition;
			postStatusLocked(ticket, actions);
			drainEndpointLocked(endpointKey, inputs, actions);
			updateWakeLocked(inputs, actions);
		} else {
			const auto gate = _gates.find(ticket.endpointKey);
			const auto reduction = (!unscoped
				&& gate != end(_gates)
				&& ticket.reservationId)
				? MtProxy::CommitOpenSlot(
					gate->second.openings,
					ticket.reservationId)
				: MtProxy::OpenSlotReduction();
			const auto openCommitted = unscoped
				? !ticket.reservationId
				: reduction.applied;
			if (!openCommitted) {
				cancelTicketLocked(key, revision, actions);
				drainEndpointLocked(endpointKey, inputs, actions);
				updateWakeLocked(inputs, actions);
			} else {
				if (!unscoped) {
					gate->second.openings = reduction.schedule;
				}
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
						const auto attemptState = state->second
							.attemptStarts.find(admission->attemptId);
						Assert(attemptState
							!= end(state->second.attemptStarts));
						attemptState->second.ownerDestroyed
							= ticket.ownerDestroyed;
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
					if (!unscoped) {
						const auto openingIdentity
							= MtProxy::EndpointOpeningAttemptIdentity{
								.flow = {
									.endpoint = ticket.endpoint.canonical,
									.runtimeId = key.runtimeId,
									.proxyGeneration
										= ticket.proxyGeneration,
									.use = ticket.use,
								},
								.key = AttemptKeyFrom(attempt),
							};
						Assert(transferPermitLocked(
							endpointKey,
							ticketIdentityLocked(ticket),
							openingIdentity));
						const auto &gateState = gate->second;
						const auto openingOwner
							= MtProxy::EndpointOpeningIdentity{
								.flow = openingIdentity.flow,
								.owner = openingIdentity.key,
							};
						if (gateState.stage
								== MtProxy::EndpointOpenGateStage::Recovering
							&& gateState.stageOwner
							&& OpeningIdentityMatches(
								*gateState.stageOwner,
								openingOwner)) {
							gate->second.recoveryNextOpenAt = std::max(
								gate->second.recoveryNextOpenAt,
								inputs.now + kRecoveryOpenSpacing);
							++gate->second.revision;
						}
					}
					if (trace != end(_storage.activeTraces)) {
						trace->second = attempt;
					}
					if (!unscoped) {
						const auto schedule = _endpoints.find(endpointKey);
						if (schedule != end(_endpoints)) {
							AdvanceFairness(
								schedule->second.fairness,
								ticket,
								priorityForLocked(
									ticket,
									state->second,
									inputs.now));
						}
					} else {
						actions.ownerConnections.push_back(
							std::move(ticket.ownerDestroyed));
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
	actions.run();
}

bool EndpointAdmissionArbiter::Private::deliveryRegistrationCurrentLocked(
		Ticket &ticket,
		const std::shared_ptr<std::atomic<bool>> &registrationLive,
		TicketDelivery delivery,
		DrainInputs &inputs,
		Actions &actions) {
	const auto runtime = _runtimes.find(ticket.key.runtimeId);
	const auto runtimeLive = runtime != end(_runtimes)
		&& runtimeLiveLocked(ticket.key.runtimeId)
		&& runtime->second->registrationLive
		&& runtime->second->registrationLive->load(
			std::memory_order_acquire);
	if (runtimeLive
		&& runtime->second->registrationLive == registrationLive) {
		return true;
	}
	if (runtimeLive) {
		if (delivery == TicketDelivery::Grant) {
			postGrantLocked(ticket, actions);
		} else {
			postStatusLocked(ticket, actions);
		}
		return false;
	}
	const auto key = ticket.key;
	const auto revision = ticket.revision;
	const auto endpointKey = ticket.endpointKey;
	cancelTicketLocked(key, revision, actions);
	drainEndpointLocked(endpointKey, inputs, actions);
	updateWakeLocked(inputs, actions);
	return false;
}

void EndpointAdmissionArbiter::Private::deliveryMissing(
		AdmissionTicketKey key,
		uint64 revision,
		uint64 transition,
		ProxySchedulerLifecycle lifecycle,
		const std::shared_ptr<std::atomic<bool>> &registrationLive,
		TicketDelivery delivery) {
	auto inputs = prepareInputs();
	auto actions = Actions();
	{
		QMutexLocker lock(&_storage.mutex);
		const auto i = _tickets.find(key);
		if (i == end(_tickets)
			|| i->second->revision != revision
			|| i->second->transition != transition
			|| i->second->lifecycle != lifecycle) {
			return;
		}
		if (deliveryRegistrationCurrentLocked(
				*i->second,
				registrationLive,
				delivery,
				inputs,
				actions)) {
			const auto endpointKey = i->second->endpointKey;
			cancelTicketLocked(key, revision, actions);
			drainEndpointLocked(endpointKey, inputs, actions);
			updateWakeLocked(inputs, actions);
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

void EndpointAdmissionArbiter::drainEndpoint(
		const QString &endpointKey) {
	_private->drainEndpoint(endpointKey);
}

void EndpointAdmissionArbiter::openingEvent(
		MtProxy::EndpointOpeningEvent event) {
	_private->openingEvent(std::move(event));
}

void EndpointAdmissionArbiter::requestImmediateScout(
		const MtProxy::CanonicalProxyEndpoint &endpoint,
		RuntimeGenerationKey requester) {
	_private->requestImmediateScout(endpoint, requester);
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
		ProxySchedulerLifecycle lifecycle,
		const std::shared_ptr<std::atomic<bool>> &registrationLive) {
	_private->deliverStatus(
		key,
		revision,
		transition,
		lifecycle,
		registrationLive);
}

void EndpointAdmissionArbiter::deliverGrant(
		AdmissionTicketKey key,
		uint64 revision,
		uint64 transition,
		ProxySchedulerLifecycle lifecycle,
		const std::shared_ptr<std::atomic<bool>> &registrationLive) {
	_private->deliverGrant(
		key,
		revision,
		transition,
		lifecycle,
		registrationLive);
}

void EndpointAdmissionArbiter::statusDeliveryMissing(
		AdmissionTicketKey key,
		uint64 revision,
		uint64 transition,
		ProxySchedulerLifecycle lifecycle,
		const std::shared_ptr<std::atomic<bool>> &registrationLive) {
	_private->deliveryMissing(
		key,
		revision,
		transition,
		lifecycle,
		registrationLive,
		TicketDelivery::Status);
}

void EndpointAdmissionArbiter::grantDeliveryMissing(
		AdmissionTicketKey key,
		uint64 revision,
		uint64 transition,
		ProxySchedulerLifecycle lifecycle,
		const std::shared_ptr<std::atomic<bool>> &registrationLive) {
	_private->deliveryMissing(
		key,
		revision,
		transition,
		lifecycle,
		registrationLive,
		TicketDelivery::Grant);
}

} // namespace MTP::details
