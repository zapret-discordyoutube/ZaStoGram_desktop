/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "mtproto/proxy/endpoint_admission_arbiter.h"

#include "mtproto/proxy/mtproxy/endpoint_health_policy.h"
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
constexpr auto kOpenSpacingJitter = crl::time(125);
constexpr auto kLiveQuantum = crl::time(60 * 1000);

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
	Fn<void(MtProxy::LiveSlotKey)> reclaim;
	std::shared_ptr<TicketCallbacks> callbacks;
	ProxySchedulerLifecycle lifecycle = ProxySchedulerLifecycle::None;
	MtProxy::EndpointAdmissionWaitReason waitReason
		= MtProxy::EndpointAdmissionWaitReason::None;
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
	std::optional<MtProxy::LiveSlotKey> slotKey;
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

void GrantAction::run() {
	if (!ticket) {
		return;
	}
	if (ticket->owner
		&& ticket->callbacks
		&& ticket->callbacks->grant) {
		ticket->callbacks->grant(std::move(grant));
		return;
	}
	if (const auto strong = context.lock()) {
		(void)strong->finishTrace(grant.attempt.traceId);
		strong->endpointAdmissionArbiter().releaseLiveSlot(
			grant.slotKey,
			grant.attempt);
	}
	grant.admission.lease.release();
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

[[nodiscard]] bool IsTransfer(MtProxy::EndpointUse use) {
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

[[nodiscard]] std::optional<MtProxy::LiveSlotEntitlement> NativeEntitlement(
		ProxyRuntimeId runtimeId,
		MtProxy::EndpointUse use,
		ProxyRuntimeId foregroundRuntimeId) {
	if (use == MtProxy::EndpointUse::Main) {
		return (runtimeId == foregroundRuntimeId)
			? MtProxy::LiveSlotEntitlement::ForegroundMain
			: MtProxy::LiveSlotEntitlement::BackgroundMain;
	}
	if (runtimeId != foregroundRuntimeId) {
		return std::nullopt;
	}
	if (use == MtProxy::EndpointUse::Media) {
		return MtProxy::LiveSlotEntitlement::ForegroundMedia;
	}
	if (use == MtProxy::EndpointUse::Upload) {
		return MtProxy::LiveSlotEntitlement::ForegroundUpload;
	}
	return std::nullopt;
}

[[nodiscard]] bool TicketOwnerMatches(
		const MtProxy::LiveSlotTicketOwner &owner,
		const Ticket &ticket) {
	return owner.key == ticket.key && owner.revision == ticket.revision;
}

[[nodiscard]] bool AttemptOwnerMatches(
		const MtProxy::LiveSlotAttemptOwner &owner,
		const ProxyConnectionAttempt &attempt) {
	return owner.attempt == attempt;
}

[[nodiscard]] MtProxy::LiveSlotKey SlotKey(
		const QString &endpointKey,
		int index,
		const MtProxy::EndpointLiveSlot &slot) {
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
	void ownerDestroyed(AdmissionTicketKey key, uint64 revision);
	void cancelBeforeGeneration(
		ProxyRuntimeId runtimeId,
		uint64 proxyGeneration);
	void drainEndpoint(const QString &endpointKey);
	void reevaluate(AdmissionTicketKey key, uint64 revision);
	void markTransportReady(
		const MtProxy::LiveSlotKey &slotKey,
		const ProxyConnectionAttempt &attempt);
	void releaseLiveSlot(
		const MtProxy::LiveSlotKey &slotKey,
		const ProxyConnectionAttempt &attempt);
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
	[[nodiscard]] int entitlementSlotLocked(
		const MtProxy::EndpointLivePool &pool,
		MtProxy::LiveSlotEntitlement entitlement) const;
	[[nodiscard]] int reservedSlotLocked(
		const MtProxy::EndpointLivePool &pool,
		const Ticket &ticket) const;
	[[nodiscard]] bool successorSlotLocked(
		const MtProxy::EndpointLivePool &pool,
		const Ticket &ticket) const;
	[[nodiscard]] bool reservationCurrentLocked(
		const Ticket &ticket,
		const MtProxy::EndpointLivePool &pool) const;
	void invalidateTicketLocked(Ticket &ticket, Actions &actions);
	void postStatusLocked(Ticket &ticket, Actions &actions);
	void postGenerationCancelledStatusLocked(
		const Ticket &ticket,
		Actions &actions);
	void postGrantLocked(Ticket &ticket, Actions &actions);
	void updateQueuedStatusLocked(
		Ticket &ticket,
		MtProxy::EndpointAdmissionWaitReason waitReason,
		MtProxy::FailureReason blockedBy,
		crl::time retryAfter,
		crl::time reevaluateAt,
		Actions &actions);
	[[nodiscard]] bool deliveryRegistrationCurrentLocked(
		Ticket &ticket,
		const std::shared_ptr<std::atomic<bool>> &registrationLive,
		TicketDelivery delivery,
		DrainInputs &inputs,
		Actions &actions);
	void clearTicketSlotLocked(Ticket &ticket);
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
	[[nodiscard]] bool reserveTicketLocked(
		const QString &endpointKey,
		int slotIndex,
		Ticket &ticket,
		MtProxy::EndpointState &state,
		DrainInputs &inputs,
		Actions &actions);
	void revalidateReservationsLocked(
		const QString &endpointKey,
		MtProxy::EndpointState &state,
		DrainInputs &inputs,
		Actions &actions);
	void reconcileForegroundLocked(
		const QString &endpointKey,
		MtProxy::EndpointLivePool &pool);
	[[nodiscard]] bool slotBorrowableLocked(
		const QString &endpointKey,
		const MtProxy::EndpointState &state,
		const MtProxy::EndpointLivePool &pool,
		const Ticket &ticket,
		int slotIndex) const;
	[[nodiscard]] int borrowableSlotLocked(
		const QString &endpointKey,
		const MtProxy::EndpointState &state,
		const MtProxy::EndpointLivePool &pool,
		const Ticket &ticket) const;
	void bindClosingSuccessorLocked(
		MtProxy::EndpointLiveSlot &slot,
		Ticket &ticket,
		Actions &actions);
	void closeSlotLocked(
		const QString &endpointKey,
		int slotIndex,
		std::optional<MtProxy::LiveSlotTicketOwner> successor,
		bool fairness,
		Actions &actions);
	void closeMatchingAttemptsLocked(
		Fn<bool(const ProxyConnectionAttempt&)> matches,
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
	std::map<QString, MtProxy::EndpointLivePool> _pools;
	std::map<
		ProxyRuntimeId,
		std::shared_ptr<const EndpointAdmissionRuntimeDispatch>> _runtimes;
	std::weak_ptr<ProxyEndpointContext> _context;
	std::atomic<uint64> _lastRevision = 0;
	uint64 _lastSequence = 0;
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
			actions.removed.push_back(std::move(entry.second));
		}
		_tickets.clear();
		_endpoints.clear();
		_pools.clear();
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
		&& IsTransfer(ticket.use)
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
				&& IsTransfer(ticket->use)
				&& ticket->use != desired)) {
			continue;
		}
		if (!result
			|| ticket->enqueuedAt < result->enqueuedAt
			|| (ticket->enqueuedAt == result->enqueuedAt
				&& ticket->sequence < result->sequence)) {
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

bool EndpointAdmissionArbiter::Private::baseEligibleLocked(
		const Ticket &ticket,
		const MtProxy::EndpointState &state) const {
	if (!ticketCurrentLocked(ticket, state)) {
		return false;
	}
	if (!IsTransfer(ticket.use)) {
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

int EndpointAdmissionArbiter::Private::entitlementSlotLocked(
		const MtProxy::EndpointLivePool &pool,
		MtProxy::LiveSlotEntitlement entitlement) const {
	for (auto i = 0; i != int(pool.slots.size()); ++i) {
		if (pool.slots[i].entitlement == entitlement) {
			return i;
		}
	}
	return -1;
}

int EndpointAdmissionArbiter::Private::reservedSlotLocked(
		const MtProxy::EndpointLivePool &pool,
		const Ticket &ticket) const {
	for (auto i = 0; i != int(pool.slots.size()); ++i) {
		const auto &slot = pool.slots[i];
		const auto owner = std::get_if<MtProxy::LiveSlotTicketOwner>(
			&slot.owner);
		if (slot.phase == MtProxy::LiveSlotPhase::Reserved
			&& owner
			&& TicketOwnerMatches(*owner, ticket)) {
			return i;
		}
	}
	return -1;
}

bool EndpointAdmissionArbiter::Private::successorSlotLocked(
		const MtProxy::EndpointLivePool &pool,
		const Ticket &ticket) const {
	for (const auto &slot : pool.slots) {
		const auto closing = std::get_if<MtProxy::LiveSlotClosingState>(
			&slot.owner);
		if (slot.phase == MtProxy::LiveSlotPhase::Closing
			&& closing
			&& closing->pendingSuccessor
			&& closing->pendingSuccessor->key == ticket.key
			&& closing->pendingSuccessor->revision == ticket.revision) {
			return true;
		}
	}
	return false;
}

bool EndpointAdmissionArbiter::Private::reservationCurrentLocked(
		const Ticket &ticket,
		const MtProxy::EndpointLivePool &pool) const {
	const auto index = reservedSlotLocked(pool, ticket);
	return index >= 0
		&& ticket.slotKey
		&& ticket.slotKey->index == index
		&& ticket.slotKey->endpointKey == ticket.endpointKey
		&& ticket.slotKey->incarnation == pool.slots[index].incarnation;
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
		.waitReason = ticket.waitReason,
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

void EndpointAdmissionArbiter::Private::updateQueuedStatusLocked(
		Ticket &ticket,
		MtProxy::EndpointAdmissionWaitReason waitReason,
		MtProxy::FailureReason blockedBy,
		crl::time retryAfter,
		crl::time reevaluateAt,
		Actions &actions) {
	if (ticket.waitReason == waitReason
		&& ticket.blockedBy == blockedBy
		&& ticket.retryAfter == retryAfter
		&& ticket.reevaluateAt == reevaluateAt) {
		return;
	}
	ticket.waitReason = waitReason;
	ticket.blockedBy = blockedBy;
	ticket.retryAfter = retryAfter;
	ticket.reevaluateAt = reevaluateAt;
	++ticket.transition;
	postStatusLocked(ticket, actions);
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

void EndpointAdmissionArbiter::Private::clearTicketSlotLocked(
		Ticket &ticket) {
	const auto pool = _pools.find(ticket.endpointKey);
	if (pool == end(_pools)) {
		ticket.slotKey.reset();
		return;
	}
	auto &current = pool->second;
	const auto reserved = reservedSlotLocked(current, ticket);
	if (reserved >= 0) {
		auto &slot = current.slots[reserved];
		slot.phase = MtProxy::LiveSlotPhase::Empty;
		slot.owner = std::monostate();
	}
	for (auto &slot : current.slots) {
		auto closing = std::get_if<MtProxy::LiveSlotClosingState>(
			&slot.owner);
		if (slot.phase == MtProxy::LiveSlotPhase::Closing
			&& closing
			&& closing->pendingSuccessor
			&& closing->pendingSuccessor->key == ticket.key
			&& closing->pendingSuccessor->revision == ticket.revision) {
			closing->pendingSuccessor.reset();
		}
	}
	if (ticket.reservationId) {
		current.openings = MtProxy::CancelOpenSlot(
			current.openings,
			ticket.reservationId).schedule;
	}
	ticket.slotKey.reset();
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
	clearTicketSlotLocked(ticket);
	if (ticket.traceId) {
		_storage.activeTraces.erase(ticket.traceId);
	}
	ticket.reservationId = 0;
	ticket.lifecycle = ProxySchedulerLifecycle::Cancelled;
	++ticket.transition;
	invalidateTicketLocked(ticket, actions);
	actions.removed.push_back(takeTicketLocked(key));
}

void EndpointAdmissionArbiter::Private::demoteTicketLocked(
		Ticket &ticket,
		Actions &actions) {
	clearTicketSlotLocked(ticket);
	ticket.reservationId = 0;
	ticket.scheduledOpenAt = 0;
	ticket.nextOpenAt = 0;
	ticket.reevaluateAt = 0;
	ticket.retryAfter = 0;
	ticket.waitReason = MtProxy::EndpointAdmissionWaitReason::Slot;
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

bool EndpointAdmissionArbiter::Private::reserveTicketLocked(
		const QString &endpointKey,
		int slotIndex,
		Ticket &ticket,
		MtProxy::EndpointState &state,
		DrainInputs &inputs,
		Actions &actions) {
	auto &pool = _pools[endpointKey];
	if (slotIndex < 0
		|| slotIndex >= int(pool.slots.size())
		|| pool.slots[slotIndex].phase != MtProxy::LiveSlotPhase::Empty
		|| ticket.lifecycle != ProxySchedulerLifecycle::Queued
		|| !baseEligibleLocked(ticket, state)) {
		return false;
	}
	const auto plan = MtProxy::BuildAttemptPlan(
		ticket.admissionRequest,
		state.recipeLevel);
	ticket.spacing = MtProxy::OpenConnectionSpacing(
		plan.stealth.connectionPattern);
	ticket.jitter = inputs.takeJitter(ticket.key.runtimeId);
	const auto reduction = MtProxy::ReserveOpenSlot(
		pool.openings,
		{
			.now = inputs.now,
			.earliestOpenAt = ticket.notBeforeAt,
			.spacing = ticket.spacing,
			.jitter = ticket.jitter,
		});
	if (!reduction.applied || !reduction.assignment) {
		return false;
	}
	pool.openings = reduction.schedule;
	const auto reservation = *reduction.assignment;
	auto &slot = pool.slots[slotIndex];
	slot.incarnation = NextIncarnation(slot.incarnation);
	slot.phase = MtProxy::LiveSlotPhase::Reserved;
	slot.owner = MtProxy::LiveSlotTicketOwner{
		.key = ticket.key,
		.revision = ticket.revision,
	};
	ticket.reservationId = reservation.id;
	ticket.scheduledOpenAt = reservation.openAt;
	ticket.nextOpenAt = reservation.nextOpenAt;
	ticket.retryAfter = std::max(
		crl::time(),
		reservation.openAt - inputs.now);
	ticket.reevaluateAt = 0;
	ticket.blockedBy = MtProxy::FailureReason::None;
	ticket.waitReason = MtProxy::EndpointAdmissionWaitReason::None;
	ticket.slotKey = SlotKey(endpointKey, slotIndex, slot);
	ticket.lifecycle = ProxySchedulerLifecycle::Scheduled;
	++ticket.transition;
	postStatusLocked(ticket, actions);
	return true;
}

void EndpointAdmissionArbiter::Private::revalidateReservationsLocked(
		const QString &endpointKey,
		MtProxy::EndpointState &state,
		DrainInputs &inputs,
		Actions &actions) {
	const auto schedule = _endpoints.find(endpointKey);
	const auto pool = _pools.find(endpointKey);
	if (schedule == end(_endpoints) || pool == end(_pools)) {
		return;
	}
	auto planned = std::vector<Ticket*>();
	for (const auto &key : schedule->second.order) {
		const auto i = _tickets.find(key);
		if (i == end(_tickets)
			|| (i->second->lifecycle != ProxySchedulerLifecycle::Scheduled
				&& i->second->lifecycle
					!= ProxySchedulerLifecycle::Granted)) {
			continue;
		}
		if (!baseEligibleLocked(*i->second, state)
			|| !reservationCurrentLocked(*i->second, pool->second)) {
			demoteTicketLocked(*i->second, actions);
		} else {
			planned.push_back(i->second.get());
		}
	}
	if (planned.empty()) {
		return;
	}
	auto ordered = orderLocked(
		std::move(planned),
		state,
		inputs.now,
		schedule->second.fairness);
	auto requests = std::vector<MtProxy::OpenSlotReflowRequest>();
	requests.reserve(ordered.size());
	for (const auto ticket : ordered) {
		requests.push_back({
			.id = ticket->reservationId,
			.earliestOpenAt = ticket->notBeforeAt,
			.spacing = ticket->spacing,
			.jitter = ticket->jitter,
		});
	}
	const auto reflow = MtProxy::ReflowOpenSlots(
		pool->second.openings,
		requests,
		inputs.now);
	if (!reflow.applied
		|| reflow.assignments.size() != ordered.size()) {
		return;
	}
	pool->second.openings = reflow.schedule;
	for (auto i = std::size_t(); i != ordered.size(); ++i) {
		auto &ticket = *ordered[i];
		const auto changed = ticket.scheduledOpenAt
			!= reflow.assignments[i].openAt;
		ticket.scheduledOpenAt = reflow.assignments[i].openAt;
		ticket.nextOpenAt = reflow.assignments[i].nextOpenAt;
		ticket.retryAfter = std::max(
			crl::time(),
			ticket.scheduledOpenAt - inputs.now);
		if (changed) {
			if (ticket.lifecycle == ProxySchedulerLifecycle::Granted) {
				ticket.lifecycle = ProxySchedulerLifecycle::Scheduled;
			}
			++ticket.transition;
			postStatusLocked(ticket, actions);
		}
	}
}

void EndpointAdmissionArbiter::Private::reconcileForegroundLocked(
		const QString &,
		MtProxy::EndpointLivePool &pool) {
	const auto foreground = _storage.foregroundRuntimeId;
	if (!foreground) {
		return;
	}
	const auto foregroundSlot = entitlementSlotLocked(
		pool,
		MtProxy::LiveSlotEntitlement::ForegroundMain);
	if (foregroundSlot < 0) {
		return;
	}
	auto ownedSlot = -1;
	for (auto i = 0; i != int(pool.slots.size()); ++i) {
		const auto &slot = pool.slots[i];
		if (slot.phase != MtProxy::LiveSlotPhase::Opening
			&& slot.phase != MtProxy::LiveSlotPhase::Live) {
			continue;
		}
		const auto owner = std::get_if<MtProxy::LiveSlotAttemptOwner>(
			&slot.owner);
		if (owner
			&& owner->attempt.runtimeId == foreground
			&& owner->attempt.use == MtProxy::EndpointUse::Main) {
			ownedSlot = i;
			break;
		}
	}
	const auto foregroundPhase = pool.slots[foregroundSlot].phase;
	if (ownedSlot >= 0
		&& ownedSlot != foregroundSlot
		&& foregroundPhase != MtProxy::LiveSlotPhase::Reserved
		&& foregroundPhase != MtProxy::LiveSlotPhase::Closing) {
		std::swap(
			pool.slots[ownedSlot].entitlement,
			pool.slots[foregroundSlot].entitlement);
	}
}

bool EndpointAdmissionArbiter::Private::slotBorrowableLocked(
		const QString &endpointKey,
		const MtProxy::EndpointState &state,
		const MtProxy::EndpointLivePool &pool,
		const Ticket &ticket,
		int slotIndex) const {
	if (slotIndex < 0
		|| slotIndex >= int(pool.slots.size())
		|| pool.slots[slotIndex].phase != MtProxy::LiveSlotPhase::Empty
		|| !baseEligibleLocked(ticket, state)) {
		return false;
	}
	const auto native = NativeEntitlement(
		ticket.key.runtimeId,
		ticket.use,
		_storage.foregroundRuntimeId);
	const auto entitlement = pool.slots[slotIndex].entitlement;
	if (native && *native == entitlement) {
		return true;
	}
	const auto schedule = _endpoints.find(endpointKey);
	if (schedule == end(_endpoints)) {
		return false;
	}
	for (const auto &key : schedule->second.order) {
		const auto i = _tickets.find(key);
		if (i == end(_tickets)
			|| i->second.get() == &ticket
			|| i->second->lifecycle != ProxySchedulerLifecycle::Queued
			|| !baseEligibleLocked(*i->second, state)) {
			continue;
		}
		const auto claimant = NativeEntitlement(
			i->second->key.runtimeId,
			i->second->use,
			_storage.foregroundRuntimeId);
		if (claimant && *claimant == entitlement) {
			return false;
		}
	}
	return true;
}

int EndpointAdmissionArbiter::Private::borrowableSlotLocked(
		const QString &endpointKey,
		const MtProxy::EndpointState &state,
		const MtProxy::EndpointLivePool &pool,
		const Ticket &ticket) const {
	const auto native = NativeEntitlement(
		ticket.key.runtimeId,
		ticket.use,
		_storage.foregroundRuntimeId);
	if (native) {
		const auto preferred = entitlementSlotLocked(pool, *native);
		if (slotBorrowableLocked(
				endpointKey,
				state,
				pool,
				ticket,
				preferred)) {
			return preferred;
		}
	}
	for (auto i = 0; i != int(pool.slots.size()); ++i) {
		if (slotBorrowableLocked(
				endpointKey,
				state,
				pool,
				ticket,
				i)) {
			return i;
		}
	}
	return -1;
}

void EndpointAdmissionArbiter::Private::bindClosingSuccessorLocked(
		MtProxy::EndpointLiveSlot &slot,
		Ticket &ticket,
		Actions &actions) {
	if (slot.phase != MtProxy::LiveSlotPhase::Closing
		|| ticket.lifecycle != ProxySchedulerLifecycle::Queued) {
		return;
	}
	auto closing = std::get_if<MtProxy::LiveSlotClosingState>(&slot.owner);
	if (!closing || closing->pendingSuccessor) {
		return;
	}
	closing->pendingSuccessor = MtProxy::LiveSlotTicketOwner{
		.key = ticket.key,
		.revision = ticket.revision,
	};
	updateQueuedStatusLocked(
		ticket,
		MtProxy::EndpointAdmissionWaitReason::ClosingSlot,
		MtProxy::FailureReason::None,
		0,
		0,
		actions);
}

void EndpointAdmissionArbiter::Private::closeSlotLocked(
		const QString &endpointKey,
		int slotIndex,
		std::optional<MtProxy::LiveSlotTicketOwner> successor,
		bool fairness,
		Actions &actions) {
	const auto pool = _pools.find(endpointKey);
	if (pool == end(_pools)
		|| slotIndex < 0
		|| slotIndex >= int(pool->second.slots.size())) {
		return;
	}
	auto &slot = pool->second.slots[slotIndex];
	if (slot.phase == MtProxy::LiveSlotPhase::Closing) {
		auto closing = std::get_if<MtProxy::LiveSlotClosingState>(
			&slot.owner);
		if (closing && !closing->pendingSuccessor && successor) {
			closing->pendingSuccessor = successor;
		}
		return;
	}
	if (slot.phase != MtProxy::LiveSlotPhase::Opening
		&& slot.phase != MtProxy::LiveSlotPhase::Live) {
		return;
	}
	auto incumbent = std::get_if<MtProxy::LiveSlotAttemptOwner>(&slot.owner);
	if (!incumbent) {
		return;
	}
	auto closing = MtProxy::LiveSlotClosingState{
		.incumbent = std::move(*incumbent),
		.pendingSuccessor = successor,
	};
	const auto slotKey = SlotKey(endpointKey, slotIndex, slot);
	slot.phase = MtProxy::LiveSlotPhase::Closing;
	slot.owner = std::move(closing);
	if (fairness) {
		pool->second.fairnessClosing = slotKey;
	}
	const auto &stored = std::get<MtProxy::LiveSlotClosingState>(slot.owner);
	const auto runtime = _runtimes.find(stored.incumbent.attempt.runtimeId);
	if (runtime == end(_runtimes) || !stored.incumbent.reclaim) {
		return;
	}
	const auto reclaim = stored.incumbent.reclaim;
	actions.posts.push_back({
		.dispatch = runtime->second,
		.target = stored.incumbent.owner,
		.callback = [reclaim, slotKey] {
			reclaim(slotKey);
		},
	});
}

void EndpointAdmissionArbiter::Private::closeMatchingAttemptsLocked(
		Fn<bool(const ProxyConnectionAttempt&)> matches,
		Actions &actions) {
	for (auto &[endpointKey, pool] : _pools) {
		for (auto i = 0; i != int(pool.slots.size()); ++i) {
			const auto &slot = pool.slots[i];
			if (slot.phase != MtProxy::LiveSlotPhase::Opening
				&& slot.phase != MtProxy::LiveSlotPhase::Live) {
				continue;
			}
			const auto owner = std::get_if<MtProxy::LiveSlotAttemptOwner>(
				&slot.owner);
			if (owner && matches(owner->attempt)) {
				closeSlotLocked(
					endpointKey,
					i,
					std::nullopt,
					false,
					actions);
			}
		}
	}
}

void EndpointAdmissionArbiter::Private::assignReservationsLocked(
		const QString &endpointKey,
		MtProxy::EndpointState &state,
		DrainInputs &inputs,
		Actions &actions) {
	const auto schedule = _endpoints.find(endpointKey);
	if (schedule == end(_endpoints)) {
		return;
	}
	auto &pool = _pools[endpointKey];
	if (pool.fairnessClosing) {
		const auto key = *pool.fairnessClosing;
		const auto valid = key.index >= 0
			&& key.index < int(pool.slots.size())
			&& pool.slots[key.index].phase
				== MtProxy::LiveSlotPhase::Closing
			&& pool.slots[key.index].incarnation == key.incarnation;
		if (!valid) {
			pool.fairnessClosing.reset();
		}
	}
	reconcileForegroundLocked(endpointKey, pool);
	const auto entitlements = std::array{
		MtProxy::LiveSlotEntitlement::ForegroundMain,
		MtProxy::LiveSlotEntitlement::ForegroundMedia,
		MtProxy::LiveSlotEntitlement::ForegroundUpload,
		MtProxy::LiveSlotEntitlement::BackgroundMain,
	};
	for (const auto entitlement : entitlements) {
		auto candidates = std::vector<Ticket*>();
		auto eligible = std::set<AdmissionTicketKey>();
		for (const auto &key : schedule->second.order) {
			const auto i = _tickets.find(key);
			if (i == end(_tickets)
				|| i->second->lifecycle != ProxySchedulerLifecycle::Queued
				|| successorSlotLocked(pool, *i->second)) {
				continue;
			}
			const auto native = NativeEntitlement(
				i->second->key.runtimeId,
				i->second->use,
				_storage.foregroundRuntimeId);
			if (!native || *native != entitlement) {
				continue;
			}
			candidates.push_back(i->second.get());
			if (baseEligibleLocked(*i->second, state)) {
				eligible.emplace(key);
			}
		}
		auto selected = selectLocked(
			candidates,
			eligible,
			state,
			inputs.now,
			schedule->second.fairness);
		if (!selected) {
			continue;
		}
		const auto slotIndex = entitlementSlotLocked(pool, entitlement);
		if (slotIndex < 0) {
			continue;
		}
		auto &slot = pool.slots[slotIndex];
		if (slot.phase == MtProxy::LiveSlotPhase::Empty) {
			static_cast<void>(reserveTicketLocked(
				endpointKey,
				slotIndex,
				*selected,
				state,
				inputs,
				actions));
			continue;
		}
		if (slot.phase == MtProxy::LiveSlotPhase::Reserved) {
			const auto owner = std::get_if<MtProxy::LiveSlotTicketOwner>(
				&slot.owner);
			const auto occupying = owner ? _tickets.find(owner->key) : end(_tickets);
			const auto native = (occupying != end(_tickets))
				? NativeEntitlement(
					occupying->second->key.runtimeId,
					occupying->second->use,
					_storage.foregroundRuntimeId)
				: std::nullopt;
			if (!native || *native != entitlement) {
				if (occupying != end(_tickets)
					&& occupying->second->key.runtimeId
						== _storage.foregroundRuntimeId
					&& occupying->second->use
						== MtProxy::EndpointUse::Main) {
					continue;
				}
				if (occupying != end(_tickets)
					&& owner->revision == occupying->second->revision) {
					demoteTicketLocked(*occupying->second, actions);
				}
				if (pool.slots[slotIndex].phase
						== MtProxy::LiveSlotPhase::Empty) {
					static_cast<void>(reserveTicketLocked(
						endpointKey,
						slotIndex,
						*selected,
						state,
						inputs,
						actions));
				}
			}
			continue;
		}
		if (slot.phase == MtProxy::LiveSlotPhase::Closing) {
			auto closing = std::get_if<MtProxy::LiveSlotClosingState>(
				&slot.owner);
			const auto incumbentNative = closing
				? NativeEntitlement(
					closing->incumbent.attempt.runtimeId,
					closing->incumbent.attempt.use,
					_storage.foregroundRuntimeId)
				: std::nullopt;
			if (closing
				&& (!incumbentNative || *incumbentNative != entitlement)
				&& closing->pendingSuccessor
				&& (closing->pendingSuccessor->key != selected->key
					|| closing->pendingSuccessor->revision
						!= selected->revision)) {
				const auto previous = _tickets.find(
					closing->pendingSuccessor->key);
				if (previous != end(_tickets)
					&& previous->second->revision
						== closing->pendingSuccessor->revision) {
					updateQueuedStatusLocked(
						*previous->second,
						MtProxy::EndpointAdmissionWaitReason::Slot,
						MtProxy::FailureReason::None,
						0,
						0,
						actions);
				}
				closing->pendingSuccessor.reset();
			}
			bindClosingSuccessorLocked(slot, *selected, actions);
			continue;
		}
		const auto owner = std::get_if<MtProxy::LiveSlotAttemptOwner>(
			&slot.owner);
		if (!owner) {
			continue;
		}
		const auto ownerNative = NativeEntitlement(
			owner->attempt.runtimeId,
			owner->attempt.use,
			_storage.foregroundRuntimeId);
		if (!ownerNative || *ownerNative != entitlement) {
			if (owner->attempt.runtimeId == _storage.foregroundRuntimeId
				&& owner->attempt.use == MtProxy::EndpointUse::Main) {
				continue;
			}
			auto reclaimIndex = slotIndex;
			if (entitlement
					== MtProxy::LiveSlotEntitlement::ForegroundMain
				&& owner->attempt.runtimeId
					!= _storage.foregroundRuntimeId) {
				auto alternate = -1;
				for (auto i = 0; i != int(pool.slots.size()); ++i) {
					if (i == slotIndex) {
						continue;
					}
					const auto &candidateSlot = pool.slots[i];
					if (candidateSlot.phase != MtProxy::LiveSlotPhase::Opening
						&& candidateSlot.phase
							!= MtProxy::LiveSlotPhase::Live) {
						continue;
					}
					const auto candidate = std::get_if<
						MtProxy::LiveSlotAttemptOwner>(&candidateSlot.owner);
					if (!candidate
						|| (candidate->attempt.runtimeId
								== _storage.foregroundRuntimeId
							&& candidate->attempt.use
								== MtProxy::EndpointUse::Main)
						|| (candidate->attempt.runtimeId
								== _storage.foregroundRuntimeId
							&& IsTransfer(candidate->attempt.use))) {
						continue;
					}
					if (alternate < 0) {
						alternate = i;
						continue;
					}
					const auto current = std::get_if<
						MtProxy::LiveSlotAttemptOwner>(
							&pool.slots[alternate].owner);
					if (current
						&& candidate->liveSince < current->liveSince) {
						alternate = i;
					}
				}
				if (alternate >= 0) {
					std::swap(
						pool.slots[alternate].entitlement,
						pool.slots[slotIndex].entitlement);
					reclaimIndex = alternate;
				}
			}
			closeSlotLocked(
				endpointKey,
				reclaimIndex,
				MtProxy::LiveSlotTicketOwner{
					.key = selected->key,
					.revision = selected->revision,
				},
				false,
				actions);
			updateQueuedStatusLocked(
				*selected,
				MtProxy::EndpointAdmissionWaitReason::ClosingSlot,
				MtProxy::FailureReason::None,
				0,
				0,
				actions);
			continue;
		}
		const auto fairnessEntitlement
			= entitlement == MtProxy::LiveSlotEntitlement::ForegroundMedia
			|| entitlement == MtProxy::LiveSlotEntitlement::ForegroundUpload
			|| entitlement == MtProxy::LiveSlotEntitlement::BackgroundMain;
		if (fairnessEntitlement
			&& slot.phase == MtProxy::LiveSlotPhase::Live
			&& owner->liveSince
			&& owner->liveSince + kLiveQuantum <= inputs.now
			&& !pool.fairnessClosing) {
			closeSlotLocked(
				endpointKey,
				slotIndex,
				MtProxy::LiveSlotTicketOwner{
					.key = selected->key,
					.revision = selected->revision,
				},
				true,
				actions);
			updateQueuedStatusLocked(
				*selected,
				MtProxy::EndpointAdmissionWaitReason::ClosingSlot,
				MtProxy::FailureReason::None,
				0,
				0,
				actions);
		}
	}

	while (true) {
		auto candidates = std::vector<Ticket*>();
		auto eligible = std::set<AdmissionTicketKey>();
		for (const auto &key : schedule->second.order) {
			const auto i = _tickets.find(key);
			if (i == end(_tickets)
				|| i->second->lifecycle != ProxySchedulerLifecycle::Queued
				|| successorSlotLocked(pool, *i->second)) {
				continue;
			}
			candidates.push_back(i->second.get());
			if (borrowableSlotLocked(
					endpointKey,
					state,
					pool,
					*i->second) >= 0) {
				eligible.emplace(key);
			}
		}
		const auto selected = selectLocked(
			candidates,
			eligible,
			state,
			inputs.now,
			schedule->second.fairness);
		if (!selected) {
			break;
		}
		const auto slotIndex = borrowableSlotLocked(
			endpointKey,
			state,
			pool,
			*selected);
		if (!reserveTicketLocked(
				endpointKey,
				slotIndex,
				*selected,
				state,
				inputs,
				actions)) {
			break;
		}
		AdvanceFairness(
			schedule->second.fairness,
			*selected,
			priorityForLocked(*selected, state, inputs.now));
	}

	if (!pool.fairnessClosing) {
		auto waiters = std::vector<Ticket*>();
		auto eligible = std::set<AdmissionTicketKey>();
		for (const auto &key : schedule->second.order) {
			const auto i = _tickets.find(key);
			if (i == end(_tickets)
				|| i->second->lifecycle != ProxySchedulerLifecycle::Queued
				|| i->second->use != MtProxy::EndpointUse::Main
				|| i->second->key.runtimeId
					== _storage.foregroundRuntimeId
				|| successorSlotLocked(pool, *i->second)) {
				continue;
			}
			waiters.push_back(i->second.get());
			if (baseEligibleLocked(*i->second, state)) {
				eligible.emplace(key);
			}
		}
		const auto selected = selectLocked(
			waiters,
			eligible,
			state,
			inputs.now,
			schedule->second.fairness);
		if (selected) {
			auto victim = -1;
			for (auto i = 0; i != int(pool.slots.size()); ++i) {
				const auto &slot = pool.slots[i];
				const auto owner = std::get_if<
					MtProxy::LiveSlotAttemptOwner>(&slot.owner);
				if (slot.phase != MtProxy::LiveSlotPhase::Live
					|| !owner
					|| owner->attempt.use != MtProxy::EndpointUse::Main
					|| owner->attempt.runtimeId
						== _storage.foregroundRuntimeId
					|| !owner->liveSince
					|| owner->liveSince + kLiveQuantum > inputs.now) {
					continue;
				}
				if (victim < 0) {
					victim = i;
					continue;
				}
				const auto current = std::get_if<
					MtProxy::LiveSlotAttemptOwner>(
						&pool.slots[victim].owner);
				if (current && owner->liveSince < current->liveSince) {
					victim = i;
				}
			}
			if (victim >= 0) {
				closeSlotLocked(
					endpointKey,
					victim,
					MtProxy::LiveSlotTicketOwner{
						.key = selected->key,
						.revision = selected->revision,
					},
					true,
					actions);
				updateQueuedStatusLocked(
					*selected,
					MtProxy::EndpointAdmissionWaitReason::ClosingSlot,
					MtProxy::FailureReason::None,
					0,
					0,
					actions);
			}
		}
	}

	for (const auto &key : schedule->second.order) {
		const auto i = _tickets.find(key);
		if (i == end(_tickets)
			|| i->second->lifecycle != ProxySchedulerLifecycle::Queued) {
			continue;
		}
		auto &ticket = *i->second;
		if (successorSlotLocked(pool, ticket)) {
			updateQueuedStatusLocked(
				ticket,
				MtProxy::EndpointAdmissionWaitReason::ClosingSlot,
				MtProxy::FailureReason::None,
				0,
				0,
				actions);
			continue;
		}
		if (!baseEligibleLocked(ticket, state)) {
			const auto verdict = state.canonicalVerdicts.find({
				.runtimeId = ticket.key.runtimeId,
				.proxyGeneration = ticket.proxyGeneration,
			});
			const auto blockedBy = (verdict != end(state.canonicalVerdicts))
				? verdict->second.reason
				: state.lastFailure;
			updateQueuedStatusLocked(
				ticket,
				MtProxy::EndpointAdmissionWaitReason::HealthOrNotBefore,
				blockedBy,
				0,
				0,
				actions);
			continue;
		}
		auto waitReason = MtProxy::EndpointAdmissionWaitReason::Slot;
		auto retryAfter = crl::time();
		const auto native = NativeEntitlement(
			ticket.key.runtimeId,
			ticket.use,
			_storage.foregroundRuntimeId);
		if (native) {
			const auto slotIndex = entitlementSlotLocked(pool, *native);
			if (slotIndex >= 0
				&& pool.slots[slotIndex].phase
					== MtProxy::LiveSlotPhase::Closing) {
				waitReason = MtProxy::EndpointAdmissionWaitReason::ClosingSlot;
			} else if (slotIndex >= 0
				&& pool.slots[slotIndex].phase
					== MtProxy::LiveSlotPhase::Live) {
				const auto owner = std::get_if<
					MtProxy::LiveSlotAttemptOwner>(
						&pool.slots[slotIndex].owner);
				if (owner && owner->liveSince) {
					retryAfter = std::max(
						crl::time(),
						owner->liveSince + kLiveQuantum - inputs.now);
				}
			}
		}
		updateQueuedStatusLocked(
			ticket,
			waitReason,
			MtProxy::FailureReason::None,
			retryAfter,
			retryAfter ? inputs.now + retryAfter : crl::time(),
			actions);
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
		if (!MtProxy::EndpointEmpty(ticket.endpoint)) {
			const auto pool = _pools.find(endpointKey);
			const auto state = _storage.states.find(endpointKey);
			if (pool == end(_pools)
				|| state == end(_storage.states)
				|| !baseEligibleLocked(ticket, state->second)
				|| !reservationCurrentLocked(ticket, pool->second)) {
				continue;
			}
		}
		ticket.lifecycle = ProxySchedulerLifecycle::Granted;
		ticket.retryAfter = 0;
		ticket.waitReason = MtProxy::EndpointAdmissionWaitReason::None;
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
			ticket.waitReason = MtProxy::EndpointAdmissionWaitReason::None;
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
	_pools.try_emplace(endpointKey);
	DeferEndpointCleanup(
		actions,
		MtProxy::PruneExpiredEndpointStateDeferred(state, inputs.now));
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
	auto wakeAt = crl::time();
	const auto consider = [&](crl::time boundary) {
		if (boundary > inputs.now
			&& (!wakeAt || boundary < wakeAt)) {
			wakeAt = boundary;
		}
	};
	for (const auto &entry : _tickets) {
		const auto &ticket = *entry.second;
		if (ticket.lifecycle == ProxySchedulerLifecycle::Scheduled) {
			consider(ticket.scheduledOpenAt);
		} else if (ticket.lifecycle == ProxySchedulerLifecycle::Queued) {
			consider(ticket.reevaluateAt);
		}
	}
	for (const auto &[endpointKey, pool] : _pools) {
		const auto schedule = _endpoints.find(endpointKey);
		if (schedule == end(_endpoints)) {
			continue;
		}
		for (const auto &slot : pool.slots) {
			if (slot.phase != MtProxy::LiveSlotPhase::Live) {
				continue;
			}
			const auto owner = std::get_if<MtProxy::LiveSlotAttemptOwner>(
				&slot.owner);
			if (!owner || !owner->liveSince) {
				continue;
			}
			auto demanded = false;
			for (const auto &key : schedule->second.order) {
				const auto ticket = _tickets.find(key);
				if (ticket == end(_tickets)
					|| ticket->second->lifecycle
						!= ProxySchedulerLifecycle::Queued) {
					continue;
				}
				const auto sameTransfer = IsTransfer(owner->attempt.use)
					&& ticket->second->use == owner->attempt.use
					&& ticket->second->key.runtimeId
						== owner->attempt.runtimeId;
				const auto backgroundMain
					= owner->attempt.use == MtProxy::EndpointUse::Main
					&& owner->attempt.runtimeId
						!= _storage.foregroundRuntimeId
					&& ticket->second->use
						== MtProxy::EndpointUse::Main
					&& ticket->second->key.runtimeId
						!= _storage.foregroundRuntimeId;
				if (sameTransfer || backgroundMain) {
					demanded = true;
					break;
				}
			}
			if (demanded) {
				consider(owner->liveSince + kLiveQuantum);
			}
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
	auto inputs = prepareInputs();
	auto actions = Actions();
	{
		QMutexLocker lock(&_storage.mutex);
		if (!_storage.runtimes.contains(runtimeId)) {
			return;
		}
		auto affected = std::set<QString>();
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
		closeMatchingAttemptsLocked(
			[=](const ProxyConnectionAttempt &attempt) {
				return attempt.runtimeId == runtimeId;
			},
			actions);
		for (const auto &entry : _pools) {
			affected.emplace(entry.first);
		}
		for (const auto &endpointKey : affected) {
			drainEndpointLocked(endpointKey, inputs, actions);
		}
		updateWakeLocked(inputs, actions);
	}
	actions.run();
}

void EndpointAdmissionArbiter::Private::unregisterRuntime(
		ProxyRuntimeId runtimeId) {
	if (!runtimeId) {
		return;
	}
	auto inputs = prepareInputs();
	auto actions = Actions();
	{
		QMutexLocker lock(&_storage.mutex);
		closeMatchingAttemptsLocked(
			[=](const ProxyConnectionAttempt &attempt) {
				return attempt.runtimeId == runtimeId;
			},
			actions);
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
			}
		}
		for (const auto &key : cancelled) {
			cancelTicketLocked(key, 0, actions);
		}
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
			if (_endpoints.contains(endpointKey)) {
				drainEndpointLocked(endpointKey, inputs, actions);
			}
		}
		clearWakeLocked(true);
		updateWakeLocked(inputs, actions);
	}
	actions.run();
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
	ticket->reclaim = std::move(request.reclaim);
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
			auto &stored = *_tickets.emplace(
				key,
				std::move(ticket)).first->second;
			postStatusLocked(stored, actions);
			drainEndpointLocked(stored.endpointKey, inputs, actions);
			updateWakeLocked(inputs, actions);
			result.revision = revision;
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
		AdmissionTicketKey key,
		uint64 revision) {
	if (!key.runtimeId || !key.ticketId || !revision) {
		return;
	}
	auto inputs = prepareInputs();
	auto actions = Actions();
	{
		QMutexLocker lock(&_storage.mutex);
		const auto ticket = _tickets.find(key);
		if (ticket != end(_tickets)
			&& ticket->second->revision == revision) {
			const auto endpointKey = ticket->second->endpointKey;
			cancelTicketLocked(key, revision, actions);
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
	auto inputs = prepareInputs();
	auto actions = Actions();
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
		auto affected = std::set<QString>();
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
			if (ticket != end(_tickets)) {
				postGenerationCancelledStatusLocked(
					*ticket->second,
					actions);
			}
			cancelTicketLocked(key, 0, actions);
		}
		closeMatchingAttemptsLocked(
			[=](const ProxyConnectionAttempt &attempt) {
				return attempt.runtimeId == runtimeId
					&& attempt.proxyGeneration < proxyGeneration;
			},
			actions);
		for (const auto &entry : _pools) {
			affected.emplace(entry.first);
		}
		for (const auto &endpointKey : affected) {
			drainEndpointLocked(endpointKey, inputs, actions);
		}
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

void EndpointAdmissionArbiter::Private::reevaluate(
		AdmissionTicketKey key,
		uint64 revision) {
	if (!key.runtimeId || !key.ticketId || !revision) {
		return;
	}
	auto inputs = prepareInputs();
	auto actions = Actions();
	{
		QMutexLocker lock(&_storage.mutex);
		const auto ticket = _tickets.find(key);
		if (ticket == end(_tickets)
			|| ticket->second->revision != revision) {
			return;
		}
		drainEndpointLocked(ticket->second->endpointKey, inputs, actions);
		updateWakeLocked(inputs, actions);
	}
	actions.run();
}

void EndpointAdmissionArbiter::Private::markTransportReady(
		const MtProxy::LiveSlotKey &slotKey,
		const ProxyConnectionAttempt &attempt) {
	if (slotKey.endpointKey.isEmpty()
		|| slotKey.index < 0
		|| !slotKey.incarnation) {
		return;
	}
	auto inputs = prepareInputs();
	auto actions = Actions();
	{
		QMutexLocker lock(&_storage.mutex);
		const auto pool = _pools.find(slotKey.endpointKey);
		if (pool == end(_pools)
			|| slotKey.index >= int(pool->second.slots.size())) {
			return;
		}
		auto &slot = pool->second.slots[slotKey.index];
		auto owner = std::get_if<MtProxy::LiveSlotAttemptOwner>(&slot.owner);
		if (slot.phase != MtProxy::LiveSlotPhase::Opening
			|| slot.incarnation != slotKey.incarnation
			|| !owner
			|| !AttemptOwnerMatches(*owner, attempt)) {
			return;
		}
		slot.phase = MtProxy::LiveSlotPhase::Live;
		owner->liveSince = inputs.now;
		drainEndpointLocked(slotKey.endpointKey, inputs, actions);
		updateWakeLocked(inputs, actions);
	}
	actions.run();
}

void EndpointAdmissionArbiter::Private::releaseLiveSlot(
		const MtProxy::LiveSlotKey &slotKey,
		const ProxyConnectionAttempt &attempt) {
	if (slotKey.endpointKey.isEmpty()
		|| slotKey.index < 0
		|| !slotKey.incarnation) {
		return;
	}
	auto inputs = prepareInputs();
	auto actions = Actions();
	{
		QMutexLocker lock(&_storage.mutex);
		const auto pool = _pools.find(slotKey.endpointKey);
		if (pool == end(_pools)
			|| slotKey.index >= int(pool->second.slots.size())) {
			return;
		}
		auto &slot = pool->second.slots[slotKey.index];
		if (slot.incarnation != slotKey.incarnation) {
			return;
		}
		auto successor = std::optional<MtProxy::LiveSlotTicketOwner>();
		if (slot.phase == MtProxy::LiveSlotPhase::Closing) {
			const auto closing = std::get_if<
				MtProxy::LiveSlotClosingState>(&slot.owner);
			if (!closing
				|| !AttemptOwnerMatches(closing->incumbent, attempt)) {
				return;
			}
			successor = closing->pendingSuccessor;
			if (pool->second.fairnessClosing
				&& *pool->second.fairnessClosing == slotKey) {
				pool->second.fairnessClosing.reset();
			}
		} else if (slot.phase == MtProxy::LiveSlotPhase::Opening
			|| slot.phase == MtProxy::LiveSlotPhase::Live) {
			const auto owner = std::get_if<MtProxy::LiveSlotAttemptOwner>(
				&slot.owner);
			if (!owner || !AttemptOwnerMatches(*owner, attempt)) {
				return;
			}
		} else {
			return;
		}
		slot.phase = MtProxy::LiveSlotPhase::Empty;
		slot.owner = std::monostate();
		if (successor) {
			const auto ticket = _tickets.find(successor->key);
			const auto state = _storage.states.find(slotKey.endpointKey);
			if (ticket != end(_tickets)
				&& ticket->second->revision == successor->revision
				&& ticket->second->lifecycle
					== ProxySchedulerLifecycle::Queued
				&& state != end(_storage.states)
				&& slotBorrowableLocked(
					slotKey.endpointKey,
					state->second,
					pool->second,
					*ticket->second,
					slotKey.index)) {
				static_cast<void>(reserveTicketLocked(
					slotKey.endpointKey,
					slotKey.index,
					*ticket->second,
					state->second,
					inputs,
					actions));
			}
		}
		drainEndpointLocked(slotKey.endpointKey, inputs, actions);
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
			.waitReason = ticket.waitReason,
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
			|| lifecycle != ProxySchedulerLifecycle::Granted) {
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
		const auto schedule = _endpoints.find(endpointKey);
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
		const auto pool = _pools.find(endpointKey);
		const auto reserved = unscoped
			|| (pool != end(_pools)
				&& reservationCurrentLocked(ticket, pool->second));
		if (!context
			|| !ticket.owner
			|| !runtimeLiveLocked(key.runtimeId)
			|| !traceCurrent
			|| !current
			|| !reserved) {
			cancelTicketLocked(key, revision, actions);
			drainEndpointLocked(endpointKey, inputs, actions);
			updateWakeLocked(inputs, actions);
		} else if (!unscoped
			&& !baseEligibleLocked(ticket, state->second)) {
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
			const auto reduction = (!unscoped && ticket.reservationId)
				? MtProxy::CommitOpenSlot(
					pool->second.openings,
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
					pool->second.openings = reduction.schedule;
				}
				auto admission = unscoped
					? std::optional<MtProxy::Admission>(MtProxy::Admission())
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
								.proxyGeneration = ticket.proxyGeneration,
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
					auto slotKey = MtProxy::LiveSlotKey();
					if (!unscoped) {
						const auto slotIndex = reservedSlotLocked(
							pool->second,
							ticket);
						Assert(slotIndex >= 0);
						auto &slot = pool->second.slots[slotIndex];
						slotKey = SlotKey(endpointKey, slotIndex, slot);
						slot.phase = MtProxy::LiveSlotPhase::Opening;
						slot.owner = MtProxy::LiveSlotAttemptOwner{
							.attempt = attempt,
							.owner = ticket.owner,
							.reclaim = std::move(ticket.reclaim),
						};
					}
					if (trace != end(_storage.activeTraces)) {
						trace->second = attempt;
					}
					if (!unscoped && schedule != end(_endpoints)) {
						AdvanceFairness(
							schedule->second.fairness,
							ticket,
							priorityForLocked(
								ticket,
								state->second,
								inputs.now));
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
						.slotKey = slotKey,
						.proxyGeneration = ticket.proxyGeneration,
						.endpoint = ticket.endpoint,
						.use = ticket.use,
						.acceptedRecoveryToken = acceptedRecoveryToken,
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
		AdmissionTicketKey key,
		uint64 revision) {
	_private->ownerDestroyed(key, revision);
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

void EndpointAdmissionArbiter::reevaluate(
		AdmissionTicketKey key,
		uint64 revision) {
	_private->reevaluate(key, revision);
}

void EndpointAdmissionArbiter::markTransportReady(
		const MtProxy::LiveSlotKey &slotKey,
		const ProxyConnectionAttempt &attempt) {
	_private->markTransportReady(slotKey, attempt);
}

void EndpointAdmissionArbiter::releaseLiveSlot(
		const MtProxy::LiveSlotKey &slotKey,
		const ProxyConnectionAttempt &attempt) {
	_private->releaseLiveSlot(slotKey, attempt);
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
