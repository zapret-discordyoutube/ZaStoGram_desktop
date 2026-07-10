/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "mtproto/proxy/connection_broker.h"

#include "base/algorithm.h"
#include "mtproto/proxy/mtproxy/open_scheduler.h"
#include "mtproto/proxy/control_plane.h"
#include "mtproto/proxy/diagnostics.h"
#include "mtproto/proxy/proxy_endpoint_context.h"
#include "mtproto/proxy/proxy_services.h"
#include "mtproto/runtime/runtime_environment.h"

#include <algorithm>
#include <array>
#include <deque>
#include <optional>
#include <vector>

namespace MTP::details {
namespace {

constexpr auto kFallbackQueuedRetry = crl::time(1000);
constexpr auto kQueuePriorityOrder = std::array{
	MtProxy::EndpointUse::Main,
	MtProxy::EndpointUse::ProxyCheck,
	MtProxy::EndpointUse::Media,
	MtProxy::EndpointUse::Upload,
};

} // namespace

struct ConnectionBroker::RequestState {
	ConnectionTicketId id = 0;
	ProxyTraceId traceId = 0;
	uint64 proxyGeneration = 0;
	ConnectionRequest request;
	std::optional<ProxyAdmissionDecision> admission;
	MtProxy::OpenSlotReservation openSlot;
	crl::time createdAt = 0;
	crl::time openRetryAt = 0;
	bool active = true;
	bool queuedNotified = false;
	bool startAfterNotified = false;
	bool admissionInProgress = false;
	bool openRetryScheduled = false;
	bool startScheduled = false;
};

struct ConnectionBroker::EndpointQueue {
	explicit EndpointQueue(MtProxy::EndpointUse use) : use(use) {
	}

	MtProxy::EndpointUse use = MtProxy::EndpointUse::Main;
	std::deque<std::shared_ptr<RequestState>> pending;
};

[[nodiscard]] QString CanonicalText(const MtProxy::EndpointId &endpoint) {
	return ProxyDiagnosticsEndpointText(
		endpoint.canonical.originalHost,
		endpoint.canonical.port);
}

[[nodiscard]] QString RouteText(const MtProxy::EndpointId &endpoint) {
	return ProxyDiagnosticsEndpointText(
		endpoint.route.address,
		endpoint.route.port);
}

[[nodiscard]] QString EndpointHash(const MtProxy::EndpointId &endpoint) {
	return ProxyDiagnosticsKeyHash(MtProxy::EndpointKey(endpoint.canonical));
}

ConnectionTicket::ConnectionTicket(
	ConnectionBroker *broker,
	ConnectionTicketId id)
: _broker(broker)
, _id(id) {
}

ConnectionTicket::ConnectionTicket(ConnectionTicket &&other) noexcept
: _broker(base::take(other._broker))
, _id(base::take(other._id)) {
}

ConnectionTicket &ConnectionTicket::operator=(
		ConnectionTicket &&other) noexcept {
	if (this != &other) {
		cancel();
		_broker = base::take(other._broker);
		_id = base::take(other._id);
	}
	return *this;
}

ConnectionTicket::~ConnectionTicket() {
	cancel();
}

void ConnectionTicket::cancel() {
	if (_broker && _id) {
		_broker->cancel(base::take(_id));
	}
	_broker = nullptr;
}

ConnectionTicketId ConnectionTicket::id() const {
	return _id;
}

ConnectionTicket::operator bool() const {
	return _id != 0;
}

ConnectionBroker::ConnectionBroker(not_null<RuntimeEnvironment*> runtime)
: _mainQueue(std::make_unique<EndpointQueue>(MtProxy::EndpointUse::Main))
, _mediaQueue(std::make_unique<EndpointQueue>(MtProxy::EndpointUse::Media))
, _uploadQueue(std::make_unique<EndpointQueue>(MtProxy::EndpointUse::Upload))
, _proxyCheckQueue(
	std::make_unique<EndpointQueue>(MtProxy::EndpointUse::ProxyCheck))
, _runtime(runtime) {
}

ConnectionBroker::~ConnectionBroker() {
	cancelByOwnerDestruction();
}

void ConnectionBroker::cancelByOwnerDestruction() {
	auto cancelled = std::vector<std::shared_ptr<RequestState>>();
	{
		QMutexLocker lock(&_mutex);
		for (const auto queue : {
				_mainQueue.get(),
				_proxyCheckQueue.get(),
				_mediaQueue.get(),
				_uploadQueue.get() }) {
			for (const auto &state : queue->pending) {
				state->active = false;
				cancelled.push_back(state);
			}
			queue->pending.clear();
		}
	}
	for (const auto &state : cancelled) {
		reportAdmissionEvent(
			state,
			ProxyDiagnosticsPhase::AdmissionCancelled,
			{},
			u"mtproxy admission cancelled by owner destruction"_q);
		releaseAdmission(state);
	}
}

ConnectionTicket ConnectionBroker::request(ConnectionRequest request) {
	if (!request.context || !request.start) {
		return ConnectionTicket();
	}
	const auto state = std::make_shared<RequestState>();
	{
		QMutexLocker lock(&_mutex);
		state->id = ++_lastTicketId;
		state->request = std::move(request);
		if (!MtProxy::EndpointEmpty(state->request.endpoint)) {
			state->traceId = _runtime->proxyEndpointContext().nextTraceId({
				.runtimeId = _runtime->proxyRuntimeId(),
				.ticketId = state->id,
				.proxyGeneration = state->request.proxyGeneration,
				.use = state->request.use,
			});
		}
		state->createdAt = _runtime->async().now();
		state->proxyGeneration = state->request.proxyGeneration;
		queueFor(state->request.use).pending.push_back(state);
	}
	scheduleDrain(state, 0);
	return ConnectionTicket(this, state->id);
}

void ConnectionBroker::cancel(ConnectionTicketId id) {
	if (!id) {
		return;
	}
	auto cancelled = std::shared_ptr<RequestState>();
	{
		QMutexLocker lock(&_mutex);
		for (const auto queue : {
				_mainQueue.get(),
				_proxyCheckQueue.get(),
				_mediaQueue.get(),
				_uploadQueue.get() }) {
			const auto i = std::find_if(
				begin(queue->pending),
				end(queue->pending),
				[=](const std::shared_ptr<RequestState> &state) {
					return state->id == id;
				});
			if (i != end(queue->pending)) {
				cancelled = *i;
				cancelled->active = false;
				queue->pending.erase(i);
				break;
			}
		}
	}
	if (cancelled) {
		reportAdmissionEvent(
			cancelled,
			ProxyDiagnosticsPhase::AdmissionCancelled,
			{},
			u"mtproxy admission cancelled"_q);
		releaseAdmission(cancelled);
	}
}

void ConnectionBroker::cancelByProxyGeneration(uint64 generation) {
	auto cancelled = std::vector<std::shared_ptr<RequestState>>();
	{
		QMutexLocker lock(&_mutex);
		for (const auto queue : {
				_mainQueue.get(),
				_proxyCheckQueue.get(),
				_mediaQueue.get(),
				_uploadQueue.get() }) {
			for (auto i = begin(queue->pending); i != end(queue->pending);) {
				const auto &state = *i;
				if (state->proxyGeneration < generation) {
					state->active = false;
					cancelled.push_back(state);
					i = queue->pending.erase(i);
				} else {
					++i;
				}
			}
		}
	}
	for (const auto &state : cancelled) {
		reportAdmissionEvent(
			state,
			ProxyDiagnosticsPhase::AdmissionCancelled,
			{},
			u"mtproxy admission cancelled by proxy switch"_q);
		releaseAdmission(state);
	}
}

ConnectionBroker::EndpointQueue &ConnectionBroker::queueFor(
		MtProxy::EndpointUse use) {
	switch (use) {
	case MtProxy::EndpointUse::Media:
		return *_mediaQueue;
	case MtProxy::EndpointUse::Upload:
		return *_uploadQueue;
	case MtProxy::EndpointUse::ProxyCheck:
		return *_proxyCheckQueue;
	case MtProxy::EndpointUse::Main:
		return *_mainQueue;
	}
	Unexpected("MtProxy::EndpointUse in ConnectionBroker::queueFor.");
}

void ConnectionBroker::drain() {
	// Each queue is drained independently: a Main request waiting out an
	// admission cooldown must not starve Media/Upload requests whose
	// endpoints are ready to start.
	for (const auto use : kQueuePriorityOrder) {
		drainQueue(use);
	}
}

void ConnectionBroker::drainQueue(MtProxy::EndpointUse use) {
	auto state = std::shared_ptr<RequestState>();
	auto openRetryAfter = crl::time(0);
	{
		QMutexLocker lock(&_mutex);
		auto &queue = queueFor(use);
		while (!queue.pending.empty()) {
			const auto &front = queue.pending.front();
			if (front->active && front->request.context) {
				state = front;
				break;
			}
			front->active = false;
			queue.pending.pop_front();
		}
		if (!state
			|| state->admission
			|| state->admissionInProgress
			|| state->startScheduled) {
			return;
		}
		const auto now = _runtime->async().now();
		if (state->openRetryAt > now) {
			if (state->openRetryScheduled) {
				return;
			}
			openRetryAfter = state->openRetryAt - now;
			state->openRetryScheduled = true;
		} else {
			state->openRetryAt = 0;
			state->openRetryScheduled = false;
			state->admissionInProgress = true;
		}
	}
	if (openRetryAfter > 0) {
		scheduleOpenRetry(state, openRetryAfter);
		return;
	}

	if (MtProxy::EndpointEmpty(state->request.endpoint)) {
		{
			QMutexLocker lock(&_mutex);
			state->admissionInProgress = false;
			if (!state->active
				|| !state->request.context
				|| state->startScheduled) {
				return;
			}
			state->startScheduled = true;
		}
		scheduleStart(state, state->request.notBefore);
		return;
	}

	auto admission = _runtime->proxyServices().control().admit({
		.endpoint = state->request.endpoint,
		.use = state->request.use,
		.runtimeId = _runtime->proxyRuntimeId(),
		.stealth = state->request.stealth,
		.configuredTlsProfile = state->request.configuredTlsProfile,
		.proxyGeneration = state->proxyGeneration,
	});
	if (admission.action == ProxyAdmissionAction::StartNow) {
		auto openSlot = IsProxyCheck(state->request.use)
			? MtProxy::OpenSlotReservation()
			: MtProxy::ReserveOpenSlot(
				_runtime,
				state->request.endpoint,
				admission.plan.admitted
					? admission.plan.stealth.connectionPattern
					: state->request.connectionPattern,
				state->request.notBefore);
		const auto openDelay = IsProxyCheck(state->request.use)
			? std::max(crl::time(0), state->request.notBefore)
			: openSlot.delay();
		if (!IsProxyCheck(state->request.use) && openDelay > 0) {
			auto keepQueued = false;
			auto notifyStartAfter = false;
			{
				QMutexLocker lock(&_mutex);
				const auto &queue = queueFor(use);
				keepQueued = !queue.pending.empty()
					&& queue.pending.front() == state
					&& state->active
					&& state->request.context;
				state->admissionInProgress = false;
				if (keepQueued) {
					state->request.notBefore = 0;
					state->openRetryAt = _runtime->async().now()
						+ openDelay;
					state->openRetryScheduled = true;
					state->admission = std::move(admission);
					state->openSlot = std::move(openSlot);
					notifyStartAfter = !state->startAfterNotified;
					if (notifyStartAfter) {
						state->startAfterNotified = true;
					}
				}
			}
			if (!keepQueued) {
				return;
			}
			if (notifyStartAfter) {
				notify(state, {
					.action = ConnectionBrokerAction::StartAfter,
					.retryAfter = openDelay,
				});
			}
			releaseAdmission(state);
			scheduleOpenRetry(state, openDelay);
			return;
		}
		auto keepAdmission = false;
		auto notifyStartAfter = false;
		{
			QMutexLocker lock(&_mutex);
			const auto &queue = queueFor(use);
			keepAdmission = !queue.pending.empty()
				&& queue.pending.front() == state
				&& state->active
				&& state->request.context;
			if (keepAdmission) {
				state->admission = std::move(admission);
				state->openSlot = std::move(openSlot);
				state->admissionInProgress = false;
				state->startScheduled = true;
				notifyStartAfter = (openDelay > 0)
					&& !state->startAfterNotified;
				if (notifyStartAfter) {
					state->startAfterNotified = true;
				}
			} else {
				state->admissionInProgress = false;
			}
		}
		if (!keepAdmission) {
			return;
		}
		if (notifyStartAfter) {
			notify(state, {
				.action = ConnectionBrokerAction::StartAfter,
				.retryAfter = openDelay,
			});
		}
		scheduleStart(state, openDelay);
		return;
	}

	const auto delay = admission.retryAfter > 0
		? admission.retryAfter
		: kFallbackQueuedRetry;
	auto keepQueued = false;
	auto notifyQueued = false;
	{
		QMutexLocker lock(&_mutex);
		const auto &queue = queueFor(use);
		keepQueued = !queue.pending.empty()
			&& queue.pending.front() == state
			&& state->active
			&& state->request.context;
		if (keepQueued) {
			state->admissionInProgress = false;
			notifyQueued = !state->queuedNotified;
			if (notifyQueued) {
				state->queuedNotified = true;
			}
		} else {
			state->admissionInProgress = false;
		}
	}
	if (!keepQueued) {
		return;
	}
	if (notifyQueued) {
		notify(state, {
			.action = ConnectionBrokerAction::Queued,
			.retryAfter = delay,
			.blockedBy = admission.blockedBy,
		});
	}
	scheduleDrain(state, delay);
}

void ConnectionBroker::scheduleDrain(
		const std::shared_ptr<RequestState> &state,
		crl::time delay) {
	if (!state->request.context) {
		cancel(state->id);
		return;
	}
	_runtime->async().singleShot(delay, state->request.context, [=] {
		if (state->active) {
			drain();
		}
	});
}

void ConnectionBroker::scheduleOpenRetry(
		const std::shared_ptr<RequestState> &state,
		crl::time delay) {
	if (!state->request.context) {
		cancel(state->id);
		return;
	}
	_runtime->async().singleShot(delay, state->request.context, [=] {
		state->openRetryScheduled = false;
		if (state->active) {
			drain();
		}
	});
}

void ConnectionBroker::scheduleStart(
		const std::shared_ptr<RequestState> &state,
		crl::time delay) {
	if (!state->request.context) {
		cancel(state->id);
		return;
	}
	_runtime->async().singleShot(delay, state->request.context, [=] {
		if (state->active) {
			start(state->id);
		}
	});
}

void ConnectionBroker::start(ConnectionTicketId id) {
	auto state = std::shared_ptr<RequestState>();
	{
		QMutexLocker lock(&_mutex);
		for (const auto queue : {
				_mainQueue.get(),
				_proxyCheckQueue.get(),
				_mediaQueue.get(),
				_uploadQueue.get() }) {
			const auto i = std::find_if(
				begin(queue->pending),
				end(queue->pending),
				[=](const std::shared_ptr<RequestState> &candidate) {
					return candidate->id == id;
				});
			if (i != end(queue->pending)) {
				state = *i;
				queue->pending.erase(i);
				break;
			}
		}
		if (!state || !state->active || !state->request.context) {
			return;
		}
		state->active = false;
	}
	state->openSlot.commit();

	reportAdmissionEvent(
		state,
		ProxyDiagnosticsPhase::AdmissionStarted,
		{},
		u"mtproxy admission started"_q);
	auto request = std::move(state->request);
	auto admission = std::move(state->admission);
	auto start = ConnectionStart();
	start.ticketId = id;
	start.proxyGeneration = admission
		? admission->proxyGeneration
		: state->proxyGeneration;
	start.endpoint = request.endpoint;
	start.use = request.use;
	start.stealth = admission ? admission->stealth : request.stealth;
	start.effectiveTlsProfile = admission
		? admission->effectiveTlsProfile
		: request.configuredTlsProfile;
	start.plan = admission ? admission->plan : MtProxyAttemptPlan();
	start.attemptId = admission ? admission->attemptId : 0;
	start.proxyEpoch = admission ? admission->proxyEpoch : 0;
	start.successEpoch = admission ? admission->successEpoch : 0;
	start.attemptStartedAt = admission ? admission->attemptStartedAt : 0;
	start.attempt = {
		.runtimeId = admission
			? admission->runtimeId
			: _runtime->proxyRuntimeId(),
		.traceId = state->traceId,
		.ticketId = id,
		.proxyGeneration = start.proxyGeneration,
		.proxyEpoch = start.proxyEpoch,
		.successEpoch = start.successEpoch,
		.attemptId = start.attemptId,
		.use = request.use,
	};
	_runtime->proxyEndpointContext().updateTraceAttempt(start.attempt);
	if (admission) {
		start.lease = std::move(admission->lease);
	}
	if (request.context && request.start) {
		request.start(std::move(start));
	}
	drain();
}

void ConnectionBroker::releaseAdmission(
		const std::shared_ptr<RequestState> &state) {
	if (!state) {
		return;
	}
	state->admissionInProgress = false;
	if (state->admission) {
		state->admission->lease.release();
		state->admission.reset();
	}
	state->openSlot.cancel();
}

void ConnectionBroker::notify(
		const std::shared_ptr<RequestState> &state,
		ConnectionBrokerDecision decision) {
	if (decision.action == ConnectionBrokerAction::Queued
		|| decision.action == ConnectionBrokerAction::StartAfter) {
		reportAdmissionEvent(
			state,
			ProxyDiagnosticsPhase::AdmissionQueued,
			decision,
			(decision.action == ConnectionBrokerAction::Queued)
				? u"mtproxy admission queued"_q
				: u"mtproxy start scheduled"_q);
	}
	if (state->request.context && state->request.status) {
		state->request.status(decision);
	}
}

void ConnectionBroker::reportAdmissionEvent(
		const std::shared_ptr<RequestState> &state,
		ProxyDiagnosticsPhase phase,
		ConnectionBrokerDecision decision,
		const QString &message) {
	if (!state->request.proxy) {
		return;
	}
	ReportProxyEvent(_runtime, {
		.phase = phase,
		.mtproxyReason = MtProxy::ToProxyMtproxyTerminalReason(
			decision.blockedBy),
		.attempt = {
			.runtimeId = _runtime->proxyRuntimeId(),
			.traceId = state->traceId,
			.ticketId = state->id,
			.proxyGeneration = state->proxyGeneration,
			.use = state->request.use,
		},
		.terminalUntil = decision.retryAfter > 0
			? (_runtime->async().now() + decision.retryAfter)
			: 0,
		.severity = (phase == ProxyDiagnosticsPhase::AdmissionStarted)
			? ProxyDiagnosticsSeverity::Info
			: ProxyDiagnosticsSeverity::Warning,
		.proxy = state->request.proxy,
		.transport = ProxyDiagnosticsTransportName(
			state->request.proxy.type,
			state->request.stealth.transport),
		.message = message,
		.canonical = CanonicalText(state->request.endpoint),
		.route = RouteText(state->request.endpoint),
		.proxyKeyHash = EndpointHash(state->request.endpoint),
		.configuredProfile = ProxyDiagnosticsTlsProfileName(
			state->request.configuredTlsProfile),
		.effectiveProfile = state->admission
			? ProxyDiagnosticsTlsProfileName(
				state->admission->plan.effectiveTlsProfile)
			: QString(),
		.recipeLevel = state->admission
			? std::make_optional(state->admission->plan.recipeLevel)
			: std::nullopt,
		.queueMs = state->createdAt
			? std::make_optional(
				_runtime->async().now() - state->createdAt)
			: std::nullopt,
	});
	if (phase == ProxyDiagnosticsPhase::AdmissionCancelled) {
		(void)ReportProxyAttemptSummary(_runtime, {
			.attempt = {
				.runtimeId = _runtime->proxyRuntimeId(),
				.traceId = state->traceId,
				.ticketId = state->id,
				.proxyGeneration = state->proxyGeneration,
				.use = state->request.use,
			},
			.severity = ProxyDiagnosticsSeverity::Warning,
			.proxy = state->request.proxy,
			.transport = ProxyDiagnosticsTransportName(
				state->request.proxy.type,
				state->request.stealth.transport),
			.message = message,
			.canonical = CanonicalText(state->request.endpoint),
			.route = RouteText(state->request.endpoint),
			.proxyKeyHash = EndpointHash(state->request.endpoint),
			.configuredProfile = ProxyDiagnosticsTlsProfileName(
				state->request.configuredTlsProfile),
			.effectiveProfile = state->admission
				? ProxyDiagnosticsTlsProfileName(
					state->admission->plan.effectiveTlsProfile)
				: QString(),
			.recipeLevel = state->admission
				? std::make_optional(state->admission->plan.recipeLevel)
				: std::nullopt,
			.closeOrigin = message.contains(u"proxy switch"_q)
				? ProxyCloseOrigin::ProxySwitch
				: message.contains(u"owner destruction"_q)
				? ProxyCloseOrigin::OwnerDestroyed
				: ProxyCloseOrigin::BrokerCancelled,
			.totalMs = state->createdAt
				? std::make_optional(
					_runtime->async().now() - state->createdAt)
				: std::nullopt,
		});
	}
}

} // namespace MTP::details
