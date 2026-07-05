/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "mtproto/proxy/connection_broker.h"

#include "mtproto/proxy/diagnostics.h"
#include "mtproto/proxy/mtproxy/open_scheduler.h"
#include "base/algorithm.h"

#include <QtCore/QTimer>

#include <algorithm>
#include <array>
#include <deque>
#include <limits>
#include <optional>

namespace MTP::details {
namespace {

constexpr auto kFallbackQueuedRetry = crl::time(1000);
constexpr auto kQueuePriorityOrder = std::array{
	MtProxy::EndpointUse::Main,
	MtProxy::EndpointUse::ProxyCheck,
	MtProxy::EndpointUse::Media,
	MtProxy::EndpointUse::Upload,
};

[[nodiscard]] int TimerDelay(crl::time delay) {
	return int(std::clamp(
		delay,
		crl::time(0),
		crl::time(std::numeric_limits<int>::max())));
}

} // namespace

struct ConnectionBroker::RequestState {
	ConnectionTicketId id = 0;
	ConnectionRequest request;
	std::optional<MtProxy::Admission> admission;
	crl::time createdAt = 0;
	bool active = true;
	bool queuedNotified = false;
	bool startAfterNotified = false;
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


ConnectionTicket::ConnectionTicket(ConnectionTicketId id) : _id(id) {
}

ConnectionTicket::ConnectionTicket(ConnectionTicket &&other) noexcept
: _id(base::take(other._id)) {
}

ConnectionTicket &ConnectionTicket::operator=(
		ConnectionTicket &&other) noexcept {
	if (this != &other) {
		cancel();
		_id = base::take(other._id);
	}
	return *this;
}

ConnectionTicket::~ConnectionTicket() {
	cancel();
}

void ConnectionTicket::cancel() {
	if (_id) {
		ConnectionBroker::Instance().cancel(base::take(_id));
	}
}

ConnectionTicketId ConnectionTicket::id() const {
	return _id;
}

ConnectionTicket::operator bool() const {
	return _id != 0;
}

ConnectionBroker &ConnectionBroker::Instance() {
	static auto result = ConnectionBroker();
	return result;
}

ConnectionBroker::ConnectionBroker()
: _mainQueue(std::make_unique<EndpointQueue>(MtProxy::EndpointUse::Main))
, _mediaQueue(std::make_unique<EndpointQueue>(MtProxy::EndpointUse::Media))
, _uploadQueue(std::make_unique<EndpointQueue>(MtProxy::EndpointUse::Upload))
, _proxyCheckQueue(
	std::make_unique<EndpointQueue>(MtProxy::EndpointUse::ProxyCheck)) {
}

ConnectionBroker::~ConnectionBroker() = default;

ConnectionTicket ConnectionBroker::request(ConnectionRequest request) {
	if (!request.context || !request.start) {
		return ConnectionTicket();
	}
	const auto state = std::make_shared<RequestState>();
	{
		QMutexLocker lock(&_mutex);
		state->id = ++_lastTicketId;
		state->createdAt = crl::now();
		state->request = std::move(request);
		queueFor(state->request.use).pending.push_back(state);
	}
	scheduleDrain(state, 0);
	return ConnectionTicket(state->id);
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
	while (true) {
		auto state = std::shared_ptr<RequestState>();
		auto use = MtProxy::EndpointUse::Main;
		{
			QMutexLocker lock(&_mutex);
			for (const auto candidateUse : kQueuePriorityOrder) {
				auto &queue = queueFor(candidateUse);
				while (!queue.pending.empty()) {
					const auto &front = queue.pending.front();
					if (front->active && front->request.context) {
						state = front;
						use = candidateUse;
						break;
					}
					front->active = false;
					queue.pending.pop_front();
				}
				if (state) {
					break;
				}
			}
			if (!state || state->admission || state->startScheduled) {
				return;
			}
		}

		if (MtProxy::EndpointEmpty(state->request.endpoint)) {
			scheduleStart(state, state->request.notBefore);
			return;
		}

		auto admission = MtProxy::EndpointHealth::Instance().admit({
			.endpoint = state->request.endpoint,
			.use = state->request.use,
			.stealth = state->request.stealth,
			.configuredTlsProfile = state->request.configuredTlsProfile,
		});
		if (admission.action == MtProxy::AdmissionAction::StartNow) {
			const auto openDelay = MtProxy::ReserveOpenSlot(
				state->request.endpoint,
				state->request.connectionPattern,
				state->request.notBefore);
			auto keepAdmission = false;
			{
				QMutexLocker lock(&_mutex);
				const auto &queue = queueFor(use);
				keepAdmission = !queue.pending.empty()
					&& queue.pending.front() == state
					&& state->active
					&& state->request.context;
				if (keepAdmission) {
					state->admission = std::move(admission);
				}
			}
			if (!keepAdmission) {
				return;
			}
			if (openDelay > 0 && !state->startAfterNotified) {
				state->startAfterNotified = true;
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
		if (!state->queuedNotified) {
			state->queuedNotified = true;
			notify(state, {
				.action = ConnectionBrokerAction::Queued,
				.retryAfter = delay,
				.blockedBy = admission.blockedBy,
			});
		}
		scheduleDrain(state, delay);
		return;
	}
}

void ConnectionBroker::scheduleDrain(
		const std::shared_ptr<RequestState> &state,
		crl::time delay) {
	if (!state->request.context) {
		cancel(state->id);
		return;
	}
	QTimer::singleShot(TimerDelay(delay), state->request.context, [=] {
		if (state->active) {
			ConnectionBroker::Instance().drain();
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
	state->startScheduled = true;
	QTimer::singleShot(TimerDelay(delay), state->request.context, [=] {
		if (state->active) {
			ConnectionBroker::Instance().start(state->id);
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

	reportAdmissionEvent(
		state,
		ProxyDiagnosticsPhase::AdmissionStarted,
		{},
		u"mtproxy admission started"_q);
	auto request = std::move(state->request);
	auto admission = std::move(state->admission);
	auto start = ConnectionStart();
	start.ticketId = id;
	start.endpoint = request.endpoint;
	start.use = request.use;
	start.stealth = admission ? admission->stealth : request.stealth;
	start.effectiveTlsProfile = admission
		? admission->effectiveTlsProfile
		: request.configuredTlsProfile;
	start.attemptId = admission ? admission->attemptId : 0;
	start.proxyEpoch = admission ? admission->proxyEpoch : 0;
	if (admission) {
		start.lease = std::move(admission->lease);
	}
	if (request.context && request.start) {
		request.start(std::move(start));
	}
	drain();
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
	if (!state->request.instance || !state->request.proxy) {
		return;
	}
	const auto profile = state->admission
		? state->admission->effectiveTlsProfile
		: state->request.configuredTlsProfile;
	ReportProxyEvent(not_null<MTP::Instance*>(state->request.instance), {
		.phase = phase,
		.mtproxyReason = MtProxy::ToProxyMtproxyTerminalReason(
			decision.blockedBy),
		.terminalUntil = decision.retryAfter > 0
			? (crl::now() + decision.retryAfter)
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
		.profile = ProxyDiagnosticsTlsProfileName(profile),
		.recipeLevel = int(state->request.stealth.level),
		.queueMs = state->createdAt
			? (crl::now() - state->createdAt)
			: crl::time(0),
	});
}

} // namespace MTP::details
