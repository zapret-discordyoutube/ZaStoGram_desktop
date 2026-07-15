/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "mtproto/proxy/connection_broker.h"

#include "base/algorithm.h"
#include "mtproto/proxy/diagnostics.h"
#include "mtproto/proxy/endpoint_admission_arbiter.h"
#include "mtproto/runtime/runtime_environment.h"

#include <optional>

namespace MTP::details {
namespace {

struct AdmissionDiagnostics final {
	ProxyData proxy;
	MtProxy::EndpointId endpoint;
	MtProxy::EndpointUse use = MtProxy::EndpointUse::Main;
	ProxyStealthOptions stealth;
	ProxyTlsProfile configuredTlsProfile = ProxyTlsProfile::Auto;
	AdmissionTicketKey key;
	ProxyTraceId traceId = 0;
	uint64 proxyGeneration = 0;
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

[[nodiscard]] ConnectionBrokerDecision DecisionFromUpdate(
		const EndpointAdmissionUpdate &update) {
	auto result = ConnectionBrokerDecision{
		.retryAfter = update.retryAfter,
		.blockedBy = update.blockedBy,
	};
	switch (update.lifecycle) {
	case ProxySchedulerLifecycle::Queued:
		result.action = ConnectionBrokerAction::Queued;
		break;
	case ProxySchedulerLifecycle::Scheduled:
		result.action = ConnectionBrokerAction::StartAfter;
		break;
	case ProxySchedulerLifecycle::Granted:
	case ProxySchedulerLifecycle::HandedOff:
		result.action = ConnectionBrokerAction::StartNow;
		break;
	case ProxySchedulerLifecycle::None:
	case ProxySchedulerLifecycle::Cancelled:
		result.action = ConnectionBrokerAction::Rejected;
		break;
	}
	return result;
}

void ReportAdmissionEvent(
		RuntimeEnvironment *runtime,
		const AdmissionDiagnostics &diagnostics,
		ProxyDiagnosticsPhase phase,
		ConnectionBrokerDecision decision,
		const MtProxy::Admission *admission,
		crl::time enqueuedAt,
		const QString &message) {
	if (!runtime || !diagnostics.proxy) {
		return;
	}
	const auto now = runtime->async().now();
	ReportProxyEvent(not_null{ runtime }, {
		.phase = phase,
		.mtproxyReason = MtProxy::ToProxyMtproxyTerminalReason(
			decision.blockedBy),
		.attempt = {
			.runtimeId = diagnostics.key.runtimeId,
			.traceId = diagnostics.traceId,
			.ticketId = diagnostics.key.ticketId,
			.proxyGeneration = diagnostics.proxyGeneration,
			.use = diagnostics.use,
			.ticketKey = diagnostics.key,
		},
		.terminalUntil = decision.retryAfter > 0
			? (now + decision.retryAfter)
			: 0,
		.severity = (phase == ProxyDiagnosticsPhase::AdmissionStarted)
			? ProxyDiagnosticsSeverity::Info
			: ProxyDiagnosticsSeverity::Warning,
		.proxy = diagnostics.proxy,
		.transport = ProxyDiagnosticsTransportName(
			diagnostics.proxy.type,
			diagnostics.stealth.transport),
		.message = message,
		.canonical = CanonicalText(diagnostics.endpoint),
		.route = RouteText(diagnostics.endpoint),
		.proxyKeyHash = EndpointHash(diagnostics.endpoint),
		.configuredProfile = ProxyDiagnosticsTlsProfileName(
			diagnostics.configuredTlsProfile),
		.effectiveProfile = (admission && admission->plan.admitted)
			? ProxyDiagnosticsTlsProfileName(
				admission->plan.effectiveTlsProfile)
			: QString(),
		.recipeLevel = (admission && admission->plan.admitted)
			? std::make_optional(admission->plan.recipeLevel)
			: std::nullopt,
		.queueMs = enqueuedAt
			? std::make_optional(now - enqueuedAt)
			: std::nullopt,
	});
}

} // namespace

ConnectionTicket::ConnectionTicket(
		std::weak_ptr<ProxyEndpointContext> context,
		AdmissionTicketKey key,
		MtProxy::MainRecoveryToken acceptedRecoveryToken)
: _context(std::move(context))
, _key(key)
, _acceptedRecoveryToken(acceptedRecoveryToken) {
}

ConnectionTicket::ConnectionTicket(ConnectionTicket &&other) noexcept
: _context(std::move(other._context))
, _key(base::take(other._key))
, _acceptedRecoveryToken(base::take(other._acceptedRecoveryToken)) {
}

ConnectionTicket &ConnectionTicket::operator=(
		ConnectionTicket &&other) noexcept {
	if (this != &other) {
		cancel();
		_context = std::move(other._context);
		_key = base::take(other._key);
		_acceptedRecoveryToken = base::take(
			other._acceptedRecoveryToken);
	}
	return *this;
}

ConnectionTicket::~ConnectionTicket() {
	cancel();
}

void ConnectionTicket::cancel() {
	const auto key = base::take(_key);
	if (key.runtimeId && key.ticketId) {
		if (const auto context = _context.lock()) {
			context->endpointAdmissionArbiter().cancel(key);
		}
	}
	_acceptedRecoveryToken = {};
	_context.reset();
}

ConnectionTicketId ConnectionTicket::id() const {
	return _key.ticketId;
}

MtProxy::MainRecoveryToken ConnectionTicket::acceptedRecoveryToken() const {
	return _acceptedRecoveryToken;
}

ConnectionTicket::operator bool() const {
	return _key.ticketId != 0;
}

ConnectionBroker::ConnectionBroker(not_null<RuntimeEnvironment*> runtime)
: _runtime(runtime)
, _endpointContext(runtime->proxyEndpointContextShared()) {
}

ConnectionBroker::~ConnectionBroker() {
	cancelByOwnerDestruction();
}

ConnectionTicket ConnectionBroker::request(ConnectionRequest request) {
	if (!request.context || !request.start) {
		return {};
	}
	const auto key = AdmissionTicketKey{
		.runtimeId = _runtime->proxyRuntimeId(),
		.ticketId = ++_lastTicketId,
	};
	const auto weak = std::weak_ptr<ProxyEndpointContext>(_endpointContext);
	const auto ownerDestroyed = QObject::connect(
		request.context,
		&QObject::destroyed,
		[weak, key] {
			if (const auto context = weak.lock()) {
				context->endpointAdmissionArbiter().ownerDestroyed(key);
			}
		});
	if (!ownerDestroyed) {
		return {};
	}
	const auto traceId = MtProxy::EndpointEmpty(request.endpoint)
		? ProxyTraceId()
		: _endpointContext->nextTraceId({
			.runtimeId = key.runtimeId,
			.ticketId = key.ticketId,
			.proxyGeneration = request.proxyGeneration,
			.use = request.use,
			.ticketKey = key,
		});
	const auto diagnostics = std::make_shared<const AdmissionDiagnostics>(
		AdmissionDiagnostics{
			.proxy = request.proxy,
			.endpoint = request.endpoint,
			.use = request.use,
			.stealth = request.stealth,
			.configuredTlsProfile = request.configuredTlsProfile,
			.key = key,
			.traceId = traceId,
			.proxyGeneration = request.proxyGeneration,
		});
	const auto runtime = QPointer<RuntimeEnvironment>(_runtime.get());
	const auto accepted = _endpointContext->endpointAdmissionArbiter().enqueue(
		weak,
		{
			.key = key,
			.proxyGeneration = request.proxyGeneration,
			.endpoint = request.endpoint,
			.use = request.use,
			.requestedRecoveryToken = request.requestedRecoveryToken,
			.stealth = request.stealth,
			.configuredTlsProfile = request.configuredTlsProfile,
			.notBefore = request.notBefore,
			.traceId = traceId,
			.owner = request.context,
			.ownerDestroyed = ownerDestroyed,
			.laneControl = std::move(request.laneControl),
			.status = [
				runtime,
				diagnostics,
				status = std::move(request.status)
			](EndpointAdmissionUpdate update) mutable {
				const auto decision = DecisionFromUpdate(update);
				if (update.lifecycle == ProxySchedulerLifecycle::Queued
					|| update.lifecycle
						== ProxySchedulerLifecycle::Scheduled) {
					ReportAdmissionEvent(
						runtime.data(),
						*diagnostics,
						ProxyDiagnosticsPhase::AdmissionQueued,
						decision,
						nullptr,
						update.enqueuedAt,
						(update.lifecycle
								== ProxySchedulerLifecycle::Queued)
							? u"mtproxy admission queued"_q
							: u"mtproxy start scheduled"_q);
				}
				if (status) {
					status(decision);
				}
			},
			.grant = [
				runtime,
				diagnostics,
				start = std::move(request.start)
			](EndpointAdmissionGrant grant) mutable {
				auto admission = std::move(grant.admission);
				ReportAdmissionEvent(
					runtime.data(),
					*diagnostics,
					ProxyDiagnosticsPhase::AdmissionStarted,
					{},
					&admission,
					grant.enqueuedAt,
					u"mtproxy admission started"_q);
				const auto admitted = admission.plan.admitted;
				auto value = ConnectionStart{
					.ticketId = grant.key.ticketId,
					.attempt = grant.attempt,
					.acceptedRecoveryToken
						= grant.acceptedRecoveryToken,
					.proxyGeneration = grant.proxyGeneration,
					.endpoint = std::move(grant.endpoint),
					.use = grant.use,
					.stealth = admitted
						? admission.stealth
						: diagnostics->stealth,
					.effectiveTlsProfile = admitted
						? admission.effectiveTlsProfile
						: diagnostics->configuredTlsProfile,
					.plan = admission.plan,
					.lease = std::move(admission.lease),
					.attemptId = admission.attemptId,
					.proxyEpoch = admission.proxyEpoch,
					.successEpoch = admission.successEpoch,
					.attemptStartedAt = admission.attemptStartedAt,
				};
				if (start) {
					start(std::move(value));
				}
			},
		});
	if (!accepted.accepted) {
		QObject::disconnect(ownerDestroyed);
		if (traceId) {
			(void)_endpointContext->finishTrace(traceId);
		}
		return {};
	}
	return ConnectionTicket(
		weak,
		key,
		accepted.acceptedRecoveryToken);
}

void ConnectionBroker::cancel(ConnectionTicketId id) {
	if (id) {
		_endpointContext->endpointAdmissionArbiter().cancel({
			.runtimeId = _runtime->proxyRuntimeId(),
			.ticketId = id,
		});
	}
}

void ConnectionBroker::cancelByProxyGeneration(uint64 generation) {
	_endpointContext->endpointAdmissionArbiter().cancelBeforeGeneration(
		_runtime->proxyRuntimeId(),
		generation);
}

void ConnectionBroker::cancelByOwnerDestruction() {
	_endpointContext->endpointAdmissionArbiter().cancelRuntime(
		_runtime->proxyRuntimeId());
}

} // namespace MTP::details
