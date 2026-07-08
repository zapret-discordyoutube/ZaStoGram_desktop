/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "mtproto/proxy/session_proxy_adapter.h"

#include "mtproto/proxy/connection_broker.h"
#include "mtproto/proxy/control_plane.h"
#include "mtproto/proxy/diagnostics.h"
#include "mtproto/proxy/proxy_services.h"
#include "mtproto/runtime/runtime_environment.h"

namespace MTP::details {
namespace {

[[nodiscard]] ConnectionRequest ToBrokerRequest(SessionProxyRequest request) {
	return {
		.proxyGeneration = request.proxyGeneration,
		.endpoint = std::move(request.endpoint),
		.proxy = std::move(request.proxy),
		.use = request.use,
		.stealth = request.stealth,
		.configuredTlsProfile = request.configuredTlsProfile,
		.connectionPattern = request.connectionPattern,
		.notBefore = request.notBefore,
		.context = std::move(request.context),
		.start = [start = std::move(request.start)](ConnectionStart value) mutable {
			if (!start) {
				return;
			}
			start({
				.ticketId = value.ticketId,
				.proxyGeneration = value.proxyGeneration,
				.endpoint = std::move(value.endpoint),
				.use = value.use,
				.stealth = value.stealth,
				.effectiveTlsProfile = value.effectiveTlsProfile,
				.lease = std::move(value.lease),
				.attemptId = value.attemptId,
				.proxyEpoch = value.proxyEpoch,
				.successEpoch = value.successEpoch,
				.attemptStartedAt = value.attemptStartedAt,
			});
		},
		.status = [status = std::move(request.status)](
				ConnectionBrokerDecision value) mutable {
			if (!status) {
				return;
			}
			status({
				.action = [&] {
					switch (value.action) {
					case ConnectionBrokerAction::StartNow:
						return SessionProxyAdmissionAction::StartNow;
					case ConnectionBrokerAction::Queued:
						return SessionProxyAdmissionAction::Queued;
					case ConnectionBrokerAction::StartAfter:
						return SessionProxyAdmissionAction::StartAfter;
					case ConnectionBrokerAction::Rejected:
						return SessionProxyAdmissionAction::Rejected;
					}
					return SessionProxyAdmissionAction::Rejected;
				}(),
				.retryAfter = value.retryAfter,
				.blockedBy = value.blockedBy,
			});
		},
	};
}

class BrokerSessionProxyTicket final : public SessionProxyTicket::Impl {
public:
	explicit BrokerSessionProxyTicket(ConnectionTicket ticket)
	: _ticket(std::move(ticket)) {
	}

	void cancel() override {
		_ticket.cancel();
	}

	SessionProxyTicketId id() const override {
		return _ticket.id();
	}

private:
	ConnectionTicket _ticket;
};

[[nodiscard]] MtProxy::SuccessReport SuccessReport(
		const SessionProxyAttempt &attempt,
		MtProxy::EndpointAttemptLease *lease,
		MtProxy::SuccessScope scope) {
	return {
		.endpoint = attempt.endpoint,
		.use = attempt.use,
		.lease = lease,
		.proxyGeneration = attempt.attempt.proxyGeneration,
		.attemptId = attempt.attempt.attemptId,
		.proxyEpoch = attempt.attempt.proxyEpoch,
		.successEpoch = attempt.attempt.successEpoch,
		.attemptStartedAt = attempt.attemptStartedAt,
		.scope = scope,
	};
}

[[nodiscard]] MtProxy::FailureReport FailureReport(
		const SessionProxyAttempt &attempt,
		MtProxy::FailureReason reason,
		MtProxy::EndpointAttemptLease *lease = nullptr) {
	return {
		.endpoint = attempt.endpoint,
		.use = attempt.use,
		.reason = reason,
		.lease = lease,
		.proxyGeneration = attempt.attempt.proxyGeneration,
		.attemptId = attempt.attempt.attemptId,
		.proxyEpoch = attempt.attempt.proxyEpoch,
		.successEpoch = attempt.attempt.successEpoch,
		.attemptStartedAt = attempt.attemptStartedAt,
	};
}

} // namespace

SessionProxyTicket ProductionSessionProxyPort::requestConnection(
		SessionProxyRequest request) {
	if (!request.runtime) {
		return SessionProxyTicket();
	}
	auto ticket = not_null{ request.runtime }->proxyServices().broker().request(
		ToBrokerRequest(std::move(request)));
	return ticket
		? SessionProxyTicket(std::make_unique<BrokerSessionProxyTicket>(
			std::move(ticket)))
		: SessionProxyTicket();
}

void ProductionSessionProxyPort::cancelByProxyGeneration(
		RuntimeEnvironment *runtime,
		uint64 generation) {
	if (runtime) {
		not_null{ runtime }->proxyServices().broker().cancelByProxyGeneration(
			generation);
	}
}

MtProxy::Snapshot ProductionSessionProxyPort::endpointSnapshot(
		not_null<RuntimeEnvironment*> runtime,
		const MtProxy::EndpointId &endpoint) const {
	return runtime->proxyServices().control().mtproxyEndpointSnapshot(endpoint);
}

void ProductionSessionProxyPort::reportConnected(
		const SessionProxyAttempt &attempt,
		MtProxy::EndpointAttemptLease *lease,
		MtProxy::SuccessScope scope) {
	if (EmptySessionProxyAttempt(attempt)) {
		return;
	}
	if (!attempt.runtime) {
		return;
	}
	not_null{ attempt.runtime }->proxyServices().control().reportMtproxySuccess(
		SuccessReport(attempt, lease, scope));
}

void ProductionSessionProxyPort::reportFirstMtprotoPayload(
		const SessionProxyAttempt &attempt) {
	reportConnected(attempt, nullptr, MtProxy::SuccessScope::Relay);
}

void ProductionSessionProxyPort::reportConnectionError(
		const SessionProxyAttempt &attempt,
		MtProxy::FailureReason reason,
		MtProxy::EndpointAttemptLease *lease) {
	if (EmptySessionProxyAttempt(attempt)
		|| (reason == MtProxy::FailureReason::None)) {
		return;
	}
	if (!attempt.runtime) {
		return;
	}
	not_null{ attempt.runtime }->proxyServices().control().reportMtproxyFailure(
		FailureReport(attempt, reason, lease));
}

void ProductionSessionProxyPort::reportReceiveTimeout(
		not_null<RuntimeEnvironment*> runtime,
		const ProxyData &proxy,
		const QString &dc,
		const SessionProxyAttempt &attempt,
		bool receivedBefore,
		int silentStrikes) {
	if (EmptySessionProxyAttempt(attempt)) {
		return;
	}
	const auto reason = receivedBefore
		? ProxyMtproxyTerminalReason::MtpReceiveTimeoutAfterData
		: ProxyMtproxyTerminalReason::ServerHelloOkNoMtprotoData;
	ReportProxyEvent(runtime, {
		.phase = ProxyDiagnosticsPhase::Failed,
		.error = ProxyConnectionError::Timeout,
		.mtproxyReason = reason,
		.attempt = attempt.attempt,
		.severity = ProxyDiagnosticsSeverity::Warning,
		.proxy = proxy,
		.dc = dc,
		.message = receivedBefore
			? u"mtp receive timeout after relay data"_q
			: u"proxy connected, mtproto data stalled"_q,
	});
	if (receivedBefore) {
		reportRelayStall(attempt);
	} else {
		reportConnectionError(
			attempt,
			MtProxy::FailureReason::ServerHelloOkNoMtprotoData);
	}
}

void ProductionSessionProxyPort::reportConnectTimeout(
		const SessionProxyAttempt &attempt) {
	if (EmptySessionProxyAttempt(attempt)
		|| !attempt.endpoint.canonical.domainFromSecret.isEmpty()) {
		return;
	}
	reportConnectionError(attempt, MtProxy::FailureReason::TcpConnectTimeout);
}

void ProductionSessionProxyPort::reportRelayStall(
		const SessionProxyAttempt &attempt) {
	if (EmptySessionProxyAttempt(attempt)) {
		return;
	}
	if (!attempt.runtime) {
		return;
	}
	not_null{ attempt.runtime }->proxyServices().control().noteMtproxyRelayStall({
		.endpoint = attempt.endpoint,
		.use = attempt.use,
		.proxyGeneration = attempt.attempt.proxyGeneration,
		.attemptId = attempt.attempt.attemptId,
		.proxyEpoch = attempt.attempt.proxyEpoch,
		.successEpoch = attempt.attempt.successEpoch,
		.attemptStartedAt = attempt.attemptStartedAt,
	});
}

void ProductionSessionProxyPort::logEvent(
		not_null<RuntimeEnvironment*> runtime,
		const ProxyData &proxy,
		const ProxyConnectionAttempt &attempt,
		const QString &dc,
		ProxyDiagnosticsPhase phase,
		ProxyDiagnosticsSeverity severity,
		const QString &message) {
	if (proxy.type == ProxyData::Type::None) {
		WriteProxyDiagnosticsLine(runtime, {
			.source = ProxyDiagnosticsSource::MTP,
			.phase = phase,
			.severity = severity,
			.proxy = proxy,
			.dc = dc,
			.message = message,
		});
		return;
	}
	ReportProxyEvent(runtime, {
		.phase = phase,
		.attempt = attempt,
		.severity = severity,
		.proxy = proxy,
		.dc = dc,
		.message = message,
	});
}

SessionProxyPort &DefaultSessionProxyPort() {
	static auto result = ProductionSessionProxyPort();
	return result;
}

} // namespace MTP::details
