/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "mtproto/proxy/session_proxy_adapter.h"

#include "mtproto/proxy/mtproxy/endpoint_health.h"
#include "mtproto/proxy/mtproxy/endpoint_identity.h"
#include "mtproto/proxy/connection_broker.h"
#include "mtproto/proxy/control_plane.h"
#include "mtproto/proxy/diagnostics.h"
#include "mtproto/proxy/proxy_endpoint_context.h"
#include "mtproto/proxy/proxy_services.h"
#include "mtproto/runtime/runtime_environment.h"
#include "mtproto/session/private/proxy_port.h"

namespace MTP::details {
namespace {

[[nodiscard]] MtProxy::SuccessScope ToMtProxySuccessScope(
		SessionProxySuccessScope scope) {
	switch (scope) {
	case SessionProxySuccessScope::FakeTlsAppData:
		return MtProxy::SuccessScope::FakeTlsAppData;
	case SessionProxySuccessScope::Relay:
		return MtProxy::SuccessScope::Relay;
	case SessionProxySuccessScope::Handshake:
		return MtProxy::SuccessScope::Handshake;
	}
	return MtProxy::SuccessScope::Handshake;
}

class EndpointSessionProxyLease final : public SessionProxyLease::Impl {
public:
	explicit EndpointSessionProxyLease(MtProxy::EndpointAttemptLease lease)
	: _lease(std::move(lease)) {
	}

	void release() override {
		_lease.release();
	}

	void releaseAdmissionForRelayCandidate() override {
		_lease.releaseAdmissionForRelayCandidate();
	}

	bool active() const override {
		return _lease.active();
	}

	uint64 attemptId() const override {
		return _lease.attemptId();
	}

	uint64 proxyGeneration() const override {
		return _lease.proxyGeneration();
	}

	uint64 proxyEpoch() const override {
		return _lease.proxyEpoch();
	}

	uint64 successEpoch() const override {
		return _lease.successEpoch();
	}

	crl::time startedAt() const override {
		return _lease.startedAt();
	}

	[[nodiscard]] MtProxy::EndpointAttemptLease *lease() {
		return &_lease;
	}

	void *opaque() override {
		return &_lease;
	}

private:
	MtProxy::EndpointAttemptLease _lease;
};

[[nodiscard]] MtProxy::EndpointAttemptLease *EndpointLease(
		SessionProxyLease *lease) {
	const auto impl = lease ? lease->impl() : nullptr;
	return impl
		? static_cast<MtProxy::EndpointAttemptLease*>(impl->opaque())
		: nullptr;
}

[[nodiscard]] ConnectionRequest ToBrokerRequest(SessionProxyRequest request) {
	const auto endpoint = MtProxy::EndpointIdFromProxy(
		request.proxy,
		request.stealth,
		request.address,
		request.port);
	return {
		.proxyGeneration = request.proxyGeneration,
		.endpoint = std::move(endpoint),
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
				.attempt = value.attempt,
				.proxyGeneration = value.proxyGeneration,
				.endpoint = std::move(value.endpoint),
				.use = value.use,
				.stealth = value.stealth,
				.effectiveTlsProfile = value.effectiveTlsProfile,
				.plan = value.plan,
				.lease = SessionProxyLease(
					std::make_unique<EndpointSessionProxyLease>(
						std::move(value.lease))),
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
				.blockedBy = MtProxy::ToProxyConnectionError(value.blockedBy),
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
		SessionProxyLease *lease,
		SessionProxySuccessScope scope) {
	return {
		.endpoint = attempt.endpoint,
		.use = attempt.use,
		.runtimeId = attempt.attempt.runtimeId,
		.stealth = attempt.plan.stealth,
		.sentProfile = attempt.transport.sentTlsProfile.value_or(
			ProxyTlsProfile::Auto),
		.lease = EndpointLease(lease),
		.proxyGeneration = attempt.attempt.proxyGeneration,
		.attemptId = attempt.attempt.attemptId,
		.proxyEpoch = attempt.attempt.proxyEpoch,
		.successEpoch = attempt.attempt.successEpoch,
		.attemptStartedAt = attempt.attemptStartedAt,
		.scope = ToMtProxySuccessScope(scope),
	};
}

[[nodiscard]] MtProxy::FailureReport FailureReport(
		const SessionProxyAttempt &attempt,
		MtProxy::FailureReason reason,
		SessionProxyLease *lease = nullptr) {
	return {
		.endpoint = attempt.endpoint,
		.use = attempt.use,
		.runtimeId = attempt.attempt.runtimeId,
		.reason = reason,
		.lease = EndpointLease(lease),
		.proxyGeneration = attempt.attempt.proxyGeneration,
		.attemptId = attempt.attempt.attemptId,
		.proxyEpoch = attempt.attempt.proxyEpoch,
		.successEpoch = attempt.attempt.successEpoch,
		.attemptStartedAt = attempt.attemptStartedAt,
	};
}

[[nodiscard]] MtProxy::RelayProofReport RelayProofReport(
		const SessionProxyAttempt &attempt) {
	return {
		.endpoint = attempt.endpoint,
		.use = attempt.use,
		.runtimeId = attempt.attempt.runtimeId,
		.proxyGeneration = attempt.attempt.proxyGeneration,
		.attemptId = attempt.attempt.attemptId,
		.proxyEpoch = attempt.attempt.proxyEpoch,
		.successEpoch = attempt.attempt.successEpoch,
		.attemptStartedAt = attempt.attemptStartedAt,
	};
}

[[nodiscard]] ProxyEventReport AttemptReport(
		const SessionProxyAttempt &attempt,
		ProxyConnectionError error,
		ProxyMtproxyTerminalReason reason,
		ProxyDiagnosticsSeverity severity,
		const QString &message,
		ProxyTransportFailure failure = {}) {
	const auto proxy = attempt.runtime
		? attempt.runtime->proxy().selected()
		: ProxyData();
	const auto now = crl::now();
	return {
		.error = (failure.error == ProxyConnectionError::None)
			? error
			: failure.error,
		.mtproxyReason = reason,
		.attempt = attempt.attempt,
		.severity = severity,
		.proxy = proxy,
		.transport = ProxyDiagnosticsTransportName(
			proxy.type,
			attempt.plan.stealth.transport),
		.message = message,
		.canonical = ProxyDiagnosticsEndpointText(
			attempt.endpoint.canonical.originalHost,
			attempt.endpoint.canonical.port),
		.route = ProxyDiagnosticsEndpointText(
			attempt.endpoint.route.address,
			attempt.endpoint.route.port),
		.proxyKeyHash = ProxyDiagnosticsKeyHash(
			MtProxy::EndpointKey(attempt.endpoint.canonical)),
		.profile = failure.sentTlsProfile
			? ProxyDiagnosticsTlsProfileName(*failure.sentTlsProfile)
			: QString(),
		.configuredProfile = ProxyDiagnosticsTlsProfileName(
			attempt.plan.configuredTlsProfile),
		.effectiveProfile = ProxyDiagnosticsTlsProfileName(
			attempt.plan.effectiveTlsProfile),
		.recipeLevel = attempt.plan.admitted
			? std::make_optional(attempt.plan.recipeLevel)
			: std::nullopt,
		.pskOffered = failure.pskOffered,
		.fragmentedClientHello = failure.fragmentedClientHello,
		.clientHelloBytes = failure.clientHelloBytes,
		.clientHelloWrites = failure.clientHelloWrites,
		.clientHelloAcceptedBytes = failure.clientHelloAcceptedBytes,
		.clientHelloFragmentSplit = failure.clientHelloFragmentSplit,
		.clientHelloFragmentDelayMs = failure.clientHelloFragmentDelayMs,
		.rxAfterClientHello = failure.rxAfterClientHello,
		.rxClass = std::move(failure.rxClass),
		.tlsRecordType = std::move(failure.tlsRecordType),
		.tlsRecordVersion = std::move(failure.tlsRecordVersion),
		.tlsRecordLength = failure.tlsRecordLength,
		.responsePrefixHash = std::move(failure.responsePrefixHash),
		.sniLength = failure.sniLength,
		.sniHash = std::move(failure.sniHash),
		.parserStage = std::move(failure.parserStage),
		.closeOrigin = (failure.closeOrigin == ProxyCloseOrigin::None)
			? std::optional<ProxyCloseOrigin>()
			: std::make_optional(failure.closeOrigin),
		.dnsMs = failure.dnsMs,
		.tcpMs = failure.tcpMs,
		.firstRxMs = failure.firstRxMs,
		.serverHelloMs = failure.serverHelloMs,
		.appDataMs = failure.appDataMs,
		.mtprotoMs = (reason == ProxyMtproxyTerminalReason::None
			&& attempt.attemptStartedAt)
			? std::make_optional(now - attempt.attemptStartedAt)
			: std::nullopt,
		.totalMs = attempt.attemptStartedAt
			? std::make_optional(now - attempt.attemptStartedAt)
			: std::nullopt,
	};
}

void ReportConnectionFailure(
		const SessionProxyAttempt &attempt,
		MtProxy::FailureReason reason,
		SessionProxyLease *lease = nullptr) {
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

class ProductionSessionProxyPort final : public SessionProxyPort {
public:
	[[nodiscard]] SessionProxyTicket requestConnection(
		SessionProxyRequest request) override;
	void cancelByProxyGeneration(
		RuntimeEnvironment *runtime,
		uint64 generation) override;
	[[nodiscard]] SessionProxyEndpointSnapshot endpointSnapshot(
		not_null<RuntimeEnvironment*> runtime,
		const MtProxy::EndpointId &endpoint) const override;
	void reportConnected(
		const SessionProxyAttempt &attempt,
		SessionProxyLease *lease,
		SessionProxySuccessScope scope) override;
	void reportFirstMtprotoPayload(
		const SessionProxyAttempt &attempt,
		SessionProxyLease *lease) override;
	void reportConnectionError(
		const SessionProxyAttempt &attempt,
		int errorCode,
		ProxyTransportFailure failure = {},
		SessionProxyLease *lease = nullptr,
		bool ignoreHealthyRemoteClosed = false) override;
	void reportReceiveTimeout(
		not_null<RuntimeEnvironment*> runtime,
		const ProxyData &proxy,
		const QString &dc,
		const SessionProxyAttempt &attempt,
		bool receivedBefore,
		int silentStrikes) override;
	void reportConnectTimeout(
		const SessionProxyAttempt &attempt) override;
	void reportAttemptCancelled(
		const SessionProxyAttempt &attempt,
		ProxyCloseOrigin origin) override;
	void reportRelayStall(
		const SessionProxyAttempt &attempt) override;
	void logEvent(
		not_null<RuntimeEnvironment*> runtime,
		const ProxyData &proxy,
		const ProxyConnectionAttempt &attempt,
		const QString &dc,
		ProxyDiagnosticsPhase phase,
		ProxyDiagnosticsSeverity severity,
		const QString &message) override;
};

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

SessionProxyEndpointSnapshot ProductionSessionProxyPort::endpointSnapshot(
		not_null<RuntimeEnvironment*> runtime,
		const MtProxy::EndpointId &endpoint) const {
	const auto snapshot = runtime->proxyServices().control(
	).mtproxyEndpointSnapshot(endpoint);
	return {
		.healthy = snapshot.healthy,
		.halfOpen = snapshot.halfOpen,
	};
}

void ProductionSessionProxyPort::reportConnected(
		const SessionProxyAttempt &attempt,
		SessionProxyLease *lease,
		SessionProxySuccessScope scope) {
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
		const SessionProxyAttempt &attempt,
		SessionProxyLease *lease) {
	reportConnected(attempt, lease, SessionProxySuccessScope::Relay);
	if (attempt.runtime) {
		(void)ReportProxyAttemptSummary(
			not_null{ attempt.runtime },
			AttemptReport(
				attempt,
				ProxyConnectionError::None,
				ProxyMtproxyTerminalReason::None,
				ProxyDiagnosticsSeverity::Info,
				u"relay_ready_first_mtproto_payload"_q,
				attempt.transport));
	}
}

void ProductionSessionProxyPort::reportConnectionError(
		const SessionProxyAttempt &attempt,
		int errorCode,
		ProxyTransportFailure failure,
		SessionProxyLease *lease,
		bool ignoreHealthyRemoteClosed) {
	const auto reason = (failure.reason != ProxyMtproxyTerminalReason::None)
		? MtProxy::FromProxyMtproxyTerminalReason(failure.reason)
		: MtProxy::FailureReasonFromErrorCode(errorCode);
	if (reason == MtProxy::FailureReason::None) {
		return;
	}
	if (ignoreHealthyRemoteClosed
		&& attempt.runtime
		&& (reason == MtProxy::FailureReason::AppDataRemoteClosed)) {
		const auto runtime = not_null{ attempt.runtime };
		const auto snapshot = endpointSnapshot(runtime, attempt.endpoint);
		const auto postTerminal = attempt.attempt.traceId
			&& !runtime->proxyEndpointContext().traceActive(
				attempt.attempt.traceId);
		if (snapshot.healthy && !snapshot.halfOpen && postTerminal) {
			runtime->proxyServices().control().retireMtproxyRelayProof(
				RelayProofReport(attempt));
			ReportProxyLiveness(
				runtime,
				AttemptReport(
					attempt,
					MtProxy::ToProxyConnectionError(reason),
					MtProxy::ToProxyMtproxyTerminalReason(reason),
					ProxyDiagnosticsSeverity::Info,
					u"post_success_connection_closed"_q,
					std::move(failure)));
			return;
		}
	}
	ReportConnectionFailure(attempt, reason, lease);
	if (attempt.runtime) {
		const auto livenessReported = failure.livenessReported;
		auto report = AttemptReport(
			attempt,
			MtProxy::ToProxyConnectionError(reason),
			MtProxy::ToProxyMtproxyTerminalReason(reason),
			ProxyDiagnosticsSeverity::Error,
			u"proxy_attempt_failed"_q,
			std::move(failure));
		if (!ReportProxyAttemptSummary(not_null{ attempt.runtime }, report)
			&& !livenessReported) {
			ReportProxyLiveness(
				not_null{ attempt.runtime },
				std::move(report));
		}
	}
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
	const auto typed = attempt.transport.reason;
	const auto reason = (typed != ProxyMtproxyTerminalReason::None)
		? typed
		: receivedBefore
		? ProxyMtproxyTerminalReason::MtpReceiveTimeoutAfterData
		: attempt.endpoint.canonical.domainFromSecret.isEmpty()
		? ProxyMtproxyTerminalReason::ConnectedNoMtprotoData
		: ProxyMtproxyTerminalReason::ServerHelloOkNoMtprotoData;
	const auto traceActive = !attempt.attempt.traceId
		|| runtime->proxyEndpointContext().traceActive(
			attempt.attempt.traceId);
	if (traceActive) {
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
	}
	auto terminal = AttemptReport(
		attempt,
		ProxyConnectionError::Timeout,
		reason,
		ProxyDiagnosticsSeverity::Warning,
		receivedBefore
			? u"post_success_receive_timeout"_q
			: u"connected_without_mtproto_payload"_q,
		attempt.transport);
	terminal.message += u" silent_strikes=%1"_q.arg(silentStrikes);
	if (!ReportProxyAttemptSummary(runtime, terminal)) {
		ReportProxyLiveness(runtime, std::move(terminal));
	}
	if (receivedBefore) {
		reportRelayStall(attempt);
	} else {
		ReportConnectionFailure(
			attempt,
			MtProxy::FromProxyMtproxyTerminalReason(reason));
	}
}

void ProductionSessionProxyPort::reportConnectTimeout(
		const SessionProxyAttempt &attempt) {
	if (EmptySessionProxyAttempt(attempt)) {
		return;
	}
	const auto typed = attempt.transport.reason;
	const auto reason = (typed == ProxyMtproxyTerminalReason::None)
		? MtProxy::FailureReason::TcpConnectTimeout
		: MtProxy::FromProxyMtproxyTerminalReason(typed);
	if (typed == ProxyMtproxyTerminalReason::None) {
		ReportConnectionFailure(attempt, reason);
	}
	if (attempt.runtime) {
		(void)ReportProxyAttemptSummary(
			not_null{ attempt.runtime },
			AttemptReport(
				attempt,
				MtProxy::ToProxyConnectionError(reason),
				MtProxy::ToProxyMtproxyTerminalReason(reason),
				ProxyDiagnosticsSeverity::Error,
				u"proxy_connect_timeout"_q,
				attempt.transport));
	}
}

void ProductionSessionProxyPort::reportAttemptCancelled(
		const SessionProxyAttempt &attempt,
		ProxyCloseOrigin origin) {
	if (EmptySessionProxyAttempt(attempt) || !attempt.runtime) {
		return;
	}
	const auto runtime = not_null{ attempt.runtime };
	runtime->proxyServices().control().retireMtproxyRelayProof(
		RelayProofReport(attempt));
	const auto message = (origin == ProxyCloseOrigin::ProxySwitch)
		? u"proxy_attempt_cancelled_by_proxy_switch"_q
		: (origin == ProxyCloseOrigin::OwnerDestroyed)
		? u"proxy_attempt_cancelled_by_owner_destruction"_q
		: u"proxy_attempt_cancelled_by_broker"_q;
	auto report = AttemptReport(
		attempt,
		ProxyConnectionError::None,
		ProxyMtproxyTerminalReason::None,
		ProxyDiagnosticsSeverity::Warning,
		message,
		attempt.transport);
	report.closeOrigin = origin;
	(void)ReportProxyAttemptSummary(
		runtime,
		std::move(report));
}

void ProductionSessionProxyPort::reportRelayStall(
		const SessionProxyAttempt &attempt) {
	if (EmptySessionProxyAttempt(attempt)) {
		return;
	}
	if (!attempt.runtime) {
		return;
	}
	const auto runtime = not_null{ attempt.runtime };
	runtime->proxyServices().control().noteMtproxyRelayStall(
		RelayProofReport(attempt));
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
