/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "mtproto/proxy/session_proxy_adapter.h"

#include "mtproto/session/private/proxy_port.h"
#include "mtproto/proxy/connection_broker.h"
#include "mtproto/proxy/control_plane.h"
#include "mtproto/proxy/diagnostics.h"
#include "mtproto/proxy/mtproxy/endpoint_health.h"
#include "mtproto/proxy/mtproxy/endpoint_identity.h"
#include "mtproto/proxy/proxy_services.h"
#include "mtproto/runtime/runtime_environment.h"

namespace MTP::details {
namespace {

[[nodiscard]] MtProxy::EndpointUse ToMtProxyUse(
		SessionProxyEndpointUse use) {
	switch (use) {
	case SessionProxyEndpointUse::Media:
		return MtProxy::EndpointUse::Media;
	case SessionProxyEndpointUse::Upload:
		return MtProxy::EndpointUse::Upload;
	case SessionProxyEndpointUse::ProxyCheck:
		return MtProxy::EndpointUse::ProxyCheck;
	case SessionProxyEndpointUse::Main:
		return MtProxy::EndpointUse::Main;
	}
	return MtProxy::EndpointUse::Main;
}

[[nodiscard]] SessionProxyEndpointUse FromMtProxyUse(
		MtProxy::EndpointUse use) {
	switch (use) {
	case MtProxy::EndpointUse::Media:
		return SessionProxyEndpointUse::Media;
	case MtProxy::EndpointUse::Upload:
		return SessionProxyEndpointUse::Upload;
	case MtProxy::EndpointUse::ProxyCheck:
		return SessionProxyEndpointUse::ProxyCheck;
	case MtProxy::EndpointUse::Main:
		return SessionProxyEndpointUse::Main;
	}
	return SessionProxyEndpointUse::Main;
}

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
		.use = ToMtProxyUse(request.use),
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
				.use = FromMtProxyUse(value.use),
				.stealth = value.stealth,
				.effectiveTlsProfile = value.effectiveTlsProfile,
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
		.use = ToMtProxyUse(attempt.use),
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
		.use = ToMtProxyUse(attempt.use),
		.reason = reason,
		.lease = EndpointLease(lease),
		.proxyGeneration = attempt.attempt.proxyGeneration,
		.attemptId = attempt.attempt.attemptId,
		.proxyEpoch = attempt.attempt.proxyEpoch,
		.successEpoch = attempt.attempt.successEpoch,
		.attemptStartedAt = attempt.attemptStartedAt,
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
		const SessionProxyAttempt &attempt) override;
	void reportConnectionError(
		const SessionProxyAttempt &attempt,
		int errorCode,
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
		const SessionProxyAttempt &attempt) {
	reportConnected(attempt, nullptr, SessionProxySuccessScope::Relay);
}

void ProductionSessionProxyPort::reportConnectionError(
		const SessionProxyAttempt &attempt,
		int errorCode,
		SessionProxyLease *lease,
		bool ignoreHealthyRemoteClosed) {
	const auto reason = MtProxy::FailureReasonFromErrorCode(errorCode);
	if (reason == MtProxy::FailureReason::None) {
		return;
	}
	if (ignoreHealthyRemoteClosed
		&& attempt.runtime
		&& (reason == MtProxy::FailureReason::AppDataRemoteClosed)) {
		const auto snapshot = endpointSnapshot(
			not_null{ attempt.runtime },
			attempt.endpoint);
		if (snapshot.healthy && !snapshot.halfOpen) {
			return;
		}
	}
	ReportConnectionFailure(attempt, reason, lease);
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
		ReportConnectionFailure(
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
	ReportConnectionFailure(attempt, MtProxy::FailureReason::TcpConnectTimeout);
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
		.use = ToMtProxyUse(attempt.use),
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
