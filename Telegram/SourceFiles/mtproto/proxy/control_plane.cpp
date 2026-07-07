/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "mtproto/proxy/control_plane.h"

#include "base/invoke_queued.h"
#include "base/timer.h"
#include "mtproto/mtp_instance.h"
#include "mtproto/proxy/diagnostics.h"

namespace MTP {
namespace {
namespace MtProxy = details::MtProxy;

constexpr auto kFreshRelaySuccessWindow = crl::time(15 * 1000);

[[nodiscard]] ProxyAdmissionAction AdmissionActionFromMtproxy(
		MtProxy::AdmissionAction action) {
	switch (action) {
	case MtProxy::AdmissionAction::StartNow:
	case MtProxy::AdmissionAction::SkipCooldown:
		return ProxyAdmissionAction::StartNow;
	case MtProxy::AdmissionAction::StartAfter:
	case MtProxy::AdmissionAction::Queued:
		return ProxyAdmissionAction::Queued;
	}
	return ProxyAdmissionAction::Rejected;
}

[[nodiscard]] bool IsTerminalFailure(
		const ProxyConnectionStatus &status) {
	return (status.error != ProxyConnectionError::None)
		|| IsMtproxyTerminalFailure(status.mtproxyReason);
}

[[nodiscard]] bool IsNewerProxyEpoch(
		const ProxyConnectionAttempt &current,
		const ProxyConnectionAttempt &update) {
	if (update.proxyGeneration != current.proxyGeneration) {
		return update.proxyGeneration > current.proxyGeneration;
	}
	return update.proxyEpoch > current.proxyEpoch;
}

[[nodiscard]] bool RelaySuccessIsFresh(
		const ProxyConnectionStatus &status) {
	return (status.phase == ProxyConnectionPhase::Connected)
		&& status.successUntil
		&& (status.successUntil > crl::now());
}

[[nodiscard]] bool IsRelayDataStall(
		const ProxyConnectionStatus &status) {
	switch (status.mtproxyReason) {
	case ProxyMtproxyTerminalReason::ServerHelloOkNoAppData:
	case ProxyMtproxyTerminalReason::ServerHelloOkNoMtprotoData:
	case ProxyMtproxyTerminalReason::ConnectedNoMtprotoData:
	case ProxyMtproxyTerminalReason::MtpReceiveTimeoutAfterData:
		return true;
	case ProxyMtproxyTerminalReason::None:
	case ProxyMtproxyTerminalReason::DnsFailed:
	case ProxyMtproxyTerminalReason::TcpConnectTimeout:
	case ProxyMtproxyTerminalReason::TcpConnectedNoClientHelloWrite:
	case ProxyMtproxyTerminalReason::ClientHelloSentNoServerHello:
	case ProxyMtproxyTerminalReason::TlsAlertAfterClientHello:
	case ProxyMtproxyTerminalReason::ServerHelloHmacMismatch:
	case ProxyMtproxyTerminalReason::AppDataRemoteClosed:
	case ProxyMtproxyTerminalReason::ProxyProtocolBadResponse:
		return false;
	}
	return false;
}

void NormalizeMtproxyTerminalReason(
		const ProxyConnectionStatus &current,
		ProxyConnectionStatus &status) {
	if (status.mtproxyReason
		!= ProxyMtproxyTerminalReason::ClientHelloSentNoServerHello) {
		return;
	}
	if (!(current.attempt == status.attempt)) {
		return;
	}
	if (current.phase != ProxyConnectionPhase::CheckingTelegram
		&& current.phase != ProxyConnectionPhase::Connected) {
		return;
	}
	status.mtproxyReason = ProxyMtproxyTerminalReason::ServerHelloOkNoAppData;
	status.error = ProxyConnectionError::None;
}

[[nodiscard]] bool ShadowedByFreshRelaySuccess(
		const ProxyConnectionStatus &current,
		const ProxyFact &fact) {
	return RelaySuccessIsFresh(current)
		&& IsTerminalFailure(fact.status)
		&& !IsNewerProxyEpoch(current.attempt, fact.status.attempt);
}

[[nodiscard]] bool EmptyFact(const ProxyFact &fact) {
	return (fact.status.phase == ProxyConnectionPhase::None)
		&& !IsTerminalFailure(fact.status)
		&& (fact.successScope == ProxyControlPlaneSuccessScope::None);
}

[[nodiscard]] ProxyDiagnosticsSource SourceForProxy(const ProxyData &proxy) {
	return (proxy.type == ProxyData::Type::Mtproto)
		? ProxyDiagnosticsSource::MTProxy
		: ProxyDiagnosticsSource::Network;
}

void LogShadowedFact(const ProxyFact &fact) {
	WriteProxyDiagnosticsLine({
		.source = SourceForProxy(fact.status.proxy),
		.phase = ProxyDiagnosticsPhase::Failed,
		.severity = ProxyDiagnosticsSeverity::Info,
		.error = fact.status.error,
		.mtproxyReason = fact.status.mtproxyReason,
		.attempt = fact.status.attempt,
		.terminalUntil = fact.status.terminalUntil,
		.proxy = fact.status.proxy,
		.message = u"proxy fact shadowed_by_fresh_success"_q,
	});
}

} // namespace

void ProxyControlPlane::submitFact(ProxyFact fact) {
	_selectedStatus = Reduce(_selectedStatus, std::move(fact));
	_endpointSnapshot.proxy = _selectedStatus.proxy;
	_endpointSnapshot.status = _selectedStatus;
	_endpointSnapshot.relayProven = RelaySuccessIsFresh(_selectedStatus);
}

ProxyAdmissionDecision ProxyControlPlane::admit(
		ProxyAdmissionRequest request) {
	if (!MtProxy::EndpointEmpty(request.endpoint)) {
		return Admit(std::move(request));
	}
	if (request.relayProofRequired
		&& !request.relayProven
		&& request.active >= request.scoutCap) {
		return {
			.action = ProxyAdmissionAction::Queued,
			.retryAfter = request.retryAfter,
		};
	}
	return {};
}

ProxyAdmissionDecision ProxyControlPlane::Admit(
		ProxyAdmissionRequest request) {
	auto admission = MtProxy::EndpointHealth::Instance().admit({
		.endpoint = request.endpoint,
		.use = request.use,
		.stealth = request.stealth,
		.configuredTlsProfile = request.configuredTlsProfile,
	});
	return {
		.action = AdmissionActionFromMtproxy(admission.action),
		.retryAfter = admission.retryAfter,
		.blockedBy = admission.blockedBy,
		.stealth = admission.stealth,
		.effectiveTlsProfile = admission.effectiveTlsProfile,
		.lease = std::move(admission.lease),
		.attemptId = admission.attemptId,
		.proxyEpoch = admission.proxyEpoch,
		.attemptStartedAt = admission.attemptStartedAt,
	};
}

void ProxyControlPlane::ReportMtproxyFailure(
		MtProxy::FailureReport report) {
	MtProxy::EndpointHealth::Instance().reportFailure(std::move(report));
}

void ProxyControlPlane::ReportMtproxySuccess(
		MtProxy::SuccessReport report) {
	MtProxy::EndpointHealth::Instance().reportSuccess(std::move(report));
}

void ProxyControlPlane::NoteMtproxyRelayStall(
		const MtProxy::EndpointId &endpoint) {
	MtProxy::EndpointHealth::Instance().noteRelayStall(endpoint);
}

MtProxy::Snapshot ProxyControlPlane::MtproxyEndpointSnapshot(
		const MtProxy::EndpointId &endpoint) {
	return MtProxy::EndpointHealth::Instance().snapshot(endpoint);
}

ProxyConnectionStatus ProxyControlPlane::selectedStatus() const {
	return _selectedStatus;
}

ProxyEndpointSnapshot ProxyControlPlane::endpointSnapshot() const {
	return _endpointSnapshot;
}

ProxyFact ProxyControlPlane::FactFromReport(
		const ProxyEventReport &report) {
	auto fact = ProxyFact();
	fact.status = {
		.phase = ProxyConnectionPhase::None,
		.error = report.error,
		.mtproxyReason = report.mtproxyReason,
		.attempt = report.attempt,
		.terminalUntil = report.terminalUntil,
		.proxy = report.proxy,
	};
	switch (report.phase) {
	case ProxyDiagnosticsPhase::Resolving:
		fact.status.phase = ProxyConnectionPhase::Resolving;
		return fact;
	case ProxyDiagnosticsPhase::Connecting:
	case ProxyDiagnosticsPhase::TcpConnected:
		fact.status.phase = ProxyConnectionPhase::Connecting;
		return fact;
	case ProxyDiagnosticsPhase::ClientHelloSent:
		fact.status.phase = ProxyConnectionPhase::Handshake;
		return fact;
	case ProxyDiagnosticsPhase::ServerHelloOk:
		fact.status.phase = ProxyConnectionPhase::CheckingTelegram;
		fact.successScope = ProxyControlPlaneSuccessScope::Handshake;
		return fact;
	case ProxyDiagnosticsPhase::TelegramCheck:
		fact.status.phase = ProxyConnectionPhase::CheckingTelegram;
		return fact;
	case ProxyDiagnosticsPhase::Connected:
		fact.status.phase = ProxyConnectionPhase::Connected;
		fact.successScope = ProxyControlPlaneSuccessScope::Handshake;
		return fact;
	case ProxyDiagnosticsPhase::MtpFirstDataReceived:
		fact.status.phase = ProxyConnectionPhase::Connected;
		fact.successScope = ProxyControlPlaneSuccessScope::Relay;
		return fact;
	case ProxyDiagnosticsPhase::Failed:
		fact.status.phase = ProxyConnectionPhase::Failed;
		return fact;
	case ProxyDiagnosticsPhase::None:
	case ProxyDiagnosticsPhase::ProxyCheckStarted:
	case ProxyDiagnosticsPhase::ProxyCheckFinished:
	case ProxyDiagnosticsPhase::AdmissionQueued:
	case ProxyDiagnosticsPhase::AdmissionStarted:
	case ProxyDiagnosticsPhase::AdmissionCancelled:
	case ProxyDiagnosticsPhase::RouteSelected:
	case ProxyDiagnosticsPhase::RouteFailed:
	case ProxyDiagnosticsPhase::CanonicalDegraded:
	case ProxyDiagnosticsPhase::CanonicalRecovered:
	case ProxyDiagnosticsPhase::StealthRecipeApplied:
	case ProxyDiagnosticsPhase::TransportFallbackApplied:
	case ProxyDiagnosticsPhase::RotationSwitched:
	case ProxyDiagnosticsPhase::MtpConnecting:
	case ProxyDiagnosticsPhase::MtpTransportReady:
	case ProxyDiagnosticsPhase::MtpKeyCreating:
	case ProxyDiagnosticsPhase::MtpKeyReady:
	case ProxyDiagnosticsPhase::MtpReceiveTimeout:
	case ProxyDiagnosticsPhase::MtpConnectTimeout:
	case ProxyDiagnosticsPhase::MtpBrokerTimeout:
	case ProxyDiagnosticsPhase::MtpPingTimeout:
	case ProxyDiagnosticsPhase::MtpBindFailed:
	case ProxyDiagnosticsPhase::MtpKeyDestroyed:
	case ProxyDiagnosticsPhase::MtpRestart:
		return fact;
	}
	return fact;
}

ProxyConnectionStatus ProxyControlPlane::Reduce(
		const ProxyConnectionStatus &current,
		ProxyFact fact) {
	if (EmptyFact(fact)) {
		return current;
	}
	if (fact.status.attempt.probe) {
		return current;
	}
	if (IsRelayDataStall(fact.status)) {
		fact.status.error = ProxyConnectionError::None;
	}
	if (fact.successScope == ProxyControlPlaneSuccessScope::Relay) {
		fact.status.phase = ProxyConnectionPhase::Connected;
		fact.status.successUntil = crl::now() + kFreshRelaySuccessWindow;
	}
	NormalizeMtproxyTerminalReason(current, fact.status);
	if (ShadowedByFreshRelaySuccess(current, fact)) {
		return current;
	}
	return ApplyProxyConnectionStatusUpdate(
		current,
		std::move(fact.status));
}

void ProxyControlPlane::SubmitFact(
		not_null<Instance*> instance,
		const ProxyEventReport &report) {
	auto fact = FactFromReport(report);
	if (EmptyFact(fact)) {
		return;
	}
	InvokeQueued(instance, [=] {
		const auto current = instance->proxyConnectionStatus();
		auto normalized = fact;
		NormalizeMtproxyTerminalReason(current, normalized.status);
		if (ShadowedByFreshRelaySuccess(current, normalized)) {
			LogShadowedFact(normalized);
		}
		instance->setProxyConnectionStatus(Reduce(current, normalized));
	});
}

} // namespace MTP
