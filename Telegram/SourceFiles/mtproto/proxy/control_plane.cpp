/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "mtproto/proxy/control_plane.h"

#include "base/invoke_queued.h"
#include "mtproto/proxy/diagnostics.h"
#include "mtproto/proxy/transport_policy.h"
#include "mtproto/runtime/connection_status.h"
#include "mtproto/runtime/runtime_environment.h"

namespace MTP {
namespace {
constexpr auto kNonMtproxyFreshRelaySuccessWindow = crl::time(15 * 1000);

[[nodiscard]] bool IsSuccess(const ProxyConnectionStatus &status) {
	return status.phase == ProxyConnectionPhase::Connected;
}

[[nodiscard]] bool IsTerminalFailure(
		const ProxyConnectionStatus &status) {
	return (status.error != ProxyConnectionError::None)
		|| IsMtproxyTerminalFailure(status.mtproxyReason);
}

[[nodiscard]] bool IsNewerProxyEpoch(
		const ProxyConnectionAttempt &current,
		const ProxyConnectionAttempt &update) {
	if (current.runtimeId && update.runtimeId != current.runtimeId) {
		return false;
	}
	if (update.proxyGeneration != current.proxyGeneration) {
		return update.proxyGeneration > current.proxyGeneration;
	}
	if (update.proxyEpoch != current.proxyEpoch) {
		return update.proxyEpoch > current.proxyEpoch;
	}
	return update.successEpoch > current.successEpoch;
}

[[nodiscard]] bool IsNewerAttempt(
		const ProxyConnectionAttempt &current,
		const ProxyConnectionAttempt &update) {
	if (current.runtimeId && update.runtimeId != current.runtimeId) {
		return false;
	}
	if (update.proxyGeneration != current.proxyGeneration) {
		return update.proxyGeneration > current.proxyGeneration;
	}
	if (update.proxyEpoch != current.proxyEpoch) {
		return update.proxyEpoch > current.proxyEpoch;
	}
	if (update.successEpoch != current.successEpoch) {
		return update.successEpoch > current.successEpoch;
	}
	return update.attemptId > current.attemptId;
}

[[nodiscard]] bool IsOlderAttempt(
		const ProxyConnectionAttempt &current,
		const ProxyConnectionAttempt &update) {
	if (current.runtimeId && update.runtimeId != current.runtimeId) {
		return false;
	}
	if (current.proxyGeneration
		&& update.proxyGeneration != current.proxyGeneration) {
		return false;
	}
	if (current.proxyEpoch && !update.proxyEpoch) {
		return true;
	}
	if (update.proxyEpoch && update.proxyEpoch < current.proxyEpoch) {
		return true;
	}
	if (update.proxyEpoch != current.proxyEpoch) {
		return false;
	}
	if (current.successEpoch && !update.successEpoch) {
		return true;
	}
	if (update.successEpoch && update.successEpoch < current.successEpoch) {
		return true;
	}
	if (update.successEpoch != current.successEpoch) {
		return false;
	}
	return current.attemptId
		&& update.attemptId
		&& (update.attemptId < current.attemptId);
}

[[nodiscard]] bool IsOlderProxyGeneration(
		const ProxyConnectionAttempt &current,
		const ProxyConnectionAttempt &update) {
	if (current.runtimeId && update.runtimeId != current.runtimeId) {
		return false;
	}
	return current.proxyGeneration
		&& (!update.proxyGeneration
			|| (update.proxyGeneration < current.proxyGeneration));
}

[[nodiscard]] bool StickyWindowActive(
		const ProxyConnectionStatus &status) {
	return status.terminalUntil
		&& (status.terminalUntil > crl::now());
}

[[nodiscard]] bool NonMtproxyRelaySuccessIsFresh(
		const ProxyConnectionStatus &status) {
	return (status.proxy.type != ProxyData::Type::Mtproto)
		&& (status.phase == ProxyConnectionPhase::Connected)
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

[[nodiscard]] bool ShadowedByFreshRelaySuccess(
		const ProxyConnectionStatus &current,
		const ProxyFact &fact) {
	return NonMtproxyRelaySuccessIsFresh(current)
		&& IsTerminalFailure(fact.status)
		&& !(fact.status.attempt == current.attempt)
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

void LogShadowedFact(
		not_null<RuntimeEnvironment*> runtime,
		const ProxyFact &fact) {
	WriteProxyDiagnosticsLine(runtime, {
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

[[nodiscard]] ProxyConnectionStatus ApplySelectedStatusUpdate(
		const ProxyConnectionStatus &current,
		ProxyConnectionStatus update) {
	if (IsOlderProxyGeneration(current.attempt, update.attempt)) {
		return current;
	}
	if (IsOlderAttempt(current.attempt, update.attempt)) {
		return current;
	}
	if (NonMtproxyRelaySuccessIsFresh(current)
		&& IsTerminalFailure(update)
		&& !(update.attempt == current.attempt)
		&& !IsNewerProxyEpoch(current.attempt, update.attempt)) {
		return current;
	}
	if (!IsMtproxyTerminalFailure(current.mtproxyReason)) {
		return update;
	}
	if (IsSuccess(update)
		|| IsMtproxyTerminalFailure(update.mtproxyReason)
		|| IsNewerAttempt(current.attempt, update.attempt)) {
		return update;
	}
	if (StickyWindowActive(current)) {
		return current;
	}
	return update;
}

} // namespace

ProxyControlPlane::ProxyControlPlane(not_null<RuntimeEnvironment*> runtime)
: _runtime(runtime) {
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
		fact.status.phase = ProxyConnectionPhase::CheckingTelegram;
		fact.successScope = ProxyControlPlaneSuccessScope::Handshake;
		return fact;
	case ProxyDiagnosticsPhase::MtpFirstDataReceived:
		fact.status.phase = ProxyConnectionPhase::Connected;
		fact.successScope = ProxyControlPlaneSuccessScope::Relay;
		return fact;
	case ProxyDiagnosticsPhase::Failed:
		fact.status.phase = ProxyConnectionPhase::Failed;
		return fact;
	case ProxyDiagnosticsPhase::ProxyCheckStarted:
	case ProxyDiagnosticsPhase::ProxyCheckFinished:
		fact.status.error = ProxyConnectionError::None;
		fact.status.mtproxyReason = ProxyMtproxyTerminalReason::None;
		return fact;
	case ProxyDiagnosticsPhase::None:
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
	case ProxyDiagnosticsPhase::AttemptSummary:
	case ProxyDiagnosticsPhase::Liveness:
		fact.status.error = ProxyConnectionError::None;
		fact.status.mtproxyReason = ProxyMtproxyTerminalReason::None;
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
	if (IsProxyCheck(fact.status.attempt.use)) {
		return current;
	}
	if (IsRelayDataStall(fact.status)) {
		fact.status.error = ProxyConnectionError::None;
	}
	if (fact.status.proxy.type == ProxyData::Type::Mtproto) {
		if (fact.successScope == ProxyControlPlaneSuccessScope::Relay) {
			fact.status.phase = ProxyConnectionPhase::Connected;
		}
		fact.status.successUntil = 0;
		return std::move(fact.status);
	}
	if (fact.successScope == ProxyControlPlaneSuccessScope::Relay) {
		fact.status.phase = ProxyConnectionPhase::Connected;
		fact.status.successUntil = crl::now()
			+ kNonMtproxyFreshRelaySuccessWindow;
	}
	if (ShadowedByFreshRelaySuccess(current, fact)) {
		return current;
	}
	return ApplySelectedStatusUpdate(
		current,
		std::move(fact.status));
}

void ProxyControlPlane::submitFact(const ProxyEventReport &report) {
	auto fact = FactFromReport(report);
	if (EmptyFact(fact)) {
		return;
	}
	InvokeQueued(_runtime, [=] { submitFactOnOwner(fact); });
}

void ProxyControlPlane::submitFactOnOwner(ProxyFact fact) {
	// Every proxy type, mtproxy included, now reduces into the same
	// connection status. There is no separate per-endpoint projection to
	// divert into: what the user sees is what the transport reported.
	const auto current = _runtime->instance().connectionStatus
		? _runtime->instance().connectionStatus->proxyStatus()
		: ProxyConnectionStatus();
	if (ShadowedByFreshRelaySuccess(current, fact)) {
		LogShadowedFact(_runtime, fact);
	}
	if (_runtime->instance().connectionStatus) {
		const auto reduced = ProxyControlPlane::Reduce(current, fact);
		_selectedStatus = reduced;
		_endpointSnapshot.proxy = reduced.proxy;
		_endpointSnapshot.status = reduced;
		_endpointSnapshot.relayProven = NonMtproxyRelaySuccessIsFresh(reduced);
		_runtime->instance().connectionStatus->setProxyStatus(reduced);
	}
}

} // namespace MTP
