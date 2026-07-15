/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "mtproto/proxy/control_plane.h"

#include "base/invoke_queued.h"
#include "base/timer.h"
#include "mtproto/proxy/mtproxy/endpoint_identity.h"
#include "mtproto/proxy/diagnostics.h"
#include "mtproto/proxy/proxy_endpoint_context.h"
#include "mtproto/proxy/transport_policy.h"
#include "mtproto/runtime/connection_status.h"
#include "mtproto/runtime/runtime_environment.h"

namespace MTP {
namespace {
namespace MtProxy = details::MtProxy;

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

[[nodiscard]] MtProxy::EndpointId EndpointForProxy(
		not_null<RuntimeEnvironment*> runtime,
		const ProxyData &proxy) {
	const auto settings = runtime->proxy().settings
		? runtime->proxy().settings()
		: ProxyData::Settings::Enabled;
	const auto saved = runtime->proxy().stealthOptions
		? runtime->proxy().stealthOptions()
		: ProxyStealthOptions();
	return MtProxy::EndpointIdFromProxy(
		proxy,
		EffectiveProxyStealthOptions(
			runtime,
			proxy,
			settings,
			saved));
}

[[nodiscard]] bool ActiveMainNetworkFact(
		const MtProxy::ProxyEndpointView &view,
		const ProxyConnectionStatus &status) {
	const auto &attempt = status.attempt;
	const auto exact = view.mainAttempt.attemptId
		&& attempt.runtimeId == view.runtimeGeneration.runtimeId
		&& attempt.proxyGeneration
			== view.runtimeGeneration.proxyGeneration
		&& attempt.use == ProxyConnectionUse::Main
		&& attempt.attemptId == view.mainAttempt.attemptId
		&& attempt.ticketKey == view.mainAttempt.ticketKey;
	if (!exact) {
		return false;
	}
	switch (status.phase) {
	case ProxyConnectionPhase::Resolving:
	case ProxyConnectionPhase::Connecting:
	case ProxyConnectionPhase::Handshake:
	case ProxyConnectionPhase::CheckingTelegram:
		return true;
	case ProxyConnectionPhase::None:
	case ProxyConnectionPhase::Connected:
	case ProxyConnectionPhase::Failed:
		return false;
	}
	return false;
}

[[nodiscard]] ProxyAdmissionPhase AdmissionPhaseForNetwork(
		ProxyConnectionPhase phase) {
	switch (phase) {
	case ProxyConnectionPhase::Resolving:
		return ProxyAdmissionPhase::Resolving;
	case ProxyConnectionPhase::Connecting:
		return ProxyAdmissionPhase::Tcp;
	case ProxyConnectionPhase::Handshake:
	case ProxyConnectionPhase::CheckingTelegram:
		return ProxyAdmissionPhase::FakeTls;
	case ProxyConnectionPhase::None:
	case ProxyConnectionPhase::Connected:
	case ProxyConnectionPhase::Failed:
		return ProxyAdmissionPhase::Idle;
	}
	return ProxyAdmissionPhase::Idle;
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

ProxyControlPlane::ProxyControlPlane(
	not_null<RuntimeEnvironment*> runtime,
	not_null<MtProxy::EndpointHealth*> endpointHealth)
: _runtime(runtime)
, _endpointHealth(endpointHealth) {
	_runtime->proxyEndpointContext().endpointViewChanges(
	) | rpl::on_next([=](MtProxy::EndpointViewInvalidation invalidation) {
		if (invalidation.runtimeGeneration.runtimeId
				== _runtime->proxyRuntimeId()) {
			invalidateMtproxyEndpointView(invalidation.endpoint);
		}
	}, _endpointViewLifetime);
}

void ProxyControlPlane::reportMtproxyFailure(
		MtProxy::FailureReport report) {
	const auto endpoint = report.endpoint;
	_endpointHealth->reportFailure(std::move(report));
	_runtime->proxyEndpointContext().notifyEndpointViewChanged(endpoint);
}

void ProxyControlPlane::reportMtproxySuccess(
		MtProxy::SuccessReport report) {
	const auto endpoint = report.endpoint;
	_endpointHealth->reportSuccess(std::move(report));
	_runtime->proxyEndpointContext().notifyEndpointViewChanged(endpoint);
}

void ProxyControlPlane::noteMtproxyRelayStall(
		MtProxy::RelayProofReport report) {
	const auto endpoint = report.endpoint;
	_endpointHealth->noteRelayStall(std::move(report));
	_runtime->proxyEndpointContext().notifyEndpointViewChanged(endpoint);
}

void ProxyControlPlane::retireMtproxyRelayProof(
		MtProxy::RelayProofReport report) {
	const auto endpoint = report.endpoint;
	_endpointHealth->retireRelayProof(std::move(report));
	_runtime->proxyEndpointContext().notifyEndpointViewChanged(endpoint);
}

void ProxyControlPlane::noteMtproxyEndpointSelected(
		const MtProxy::EndpointId &endpoint) {
	_selectedMtproxyEndpoint = endpoint;
	_endpointHealth->noteEndpointSelected(endpoint);
	_runtime->proxyEndpointContext().notifyEndpointViewChanged(endpoint);
}

void ProxyControlPlane::applyMtproxyProxyGeneration(
		uint64 proxyGeneration) {
	_mtproxyProxyGeneration = proxyGeneration;
	_endpointHealth->applyProxyGeneration(proxyGeneration);
	_runtime->proxyEndpointContext().notifyEndpointViewsChanged(
		_runtime->proxyRuntimeId());
	_runtime->proxyEndpointContext().notifyEndpointViewChanged(
		_selectedMtproxyEndpoint,
		{
			.runtimeId = _runtime->proxyRuntimeId(),
			.proxyGeneration = proxyGeneration,
		});
}

MtProxy::ProxyEndpointView ProxyControlPlane::mtproxyEndpointView(
		const MtProxy::EndpointId &endpoint) const {
	const auto runtimeId = _runtime->proxyRuntimeId();
	auto result = _mtproxyProxyGeneration
		? _runtime->proxyEndpointContext().endpointView(
			endpoint,
			RuntimeGenerationKey{
				.runtimeId = runtimeId,
				.proxyGeneration = _mtproxyProxyGeneration,
			})
		: _runtime->proxyEndpointContext().endpointView(endpoint, runtimeId);
	const auto i = _mainNetworkFacts.find(MtProxy::EndpointKey(endpoint));
	if (i != end(_mainNetworkFacts)
		&& ActiveMainNetworkFact(result, i->second.status)) {
		result.mainAttempt = i->second.status.attempt;
		result.networkPhase = i->second.status.phase;
		result.admissionPhase = AdmissionPhaseForNetwork(
			i->second.status.phase);
		result.phaseStartedAt = i->second.phaseStartedAt;
	} else if (result.canonicalVerdict
		&& result.admissionPhase != ProxyAdmissionPhase::Queued
		&& result.admissionPhase != ProxyAdmissionPhase::Scheduled) {
		result.admissionPhase = ProxyAdmissionPhase::Idle;
		result.networkPhase = ProxyConnectionPhase::None;
	}
	return result;
}

auto ProxyControlPlane::mtproxyEndpointViewChanges()
-> rpl::producer<MtProxy::ProxyEndpointView> {
	return _endpointViewEvents.events();
}

crl::time ProxyControlPlane::mtproxyEndpointRetryUntil(
		const MtProxy::EndpointId &endpoint,
		RuntimeGenerationKey runtimeGeneration) const {
	if (!runtimeGeneration.runtimeId
		|| !runtimeGeneration.proxyGeneration
		|| runtimeGeneration.runtimeId != _runtime->proxyRuntimeId()) {
		return 0;
	}
	return _runtime->proxyEndpointContext().endpointRetryUntil(
		endpoint,
		runtimeGeneration);
}

void ProxyControlPlane::invalidateMtproxyEndpointView(
		const MtProxy::EndpointId &endpoint) {
	if (MtProxy::EndpointEmpty(endpoint)) {
		return;
	}
	InvokeQueued(_runtime, [=] {
		_pendingEndpointViews.insert_or_assign(
			MtProxy::EndpointKey(endpoint),
			endpoint);
		if (_endpointViewFlushScheduled) {
			return;
		}
		_endpointViewFlushScheduled = true;
		InvokeQueued(_runtime, [=] { flushMtproxyEndpointViews(); });
	});
}

void ProxyControlPlane::flushMtproxyEndpointViews() {
	_endpointViewFlushScheduled = false;
	auto pending = std::map<QString, MtProxy::EndpointId>();
	pending.swap(_pendingEndpointViews);
	const auto selectedProxy = _runtime->proxy().selected
		? _runtime->proxy().selected()
		: ProxyData();
	if (selectedProxy.type == ProxyData::Type::Mtproto) {
		_selectedMtproxyEndpoint = EndpointForProxy(_runtime, selectedProxy);
	}
	const auto selectedKey = (selectedProxy.type
			== ProxyData::Type::Mtproto)
		? MtProxy::EndpointKey(_selectedMtproxyEndpoint)
		: QString();
	for (const auto &[endpointKey, endpoint] : pending) {
		const auto view = mtproxyEndpointView(endpoint);
		_endpointViewEvents.fire_copy(view);
		if (!selectedKey.isEmpty() && endpointKey == selectedKey) {
			updateSelectedMtproxyProjection(view);
		}
	}
}

void ProxyControlPlane::updateSelectedMtproxyProjection(
		const MtProxy::ProxyEndpointView &view) {
	const auto selected = _runtime->proxy().selected
		? _runtime->proxy().selected()
		: ProxyData();
	const auto proxy = (selected.type == ProxyData::Type::Mtproto)
		? selected
		: _selectedStatus.proxy;
	auto status = ProxyConnectionStatus{
		.proxy = proxy,
	};
	const auto hasMainProof = view.mainProof.strength
		!= MtProxy::MainRelayProofStrength::None;
	const auto network = _mainNetworkFacts.find(
		MtProxy::EndpointKey(view.endpoint));
	if (hasMainProof) {
		status.phase = ProxyConnectionPhase::Connected;
		const auto &current = _selectedStatus.attempt;
		status.attempt = (current.runtimeId
				== view.runtimeGeneration.runtimeId
			&& current.proxyGeneration
				== view.runtimeGeneration.proxyGeneration
			&& current.use == ProxyConnectionUse::Main)
			? current
			: ProxyConnectionAttempt{
				.runtimeId = view.runtimeGeneration.runtimeId,
				.proxyGeneration = view.runtimeGeneration.proxyGeneration,
				.use = ProxyConnectionUse::Main,
			};
	} else if (network != end(_mainNetworkFacts)
		&& ActiveMainNetworkFact(view, network->second.status)) {
		status = network->second.status;
		status.successUntil = 0;
		if (status.phase == ProxyConnectionPhase::Connected) {
			status.phase = ProxyConnectionPhase::CheckingTelegram;
		}
	} else if (view.admissionPhase != ProxyAdmissionPhase::Idle) {
		status.attempt = view.mainAttempt;
		switch (view.admissionPhase) {
		case ProxyAdmissionPhase::Resolving:
			status.phase = ProxyConnectionPhase::Resolving;
			break;
		case ProxyAdmissionPhase::FakeTls:
			status.phase = ProxyConnectionPhase::Handshake;
			break;
		case ProxyAdmissionPhase::Queued:
		case ProxyAdmissionPhase::Scheduled:
		case ProxyAdmissionPhase::Tcp:
			status.phase = ProxyConnectionPhase::Connecting;
			break;
		case ProxyAdmissionPhase::Idle:
			break;
		}
	} else if (view.canonicalVerdict) {
		const auto &verdict = *view.canonicalVerdict;
		status.attempt = verdict.sourceAttempt;
		status.terminalUntil = view.retryUntil;
		status.phase = ProxyConnectionPhase::Failed;
		status.error = MtProxy::ToProxyConnectionError(verdict.reason);
		status.mtproxyReason = MtProxy::ToProxyMtproxyTerminalReason(
			verdict.reason);
	}
	_selectedStatus = status;
	_endpointSnapshot = {
		.proxy = status.proxy,
		.status = status,
		.relayProven = hasMainProof,
	};
	if (_runtime->instance().connectionStatus) {
		_runtime->instance().connectionStatus->setProxyStatus(status);
	}
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
	if (fact.status.proxy.type == ProxyData::Type::Mtproto) {
		const auto &attempt = fact.status.attempt;
		if (attempt.runtimeId != _runtime->proxyRuntimeId()
			|| attempt.proxyGeneration != _mtproxyProxyGeneration
			|| attempt.use != ProxyConnectionUse::Main
			|| !attempt.attemptId) {
			return;
		}
		const auto endpoint = EndpointForProxy(
			_runtime,
			fact.status.proxy);
		if (MtProxy::EndpointEmpty(endpoint)) {
			return;
		}
		auto status = fact.status;
		if (IsRelayDataStall(status)) {
			status.error = ProxyConnectionError::None;
		}
		if (fact.successScope == ProxyControlPlaneSuccessScope::Relay) {
			status.phase = ProxyConnectionPhase::Connected;
		}
		status.successUntil = 0;
		auto &network = _mainNetworkFacts[MtProxy::EndpointKey(endpoint)];
		if (!(network.status.attempt == status.attempt)
			|| network.status.phase != status.phase) {
			network.phaseStartedAt = crl::now();
		}
		network.status = std::move(status);
		_selectedMtproxyEndpoint = endpoint;
		_endpointSnapshot.proxy = fact.status.proxy;
		invalidateMtproxyEndpointView(endpoint);
		return;
	}
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
