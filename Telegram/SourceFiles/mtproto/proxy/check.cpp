/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "mtproto/proxy/check.h"

#include "mtproto/config/mtproto_dc_options.h"
#include "mtproto/proxy/capabilities.h"
#include "mtproto/proxy/control_plane.h"
#include "mtproto/proxy/diagnostics.h"
#include "mtproto/proxy/mtproxy/endpoint_health_policy.h"
#include "mtproto/proxy/proxy_endpoint_context.h"
#include "mtproto/proxy/proxy_services.h"
#include "mtproto/proxy/transport_policy.h"
#include "mtproto/runtime/connection_status.h"
#include "mtproto/runtime/runtime_environment.h"
#include "mtproto/transport/details/mtproto_abstract_socket.h"

#include <QtCore/QHash>
#include <QtCore/QTimer>

#include <utility>

namespace MTP {

using Connection = details::AbstractConnection;
namespace MtProxy = details::MtProxy;
namespace {

QHash<QString, int> ActiveProxyCheckKeys;

void RetainActiveProxyCheckKey(const QString &key) {
	if (!key.isEmpty()) {
		ActiveProxyCheckKeys.insert(
			key,
			ActiveProxyCheckKeys.value(key) + 1);
	}
}

void ReleaseActiveProxyCheckKey(const QString &key) {
	if (key.isEmpty()) {
		return;
	}
	const auto count = ActiveProxyCheckKeys.value(key);
	if (count <= 1) {
		ActiveProxyCheckKeys.remove(key);
	} else {
		ActiveProxyCheckKeys.insert(key, count - 1);
	}
}

[[nodiscard]] ProxyCheckStatus ProxyCheckStatusForHandshake(
		details::HandshakePhase phase) {
	switch (phase) {
	case details::HandshakePhase::None:
		return ProxyCheckStatus::Resolving;
	case details::HandshakePhase::TcpConnected:
		return ProxyCheckStatus::TcpConnected;
	case details::HandshakePhase::ClientHelloSent:
		return ProxyCheckStatus::ClientHelloSent;
	case details::HandshakePhase::ServerHelloOk:
		return ProxyCheckStatus::ServerHelloOk;
	case details::HandshakePhase::FirstDataReceived:
		return ProxyCheckStatus::FirstTlsAppData;
	}
	return ProxyCheckStatus::Resolving;
}

void SetProxyCheckProgress(
		const std::shared_ptr<ProxyCheckConnection::Data> &state,
		ProxyCheckStatus status) {
	if (!state || state->finished) {
		return;
	}
	state->progressStatus = status;
	if (state->progress) {
		state->progress(status);
	}
}

[[nodiscard]] ProxyCheckStatus CurrentProxyCheckStatus(
		const ProxyCheckConnection &v4,
		const ProxyCheckConnection &v6) {
	if (v4) {
		return v4.state()->progressStatus;
	}
	if (v6) {
		return v6.state()->progressStatus;
	}
	return ProxyCheckStatus::Idle;
}

[[nodiscard]] bool ActiveSessionProvesProxy(
		not_null<RuntimeEnvironment*> runtime,
		const ProxyData &proxy,
		const ProxyStealthOptions &stealth) {
	if (proxy.type == ProxyData::Type::Mtproto) {
		const auto endpoint = MtProxy::EndpointIdFromProxy(proxy, stealth);
		const auto &control = runtime->proxyServices().control();
		const auto view = control.mtproxyEndpointView(endpoint);
		return view.mainProof.strength
			!= MtProxy::MainRelayProofStrength::None
			|| view.endpointMainProof.strength
			!= MtProxy::MainRelayProofStrength::None;
	}
	const auto status = runtime->instance().connectionStatus
		? runtime->instance().connectionStatus->proxyStatus()
		: ProxyConnectionStatus();
	return (status.phase == ProxyConnectionPhase::Connected)
		&& (status.proxy == proxy);
}

[[nodiscard]] ProxyFailureAttribution ProxyCheckFailureAttribution(
		MtProxy::FailureReason reason,
		const ProxyTransportFailure &failure) {
	if (failure.attribution != ProxyFailureAttribution::None) {
		return failure.attribution;
	} else if (failure.closeOrigin == ProxyCloseOrigin::PeerClosed) {
		return ProxyFailureAttribution::Peer;
	} else if (failure.error == ProxyConnectionError::Network
		|| failure.error == ProxyConnectionError::ConnectionRefused
		|| failure.error == ProxyConnectionError::HostNotFound) {
		return ProxyFailureAttribution::Network;
	} else if (reason == MtProxy::FailureReason::TlsAlertAfterClientHello) {
		return ProxyFailureAttribution::Client;
	} else if (reason == MtProxy::FailureReason::ServerHelloHmacMismatch
		|| reason == MtProxy::FailureReason::ProxyProtocolBadResponse) {
		return ProxyFailureAttribution::Peer;
	}
	return (reason == MtProxy::FailureReason::None)
		? ProxyFailureAttribution::None
		: ProxyFailureAttribution::Unclear;
}

[[nodiscard]] ProxyEventReport ProxyCheckAttemptReport(
		const std::shared_ptr<ProxyCheckConnection::Data> &state,
		const ProxyData &proxy,
		DcId dcId,
		details::AbstractConnection *connection,
		ProxyConnectionError error,
		MtProxy::FailureReason reason,
		ProxyDiagnosticsSeverity severity,
		const QString &message) {
	const auto failure = connection
		? connection->proxyTransportFailure()
		: ProxyTransportFailure();
	const auto attempt = connection
		? connection->proxyConnectionAttempt()
		: state->mtproxyAttempt;
	const auto now = crl::now();
	return {
		.error = (failure.error != ProxyConnectionError::None)
			? failure.error
			: (reason == MtProxy::FailureReason::None)
			? error
			: MtProxy::ToProxyConnectionError(reason),
		.mtproxyReason = MtProxy::ToProxyMtproxyTerminalReason(reason),
		.attempt = attempt,
		.severity = severity,
		.proxy = proxy,
		.transport = ProxyDiagnosticsTransportName(
			proxy.type,
			state->mtproxyPlan.stealth.transport),
		.dc = QString::number(dcId),
		.connectionId = connection ? connection->debugId() : QString(),
		.message = message,
		.canonical = ProxyDiagnosticsEndpointText(
			state->mtproxyEndpoint.canonical.originalHost,
			state->mtproxyEndpoint.canonical.port),
		.route = ProxyDiagnosticsEndpointText(
			state->mtproxyEndpoint.route.address,
			state->mtproxyEndpoint.route.port),
		.proxyKeyHash = ProxyDiagnosticsKeyHash(
			MtProxy::EndpointKey(state->mtproxyEndpoint.canonical)),
		.profile = failure.sentTlsProfile
			? ProxyDiagnosticsTlsProfileName(*failure.sentTlsProfile)
			: QString(),
		.configuredProfile = ProxyDiagnosticsTlsProfileName(
			state->mtproxyPlan.configuredTlsProfile),
		.effectiveProfile = ProxyDiagnosticsTlsProfileName(
			state->mtproxyPlan.effectiveTlsProfile),
		.recipeLevel = state->mtproxyPlan.admitted
			? std::make_optional(state->mtproxyPlan.recipeLevel)
			: std::nullopt,
		.pskOffered = failure.pskOffered,
		.fragmentedClientHello = failure.fragmentedClientHello,
		.clientHelloBytes = failure.clientHelloBytes,
		.clientHelloWrites = failure.clientHelloWrites,
		.clientHelloAcceptedBytes = failure.clientHelloAcceptedBytes,
		.clientHelloFragmentSplit = failure.clientHelloFragmentSplit,
		.clientHelloFragmentDelayMs = failure.clientHelloFragmentDelayMs,
		.rxAfterClientHello = failure.rxAfterClientHello,
		.rxClass = failure.rxClass,
		.tlsRecordType = failure.tlsRecordType,
		.tlsRecordVersion = failure.tlsRecordVersion,
		.tlsRecordLength = failure.tlsRecordLength,
		.responsePrefixHash = failure.responsePrefixHash,
		.sniLength = failure.sniLength,
		.sniHash = failure.sniHash,
		.parserStage = failure.parserStage,
		.closeOrigin = (failure.closeOrigin == ProxyCloseOrigin::None)
			? std::optional<ProxyCloseOrigin>()
			: std::make_optional(failure.closeOrigin),
		.dnsMs = failure.dnsMs,
		.tcpMs = failure.tcpMs,
		.firstRxMs = failure.firstRxMs,
		.serverHelloMs = failure.serverHelloMs,
		.appDataMs = failure.appDataMs,
		.mtprotoMs = (reason == MtProxy::FailureReason::None
			&& state->mtproxyAttemptStartedAt)
			? std::make_optional(now - state->mtproxyAttemptStartedAt)
			: std::nullopt,
		.totalMs = state->mtproxyAttemptStartedAt
			? std::make_optional(now - state->mtproxyAttemptStartedAt)
			: std::nullopt,
	};
}

[[nodiscard]] bool ClaimProxyCheckTerminal(
		not_null<RuntimeEnvironment*> runtime,
		const std::shared_ptr<ProxyCheckConnection::Data> &state) {
	return state->mtproxyAttempt.traceId
		&& runtime->proxyEndpointContext().finishTrace(
			state->mtproxyAttempt.traceId);
}

void ReportClaimedProxyCheckSummary(
		not_null<RuntimeEnvironment*> runtime,
		ProxyEventReport report) {
	report.phase = ProxyDiagnosticsPhase::AttemptSummary;
	report.traceSchema = 2;
	ReportProxyEvent(runtime, std::move(report));
}

} // namespace

[[nodiscard]] MtProxy::FailureReason ProxyCheckFailureReason(
		ProxyConnectionError error) {
	switch (error) {
	case ProxyConnectionError::HostNotFound:
		return MtProxy::FailureReason::DnsFailed;
	case ProxyConnectionError::Timeout:
		return MtProxy::FailureReason::TcpConnectTimeout;
	case ProxyConnectionError::RemoteClosed:
		return MtProxy::FailureReason::AppDataRemoteClosed;
	case ProxyConnectionError::Network:
		return MtProxy::FailureReason::Network;
	case ProxyConnectionError::ConnectionRefused:
	case ProxyConnectionError::Authentication:
	case ProxyConnectionError::ProxyProtocol:
	case ProxyConnectionError::BadResponse:
	case ProxyConnectionError::Unknown:
	case ProxyConnectionError::None:
		return MtProxy::FailureReason::ProxyProtocolBadResponse;
	}
	return MtProxy::FailureReason::ProxyProtocolBadResponse;
}

ProxyCheckConnection::ProxyCheckConnection()
: _data(std::make_shared<Data>()) {
}

ProxyCheckConnection::ProxyCheckConnection(
		ProxyCheckConnection &&other) noexcept
: _data(std::move(other._data)) {
}

ProxyCheckConnection &ProxyCheckConnection::operator=(
		ProxyCheckConnection &&other) noexcept {
	if (this != &other) {
		reset();
		_data = std::move(other._data);
	}
	return *this;
}

ProxyCheckConnection::~ProxyCheckConnection() {
	reset();
}

Connection *ProxyCheckConnection::get() const {
	return _data ? _data->connection.get() : nullptr;
}

ProxyCheckConnection::operator bool() const {
	return get() != nullptr;
}

Connection *ProxyCheckConnection::operator->() const {
	return get();
}

std::shared_ptr<ProxyCheckConnection::Data> ProxyCheckConnection::state() const {
	return _data;
}

void ProxyCheckConnection::reset() {
	if (_data) {
		_data->connectionTicket.cancel();
		if (_data->runtime && _data->mtproxyAttempt.traceId) {
			const auto runtime = not_null{ _data->runtime };
			if (ClaimProxyCheckTerminal(runtime, _data)) {
				auto report = ProxyCheckAttemptReport(
					_data,
					_data->proxy,
					_data->dcId,
					_data->connection.get(),
					ProxyConnectionError::None,
					MtProxy::FailureReason::None,
					ProxyDiagnosticsSeverity::Warning,
					u"proxy_check_owner_destroyed"_q);
				report.closeOrigin = ProxyCloseOrigin::OwnerDestroyed;
				ReportClaimedProxyCheckSummary(runtime, std::move(report));
			}
		}
		_data->handshakeGate.release();
		_data->mtproxyLease.release();
		_data->mtproxyEndpoint = MtProxy::EndpointId();
		_data->mtproxyAttempt = {};
		_data->mtproxyPlan = {};
		_data->mtproxyAttemptStartedAt = 0;
		_data->finished = true;
		_data->networkStarted = false;
		_data->progressStatus = ProxyCheckStatus::Idle;
		_data->runtime = nullptr;
		_data->proxy = ProxyData();
		_data->dcId = 0;
		if (!_data->probeKey.isEmpty()) {
			ReleaseActiveProxyCheckKey(_data->probeKey);
			_data->probeKey.clear();
		}
		_data->connection = nullptr;
	}
}

void ResetProxyCheckers(
		ProxyCheckConnection &v4,
		ProxyCheckConnection &v6) {
	v4.reset();
	v6.reset();
}

void DropProxyChecker(
		ProxyCheckConnection &v4,
		ProxyCheckConnection &v6,
		not_null<Connection*> raw) {
	if (v4.get() == raw) {
		v4.reset();
	} else if (v6.get() == raw) {
		v6.reset();
	}
}

bool HasProxyCheckers(
		const ProxyCheckConnection &v4,
		const ProxyCheckConnection &v6) {
	return v4 || v6;
}

void StartProxyCheck(
		not_null<RuntimeEnvironment*> runtime,
		const ProxyData &proxy,
		bool tryIPv6,
		const ProxyStealthOptions &stealth,
	ProxyCheckConnection &v4,
	ProxyCheckConnection &v6,
	Fn<void(Connection *raw, int ping)> done,
	Fn<void(Connection *raw)> fail,
	Fn<void(ProxyCheckStatus status)> progress) {
	using Variants = DcOptions::Variants;

	const auto connType = (proxy.type == ProxyData::Type::Http)
		? Variants::Http
		: Variants::Tcp;
	const auto dcId = runtime->instance().mainDcId ? runtime->instance().mainDcId() : DcId();
	const auto checkStealth = MTP::EffectiveProxyStealthOptions(
		runtime,
		proxy,
		ProxyData::Settings::Enabled,
		stealth);
	const auto probeKey = ProxyCapabilityKey(proxy);
	if (progress && HasProxyCheckers(v4, v6)) {
		progress(CurrentProxyCheckStatus(v4, v6));
		return;
	}
	if (progress
		&& !probeKey.isEmpty()
		&& ActiveProxyCheckKeys.contains(probeKey)) {
		progress(ProxyCheckStatus::WaitingForConnectionSlot);
		return;
	}
	if (progress && ActiveSessionProvesProxy(runtime, proxy, checkStealth)) {
		progress(ProxyCheckStatus::ConnectedByActiveSession);
		return;
	}
	ResetProxyCheckers(v4, v6);
	ReportProxyEvent(runtime, {
		.phase = ProxyDiagnosticsPhase::ProxyCheckStarted,
		.proxy = proxy,
		.dc = QString::number(dcId),
		.message = u"proxy check started"_q,
	});
	const auto finishWithFail = [=](
			const auto &state,
			Connection *raw,
			ProxyConnectionError error) {
		if (state->connection.get() != raw || state->finished) {
			return;
		}
		state->finished = true;
		state->networkStarted = false;
		state->connectionTicket.cancel();
		state->handshakeGate.release();
		if (!MtProxy::EndpointEmpty(state->mtproxyEndpoint)) {
			const auto transportFailure = raw->proxyTransportFailure();
			const auto reason =
				(transportFailure.reason != ProxyMtproxyTerminalReason::None)
				? MtProxy::FromProxyMtproxyTerminalReason(
					transportFailure.reason)
				: ProxyCheckFailureReason(error);
			if (ClaimProxyCheckTerminal(runtime, state)) {
				runtime->proxyServices().control().reportMtproxyFailure({
					.endpoint = state->mtproxyEndpoint,
					.use = MtProxy::EndpointUse::ProxyCheck,
					.runtimeId = state->mtproxyAttempt.runtimeId,
					.reason = reason,
					.configuredTlsProfile
						= state->mtproxyPlan.configuredTlsProfile,
					.sentProfile = transportFailure.sentTlsProfile.value_or(
						state->mtproxyPlan.effectiveTlsProfile),
					.lease = &state->mtproxyLease,
					.proxyGeneration = state->mtproxyAttempt.proxyGeneration,
					.attemptId = state->mtproxyAttempt.attemptId,
					.proxyEpoch = state->mtproxyAttempt.proxyEpoch,
					.successEpoch = state->mtproxyAttempt.successEpoch,
					.attemptStartedAt = state->mtproxyAttemptStartedAt,
					.routesExhausted = true,
					.ticketKey = state->mtproxyAttempt.ticketKey,
					.attribution = ProxyCheckFailureAttribution(
						reason,
						transportFailure),
					.terminalAt = crl::now(),
				});
				ReportClaimedProxyCheckSummary(
					runtime,
					ProxyCheckAttemptReport(
						state,
						proxy,
						dcId,
						raw,
						error,
						reason,
						ProxyDiagnosticsSeverity::Error,
						u"proxy_check_failed"_q));
			}
		}
		ReportProxyEvent(runtime, {
			.phase = ProxyDiagnosticsPhase::ProxyCheckFinished,
			.error = error,
			.severity = ProxyDiagnosticsSeverity::Error,
			.proxy = proxy,
			.dc = QString::number(dcId),
			.connectionId = raw->debugId(),
			.message = u"proxy check failed"_q,
		});
		if (fail) {
			fail(raw);
		}
	};
	const auto setup = [&](
			ProxyCheckConnection &checker,
			const bytes::vector &secret) {
		const auto state = checker.state();
		state->runtime = runtime;
		state->proxy = proxy;
		state->dcId = dcId;
		state->progress = progress;
		state->probeKey = probeKey;
		RetainActiveProxyCheckKey(probeKey);
		state->progressStatus = ProxyCheckStatus::Idle;
		state->networkStarted = false;
		auto handshakeGate = details::ReserveHandshakeGateForProxy(
			runtime,
			proxy);
		state->connection = Connection::Create(
			runtime,
			connType,
			QThread::currentThread(),
			secret,
			proxy,
			checkStealth);
		state->finished = false;
		state->handshakeGate = std::move(handshakeGate);
		const auto raw = state->connection.get();
		raw->connect(raw, &Connection::connected, [=] {
			if (state->connection.get() != raw || state->finished) {
				return;
			}
			if (!MtProxy::EndpointEmpty(state->mtproxyEndpoint)
				&& !ClaimProxyCheckTerminal(runtime, state)) {
				return;
			}
			SetProxyCheckProgress(
				state,
				ProxyCheckStatus::FirstMtprotoPayload);
			state->finished = true;
			state->networkStarted = false;
			state->connectionTicket.cancel();
			state->handshakeGate.release();
			if (!MtProxy::EndpointEmpty(state->mtproxyEndpoint)) {
				runtime->proxyServices().control().reportMtproxySuccess({
					.endpoint = state->mtproxyEndpoint,
					.use = MtProxy::EndpointUse::ProxyCheck,
					.runtimeId = state->mtproxyAttempt.runtimeId,
					.stealth = state->mtproxyStealth,
					.sentProfile = state->mtproxySentProfile,
					.lease = &state->mtproxyLease,
					.proxyGeneration = state->mtproxyAttempt.proxyGeneration,
					.attemptId = state->mtproxyAttempt.attemptId,
					.proxyEpoch = state->mtproxyAttempt.proxyEpoch,
					.successEpoch = state->mtproxyAttempt.successEpoch,
					.attemptStartedAt = state->mtproxyAttemptStartedAt,
					.scope = MtProxy::SuccessScope::Relay,
					.ticketKey = state->mtproxyAttempt.ticketKey,
					.payloadAt = crl::now(),
				});
				ReportClaimedProxyCheckSummary(
					runtime,
					ProxyCheckAttemptReport(
						state,
						proxy,
						dcId,
						raw,
						ProxyConnectionError::None,
						MtProxy::FailureReason::None,
						ProxyDiagnosticsSeverity::Info,
						u"proxy_check_relay_ready"_q));
			}
			ReportProxyEvent(runtime, {
				.phase = ProxyDiagnosticsPhase::ProxyCheckFinished,
				.proxy = proxy,
				.dc = QString::number(dcId),
				.connectionId = raw->debugId(),
				.message = u"proxy check succeeded"_q,
			});
			if (done) {
				done(raw, raw->pingTime());
			}
		});
		raw->connect(raw, &Connection::disconnected, [=] {
			finishWithFail(state, raw, ProxyConnectionError::RemoteClosed);
		});
		raw->connect(raw, &Connection::error, [=] {
			finishWithFail(state, raw, ProxyConnectionError::Unknown);
		});
		raw->connect(raw, &Connection::handshakeProgress, [=] {
			if (state->connection.get() != raw || state->finished) {
				return;
			}
			SetProxyCheckProgress(
				state,
				ProxyCheckStatusForHandshake(raw->handshakePhase()));
		});
	};
	const auto start = [&](
			ProxyCheckConnection &checker,
			QString address,
			int port,
			bytes::vector secret) {
		const auto state = checker.state();
		const auto raw = state->connection.get();
		const auto gateDelay = state->handshakeGate.delay();
		const auto endpoint = (proxy.type == ProxyData::Type::Mtproto)
			? MtProxy::EndpointIdFromProxy(proxy, checkStealth)
			: MtProxy::EndpointId();
		const auto proxyGeneration = MtProxy::EndpointEmpty(endpoint)
			? uint64()
			: runtime->proxyServices().control().mtproxyEndpointView(
				endpoint).runtimeGeneration.proxyGeneration;
		state->connectionTicket = runtime->proxyServices().broker().request({
			.proxyGeneration = proxyGeneration,
			.endpoint = endpoint,
			.proxy = proxy,
			.use = MtProxy::EndpointUse::ProxyCheck,
			.stealth = checkStealth,
			.configuredTlsProfile = checkStealth.tlsProfile,
			.notBefore = gateDelay,
			.context = raw,
			.start = [=, secret = std::move(secret)](
					details::ConnectionStart start) mutable {
				if (state->connection.get() != raw) {
					return;
				}
				state->mtproxyEndpoint = start.endpoint;
				state->mtproxyLease = std::move(start.lease);
				state->mtproxyStealth = start.stealth;
				state->mtproxySentProfile = start.effectiveTlsProfile;
				state->mtproxyAttempt = start.attempt;
				state->mtproxyAttempt.connectionId = raw->debugId();
				state->mtproxyPlan = start.plan;
				state->mtproxyAttemptStartedAt = start.attemptStartedAt;
				state->networkStarted = true;
				SetProxyCheckProgress(state, ProxyCheckStatus::Resolving);
				raw->connectToServer(
					address,
					port,
					secret,
					dcId,
					false,
					{
						.mtproxyAttempt = state->mtproxyAttempt,
						.mtproxyPlan = start.plan,
						.mtproxyAttemptStartedAt = start.attemptStartedAt,
					});
				QTimer::singleShot(int(raw->fullConnectTimeout()), raw, [=] {
					if (state->connection.get() != raw || state->finished) {
						return;
					}
					raw->timedOut();
					finishWithFail(state, raw, ProxyConnectionError::Timeout);
				});
			},
			.status = [=](details::ConnectionBrokerDecision decision) {
				if (state->connection.get() != raw || state->finished) {
					return;
				}
				if (decision.action
						== details::ConnectionBrokerAction::Rejected) {
					finishWithFail(
						state,
						raw,
						ProxyConnectionError::Unknown);
				} else if (decision.action
						== details::ConnectionBrokerAction::Queued
					|| decision.action
						== details::ConnectionBrokerAction::StartAfter) {
					SetProxyCheckProgress(
						state,
						ProxyCheckStatus::WaitingForConnectionSlot);
				}
			},
		});
		if (!state->connectionTicket) {
			finishWithFail(state, raw, ProxyConnectionError::Unknown);
		}
	};
	if (proxy.type == ProxyData::Type::Mtproto) {
		const auto secret = proxy.secretFromMtprotoPassword();
		setup(v4, secret);
		start(
			v4,
			proxy.host,
			proxy.port,
			secret);
		return;
	}
	if (!runtime->instance().dcOptionsLookup) {
		return;
	}
	const auto options = runtime->instance().dcOptionsLookup(dcId, DcType::Regular, true);
	const auto tryConnect = [&](
			ProxyCheckConnection &checker,
			Variants::Address address) {
		const auto &list = options.data[address][connType];
		if (list.empty() || ((address == Variants::IPv6) && !tryIPv6)) {
			checker.reset();
			return;
		}
		const auto &endpoint = list.front();
		setup(checker, endpoint.secret);
		start(
			checker,
			QString::fromStdString(endpoint.ip),
			endpoint.port,
			endpoint.secret);
	};
	tryConnect(v4, Variants::IPv4);
	tryConnect(v6, Variants::IPv6);
}

} // namespace MTP
