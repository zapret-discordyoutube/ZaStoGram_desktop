/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "mtproto/proxy/resolving_connection.h"

#include "mtproto/proxy/capabilities.h"
#include "mtproto/proxy/diagnostics.h"
#include "mtproto/proxy/dns_resolver_cache.h"
#include "mtproto/proxy/mtproxy/endpoint_identity.h"
#include "mtproto/proxy/proxy_endpoint_context.h"
#include "mtproto/proxy/proxy_services.h"
#include "mtproto/runtime/runtime_environment.h"
#include "mtproto/transport/details/mtproto_abstract_socket.h"

#include <algorithm>
#include <tuple>

namespace MTP {
namespace details {
namespace {

constexpr auto kRouteAttemptTimeout = crl::time(4000);
constexpr auto kRouteRaceDelay = crl::time(300);
constexpr auto kMaxParallelRouteAttempts = 2;
constexpr auto kColdServerHelloTimeout = crl::time(5000);
constexpr auto kFullConnectTimeoutSafetyMargin = crl::time(500);
constexpr auto kFullConnectTimeout = crl::time(12600);

// When the running attempt is the last route available there is nothing
// to race it against - killing it at the short timeout only burns a
// handshake and reconnects. Give TCP time to retransmit SYN instead: a
// proxy that throttles new connects often accepts on a later try. This
// also covers the post-handshake wait for the proxy to relay telegram
// data (its own dial to the DC), which racing cannot speed up.
constexpr auto kOnlyRouteAttemptTimeout = crl::time(8000);

// The route attempt timer knows nothing about handshakes by itself, so
// when it fires the failure must be attributed from the phase the child
// socket actually reached - reporting a generic tcp_connect_timeout for
// a connection that completed TCP (or even the whole TLS handshake)
// corrupts diagnostics.
[[nodiscard]] MtProxy::FailureReason RouteTimeoutReason(
		HandshakePhase phase) {
	switch (phase) {
	case HandshakePhase::None:
		return MtProxy::FailureReason::TcpConnectTimeout;
	case HandshakePhase::TcpConnected:
		return MtProxy::FailureReason::TcpConnectedNoClientHelloWrite;
	case HandshakePhase::ClientHelloSent:
		return MtProxy::FailureReason::ClientHelloSentNoServerHello;
	case HandshakePhase::ServerHelloOk:
		return MtProxy::FailureReason::ServerHelloOkNoAppData;
	case HandshakePhase::FirstDataReceived:
		return MtProxy::FailureReason::ServerHelloOkNoMtprotoData;
	}
	return MtProxy::FailureReason::TcpConnectTimeout;
}

[[nodiscard]] HandshakePhase ChildHandshakePhase(
		AbstractConnection *child) {
	return child ? child->handshakePhase() : HandshakePhase::None;
}

[[nodiscard]] MtProxy::FailureReason ChildFailureReason(
		AbstractConnection *child,
		int errorCode) {
	if (child) {
		const auto failure = child->proxyTransportFailure();
		if (failure.reason != ProxyMtproxyTerminalReason::None) {
			return MtProxy::FromProxyMtproxyTerminalReason(failure.reason);
		}
	}
	const auto reason = MtProxy::FailureReasonFromErrorCode(errorCode);
	return (reason == MtProxy::FailureReason::None)
		? MtProxy::FailureReason::TcpConnectTimeout
		: reason;
}

[[nodiscard]] MtProxy::EndpointId MtproxyEndpointIdForRoute(
		const ProxyData &proxy,
		int ipIndex) {
	auto stealth = ProxyStealthOptions();
	stealth.transport = ProxyTransport::Tcp;
	const auto address = (ipIndex >= 0 && ipIndex < proxy.resolvedIPs.size())
		? proxy.resolvedIPs[ipIndex]
		: QString();
	return MtProxy::EndpointIdFromProxy(
		proxy,
		stealth,
		address,
		int(proxy.port));
}

[[nodiscard]] ProxyFailureAttribution DefaultFailureAttribution(
		const ProxyTransportFailure &failure) {
	if (failure.closeOrigin == ProxyCloseOrigin::PeerClosed) {
		return ProxyFailureAttribution::Peer;
	} else if (failure.error == ProxyConnectionError::Network
		|| failure.error == ProxyConnectionError::ConnectionRefused
		|| failure.error == ProxyConnectionError::HostNotFound) {
		return ProxyFailureAttribution::Network;
	}
	const auto reason = MtProxy::FromProxyMtproxyTerminalReason(failure.reason);
	if (reason == MtProxy::FailureReason::TlsAlertAfterClientHello) {
		return ProxyFailureAttribution::Client;
	} else if (reason == MtProxy::FailureReason::ServerHelloHmacMismatch
		|| reason == MtProxy::FailureReason::ServerHelloForeignTls
		|| reason == MtProxy::FailureReason::ProxyProtocolBadResponse) {
		return ProxyFailureAttribution::Peer;
	}
	return (reason == MtProxy::FailureReason::None)
		? ProxyFailureAttribution::None
		: ProxyFailureAttribution::Unclear;
}

[[nodiscard]] int FailureReasonSpecificity(
		ProxyMtproxyTerminalReason reason) {
	switch (reason) {
	case ProxyMtproxyTerminalReason::None:
		return 0;
	case ProxyMtproxyTerminalReason::DnsFailed:
		return 10;
	case ProxyMtproxyTerminalReason::TcpConnectTimeout:
		return 20;
	case ProxyMtproxyTerminalReason::TcpConnectedNoClientHelloWrite:
		return 30;
	case ProxyMtproxyTerminalReason::ClientHelloSentNoServerHello:
		return 40;
	case ProxyMtproxyTerminalReason::TlsAlertAfterClientHello:
		return 50;
	case ProxyMtproxyTerminalReason::ServerHelloHmacMismatch:
		return 60;
	case ProxyMtproxyTerminalReason::ServerHelloForeignTls:
		return 62;
	case ProxyMtproxyTerminalReason::ProxyProtocolBadResponse:
		return 65;
	case ProxyMtproxyTerminalReason::ServerHelloOkNoAppData:
		return 70;
	case ProxyMtproxyTerminalReason::ServerHelloOkNoMtprotoData:
	case ProxyMtproxyTerminalReason::ConnectedNoMtprotoData:
		return 80;
	case ProxyMtproxyTerminalReason::AppDataRemoteClosed:
		return 90;
	case ProxyMtproxyTerminalReason::MtpReceiveTimeoutAfterData:
		return 100;
	}
	return 0;
}

[[nodiscard]] int FailureAttributionSpecificity(
		ProxyFailureAttribution attribution) {
	switch (attribution) {
	case ProxyFailureAttribution::None:
		return 0;
	case ProxyFailureAttribution::Unclear:
		return 1;
	case ProxyFailureAttribution::Local:
		return 2;
	case ProxyFailureAttribution::Network:
		return 3;
	case ProxyFailureAttribution::Client:
	case ProxyFailureAttribution::Peer:
		return 4;
	}
	return 0;
}

[[nodiscard]] int FailureErrorSpecificity(ProxyConnectionError error) {
	switch (error) {
	case ProxyConnectionError::None:
	case ProxyConnectionError::Unknown:
		return 0;
	case ProxyConnectionError::Timeout:
		return 1;
	case ProxyConnectionError::HostNotFound:
	case ProxyConnectionError::Network:
		return 2;
	case ProxyConnectionError::ConnectionRefused:
	case ProxyConnectionError::RemoteClosed:
		return 3;
	case ProxyConnectionError::Authentication:
	case ProxyConnectionError::ProxyProtocol:
	case ProxyConnectionError::BadResponse:
		return 4;
	}
	return 0;
}

[[nodiscard]] std::tuple<int, int, int> FailureSpecificity(
		const ProxyTransportFailure &failure) {
	return {
		FailureReasonSpecificity(failure.reason),
		FailureAttributionSpecificity(failure.attribution),
		FailureErrorSpecificity(failure.error),
	};
}

[[nodiscard]] ProxyTransportFailure TypedRouteFailure(
		AbstractConnection *child,
		MtProxy::FailureReason fallbackReason,
		ProxyConnectionError fallbackError,
		ProxyCloseOrigin fallbackOrigin) {
	auto result = child
		? child->proxyTransportFailure()
		: ProxyTransportFailure();
	if (result.reason == ProxyMtproxyTerminalReason::None) {
		result.reason = MtProxy::ToProxyMtproxyTerminalReason(
			fallbackReason);
	}
	if (result.error == ProxyConnectionError::None) {
		result.error = fallbackError;
	}
	if (result.closeOrigin == ProxyCloseOrigin::None) {
		result.closeOrigin = fallbackOrigin;
	}
	if (result.attribution == ProxyFailureAttribution::None) {
		result.attribution = DefaultFailureAttribution(result);
	}
	return result;
}

void MergeExhaustedFailure(
		ProxyTransportFailure &result,
		ProxyTransportFailure failure) {
	if (FailureSpecificity(failure) > FailureSpecificity(result)) {
		result = std::move(failure);
	}
}

enum class RouteOutcomeKind {
	RaceLost,
	Failed,
};

void RecordRouteOutcome(
		not_null<RuntimeEnvironment*> runtime,
		const ProxyData &proxy,
		int ipIndex,
		RouteOutcomeKind kind,
		MtProxy::FailureReason reason) {
	if (proxy.type != ProxyData::Type::Mtproto
		|| kind == RouteOutcomeKind::RaceLost) {
		return;
	}
	const auto endpoint = MtproxyEndpointIdForRoute(proxy, ipIndex);
	// Route memory only: "this address of this proxy did not answer". It
	// never feeds back into the handshake shape.
	runtime->proxyServices().capabilities().noteMtproxyFailure(
		MtProxy::CapabilityProxyKey(endpoint.canonical),
		MtProxy::RouteKey(endpoint.route),
		MtProxy::ToLegacyDiagnostic(reason));
}

void ReportRouteEvent(
		not_null<RuntimeEnvironment*> runtime,
		const ProxyData &proxy,
		int ipIndex,
		ProxyDiagnosticsPhase phase,
		ProxyConnectionAttempt attempt,
		MtProxy::FailureReason reason = MtProxy::FailureReason::None,
		std::optional<crl::time> dnsMs = std::nullopt,
		std::optional<ProxyCloseOrigin> closeOrigin = std::nullopt,
		ProxyConnectionError connectionError = ProxyConnectionError::None) {
	if (proxy.type != ProxyData::Type::Mtproto) {
		return;
	}
	const auto endpoint = MtproxyEndpointIdForRoute(proxy, ipIndex);
	const auto routeKey = MtProxy::RouteKey(endpoint.route);
	const auto routeText = ProxyDiagnosticsEndpointText(
		endpoint.route.address,
		endpoint.route.port);
	const auto failurePhase = MtProxy::ToLegacyDiagnostic(reason);
	const auto routeRaceLost = closeOrigin
		&& (*closeOrigin == ProxyCloseOrigin::RouteRaceLost)
		&& (reason == MtProxy::FailureReason::None);
	ReportProxyEvent(runtime, {
		.phase = phase,
		.error = (connectionError == ProxyConnectionError::None)
			? MtProxy::ToProxyConnectionError(reason)
			: connectionError,
		.mtproxyReason = MtProxy::ToProxyMtproxyTerminalReason(reason),
		.attempt = std::move(attempt),
		.severity = routeRaceLost
			? ProxyDiagnosticsSeverity::Info
			: (phase == ProxyDiagnosticsPhase::RouteFailed)
			? ProxyDiagnosticsSeverity::Warning
			: ProxyDiagnosticsSeverity::Info,
		.proxy = proxy,
		.transport = ProxyDiagnosticsTransportName(
			proxy,
			ProxyTransport::Tcp),
		.message = routeRaceLost
			? u"mtproxy route race lost"_q
			: (phase == ProxyDiagnosticsPhase::RouteFailed)
			? u"mtproxy route failed"_q
			: u"mtproxy route selected"_q,
		.canonical = ProxyDiagnosticsEndpointText(
			endpoint.canonical.originalHost,
			endpoint.canonical.port),
		.route = routeText.isEmpty() ? routeKey : routeText,
		.proxyKeyHash = ProxyDiagnosticsKeyHash(
			MtProxy::EndpointKey(endpoint.canonical)),
		.phaseAtFailure = (phase == ProxyDiagnosticsPhase::RouteFailed
			&& reason != MtProxy::FailureReason::None)
			? (failurePhase.isEmpty()
				? u"tcp_not_connected"_q
				: failurePhase)
			: QString(),
		.closeOrigin = closeOrigin,
		.dnsMs = dnsMs,
	});
}

} // namespace

ResolvingConnection::ResolvingConnection(
	not_null<RuntimeEnvironment*> runtime,
	QThread *thread,
	const ProxyData &proxy,
	ConnectionPointer &&child)
: AbstractConnection(runtime, thread, proxy)
, _child(std::move(child))
, _timeoutTimer([=] { handleRouteAttemptTimeout(); })
, _routeRaceTimer([=] { startNextRouteAttempt(); }) {
}

ConnectionPointer ResolvingConnection::clone(const ProxyData &proxy) {
	Unexpected("ResolvingConnection::clone call.");
}

void ResolvingConnection::startResolving() {
	if (_resolvingStartedAt || !_child) {
		return;
	}
	_resolvingStartedAt = crl::now();
	_resolvingDeadline = _resolvingStartedAt + kRouteAttemptTimeout;
	refreshAttemptTimeout();
	ReportProxyEvent(_runtime, {
		.phase = ProxyDiagnosticsPhase::Resolving,
		.attempt = _mtproxyAttempt,
		.proxy = _proxy,
		.message = u"resolving proxy host"_q,
	});
	const auto host = _proxy.host;
	_runtime->proxyServices().dnsResolver().request(
		this,
		host,
		[=](QString host, QStringList ips, qint64 expireAt) {
			domainResolved(host, ips, expireAt);
		});
}

void ResolvingConnection::addRouteAttempt(int ipIndex) {
	if (!_child
		|| ipIndex < 0
		|| ipIndex >= int(_proxy.resolvedIPs.size())) {
		return;
	}
	auto attempt = RouteAttempt();
	attempt.ipIndex = ipIndex;
	attempt.routeAttemptId = ++_lastRouteAttemptId;
	attempt.child = _child->clone(ToDirectIpProxy(_proxy, ipIndex));
	const auto raw = attempt.child.get();
	attempt.phase = ChildHandshakePhase(raw);
	attempt.phaseEnteredAt = crl::now();
	connect(
		raw,
		&AbstractConnection::receivedData,
		this,
		[=] { handleReceivedData(raw); });
	connect(
		raw,
		&AbstractConnection::receivedSome,
		this,
		&ResolvingConnection::receivedSome);
	connect(
		raw,
		&AbstractConnection::handshakeProgress,
		this,
		[=] {
			refreshAttemptTimeout();
			handshakeProgress();
		});
	connect(
		raw,
		&AbstractConnection::error,
		this,
		[=](int errorCode) { handleError(raw, errorCode); });
	connect(raw,
		&AbstractConnection::connected,
		this,
		[=] { handleConnected(raw); });
	connect(raw,
		&AbstractConnection::disconnected,
		this,
		[=] { handleDisconnected(raw); });
	_routeAttempts.push_back(std::move(attempt));
	auto &stored = _routeAttempts.back();
	stored.wrapperDeadline = stored.phaseEnteredAt
		+ routePhaseBudget(stored.phase);
	if (_protocolDcId) {
		auto routeConnectionAttempt = _mtproxyAttempt;
		routeConnectionAttempt.routeAttemptId = stored.routeAttemptId;
		stored.child->connectToServer(
			_address,
			_port,
			_protocolSecret,
			_protocolDcId,
			_protocolForFiles,
			{
				.mtproxyAttempt = routeConnectionAttempt,
				.mtproxyPlan = _mtproxyPlan,
				.mtproxyAttemptStartedAt = _mtproxyAttemptStartedAt,
			});
		CONNECTION_LOG_INFO("Resolving connected a new child: "
			+ stored.child->debugId());
	}
	ReportRouteEvent(
		_runtime,
		_proxy,
		ipIndex,
		ProxyDiagnosticsPhase::RouteSelected,
		[&] {
			auto result = _mtproxyAttempt;
			result.routeAttemptId = _lastRouteAttemptId;
			return result;
		}(),
		MtProxy::FailureReason::None,
		_dnsDuration,
		std::nullopt);
	refreshAttemptTimeout();
}

std::vector<int> ResolvingConnection::routeOrder() const {
	auto result = std::vector<int>();
	result.reserve(_proxy.resolvedIPs.size());
	const auto append = [&](int index) {
		if (std::find(begin(result), end(result), index) == end(result)) {
			result.push_back(index);
		}
	};
	if (_proxy.type != ProxyData::Type::Mtproto) {
		for (auto index = 0; index != int(_proxy.resolvedIPs.size()); ++index) {
			append(index);
		}
		return result;
	}
	const auto capability = _runtime->proxyServices().capabilities().lookup(
		_proxy);
	const auto keyOf = [&](int index) {
		return MtProxy::RouteKey(MtProxy::RouteEndpointFromAddress(
			_proxy.resolvedIPs[index],
			int(_proxy.port),
			ProxyTransport::Tcp,
			_proxy.originalHost.isEmpty()
				? _proxy.host
				: _proxy.originalHost));
	};
	const auto listed = [](const std::vector<QString> &list,
			const QString &key) {
		return std::find(begin(list), end(list), key) != end(list);
	};
	// Addresses that answered last time first, then untried ones, then the
	// ones that already failed - a blackholed IP of a multi-homed proxy
	// should not keep being the first thing we dial.
	for (auto index = 0; index != int(_proxy.resolvedIPs.size()); ++index) {
		if (listed(capability.goodRoutes, keyOf(index))) {
			append(index);
		}
	}
	for (auto index = 0; index != int(_proxy.resolvedIPs.size()); ++index) {
		const auto key = keyOf(index);
		if (!listed(capability.goodRoutes, key)
			&& !listed(capability.badRoutes, key)) {
			append(index);
		}
	}
	for (auto index = 0; index != int(_proxy.resolvedIPs.size()); ++index) {
		append(index);
	}
	return result;
}

int ResolvingConnection::activeRouteAttempts() const {
	return int(_routeAttempts.size());
}

ResolvingConnection::RouteAttempt *ResolvingConnection::findRouteAttempt(
		AbstractConnection *child) {
	const auto i = std::find_if(
		begin(_routeAttempts),
		end(_routeAttempts),
		[&](const RouteAttempt &attempt) {
			return attempt.child.get() == child;
		});
	return (i == end(_routeAttempts)) ? nullptr : &*i;
}

void ResolvingConnection::removeRouteAttempt(AbstractConnection *child) {
	const auto i = std::find_if(
		begin(_routeAttempts),
		end(_routeAttempts),
		[&](const RouteAttempt &attempt) {
			return attempt.child.get() == child;
		});
	if (i != end(_routeAttempts)) {
		_routeAttempts.erase(i);
	}
	refreshAttemptTimeout();
}

void ResolvingConnection::startRouteAttempts() {
	if (_connected || _protocolDcId == 0 || _proxy.resolvedIPs.empty()) {
		return;
	}
	if (_routeOrder.empty()) {
		_routeOrder = routeOrder();
		_nextRoutePosition = 0;
	}
	if (_routeAttempts.empty()) {
		startNextRouteAttempt();
	} else {
		scheduleRouteRace();
	}
}

void ResolvingConnection::startNextRouteAttempt() {
	_routeRaceTimer.cancel();
	if (_connected
		|| _protocolDcId == 0
		|| activeRouteAttempts() >= kMaxParallelRouteAttempts) {
		return;
	}
	if (_routeOrder.empty()) {
		_routeOrder = routeOrder();
		_nextRoutePosition = 0;
	}
	while (_nextRoutePosition < int(_routeOrder.size())) {
		const auto ipIndex = _routeOrder[_nextRoutePosition++];
		const auto alreadyStarted = std::find_if(
			begin(_routeAttempts),
			end(_routeAttempts),
			[&](const RouteAttempt &attempt) {
				return attempt.ipIndex == ipIndex;
			}) != end(_routeAttempts);
		if (!alreadyStarted) {
			addRouteAttempt(ipIndex);
			break;
		}
	}
	scheduleRouteRace();
}

void ResolvingConnection::scheduleRouteRace() {
	if (_connected
		|| _routeRaceTimer.isActive()
		|| _nextRoutePosition >= int(_routeOrder.size())
		|| activeRouteAttempts() >= kMaxParallelRouteAttempts) {
		return;
	}
	_routeRaceTimer.callOnce(kRouteRaceDelay);
}

crl::time ResolvingConnection::routePhaseBudget(
		HandshakePhase phase) const {
	if (phase == HandshakePhase::ClientHelloSent) {
		return 0;
	} else if (phase == HandshakePhase::ServerHelloOk
		|| phase == HandshakePhase::FirstDataReceived) {
		return kOnlyRouteAttemptTimeout;
	}
	const auto onlyRoute = (_routeAttempts.size() == 1)
		&& (_nextRoutePosition >= int(_routeOrder.size()));
	return onlyRoute ? kOnlyRouteAttemptTimeout : kRouteAttemptTimeout;
}

void ResolvingConnection::refreshAttemptTimeout() {
	if (_connected || _terminal) {
		_timeoutTimer.cancel();
		return;
	}
	const auto now = crl::now();
	auto earliest = _resolvingDeadline;
	for (auto &attempt : _routeAttempts) {
		const auto phase = ChildHandshakePhase(attempt.child.get());
		if (phase != attempt.phase) {
			attempt.phase = phase;
			attempt.phaseEnteredAt = now;
			const auto budget = routePhaseBudget(phase);
			attempt.wrapperDeadline = budget
				? (attempt.phaseEnteredAt + budget)
				: 0;
		}
		if (attempt.wrapperDeadline
			&& (!earliest || attempt.wrapperDeadline < earliest)) {
			earliest = attempt.wrapperDeadline;
		}
	}
	if (!earliest) {
		_timeoutTimer.cancel();
		return;
	}
	_timeoutTimer.callOnce(std::max(crl::time(0), earliest - now));
}

void ResolvingConnection::handleRouteAttemptTimeout() {
	if (_connected || _terminal) {
		return;
	}
	const auto now = crl::now();
	if (_resolvingDeadline && _resolvingDeadline <= now) {
		_resolvingDeadline = 0;
		_lastFailure.reason = ProxyMtproxyTerminalReason::DnsFailed;
		_lastFailure.error = ProxyConnectionError::Timeout;
		_lastFailure.closeOrigin = ProxyCloseOrigin::LocalTimeout;
		_lastFailure.parserStage = u"dns"_q;
		_lastFailure.dnsMs = now - _resolvingStartedAt;
		_lastFailure.attribution = ProxyFailureAttribution::Network;
		emitError(kErrorCodeOther);
		return;
	}
	refreshAttemptTimeout();
	const auto victim = std::min_element(
		begin(_routeAttempts),
		end(_routeAttempts),
		[&](const RouteAttempt &a, const RouteAttempt &b) {
			const auto aDue = a.wrapperDeadline
				&& a.wrapperDeadline <= now;
			const auto bDue = b.wrapperDeadline
				&& b.wrapperDeadline <= now;
			return (aDue != bDue)
				? aDue
				: (a.wrapperDeadline < b.wrapperDeadline);
		});
	if (victim == end(_routeAttempts)
		|| !victim->wrapperDeadline
		|| victim->wrapperDeadline > now
		|| victim->phase == HandshakePhase::ClientHelloSent) {
		refreshAttemptTimeout();
		return;
	}
	const auto ipIndex = victim->ipIndex;
	auto routeAttempt = _mtproxyAttempt;
	routeAttempt.routeAttemptId = victim->routeAttemptId;
	const auto fallbackReason = RouteTimeoutReason(
		victim->phase);
	const auto child = victim->child.get();
	if (child) {
		child->timedOut();
	}
	const auto failure = TypedRouteFailure(
		child,
		fallbackReason,
		ProxyConnectionError::Timeout,
		ProxyCloseOrigin::LocalTimeout);
	const auto reason = MtProxy::FromProxyMtproxyTerminalReason(
		failure.reason);
	RecordRouteOutcome(
		_runtime,
		_proxy,
		ipIndex,
		RouteOutcomeKind::Failed,
		reason);
	ReportRouteEvent(
		_runtime,
		_proxy,
		ipIndex,
		ProxyDiagnosticsPhase::RouteFailed,
		routeAttempt,
		reason,
		std::nullopt,
		(failure.closeOrigin == ProxyCloseOrigin::None)
			? std::optional<ProxyCloseOrigin>()
			: std::make_optional(failure.closeOrigin),
		failure.error);
	MergeExhaustedFailure(_lastFailure, failure);
	_routeAttempts.erase(victim);
	if (_routeAttempts.empty() && _nextRoutePosition >= int(_routeOrder.size())) {
		emitError(kErrorCodeOther);
		return;
	}
	startNextRouteAttempt();
	refreshAttemptTimeout();
}

void ResolvingConnection::domainResolved(
		const QString &host,
		const QStringList &ips,
		qint64 expireAt) {
	if (_terminal) {
		return;
	}
	if (_resolvingStartedAt) {
		_dnsDuration = crl::now() - _resolvingStartedAt;
	}
	if (host != _proxy.host || !_child) {
		return;
	}
	_resolvingDeadline = 0;
	_proxy.resolvedExpireAt = expireAt;
	if (ips.empty()) {
		if (_proxy.type == ProxyData::Type::Mtproto) {
			_lastFailure.reason = ProxyMtproxyTerminalReason::DnsFailed;
			_lastFailure.error = ProxyConnectionError::HostNotFound;
			_lastFailure.closeOrigin = ProxyCloseOrigin::NetworkError;
			_lastFailure.parserStage = u"dns"_q;
			_lastFailure.dnsMs = _dnsDuration;
			_lastFailure.attribution = ProxyFailureAttribution::Network;
		}
		ReportProxyEvent(_runtime, {
			.phase = ProxyDiagnosticsPhase::Failed,
			.error = ProxyConnectionError::HostNotFound,
			.mtproxyReason = (_proxy.type == ProxyData::Type::Mtproto)
				? ProxyMtproxyTerminalReason::DnsFailed
				: ProxyMtproxyTerminalReason::None,
			.attempt = _mtproxyAttempt,
			.terminalUntil = expireAt,
			.proxy = _proxy,
			.message = u"proxy host not found"_q,
		});
		emitError(kErrorCodeOther);
		return;
	}
	ReportProxyEvent(_runtime, {
		.phase = ProxyDiagnosticsPhase::Resolving,
		.attempt = _mtproxyAttempt,
		.proxy = _proxy,
		.message = u"proxy host resolved (%1 addresses)"_q.arg(
			ips.size()),
	});
	_proxy.resolvedIPs.clear();
	_proxy.resolvedIPs.reserve(ips.size());
	for (const auto &ip : ips) {
		_proxy.resolvedIPs.push_back(ip);
	}
	_routeOrder = routeOrder();
	_nextRoutePosition = 0;
	startRouteAttempts();
}

void ResolvingConnection::emitError(int errorCode) {
	if (_terminal) {
		return;
	}
	_terminal = true;
	_ipIndex = -1;
	_resolvingDeadline = 0;
	_routeRaceTimer.cancel();
	_timeoutTimer.cancel();
	_routeAttempts.clear();
	_child = nullptr;
	error(errorCode);
}

void ResolvingConnection::handleError(
		AbstractConnection *child,
		int errorCode) {
	if (_terminal) {
		return;
	}
	if (_connected && _child.get() == child) {
		_lastFailure = child->proxyTransportFailure();
		emitError(errorCode);
		return;
	} else if (_connected) {
		return;
	}
	const auto fallbackReason = ChildFailureReason(child, errorCode);
	if (const auto attempt = findRouteAttempt(child)) {
		const auto failure = TypedRouteFailure(
			child,
			fallbackReason,
			SocketProxyConnectionError(errorCode),
			ProxyCloseOrigin::NetworkError);
		const auto typedReason = MtProxy::FromProxyMtproxyTerminalReason(
			failure.reason);
		const auto reason = (typedReason == MtProxy::FailureReason::None)
			? fallbackReason
			: typedReason;
		RecordRouteOutcome(
			_runtime,
			_proxy,
			attempt->ipIndex,
			RouteOutcomeKind::Failed,
			reason);
		auto routeConnectionAttempt = _mtproxyAttempt;
		routeConnectionAttempt.routeAttemptId = attempt->routeAttemptId;
		ReportRouteEvent(
			_runtime,
			_proxy,
			attempt->ipIndex,
			ProxyDiagnosticsPhase::RouteFailed,
			routeConnectionAttempt,
			reason,
			std::nullopt,
			(failure.closeOrigin == ProxyCloseOrigin::None)
				? std::optional<ProxyCloseOrigin>()
				: std::make_optional(failure.closeOrigin),
			failure.error);
		MergeExhaustedFailure(_lastFailure, failure);
	}
	removeRouteAttempt(child);
	if (_routeAttempts.empty() && _nextRoutePosition >= int(_routeOrder.size())) {
		emitError(errorCode);
	} else if (_routeAttempts.empty()) {
		startNextRouteAttempt();
	} else {
		scheduleRouteRace();
	}
}

void ResolvingConnection::handleDisconnected(AbstractConnection *child) {
	if (_terminal) {
		return;
	}
	if (_connected && _child.get() == child) {
		disconnected();
	} else if (!_connected) {
		handleError(child, kErrorCodeOther);
	}
}

void ResolvingConnection::handleReceivedData(AbstractConnection *child) {
	if (_connected && _child.get() != child) {
		return;
	}
	const auto attempt = findRouteAttempt(child);
	const auto source = _connected ? _child.get() : (attempt
		? attempt->child.get()
		: nullptr);
	if (!source) {
		return;
	}
	auto &my = received();
	auto &his = source->received();
	for (auto &item : his) {
		my.push_back(std::move(item));
	}
	his.clear();
	receivedData();
}

void ResolvingConnection::promoteRouteAttempt(AbstractConnection *child) {
	auto winner = ConnectionPointer();
	auto winnerIpIndex = -1;
	for (auto &attempt : _routeAttempts) {
		if (attempt.child.get() == child) {
			winner = std::move(attempt.child);
			winnerIpIndex = attempt.ipIndex;
		} else if (attempt.child) {
			auto routeAttempt = _mtproxyAttempt;
			routeAttempt.routeAttemptId = attempt.routeAttemptId;
			RecordRouteOutcome(
				_runtime,
				_proxy,
				attempt.ipIndex,
				RouteOutcomeKind::RaceLost,
				MtProxy::FailureReason::None);
			ReportRouteEvent(
				_runtime,
				_proxy,
				attempt.ipIndex,
				ProxyDiagnosticsPhase::RouteFailed,
				routeAttempt,
				MtProxy::FailureReason::None,
				std::nullopt,
				ProxyCloseOrigin::RouteRaceLost);
			attempt.child->disconnectFromServer();
		}
	}
	_routeAttempts.clear();
	if (!winner) {
		return;
	}
	_child = std::move(winner);
	_ipIndex = winnerIpIndex;
	_runtime->proxyEndpointContext().updateTraceAttempt(
		_child->proxyConnectionAttempt());
}

void ResolvingConnection::handleConnected(AbstractConnection *child) {
	if (_connected || _terminal) {
		return;
	}
	_connected = true;
	promoteRouteAttempt(child);
	if (!_child) {
		_connected = false;
		return;
	}
	_timeoutTimer.cancel();
	_routeRaceTimer.cancel();
	if (_ipIndex >= 0 && !IsProxyCheck(_mtproxyAttempt.use)) {
		const auto host = _proxy.host;
		const auto good = _proxy.resolvedIPs[_ipIndex];
		const auto runtime = _runtime;
		InvokeQueued(runtime, [=] {
			if (runtime->proxyResolver().setGoodDomain) {
				runtime->proxyResolver().setGoodDomain(host, good);
			}
		});
		if (_proxy.type == ProxyData::Type::Mtproto) {
			// This address of this proxy answered a Telegram reply, so it
			// goes to the front of the order next time. Route memory only -
			// it never influences the handshake shape.
			const auto endpoint = MtproxyEndpointIdForRoute(
				_proxy,
				_ipIndex);
			const auto routeKey = MtProxy::RouteKey(endpoint.route);
			_runtime->proxyServices().capabilities().noteMtproxySuccess(
				MtProxy::CapabilityProxyKey(endpoint.canonical),
				routeKey,
				routeKey,
				_mtproxyPlan.effectiveTlsProfile,
				_mtproxyPlan.stealth,
				_mtproxyPlan.recipeLevel,
				true);
		}
	}
	connected();
}

crl::time ResolvingConnection::pingTime() const {
	Expects(_child != nullptr);

	return _child->pingTime();
}

crl::time ResolvingConnection::fullConnectTimeout() const {
	const auto resolvingRaceTimeout = kRouteAttemptTimeout
		+ kRouteRaceDelay * kMaxParallelRouteAttempts;
	if (_proxy.type != ProxyData::Type::Mtproto) {
		return std::min(
			kFullConnectTimeout,
			resolvingRaceTimeout + kOnlyRouteAttemptTimeout);
	}
	const auto serverHelloTimeout = (_mtproxyPlan.serverHelloTimeout > 0)
		? _mtproxyPlan.serverHelloTimeout
		: kColdServerHelloTimeout;
	const auto phasedTimeout = resolvingRaceTimeout
		+ kOnlyRouteAttemptTimeout
		+ serverHelloTimeout
		+ kOnlyRouteAttemptTimeout
		+ kFullConnectTimeoutSafetyMargin;
	return std::min(kFullConnectTimeout, phasedTimeout);
}

void ResolvingConnection::sendData(
		mtpBuffer &&buffer,
		SendDataContext context) {
	Expects(_child != nullptr);

	_child->sendData(std::move(buffer), context);
}

void ResolvingConnection::disconnectFromServer() {
	_address = QString();
	_port = 0;
	_protocolSecret = bytes::vector();
	_protocolDcId = 0;
	_resolvingDeadline = 0;
	_routeRaceTimer.cancel();
	_timeoutTimer.cancel();
	for (auto &attempt : _routeAttempts) {
		if (attempt.child) {
			attempt.child->disconnectFromServer();
		}
	}
	_routeAttempts.clear();
	if (!_child) {
		return;
	}
	_child->disconnectFromServer();
}

void ResolvingConnection::connectToServer(
		const QString &address,
		int port,
		const bytes::vector &protocolSecret,
		int16 protocolDcId,
		bool protocolForFiles,
		ConnectionStartContext context) {
	_mtproxyAttempt = context.mtproxyAttempt;
	_mtproxyPlan = context.mtproxyPlan;
	_mtproxyAttemptStartedAt = context.mtproxyAttemptStartedAt;
	_terminal = false;
	_lastFailure = {};
	if (!_child) {
		if (_proxy.type == ProxyData::Type::Mtproto) {
			_lastFailure.reason = ProxyMtproxyTerminalReason::DnsFailed;
			_lastFailure.error = ProxyConnectionError::HostNotFound;
			_lastFailure.closeOrigin = ProxyCloseOrigin::NetworkError;
			_lastFailure.parserStage = u"dns"_q;
			_lastFailure.dnsMs = _dnsDuration;
			_lastFailure.attribution = ProxyFailureAttribution::Network;
		}
		ReportProxyEvent(_runtime, {
			.phase = ProxyDiagnosticsPhase::Failed,
			.error = ProxyConnectionError::HostNotFound,
			.mtproxyReason = (_proxy.type == ProxyData::Type::Mtproto)
				? ProxyMtproxyTerminalReason::DnsFailed
				: ProxyMtproxyTerminalReason::None,
			.attempt = _mtproxyAttempt,
			.terminalUntil = _proxy.resolvedExpireAt,
			.proxy = _proxy,
			.message = u"proxy host not found"_q,
		});
		InvokeQueued(this, [=] { emitError(kErrorCodeOther); });
		return;
	}
	_address = address;
	_port = port;
	_protocolSecret = protocolSecret;
	_protocolDcId = protocolDcId;
	_protocolForFiles = protocolForFiles;
	if (_proxy.resolvedIPs.empty()
		|| _proxy.resolvedExpireAt < crl::now()) {
		startResolving();
	} else {
		startRouteAttempts();
	}
}

bool ResolvingConnection::isConnected() const {
	return _child ? _child->isConnected() : false;
}

HandshakePhase ResolvingConnection::handshakePhase() const {
	if (_connected && _child) {
		return _child->handshakePhase();
	}
	auto result = HandshakePhase::None;
	for (const auto &attempt : _routeAttempts) {
		result = std::max(
			result,
			ChildHandshakePhase(attempt.child.get()));
	}
	return result;
}

ProxyConnectionAttempt ResolvingConnection::proxyConnectionAttempt() const {
	if (_child) {
		const auto result = _child->proxyConnectionAttempt();
		if (result.traceId) {
			return result;
		}
	}
	if (!_routeAttempts.empty()) {
		const auto result = _routeAttempts.front().child
			->proxyConnectionAttempt();
		if (result.traceId) {
			return result;
		}
	}
	return _mtproxyAttempt;
}

ProxyTransportFailure ResolvingConnection::proxyTransportFailure() const {
	const auto withDns = [&](ProxyTransportFailure result) {
		if (!result.dnsMs) {
			result.dnsMs = _dnsDuration;
		}
		return result;
	};
	if (_connected && _child) {
		return withDns(_child->proxyTransportFailure());
	}
	if (!_routeAttempts.empty()) {
		const auto best = std::max_element(
			begin(_routeAttempts),
			end(_routeAttempts),
			[](const RouteAttempt &a, const RouteAttempt &b) {
				return int(ChildHandshakePhase(a.child.get()))
					< int(ChildHandshakePhase(b.child.get()));
			});
		return withDns(best->child->proxyTransportFailure());
	}
	return withDns(_lastFailure);
}

void ResolvingConnection::timedOut() {
	if (_terminal) {
		return;
	}
	auto reported = false;
	for (const auto &attempt : _routeAttempts) {
		if (attempt.child) {
			attempt.child->timedOut();
			reported = true;
		}
	}
	// _child is the template the routes are cloned from: it never dials, so
	// its own report is always "tcp connect timed out" no matter how far the
	// routes got. Letting it speak over them puts that reason on the proxy
	// status the user sees. It is only the truth while no route exists yet.
	if (!reported && _child) {
		_child->timedOut();
	}
}

void ResolvingConnection::markProxyMtprotoPayloadReceived() {
	if (_child) {
		_child->markProxyMtprotoPayloadReceived();
	}
}

int32 ResolvingConnection::debugState() const {
	if (!_connected && !_routeAttempts.empty()) {
		return _routeAttempts.front().child->debugState();
	}
	return _child ? _child->debugState() : -1;
}

QString ResolvingConnection::transport() const {
	if (!_connected && !_routeAttempts.empty()) {
		return _routeAttempts.front().child->transport();
	}
	return _child ? _child->transport() : QString();
}

QString ResolvingConnection::tag() const {
	if (!_connected && !_routeAttempts.empty()) {
		return _routeAttempts.front().child->tag();
	}
	return _child ? _child->tag() : QString();
}

} // namespace details
} // namespace MTP
