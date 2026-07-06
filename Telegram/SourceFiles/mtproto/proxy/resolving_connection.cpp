/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "mtproto/proxy/resolving_connection.h"

#include "mtproto/mtp_instance.h"
#include "mtproto/proxy/capabilities.h"
#include "mtproto/proxy/diagnostics.h"
#include "mtproto/proxy/dns_resolver_cache.h"
#include "mtproto/proxy/mtproxy/endpoint_health.h"

#include <algorithm>

namespace MTP {
namespace details {
namespace {

constexpr auto kRouteAttemptTimeout = crl::time(4000);
constexpr auto kRouteRaceDelay = crl::time(300);
constexpr auto kMaxParallelRouteAttempts = 2;

// When the running attempt is the last route available there is nothing
// to race it against - killing it at the short timeout only burns a
// handshake and reconnects. Give TCP time to retransmit SYN instead: a
// proxy that throttles new connects often accepts on a later try.
constexpr auto kOnlyRouteAttemptTimeout = crl::time(8000);

[[nodiscard]] MtProxy::EndpointId MtproxyEndpointIdForProxy(
		const ProxyData &proxy) {
	auto stealth = ProxyStealthOptions();
	stealth.transport = ProxyTransport::Tcp;
	return MtProxy::EndpointIdFromProxy(proxy, stealth);
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

// A route attempt destroyed by our own timeout never produces a socket
// error, so nothing else reports it to EndpointHealth - do it here.
void ReportRouteFailureToHealth(
		const ProxyData &proxy,
		int ipIndex,
		MtProxy::FailureReason reason) {
	if (proxy.type != ProxyData::Type::Mtproto) {
		return;
	}
	MtProxy::EndpointHealth::Instance().reportFailure({
		.endpoint = MtproxyEndpointIdForRoute(proxy, ipIndex),
		.reason = reason,
	});
}

void ReportAllRoutesFailed(
		const ProxyData &proxy,
		MtProxy::FailureReason reason) {
	if (proxy.type != ProxyData::Type::Mtproto) {
		return;
	}
	MtProxy::EndpointHealth::Instance().reportFailure({
		.endpoint = MtproxyEndpointIdForProxy(proxy),
		.reason = reason,
		.routesExhausted = true,
	});
}

void ReportRouteEvent(
		not_null<Instance*> instance,
		const ProxyData &proxy,
		int ipIndex,
		ProxyDiagnosticsPhase phase,
		MtProxy::FailureReason reason = MtProxy::FailureReason::None) {
	if (proxy.type != ProxyData::Type::Mtproto) {
		return;
	}
	const auto endpoint = MtproxyEndpointIdForRoute(proxy, ipIndex);
	const auto routeKey = MtProxy::RouteKey(endpoint.route);
	const auto routeText = ProxyDiagnosticsEndpointText(
		endpoint.route.address,
		endpoint.route.port);
	const auto failurePhase = MtProxy::ToLegacyDiagnostic(reason);
	ReportProxyEvent(instance, {
		.phase = phase,
		.error = MtProxy::ToProxyConnectionError(reason),
		.mtproxyReason = MtProxy::ToProxyMtproxyTerminalReason(reason),
		.severity = (phase == ProxyDiagnosticsPhase::RouteFailed)
			? ProxyDiagnosticsSeverity::Warning
			: ProxyDiagnosticsSeverity::Info,
		.proxy = proxy,
		.transport = ProxyDiagnosticsTransportName(
			proxy.type,
			ProxyTransport::Tcp),
		.message = (phase == ProxyDiagnosticsPhase::RouteFailed)
			? u"mtproxy route failed"_q
			: u"mtproxy route selected"_q,
		.canonical = ProxyDiagnosticsEndpointText(
			endpoint.canonical.originalHost,
			endpoint.canonical.port),
		.route = routeText.isEmpty() ? routeKey : routeText,
		.proxyKeyHash = ProxyDiagnosticsKeyHash(
			MtProxy::EndpointKey(endpoint.canonical)),
		.phaseAtFailure = (phase == ProxyDiagnosticsPhase::RouteFailed)
			? (failurePhase.isEmpty()
				? u"tcp_not_connected"_q
				: failurePhase)
			: QString(),
	});
}

} // namespace

ResolvingConnection::ResolvingConnection(
	not_null<Instance*> instance,
	QThread *thread,
	const ProxyData &proxy,
	ConnectionPointer &&child)
: AbstractConnection(thread, proxy)
, _instance(instance)
, _child(std::move(child))
, _timeoutTimer([=] { handleRouteAttemptTimeout(); })
, _routeRaceTimer([=] { startNextRouteAttempt(); }) {
	if (proxy.resolvedIPs.empty() || proxy.resolvedExpireAt < crl::now()) {
		ReportProxyEvent(_instance, {
			.phase = ProxyDiagnosticsPhase::Resolving,
			.proxy = _proxy,
			.message = u"resolving proxy host"_q,
		});
		const auto host = proxy.host;
		DnsResolverCache::Instance().request(
			instance,
			this,
			host,
			[=](QString host, QStringList ips, qint64 expireAt) {
				domainResolved(host, ips, expireAt);
			});
	}
	if (!proxy.resolvedIPs.empty()) {
		startRouteAttempts();
	}
}

ConnectionPointer ResolvingConnection::clone(const ProxyData &proxy) {
	Unexpected("ResolvingConnection::clone call.");
}

void ResolvingConnection::addRouteAttempt(int ipIndex) {
	if (!_child
		|| ipIndex < 0
		|| ipIndex >= int(_proxy.resolvedIPs.size())) {
		return;
	}
	auto attempt = RouteAttempt();
	attempt.ipIndex = ipIndex;
	attempt.child = _child->clone(ToDirectIpProxy(_proxy, ipIndex));
	const auto raw = attempt.child.get();
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
	if (_protocolDcId) {
		attempt.child->connectToServer(
			_address,
			_port,
			_protocolSecret,
			_protocolDcId,
			_protocolForFiles);
		CONNECTION_LOG_INFO("Resolving connected a new child: "
			+ attempt.child->debugId());
	}
	_routeAttempts.push_back(std::move(attempt));
	ReportRouteEvent(
		_instance,
		_proxy,
		ipIndex,
		ProxyDiagnosticsPhase::RouteSelected);
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
	if (_proxy.type == ProxyData::Type::Mtproto) {
		const auto capability = ProxyCapabilityCache::Instance().lookup(_proxy);
		for (const auto &goodRoute : capability.goodRoutes) {
			for (auto index = 0; index != int(_proxy.resolvedIPs.size()); ++index) {
				const auto route = MtProxy::RouteEndpointFromAddress(
					_proxy.resolvedIPs[index],
					int(_proxy.port),
					ProxyTransport::Tcp,
					_proxy.originalHost.isEmpty()
						? _proxy.host
						: _proxy.originalHost);
				if (MtProxy::RouteKey(route) == goodRoute) {
					result.push_back(index);
				}
			}
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

void ResolvingConnection::refreshAttemptTimeout() {
	if (_connected || _routeAttempts.empty()) {
		_timeoutTimer.cancel();
		return;
	}
	const auto lastRoute = (_routeAttempts.size() == 1)
		&& (_nextRoutePosition >= int(_routeOrder.size()));
	_timeoutTimer.callOnce(lastRoute
		? kOnlyRouteAttemptTimeout
		: kRouteAttemptTimeout);
}

void ResolvingConnection::handleRouteAttemptTimeout() {
	if (_connected || _routeAttempts.empty()) {
		return;
	}
	const auto ipIndex = _routeAttempts.front().ipIndex;
	ReportRouteEvent(
		_instance,
		_proxy,
		ipIndex,
		ProxyDiagnosticsPhase::RouteFailed,
		MtProxy::FailureReason::TcpConnectTimeout);
	ReportRouteFailureToHealth(
		_proxy,
		ipIndex,
		MtProxy::FailureReason::TcpConnectTimeout);
	// Let the attempt report its own failure before it is destroyed: the
	// socket knows which handshake phase actually stalled. A proxy that
	// completes FakeTLS but never relays telegram data must be recorded
	// as server_hello_ok_no_appdata (triggering recipe escalation and
	// TLS profile rotation), not as a generic tcp connect timeout.
	if (const auto child = _routeAttempts.front().child.get()) {
		child->timedOut();
	}
	_routeAttempts.erase(begin(_routeAttempts));
	if (_routeAttempts.empty() && _nextRoutePosition >= int(_routeOrder.size())) {
		ReportAllRoutesFailed(
			_proxy,
			MtProxy::FailureReason::TcpConnectTimeout);
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
	if (host != _proxy.host || !_child) {
		return;
	}
	_proxy.resolvedExpireAt = expireAt;
	if (ips.empty()) {
		if (_proxy.type == ProxyData::Type::Mtproto) {
			MtProxy::EndpointHealth::Instance().reportFailure({
				.endpoint = MtproxyEndpointIdForProxy(_proxy),
				.reason = MtProxy::FailureReason::DnsFailed,
			});
		}
		ReportProxyEvent(_instance, {
			.phase = ProxyDiagnosticsPhase::Failed,
			.error = ProxyConnectionError::HostNotFound,
			.mtproxyReason = (_proxy.type == ProxyData::Type::Mtproto)
				? ProxyMtproxyTerminalReason::DnsFailed
				: ProxyMtproxyTerminalReason::None,
			.terminalUntil = expireAt,
			.proxy = _proxy,
			.message = u"proxy host not found"_q,
		});
		emitError(kErrorCodeOther);
		return;
	}
	ReportProxyEvent(_instance, {
		.phase = ProxyDiagnosticsPhase::Resolving,
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
	_ipIndex = -1;
	_routeRaceTimer.cancel();
	_timeoutTimer.cancel();
	_routeAttempts.clear();
	_child = nullptr;
	error(errorCode);
}

void ResolvingConnection::handleError(
		AbstractConnection *child,
		int errorCode) {
	if (_connected && _child.get() == child) {
		emitError(errorCode);
	} else if (_connected) {
		return;
	}
	if (const auto attempt = findRouteAttempt(child)) {
		auto reason = MtProxy::FailureReasonFromErrorCode(errorCode);
		if (reason == MtProxy::FailureReason::None) {
			reason = MtProxy::FailureReason::TcpConnectTimeout;
		}
		ReportRouteEvent(
			_instance,
			_proxy,
			attempt->ipIndex,
			ProxyDiagnosticsPhase::RouteFailed,
			reason);
	}
	removeRouteAttempt(child);
	if (_routeAttempts.empty() && _nextRoutePosition >= int(_routeOrder.size())) {
		// The child socket reported its own failure to EndpointHealth,
		// but route-only reasons leave the canonical endpoint untouched.
		// This was the last route - degrade the canonical so admission
		// gets a cooldown and rotation can kick in. reportFailure() skips
		// the escalation if a cooldown is already running. An error on an
		// already established connection is not route exhaustion.
		if (!_connected) {
			auto reason = MtProxy::FailureReasonFromErrorCode(errorCode);
			if (reason == MtProxy::FailureReason::None) {
				reason = MtProxy::FailureReason::TcpConnectTimeout;
			}
			ReportAllRoutesFailed(_proxy, reason);
		}
		emitError(errorCode);
	} else if (_routeAttempts.empty()) {
		startNextRouteAttempt();
	} else {
		scheduleRouteRace();
	}
}

void ResolvingConnection::handleDisconnected(AbstractConnection *child) {
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
			attempt.child->disconnectFromServer();
		}
	}
	_routeAttempts.clear();
	if (!winner) {
		return;
	}
	_child = std::move(winner);
	_ipIndex = winnerIpIndex;
}

void ResolvingConnection::handleConnected(AbstractConnection *child) {
	if (_connected) {
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
	if (_ipIndex >= 0) {
		const auto host = _proxy.host;
		const auto good = _proxy.resolvedIPs[_ipIndex];
		const auto instance = _instance;
		InvokeQueued(_instance, [=] {
			instance->setGoodProxyDomain(host, good);
		});
	}
	connected();
}

crl::time ResolvingConnection::pingTime() const {
	Expects(_child != nullptr);

	return _child->pingTime();
}

crl::time ResolvingConnection::fullConnectTimeout() const {
	return kOnlyRouteAttemptTimeout
		+ kRouteRaceDelay * kMaxParallelRouteAttempts;
}

void ResolvingConnection::sendData(mtpBuffer &&buffer) {
	Expects(_child != nullptr);

	_child->sendData(std::move(buffer));
}

void ResolvingConnection::disconnectFromServer() {
	_address = QString();
	_port = 0;
	_protocolSecret = bytes::vector();
	_protocolDcId = 0;
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
		bool protocolForFiles) {
	if (!_child) {
		if (_proxy.type == ProxyData::Type::Mtproto) {
			MtProxy::EndpointHealth::Instance().reportFailure({
				.endpoint = MtproxyEndpointIdForProxy(_proxy),
				.reason = MtProxy::FailureReason::DnsFailed,
			});
		}
		ReportProxyEvent(_instance, {
			.phase = ProxyDiagnosticsPhase::Failed,
			.error = ProxyConnectionError::HostNotFound,
			.mtproxyReason = (_proxy.type == ProxyData::Type::Mtproto)
				? ProxyMtproxyTerminalReason::DnsFailed
				: ProxyMtproxyTerminalReason::None,
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
	if (!_proxy.resolvedIPs.empty()) {
		startRouteAttempts();
	}
}

bool ResolvingConnection::isConnected() const {
	return _child ? _child->isConnected() : false;
}

void ResolvingConnection::timedOut() {
	// The owner (session or proxy check) times out on this wrapper, but
	// the sockets doing the actual work live in the route attempts - a
	// TlsSocket that is never told about the timeout never reports its
	// failure to EndpointHealth, so domain proxies never degraded.
	for (const auto &attempt : _routeAttempts) {
		if (attempt.child) {
			attempt.child->timedOut();
		}
	}
	if (_child) {
		_child->timedOut();
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
