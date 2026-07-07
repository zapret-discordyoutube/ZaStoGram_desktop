/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "mtproto/proxy/resolving_connection.h"

#include "mtproto/mtp_instance.h"
#include "mtproto/details/mtproto_abstract_socket.h"
#include "mtproto/proxy/capabilities.h"
#include "mtproto/proxy/control_plane.h"
#include "mtproto/proxy/diagnostics.h"
#include "mtproto/proxy/dns_resolver_cache.h"

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

// The route attempt timer knows nothing about handshakes by itself, so
// when it fires the failure must be attributed from the phase the child
// socket actually reached - reporting a generic tcp_connect_timeout for
// a connection that completed TCP (or even the whole TLS handshake)
// corrupts diagnostics and feeds the wrong signal into EndpointHealth.
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
	case HandshakePhase::FirstDataReceived:
		return MtProxy::FailureReason::ServerHelloOkNoAppData;
	}
	return MtProxy::FailureReason::TcpConnectTimeout;
}

[[nodiscard]] HandshakePhase ChildHandshakePhase(
		AbstractConnection *child) {
	return child ? child->handshakePhase() : HandshakePhase::None;
}

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
		MtProxy::FailureReason reason,
		ProxyConnectionAttempt attempt,
		crl::time attemptStartedAt) {
	if (proxy.type != ProxyData::Type::Mtproto) {
		return;
	}
	ProxyControlPlane::ReportMtproxyFailure({
		.endpoint = MtproxyEndpointIdForRoute(proxy, ipIndex),
		.reason = reason,
		.attemptId = attempt.attemptId,
		.proxyEpoch = attempt.proxyEpoch,
		.attemptStartedAt = attemptStartedAt,
	});
}

void ReportAllRoutesFailed(
		const ProxyData &proxy,
		MtProxy::FailureReason reason,
		ProxyConnectionAttempt attempt,
		crl::time attemptStartedAt) {
	if (proxy.type != ProxyData::Type::Mtproto) {
		return;
	}
	ProxyControlPlane::ReportMtproxyFailure({
		.endpoint = MtproxyEndpointIdForProxy(proxy),
		.reason = reason,
		.attemptId = attempt.attemptId,
		.proxyEpoch = attempt.proxyEpoch,
		.attemptStartedAt = attemptStartedAt,
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
			.attempt = _mtproxyAttempt,
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
	attempt.child->setMtproxyAttempt(
		_mtproxyAttempt,
		_mtproxyAttemptStartedAt);
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
		&AbstractConnection::handshakeProgress,
		this,
		[=] { refreshAttemptTimeout(); });
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

void ResolvingConnection::setMtproxyAttempt(
		ProxyConnectionAttempt attempt,
		crl::time startedAt) {
	_mtproxyAttempt = attempt;
	_mtproxyAttemptStartedAt = startedAt;
	if (_child) {
		_child->setMtproxyAttempt(attempt, startedAt);
	}
	for (auto &routeAttempt : _routeAttempts) {
		routeAttempt.child->setMtproxyAttempt(attempt, startedAt);
	}
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
	// An attempt that passed the TLS handshake is waiting for the proxy
	// to relay telegram data - that includes the proxy's own connect to
	// the DC, which racing another route cannot speed up. Do not kill a
	// route that already proved itself at the short racing timeout just
	// because a sibling attempt exists; the timer is also restarted on
	// every handshakeProgress() so each phase gets a fresh budget
	// instead of whatever was left over from TCP connect.
	const auto handshakeDone = std::any_of(
		begin(_routeAttempts),
		end(_routeAttempts),
		[](const RouteAttempt &attempt) {
			const auto phase = ChildHandshakePhase(attempt.child.get());
			return (phase == HandshakePhase::ServerHelloOk)
				|| (phase == HandshakePhase::FirstDataReceived);
		});
	_timeoutTimer.callOnce((lastRoute || handshakeDone)
		? kOnlyRouteAttemptTimeout
		: kRouteAttemptTimeout);
}

void ResolvingConnection::handleRouteAttemptTimeout() {
	if (_connected || _routeAttempts.empty()) {
		return;
	}
	// The short timeout exists to race stalled routes, so kill the least
	// progressed attempt - the one that got the furthest is exactly the
	// route worth keeping alive.
	const auto victim = std::min_element(
		begin(_routeAttempts),
		end(_routeAttempts),
		[](const RouteAttempt &a, const RouteAttempt &b) {
			return int(ChildHandshakePhase(a.child.get()))
				< int(ChildHandshakePhase(b.child.get()));
		});
	const auto ipIndex = victim->ipIndex;
	const auto reason = RouteTimeoutReason(
		ChildHandshakePhase(victim->child.get()));
	ReportRouteEvent(
		_instance,
		_proxy,
		ipIndex,
		ProxyDiagnosticsPhase::RouteFailed,
		reason);
	if (reason == MtProxy::FailureReason::TcpConnectTimeout
		|| reason == MtProxy::FailureReason::TcpConnectedNoClientHelloWrite) {
		// Route-only failures pace the open scheduler and are otherwise
		// never reported for an attempt destroyed by our own timer. The
		// later phases are reported precisely by the socket itself from
		// timedOut() below - reporting them here as well would degrade
		// the canonical endpoint twice for one failed cycle.
		ReportRouteFailureToHealth(
			_proxy,
			ipIndex,
			reason,
			_mtproxyAttempt,
			_mtproxyAttemptStartedAt);
	}
	// Let the attempt report its own failure before it is destroyed: the
	// socket knows which handshake phase actually stalled. A proxy that
	// completes FakeTLS but never relays telegram data must be recorded
	// as server_hello_ok_no_appdata, not as a generic tcp connect timeout.
	if (const auto child = victim->child.get()) {
		child->timedOut();
	}
	_routeAttempts.erase(victim);
	if (_routeAttempts.empty() && _nextRoutePosition >= int(_routeOrder.size())) {
		ReportAllRoutesFailed(
			_proxy,
			reason,
			_mtproxyAttempt,
			_mtproxyAttemptStartedAt);
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
			ProxyControlPlane::ReportMtproxyFailure({
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
			.attempt = _mtproxyAttempt,
			.terminalUntil = expireAt,
			.proxy = _proxy,
			.message = u"proxy host not found"_q,
		});
		emitError(kErrorCodeOther);
		return;
	}
	ReportProxyEvent(_instance, {
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
			ReportAllRoutesFailed(
				_proxy,
				reason,
				_mtproxyAttempt,
				_mtproxyAttemptStartedAt);
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
	// Worst honest cycle: the TLS handshake may use up the short racing
	// budget, then the wait for the proxy to relay telegram data gets a
	// fresh single-route budget (see refreshAttemptTimeout()). The
	// session-level connect timer must not fire before that budget is
	// spent, or a slow-but-working relay is killed from above.
	return kRouteAttemptTimeout
		+ kOnlyRouteAttemptTimeout
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
			ProxyControlPlane::ReportMtproxyFailure({
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
