/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "mtproto/session/private/session_private.h"
#include "mtproto/session/private/timings.h"

#include "core/version.h"
#include "mtproto/dc_id.h"
#include "mtproto/auth/mtproto_bound_key_creator.h"
#include "mtproto/details/mtproto_dcenter.h"
#include "mtproto/instance/mtp_instance.h"
#include "mtproto/protocol/mtproto_dump_to_text.h"
#include "mtproto/details/mtproto_rsa_public_key.h"
#include "mtproto/proxy/diagnostics.h"
#include "mtproto/proxy/dial_pacer.h"
#include "mtproto/proxy/mtproxy/handshake_plan.h"
#include "mtproto/proxy/transport_policy.h"
#include "mtproto/runtime/runtime_environment.h"
#include "mtproto/session/options.h"
#include "mtproto/session/session.h"
#include "mtproto/protocol/mtproto_response.h"
#include "mtproto/config/mtproto_dc_options.h"
#include "mtproto/transport/details/mtproto_abstract_socket.h"
#include "mtproto/transport/connection_abstract.h"
#include "base/options.h"
#include "base/random.h"
#include "base/qthelp_url.h"
#include "base/openssl_help.h"
#include "base/unixtime.h"

#include "base/platform/base_platform_info.h"

#include <ksandbox.h>
#include <zlib.h>

namespace MTP {
namespace details {
namespace {

constexpr auto kWaitForBetterTimeout = crl::time(2000);
constexpr auto kMaxConnectedTimeout = crl::time(8000);
constexpr auto kMtproxyMinReceiveTimeout = crl::time(8000);
constexpr auto kMaxReceiveTimeout = crl::time(64000);
constexpr auto kProxyReconnectMinTimeout = 1800;
constexpr auto kProxyReconnectMaxTimeout = 8000;
constexpr auto kWaitForProxyTimeout = 2000;
constexpr auto kMarkConnectionOldTimeout = crl::time(192000);
constexpr auto kRequestConfigTimeout = 8 * crl::time(1000);
constexpr auto kSilentTimeoutsToAssumeKeyDestroyed = 2;

base::options::toggle OptionPreferIPv6({
	.id = kOptionPreferIPv6,
	.name = "Prefer IPv6",
	.description = "Prefer IPv6 if it is available. Require \"Try connecting through IPv6\" to be enabled",
});

} // namespace

ProxyConnectionUse SessionTransport::classifyEndpointUse() const {
	return isUploadDcId(_owner->_shiftedDcId)
		? ProxyConnectionUse::Upload
		: (isMediaClusterDcId(_owner->_shiftedDcId)
			|| _owner->_realDcType == DcType::Cdn)
		? ProxyConnectionUse::Media
		: (_owner->_role == SessionRole::PrimaryMain)
		? ProxyConnectionUse::Main
		: (_owner->_role == SessionRole::Maintenance)
		? ProxyConnectionUse::Maintenance
		: ProxyConnectionUse::Auxiliary;
}

bool SessionTransport::appendTestConnection(
		DcOptions::Variants::Protocol protocol,
		const QString &ip,
		int port,
		const bytes::vector &protocolSecret,
		bool protocolForFiles) {
	QWriteLocker lock(&_owner->_stateMutex);

	const auto proxy = _owner->_sessionState.options->proxy;
	const auto stealth = _owner->_sessionState.options->stealth;
	const auto endpoint = ip.isEmpty()
		? (proxy.host + ':' + QString::number(proxy.port))
		: (ip + ':' + QString::number(port));
	const auto priority = (qthelp::is_ipv6(ip) ? (OptionPreferIPv6.value() ? 2 : 0) : 1)
		+ (protocol == DcOptions::Variants::Tcp ? 1 : 0)
		+ (protocolSecret.empty() ? 0 : 1);
	const auto mtproxy = (proxy.type == ProxyData::Type::Mtproto);
	const auto mtproxyUse = classifyEndpointUse();
	const auto protocolDcId = _owner->getProtocolDcId();
	auto attempt = ProxyConnectionAttempt{
		.proxyGeneration = _state.proxyGeneration,
		.use = mtproxyUse,
	};
	// Without a plan the socket falls back to its own emergency defaults,
	// which wait for the ServerHello for half as long as the handshake is
	// meant to - so a proxy the settings check calls working has its
	// handshake killed early on every real session.
	const auto plan = mtproxy
		? MtProxy::MakeAttemptPlan(stealth)
		: MtProxyAttemptPlan();
	if (mtproxy) {
		attempt.runtimeId = _owner->_runtime->proxyRuntimeId();
	}
	const auto attemptStartedAt = mtproxy ? crl::now() : crl::time();

	// Ordinary MTProto sessions own their connection lifecycle directly: no
	// admission queue, no health cooldown, no cross-account head-of-line
	// blocking. The one thing a proxy does impose is that it cannot answer
	// every session of every account handshaking in the same millisecond, so
	// the dial itself is paced per proxy server.
	auto dial = ReserveProxyDial(_owner->_runtime, proxy);
	const auto dialDelay = dial.delay();
	_state.testConnections.push_back({
		.data = _owner->_connectionFactory->create(
			_owner->_runtime,
			protocol,
			_owner->thread(),
			protocolSecret,
			proxy,
			stealth),
		.priority = priority,
		.endpoint = endpoint,
		.mtproxyUse = mtproxyUse,
		.mtproxyAttempt = attempt,
		.mtproxyAttemptStartedAt = attemptStartedAt,
		.mtproxyDial = std::move(dial),
		.mtproxyDialDelay = dialDelay,
	});
	const auto weak = _state.testConnections.back().data.get();
	QObject::connect(weak, &AbstractConnection::error, [=](int errorCode) {
		onError(weak, errorCode);
	});
	QObject::connect(weak, &AbstractConnection::receivedSome, [=] {
		onReceivedSome();
	});
	_timing.firstSentAt = 0;
	if (_timing.oldConnection) {
		_timing.oldConnection = false;
		DEBUG_LOG(("This connection marked as not old!"));
	}
	_timing.oldConnectionTimer.callOnce(kMarkConnectionOldTimeout);
	QObject::connect(weak, &AbstractConnection::connected, [=] {
		onConnected(weak);
	});
	QObject::connect(weak, &AbstractConnection::disconnected, [=] {
		onDisconnected(weak);
	});
	QObject::connect(weak, &AbstractConnection::syncTimeRequest, [=] {
		InvokeQueued(_owner->_runtime, [runtime = _owner->_runtime] {
			if (runtime->instance().syncHttpUnixtime) {
				runtime->instance().syncHttpUnixtime();
			}
		});
	});
	const auto start = [=] {
		weak->connectToServer(
			ip,
			port,
			protocolSecret,
			protocolDcId,
			protocolForFiles,
			{
				.mtproxyAttempt = attempt,
				.mtproxyPlan = plan,
				.mtproxyAttemptStartedAt = attemptStartedAt,
			});
	};
	if (dialDelay > 0) {
		_owner->_runtime->async().singleShot(dialDelay, weak, start);
	} else {
		InvokeQueued(_state.testConnections.back().data, start);
	}
	armWaitForConnectedTimer();
	return true;
}

void SessionTransport::destroyAllConnections(ProxyCloseOrigin) {
	_owner->clearUnboundKeyCreator();
	_timing.waitForBetterTimer.cancel();
	_timing.waitForReceivedTimer.cancel();
	_timing.waitForConnectedTimer.cancel();
	clearTestConnections();
	_state.connection.reset();
	_state.mtproxyUse = ProxyConnectionUse::Main;
	_state.mtproxyAttempt = {};
	_state.mtproxyAttemptStartedAt = 0;
	_state.mtprotoDataReceived = false;
}

void SessionTransport::clearTestConnections() {
	for (auto &connection : _state.testConnections) {
		// Whatever brings us here - a route race that someone else won, a
		// proxy switch, a restart - these connections are dropped by us and
		// not by the proxy. The one that really failed was already removed
		// through removeTestConnection(), where its lease counts as a miss.
		connection.mtproxyDial.cancel();
		connection.data.reset();
	}
	_state.testConnections.clear();
	_timing.waitForConnectedTimer.cancel();
}

void SessionTransport::armWaitForConnectedTimer() {
	if (_state.testConnections.empty()) {
		_timing.waitForConnectedTimer.cancel();
		return;
	}
	// A proxied connect needs its whole budget (tcp connect with SYN
	// retransmits plus the FakeTLS handshake) - killing it after
	// kMinConnectedTimeout only burns a handshake against the DPI and
	// reconnects, and repeated fresh handshakes are exactly what gets
	// proxies throttled. Direct connections keep the short first wait.
	auto wait = _timing.waitForConnected;
	if (_owner->_sessionState.options && (_owner->_sessionState.options->proxy.type != ProxyData::Type::None)) {
		auto minWait = crl::time(0);
		for (const auto &connection : _state.testConnections) {
			// A paced attempt has not spent any of its budget yet, so the
			// wait must cover the pacing delay as well or the timer fires
			// before the socket is even opened. The delay belongs to this
			// attempt only: folding it into waitForConnected would leave
			// every later attempt of this session waiting out a queue it is
			// no longer in, since that budget is reset only by a connect.
			accumulate_max(
				minWait,
				connection.data->fullConnectTimeout()
					+ connection.mtproxyDialDelay);
		}
		accumulate_max(wait, minWait);
	}
	// Connections are appended one after another, and the one that got the
	// long pacing delay is rarely the first. Leaving the timer that the first
	// one armed in place kills the queued attempt before it dials, which is
	// exactly the wait the pacer was granting it. Never shorten the timer,
	// only stretch it to the budget the widest attempt now needs.
	if (!_timing.waitForConnectedTimer.isActive()
		|| (wait > _timing.waitForConnectedArmed)) {
		_timing.waitForConnectedArmed = wait;
		_timing.waitForConnectedTimer.callOnce(wait);
	}
}

void SessionTransport::retryByTimer() {
	const auto proxied = _owner->_sessionState.options
		&& (_owner->_sessionState.options->proxy.type != ProxyData::Type::None);
	const auto maxTimeout = proxied ? kProxyReconnectMaxTimeout : 64000;
	if (_timing.retryTimeout < 3) {
		++_timing.retryTimeout;
	} else if (_timing.retryTimeout == 3) {
		_timing.retryTimeout = proxied ? kProxyReconnectMinTimeout : 1000;
	} else if (_timing.retryTimeout < maxTimeout) {
		_timing.retryTimeout = std::min(_timing.retryTimeout * 2, maxTimeout);
	}
	connectToServer();
}

void SessionTransport::restartNow() {
	_timing.retryTimeout = 1;
	_timing.retryTimer.cancel();
	restart();
}

void SessionTransport::migrateProxy(uint64 generation) {
	_state.proxyGeneration = generation;
	_state.mtproxyAttempt = { .proxyGeneration = generation };
	_owner->_sessionState.options = std::make_unique<SessionOptions>(_owner->_sessionState.data->options());
	_timing.retryTimer.cancel();
	_timing.retryTimeout = 1;
	_timing.waitForReceivedTimer.cancel();
	_timing.waitForConnectedTimer.cancel();
	_timing.waitForBetterTimer.cancel();
	_owner->logMtprotoEvent(
		ProxyDiagnosticsPhase::MtpRestart,
		ProxyDiagnosticsSeverity::Info,
		u"proxy_route_changed"_q);
	destroyAllConnections(ProxyCloseOrigin::ProxySwitch);
	_state.mtproxyAttempt = { .proxyGeneration = generation };
	_owner->setState(DisconnectedState);
	connectToServer();
}

void SessionTransport::connectToServer(bool afterConfig) {
	if (afterConfig
		&& (!_state.testConnections.empty()
			|| _state.connection)) {
		return;
	}

	destroyAllConnections(ProxyCloseOrigin::RouteRaceLost);

	if (_owner->realDcTypeChanged() && _owner->_authState.keyCreator) {
		_owner->destroyTemporaryKey();
		return;
	}

	_owner->_sessionState.options = std::make_unique<SessionOptions>(_owner->_sessionState.data->options());
	_owner->setConnectionNotice(MTP::ConnectionNotice::None);

	if (_owner->_sessionState.options->proxy.type == ProxyData::Type::None
		&& _owner->_sessionState.options->stealth.transport != ProxyTransport::Wss) {
		DEBUG_LOG(("MTP Info: proxy required, "
			"waiting for a proxy before connecting."));
		_owner->setState(-kWaitForProxyTimeout);
		return;
	}

	const auto bareDc = BareDcId(_owner->_shiftedDcId);

	_owner->_currentDcType = _owner->tryAcquireKeyCreation();
	if (_owner->_currentDcType == DcType::Cdn && !_owner->_delegate->isKeysDestroyer()) {
		if (!_owner->_delegate->dcOptions().hasCDNKeysForDc(bareDc)) {
			requestCDNConfig();
			return;
		}
	}
	const auto protocolForFiles = isMediaClusterDcId(_owner->_shiftedDcId)
		|| (_owner->_realDcType == DcType::Cdn);
	const auto protocolDcId = _owner->getProtocolDcId();
	_owner->setConnectionNotice(WssNeedsProxyRecommendation(
		_owner->_sessionState.options->proxy,
		_owner->_sessionState.options->stealth,
		protocolDcId)
		? MTP::ConnectionNotice::WssDirectFallback
		: MTP::ConnectionNotice::None);
	if (_owner->_sessionState.options->proxy.type == ProxyData::Type::Mtproto) {
		// host, port, secret for mtproto proxy are taken from proxy.
		if (!appendTestConnection(
				DcOptions::Variants::Tcp,
				{},
				0,
				{},
				protocolForFiles)) {
			return;
		}
	} else {
		using Variants = DcOptions::Variants;
		const auto special = (_owner->_currentDcType == DcType::Temporary);
		const auto variants = _owner->_delegate->dcOptions().lookup(
			bareDc,
			_owner->_currentDcType,
			_owner->_sessionState.options->proxy.type != ProxyData::Type::None);
		const auto useIPv4 = special ? true : _owner->_sessionState.options->useIPv4;
		const auto useIPv6 = special ? false : _owner->_sessionState.options->useIPv6;
		const auto useTcp = special ? true : _owner->_sessionState.options->useTcp;
		const auto useHttp = special ? false : _owner->_sessionState.options->useHttp;
		const auto skipAddress = !useIPv4
			? Variants::IPv4
			: !useIPv6
			? Variants::IPv6
			: Variants::AddressTypeCount;
		const auto skipProtocol = !useTcp
			? Variants::Tcp
			: !useHttp
			? Variants::Http
			: Variants::ProtocolCount;
		for (auto address = 0; address != Variants::AddressTypeCount; ++address) {
			if (address == skipAddress) {
				continue;
			}
			for (auto protocol = 0; protocol != Variants::ProtocolCount; ++protocol) {
				if (protocol == skipProtocol) {
					continue;
				}
				for (const auto &endpoint : variants.data[address][protocol]) {
					(void)appendTestConnection(
						static_cast<Variants::Protocol>(protocol),
						QString::fromStdString(endpoint.ip),
						endpoint.port,
						endpoint.secret,
						protocolForFiles);
				}
			}
		}
	}
	if (_state.testConnections.empty()) {
		if (_owner->_delegate->isKeysDestroyer()) {
			LOG(("MTP Error: DC %1 options for not found for auth key destruction!").arg(_owner->_shiftedDcId));
			_owner->_delegate->keyWasPossiblyDestroyed(_owner->_shiftedDcId);
			return;
		} else if (afterConfig) {
			LOG(("MTP Error: DC %1 options for not found right after config load!").arg(_owner->_shiftedDcId));
			return restart();
		}
		DEBUG_LOG(("MTP Info: DC %1 options not found, waiting for config").arg(_owner->_shiftedDcId));
		InvokeQueued(_owner->_instance, [delegate = _owner->_delegate] {
			delegate->requestConfig();
		});
		return;
	}
	DEBUG_LOG(("Connection Info: Connecting to %1 with %2 test connections."
		).arg(_owner->_shiftedDcId
		).arg(_state.testConnections.size()));

	if (!_state.startedConnectingAt) {
		_state.startedConnectingAt = crl::now();
	} else if (crl::now() - _state.startedConnectingAt > kRequestConfigTimeout) {
		InvokeQueued(_owner->_instance, [delegate = _owner->_delegate] {
			delegate->requestConfigIfOld();
		});
	}

	_timing.retryTimer.cancel();
	_timing.waitForConnectedTimer.cancel();

	_owner->logMtprotoEvent(
		ProxyDiagnosticsPhase::MtpConnecting,
		ProxyDiagnosticsSeverity::Info,
		u"connecting (sockets: %1)"_q.arg(_state.testConnections.size()));

	_owner->setState(ConnectingState);

	_owner->_authState.bindMsgId = 0;
	_owner->_requestState.pingId = _owner->_requestState.pingMsgId = _owner->_requestState.pingIdToSend = _owner->_requestState.pingSendAt = 0;
	_owner->_requestState.pingSentTime = 0;
	_owner->reportPingTime(0);
	_timing.pingSender.cancel();

	if (!_state.testConnections.empty()) {
		armWaitForConnectedTimer();
	}
}

void SessionTransport::restart() {
	DEBUG_LOG(("MTP Info: restarting Connection"));
	_timing.waitForReceivedTimer.cancel();
	_timing.waitForConnectedTimer.cancel();

	doDisconnect();

	if (_owner->_sessionState.needReset) {
		_owner->resetSession();
	}
	if (_timing.retryTimer.isActive()) {
		return;
	}
	if (_owner->_sessionState.options
		&& (_owner->_sessionState.options->proxy.type != ProxyData::Type::None)
		&& (_timing.retryTimeout < kProxyReconnectMinTimeout)) {
		_timing.retryTimeout = kProxyReconnectMinTimeout;
	}

	DEBUG_LOG(("MTP Info: restart timeout: %1ms").arg(_timing.retryTimeout));
	_owner->logMtprotoEvent(
		ProxyDiagnosticsPhase::MtpRestart,
		ProxyDiagnosticsSeverity::Info,
		u"restarting (backoff %1ms)"_q.arg(_timing.retryTimeout));

	_owner->setState(-_timing.retryTimeout);
}

void SessionTransport::onSentSome(uint64 size) {
	if (!_timing.waitForReceivedTimer.isActive()) {
		auto remain = static_cast<uint64>(_timing.waitForReceived);
		if (_state.connection
			&& _owner->_sessionState.options
			&& _owner->_sessionState.options->proxy.type
				== ProxyData::Type::Mtproto) {
			accumulate_max(
				remain,
				static_cast<uint64>(kMtproxyMinReceiveTimeout));
		}
		if (!_timing.oldConnection) {
			Assert(remain <= kMaxReceiveTimeout);

			// 8kb / sec, so 512 kb give 64 sec
			auto remainBySize = size * _timing.waitForReceived / 8192;
			remain = std::clamp(
				remainBySize,
				remain,
				uint64(kMaxReceiveTimeout));
			if (remain != _timing.waitForReceived) {
				DEBUG_LOG(("Checking connect for request with size %1 bytes, delay will be %2").arg(size).arg(remain));
			}
		}
		_timing.waitForReceivedTimer.callOnce(remain);
	}
	if (!_timing.firstSentAt) {
		_timing.firstSentAt = crl::now();
	}
}

void SessionTransport::onReceivedSome() {
	if (_timing.oldConnection) {
		_timing.oldConnection = false;
		DEBUG_LOG(("This connection marked as not old!"));
	}
	_timing.oldConnectionTimer.callOnce(kMarkConnectionOldTimeout);
	_timing.waitForReceivedTimer.cancel();
	if (_timing.firstSentAt > 0) {
		const auto ms = crl::now() - _timing.firstSentAt;
		DEBUG_LOG(("MTP Info: response in %1ms, _waitForReceived: %2ms"
			).arg(ms
			).arg(_timing.waitForReceived));

		if (ms > 0 && ms * 2 < _timing.waitForReceived) {
			_timing.waitForReceived = qMax(ms * 2, kMinReceiveTimeout);
		}
		_timing.firstSentAt = -1;
	}
}

void SessionTransport::markConnectionOld() {
	_timing.oldConnection = true;
	_timing.waitForReceived = kMinReceiveTimeout;
	DEBUG_LOG(("This connection marked as old! _waitForReceived now %1ms"
		).arg(_timing.waitForReceived));
}

void SessionTransport::waitReceivedFailed() {
	Expects(_owner->_sessionState.options != nullptr);

	DEBUG_LOG(("MTP Info: bad connection, _waitForReceived: %1ms").arg(_timing.waitForReceived));
	if (_timing.waitForReceived < kMaxReceiveTimeout) {
		_timing.waitForReceived = std::min(
			_timing.waitForReceived * 2,
			kMaxReceiveTimeout);
	}
	const auto mtproxyConnection = _state.connection
		&& _owner->_sessionState.options->proxy.type
			== ProxyData::Type::Mtproto;
	const auto silentMtproxyConnection = mtproxyConnection
		&& !_state.mtprotoDataReceived;
	if (silentMtproxyConnection) {
		++_state.mtprotoSilentTimeouts;
	}
	_owner->logMtprotoEvent(
		ProxyDiagnosticsPhase::MtpReceiveTimeout,
		ProxyDiagnosticsSeverity::Warning,
		u"no mtproto data in %1ms (received before: %2, silent strikes: %3)"_q
			.arg(_timing.waitForReceived)
			.arg(_state.mtprotoDataReceived ? u"yes"_q : u"no"_q)
			.arg(_state.mtprotoSilentTimeouts));
	doDisconnect();
	if (silentMtproxyConnection
		&& (_state.mtprotoSilentTimeouts >= kSilentTimeoutsToAssumeKeyDestroyed)) {
		_state.mtprotoSilentTimeouts = 0;
		LOG(("MTP Info: dc %1 connected but received nothing %2 times, "
			"assuming the temporary key was silently destroyed."
			).arg(_owner->_shiftedDcId
			).arg(kSilentTimeoutsToAssumeKeyDestroyed));
		return _owner->destroyTemporaryKey();
	}
	if (_timing.retryTimer.isActive()) {
		return;
	}

	if (_owner->_sessionState.options->proxy.type != ProxyData::Type::None) {
		if (_timing.retryTimeout < kProxyReconnectMinTimeout) {
			_timing.retryTimeout = kProxyReconnectMinTimeout;
		}
		DEBUG_LOG(("MTP Info: proxy reconnect backoff %1ms!"
			).arg(_timing.retryTimeout));
		_owner->setState(-_timing.retryTimeout);
	} else {
		DEBUG_LOG(("MTP Info: immediate restart!"));
		InvokeQueued(_owner, [=] { connectToServer(); });
	}

	const auto instance = _owner->_instance;
	const auto delegate = _owner->_delegate;
	const auto shiftedDcId = _owner->_shiftedDcId;
	InvokeQueued(instance, [=] {
		delegate->restartedByTimeout(shiftedDcId);
	});
}

void SessionTransport::waitConnectedFailed() {
	if (_state.testConnections.empty()) {
		return;
	}
	const auto waited = _timing.waitForConnectedArmed
		? _timing.waitForConnectedArmed
		: _timing.waitForConnected;
	DEBUG_LOG(("MTP Info: can't connect in %1ms").arg(waited));
	_owner->logMtprotoEvent(
		ProxyDiagnosticsPhase::MtpConnectTimeout,
		ProxyDiagnosticsSeverity::Warning,
		u"connect budget %1ms expired (sockets: %2)"_q
			.arg(waited)
			.arg(_state.testConnections.size()));
	auto maxTimeout = kMaxConnectedTimeout;
	for (const auto &connection : _state.testConnections) {
		accumulate_max(maxTimeout, connection.data->fullConnectTimeout());
	}
	if (_timing.waitForConnected < maxTimeout) {
		_timing.waitForConnected = std::min(maxTimeout, 2 * _timing.waitForConnected);
	}

	connectingTimedOut();

	if (_owner->_sessionState.options
		&& (_owner->_sessionState.options->proxy.type != ProxyData::Type::None)
		&& !_timing.retryTimer.isActive()) {
		if (_timing.retryTimeout < kProxyReconnectMinTimeout) {
			_timing.retryTimeout = kProxyReconnectMinTimeout;
		}
		DEBUG_LOG(("MTP Info: proxy reconnect backoff %1ms!"
			).arg(_timing.retryTimeout));
		_owner->setState(-_timing.retryTimeout);
	} else {
		DEBUG_LOG(("MTP Info: immediate restart!"));
			InvokeQueued(_owner, [=] { connectToServer(); });
	}
}

void SessionTransport::waitBetterFailed() {
	confirmBestConnection();
}

void SessionTransport::connectingTimedOut() {
	for (auto &connection : _state.testConnections) {
		connection.data->timedOut();
	}
	doDisconnect();
}

void SessionTransport::doDisconnect() {
	destroyAllConnections();
	_owner->setState(DisconnectedState);
}

void SessionTransport::requestCDNConfig() {
	InvokeQueued(_owner->_instance, [delegate = _owner->_delegate] {
		delegate->requestCDNConfig();
	});
}

void SessionTransport::onConnected(
		not_null<AbstractConnection*> connection) {
	QObject::disconnect(connection, &AbstractConnection::connected, nullptr, nullptr);
	if (!connection->isConnected()) {
		LOG(("Connection Error: not connected in onConnected(), "
			"state: %1").arg(connection->debugState()));
		return restart();
	}

	_timing.waitForConnected = kMinConnectedTimeout;
	_timing.waitForConnectedTimer.cancel();

	const auto i = ranges::find(
		_state.testConnections,
		connection.get(),
		[](const TestConnection &test) { return test.data.get(); });
	Assert(i != end(_state.testConnections));

	// The proxy answered a real Telegram reply through this socket: the
	// dial slot is free for the next session even while we keep waiting for
	// a higher priority route, and the failure spacing resets.
	i->mtproxyDial.proven();

	const auto my = i->priority;
	const auto j = ranges::find_if(
		_state.testConnections,
		[&](const TestConnection &test) { return test.priority > my; });
	if (j != end(_state.testConnections)) {
		DEBUG_LOG(("MTP Info: connection %1 succeed, waiting for %2.").arg(
			i->data->tag(),
			j->data->tag()));
		_timing.waitForBetterTimer.callOnce(kWaitForBetterTimeout);
	} else {
		DEBUG_LOG(("MTP Info: connection through IPv4 succeed."));
		_timing.waitForBetterTimer.cancel();
		_state.mtproxyUse = i->mtproxyUse;
		_state.mtproxyAttempt = i->mtproxyAttempt;
		_state.mtproxyAttemptStartedAt = i->mtproxyAttemptStartedAt;
		_state.connection = std::move(i->data);
		_state.testConnections.erase(i);
		clearTestConnections();
		_owner->checkAuthKey();
	}
}

void SessionTransport::onDisconnected(
		not_null<AbstractConnection*> connection) {
	const auto found = ranges::find(
		_state.testConnections,
		connection.get(),
		[](const TestConnection &test) { return test.data.get(); });
	if (found == end(_state.testConnections)
		&& _state.connection.get() != connection.get()) {
		return;
	}
	removeTestConnection(connection);

	if (_state.testConnections.empty()) {
		destroyAllConnections();
		restart();
	} else if (!_state.testConnections.empty()) {
		confirmBestConnection();
	}
}

void SessionTransport::confirmBestConnection() {
	if (_timing.waitForBetterTimer.isActive()) {
		return;
	}
	const auto i = ranges::max_element(
		_state.testConnections,
		std::less<>(),
		[](const TestConnection &test) {
			return test.data->isConnected()
				? test.priority
				: -1;
		});
	Assert(i != end(_state.testConnections));
	if (!i->data->isConnected()) {
		return;
	}

	DEBUG_LOG(("MTP Info: can't connect through better, using %1."
		).arg(i->data->tag()));

	// This one is connected - it just was not the route we hoped for. Its
	// lease used to die unclaimed here, which the pacer reads as a miss and
	// answers with the failure spacing, on a proxy that had in fact just
	// carried a Telegram reply.
	i->mtproxyDial.proven();

	_state.mtproxyAttempt = i->mtproxyAttempt;
	_state.mtproxyAttemptStartedAt = i->mtproxyAttemptStartedAt;
	_state.mtproxyUse = i->mtproxyUse;
	_state.connection = std::move(i->data);
	_state.testConnections.erase(i);
	clearTestConnections();

	_owner->checkAuthKey();
}

void SessionTransport::removeTestConnection(
		not_null<AbstractConnection*> connection) {
	const auto i = ranges::find(
		_state.testConnections,
		connection.get(),
		[](const TestConnection &test) { return test.data.get(); });
	if (i != end(_state.testConnections)) {
		i->data.reset();
		_state.testConnections.erase(i);
		armWaitForConnectedTimer();
	}
}

void SessionTransport::onError(
		not_null<AbstractConnection*> connection,
		qint32 errorCode) {
	if (errorCode == -429) {
		LOG(("Protocol Error: -429 flood code returned!"));
	} else if (errorCode == -444) {
		LOG(("Protocol Error: -444 bad dc_id code returned!"));
		InvokeQueued(_owner->_instance, [delegate = _owner->_delegate] {
			delegate->badConfigurationError();
		});
	}
	const auto found = ranges::find(
		_state.testConnections,
		connection.get(),
		[](const TestConnection &test) { return test.data.get(); });
	if (found == end(_state.testConnections)
		&& _state.connection.get() != connection.get()) {
		return;
	}
	removeTestConnection(connection);

	if (_state.testConnections.empty()) {
		handleError(errorCode);
	} else if (!_state.testConnections.empty()) {
		confirmBestConnection();
	}
}

void SessionTransport::handleError(int errorCode) {
	destroyAllConnections();
	_timing.waitForConnectedTimer.cancel();

	if (errorCode == -404) {
		_owner->destroyTemporaryKey();
	} else {
		MTP_LOG(_owner->_shiftedDcId, ("Restarting after error in connection, error code: %1...").arg(errorCode));
		return restart();
	}
}

} // namespace details
} // namespace MTP
