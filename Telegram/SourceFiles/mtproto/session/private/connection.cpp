/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "mtproto/session/private/session_private.h"

#include "core/version.h"
#include "mtproto/dc_id.h"
#include "mtproto/auth/mtproto_bound_key_creator.h"
#include "mtproto/details/mtproto_dcenter.h"
#include "mtproto/protocol/mtproto_dump_to_text.h"
#include "mtproto/details/mtproto_rsa_public_key.h"
#include "mtproto/proxy/connection_broker.h"
#include "mtproto/proxy/control_plane.h"
#include "mtproto/proxy/diagnostics.h"
#include "mtproto/proxy/transport_policy.h"
#include "mtproto/runtime/runtime_environment.h"
#include "mtproto/session/options.h"
#include "mtproto/session/session.h"
#include "mtproto/protocol/mtproto_response.h"
#include "mtproto/config/mtproto_dc_options.h"
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
constexpr auto kMinConnectedTimeout = crl::time(1000);
constexpr auto kMaxConnectedTimeout = crl::time(8000);
constexpr auto kMinReceiveTimeout = crl::time(4000);
constexpr auto kMaxReceiveTimeout = crl::time(64000);
constexpr auto kProxyReconnectMinTimeout = 1800;
constexpr auto kProxyReconnectMaxTimeout = 8000;
constexpr auto kWaitForProxyTimeout = 2000;
constexpr auto kMarkConnectionOldTimeout = crl::time(192000);
constexpr auto kRequestConfigTimeout = 8 * crl::time(1000);
constexpr auto kBrokerQueueHardDeadline = 90 * crl::time(1000);
constexpr auto kSilentTimeoutsToAssumeKeyDestroyed = 2;

base::options::toggle OptionPreferIPv6({
	.id = kOptionPreferIPv6,
	.name = "Prefer IPv6",
	.description = "Prefer IPv6 if it is available. Require \"Try connecting through IPv6\" to be enabled",
});

} // namespace

bool SessionPrivate::appendTestConnection(
		DcOptions::Variants::Protocol protocol,
		const QString &ip,
		int port,
		const bytes::vector &protocolSecret,
		bool protocolForFiles) {
	QWriteLocker lock(&_stateMutex);

	const auto proxy = _sessionState.options->proxy;
	const auto stealth = _sessionState.options->stealth;
	const auto endpoint = ip.isEmpty()
		? (proxy.host + ':' + QString::number(proxy.port))
		: (ip + ':' + QString::number(port));
	const auto priority = (qthelp::is_ipv6(ip) ? (OptionPreferIPv6.value() ? 2 : 0) : 1)
		+ (protocol == DcOptions::Variants::Tcp ? 1 : 0)
		+ (protocolSecret.empty() ? 0 : 1);
	const auto mtproxy = (proxy.type == ProxyData::Type::Mtproto);
	const auto mtproxyUse = protocolForFiles
		? MtProxy::EndpointUse::Media
		: MtProxy::EndpointUse::Main;
	if (_connectionState.proxyMigrationScout
		&& (!_connectionState.brokerTickets.empty() || !_connectionState.testConnections.empty())) {
		return false;
	}
	const auto mtproxyEndpoint = mtproxy
		? MtProxy::EndpointIdFromProxy(
			proxy,
			stealth,
			ip,
			port)
		: MtProxy::EndpointId();
	const auto protocolDcId = getProtocolDcId();
	const auto appendStartedConnection = [=, this](
			MtProxy::EndpointId startEndpoint,
			MtProxy::EndpointUse startUse,
			MtProxy::EndpointAttemptLease startLease,
			ProxyConnectionAttempt startAttempt,
			crl::time startAttemptStartedAt,
			ProxyStealthOptions startStealth) {
		QWriteLocker lock(&_stateMutex);
		_connectionState.testConnections.push_back({
			AbstractConnection::Create(
				_runtime,
				protocol,
				thread(),
				protocolSecret,
				proxy,
				startStealth),
			priority,
			endpoint,
			std::move(startEndpoint),
			startUse,
			std::move(startLease),
			startAttempt,
			startAttemptStartedAt
		});
		const auto weak = _connectionState.testConnections.back().data.get();
		weak->setMtproxyAttempt(startAttempt, startAttemptStartedAt);
		connect(weak, &AbstractConnection::error, [=](int errorCode) {
			onError(weak, errorCode);
		});
		connect(weak, &AbstractConnection::receivedSome, [=] {
			onReceivedSome();
		});
		_timing.firstSentAt = 0;
		if (_timing.oldConnection) {
			_timing.oldConnection = false;
			DEBUG_LOG(("This connection marked as not old!"));
		}
		_timing.oldConnectionTimer.callOnce(kMarkConnectionOldTimeout);
		connect(weak, &AbstractConnection::connected, [=] {
			onConnected(weak);
		});
		connect(weak, &AbstractConnection::disconnected, [=] {
			onDisconnected(weak);
		});
		connect(weak, &AbstractConnection::syncTimeRequest, [=] {
			InvokeQueued(_runtime, [runtime = _runtime] {
				if (runtime->syncHttpUnixtime) {
					runtime->syncHttpUnixtime();
				}
			});
		});
		const auto start = [=] {
			weak->connectToServer(
				ip,
				port,
				protocolSecret,
				protocolDcId,
				protocolForFiles);
		};
		InvokeQueued(_connectionState.testConnections.back().data, start);
		armWaitForConnectedTimer();
	};

	if (mtproxy) {
		auto ticket = ConnectionBroker::Instance().request({
			.proxyGeneration = _connectionState.proxyGeneration,
			.endpoint = mtproxyEndpoint,
			.proxy = proxy,
			.use = mtproxyUse,
			.stealth = stealth,
			.configuredTlsProfile = stealth.tlsProfile,
			.connectionPattern = stealth.connectionPattern,
			.runtime = _runtime,
			.context = this,
			.start = [=](ConnectionStart start) mutable {
				removeConnectionBrokerTicket(start.ticketId);
				if (start.proxyGeneration != _connectionState.proxyGeneration) {
					return;
				}
				appendStartedConnection(
					std::move(start.endpoint),
					start.use,
					std::move(start.lease),
					{
						.proxyGeneration = start.proxyGeneration,
						.proxyEpoch = start.proxyEpoch,
						.successEpoch = start.successEpoch,
						.attemptId = start.attemptId,
					},
					start.attemptStartedAt,
					start.stealth);
			},
			.status = [=](ConnectionBrokerDecision) {
			},
		});
		if (!ticket) {
			return false;
		}
		_connectionState.brokerTickets.push_back(std::move(ticket));
		return true;
	}

	lock.unlock();
	appendStartedConnection(
		MtProxy::EndpointId(),
		MtProxy::EndpointUse::Main,
		MtProxy::EndpointAttemptLease(),
		{ .proxyGeneration = _connectionState.proxyGeneration },
		0,
		stealth);
	return true;
}

void SessionPrivate::destroyAllConnections() {
	clearUnboundKeyCreator();
	_timing.waitForBetterTimer.cancel();
	_timing.waitForReceivedTimer.cancel();
	_timing.waitForConnectedTimer.cancel();
	_timing.brokerQueueDeadlineTimer.cancel();
	_connectionState.brokerTickets.clear();
	_connectionState.testConnections.clear();
	_connectionState.mtproxyEndpoint = MtProxy::EndpointId();
	_connectionState.mtproxyUse = MtProxy::EndpointUse::Main;
	_connectionState.mtproxyAttempt = {};
	_connectionState.mtproxyAttemptStartedAt = 0;
	_connectionState.mtprotoDataReceived = false;
	_connectionState.connection = nullptr;
}

void SessionPrivate::reportMtproxyConnectionUsable(
		const TestConnection &connection) {
	// EndpointHealth only learns an endpoint is healthy from TlsSocket's
	// first-app-data on the FakeTLS path; plain-obfuscated (dd-secret)
	// mtproxy sockets have no such hook, so without this they stay forever
	// "unknown" - throttled to activeCap 1 and never able to ignore a
	// benign remote_closed. Report success here for every transport once a
	// connection is actually usable. Skip if already healthy to avoid
	// redundant capability-cache writes on the FakeTLS path.
	if (MtProxy::EndpointEmpty(connection.mtproxyEndpoint)) {
		return;
	}
	const auto snapshot = ProxyControlPlane::MtproxyEndpointSnapshot(
		connection.mtproxyEndpoint);
	if (snapshot.healthy && !snapshot.halfOpen) {
		return;
	}
	ProxyControlPlane::ReportMtproxySuccess({
		.endpoint = connection.mtproxyEndpoint,
		.use = connection.mtproxyUse,
		.proxyGeneration = connection.mtproxyAttempt.proxyGeneration,
		.attemptId = connection.mtproxyAttempt.attemptId,
		.proxyEpoch = connection.mtproxyAttempt.proxyEpoch,
		.successEpoch = connection.mtproxyAttempt.successEpoch,
		.attemptStartedAt = connection.mtproxyAttemptStartedAt,
	});
}

void SessionPrivate::removeConnectionBrokerTicket(ConnectionTicketId id) {
	const auto i = ranges::find(
		_connectionState.brokerTickets,
		id,
		[](const ConnectionTicket &ticket) { return ticket.id(); });
	if (i != end(_connectionState.brokerTickets)) {
		_connectionState.brokerTickets.erase(i);
	}
	if (_connectionState.brokerTickets.empty()) {
		_timing.brokerQueueDeadlineTimer.cancel();
	}
}

void SessionPrivate::armWaitForConnectedTimer() {
	// A proxied connect needs its whole budget (tcp connect with SYN
	// retransmits plus the FakeTLS handshake) - killing it after
	// kMinConnectedTimeout only burns a handshake against the DPI and
	// reconnects, and repeated fresh handshakes are exactly what gets
	// proxies throttled. Direct connections keep the short first wait.
	if (_sessionState.options && (_sessionState.options->proxy.type != ProxyData::Type::None)) {
		auto minWait = crl::time(0);
		for (const auto &connection : _connectionState.testConnections) {
			accumulate_max(minWait, connection.data->fullConnectTimeout());
		}
		accumulate_max(_timing.waitForConnected, minWait);
	}
	if (!_timing.waitForConnectedTimer.isActive()) {
		_timing.waitForConnectedTimer.callOnce(_timing.waitForConnected);
	}
}

void SessionPrivate::retryByTimer() {
	const auto proxied = _sessionState.options
		&& (_sessionState.options->proxy.type != ProxyData::Type::None);
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

void SessionPrivate::restartNow() {
	_timing.retryTimeout = 1;
	_timing.retryTimer.cancel();
	restart();
}

void SessionPrivate::migrateProxy(uint64 generation, bool scout) {
	_connectionState.proxyGeneration = generation;
	_connectionState.proxyMigrationScout = scout;
	_connectionState.proxyMigrationSuspended = !scout;
	_connectionState.mtproxyAttempt = { .proxyGeneration = generation };
	_sessionState.options = std::make_unique<SessionOptions>(_sessionState.data->options());
	_timing.retryTimer.cancel();
	_timing.waitForReceivedTimer.cancel();
	_timing.waitForConnectedTimer.cancel();
	_timing.waitForBetterTimer.cancel();
	_timing.brokerQueueDeadlineTimer.cancel();
	logMtprotoEvent(
		ProxyDiagnosticsPhase::MtpRestart,
		ProxyDiagnosticsSeverity::Info,
		scout
			? u"proxy_switch_main_scout"_q
			: u"suspended_by_proxy_switch"_q);
	destroyAllConnections();
	_connectionState.mtproxyAttempt = { .proxyGeneration = generation };
	setState(DisconnectedState);
	if (!scout) {
		return;
	}
	connectToServer();
}

void SessionPrivate::releaseProxyMigration(uint64 generation) {
	if (generation != _connectionState.proxyGeneration || !_connectionState.proxyMigrationSuspended) {
		return;
	}
	_connectionState.proxyMigrationSuspended = false;
	_connectionState.proxyMigrationScout = false;
	_connectionState.mtproxyAttempt = { .proxyGeneration = generation };
	connectToServer();
}

void SessionPrivate::connectToServer(bool afterConfig) {
	if (_connectionState.proxyMigrationSuspended) {
		return;
	}
	if (afterConfig
		&& (!_connectionState.testConnections.empty()
			|| !_connectionState.brokerTickets.empty()
			|| _connectionState.connection)) {
		// A queued broker ticket means this session is already mid-connect
		// (mtproxy sessions sit with empty _testConnections while waiting on
		// admission); an afterConfig re-entry must not tear it down and lose
		// its place in the broker queue.
		return;
	}

	destroyAllConnections();

	if (realDcTypeChanged() && _authState.keyCreator) {
		destroyTemporaryKey();
		return;
	}

	_sessionState.options = std::make_unique<SessionOptions>(_sessionState.data->options());
	setConnectionNotice(MTP::ConnectionNotice::None);

	if (_sessionState.options->proxy.type == ProxyData::Type::None
		&& _sessionState.options->stealth.transport != ProxyTransport::Wss) {
		DEBUG_LOG(("MTP Info: proxy required, "
			"waiting for a proxy before connecting."));
		setState(-kWaitForProxyTimeout);
		return;
	}

	const auto bareDc = BareDcId(_shiftedDcId);

	_currentDcType = tryAcquireKeyCreation();
	if (_currentDcType == DcType::Cdn && !_instance->isKeysDestroyer()) {
		if (!_instance->dcOptions().hasCDNKeysForDc(bareDc)) {
			requestCDNConfig();
			return;
		}
	}
	const auto protocolForFiles = isMediaClusterDcId(_shiftedDcId)
		|| (_realDcType == DcType::Cdn);
	const auto protocolDcId = getProtocolDcId();
	setConnectionNotice(WssNeedsProxyRecommendation(
		_sessionState.options->proxy,
		_sessionState.options->stealth,
		protocolDcId,
		protocolForFiles)
		? MTP::ConnectionNotice::WssDirectFallback
		: MTP::ConnectionNotice::None);
	if (_sessionState.options->proxy.type == ProxyData::Type::Mtproto) {
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
		const auto special = (_currentDcType == DcType::Temporary);
		const auto variants = _instance->dcOptions().lookup(
			bareDc,
			_currentDcType,
			_sessionState.options->proxy.type != ProxyData::Type::None);
		const auto useIPv4 = special ? true : _sessionState.options->useIPv4;
		const auto useIPv6 = special ? false : _sessionState.options->useIPv6;
		const auto useTcp = special ? true : _sessionState.options->useTcp;
		const auto useHttp = special ? false : _sessionState.options->useHttp;
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
	if (_connectionState.testConnections.empty() && _connectionState.brokerTickets.empty()) {
		if (_instance->isKeysDestroyer()) {
			LOG(("MTP Error: DC %1 options for not found for auth key destruction!").arg(_shiftedDcId));
			_instance->keyWasPossiblyDestroyed(_shiftedDcId);
			return;
		} else if (afterConfig) {
			LOG(("MTP Error: DC %1 options for not found right after config load!").arg(_shiftedDcId));
			return restart();
		}
		DEBUG_LOG(("MTP Info: DC %1 options not found, waiting for config").arg(_shiftedDcId));
		InvokeQueued(_instance, [instance = _instance] {
			instance->requestConfig();
		});
		return;
	}
	DEBUG_LOG(("Connection Info: Connecting to %1 with %2 test connections."
		).arg(_shiftedDcId
		).arg(_connectionState.testConnections.size()));

	if (!_connectionState.startedConnectingAt) {
		_connectionState.startedConnectingAt = crl::now();
	} else if (crl::now() - _connectionState.startedConnectingAt > kRequestConfigTimeout) {
		InvokeQueued(_instance, [instance = _instance] {
			instance->requestConfigIfOld();
		});
	}

	_timing.retryTimer.cancel();
	_timing.waitForConnectedTimer.cancel();

	logMtprotoEvent(
		ProxyDiagnosticsPhase::MtpConnecting,
		ProxyDiagnosticsSeverity::Info,
		u"connecting (sockets: %1, broker queued: %2)"_q
			.arg(_connectionState.testConnections.size())
			.arg(_connectionState.brokerTickets.size()));

	setState(ConnectingState);

	_authState.bindMsgId = 0;
	_requestState.pingId = _requestState.pingMsgId = _requestState.pingIdToSend = _requestState.pingSendAt = 0;
	_requestState.pingSentTime = 0;
	reportPingTime(0);
	_timing.pingSender.cancel();

	if (!_connectionState.testConnections.empty()) {
		armWaitForConnectedTimer();
	}
	if (!_connectionState.brokerTickets.empty()) {
		_timing.brokerQueueDeadlineTimer.callOnce(kBrokerQueueHardDeadline);
	}
}

void SessionPrivate::restart() {
	DEBUG_LOG(("MTP Info: restarting Connection"));

	_timing.waitForReceivedTimer.cancel();
	_timing.waitForConnectedTimer.cancel();

	doDisconnect();

	if (_sessionState.needReset) {
		resetSession();
	}
	if (_timing.retryTimer.isActive()) {
		return;
	}
	if (_sessionState.options
		&& (_sessionState.options->proxy.type != ProxyData::Type::None)
		&& (_timing.retryTimeout < kProxyReconnectMinTimeout)) {
		_timing.retryTimeout = kProxyReconnectMinTimeout;
	}

	DEBUG_LOG(("MTP Info: restart timeout: %1ms").arg(_timing.retryTimeout));
	logMtprotoEvent(
		ProxyDiagnosticsPhase::MtpRestart,
		ProxyDiagnosticsSeverity::Info,
		u"restarting (backoff %1ms)"_q.arg(_timing.retryTimeout));

	setState(-_timing.retryTimeout);
}

void SessionPrivate::onSentSome(uint64 size) {
	if (!_timing.waitForReceivedTimer.isActive()) {
		auto remain = static_cast<uint64>(_timing.waitForReceived);
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

void SessionPrivate::onReceivedSome() {
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

void SessionPrivate::markConnectionOld() {
	_timing.oldConnection = true;
	_timing.waitForReceived = kMinReceiveTimeout;
	DEBUG_LOG(("This connection marked as old! _waitForReceived now %1ms"
		).arg(_timing.waitForReceived));
}

void SessionPrivate::waitReceivedFailed() {
	Expects(_sessionState.options != nullptr);

	DEBUG_LOG(("MTP Info: bad connection, _waitForReceived: %1ms").arg(_timing.waitForReceived));
	if (_timing.waitForReceived < kMaxReceiveTimeout) {
		_timing.waitForReceived = std::min(
			_timing.waitForReceived * 2,
			kMaxReceiveTimeout);
	}
	const auto mtproxyConnection = _connectionState.connection
		&& !MtProxy::EndpointEmpty(_connectionState.mtproxyEndpoint);
	const auto silentMtproxyConnection = mtproxyConnection
		&& !_connectionState.mtprotoDataReceived;
	if (silentMtproxyConnection) {
		++_connectionState.mtprotoSilentTimeouts;
	}
	logMtprotoEvent(
		ProxyDiagnosticsPhase::MtpReceiveTimeout,
		ProxyDiagnosticsSeverity::Warning,
		u"no mtproto data in %1ms (received before: %2, silent strikes: %3)"_q
			.arg(_timing.waitForReceived)
			.arg(_connectionState.mtprotoDataReceived ? u"yes"_q : u"no"_q)
			.arg(_connectionState.mtprotoSilentTimeouts));
	if (mtproxyConnection) {
		const auto mtproxyReason = silentMtproxyConnection
			? ProxyMtproxyTerminalReason::ServerHelloOkNoMtprotoData
			: ProxyMtproxyTerminalReason::MtpReceiveTimeoutAfterData;
		ReportProxyEvent(_runtime, {
			.phase = ProxyDiagnosticsPhase::Failed,
			.error = ProxyConnectionError::Timeout,
			.mtproxyReason = mtproxyReason,
			.attempt = _connectionState.mtproxyAttempt,
			.severity = ProxyDiagnosticsSeverity::Warning,
			.proxy = _sessionState.options->proxy,
			.dc = mtprotoLogDc(),
			.message = silentMtproxyConnection
				? u"proxy connected, mtproto data stalled"_q
				: u"mtp receive timeout after relay data"_q,
		});
	}
	if (silentMtproxyConnection) {
		ProxyControlPlane::ReportMtproxyFailure({
			.endpoint = _connectionState.mtproxyEndpoint,
			.use = _connectionState.mtproxyUse,
			.reason = MtProxy::FailureReason::ServerHelloOkNoMtprotoData,
			.proxyGeneration = _connectionState.mtproxyAttempt.proxyGeneration,
			.attemptId = _connectionState.mtproxyAttempt.attemptId,
			.proxyEpoch = _connectionState.mtproxyAttempt.proxyEpoch,
			.successEpoch = _connectionState.mtproxyAttempt.successEpoch,
			.attemptStartedAt = _connectionState.mtproxyAttemptStartedAt,
		});
	} else if (mtproxyConnection) {
		ProxyControlPlane::NoteMtproxyRelayStall({
			.endpoint = _connectionState.mtproxyEndpoint,
			.use = _connectionState.mtproxyUse,
			.proxyGeneration = _connectionState.mtproxyAttempt.proxyGeneration,
			.attemptId = _connectionState.mtproxyAttempt.attemptId,
			.proxyEpoch = _connectionState.mtproxyAttempt.proxyEpoch,
			.successEpoch = _connectionState.mtproxyAttempt.successEpoch,
			.attemptStartedAt = _connectionState.mtproxyAttemptStartedAt,
		});
	}
	doDisconnect();
	if (silentMtproxyConnection
		&& (_connectionState.mtprotoSilentTimeouts >= kSilentTimeoutsToAssumeKeyDestroyed)) {
		_connectionState.mtprotoSilentTimeouts = 0;
		LOG(("MTP Info: dc %1 connected but received nothing %2 times, "
			"assuming the temporary key was silently destroyed."
			).arg(_shiftedDcId
			).arg(kSilentTimeoutsToAssumeKeyDestroyed));
		return destroyTemporaryKey();
	}
	if (_timing.retryTimer.isActive()) {
		return;
	}

	if (_sessionState.options->proxy.type != ProxyData::Type::None) {
		if (_timing.retryTimeout < kProxyReconnectMinTimeout) {
			_timing.retryTimeout = kProxyReconnectMinTimeout;
		}
		DEBUG_LOG(("MTP Info: proxy reconnect backoff %1ms!"
			).arg(_timing.retryTimeout));
		setState(-_timing.retryTimeout);
	} else {
		DEBUG_LOG(("MTP Info: immediate restart!"));
		InvokeQueued(this, [=] { connectToServer(); });
	}

	const auto instance = _instance;
	const auto shiftedDcId = _shiftedDcId;
	InvokeQueued(instance, [=] {
		instance->restartedByTimeout(shiftedDcId);
	});
}

void SessionPrivate::waitConnectedFailed() {
	DEBUG_LOG(("MTP Info: can't connect in %1ms").arg(_timing.waitForConnected));
	logMtprotoEvent(
		ProxyDiagnosticsPhase::MtpConnectTimeout,
		ProxyDiagnosticsSeverity::Warning,
		u"connect budget %1ms expired (sockets: %2)"_q
			.arg(_timing.waitForConnected)
			.arg(_connectionState.testConnections.size()));
	auto maxTimeout = kMaxConnectedTimeout;
	for (const auto &connection : _connectionState.testConnections) {
		accumulate_max(maxTimeout, connection.data->fullConnectTimeout());
	}
	if (_timing.waitForConnected < maxTimeout) {
		_timing.waitForConnected = std::min(maxTimeout, 2 * _timing.waitForConnected);
	}

	connectingTimedOut();

	if (_sessionState.options
		&& (_sessionState.options->proxy.type != ProxyData::Type::None)
		&& !_timing.retryTimer.isActive()) {
		if (_timing.retryTimeout < kProxyReconnectMinTimeout) {
			_timing.retryTimeout = kProxyReconnectMinTimeout;
		}
		DEBUG_LOG(("MTP Info: proxy reconnect backoff %1ms!"
			).arg(_timing.retryTimeout));
		setState(-_timing.retryTimeout);
	} else {
		DEBUG_LOG(("MTP Info: immediate restart!"));
		InvokeQueued(this, [=] { connectToServer(); });
	}
}

void SessionPrivate::brokerQueueDeadlineFired() {
	if (_connectionState.brokerTickets.empty() || !_connectionState.testConnections.empty()) {
		return;
	}
	DEBUG_LOG(("MTP Info: broker ticket not started in %1ms, reconnecting"
		).arg(kBrokerQueueHardDeadline));
	logMtprotoEvent(
		ProxyDiagnosticsPhase::MtpBrokerTimeout,
		ProxyDiagnosticsSeverity::Warning,
		u"broker ticket not started in %1ms, reconnecting"_q
			.arg(kBrokerQueueHardDeadline));

	doDisconnect();

	if (_sessionState.options
		&& (_sessionState.options->proxy.type != ProxyData::Type::None)
		&& !_timing.retryTimer.isActive()) {
		if (_timing.retryTimeout < kProxyReconnectMinTimeout) {
			_timing.retryTimeout = kProxyReconnectMinTimeout;
		}
		setState(-_timing.retryTimeout);
	} else if (!_timing.retryTimer.isActive()) {
		InvokeQueued(this, [=] { connectToServer(); });
	}
}

void SessionPrivate::waitBetterFailed() {
	confirmBestConnection();
}

void SessionPrivate::connectingTimedOut() {
	for (const auto &connection : _connectionState.testConnections) {
		if (!MtProxy::EndpointEmpty(connection.mtproxyEndpoint)
			&& connection.mtproxyEndpoint.canonical.domainFromSecret.isEmpty()) {
			ProxyControlPlane::ReportMtproxyFailure({
				.endpoint = connection.mtproxyEndpoint,
				.use = connection.mtproxyUse,
				.reason = MtProxy::FailureReason::TcpConnectTimeout,
				.proxyGeneration = connection.mtproxyAttempt.proxyGeneration,
				.attemptId = connection.mtproxyAttempt.attemptId,
				.proxyEpoch = connection.mtproxyAttempt.proxyEpoch,
				.successEpoch = connection.mtproxyAttempt.successEpoch,
				.attemptStartedAt = connection.mtproxyAttemptStartedAt,
			});
		}
		connection.data->timedOut();
	}
	doDisconnect();
}

void SessionPrivate::doDisconnect() {
	destroyAllConnections();
	setState(DisconnectedState);
}

void SessionPrivate::requestCDNConfig() {
	InvokeQueued(_instance, [instance = _instance] {
		instance->requestCDNConfig();
	});
}

void SessionPrivate::onConnected(
		not_null<AbstractConnection*> connection) {
	disconnect(connection, &AbstractConnection::connected, nullptr, nullptr);
	if (!connection->isConnected()) {
		LOG(("Connection Error: not connected in onConnected(), "
			"state: %1").arg(connection->debugState()));
		return restart();
	}

	_timing.waitForConnected = kMinConnectedTimeout;
	_timing.waitForConnectedTimer.cancel();

	const auto i = ranges::find(
		_connectionState.testConnections,
		connection.get(),
		[](const TestConnection &test) { return test.data.get(); });
	Assert(i != end(_connectionState.testConnections));
	const auto mtproxyAttempt = ProxyConnectionAttempt{
		.proxyGeneration = i->mtproxyAttempt.proxyGeneration,
		.proxyEpoch = i->mtproxyLease.proxyEpoch(),
		.successEpoch = i->mtproxyLease.successEpoch(),
		.attemptId = i->mtproxyLease.attemptId(),
	};
	const auto mtproxyAttemptStartedAt = i->mtproxyLease.startedAt();
	i->mtproxyLease.release();
	reportMtproxyConnectionUsable(*i);
	const auto my = i->priority;
	const auto j = ranges::find_if(
		_connectionState.testConnections,
		[&](const TestConnection &test) { return test.priority > my; });
	if (j != end(_connectionState.testConnections)) {
		DEBUG_LOG(("MTP Info: connection %1 succeed, waiting for %2.").arg(
			i->data->tag(),
			j->data->tag()));
		_timing.waitForBetterTimer.callOnce(kWaitForBetterTimeout);
	} else {
		DEBUG_LOG(("MTP Info: connection through IPv4 succeed."));
		_timing.waitForBetterTimer.cancel();
		_connectionState.mtproxyEndpoint = i->mtproxyEndpoint;
		_connectionState.mtproxyUse = i->mtproxyUse;
		_connectionState.mtproxyAttempt = mtproxyAttempt;
		_connectionState.mtproxyAttemptStartedAt = mtproxyAttemptStartedAt;
		_connectionState.connection = std::move(i->data);
		_connectionState.brokerTickets.clear();
		_connectionState.testConnections.clear();
		checkAuthKey();
	}
}

void SessionPrivate::onDisconnected(
		not_null<AbstractConnection*> connection) {
	const auto found = ranges::find(
		_connectionState.testConnections,
		connection.get(),
		[](const TestConnection &test) { return test.data.get(); });
	if (found == end(_connectionState.testConnections)
		&& _connectionState.connection.get() != connection.get()) {
		return;
	}
	removeTestConnection(connection);

	if (_connectionState.testConnections.empty() && _connectionState.brokerTickets.empty()) {
		destroyAllConnections();
		restart();
	} else if (!_connectionState.testConnections.empty()) {
		confirmBestConnection();
	}
}

void SessionPrivate::confirmBestConnection() {
	if (_timing.waitForBetterTimer.isActive()) {
		return;
	}
	const auto i = ranges::max_element(
		_connectionState.testConnections,
		std::less<>(),
		[](const TestConnection &test) {
			return test.data->isConnected()
				? test.priority
				: -1;
		});
	Assert(i != end(_connectionState.testConnections));
	if (!i->data->isConnected()) {
		return;
	}

	DEBUG_LOG(("MTP Info: can't connect through better, using %1."
		).arg(i->data->tag()));

	reportMtproxyConnectionUsable(*i);
	_connectionState.mtproxyAttempt = {
		.proxyGeneration = i->mtproxyAttempt.proxyGeneration,
		.proxyEpoch = i->mtproxyLease.proxyEpoch(),
		.successEpoch = i->mtproxyLease.successEpoch(),
		.attemptId = i->mtproxyLease.attemptId(),
	};
	_connectionState.mtproxyAttemptStartedAt = i->mtproxyLease.startedAt();
	_connectionState.mtproxyEndpoint = i->mtproxyEndpoint;
	_connectionState.mtproxyUse = i->mtproxyUse;
	_connectionState.connection = std::move(i->data);
	_connectionState.brokerTickets.clear();
	_connectionState.testConnections.clear();

	checkAuthKey();
}

void SessionPrivate::removeTestConnection(
		not_null<AbstractConnection*> connection) {
	const auto i = ranges::find(
		_connectionState.testConnections,
		connection.get(),
		[](const TestConnection &test) { return test.data.get(); });
	if (i != end(_connectionState.testConnections)) {
		i->mtproxyLease.release();
		_connectionState.testConnections.erase(i);
	}
}

void SessionPrivate::onError(
		not_null<AbstractConnection*> connection,
		qint32 errorCode) {
	if (errorCode == -429) {
		LOG(("Protocol Error: -429 flood code returned!"));
	} else if (errorCode == -444) {
		LOG(("Protocol Error: -444 bad dc_id code returned!"));
		InvokeQueued(_instance, [instance = _instance] {
			instance->badConfigurationError();
		});
	}
	const auto found = ranges::find(
		_connectionState.testConnections,
		connection.get(),
		[](const TestConnection &test) { return test.data.get(); });
	if (found == end(_connectionState.testConnections)
		&& _connectionState.connection.get() != connection.get()) {
		return;
	}
	if (found != end(_connectionState.testConnections)) {
		if (!MtProxy::EndpointEmpty(found->mtproxyEndpoint)) {
			ProxyControlPlane::ReportMtproxyFailure({
				.endpoint = found->mtproxyEndpoint,
				.use = found->mtproxyUse,
				.reason = MtProxy::FailureReasonFromErrorCode(errorCode),
				.lease = &found->mtproxyLease,
				.proxyGeneration = found->mtproxyAttempt.proxyGeneration,
				.attemptId = found->mtproxyAttempt.attemptId,
				.proxyEpoch = found->mtproxyAttempt.proxyEpoch,
				.successEpoch = found->mtproxyAttempt.successEpoch,
				.attemptStartedAt = found->mtproxyAttemptStartedAt,
			});
		}
	} else if (_connectionState.connection.get() == connection.get()
		&& !MtProxy::EndpointEmpty(_connectionState.mtproxyEndpoint)) {
		const auto reason = MtProxy::FailureReasonFromErrorCode(errorCode);
		if (reason != MtProxy::FailureReason::None) {
			const auto snapshot = ProxyControlPlane::MtproxyEndpointSnapshot(
				_connectionState.mtproxyEndpoint);
			const auto ignoreRemoteClosed = (reason
					== MtProxy::FailureReason::AppDataRemoteClosed)
				&& snapshot.healthy
				&& !snapshot.halfOpen;
			if (!ignoreRemoteClosed) {
				ProxyControlPlane::ReportMtproxyFailure({
					.endpoint = _connectionState.mtproxyEndpoint,
					.use = _connectionState.mtproxyUse,
					.reason = reason,
					.proxyGeneration = _connectionState.mtproxyAttempt.proxyGeneration,
					.attemptId = _connectionState.mtproxyAttempt.attemptId,
					.proxyEpoch = _connectionState.mtproxyAttempt.proxyEpoch,
					.successEpoch = _connectionState.mtproxyAttempt.successEpoch,
					.attemptStartedAt = _connectionState.mtproxyAttemptStartedAt,
				});
			}
		}
	}
	removeTestConnection(connection);

	if (_connectionState.testConnections.empty() && _connectionState.brokerTickets.empty()) {
		handleError(errorCode);
	} else if (!_connectionState.testConnections.empty()) {
		confirmBestConnection();
	}
}

void SessionPrivate::handleError(int errorCode) {
	destroyAllConnections();
	_timing.waitForConnectedTimer.cancel();

	if (errorCode == -404) {
		destroyTemporaryKey();
	} else {
		MTP_LOG(_shiftedDcId, ("Restarting after error in connection, error code: %1...").arg(errorCode));
		return restart();
	}
}

} // namespace details
} // namespace MTP
