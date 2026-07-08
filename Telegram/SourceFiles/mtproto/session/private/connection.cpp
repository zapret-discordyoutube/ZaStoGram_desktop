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
constexpr auto kMaxConnectedTimeout = crl::time(8000);
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
	const auto mtproxyUse = protocolForFiles
		? SessionProxyEndpointUse::Media
		: SessionProxyEndpointUse::Main;
	if (_state.proxyMigrationScout
		&& (!_state.brokerTickets.empty() || !_state.testConnections.empty())) {
		return false;
	}
	const auto protocolDcId = _owner->getProtocolDcId();
	const auto appendStartedConnection = [=, this](
			MtProxy::EndpointId startEndpoint,
			SessionProxyEndpointUse startUse,
			SessionProxyLease startLease,
			ProxyConnectionAttempt startAttempt,
			crl::time startAttemptStartedAt,
			ProxyStealthOptions startStealth) {
		QWriteLocker lock(&_owner->_stateMutex);
		_state.testConnections.push_back({
			_owner->_connectionFactory->create(
				_owner->_runtime,
				protocol,
				_owner->thread(),
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
					.mtproxyAttempt = startAttempt,
					.mtproxyAttemptStartedAt = startAttemptStartedAt,
				});
		};
		InvokeQueued(_state.testConnections.back().data, start);
		armWaitForConnectedTimer();
	};

	if (mtproxy) {
		auto ticket = _owner->_proxyPort->requestConnection({
			.proxyGeneration = _state.proxyGeneration,
			.proxy = proxy,
			.address = ip,
			.port = port,
			.use = mtproxyUse,
			.stealth = stealth,
			.configuredTlsProfile = stealth.tlsProfile,
			.connectionPattern = stealth.connectionPattern,
			.runtime = _owner->_runtime,
			.context = _owner,
			.start = [=](SessionProxyStart start) mutable {
				removeConnectionBrokerTicket(start.ticketId);
				if (start.proxyGeneration != _state.proxyGeneration) {
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
			.status = [=](SessionProxyAdmissionDecision) {
			},
		});
		if (!ticket) {
			return false;
		}
		_state.brokerTickets.push_back(std::move(ticket));
		return true;
	}

	lock.unlock();
	appendStartedConnection(
		MtProxy::EndpointId(),
		SessionProxyEndpointUse::Main,
		SessionProxyLease(),
		{ .proxyGeneration = _state.proxyGeneration },
		0,
		stealth);
	return true;
}

void SessionTransport::destroyAllConnections() {
	_owner->clearUnboundKeyCreator();
	_timing.waitForBetterTimer.cancel();
	_timing.waitForReceivedTimer.cancel();
	_timing.waitForConnectedTimer.cancel();
	_timing.brokerQueueDeadlineTimer.cancel();
	_state.brokerTickets.clear();
	_state.testConnections.clear();
	_state.mtproxyEndpoint = MtProxy::EndpointId();
	_state.mtproxyUse = SessionProxyEndpointUse::Main;
	_state.mtproxyAttempt = {};
	_state.mtproxyAttemptStartedAt = 0;
	_state.mtprotoDataReceived = false;
	_state.connection = nullptr;
}

void SessionTransport::reportMtproxyConnectionUsable(
		const TestConnection &connection) {
	// EndpointHealth only learns an endpoint is healthy from TlsSocket's
	// first-app-data on the FakeTLS path; plain-obfuscated (dd-secret)
	// mtproxy sockets have no such hook, so without this they stay forever
	// "unknown" - throttled to activeCap 1 and never able to ignore a
	// benign remote_closed. Report success here for every transport once a
	// connection is actually usable. Skip if already healthy to avoid
	// redundant capability-cache writes on the FakeTLS path.
	if (EmptySessionProxyEndpoint(connection.mtproxyEndpoint)) {
		return;
	}
	const auto snapshot = _owner->_proxyPort->endpointSnapshot(
		_owner->_runtime,
		connection.mtproxyEndpoint);
	if (snapshot.healthy && !snapshot.halfOpen) {
		return;
	}
	_owner->_proxyPort->reportConnected(
		proxyAttempt(connection),
		nullptr,
		SessionProxySuccessScope::Handshake);
}

void SessionTransport::removeConnectionBrokerTicket(SessionProxyTicketId id) {
	const auto i = ranges::find(
		_state.brokerTickets,
		id,
		[](const SessionProxyTicket &ticket) { return ticket.id(); });
	if (i != end(_state.brokerTickets)) {
		_state.brokerTickets.erase(i);
	}
	if (_state.brokerTickets.empty()) {
		_timing.brokerQueueDeadlineTimer.cancel();
	}
}

void SessionTransport::armWaitForConnectedTimer() {
	// A proxied connect needs its whole budget (tcp connect with SYN
	// retransmits plus the FakeTLS handshake) - killing it after
	// kMinConnectedTimeout only burns a handshake against the DPI and
	// reconnects, and repeated fresh handshakes are exactly what gets
	// proxies throttled. Direct connections keep the short first wait.
	if (_owner->_sessionState.options && (_owner->_sessionState.options->proxy.type != ProxyData::Type::None)) {
		auto minWait = crl::time(0);
		for (const auto &connection : _state.testConnections) {
			accumulate_max(minWait, connection.data->fullConnectTimeout());
		}
		accumulate_max(_timing.waitForConnected, minWait);
	}
	if (!_timing.waitForConnectedTimer.isActive()) {
		_timing.waitForConnectedTimer.callOnce(_timing.waitForConnected);
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

void SessionTransport::migrateProxy(uint64 generation, bool scout) {
	_state.proxyGeneration = generation;
	_state.proxyMigrationScout = scout;
	_state.proxyMigrationSuspended = !scout;
	_state.mtproxyAttempt = { .proxyGeneration = generation };
	_owner->_sessionState.options = std::make_unique<SessionOptions>(_owner->_sessionState.data->options());
	_timing.retryTimer.cancel();
	_timing.waitForReceivedTimer.cancel();
	_timing.waitForConnectedTimer.cancel();
	_timing.waitForBetterTimer.cancel();
	_timing.brokerQueueDeadlineTimer.cancel();
	_owner->logMtprotoEvent(
		ProxyDiagnosticsPhase::MtpRestart,
		ProxyDiagnosticsSeverity::Info,
		scout
			? u"proxy_switch_main_scout"_q
			: u"suspended_by_proxy_switch"_q);
	destroyAllConnections();
	_state.mtproxyAttempt = { .proxyGeneration = generation };
	_owner->setState(DisconnectedState);
	if (!scout) {
		return;
	}
	connectToServer();
}

void SessionTransport::releaseProxyMigration(uint64 generation) {
	if (generation != _state.proxyGeneration || !_state.proxyMigrationSuspended) {
		return;
	}
	_state.proxyMigrationSuspended = false;
	_state.proxyMigrationScout = false;
	_state.mtproxyAttempt = { .proxyGeneration = generation };
	connectToServer();
}

void SessionTransport::connectToServer(bool afterConfig) {
	if (_state.proxyMigrationSuspended) {
		return;
	}
	if (afterConfig
		&& (!_state.testConnections.empty()
			|| !_state.brokerTickets.empty()
			|| _state.connection)) {
		// A queued broker ticket means this session is already mid-connect
		// (mtproxy sessions sit with empty _testConnections while waiting on
		// admission); an afterConfig re-entry must not tear it down and lose
		// its place in the broker queue.
		return;
	}

	destroyAllConnections();

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
		protocolDcId,
		protocolForFiles)
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
	if (_state.testConnections.empty() && _state.brokerTickets.empty()) {
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
		u"connecting (sockets: %1, broker queued: %2)"_q
			.arg(_state.testConnections.size())
			.arg(_state.brokerTickets.size()));

	_owner->setState(ConnectingState);

	_owner->_authState.bindMsgId = 0;
	_owner->_requestState.pingId = _owner->_requestState.pingMsgId = _owner->_requestState.pingIdToSend = _owner->_requestState.pingSendAt = 0;
	_owner->_requestState.pingSentTime = 0;
	_owner->reportPingTime(0);
	_timing.pingSender.cancel();

	if (!_state.testConnections.empty()) {
		armWaitForConnectedTimer();
	}
	if (!_state.brokerTickets.empty()) {
		_timing.brokerQueueDeadlineTimer.callOnce(kBrokerQueueHardDeadline);
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
		&& !EmptySessionProxyEndpoint(_state.mtproxyEndpoint);
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
	if (mtproxyConnection) {
		_owner->_proxyPort->reportReceiveTimeout(
			_owner->_runtime,
			_owner->_sessionState.options->proxy,
			_owner->mtprotoLogDc(),
			currentProxyAttempt(),
			_state.mtprotoDataReceived,
			_state.mtprotoSilentTimeouts);
	}
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
	DEBUG_LOG(("MTP Info: can't connect in %1ms").arg(_timing.waitForConnected));
	_owner->logMtprotoEvent(
		ProxyDiagnosticsPhase::MtpConnectTimeout,
		ProxyDiagnosticsSeverity::Warning,
		u"connect budget %1ms expired (sockets: %2)"_q
			.arg(_timing.waitForConnected)
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

void SessionTransport::brokerQueueDeadlineFired() {
	if (_state.brokerTickets.empty() || !_state.testConnections.empty()) {
		return;
	}
	DEBUG_LOG(("MTP Info: broker ticket not started in %1ms, reconnecting"
		).arg(kBrokerQueueHardDeadline));
	_owner->logMtprotoEvent(
		ProxyDiagnosticsPhase::MtpBrokerTimeout,
		ProxyDiagnosticsSeverity::Warning,
		u"broker ticket not started in %1ms, reconnecting"_q
			.arg(kBrokerQueueHardDeadline));

	doDisconnect();

	if (_owner->_sessionState.options
		&& (_owner->_sessionState.options->proxy.type != ProxyData::Type::None)
		&& !_timing.retryTimer.isActive()) {
		if (_timing.retryTimeout < kProxyReconnectMinTimeout) {
			_timing.retryTimeout = kProxyReconnectMinTimeout;
		}
		_owner->setState(-_timing.retryTimeout);
	} else if (!_timing.retryTimer.isActive()) {
		InvokeQueued(_owner, [=] { connectToServer(); });
	}
}

void SessionTransport::waitBetterFailed() {
	confirmBestConnection();
}

void SessionTransport::connectingTimedOut() {
	for (const auto &connection : _state.testConnections) {
		_owner->_proxyPort->reportConnectTimeout(proxyAttempt(connection));
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
		_state.mtproxyEndpoint = i->mtproxyEndpoint;
		_state.mtproxyUse = i->mtproxyUse;
		_state.mtproxyAttempt = mtproxyAttempt;
		_state.mtproxyAttemptStartedAt = mtproxyAttemptStartedAt;
		_state.connection = std::move(i->data);
		_state.brokerTickets.clear();
		_state.testConnections.clear();
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

	if (_state.testConnections.empty() && _state.brokerTickets.empty()) {
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

	reportMtproxyConnectionUsable(*i);
	_state.mtproxyAttempt = {
		.proxyGeneration = i->mtproxyAttempt.proxyGeneration,
		.proxyEpoch = i->mtproxyLease.proxyEpoch(),
		.successEpoch = i->mtproxyLease.successEpoch(),
		.attemptId = i->mtproxyLease.attemptId(),
	};
	_state.mtproxyAttemptStartedAt = i->mtproxyLease.startedAt();
	_state.mtproxyEndpoint = i->mtproxyEndpoint;
	_state.mtproxyUse = i->mtproxyUse;
	_state.connection = std::move(i->data);
	_state.brokerTickets.clear();
	_state.testConnections.clear();

	_owner->checkAuthKey();
}

void SessionTransport::removeTestConnection(
		not_null<AbstractConnection*> connection) {
	const auto i = ranges::find(
		_state.testConnections,
		connection.get(),
		[](const TestConnection &test) { return test.data.get(); });
	if (i != end(_state.testConnections)) {
		i->mtproxyLease.release();
		_state.testConnections.erase(i);
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
	if (found != end(_state.testConnections)) {
		if (!EmptySessionProxyEndpoint(found->mtproxyEndpoint)) {
			_owner->_proxyPort->reportConnectionError(
				proxyAttempt(*found),
				errorCode,
				&found->mtproxyLease);
		}
	} else if (_state.connection.get() == connection.get()
		&& !EmptySessionProxyEndpoint(_state.mtproxyEndpoint)) {
		_owner->_proxyPort->reportConnectionError(
			currentProxyAttempt(),
			errorCode,
			nullptr,
			true);
	}
	removeTestConnection(connection);

	if (_state.testConnections.empty() && _state.brokerTickets.empty()) {
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
