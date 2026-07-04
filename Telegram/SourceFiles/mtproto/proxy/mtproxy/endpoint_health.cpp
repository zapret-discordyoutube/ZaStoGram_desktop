/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "mtproto/proxy/mtproxy/endpoint_health.h"

#include "mtproto/connection_abstract.h"
#include "mtproto/proxy/mtproxy/adaptive_policy.h"
#include "base/algorithm.h"
#include "base/timer.h"

#include <QtCore/QCryptographicHash>
#include <QtCore/QMutex>
#include <QtNetwork/QAbstractSocket>
#include <rpl/event_stream.h>

#include <map>

namespace MTP::details::MtProxy {
namespace {

constexpr auto kFirstCooldown = crl::time(15 * 1000);
constexpr auto kSecondCooldown = crl::time(45 * 1000);
constexpr auto kMaxCooldown = crl::time(120 * 1000);
constexpr auto kDnsNegativeTtl = crl::time(30 * 1000);
constexpr auto kColdActiveCap = 1;
constexpr auto kHealthyActiveCap = 2;

struct EndpointState {
	EndpointId endpoint;
	FailureReason lastFailure = FailureReason::None;
	QString lastDiagnostic;
	crl::time terminalUntil = 0;
	int active = 0;
	int consecutiveFailures = 0;
	int recipeLevel = 0;
	bool healthy = false;
	bool halfOpen = false;
	uint64 proxyEpoch = 1;
	uint64 lastAttemptId = 0;
};

QMutex StatesMutex;
std::map<QString, EndpointState> States;
rpl::event_stream<EndpointEvent> Events;

[[nodiscard]] QByteArray BytesToQByteArray(bytes::const_span data) {
	auto result = QByteArray();
	result.reserve(int(data.size()));
	for (const auto byte : data) {
		result.append(char(gsl::to_integer<unsigned char>(byte)));
	}
	return result;
}

[[nodiscard]] QString HashBytes(bytes::const_span data) {
	const auto hash = QCryptographicHash::hash(
		BytesToQByteArray(data),
		QCryptographicHash::Sha256);
	return QString::fromLatin1(hash.toHex());
}

[[nodiscard]] QString HashText(const QString &text) {
	const auto hash = QCryptographicHash::hash(
		text.toUtf8(),
		QCryptographicHash::Sha256);
	return QString::fromLatin1(hash.toHex());
}

[[nodiscard]] QString DomainFromSecret(bytes::const_span secret) {
	if (secret.size() <= 17) {
		return QString();
	}
	return QString::fromUtf8(BytesToQByteArray(secret.subspan(17)));
}

[[nodiscard]] bool FailureNeedsCooldown(FailureReason reason) {
	switch (reason) {
	case FailureReason::NoServerHelloAfterClientHello:
	case FailureReason::TlsAlertAfterClientHello:
	case FailureReason::ShortTlsResponseAfterClientHello:
	case FailureReason::UnrecognizedTlsResponseAfterClientHello:
	case FailureReason::ServerHelloHmacMismatch:
	case FailureReason::PostHandshakeNoAppData:
	case FailureReason::DnsHostNotFound:
	case FailureReason::Timeout:
		return true;
	case FailureReason::None:
	case FailureReason::TcpNotConnected:
	case FailureReason::RemoteClosed:
	case FailureReason::Network:
	case FailureReason::BadResponse:
		return false;
	}
	return false;
}

[[nodiscard]] crl::time CooldownFor(
		FailureReason reason,
		int consecutiveFailures) {
	if (reason == FailureReason::DnsHostNotFound) {
		return kDnsNegativeTtl;
	}
	if (consecutiveFailures <= 1) {
		return kFirstCooldown;
	} else if (consecutiveFailures == 2) {
		return kSecondCooldown;
	}
	return kMaxCooldown;
}

[[nodiscard]] int ActiveCap(const EndpointState &state) {
	return state.healthy ? kHealthyActiveCap : kColdActiveCap;
}

[[nodiscard]] bool IsInteractive(EndpointUse use) {
	return use == EndpointUse::Main || use == EndpointUse::ProxyCheck;
}

[[nodiscard]] Snapshot MakeSnapshot(const EndpointState &state) {
	return {
		.endpoint = state.endpoint,
		.lastFailure = state.lastFailure,
		.lastDiagnostic = state.lastDiagnostic,
		.terminalUntil = state.terminalUntil,
		.active = state.active,
		.consecutiveFailures = state.consecutiveFailures,
		.recipeLevel = state.recipeLevel,
		.healthy = state.healthy,
		.halfOpen = state.halfOpen,
		.proxyEpoch = state.proxyEpoch,
		.attemptId = state.lastAttemptId,
	};
}

} // namespace

EndpointAttemptLease::EndpointAttemptLease(
	QString key,
	uint64 attemptId,
	uint64 proxyEpoch)
: _key(std::move(key))
, _attemptId(attemptId)
, _proxyEpoch(proxyEpoch)
, _active(true) {
}

EndpointAttemptLease::EndpointAttemptLease(
		EndpointAttemptLease &&other) noexcept
: _key(std::move(other._key))
, _attemptId(base::take(other._attemptId))
, _proxyEpoch(base::take(other._proxyEpoch))
, _active(base::take(other._active)) {
}

EndpointAttemptLease &EndpointAttemptLease::operator=(
		EndpointAttemptLease &&other) noexcept {
	if (this != &other) {
		release();
		_key = std::move(other._key);
		_attemptId = base::take(other._attemptId);
		_proxyEpoch = base::take(other._proxyEpoch);
		_active = base::take(other._active);
	}
	return *this;
}

EndpointAttemptLease::~EndpointAttemptLease() {
	release();
}

crl::time ConnectionSpacing(ProxyConnectionPattern pattern) {
	switch (pattern) {
	case ProxyConnectionPattern::Soft: return crl::time(150);
	case ProxyConnectionPattern::Quiet: return crl::time(400);
	case ProxyConnectionPattern::Strict: return crl::time(700);
	case ProxyConnectionPattern::Browser: return crl::time(250);
	case ProxyConnectionPattern::Off: break;
	}
	return crl::time(0);
}

void EndpointAttemptLease::release() {
	if (!_active) {
		return;
	}
	_active = false;
	EndpointHealth::Instance().releaseAttempt(_key, _attemptId);
}

bool EndpointAttemptLease::active() const {
	return _active;
}

uint64 EndpointAttemptLease::attemptId() const {
	return _attemptId;
}

uint64 EndpointAttemptLease::proxyEpoch() const {
	return _proxyEpoch;
}

EndpointHealth &EndpointHealth::Instance() {
	static auto result = EndpointHealth();
	return result;
}

Admission EndpointHealth::admit(const AdmissionRequest &request) {
	const auto key = EndpointKey(request.endpoint);
	const auto now = crl::now();
	QMutexLocker lock(&StatesMutex);
	auto &state = States[key];
	state.endpoint = request.endpoint;
	auto result = Admission();
	result.stealth = request.stealth;
	result.effectiveTlsProfile = ResolveEffectiveTlsProfile(
		request.configuredTlsProfile,
		key);
	result.proxyEpoch = state.proxyEpoch;
	if (state.terminalUntil > now) {
		result.action = IsInteractive(request.use)
			? AdmissionAction::StartAfter
			: AdmissionAction::SkipCooldown;
		result.retryAfter = state.terminalUntil - now;
		result.blockedBy = state.lastFailure;
		return result;
	}
	if (state.halfOpen && !IsInteractive(request.use)) {
		result.action = AdmissionAction::SkipCooldown;
		result.blockedBy = state.lastFailure;
		return result;
	}
	const auto cap = (state.halfOpen || !state.healthy)
		? kColdActiveCap
		: ActiveCap(state);
	if (state.active >= cap) {
		result.action = IsInteractive(request.use)
			? AdmissionAction::StartAfter
			: AdmissionAction::SkipCooldown;
		result.retryAfter = crl::time(1000);
		result.blockedBy = state.lastFailure;
		return result;
	}
	++state.active;
	result.attemptId = ++state.lastAttemptId;
	result.proxyEpoch = state.proxyEpoch;
	result.lease = EndpointAttemptLease(key, result.attemptId, state.proxyEpoch);
	return result;
}

void EndpointHealth::reportFailure(FailureReport report) {
	if (report.lease) {
		report.lease->release();
	}
	if (report.reason == FailureReason::None) {
		return;
	}
	const auto key = EndpointKey(report.endpoint);
	const auto diagnostic = ToLegacyDiagnostic(report.reason);
	const auto now = crl::now();
	auto event = EndpointEvent();
	QMutexLocker lock(&StatesMutex);
	auto &state = States[key];
	state.endpoint = report.endpoint;
	state.lastFailure = report.reason;
	state.lastDiagnostic = diagnostic;
	if (FailureNeedsRecipe(diagnostic) && state.recipeLevel < 4) {
		++state.recipeLevel;
	}
	if (report.configuredTlsProfile == ProxyTlsProfile::AutoRotate) {
		(void)RotateTlsProfileOnFailure(
			key,
			diagnostic,
			report.sentProfile);
	}
	if (FailureNeedsCooldown(report.reason)) {
		++state.consecutiveFailures;
		state.healthy = false;
		state.halfOpen = true;
		state.terminalUntil = now + CooldownFor(
			report.reason,
			state.consecutiveFailures);
	}
	event = {
		.endpoint = state.endpoint,
		.reason = state.lastFailure,
		.terminalUntil = state.terminalUntil,
		.rotationAllowed = FailureNeedsCooldown(report.reason),
	};
	lock.unlock();
	Events.fire(std::move(event));
}

void EndpointHealth::reportSuccess(SuccessReport report) {
	if (report.lease) {
		report.lease->release();
	}
	const auto key = EndpointKey(report.endpoint);
	QMutexLocker lock(&StatesMutex);
	auto &state = States[key];
	state.endpoint = report.endpoint;
	state.lastFailure = FailureReason::None;
	state.lastDiagnostic.clear();
	state.terminalUntil = 0;
	state.consecutiveFailures = 0;
	state.recipeLevel = 0;
	state.healthy = true;
	state.halfOpen = false;
}

Snapshot EndpointHealth::snapshot(const EndpointId &endpoint) const {
	const auto key = EndpointKey(endpoint);
	QMutexLocker lock(&StatesMutex);
	const auto i = States.find(key);
	if (i != end(States)) {
		return MakeSnapshot(i->second);
	}
	auto result = Snapshot();
	result.endpoint = endpoint;
	return result;
}

auto EndpointHealth::changes() const
-> rpl::producer<EndpointEvent> {
	return Events.events();
}

void EndpointHealth::releaseAttempt(
		const QString &key,
		uint64 attemptId) {
	QMutexLocker lock(&StatesMutex);
	const auto i = States.find(key);
	if (i == end(States) || !attemptId || i->second.active <= 0) {
		return;
	}
	--i->second.active;
}

EndpointId EndpointIdFromProxy(
		const ProxyData &proxy,
		const ProxyStealthOptions &stealth,
		const QString &address,
		int port) {
	auto result = EndpointId();
	result.host = address.isEmpty() ? proxy.host : address;
	result.port = port ? port : int(proxy.port);
	result.transport = stealth.transport;
	if (proxy.type == ProxyData::Type::Mtproto) {
		const auto secret = proxy.secretFromMtprotoPassword();
		if (!secret.empty()) {
			result.secretHash = HashBytes(secret);
			result.domain = DomainFromSecret(secret);
			return result;
		}
	}
	result.secretHash = HashText(proxy.password);
	return result;
}

EndpointId EndpointIdFromAddress(
		const QString &address,
		int port,
		bytes::const_span secret,
		ProxyTransport transport) {
	auto result = EndpointId();
	result.host = address;
	result.port = port;
	result.transport = transport;
	result.secretHash = HashBytes(secret);
	result.domain = DomainFromSecret(secret);
	return result;
}

QString EndpointKey(const EndpointId &endpoint) {
	return endpoint.host
		+ u":%1:"_q.arg(endpoint.port)
		+ QString::number(int(endpoint.transport))
		+ ':'
		+ endpoint.secretHash
		+ ':'
		+ endpoint.domain;
}

QString ToLegacyDiagnostic(FailureReason reason) {
	switch (reason) {
	case FailureReason::TcpNotConnected:
		return u"tcp_not_connected"_q;
	case FailureReason::NoServerHelloAfterClientHello:
		return u"client_hello_sent_no_server_hello"_q;
	case FailureReason::TlsAlertAfterClientHello:
		return u"tls_alert_after_client_hello"_q;
	case FailureReason::ShortTlsResponseAfterClientHello:
		return u"short_tls_response_after_client_hello"_q;
	case FailureReason::UnrecognizedTlsResponseAfterClientHello:
		return u"unrecognized_tls_response_after_client_hello"_q;
	case FailureReason::ServerHelloHmacMismatch:
		return u"server_hello_hmac_mismatch"_q;
	case FailureReason::PostHandshakeNoAppData:
		return u"post_handshake_no_appdata"_q;
	case FailureReason::DnsHostNotFound:
		return u"host_not_found"_q;
	case FailureReason::Timeout:
		return u"timeout"_q;
	case FailureReason::RemoteClosed:
		return u"remote_closed"_q;
	case FailureReason::Network:
		return u"network_error"_q;
	case FailureReason::BadResponse:
		return u"bad_response"_q;
	case FailureReason::None:
		return QString();
	}
	return QString();
}

FailureReason FailureReasonFromErrorCode(int errorCode) {
	if (errorCode == AbstractConnection::kErrorCodeOther) {
		return FailureReason::None;
	}
	switch (errorCode) {
	case QAbstractSocket::HostNotFoundError:
	case QAbstractSocket::ProxyNotFoundError:
		return FailureReason::DnsHostNotFound;
	case QAbstractSocket::SocketTimeoutError:
	case QAbstractSocket::ProxyConnectionTimeoutError:
		return FailureReason::Timeout;
	case QAbstractSocket::RemoteHostClosedError:
	case QAbstractSocket::ProxyConnectionClosedError:
		return FailureReason::RemoteClosed;
	case QAbstractSocket::NetworkError:
		return FailureReason::Network;
	}
	return FailureReason::None;
}

ProxyConnectionError ToProxyConnectionError(FailureReason reason) {
	switch (reason) {
	case FailureReason::DnsHostNotFound:
		return ProxyConnectionError::HostNotFound;
	case FailureReason::Timeout:
		return ProxyConnectionError::Timeout;
	case FailureReason::RemoteClosed:
		return ProxyConnectionError::RemoteClosed;
	case FailureReason::Network:
		return ProxyConnectionError::Network;
	case FailureReason::BadResponse:
	case FailureReason::NoServerHelloAfterClientHello:
	case FailureReason::TlsAlertAfterClientHello:
	case FailureReason::ShortTlsResponseAfterClientHello:
	case FailureReason::UnrecognizedTlsResponseAfterClientHello:
	case FailureReason::ServerHelloHmacMismatch:
	case FailureReason::PostHandshakeNoAppData:
		return ProxyConnectionError::BadResponse;
	case FailureReason::None:
	case FailureReason::TcpNotConnected:
		return ProxyConnectionError::None;
	}
	return ProxyConnectionError::Unknown;
}

ProxyMtproxyTerminalReason ToProxyMtproxyTerminalReason(
		FailureReason reason) {
	switch (reason) {
	case FailureReason::TcpNotConnected:
		return ProxyMtproxyTerminalReason::TcpNotConnected;
	case FailureReason::NoServerHelloAfterClientHello:
		return ProxyMtproxyTerminalReason::ClientHelloSentNoServerHello;
	case FailureReason::TlsAlertAfterClientHello:
		return ProxyMtproxyTerminalReason::TlsAlertAfterClientHello;
	case FailureReason::ShortTlsResponseAfterClientHello:
		return ProxyMtproxyTerminalReason::ShortTlsResponseAfterClientHello;
	case FailureReason::UnrecognizedTlsResponseAfterClientHello:
		return ProxyMtproxyTerminalReason::UnrecognizedTlsResponseAfterClientHello;
	case FailureReason::ServerHelloHmacMismatch:
		return ProxyMtproxyTerminalReason::ServerHelloHmacMismatch;
	case FailureReason::PostHandshakeNoAppData:
		return ProxyMtproxyTerminalReason::PostHandshakeNoAppData;
	case FailureReason::DnsHostNotFound:
		return ProxyMtproxyTerminalReason::DnsHostNotFound;
	case FailureReason::Timeout:
		return ProxyMtproxyTerminalReason::Timeout;
	case FailureReason::None:
	case FailureReason::RemoteClosed:
	case FailureReason::Network:
	case FailureReason::BadResponse:
		return ProxyMtproxyTerminalReason::None;
	}
	return ProxyMtproxyTerminalReason::None;
}

} // namespace MTP::details::MtProxy
