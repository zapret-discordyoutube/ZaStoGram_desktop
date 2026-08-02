/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "mtproto/proxy/transport_policy.h"

#include "mtproto/proxy/capabilities.h"
#include "mtproto/proxy/diagnostics.h"
#include "mtproto/proxy/proxy_services.h"
#include "mtproto/proxy/wss/socket.h"
#include "mtproto/runtime/runtime_environment.h"

#include <QtCore/QMutex>
#include <QtCore/QSet>
#include <QtNetwork/QHostAddress>

#include <utility>

namespace MTP {
namespace {

constexpr auto kDefaultTelegramProxyPort = 1353;
constexpr auto kWssRemoteClosedTtl = crl::time(30 * 60 * 1000);
QMutex TransportFallbackLogMutex;
QSet<QString> transportFallbackLogged;

[[nodiscard]] QString NormalizedProxyHost(QString host) {
	host = host.trimmed();
	if (host.startsWith('[') && host.endsWith(']')) {
		host = host.mid(1, host.size() - 2);
	}
	return host.toLower();
}

[[nodiscard]] bool IsLocalHost(const QString &host) {
	const auto normalized = NormalizedProxyHost(host);
	if (normalized.isEmpty()) {
		return false;
	} else if (normalized == u"localhost"_q
		|| normalized == u"localhost."_q) {
		return true;
	}
	const auto address = QHostAddress(normalized);
	auto ok = false;
	const auto ipv4 = address.toIPv4Address(&ok);
	if (ok) {
		return (ipv4 >> 24) == 127;
	}
	return address == QHostAddress(QHostAddress::LocalHostIPv6);
}

[[nodiscard]] bool IsLocalProxyEndpoint(const ProxyData &proxy) {
	return IsLocalHost(proxy.host)
		|| IsLocalHost(proxy.originalHost)
		|| proxy.port == kDefaultTelegramProxyPort;
}

[[nodiscard]] ProxyStealthOptions BoringMtproxyStealthOptions(
		ProxyStealthOptions result) {
	// Everything that shapes the flow - fragmentation, pacing, record
	// sizing - is off for an mtproxy, but the ClientHello template itself
	// stays the one the user picked. Overriding it here made the whole
	// profile selector a no-op, since an mtproxy is the only proxy type
	// that sends a ClientHello at all.
	const auto profile = result.tlsProfile;
	result = CompatStrictProxyStealthOptions(std::move(result));
	result.tlsProfile = profile;
	return result;
}

void LogTransportFallback(
		not_null<RuntimeEnvironment*> runtime,
		const ProxyData &proxy,
		ProxyTransport saved,
		ProxyTransport effective,
		const QString &reason) {
	if (!proxy || saved == effective) {
		return;
	}
	const auto proxyKeyHash = ProxyDiagnosticsProxyKeyHash(proxy);
	const auto key = proxyKeyHash
		+ ':' + QString::number(int(saved))
		+ ':' + QString::number(int(effective))
		+ ':' + reason;
	{
		QMutexLocker lock(&TransportFallbackLogMutex);
		if (transportFallbackLogged.contains(key)) {
			return;
		}
		transportFallbackLogged.insert(key);
	}
	WriteProxyDiagnosticsLine(runtime, {
		.source = (proxy.type == ProxyData::Type::Mtproto)
			? ProxyDiagnosticsSource::MTProxy
			: ProxyDiagnosticsSource::Network,
		.phase = ProxyDiagnosticsPhase::TransportFallbackApplied,
		.severity = ProxyDiagnosticsSeverity::Warning,
		.proxy = proxy,
		.transport = ProxyDiagnosticsTransportName(proxy, effective),
		.message = u"proxy transport fallback applied"_q,
		.canonical = ProxyDiagnosticsEndpointText(
			proxy.originalHost.isEmpty() ? proxy.host : proxy.originalHost,
			proxy.port),
		.route = ProxyDiagnosticsEndpointText(proxy.host, proxy.port),
		.proxyKeyHash = proxyKeyHash,
		.phaseAtFailure = reason,
	});
}

} // namespace

bool ProxyWssAllowed(
		not_null<RuntimeEnvironment*> runtime,
		const ProxyData &proxy,
		ProxyData::Settings settings) {
	if (settings != ProxyData::Settings::Enabled
		|| proxy.type == ProxyData::Type::None) {
		return true;
	} else if (proxy.type != ProxyData::Type::Socks5) {
		return false;
	} else if (IsLocalProxyEndpoint(proxy)
		|| !runtime->proxyServices().capabilities().wssAllowed(proxy)) {
		return false;
	}
	return true;
}

bool ProxyWssAllowed(
		const ProxyData &proxy,
		ProxyData::Settings settings) {
	return ProxyWssAllowed(DefaultRuntimeEnvironment(), proxy, settings);
}

void NoteProxyWssRemoteClosed(
		not_null<RuntimeEnvironment*> runtime,
		const ProxyData &proxy) {
	if (!proxy) {
		return;
	}
	runtime->proxyServices().capabilities().noteWssRemoteClosed(
		proxy,
		kWssRemoteClosedTtl);
}

ProxyTransport EffectiveProxyTransport(
		not_null<RuntimeEnvironment*> runtime,
		const ProxyData &proxy,
		ProxyData::Settings settings,
		ProxyTransport saved) {
	const auto effective = ProxyWssAllowed(runtime, proxy, settings)
		? saved
		: ProxyTransport::Tcp;
	// A socks5 relay is the only one that can carry WSS at all, so for every
	// other proxy type this is not a fallback that happened - it is a
	// transport that was never on the table. Warning about it on every
	// switch to every mtproxy made the log read like the connection had
	// degraded when nothing had.
	if (saved == ProxyTransport::Wss
		&& effective != saved
		&& proxy.type == ProxyData::Type::Socks5) {
		LogTransportFallback(
			runtime,
			proxy,
			saved,
			effective,
			u"wss_not_allowed"_q);
	}
	return effective;
}

ProxyTransport EffectiveProxyTransport(
		const ProxyData &proxy,
		ProxyData::Settings settings,
		ProxyTransport saved) {
	return EffectiveProxyTransport(
		DefaultRuntimeEnvironment(),
		proxy,
		settings,
		saved);
}

ProxyStealthOptions EffectiveProxyStealthOptions(
		not_null<RuntimeEnvironment*> runtime,
		const ProxyData &proxy,
		ProxyData::Settings settings,
		ProxyStealthOptions saved) {
	auto result = saved;
	result.transport = EffectiveProxyTransport(
		runtime,
		proxy,
		settings,
		result.transport);
	if (settings == ProxyData::Settings::Enabled
		&& proxy.type == ProxyData::Type::Mtproto) {
		result.transport = ProxyTransport::Tcp;
		return BoringMtproxyStealthOptions(std::move(result));
	}
	if (settings == ProxyData::Settings::Enabled
		&& (IsLocalProxyEndpoint(proxy)
			|| !ProxyWssAllowed(runtime, proxy, settings))) {
		return CompatStrictProxyStealthOptions(std::move(result));
	}
	return result;
}

ProxyStealthOptions EffectiveProxyStealthOptions(
		const ProxyData &proxy,
		ProxyData::Settings settings,
		ProxyStealthOptions saved) {
	return EffectiveProxyStealthOptions(
		DefaultRuntimeEnvironment(),
		proxy,
		settings,
		std::move(saved));
}

WssDcCoverage WssDcCoverageForDc(
		const ProxyStealthOptions &stealth,
		int16 protocolDcId) {
	if (details::WssCustomRoute(stealth)) {
		return WssDcCoverage::Custom;
	} else if (details::WssOfficialRoute(protocolDcId)) {
		return WssDcCoverage::Official;
	}
	return WssDcCoverage::Unavailable;
}

bool WssNeedsProxyRecommendation(
		const ProxyData &proxy,
		const ProxyStealthOptions &stealth,
		int16 protocolDcId) {
	return proxy.type == ProxyData::Type::None
		&& stealth.transport == ProxyTransport::Wss
		&& (WssDcCoverageForDc(
			stealth,
			protocolDcId) == WssDcCoverage::Unavailable);
}

} // namespace MTP
