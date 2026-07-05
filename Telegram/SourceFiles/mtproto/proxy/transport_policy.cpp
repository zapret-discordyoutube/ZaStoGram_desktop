/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "mtproto/proxy/transport_policy.h"

#include "mtproto/proxy/capabilities.h"
#include "mtproto/proxy/diagnostics.h"
#include "mtproto/proxy/wss/socket.h"

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

void LogTransportFallback(
		const ProxyData &proxy,
		ProxyTransport saved,
		ProxyTransport effective,
		const QString &reason) {
	if (!proxy || saved == effective) {
		return;
	}
	const auto proxyKeyHash = ProxyDiagnosticsKeyHash(
		QString::number(int(proxy.type))
		+ ':' + (proxy.originalHost.isEmpty() ? proxy.host : proxy.originalHost)
		+ u":%1:"_q.arg(proxy.port)
		+ proxy.password);
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
	WriteProxyDiagnosticsLine({
		.source = (proxy.type == ProxyData::Type::Mtproto)
			? ProxyDiagnosticsSource::MTProxy
			: ProxyDiagnosticsSource::Network,
		.phase = ProxyDiagnosticsPhase::TransportFallbackApplied,
		.severity = ProxyDiagnosticsSeverity::Warning,
		.proxy = proxy,
		.transport = ProxyDiagnosticsTransportName(proxy.type, effective),
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
		const ProxyData &proxy,
		ProxyData::Settings settings) {
	if (settings != ProxyData::Settings::Enabled
		|| proxy.type == ProxyData::Type::None) {
		return true;
	} else if (proxy.type != ProxyData::Type::Socks5) {
		return false;
	} else if (IsLocalProxyEndpoint(proxy)
		|| !ProxyCapabilityCache::Instance().wssAllowed(proxy)) {
		return false;
	}
	return true;
}

void NoteProxyWssRemoteClosed(const ProxyData &proxy) {
	if (!proxy) {
		return;
	}
	ProxyCapabilityCache::Instance().noteWssRemoteClosed(
		proxy,
		kWssRemoteClosedTtl);
}

ProxyTransport EffectiveProxyTransport(
		const ProxyData &proxy,
		ProxyData::Settings settings,
		ProxyTransport saved) {
	const auto effective = ProxyWssAllowed(proxy, settings)
		? saved
		: ProxyTransport::Tcp;
	if (saved == ProxyTransport::Wss && effective != saved) {
		LogTransportFallback(
			proxy,
			saved,
			effective,
			u"wss_not_allowed"_q);
	}
	return effective;
}

ProxyStealthOptions EffectiveProxyStealthOptions(
		const ProxyData &proxy,
		ProxyData::Settings settings,
		ProxyStealthOptions saved) {
	auto result = saved;
	result.transport = EffectiveProxyTransport(
		proxy,
		settings,
		result.transport);
	if (settings == ProxyData::Settings::Enabled
		&& proxy.type == ProxyData::Type::Mtproto) {
		result.transport = ProxyTransport::Tcp;
		const auto capability = ProxyCapabilityCache::Instance().lookup(proxy);
		if (capability.lastGoodTransport
				== ProxyCapabilityTransport::MtproxyFakeTlsTcp
			&& capability.lastGoodProfile != ProxyTlsProfile::Auto) {
			result = CompatStrictProxyStealthOptions(std::move(result));
			result.tlsProfile = capability.lastGoodProfile;
			return result;
		}
		return CompatStrictProxyStealthOptions(std::move(result));
	}
	if (settings == ProxyData::Settings::Enabled
		&& (IsLocalProxyEndpoint(proxy)
			|| !ProxyWssAllowed(proxy, settings))) {
		return CompatStrictProxyStealthOptions(std::move(result));
	}
	return result;
}

WssDcCoverage WssDcCoverageForDc(
		const ProxyStealthOptions &stealth,
		int16 protocolDcId,
		bool protocolForFiles) {
	if (details::WssCustomRoute(stealth)) {
		return WssDcCoverage::Custom;
	} else if (details::WssOfficialRoute(protocolDcId, protocolForFiles)) {
		return WssDcCoverage::Official;
	}
	return WssDcCoverage::Unavailable;
}

bool WssNeedsProxyRecommendation(
		const ProxyData &proxy,
		const ProxyStealthOptions &stealth,
		int16 protocolDcId,
		bool protocolForFiles) {
	return proxy.type == ProxyData::Type::None
		&& stealth.transport == ProxyTransport::Wss
		&& (WssDcCoverageForDc(
			stealth,
			protocolDcId,
			protocolForFiles) == WssDcCoverage::Unavailable);
}

} // namespace MTP
