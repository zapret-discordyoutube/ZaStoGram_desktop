/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#pragma once

#include "base/bytes.h"
#include "mtproto/proxy/data.h"
#include "mtproto/proxy/status.h"

namespace MTP::details::MtProxy {

enum class RouteAddressFamily {
	Unknown,
	Host,
	IPv4,
	IPv6,
};

struct CanonicalProxyEndpoint {
	ProxyData::Type type = ProxyData::Type::None;
	QString originalHost;
	int port = 0;
	QString secretHash;
	QString domainFromSecret;
	ProxyData::Type proxyKind = ProxyData::Type::None;

	bool operator==(const CanonicalProxyEndpoint &other) const {
		return (type == other.type)
			&& (originalHost == other.originalHost)
			&& (port == other.port)
			&& (secretHash == other.secretHash)
			&& (domainFromSecret == other.domainFromSecret)
			&& (proxyKind == other.proxyKind);
	}
};

struct RouteEndpoint {
	QString address;
	int port = 0;
	RouteAddressFamily addressFamily = RouteAddressFamily::Unknown;
	ProxyTransport transport = ProxyTransport::Tcp;
	QString resolvedFromHost;

	bool operator==(const RouteEndpoint &other) const {
		return (address == other.address)
			&& (port == other.port)
			&& (addressFamily == other.addressFamily)
			&& (transport == other.transport)
			&& (resolvedFromHost == other.resolvedFromHost);
	}
};

struct EndpointId {
	CanonicalProxyEndpoint canonical;
	RouteEndpoint route;

	bool operator==(const EndpointId &other) const {
		return (canonical == other.canonical)
			&& (route == other.route);
	}
};

[[nodiscard]] EndpointId EndpointIdFromProxy(
	const ProxyData &proxy,
	const ProxyStealthOptions &stealth,
	const QString &address = QString(),
	int port = 0);
[[nodiscard]] EndpointId EndpointIdFromAddress(
	const QString &address,
	int port,
	bytes::const_span secret,
	ProxyTransport transport);
[[nodiscard]] RouteEndpoint RouteEndpointFromAddress(
	const QString &address,
	int port,
	ProxyTransport transport,
	const QString &resolvedFromHost = QString());
[[nodiscard]] bool EndpointEmpty(const CanonicalProxyEndpoint &endpoint);
[[nodiscard]] bool EndpointEmpty(const EndpointId &endpoint);
[[nodiscard]] QString EndpointKey(const CanonicalProxyEndpoint &endpoint);
[[nodiscard]] QString EndpointKey(const EndpointId &endpoint);
[[nodiscard]] QString CapabilityProxyKey(const CanonicalProxyEndpoint &endpoint);
[[nodiscard]] QString RouteKey(const RouteEndpoint &route);
[[nodiscard]] QString RouteKey(const EndpointId &endpoint);
[[nodiscard]] QString ToLegacyDiagnostic(FailureReason reason);
[[nodiscard]] FailureReason FailureReasonFromErrorCode(int errorCode);
[[nodiscard]] ProxyConnectionError ToProxyConnectionError(
	FailureReason reason);
[[nodiscard]] ProxyMtproxyTerminalReason ToProxyMtproxyTerminalReason(
	FailureReason reason);

} // namespace MTP::details::MtProxy
