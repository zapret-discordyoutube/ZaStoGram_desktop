/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#pragma once

#include "base/bytes.h"
#include "mtproto/runtime/connection_status_types.h"
#include "mtproto/runtime/proxy_endpoint.h"

namespace MTP::details::MtProxy {

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
