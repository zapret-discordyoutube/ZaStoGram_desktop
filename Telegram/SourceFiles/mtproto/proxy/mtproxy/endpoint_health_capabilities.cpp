/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "mtproto/proxy/mtproxy/endpoint_health_capabilities.h"

#include "mtproto/proxy/capabilities.h"

namespace MTP::details::MtProxy {

void NoteCapabilityMtproxyFailure(
		const EndpointId &endpoint,
		const QString &diagnostic) {
	ProxyCapabilityCache::Instance().noteMtproxyFailure(
		CapabilityProxyKey(endpoint.canonical),
		RouteKey(endpoint.route),
		diagnostic);
}

void NoteCapabilityMtproxyRelayFailure(const CapabilityFailure &failure) {
	ProxyCapabilityCache::Instance().noteMtproxyRelayFailure(
		failure.proxyKey,
		failure.routeKey,
		failure.diagnostic);
}

void NoteCapabilityMtproxySuccess(const CapabilitySuccess &success) {
	ProxyCapabilityCache::Instance().noteMtproxySuccess(
		success.proxyKey,
		success.routeKey,
		success.route,
		success.sentProfile,
		success.stealth,
		success.recipeLevel,
		success.relayProven);
}

} // namespace MTP::details::MtProxy
