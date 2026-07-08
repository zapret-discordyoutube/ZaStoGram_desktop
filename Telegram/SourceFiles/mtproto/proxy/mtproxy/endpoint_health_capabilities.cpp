/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "mtproto/proxy/mtproxy/endpoint_health_capabilities.h"

#include "mtproto/proxy/capabilities.h"
#include "mtproto/proxy/proxy_services.h"
#include "mtproto/runtime/runtime_environment.h"

namespace MTP::details::MtProxy {

void NoteCapabilityMtproxyFailure(
		not_null<RuntimeEnvironment*> runtime,
		const EndpointId &endpoint,
		const QString &diagnostic) {
	runtime->proxyServices().capabilities().noteMtproxyFailure(
		CapabilityProxyKey(endpoint.canonical),
		RouteKey(endpoint.route),
		diagnostic);
}

void NoteCapabilityMtproxyRelayFailure(
		not_null<RuntimeEnvironment*> runtime,
		const CapabilityFailure &failure) {
	runtime->proxyServices().capabilities().noteMtproxyRelayFailure(
		failure.proxyKey,
		failure.routeKey,
		failure.diagnostic);
}

void NoteCapabilityMtproxySuccess(
		not_null<RuntimeEnvironment*> runtime,
		const CapabilitySuccess &success) {
	runtime->proxyServices().capabilities().noteMtproxySuccess(
		success.proxyKey,
		success.routeKey,
		success.route,
		success.sentProfile,
		success.stealth,
		success.recipeLevel,
		success.relayProven);
}

} // namespace MTP::details::MtProxy
