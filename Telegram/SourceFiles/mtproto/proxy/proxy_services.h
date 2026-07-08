/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#pragma once

#include "base/basic_types.h"
#include "mtproto/proxy/connection_broker.h"
#include "mtproto/proxy/control_plane.h"
#include "mtproto/proxy/dns_resolver_cache.h"
#include "mtproto/proxy/mtproxy/endpoint_health.h"

namespace MTP {

class RuntimeEnvironment;

class ProxyServices final {
public:
	explicit ProxyServices(not_null<RuntimeEnvironment*> runtime);

	[[nodiscard]] ProxyControlPlane &control();
	[[nodiscard]] details::ConnectionBroker &broker();
	[[nodiscard]] details::DnsResolverCache &dnsResolver();

private:
	details::MtProxy::EndpointHealth _endpointHealth;
	ProxyControlPlane _control;
	details::ConnectionBroker _broker;
	details::DnsResolverCache _dnsResolver;
};

} // namespace MTP
