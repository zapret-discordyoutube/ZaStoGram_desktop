/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "mtproto/proxy/proxy_services.h"

#include "mtproto/runtime/runtime_environment.h"

namespace MTP {

ProxyServices::ProxyServices(not_null<RuntimeEnvironment*> runtime)
: _endpointHealth(runtime, runtime->proxyEndpointContextShared())
, _capabilities(runtime->proxyCapabilities().path)
, _control(runtime, &_endpointHealth)
, _broker(runtime)
, _dnsResolver(runtime) {
}

ProxyControlPlane &ProxyServices::control() {
	return _control;
}

details::ConnectionBroker &ProxyServices::broker() {
	return _broker;
}

details::DnsResolverCache &ProxyServices::dnsResolver() {
	return _dnsResolver;
}

ProxyCapabilityCache &ProxyServices::capabilities() {
	return _capabilities;
}

details::SyntheticPskCache &ProxyServices::syntheticPsks() {
	return _syntheticPsks;
}

} // namespace MTP
