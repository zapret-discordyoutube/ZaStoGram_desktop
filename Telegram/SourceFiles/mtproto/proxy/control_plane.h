/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#pragma once

#include "base/basic_types.h"
#include "mtproto/proxy/mtproxy/endpoint_health.h"
#include "mtproto/proxy/status.h"

#include <rpl/event_stream.h>

#include <map>

namespace MTP {

struct ProxyEventReport;
class RuntimeEnvironment;
namespace details::MtProxy {
class EndpointHealth;
} // namespace details::MtProxy

enum class ProxyControlPlaneSuccessScope {
	None,
	Handshake,
	Relay,
};

struct ProxyFact {
	ProxyConnectionStatus status;
	ProxyControlPlaneSuccessScope successScope
		= ProxyControlPlaneSuccessScope::None;
};

struct ProxyEndpointSnapshot {
	ProxyData proxy;
	ProxyConnectionStatus status;
	bool relayProven = false;
};

class ProxyControlPlane final {
public:
	explicit ProxyControlPlane(
		not_null<RuntimeEnvironment*> runtime,
		not_null<details::MtProxy::EndpointHealth*> endpointHealth);

	void submitFact(const ProxyEventReport &report);
	[[nodiscard]] ProxyConnectionStatus selectedStatus() const;
	[[nodiscard]] ProxyEndpointSnapshot endpointSnapshot() const;

	[[nodiscard]] static ProxyFact FactFromReport(
		const ProxyEventReport &report);
	[[nodiscard]] static ProxyConnectionStatus Reduce(
		const ProxyConnectionStatus &current,
		ProxyFact fact);
	void reportMtproxyFailure(
		details::MtProxy::FailureReport report);
	void reportMtproxySuccess(
		details::MtProxy::SuccessReport report);
	void noteMtproxyRelayStall(
		details::MtProxy::RelayProofReport report);
	void retireMtproxyRelayProof(
		details::MtProxy::RelayProofReport report);
	void noteMtproxyEndpointSelected(
		const details::MtProxy::EndpointId &endpoint);
	void applyMtproxyProxyGeneration(uint64 proxyGeneration);
	[[nodiscard]] details::MtProxy::ProxyEndpointView mtproxyEndpointView(
		const details::MtProxy::EndpointId &endpoint) const;
	[[nodiscard]] auto mtproxyEndpointViewChanges()
	-> rpl::producer<details::MtProxy::ProxyEndpointView>;
	[[nodiscard]] crl::time mtproxyEndpointRetryUntil(
		const details::MtProxy::EndpointId &endpoint,
		RuntimeGenerationKey runtimeGeneration) const;

private:
	struct MainNetworkFact final {
		ProxyConnectionStatus status;
		crl::time phaseStartedAt = 0;
	};

	void invalidateMtproxyEndpointView(
		const details::MtProxy::EndpointId &endpoint);
	void flushMtproxyEndpointViews();
	void updateSelectedMtproxyProjection(
		const details::MtProxy::ProxyEndpointView &view);
	void submitFactOnOwner(ProxyFact fact);

	const not_null<RuntimeEnvironment*> _runtime;
	const not_null<details::MtProxy::EndpointHealth*> _endpointHealth;
	ProxyConnectionStatus _selectedStatus;
	ProxyEndpointSnapshot _endpointSnapshot;
	details::MtProxy::EndpointId _selectedMtproxyEndpoint;
	uint64 _mtproxyProxyGeneration = 0;
	std::map<QString, MainNetworkFact> _mainNetworkFacts;
	std::map<QString, details::MtProxy::EndpointId> _pendingEndpointViews;
	bool _endpointViewFlushScheduled : 1 = false;
	rpl::event_stream<details::MtProxy::ProxyEndpointView> _endpointViewEvents;
	rpl::lifetime _endpointViewLifetime;

};

} // namespace MTP
