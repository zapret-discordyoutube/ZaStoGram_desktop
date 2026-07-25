/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#pragma once

#include "base/basic_types.h"
#include "mtproto/proxy/status.h"

#include <map>

namespace MTP {

struct ProxyEventReport;
class RuntimeEnvironment;

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
	explicit ProxyControlPlane(not_null<RuntimeEnvironment*> runtime);

	void submitFact(const ProxyEventReport &report);
	[[nodiscard]] ProxyConnectionStatus selectedStatus() const;
	[[nodiscard]] ProxyEndpointSnapshot endpointSnapshot() const;

	[[nodiscard]] static ProxyFact FactFromReport(
		const ProxyEventReport &report);
	[[nodiscard]] static ProxyConnectionStatus Reduce(
		const ProxyConnectionStatus &current,
		ProxyFact fact);

private:
	struct MainNetworkFact final {
		ProxyConnectionStatus status;
		crl::time phaseStartedAt = 0;
	};

	void submitFactOnOwner(ProxyFact fact);

	const not_null<RuntimeEnvironment*> _runtime;
	ProxyConnectionStatus _selectedStatus;
	ProxyEndpointSnapshot _endpointSnapshot;
	std::map<QString, MainNetworkFact> _mainNetworkFacts;

};

} // namespace MTP
