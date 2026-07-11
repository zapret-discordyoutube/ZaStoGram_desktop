/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#pragma once

#include "base/basic_types.h"
#include "mtproto/runtime/connection_status_types.h"

#include <memory>
#include <vector>

namespace MTP {

namespace details::MtProxy {
struct EndpointContextStorage;
} // namespace details::MtProxy

using AdmissionReleaseListenerId = uint64;

class ProxyEndpointContext final {
public:
	ProxyEndpointContext();
	ProxyEndpointContext(const ProxyEndpointContext &other) = delete;
	ProxyEndpointContext &operator=(const ProxyEndpointContext &other) = delete;
	~ProxyEndpointContext();

	[[nodiscard]] ProxyRuntimeId registerRuntime();
	void unregisterRuntime(ProxyRuntimeId runtimeId);
	[[nodiscard]] ProxyTraceId nextTraceId(
		ProxyConnectionAttempt attempt = {});
	void updateTraceAttempt(const ProxyConnectionAttempt &attempt);
	[[nodiscard]] bool traceActive(ProxyTraceId traceId) const;
	[[nodiscard]] auto activeTracesForRuntime(
		ProxyRuntimeId runtimeId) const
		-> std::vector<ProxyConnectionAttempt>;
	[[nodiscard]] bool finishTrace(ProxyTraceId traceId);
	void releaseEndpointAttempt(const QString &key, uint64 attemptId);
	void releaseAdmissionForRelayCandidate(
		const QString &key,
		ProxyRuntimeId runtimeId,
		uint64 proxyGeneration,
		uint64 attemptId);

	// Invoked (strictly after the storage mutex unlocks, on the caller's
	// thread) whenever an endpoint may newly admit a queued request - either
	// a slot freed (releaseEndpointAttempt / releaseAdmissionForRelayCandidate)
	// or its penalty was cleared early by a relay success / manual selection
	// (notifyEndpointAdmissible). The listener just re-drains that endpoint.
	[[nodiscard]] AdmissionReleaseListenerId addAdmissionReleaseListener(
		Fn<void(const QString &endpointKey)> callback);
	void removeAdmissionReleaseListener(AdmissionReleaseListenerId id);
	void notifyEndpointAdmissible(const QString &key);

	[[nodiscard]] auto storage()
		-> details::MtProxy::EndpointContextStorage &;
	[[nodiscard]] auto storage() const
		-> const details::MtProxy::EndpointContextStorage &;

private:
	const std::unique_ptr<details::MtProxy::EndpointContextStorage> _storage;

};

[[nodiscard]] auto CreateProxyEndpointContext()
	-> std::shared_ptr<ProxyEndpointContext>;

} // namespace MTP
