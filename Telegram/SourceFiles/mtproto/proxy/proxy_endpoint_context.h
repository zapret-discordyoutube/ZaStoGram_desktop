/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#pragma once

#include "mtproto/runtime/connection_status_types.h"

#include <memory>
#include <vector>

namespace MTP {

namespace details::MtProxy {
struct EndpointContextStorage;
} // namespace details::MtProxy

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
