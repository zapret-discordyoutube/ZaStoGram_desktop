/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#pragma once

#include "base/basic_types.h"
#include "mtproto/proxy/mtproxy/endpoint_health.h"

#include <memory>
#include <vector>

namespace MTP::details::MtProxy {
struct EndpointContextStorage;

struct EndpointViewInvalidation final {
	EndpointId endpoint;
	RuntimeGenerationKey runtimeGeneration;
};
} // namespace MTP::details::MtProxy

namespace MTP::details {
class EndpointAdmissionArbiter;
} // namespace MTP::details

namespace MTP {

class ProxyEndpointContext final
	: public std::enable_shared_from_this<ProxyEndpointContext> {
public:
	ProxyEndpointContext();
	ProxyEndpointContext(const ProxyEndpointContext &other) = delete;
	ProxyEndpointContext &operator=(const ProxyEndpointContext &other) = delete;
	~ProxyEndpointContext();

	[[nodiscard]] ProxyRuntimeId registerRuntime();
	void unregisterRuntime(ProxyRuntimeId runtimeId);
	void setForegroundRuntime(ProxyRuntimeId runtimeId);
	[[nodiscard]] ProxyTraceId nextTraceId(
		ProxyConnectionAttempt attempt = {});
	void updateTraceAttempt(const ProxyConnectionAttempt &attempt);
	[[nodiscard]] bool traceActive(ProxyTraceId traceId) const;
	[[nodiscard]] auto activeTracesForRuntime(
		ProxyRuntimeId runtimeId) const
		-> std::vector<ProxyConnectionAttempt>;
	[[nodiscard]] bool finishTrace(ProxyTraceId traceId);
	void cancelEndpointAttempt(const QString &key, uint64 attemptId);
	void transportReady(
		const QString &key,
		ProxyRuntimeId runtimeId,
		uint64 proxyGeneration,
		uint64 attemptId);

	void notifyEndpointAdmissible(const QString &key);
	void notifyEndpointViewChanged(
		const details::MtProxy::EndpointId &endpoint);
	void notifyEndpointViewChanged(
		const details::MtProxy::EndpointId &endpoint,
		RuntimeGenerationKey runtimeGeneration);
	void notifyEndpointViewsChanged(ProxyRuntimeId runtimeId);
	[[nodiscard]] details::MtProxy::ProxyEndpointView endpointView(
		const details::MtProxy::EndpointId &endpoint,
		ProxyRuntimeId runtimeId) const;
	[[nodiscard]] details::MtProxy::ProxyEndpointView endpointView(
		const details::MtProxy::EndpointId &endpoint,
		RuntimeGenerationKey runtimeGeneration) const;
	[[nodiscard]] crl::time endpointRetryUntil(
		const details::MtProxy::EndpointId &endpoint,
		RuntimeGenerationKey runtimeGeneration) const;
	[[nodiscard]] auto endpointViewChanges() const
		-> rpl::producer<details::MtProxy::EndpointViewInvalidation>;
	[[nodiscard]] details::EndpointAdmissionArbiter &endpointAdmissionArbiter();

	[[nodiscard]] auto storage()
		-> details::MtProxy::EndpointContextStorage &;
	[[nodiscard]] auto storage() const
		-> const details::MtProxy::EndpointContextStorage &;

private:
	const std::unique_ptr<details::MtProxy::EndpointContextStorage> _storage;
	const std::unique_ptr<details::EndpointAdmissionArbiter> _arbiter;

};

[[nodiscard]] auto CreateProxyEndpointContext()
	-> std::shared_ptr<ProxyEndpointContext>;

} // namespace MTP
