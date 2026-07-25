/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "mtproto/proxy/proxy_endpoint_context.h"

#include <utility>

namespace MTP {

ProxyRuntimeId ProxyEndpointContext::registerRuntime() {
	QMutexLocker lock(&_mutex);
	const auto result = ++_lastRuntimeId;
	_runtimes.emplace(result);
	return result;
}

void ProxyEndpointContext::unregisterRuntime(ProxyRuntimeId runtimeId) {
	QMutexLocker lock(&_mutex);
	_runtimes.erase(runtimeId);
	for (auto i = begin(_activeTraces); i != end(_activeTraces);) {
		if (i->second.runtimeId == runtimeId) {
			i = _activeTraces.erase(i);
		} else {
			++i;
		}
	}
}

ProxyTraceId ProxyEndpointContext::nextTraceId(
		ProxyConnectionAttempt attempt) {
	QMutexLocker lock(&_mutex);
	const auto result = ++_lastTraceId;
	attempt.traceId = result;
	_activeTraces.emplace(result, std::move(attempt));
	return result;
}

void ProxyEndpointContext::updateTraceAttempt(
		const ProxyConnectionAttempt &attempt) {
	if (!attempt.traceId) {
		return;
	}
	QMutexLocker lock(&_mutex);
	const auto i = _activeTraces.find(attempt.traceId);
	if (i != end(_activeTraces)) {
		i->second = attempt;
	}
}

bool ProxyEndpointContext::traceActive(ProxyTraceId traceId) const {
	if (!traceId) {
		return false;
	}
	QMutexLocker lock(&_mutex);
	return _activeTraces.contains(traceId);
}

auto ProxyEndpointContext::activeTracesForRuntime(
		ProxyRuntimeId runtimeId) const
-> std::vector<ProxyConnectionAttempt> {
	auto result = std::vector<ProxyConnectionAttempt>();
	QMutexLocker lock(&_mutex);
	for (const auto &[traceId, attempt] : _activeTraces) {
		if (attempt.runtimeId == runtimeId) {
			result.push_back(attempt);
		}
	}
	return result;
}

bool ProxyEndpointContext::finishTrace(ProxyTraceId traceId) {
	if (!traceId) {
		return false;
	}
	QMutexLocker lock(&_mutex);
	return _activeTraces.erase(traceId) > 0;
}

std::shared_ptr<ProxyEndpointContext> CreateProxyEndpointContext() {
	return std::make_shared<ProxyEndpointContext>();
}

} // namespace MTP
