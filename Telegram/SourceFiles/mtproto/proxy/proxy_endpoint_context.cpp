/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "mtproto/proxy/proxy_endpoint_context.h"

#include "mtproto/proxy/proxy_endpoint_context_p.h"

namespace MTP {

ProxyEndpointContext::ProxyEndpointContext()
: _storage(std::make_unique<details::MtProxy::EndpointContextStorage>()) {
}

ProxyEndpointContext::~ProxyEndpointContext() = default;

ProxyRuntimeId ProxyEndpointContext::registerRuntime() {
	QMutexLocker lock(&_storage->mutex);
	const auto result = ++_storage->lastRuntimeId;
	_storage->runtimes.emplace(result);
	return result;
}

void ProxyEndpointContext::unregisterRuntime(ProxyRuntimeId runtimeId) {
	if (!runtimeId) {
		return;
	}
	QMutexLocker lock(&_storage->mutex);
	_storage->runtimes.erase(runtimeId);
	for (auto i = begin(_storage->activeTraces);
			i != end(_storage->activeTraces);) {
		if (i->second.runtimeId == runtimeId) {
			i = _storage->activeTraces.erase(i);
		} else {
			++i;
		}
	}
	for (auto &entry : _storage->states) {
		auto &state = entry.second;
		state.generations.erase(runtimeId);
		for (auto i = begin(state.attemptStarts);
				i != end(state.attemptStarts);) {
			if (i->second.runtimeId == runtimeId) {
				i = state.attemptStarts.erase(i);
			} else {
				++i;
			}
		}
		state.active = int(state.attemptStarts.size());
	}
}

ProxyTraceId ProxyEndpointContext::nextTraceId(
		ProxyConnectionAttempt attempt) {
	QMutexLocker lock(&_storage->mutex);
	const auto result = ++_storage->lastTraceId;
	attempt.traceId = result;
	_storage->activeTraces.emplace(result, std::move(attempt));
	return result;
}

void ProxyEndpointContext::updateTraceAttempt(
		const ProxyConnectionAttempt &attempt) {
	if (!attempt.traceId) {
		return;
	}
	QMutexLocker lock(&_storage->mutex);
	const auto i = _storage->activeTraces.find(attempt.traceId);
	if (i != end(_storage->activeTraces)) {
		i->second = attempt;
	}
}

bool ProxyEndpointContext::traceActive(ProxyTraceId traceId) const {
	if (!traceId) {
		return false;
	}
	QMutexLocker lock(&_storage->mutex);
	return _storage->activeTraces.contains(traceId);
}

auto ProxyEndpointContext::activeTracesForRuntime(
		ProxyRuntimeId runtimeId) const
-> std::vector<ProxyConnectionAttempt> {
	auto result = std::vector<ProxyConnectionAttempt>();
	QMutexLocker lock(&_storage->mutex);
	for (const auto &entry : _storage->activeTraces) {
		const auto &attempt = entry.second;
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
	QMutexLocker lock(&_storage->mutex);
	return _storage->activeTraces.erase(traceId) > 0;
}

void ProxyEndpointContext::releaseEndpointAttempt(
		const QString &key,
		uint64 attemptId) {
	if (key.isEmpty() || !attemptId) {
		return;
	}
	QMutexLocker lock(&_storage->mutex);
	const auto i = _storage->states.find(key);
	if (i == end(_storage->states)) {
		return;
	}
	i->second.attemptStarts.erase(attemptId);
	i->second.active = int(i->second.attemptStarts.size());
}

auto ProxyEndpointContext::storage()
-> details::MtProxy::EndpointContextStorage & {
	return *_storage;
}

auto ProxyEndpointContext::storage() const
-> const details::MtProxy::EndpointContextStorage & {
	return *_storage;
}

std::shared_ptr<ProxyEndpointContext> CreateProxyEndpointContext() {
	return std::make_shared<ProxyEndpointContext>();
}

} // namespace MTP
