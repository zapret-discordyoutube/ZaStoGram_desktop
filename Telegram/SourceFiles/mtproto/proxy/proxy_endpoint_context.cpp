/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "mtproto/proxy/proxy_endpoint_context.h"

#include "mtproto/proxy/endpoint_admission_arbiter.h"
#include "mtproto/proxy/proxy_endpoint_context_p.h"

#include <vector>

namespace MTP {

ProxyEndpointContext::ProxyEndpointContext()
: _storage(std::make_unique<details::MtProxy::EndpointContextStorage>())
, _arbiter(std::make_unique<details::EndpointAdmissionArbiter>(*_storage)) {
}

ProxyEndpointContext::~ProxyEndpointContext() = default;

ProxyRuntimeId ProxyEndpointContext::registerRuntime() {
	QMutexLocker lock(&_storage->mutex);
	const auto result = ++_storage->lastRuntimeId;
	_storage->runtimes.emplace(result);
	return result;
}

void ProxyEndpointContext::unregisterRuntime(ProxyRuntimeId runtimeId) {
	_arbiter->unregisterRuntime(runtimeId);
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
	auto released = false;
	{
		QMutexLocker lock(&_storage->mutex);
		const auto i = _storage->states.find(key);
		if (i == end(_storage->states)) {
			return;
		}
		const auto wasActive = i->second.active;
		i->second.attemptStarts.erase(attemptId);
		details::MtProxy::SynchronizeEndpointAdmissionAggregate(i->second);
		released = (i->second.active < wasActive);
	}
	if (released) {
		_arbiter->drainEndpoint(key);
	}
}

void ProxyEndpointContext::releaseAdmissionForRelayCandidate(
		const QString &key,
		ProxyRuntimeId runtimeId,
		uint64 proxyGeneration,
		uint64 attemptId) {
	if (key.isEmpty() || !runtimeId || !attemptId) {
		return;
	}
	auto released = false;
	{
		QMutexLocker lock(&_storage->mutex);
		const auto i = _storage->states.find(key);
		if (i == end(_storage->states)) {
			return;
		}
		const auto identity = details::MtProxy::RelayProofIdentity{
			.runtimeId = runtimeId,
			.proxyGeneration = proxyGeneration,
			.attemptId = attemptId,
		};
		released = details::MtProxy::ReleaseAdmissionForRelayCandidate(
			i->second,
			identity);
	}
	if (released) {
		_arbiter->drainEndpoint(key);
	}
}

void ProxyEndpointContext::notifyEndpointAdmissible(const QString &key) {
	if (key.isEmpty()) {
		return;
	}
	_arbiter->drainEndpoint(key);
}

auto ProxyEndpointContext::endpointAdmissionArbiter()
-> details::EndpointAdmissionArbiter & {
	return *_arbiter;
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
