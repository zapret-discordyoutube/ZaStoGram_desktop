/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "mtproto/proxy/proxy_endpoint_context.h"

#include "mtproto/proxy/proxy_endpoint_context_p.h"

#include <vector>

namespace MTP {
namespace {

using AdmissionReleaseListener = std::shared_ptr<const Fn<void(const QString&)>>;

// Copied out under the storage mutex so the callbacks can be invoked
// after it unlocks: a listener may re-enter admission paths that take
// the broker and storage mutexes (calling under the lock would invert
// the broker's request() lock order and deadlock).
[[nodiscard]] auto CollectAdmissionReleaseListeners(
	const details::MtProxy::EndpointContextStorage &storage)
-> std::vector<AdmissionReleaseListener> {
	auto result = std::vector<AdmissionReleaseListener>();
	result.reserve(storage.admissionReleaseListeners.size());
	for (const auto &[id, listener] : storage.admissionReleaseListeners) {
		result.push_back(listener);
	}
	return result;
}

} // namespace

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
		details::MtProxy::SynchronizeEndpointAdmissionAggregate(state);
		details::MtProxy::RemoveRelayProofsForRuntime(state, runtimeId);
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
	auto listeners = std::vector<AdmissionReleaseListener>();
	{
		QMutexLocker lock(&_storage->mutex);
		const auto i = _storage->states.find(key);
		if (i == end(_storage->states)) {
			return;
		}
		const auto wasActive = i->second.active;
		i->second.attemptStarts.erase(attemptId);
		details::MtProxy::SynchronizeEndpointAdmissionAggregate(i->second);
		if (i->second.active < wasActive) {
			listeners = CollectAdmissionReleaseListeners(*_storage);
		}
	}
	for (const auto &listener : listeners) {
		(*listener)(key);
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
	auto listeners = std::vector<AdmissionReleaseListener>();
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
		if (details::MtProxy::ReleaseAdmissionForRelayCandidate(
				i->second,
				identity)) {
			listeners = CollectAdmissionReleaseListeners(*_storage);
		}
	}
	for (const auto &listener : listeners) {
		(*listener)(key);
	}
}

AdmissionReleaseListenerId ProxyEndpointContext::addAdmissionReleaseListener(
		Fn<void(const QString &endpointKey)> callback) {
	if (!callback) {
		return 0;
	}
	QMutexLocker lock(&_storage->mutex);
	const auto id = ++_storage->lastAdmissionReleaseListenerId;
	_storage->admissionReleaseListeners.emplace(
		id,
		std::make_shared<const Fn<void(const QString&)>>(
			std::move(callback)));
	return id;
}

void ProxyEndpointContext::removeAdmissionReleaseListener(
		AdmissionReleaseListenerId id) {
	if (!id) {
		return;
	}
	QMutexLocker lock(&_storage->mutex);
	_storage->admissionReleaseListeners.erase(id);
}

void ProxyEndpointContext::notifyEndpointAdmissible(const QString &key) {
	if (key.isEmpty()) {
		return;
	}
	auto listeners = std::vector<AdmissionReleaseListener>();
	{
		QMutexLocker lock(&_storage->mutex);
		listeners = CollectAdmissionReleaseListeners(*_storage);
	}
	for (const auto &listener : listeners) {
		(*listener)(key);
	}
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
