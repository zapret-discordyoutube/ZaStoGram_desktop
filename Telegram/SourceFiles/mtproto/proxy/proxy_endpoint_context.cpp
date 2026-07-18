/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "mtproto/proxy/proxy_endpoint_context.h"

#include "base/timer.h"
#include "mtproto/proxy/endpoint_admission_arbiter.h"
#include "mtproto/proxy/proxy_endpoint_context_p.h"

#include <algorithm>
#include <optional>
#include <utility>
#include <vector>

namespace MTP {
namespace {
namespace MtProxy = details::MtProxy;

struct MainAttemptSelection {
	uint64 attemptId = 0;
	const MtProxy::EndpointAttemptState *attempt = nullptr;
};

MtProxy::EndpointOpeningAttemptIdentity OpeningAttemptIdentity(
		const MtProxy::EndpointId &endpoint,
		uint64 attemptId,
		const MtProxy::EndpointAttemptState &attempt) {
	return {
		.flow = {
			.endpoint = endpoint.canonical,
			.runtimeId = attempt.runtimeId,
			.proxyGeneration = attempt.proxyGeneration,
			.use = attempt.use,
		},
		.key = {
			.runtimeId = attempt.runtimeId,
			.traceId = attempt.traceId,
			.ticketId = attempt.ticketKey.ticketId,
			.proxyGeneration = attempt.proxyGeneration,
			.proxyEpoch = attempt.proxyEpoch,
			.successEpoch = attempt.successEpoch,
			.attemptId = attemptId,
			.use = attempt.use,
			.ticketKey = attempt.ticketKey,
		},
	};
}

MainAttemptSelection SelectMainAttempt(
		const MtProxy::EndpointState &state,
		RuntimeGenerationKey runtimeGeneration) {
	auto result = MainAttemptSelection();
	for (const auto &[attemptId, candidate] : state.attemptStarts) {
		if (candidate.runtimeId != runtimeGeneration.runtimeId
			|| candidate.proxyGeneration
				!= runtimeGeneration.proxyGeneration
			|| candidate.use != MtProxy::EndpointUse::Main) {
			continue;
		}
		if (!result.attempt
			|| (result.attempt->terminalVerdict.has_value()
				&& !candidate.terminalVerdict.has_value())
			|| (result.attempt->terminalVerdict.has_value()
				== candidate.terminalVerdict.has_value()
				&& candidate.attemptStartedAt
					< result.attempt->attemptStartedAt)) {
			result = {
				.attemptId = attemptId,
				.attempt = &candidate,
			};
		}
	}
	return result;
}

MtProxy::ProxyEndpointView ComposeEndpointViewLocked(
		const MtProxy::EndpointContextStorage &storage,
		const details::EndpointAdmissionArbiter &arbiter,
		const MtProxy::EndpointId &endpoint,
		RuntimeGenerationKey runtimeGeneration) {
	auto result = MtProxy::ProxyEndpointView{
		.endpoint = endpoint,
		.runtimeGeneration = runtimeGeneration,
	};
	if (!runtimeGeneration.runtimeId
		|| !runtimeGeneration.proxyGeneration) {
		return result;
	}
	const auto key = MtProxy::EndpointKey(endpoint);
	const auto i = storage.states.find(key);
	if (i != end(storage.states)) {
		const auto &state = i->second;
		result.endpointMainProof = MtProxy::EndpointMainRelayProof(state);
		const auto generation = state.generations.find(
			runtimeGeneration.runtimeId);
		if (generation != end(state.generations)
			&& generation->second != runtimeGeneration.proxyGeneration) {
			return result;
		}
		if (generation != end(state.generations)) {
			result.mainProof = MtProxy::CurrentMainRelayProof(
				state,
				runtimeGeneration);
			result.mainRecovery = MtProxy::ComposeMainRecoveryViewLocked(
				storage,
				key,
				runtimeGeneration);
			const auto canonical = state.canonicalVerdicts.find(
				runtimeGeneration);
			if (canonical != end(state.canonicalVerdicts)) {
				result.canonicalVerdict = canonical->second;
				result.terminalAt = canonical->second.terminalAt;
				result.retryUntil = canonical->second.retryUntil;
			}
			const auto selected = SelectMainAttempt(
				state,
				runtimeGeneration);
			if (selected.attempt) {
				const auto &attempt = *selected.attempt;
				result.mainAttempt = {
					.runtimeId = attempt.runtimeId,
					.traceId = attempt.traceId,
					.ticketId = attempt.ticketKey.ticketId,
					.proxyGeneration = attempt.proxyGeneration,
					.proxyEpoch = attempt.proxyEpoch,
					.successEpoch = attempt.successEpoch,
					.attemptId = selected.attemptId,
					.use = attempt.use,
					.ticketKey = attempt.ticketKey,
				};
				result.ticketKey = attempt.ticketKey;
				result.schedulerLifecycle = attempt.schedulerLifecycle;
				result.admissionPhase = attempt.admissionPhase;
				result.enqueuedAt = attempt.enqueuedAt;
				result.scheduledOpenAt = attempt.scheduledOpenAt;
				result.attemptStartedAt = attempt.attemptStartedAt;
				result.phaseStartedAt = attempt.phaseStartedAt;
				result.terminalAt = std::max(
					result.terminalAt,
					attempt.terminalAt);
			}
		}
	}
	arbiter.composeEndpointViewLocked(endpoint, runtimeGeneration, result);
	return result;
}

} // namespace

ProxyEndpointContext::ProxyEndpointContext()
: _storage(std::make_unique<details::MtProxy::EndpointContextStorage>())
, _arbiter(std::make_unique<details::EndpointAdmissionArbiter>(*_storage)) {
}

ProxyEndpointContext::~ProxyEndpointContext() = default;

ProxyRuntimeId ProxyEndpointContext::registerRuntime() {
	QMutexLocker lock(&_storage->mutex);
	const auto result = ++_storage->lastRuntimeId;
	_storage->runtimes.emplace(result);
	_storage->runtimeGenerations.emplace(result, 0);
	return result;
}

void ProxyEndpointContext::unregisterRuntime(ProxyRuntimeId runtimeId) {
	_arbiter->unregisterRuntime(runtimeId);
}

void ProxyEndpointContext::setForegroundRuntime(ProxyRuntimeId runtimeId) {
	auto endpoints = std::vector<QString>();
	{
		QMutexLocker lock(&_storage->mutex);
		if ((runtimeId && !_storage->runtimes.contains(runtimeId))
			|| _storage->foregroundRuntimeId == runtimeId) {
			return;
		}
		_storage->foregroundRuntimeId = runtimeId;
		endpoints.reserve(_storage->states.size());
		for (const auto &entry : _storage->states) {
			endpoints.push_back(entry.first);
		}
	}
	for (const auto &endpoint : endpoints) {
		_arbiter->drainEndpoint(endpoint);
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

void ProxyEndpointContext::cancelEndpointAttempt(
		const QString &key,
		uint64 attemptId) {
	if (key.isEmpty() || !attemptId) {
		return;
	}
	auto removed = false;
	auto endpoint = details::MtProxy::EndpointId();
	auto runtimeGeneration = RuntimeGenerationKey();
	auto openingEvent = std::optional<details::MtProxy::Cancelled>();
	auto cleanup = details::MtProxy::EndpointDeferredCleanup();
	{
		QMutexLocker lock(&_storage->mutex);
		const auto i = _storage->states.find(key);
		if (i == end(_storage->states)) {
			return;
		}
		const auto attempt = i->second.attemptStarts.find(attemptId);
		if (attempt != end(i->second.attemptStarts)) {
			const auto attemptState = attempt->second;
			endpoint = i->second.endpoint;
			runtimeGeneration = {
				.runtimeId = attemptState.runtimeId,
				.proxyGeneration = attemptState.proxyGeneration,
			};
			const auto identity = details::MtProxy::RelayProofIdentity{
				.runtimeId = attemptState.runtimeId,
				.proxyGeneration = attemptState.proxyGeneration,
				.attemptId = attemptId,
			};
			const auto openingIdentity = OpeningAttemptIdentity(
				endpoint,
				attemptId,
				attemptState);
			openingEvent = details::MtProxy::Cancelled{
				.identity = {
					.flow = openingIdentity.flow,
					.owner = openingIdentity.key,
				},
				.observedAt = crl::now(),
			};
			static_cast<void>(
				details::MtProxy::FinishMainRecoveryByReplacementAttemptLocked(
					*_storage,
					key,
					runtimeGeneration,
					attemptState.use,
					attemptId));
			static_cast<void>(details::MtProxy::RetireRelayProof(
				i->second,
				identity));
			details::MtProxy::DeferEndpointOwnerDisconnect(
				cleanup,
				attemptState.ownerDestroyed);
			removed = true;
		} else {
			const auto lane = std::find_if(
				begin(i->second.liveLanes),
				end(i->second.liveLanes),
				[=](const auto &entry) {
					return entry.first.attemptId == attemptId;
				});
			if (lane != end(i->second.liveLanes)) {
				const auto laneState = lane->second;
				const auto identity = lane->first;
				endpoint = i->second.endpoint;
				runtimeGeneration = {
					.runtimeId = identity.runtimeId,
					.proxyGeneration = identity.proxyGeneration,
				};
				const auto openingIdentity = OpeningAttemptIdentity(
					endpoint,
					attemptId,
					laneState);
				openingEvent = details::MtProxy::Cancelled{
					.identity = {
						.flow = openingIdentity.flow,
						.owner = openingIdentity.key,
					},
					.observedAt = crl::now(),
				};
				static_cast<void>(
					details::MtProxy::FinishMainRecoveryByReplacementAttemptLocked(
						*_storage,
						key,
						runtimeGeneration,
						laneState.use,
						attemptId));
				static_cast<void>(details::MtProxy::RetireRelayProof(
					i->second,
					identity));
				details::MtProxy::DeferEndpointOwnerDisconnect(
					cleanup,
					laneState.ownerDestroyed);
				i->second.liveLanes.erase(lane);
				removed = true;
			}
		}
		i->second.attemptStarts.erase(attemptId);
	}
	for (const auto &connection : cleanup.ownerConnections) {
		QObject::disconnect(connection);
	}
	if (openingEvent) {
		_arbiter->openingEvent(std::move(*openingEvent));
	}
	if (removed) {
		notifyEndpointViewChanged(endpoint, runtimeGeneration);
	}
}

void ProxyEndpointContext::transportReady(
		const QString &key,
		ProxyRuntimeId runtimeId,
		uint64 proxyGeneration,
		uint64 attemptId) {
	if (key.isEmpty() || !runtimeId || !attemptId) {
		return;
	}
	auto openingEvent = std::optional<details::MtProxy::TransportReady>();
	{
		QMutexLocker lock(&_storage->mutex);
		const auto i = _storage->states.find(key);
		if (i == end(_storage->states)) {
			return;
		}
		const auto attempt = i->second.attemptStarts.find(attemptId);
		if (attempt == end(i->second.attemptStarts)
			|| attempt->second.runtimeId != runtimeId
			|| attempt->second.proxyGeneration != proxyGeneration
			|| attempt->second.terminalVerdict.has_value()) {
			return;
		}
		openingEvent = details::MtProxy::TransportReady{
			.identity = OpeningAttemptIdentity(
				i->second.endpoint,
				attemptId,
				attempt->second),
			.observedAt = crl::now(),
		};
	}
	if (openingEvent) {
		_arbiter->openingEvent(std::move(*openingEvent));
	}
}

void ProxyEndpointContext::notifyEndpointAdmissible(const QString &key) {
	if (key.isEmpty()) {
		return;
	}
	_arbiter->drainEndpoint(key);
}

void ProxyEndpointContext::notifyEndpointViewChanged(
		const details::MtProxy::EndpointId &endpoint) {
	auto generations = std::vector<RuntimeGenerationKey>();
	{
		QMutexLocker lock(&_storage->mutex);
		const auto i = _storage->states.find(
			details::MtProxy::EndpointKey(endpoint));
		if (i != end(_storage->states)) {
			generations.reserve(i->second.generations.size());
			for (const auto &[runtimeId, proxyGeneration]
					: i->second.generations) {
				generations.push_back({ runtimeId, proxyGeneration });
			}
		}
	}
	for (const auto runtimeGeneration : generations) {
		notifyEndpointViewChanged(endpoint, runtimeGeneration);
	}
}

void ProxyEndpointContext::notifyEndpointViewChanged(
		const details::MtProxy::EndpointId &endpoint,
		RuntimeGenerationKey runtimeGeneration) {
	if (details::MtProxy::EndpointEmpty(endpoint)
		|| !runtimeGeneration.runtimeId
		|| !runtimeGeneration.proxyGeneration) {
		return;
	}
	const auto weak = weak_from_this();
	crl::on_main([weak, endpoint, runtimeGeneration] {
		if (const auto context = weak.lock()) {
			context->_storage->viewInvalidations.fire_copy({
				.endpoint = endpoint,
				.runtimeGeneration = runtimeGeneration,
			});
		}
	});
}

void ProxyEndpointContext::notifyEndpointViewsChanged(
		ProxyRuntimeId runtimeId) {
	auto invalidations = std::vector<
		details::MtProxy::EndpointViewInvalidation>();
	{
		QMutexLocker lock(&_storage->mutex);
		for (const auto &entry : _storage->states) {
			const auto &state = entry.second;
			const auto generation = state.generations.find(runtimeId);
			if (generation != end(state.generations)) {
				invalidations.push_back({
					.endpoint = state.endpoint,
					.runtimeGeneration = {
						.runtimeId = runtimeId,
						.proxyGeneration = generation->second,
					},
				});
			}
		}
	}
	for (const auto &invalidation : invalidations) {
		notifyEndpointViewChanged(
			invalidation.endpoint,
			invalidation.runtimeGeneration);
	}
}

auto ProxyEndpointContext::endpointView(
		const details::MtProxy::EndpointId &endpoint,
		ProxyRuntimeId runtimeId) const
-> details::MtProxy::ProxyEndpointView {
	QMutexLocker lock(&_storage->mutex);
	auto runtimeGeneration = RuntimeGenerationKey{
		.runtimeId = runtimeId,
	};
	const auto i = _storage->states.find(
		details::MtProxy::EndpointKey(endpoint));
	if (i != end(_storage->states)) {
		const auto generation = i->second.generations.find(runtimeId);
		if (generation != end(i->second.generations)) {
			runtimeGeneration.proxyGeneration = generation->second;
		}
	}
	return ComposeEndpointViewLocked(
		*_storage,
		*_arbiter,
		endpoint,
		runtimeGeneration);
}

auto ProxyEndpointContext::endpointView(
		const details::MtProxy::EndpointId &endpoint,
		RuntimeGenerationKey runtimeGeneration) const
-> details::MtProxy::ProxyEndpointView {
	QMutexLocker lock(&_storage->mutex);
	return ComposeEndpointViewLocked(
		*_storage,
		*_arbiter,
		endpoint,
		runtimeGeneration);
}

crl::time ProxyEndpointContext::endpointRetryUntil(
		const details::MtProxy::EndpointId &endpoint,
		RuntimeGenerationKey runtimeGeneration) const {
	if (!runtimeGeneration.runtimeId
		|| !runtimeGeneration.proxyGeneration) {
		return 0;
	}
	QMutexLocker lock(&_storage->mutex);
	const auto i = _storage->states.find(
		details::MtProxy::EndpointKey(endpoint));
	if (i == end(_storage->states)
		|| !details::MtProxy::RuntimeGenerationIsCurrent(
			i->second,
			runtimeGeneration)) {
		return 0;
	}
	return ComposeEndpointViewLocked(
		*_storage,
		*_arbiter,
		endpoint,
		runtimeGeneration).retryUntil;
}

auto ProxyEndpointContext::endpointViewChanges() const
-> rpl::producer<details::MtProxy::EndpointViewInvalidation> {
	return _storage->viewInvalidations.events();
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
