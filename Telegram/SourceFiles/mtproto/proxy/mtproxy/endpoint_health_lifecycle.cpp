/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "mtproto/proxy/mtproxy/endpoint_health.h"

#include "base/algorithm.h"
#include "base/timer.h"
#include "mtproto/proxy/mtproxy/endpoint_health_capabilities.h"
#include "mtproto/proxy/mtproxy/endpoint_health_diagnostics.h"
#include "mtproto/proxy/mtproxy/endpoint_health_policy.h"
#include "mtproto/proxy/mtproxy/endpoint_health_state.h"
#include "mtproto/proxy/proxy_endpoint_context.h"
#include "mtproto/proxy/proxy_endpoint_context_p.h"

#include <QtCore/QMutex>

namespace MTP::details::MtProxy {

namespace {

enum class RelayProofRetirement {
	StaleGeneration,
	MissingOrDuplicate,
	RetiredWithSurvivors,
	RetiredFinal,
};

[[nodiscard]] RelayProofRetirement RetireRelayProofLocked(
		EndpointState &state,
		const RelayProofReport &report,
		crl::time now) {
	PruneExpiredEndpointState(state, now);
	if (RuntimeProxyGenerationIsStale(
			state,
			report.runtimeId,
			report.proxyGeneration)) {
		return RelayProofRetirement::StaleGeneration;
	}
	ApplyProxyGeneration(
		state,
		report.runtimeId,
		report.proxyGeneration);
	const auto identity = RelayProofIdentity{
		.runtimeId = report.runtimeId,
		.proxyGeneration = report.proxyGeneration,
		.attemptId = report.attemptId,
	};
	if (!RetireRelayProof(state, identity)) {
		return RelayProofRetirement::MissingOrDuplicate;
	}
	return state.relayProven
		? RelayProofRetirement::RetiredWithSurvivors
		: RelayProofRetirement::RetiredFinal;
}

[[nodiscard]] FailureReport RelayStallFailureReport(
		const RelayProofReport &report) {
	return {
		.endpoint = report.endpoint,
		.use = report.use,
		.runtimeId = report.runtimeId,
		.reason = FailureReason::MtpReceiveTimeoutAfterData,
		.proxyGeneration = report.proxyGeneration,
		.attemptId = report.attemptId,
		.proxyEpoch = report.proxyEpoch,
		.successEpoch = report.successEpoch,
		.attemptStartedAt = report.attemptStartedAt,
	};
}

} // namespace

void EndpointHealth::noteRelayStall(RelayProofReport report) {
	if (!report.runtimeId) {
		report.runtimeId = _runtimeId;
	}
	if (IsProxyCheck(report.use)) {
		return;
	}
	const auto now = crl::now();
	const auto staleReport = RelayStallFailureReport(report);
	auto retirement = RelayProofRetirement::MissingOrDuplicate;
	auto recipeLevel = 0;
	{
		auto &storage = _context->storage();
		QMutexLocker lock(&storage.mutex);
		const auto i = storage.states.find(EndpointKey(report.endpoint));
		if (i != end(storage.states)) {
			auto &state = i->second;
			recipeLevel = state.recipeLevel;
			retirement = RetireRelayProofLocked(state, report, now);
		}
	}
	if (retirement == RelayProofRetirement::StaleGeneration
		|| retirement == RelayProofRetirement::MissingOrDuplicate) {
		LogStaleAttemptFailure(_runtime, staleReport, recipeLevel);
		return;
	}
	if (retirement == RelayProofRetirement::RetiredWithSurvivors) {
		return;
	}
	NoteCapabilityMtproxyRelayFailure(
		_runtime,
		CapabilityFailure{
			.proxyKey = CapabilityProxyKey(report.endpoint.canonical),
			.routeKey = RouteKey(report.endpoint.route),
			.diagnostic = u"relay_stall"_q,
		});
}

void EndpointHealth::retireRelayProof(RelayProofReport report) {
	if (!report.runtimeId) {
		report.runtimeId = _runtimeId;
	}
	if (IsProxyCheck(report.use)) {
		return;
	}
	const auto now = crl::now();
	auto &storage = _context->storage();
	QMutexLocker lock(&storage.mutex);
	const auto i = storage.states.find(EndpointKey(report.endpoint));
	if (i != end(storage.states)) {
		static_cast<void>(RetireRelayProofLocked(i->second, report, now));
	}
}

void EndpointHealth::applyProxyGeneration(uint64 proxyGeneration) {
	const auto now = crl::now();
	auto &storage = _context->storage();
	QMutexLocker lock(&storage.mutex);
	for (auto &entry : storage.states) {
		auto &state = entry.second;
		PruneExpiredEndpointState(state, now);
		ApplyProxyGeneration(state, _runtimeId, proxyGeneration);
	}
}

Snapshot EndpointHealth::snapshot(const EndpointId &endpoint) const {
	const auto key = EndpointKey(endpoint);
	const auto now = crl::now();
	auto &storage = _context->storage();
	QMutexLocker lock(&storage.mutex);
	const auto i = storage.states.find(key);
	if (i != end(storage.states)) {
		PruneExpiredEndpointState(i->second, now);
		return MakeSnapshot(i->second, _runtimeId);
	}
	auto result = Snapshot();
	result.endpoint = endpoint;
	return result;
}

} // namespace MTP::details::MtProxy
