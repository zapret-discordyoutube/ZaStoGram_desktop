/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "mtproto/proxy/mtproxy/endpoint_health_state.h"
#include "mtproto/proxy/proxy_endpoint_context.h"
#include "mtproto/proxy/proxy_endpoint_context_p.h"

#include <cstdio>

namespace {

[[nodiscard]] int Fail(const char *message) {
	std::fprintf(stderr, "%s\n", message);
	return 1;
}

} // namespace

int main(int, char *[]) {
	const auto context = MTP::CreateProxyEndpointContext();
	const auto firstRuntime = context->registerRuntime();
	const auto secondRuntime = context->registerRuntime();
	if (!firstRuntime || firstRuntime == secondRuntime) {
		return Fail("runtime ids are not unique");
	}
	const auto firstTrace = context->nextTraceId({
		.runtimeId = firstRuntime,
		.ticketId = 1,
	});
	const auto secondTrace = context->nextTraceId({
		.runtimeId = secondRuntime,
		.ticketId = 1,
	});
	if (!firstTrace || secondTrace <= firstTrace) {
		return Fail("trace ids are not monotonic");
	}
	if (!context->finishTrace(firstTrace) || context->finishTrace(firstTrace)) {
		return Fail("trace finalization is not exactly once");
	}
	if (context->traceActive(firstTrace)
		|| !context->traceActive(secondTrace)) {
		return Fail("trace active state is inconsistent");
	}
	if (context->activeTracesForRuntime(secondRuntime).size() != 1) {
		return Fail("runtime trace ownership failed");
	}

	auto state = MTP::details::MtProxy::EndpointState();
	MTP::details::MtProxy::ApplyRuntimeProxyGeneration(
		state,
		firstRuntime,
		1);
	MTP::details::MtProxy::ApplyRuntimeProxyGeneration(
		state,
		secondRuntime,
		1);
	state.attemptStarts.emplace(1, MTP::details::MtProxy::EndpointAttemptState{
		.runtimeId = firstRuntime,
		.proxyGeneration = 1,
		.startedAt = 100,
	});
	state.attemptStarts.emplace(2, MTP::details::MtProxy::EndpointAttemptState{
		.runtimeId = secondRuntime,
		.proxyGeneration = 1,
		.startedAt = 100,
	});
	MTP::details::MtProxy::ApplyRuntimeProxyGeneration(
		state,
		firstRuntime,
		2);
	if (state.generations[firstRuntime] != 2
		|| state.generations[secondRuntime] != 1
		|| state.attemptStarts.contains(1)
		|| !state.attemptStarts.contains(2)) {
		return Fail("runtime generation isolation failed");
	}

	auto &storage = context->storage();
	storage.states.emplace(QString::fromLatin1("endpoint"), std::move(state));
	context->unregisterRuntime(secondRuntime);
	if (!storage.states.begin()->second.attemptStarts.empty()) {
		return Fail("runtime attempts survived unregister");
	}
	if (!context->activeTracesForRuntime(secondRuntime).empty()
		|| context->finishTrace(secondTrace)) {
		return Fail("runtime traces survived unregister");
	}
	return 0;
}
