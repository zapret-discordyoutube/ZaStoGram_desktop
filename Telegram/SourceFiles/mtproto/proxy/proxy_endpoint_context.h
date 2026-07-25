/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#pragma once

#include "base/basic_types.h"
#include "mtproto/runtime/connection_status_types.h"

#include <QtCore/QMutex>

#include <map>
#include <memory>
#include <set>
#include <vector>

namespace MTP {

// Diagnostics correlation shared by every account: a trace id ties all log
// lines of one connection attempt together, and runtime ids keep those
// attempts apart between accounts. This used to also carry per-endpoint
// health - verdicts, cooldowns, relay proofs - which is gone: the client no
// longer reacts to its own failure history.
class ProxyEndpointContext final {
public:
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

private:
	mutable QMutex _mutex;
	std::set<ProxyRuntimeId> _runtimes;
	std::map<ProxyTraceId, ProxyConnectionAttempt> _activeTraces;
	ProxyRuntimeId _lastRuntimeId = 0;
	ProxyTraceId _lastTraceId = 0;

};

[[nodiscard]] auto CreateProxyEndpointContext()
	-> std::shared_ptr<ProxyEndpointContext>;

} // namespace MTP
