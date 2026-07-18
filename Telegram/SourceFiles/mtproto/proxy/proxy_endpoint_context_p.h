/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#pragma once

#include "mtproto/proxy/mtproxy/endpoint_health_state.h"
#include "mtproto/proxy/proxy_endpoint_context.h"

#include <QtCore/QMutex>
#include <rpl/event_stream.h>

#include <map>
#include <set>

namespace MTP::details::MtProxy {

struct EndpointContextStorage {
	QMutex mutex;
	std::map<QString, EndpointState> states;
	std::map<QString, RouteState> routes;
	rpl::event_stream<EndpointViewInvalidation> viewInvalidations;
	std::set<ProxyRuntimeId> runtimes;
	std::map<ProxyRuntimeId, uint64> runtimeGenerations;
	std::map<ProxyTraceId, ProxyConnectionAttempt> activeTraces;
	ProxyRuntimeId foregroundRuntimeId = 0;
	ProxyRuntimeId lastRuntimeId = 0;
	ProxyTraceId lastTraceId = 0;
	uint64 lastMainRecoveryId = 0;
};

} // namespace MTP::details::MtProxy
