/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#pragma once

#include "mtproto/proxy/mtproxy/endpoint_health_state.h"

#include <QtCore/QMutex>
#include <rpl/event_stream.h>

#include <deque>
#include <map>
#include <set>

namespace MTP::details::MtProxy {

struct OpenState {
	crl::time nextOpenAt = 0;
	crl::time adaptiveSpacing = 0;
	std::deque<crl::time> recentOpens;
};

struct EndpointContextStorage {
	QMutex mutex;
	std::map<QString, EndpointState> states;
	std::map<QString, RouteState> routes;
	std::map<QString, OpenState> openStates;
	rpl::event_stream<EndpointEvent> events;
	std::set<ProxyRuntimeId> runtimes;
	std::map<ProxyTraceId, ProxyConnectionAttempt> activeTraces;
	ProxyRuntimeId lastRuntimeId = 0;
	ProxyTraceId lastTraceId = 0;
};

} // namespace MTP::details::MtProxy
