/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#pragma once

#include "mtproto/proxy/mtproxy/endpoint_health.h"

#include <map>
#include <set>

namespace MTP::details::MtProxy {

struct EndpointState {
	EndpointId endpoint;
	std::set<QString> routeKeys;
	FailureReason lastFailure = FailureReason::None;
	QString lastDiagnostic;
	crl::time terminalUntil = 0;
	int active = 0;
	int consecutiveFailures = 0;
	int recipeLevel = 0;
	crl::time nextHandshakeAt = 0;
	bool healthy = false;
	bool halfOpen = false;
	uint64 proxyGeneration = 0;
	uint64 proxyEpoch = 1;
	uint64 lastAttemptId = 0;
	std::map<uint64, crl::time> attemptStarts;
	crl::time deniedSince = 0;
	crl::time lastDenialRotationSignal = 0;
	crl::time lastSuccessAt = 0;
	int exhaustedSinceSuccess = 0;
	bool relayProven = false;
	uint64 successEpoch = 0;
	crl::time lastRelaySuccessAt = 0;
	ProxyTlsProfile lastGoodProfile = ProxyTlsProfile::Auto;
	RouteEndpoint lastGoodRoute;
};

struct RouteState {
	RouteEndpoint route;
	FailureReason lastFailure = FailureReason::None;
	bool healthy = false;
	int relaySuspect = 0;
};

struct EndpointConcurrencyPolicy {
	int activeCap = 0;
	crl::time handshakeSpacing = 0;
	crl::time retryAfter = 0;
	bool recipeEscalationAllowed = false;
	bool useAllowed = true;
};

struct CapabilitySuccess {
	QString proxyKey;
	QString routeKey;
	QString route;
	ProxyTlsProfile sentProfile = ProxyTlsProfile::Auto;
	ProxyStealthOptions stealth;
	int recipeLevel = 0;
	bool relayProven = false;
};

struct CapabilityFailure {
	QString proxyKey;
	QString routeKey;
	QString diagnostic;
};


} // namespace MTP::details::MtProxy
