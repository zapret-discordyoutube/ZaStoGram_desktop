/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#pragma once

#include "mtproto/proxy/mtproxy/endpoint_health_state.h"
#include "mtproto/proxy/diagnostics.h"

namespace MTP {
class RuntimeEnvironment;
} // namespace MTP

namespace MTP::details::MtProxy {

[[nodiscard]] QString CanonicalText(const EndpointId &endpoint);
[[nodiscard]] QString RouteText(const EndpointId &endpoint);
[[nodiscard]] ProxyDiagnosticsEvent CanonicalDiagnosticsEvent(
	ProxyDiagnosticsPhase phase,
	const EndpointState &state,
	FailureReason reason,
	const QString &message);
void LogStaleAttemptFailure(
	not_null<RuntimeEnvironment*> runtime,
	const FailureReport &report,
	int recipeLevel);
void LogProbeAttemptFailure(
	not_null<RuntimeEnvironment*> runtime,
	const FailureReport &report);
void LogProbeAttemptSuccess(
	not_null<RuntimeEnvironment*> runtime,
	const SuccessReport &report);

} // namespace MTP::details::MtProxy
