/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "mtproto/proxy/mtproxy/endpoint_health_diagnostics.h"

namespace MTP::details::MtProxy {

[[nodiscard]] QString CanonicalText(const EndpointId &endpoint) {
	return ProxyDiagnosticsEndpointText(
		endpoint.canonical.originalHost,
		endpoint.canonical.port);
}

[[nodiscard]] QString RouteText(const EndpointId &endpoint) {
	return ProxyDiagnosticsEndpointText(
		endpoint.route.address,
		endpoint.route.port);
}

[[nodiscard]] ProxyDiagnosticsEvent CanonicalDiagnosticsEvent(
		ProxyDiagnosticsPhase phase,
		const EndpointState &state,
		FailureReason reason,
		const QString &message) {
	return {
		.source = ProxyDiagnosticsSource::MTProxy,
		.phase = phase,
		.severity = (phase == ProxyDiagnosticsPhase::CanonicalRecovered)
			? ProxyDiagnosticsSeverity::Info
			: ProxyDiagnosticsSeverity::Warning,
		.error = ToProxyConnectionError(reason),
		.mtproxyReason = ToProxyMtproxyTerminalReason(reason),
		.terminalUntil = state.terminalUntil,
		.transport = ProxyDiagnosticsTransportName(
			state.endpoint.canonical.proxyKind,
			state.endpoint.route.transport),
		.message = message,
		.canonical = CanonicalText(state.endpoint),
		.route = RouteText(state.endpoint),
		.proxyKeyHash = ProxyDiagnosticsKeyHash(
			EndpointKey(state.endpoint.canonical)),
		.recipeLevel = state.recipeLevel,
		.phaseAtFailure = ToLegacyDiagnostic(reason),
	};
}

void LogStaleAttemptFailure(
		const FailureReport &report,
		int recipeLevel) {
	WriteProxyDiagnosticsLine({
		.source = ProxyDiagnosticsSource::MTProxy,
		.phase = ProxyDiagnosticsPhase::RouteFailed,
		.severity = ProxyDiagnosticsSeverity::Info,
		.error = ToProxyConnectionError(report.reason),
		.mtproxyReason = ToProxyMtproxyTerminalReason(report.reason),
		.transport = ProxyDiagnosticsTransportName(
			report.endpoint.canonical.proxyKind,
			report.endpoint.route.transport),
		.message = u"stale_attempt_failed"_q,
		.canonical = CanonicalText(report.endpoint),
		.route = RouteText(report.endpoint),
		.proxyKeyHash = ProxyDiagnosticsKeyHash(
			EndpointKey(report.endpoint.canonical)),
		.recipeLevel = recipeLevel,
		.phaseAtFailure = ToLegacyDiagnostic(report.reason),
	});
}

void LogProbeAttemptFailure(const FailureReport &report) {
	WriteProxyDiagnosticsLine({
		.source = ProxyDiagnosticsSource::MTProxy,
		.phase = ProxyDiagnosticsPhase::RouteFailed,
		.severity = ProxyDiagnosticsSeverity::Info,
		.error = ToProxyConnectionError(report.reason),
		.mtproxyReason = ToProxyMtproxyTerminalReason(report.reason),
		.transport = ProxyDiagnosticsTransportName(
			report.endpoint.canonical.proxyKind,
			report.endpoint.route.transport),
		.message = u"probe_attempt_failed"_q,
		.canonical = CanonicalText(report.endpoint),
		.route = RouteText(report.endpoint),
		.proxyKeyHash = ProxyDiagnosticsKeyHash(
			EndpointKey(report.endpoint.canonical)),
		.phaseAtFailure = ToLegacyDiagnostic(report.reason),
	});
}

void LogProbeAttemptSuccess(const SuccessReport &report) {
	WriteProxyDiagnosticsLine({
		.source = ProxyDiagnosticsSource::MTProxy,
		.phase = ProxyDiagnosticsPhase::ProxyCheckFinished,
		.severity = ProxyDiagnosticsSeverity::Info,
		.transport = ProxyDiagnosticsTransportName(
			report.endpoint.canonical.proxyKind,
			report.endpoint.route.transport),
		.message = u"probe_attempt_succeeded"_q,
		.canonical = CanonicalText(report.endpoint),
		.route = RouteText(report.endpoint),
		.proxyKeyHash = ProxyDiagnosticsKeyHash(
			EndpointKey(report.endpoint.canonical)),
	});
}


} // namespace MTP::details::MtProxy
