/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "mtproto/runtime_environment.h"

#include "logs.h"
#include "mtproto/proxy/control_plane.h"
#include "mtproto/proxy/diagnostics.h"
#include "settings.h"

#include <QtCore/QDir>

namespace MTP {
namespace {

void InstallDefaultHandlers(not_null<RuntimeEnvironment*> runtime) {
	runtime->writeProxyDiagnosticsLine = [](ProxyDiagnosticsEvent event) {
		Logs::writeMtproxy(FormatProxyDiagnosticsEvent(event));
	};
	runtime->proxyCapabilitiesPath = [] {
		const auto dir = cWorkingDir() + u"tdata/"_q;
		QDir().mkpath(dir);
		return dir + u"proxy-capabilities.json"_q;
	};
	runtime->reportProxyEvent = [=](ProxyEventReport report) {
		ProxyControlPlane::SubmitFact(runtime, report);
		WriteProxyDiagnosticsLine(runtime, {
			.source = SourceForReport(report),
			.phase = report.phase,
			.severity = report.severity.value_or(
				(report.error == ProxyConnectionError::None)
					? ProxyDiagnosticsSeverity::Info
					: ProxyDiagnosticsSeverity::Error),
			.error = report.error,
			.mtproxyReason = report.mtproxyReason,
			.attempt = report.attempt,
			.terminalUntil = report.terminalUntil,
			.proxy = std::move(report.proxy),
			.transport = std::move(report.transport),
			.dc = std::move(report.dc),
			.connectionId = std::move(report.connectionId),
			.message = std::move(report.message),
			.canonical = std::move(report.canonical),
			.route = std::move(report.route),
			.proxyKeyHash = std::move(report.proxyKeyHash),
			.profile = std::move(report.profile),
			.recipeLevel = report.recipeLevel,
			.pskOffered = report.pskOffered,
			.pskOfferedKnown = report.pskOfferedKnown,
			.fragmentedClientHello = report.fragmentedClientHello,
			.fragmentedClientHelloKnown = report.fragmentedClientHelloKnown,
			.phaseAtFailure = std::move(report.phaseAtFailure),
			.queueMs = report.queueMs,
		});
	};
}

} // namespace

std::shared_ptr<RuntimeEnvironment> CreateRuntimeEnvironment() {
	auto result = std::make_shared<RuntimeEnvironment>();
	InstallDefaultHandlers(not_null{ result.get() });
	return result;
}

not_null<RuntimeEnvironment*> DefaultRuntimeEnvironment() {
	static const auto Result = CreateRuntimeEnvironment();
	return not_null{ Result.get() };
}

} // namespace MTP
