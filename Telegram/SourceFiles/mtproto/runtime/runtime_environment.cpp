/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "mtproto/runtime/runtime_environment.h"

#include "core/application.h"
#include "core/core_settings.h"
#include "lang/lang_cloud_manager.h"
#include "lang/lang_instance.h"
#include "logs.h"
#include "mtproto/proxy/control_plane.h"
#include "mtproto/proxy/diagnostics.h"
#include "settings.h"
#include "storage/localstorage.h"

#include <QtCore/QDir>

namespace MTP {
namespace {

void InstallProxySettings(not_null<RuntimeEnvironment*> runtime) {
	runtime->proxy.enabled = [] {
		return Core::App().settings().proxy().isEnabled();
	};
	runtime->proxy.selected = [] {
		return Core::App().settings().proxy().selected();
	};
	runtime->proxy.settings = [] {
		return Core::App().settings().proxy().settings();
	};
	runtime->proxy.tryIPv6 = [] {
		return Core::App().settings().proxy().tryIPv6();
	};
	runtime->proxy.stealthOptions = [] {
		return Core::App().settings().proxyStealthOptions();
	};
	runtime->proxy.watchConnectionTypeChanges = [](
			Fn<void()> callback,
			rpl::lifetime &lifetime) {
		Core::App().settings().proxy().connectionTypeChanges(
		) | rpl::on_next([callback = std::move(callback)] {
			callback();
		}, lifetime);
	};
	runtime->proxy.applyDomainIps = [](
			const QString &host,
			const QStringList &ips,
			crl::time expireAt) {
		auto &settings = Core::App().settings().proxy();
		const auto applyToProxy = [&](ProxyData &proxy) {
			if (!proxy.tryCustomResolve() || proxy.host != host) {
				return false;
			}
			proxy.resolvedExpireAt = expireAt;
			auto copy = ips;
			auto &current = proxy.resolvedIPs;
			const auto i = ranges::remove_if(current, [&](const QString &ip) {
				const auto index = copy.indexOf(ip);
				if (index < 0) {
					return true;
				}
				copy.removeAt(index);
				return false;
			});
			if (i == end(current) && copy.isEmpty()) {
				return true;
			}
			current.erase(i, end(current));
			for (const auto &ip : std::as_const(copy)) {
				proxy.resolvedIPs.push_back(ip);
			}
			return true;
		};
		for (auto &proxy : settings.list()) {
			applyToProxy(proxy);
		}
		auto selected = settings.selected();
		if (!applyToProxy(selected) || !settings.isEnabled()) {
			return false;
		}
		settings.setSelected(selected);
		return true;
	};
	runtime->proxy.promoteDomainIp = [](
			const QString &host,
			const QString &ip) {
		auto &settings = Core::App().settings().proxy();
		const auto applyToProxy = [&](ProxyData &proxy) {
			if (!proxy.tryCustomResolve() || proxy.host != host) {
				return false;
			}
			auto &current = proxy.resolvedIPs;
			auto i = ranges::find(current, ip);
			if (i == end(current) || i == begin(current)) {
				return false;
			}
			while (i != begin(current)) {
				const auto j = i--;
				std::swap(*i, *j);
			}
			return true;
		};
		for (auto &proxy : settings.list()) {
			applyToProxy(proxy);
		}
		auto selected = settings.selected();
		if (!applyToProxy(selected) || !settings.isEnabled()) {
			return false;
		}
		settings.setSelected(selected);
		return true;
	};
}

void InstallDeviceSettings(not_null<RuntimeEnvironment*> runtime) {
	runtime->device.model = [] {
		return Core::App().settings().customDeviceModel();
	};
	runtime->device.watchModelChanges = [](
			Fn<void(QString)> callback,
			rpl::lifetime &lifetime) {
		Core::App().settings().customDeviceModelChanges(
		) | rpl::on_next([callback = std::move(callback)](
				const QString &value) {
			callback(value);
		}, lifetime);
	};
}

void InstallLanguageGateway(not_null<RuntimeEnvironment*> runtime) {
	runtime->language.systemCode = [] {
		return Lang::GetInstance().systemLangCode();
	};
	runtime->language.cloudCode = [] {
		return Lang::GetInstance().cloudLangCode(Lang::Pack::Current);
	};
	runtime->language.packName = [] {
		return Lang::GetInstance().langPackName();
	};
	runtime->language.setSuggested = [](const QString &lang) {
		Lang::CurrentCloudManager().setSuggestedLanguage(lang);
	};
	runtime->language.setCurrentVersions = [](int version, int baseVersion) {
		Lang::CurrentCloudManager().setCurrentVersions(version, baseVersion);
	};
	runtime->language.resetToDefault = [] {
		Lang::CurrentCloudManager().resetToDefault();
	};
}

void InstallStorageGateway(not_null<RuntimeEnvironment*> runtime) {
	runtime->storage.writeSettings = [] {
		Local::writeSettings();
	};
	runtime->storage.writeAutoupdatePrefix = [](const QString &prefix) {
		Local::writeAutoupdatePrefix(prefix);
	};
}

void InstallAppGateway(not_null<RuntimeEnvironment*> runtime) {
	runtime->app.refreshGlobalProxy = [] {
		Core::App().refreshGlobalProxy();
	};
	runtime->app.badMtprotoConfigurationError = [] {
		Core::App().badMtprotoConfigurationError();
	};
}

void InstallDefaultHandlers(not_null<RuntimeEnvironment*> runtime) {
	InstallProxySettings(runtime);
	InstallDeviceSettings(runtime);
	InstallLanguageGateway(runtime);
	InstallStorageGateway(runtime);
	InstallAppGateway(runtime);

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
