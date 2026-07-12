/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "mtproto/runtime/runtime_environment.h"

#include "base/random.h"
#include "base/timer.h"
#include "core/application.h"
#include "core/core_settings.h"
#include "lang/lang_cloud_manager.h"
#include "lang/lang_instance.h"
#include "logs.h"
#include "mtproto/proxy/diagnostics.h"
#include "mtproto/proxy/endpoint_admission_arbiter.h"
#include "mtproto/proxy/proxy_endpoint_context.h"
#include "mtproto/proxy/proxy_services.h"
#include "settings.h"
#include "storage/localstorage.h"

#include <QtCore/QDir>
#include <QtCore/QTimer>

namespace MTP {
namespace {

RuntimeProxySettings CreateProxySettings() {
	return {
		.enabled = [] {
			return Core::App().settings().proxy().isEnabled();
		},
		.selected = [] {
			return Core::App().settings().proxy().selected();
		},
		.settings = [] {
			return Core::App().settings().proxy().settings();
		},
		.tryIPv6 = [] {
			return Core::App().settings().proxy().tryIPv6();
		},
		.fastProxyWarmup = [] {
			return Core::App().settings().proxy().fastWarmup();
		},
		.stealthOptions = [] {
			return Core::App().settings().proxyStealthOptions();
		},
		.watchConnectionTypeChanges = [](
				Fn<void()> callback,
				rpl::lifetime &lifetime) {
			Core::App().settings().proxy().connectionTypeChanges(
			) | rpl::on_next([callback = std::move(callback)] {
				callback();
			}, lifetime);
		},
		.applyDomainIps = [](
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
		},
		.promoteDomainIp = [](
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
		},
	};
}

RuntimeDeviceSettings CreateDeviceSettings() {
	return {
		.model = [] {
			return Core::App().settings().customDeviceModel();
		},
		.watchModelChanges = [](
				Fn<void(QString)> callback,
				rpl::lifetime &lifetime) {
			Core::App().settings().customDeviceModelChanges(
			) | rpl::on_next([callback = std::move(callback)](
					const QString &value) {
				callback(value);
			}, lifetime);
		},
	};
}

RuntimeLanguageGateway CreateLanguageGateway() {
	return {
		.systemCode = [] {
			return Lang::GetInstance().systemLangCode();
		},
		.cloudCode = [] {
			return Lang::GetInstance().cloudLangCode(Lang::Pack::Current);
		},
		.packName = [] {
			return Lang::GetInstance().langPackName();
		},
		.setSuggested = [](const QString &lang) {
			Lang::CurrentCloudManager().setSuggestedLanguage(lang);
		},
		.setCurrentVersions = [](int version, int baseVersion) {
			Lang::CurrentCloudManager().setCurrentVersions(version, baseVersion);
		},
		.resetToDefault = [] {
			Lang::CurrentCloudManager().resetToDefault();
		},
	};
}

RuntimeStorageGateway CreateStorageGateway() {
	return {
		.writeSettings = [] {
			Local::writeSettings();
		},
		.writeAutoupdatePrefix = [](const QString &prefix) {
			Local::writeAutoupdatePrefix(prefix);
		},
	};
}

RuntimeAppGateway CreateAppGateway() {
	return {
		.refreshGlobalProxy = [] {
			Core::App().refreshGlobalProxy();
		},
		.badMtprotoConfigurationError = [] {
			Core::App().badMtprotoConfigurationError();
		},
	};
}

RuntimeDiagnosticsGateway CreateDiagnosticsGateway() {
	return {
		.writeProxyDiagnosticsLine = [](ProxyDiagnosticsEvent event) {
			Logs::writeMtproxy(FormatProxyDiagnosticsEvent(event));
		},
	};
}

RuntimeProxyCapabilities CreateProxyCapabilities() {
	return {
		.path = [] {
			const auto dir = cWorkingDir() + u"tdata/"_q;
			QDir().mkpath(dir);
			return dir + u"proxy-capabilities.json"_q;
		},
	};
}

RuntimeAsyncGateway CreateAsyncGateway() {
	return {
		.now = [] {
			return crl::now();
		},
		.randomIndex = [](int limit) {
			return base::RandomIndex(limit);
		},
		.singleShot = [](
				crl::time delay,
				QObject *context,
				Fn<void()> callback) {
			QTimer::singleShot(int(delay), context, [
				callback = std::move(callback)
			] {
				callback();
			});
		},
		.makeTimer = [](
				not_null<QThread*> thread,
				Fn<void()> callback) {
			const auto timer = std::make_shared<base::Timer>(
				thread,
				std::move(callback));
			return RuntimeTimer(
				[timer](crl::time delay) {
					timer->callOnce(delay);
				},
				[timer](crl::time delay) {
					timer->callEach(delay);
				},
				[timer] {
					timer->cancel();
				},
				[timer] {
					return timer->isActive();
				});
		},
	};
}

RuntimeEnvironmentDescriptor CreateRuntimeDescriptor() {
	return {
		.proxy = CreateProxySettings(),
		.device = CreateDeviceSettings(),
		.language = CreateLanguageGateway(),
		.storage = CreateStorageGateway(),
		.app = CreateAppGateway(),
		.diagnostics = CreateDiagnosticsGateway(),
		.proxyCapabilities = CreateProxyCapabilities(),
		.async = CreateAsyncGateway(),
	};
}

} // namespace

RuntimeEnvironment::RuntimeEnvironment(
	RuntimeEnvironmentDescriptor descriptor,
	std::shared_ptr<ProxyEndpointContext> endpointContext)
: _proxyEndpointContext(endpointContext
	? std::move(endpointContext)
	: CreateProxyEndpointContext())
, _proxyRuntimeId(_proxyEndpointContext->registerRuntime())
, _descriptor(std::move(descriptor))
, _proxyServices(std::make_unique<ProxyServices>(this)) {
	_proxyEndpointContext->endpointAdmissionArbiter().bindRuntime(
		_proxyRuntimeId,
		{
			.dispatcher = this,
			.now = _descriptor.async.now,
			.randomIndex = _descriptor.async.randomIndex,
			.singleShot = _descriptor.async.singleShot,
			.fastProxyWarmup = _descriptor.proxy.fastProxyWarmup,
		});
	_descriptor.diagnostics.reportProxyEvent = [=](ProxyEventReport report) {
		const auto runtime = not_null{ this };
		proxyServices().control().submitFact(report);
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
			.configuredProfile = std::move(report.configuredProfile),
			.effectiveProfile = std::move(report.effectiveProfile),
			.recipeLevel = report.recipeLevel,
			.pskOffered = report.pskOffered,
			.fragmentedClientHello = report.fragmentedClientHello,
			.phaseAtFailure = std::move(report.phaseAtFailure),
			.queueMs = report.queueMs,
			.clientHelloBytes = report.clientHelloBytes,
			.clientHelloWrites = report.clientHelloWrites,
			.clientHelloAcceptedBytes = report.clientHelloAcceptedBytes,
			.clientHelloFragmentSplit = report.clientHelloFragmentSplit,
			.clientHelloFragmentDelayMs = report.clientHelloFragmentDelayMs,
			.rxAfterClientHello = report.rxAfterClientHello,
			.rxClass = std::move(report.rxClass),
			.tlsRecordType = std::move(report.tlsRecordType),
			.tlsRecordVersion = std::move(report.tlsRecordVersion),
			.tlsRecordLength = report.tlsRecordLength,
			.responsePrefixHash = std::move(report.responsePrefixHash),
			.sniLength = report.sniLength,
			.sniHash = std::move(report.sniHash),
			.parserStage = std::move(report.parserStage),
			.closeOrigin = report.closeOrigin,
			.dnsMs = report.dnsMs,
			.tcpMs = report.tcpMs,
			.firstRxMs = report.firstRxMs,
			.serverHelloMs = report.serverHelloMs,
			.appDataMs = report.appDataMs,
			.mtprotoMs = report.mtprotoMs,
			.totalMs = report.totalMs,
			.traceSchema = report.traceSchema,
		});
	};
}

RuntimeEnvironment::~RuntimeEnvironment() {
	_proxyServices->broker().cancelByOwnerDestruction();
	const auto attempts = _proxyEndpointContext->activeTracesForRuntime(
		_proxyRuntimeId);
	if (!attempts.empty()) {
		const auto proxy = _descriptor.proxy.selected
			? _descriptor.proxy.selected()
			: ProxyData();
		for (const auto &attempt : attempts) {
			(void)ReportProxyAttemptSummary(not_null{ this }, {
				.attempt = attempt,
				.severity = ProxyDiagnosticsSeverity::Warning,
				.proxy = proxy,
				.message = u"proxy attempt owner destroyed"_q,
				.closeOrigin = ProxyCloseOrigin::OwnerDestroyed,
			});
		}
	}
	_proxyServices.reset();
	_proxyEndpointContext->unregisterRuntime(_proxyRuntimeId);
}

void RuntimeEnvironment::bindInstance(RuntimeInstanceServices services) {
	Expects(!_instance.connectionStatus);

	_instance = std::move(services);
}

void RuntimeEnvironment::unbindInstance(ConnectionStatus *status) {
	if (_instance.connectionStatus == status) {
		_instance = RuntimeInstanceServices();
	}
}

const RuntimeProxySettings &RuntimeEnvironment::proxy() const {
	return _descriptor.proxy;
}

const RuntimeDeviceSettings &RuntimeEnvironment::device() const {
	return _descriptor.device;
}

const RuntimeLanguageGateway &RuntimeEnvironment::language() const {
	return _descriptor.language;
}

const RuntimeStorageGateway &RuntimeEnvironment::storage() const {
	return _descriptor.storage;
}

const RuntimeAppGateway &RuntimeEnvironment::app() const {
	return _descriptor.app;
}

const RuntimeDiagnosticsGateway &RuntimeEnvironment::diagnostics() const {
	return _descriptor.diagnostics;
}

const RuntimeInstanceServices &RuntimeEnvironment::instance() const {
	return _instance;
}

const RuntimeProxyResolver &RuntimeEnvironment::proxyResolver() const {
	return _instance.proxyResolver;
}

const RuntimeProxyCapabilities &RuntimeEnvironment::proxyCapabilities() const {
	return _descriptor.proxyCapabilities;
}

const RuntimeAsyncGateway &RuntimeEnvironment::async() const {
	return _descriptor.async;
}

ProxyServices &RuntimeEnvironment::proxyServices() const {
	return *_proxyServices;
}

ProxyRuntimeId RuntimeEnvironment::proxyRuntimeId() const {
	return _proxyRuntimeId;
}

ProxyEndpointContext &RuntimeEnvironment::proxyEndpointContext() const {
	return *_proxyEndpointContext;
}

auto RuntimeEnvironment::proxyEndpointContextShared() const
-> std::shared_ptr<ProxyEndpointContext> {
	return _proxyEndpointContext;
}

std::shared_ptr<RuntimeEnvironment> CreateRuntimeEnvironment() {
	return CreateRuntimeEnvironment(CreateProxyEndpointContext());
}

std::shared_ptr<RuntimeEnvironment> CreateRuntimeEnvironment(
		std::shared_ptr<ProxyEndpointContext> endpointContext) {
	return std::make_shared<RuntimeEnvironment>(
		CreateRuntimeDescriptor(),
		std::move(endpointContext));
}

not_null<RuntimeEnvironment*> DefaultRuntimeEnvironment() {
	static const auto Result = CreateRuntimeEnvironment();
	return not_null{ Result.get() };
}

} // namespace MTP
