/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#pragma once

#include "base/basic_types.h"
#include "mtproto/config/mtproto_dc_options.h"
#include "mtproto/dc_id.h"
#include "mtproto/runtime/connection_status_types.h"
#include "rpl/lifetime.h"

#include <QtCore/QObject>
#include <QtCore/QThread>
#include <QtCore/QStringList>

#include <memory>

namespace MTP {

class ConnectionStatus;
class ProxyEndpointContext;
class ProxyServices;
struct ProxyDiagnosticsEvent;
struct ProxyEventReport;

struct RuntimeProxySettings final {
	Fn<bool()> enabled;
	Fn<ProxyData()> selected;
	Fn<ProxyData::Settings()> settings;
	Fn<bool()> tryIPv6;
	Fn<ProxyStealthOptions()> stealthOptions;
	Fn<void(Fn<void()>, rpl::lifetime&)> watchConnectionTypeChanges;
	Fn<bool(const QString&, const QStringList&, crl::time)> applyDomainIps;
	Fn<bool(const QString&, const QString&)> promoteDomainIp;
};

struct RuntimeDeviceSettings final {
	Fn<QString()> model;
	Fn<void(Fn<void(QString)>, rpl::lifetime&)> watchModelChanges;
};

struct RuntimeLanguageGateway final {
	Fn<QString()> systemCode;
	Fn<QString()> cloudCode;
	Fn<QString()> packName;
	Fn<void(const QString&)> setSuggested;
	Fn<void(int, int)> setCurrentVersions;
	Fn<void()> resetToDefault;
};

struct RuntimeStorageGateway final {
	Fn<void()> writeSettings;
	Fn<void(const QString&)> writeAutoupdatePrefix;
};

struct RuntimeAppGateway final {
	Fn<void()> refreshGlobalProxy;
	Fn<void()> badMtprotoConfigurationError;
};

struct RuntimeDiagnosticsGateway final {
	Fn<void(ProxyDiagnosticsEvent)> writeProxyDiagnosticsLine;
	Fn<void(ProxyEventReport)> reportProxyEvent;
};

struct RuntimeProxyResolver final {
	Fn<void(QString)> resolveDomain;
	Fn<void(QString, QString)> setGoodDomain;
	Fn<void(QString, QStringList, qint64)> domainResolved;
};

struct RuntimeInstanceServices final {
	ConnectionStatus *connectionStatus = nullptr;
	Fn<DcId()> mainDcId;
	Fn<DcOptions::Variants(DcId, DcType, bool)> dcOptionsLookup;
	RuntimeProxyResolver proxyResolver;
	Fn<void()> syncHttpUnixtime;
};

struct RuntimeProxyCapabilities final {
	Fn<QString()> path;
};

class RuntimeTimer final {
public:
	RuntimeTimer() = default;
	RuntimeTimer(
		Fn<void(crl::time)> callOnce,
		Fn<void(crl::time)> callEach,
		Fn<void()> cancel,
		Fn<bool()> isActive)
	: _callOnce(std::move(callOnce))
	, _callEach(std::move(callEach))
	, _cancel(std::move(cancel))
	, _isActive(std::move(isActive)) {
	}

	void callOnce(crl::time delay) {
		if (_callOnce) {
			_callOnce(delay);
		}
	}

	void callEach(crl::time delay) {
		if (_callEach) {
			_callEach(delay);
		}
	}

	void cancel() {
		if (_cancel) {
			_cancel();
		}
	}

	[[nodiscard]] bool isActive() const {
		return _isActive ? _isActive() : false;
	}

private:
	Fn<void(crl::time)> _callOnce;
	Fn<void(crl::time)> _callEach;
	Fn<void()> _cancel;
	Fn<bool()> _isActive;

};

struct RuntimeAsyncGateway final {
	Fn<crl::time()> now;
	Fn<int(int)> randomIndex;
	Fn<void(crl::time, QObject*, Fn<void()>)> singleShot;
	Fn<RuntimeTimer(not_null<QThread*>, Fn<void()>)> makeTimer;
};

struct RuntimeEnvironmentDescriptor final {
	RuntimeProxySettings proxy;
	RuntimeDeviceSettings device;
	RuntimeLanguageGateway language;
	RuntimeStorageGateway storage;
	RuntimeAppGateway app;
	RuntimeDiagnosticsGateway diagnostics;
	RuntimeProxyCapabilities proxyCapabilities;
	RuntimeAsyncGateway async;
};

class RuntimeEnvironment final : public QObject {
public:
	RuntimeEnvironment(
		RuntimeEnvironmentDescriptor descriptor,
		std::shared_ptr<ProxyEndpointContext> endpointContext = nullptr);
	~RuntimeEnvironment();

	void bindInstance(RuntimeInstanceServices services);
	void unbindInstance(ConnectionStatus *status);

	[[nodiscard]] const RuntimeProxySettings &proxy() const;
	[[nodiscard]] const RuntimeDeviceSettings &device() const;
	[[nodiscard]] const RuntimeLanguageGateway &language() const;
	[[nodiscard]] const RuntimeStorageGateway &storage() const;
	[[nodiscard]] const RuntimeAppGateway &app() const;
	[[nodiscard]] const RuntimeDiagnosticsGateway &diagnostics() const;
	[[nodiscard]] const RuntimeInstanceServices &instance() const;
	[[nodiscard]] const RuntimeProxyResolver &proxyResolver() const;
	[[nodiscard]] const RuntimeProxyCapabilities &proxyCapabilities() const;
	[[nodiscard]] const RuntimeAsyncGateway &async() const;
	[[nodiscard]] ProxyServices &proxyServices() const;
	[[nodiscard]] ProxyRuntimeId proxyRuntimeId() const;
	[[nodiscard]] ProxyEndpointContext &proxyEndpointContext() const;
	[[nodiscard]] auto proxyEndpointContextShared() const
		-> std::shared_ptr<ProxyEndpointContext>;

private:
	std::shared_ptr<ProxyEndpointContext> _proxyEndpointContext;
	ProxyRuntimeId _proxyRuntimeId = 0;
	RuntimeEnvironmentDescriptor _descriptor;
	std::unique_ptr<ProxyServices> _proxyServices;
	RuntimeInstanceServices _instance;

};

[[nodiscard]] std::shared_ptr<RuntimeEnvironment> CreateRuntimeEnvironment();
[[nodiscard]] std::shared_ptr<RuntimeEnvironment> CreateRuntimeEnvironment(
	std::shared_ptr<ProxyEndpointContext> endpointContext);
[[nodiscard]] not_null<RuntimeEnvironment*> DefaultRuntimeEnvironment();

} // namespace MTP
