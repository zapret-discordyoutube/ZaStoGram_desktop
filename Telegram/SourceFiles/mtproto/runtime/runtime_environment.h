/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#pragma once

#include "base/basic_types.h"
#include "mtproto/dc_id.h"
#include "mtproto/config/mtproto_dc_options.h"
#include "mtproto/proxy/data.h"
#include "rpl/lifetime.h"

#include <QtCore/QObject>
#include <QtCore/QStringList>

#include <memory>

namespace MTP {

class ConnectionStatus;
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

struct RuntimeEnvironment final : public QObject {
	RuntimeProxySettings proxy;
	RuntimeDeviceSettings device;
	RuntimeLanguageGateway language;
	RuntimeStorageGateway storage;
	RuntimeAppGateway app;
	ConnectionStatus *connectionStatus = nullptr;

	Fn<void(ProxyDiagnosticsEvent)> writeProxyDiagnosticsLine;
	Fn<void(ProxyEventReport)> reportProxyEvent;
	Fn<DcId()> mainDcId;
	Fn<DcOptions::Variants(DcId, DcType, bool)> dcOptionsLookup;
	Fn<void(QString)> resolveProxyDomain;
	Fn<void(QString, QString)> setGoodProxyDomain;
	Fn<void(QString, QStringList, qint64)> proxyDomainResolved;
	Fn<QString()> proxyCapabilitiesPath;
	Fn<void()> syncHttpUnixtime;
};

[[nodiscard]] std::shared_ptr<RuntimeEnvironment> CreateRuntimeEnvironment();
[[nodiscard]] not_null<RuntimeEnvironment*> DefaultRuntimeEnvironment();

} // namespace MTP
