/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#pragma once

#include "base/basic_types.h"
#include "mtproto/dc_id.h"
#include "mtproto/mtproto_dc_options.h"

#include <QtCore/QObject>
#include <QtCore/QStringList>

#include <memory>

namespace MTP {

struct ProxyConnectionStatus;
struct ProxyDiagnosticsEvent;
struct ProxyEventReport;

struct RuntimeEnvironment final : public QObject {
	Fn<void(ProxyDiagnosticsEvent)> writeProxyDiagnosticsLine;
	Fn<void(ProxyEventReport)> reportProxyEvent;
	Fn<ProxyConnectionStatus()> proxyConnectionStatus;
	Fn<void(ProxyConnectionStatus)> setProxyConnectionStatus;
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
