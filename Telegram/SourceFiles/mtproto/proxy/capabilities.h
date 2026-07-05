/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#pragma once

#include "mtproto/proxy/data.h"

#include <QtCore/QMutex>

#include <map>

namespace MTP {

enum class ProxyCapabilityTransport {
	Unknown,
	Tcp,
	MtproxyFakeTlsTcp,
	Wss,
};

struct ProxyCapabilityCard {
	QString proxyKey;
	ProxyCapabilityTransport lastGoodTransport
		= ProxyCapabilityTransport::Unknown;
	ProxyTlsProfile lastGoodProfile = ProxyTlsProfile::Auto;
	bool wssAllowed = true;
	bool syntheticPskAllowed = false;
	bool fragmentationAllowed = false;
	crl::time lastSuccessAt = 0;
	QString lastFailureClass;
	std::vector<QString> badRoutes;
	std::vector<QString> goodRoutes;
	crl::time wssBlockedUntil = 0;
};

class ProxyCapabilityCache final {
public:
	[[nodiscard]] static ProxyCapabilityCache &Instance();

	[[nodiscard]] ProxyCapabilityCard lookup(const ProxyData &proxy);
	[[nodiscard]] ProxyCapabilityCard lookup(const QString &proxyKey);
	[[nodiscard]] bool wssAllowed(const ProxyData &proxy);

	void noteWssRemoteClosed(const ProxyData &proxy, crl::time ttl);
	void noteMtproxySuccess(
		const QString &proxyKey,
		const QString &routeKey,
		ProxyTlsProfile sentProfile,
		const ProxyStealthOptions &stealth);
	void noteMtproxyFailure(
		const QString &proxyKey,
		const QString &routeKey,
		const QString &failureClass);

private:
	void load();
	void save();

	QMutex _mutex;
	bool _loaded = false;
	std::map<QString, ProxyCapabilityCard> _cards;
};

[[nodiscard]] QString ProxyCapabilityKey(const ProxyData &proxy);

} // namespace MTP
