/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "mtproto/proxy/capabilities.h"

#include "base/bytes.h"
#include "base/qt/qt_string_view.h"
#include "settings.h"

#include <QtCore/QCryptographicHash>
#include <QtCore/QDir>
#include <QtCore/QFile>
#include <QtCore/QJsonArray>
#include <QtCore/QJsonDocument>
#include <QtCore/QJsonObject>
#include <QtCore/QSaveFile>

#include <algorithm>

namespace MTP {
namespace {

constexpr auto kMaxStoredRoutes = 16;

[[nodiscard]] QByteArray BytesToQByteArray(bytes::const_span data) {
	auto result = QByteArray();
	result.reserve(int(data.size()));
	for (const auto byte : data) {
		result.append(char(gsl::to_integer<unsigned char>(byte)));
	}
	return result;
}

[[nodiscard]] QString HashBytes(bytes::const_span data) {
	const auto hash = QCryptographicHash::hash(
		BytesToQByteArray(data),
		QCryptographicHash::Sha256);
	return QString::fromLatin1(hash.toHex());
}

[[nodiscard]] QString HashText(const QString &text) {
	const auto hash = QCryptographicHash::hash(
		text.toUtf8(),
		QCryptographicHash::Sha256);
	return QString::fromLatin1(hash.toHex());
}

[[nodiscard]] QString DomainFromSecret(bytes::const_span secret) {
	if (secret.size() <= 17) {
		return QString();
	}
	return QString::fromUtf8(BytesToQByteArray(secret.subspan(17)));
}

[[nodiscard]] QString ProxyCapabilityHost(const ProxyData &proxy) {
	return proxy.originalHost.isEmpty()
		? proxy.host
		: proxy.originalHost;
}

[[nodiscard]] QString ProxyCapabilitySecretHash(const ProxyData &proxy) {
	if (proxy.type == ProxyData::Type::Mtproto) {
		const auto secret = proxy.secretFromMtprotoPassword();
		if (!secret.empty()) {
			return HashBytes(bytes::make_span(secret));
		}
	}
	return (proxy.type == ProxyData::Type::Mtproto)
		? HashText(proxy.password)
		: HashText(proxy.user + ':' + proxy.password);
}

[[nodiscard]] QString ProxyCapabilityDomain(const ProxyData &proxy) {
	if (proxy.type != ProxyData::Type::Mtproto) {
		return QString();
	}
	const auto secret = proxy.secretFromMtprotoPassword();
	return secret.empty()
		? QString()
		: DomainFromSecret(bytes::make_span(secret));
}

[[nodiscard]] QString CapabilitiesPath() {
	const auto dir = cWorkingDir() + u"tdata/"_q;
	QDir().mkpath(dir);
	return dir + u"proxy-capabilities.json"_q;
}

[[nodiscard]] QString TransportName(ProxyCapabilityTransport value) {
	switch (value) {
	case ProxyCapabilityTransport::Tcp:
		return u"Tcp"_q;
	case ProxyCapabilityTransport::MtproxyFakeTlsTcp:
		return u"MtproxyFakeTlsTcp"_q;
	case ProxyCapabilityTransport::Wss:
		return u"Wss"_q;
	case ProxyCapabilityTransport::Unknown:
		return QString();
	}
	return QString();
}

[[nodiscard]] ProxyCapabilityTransport TransportFromName(
		const QString &value) {
	if (value == u"Tcp"_q) {
		return ProxyCapabilityTransport::Tcp;
	} else if (value == u"MtproxyFakeTlsTcp"_q) {
		return ProxyCapabilityTransport::MtproxyFakeTlsTcp;
	} else if (value == u"Wss"_q) {
		return ProxyCapabilityTransport::Wss;
	}
	return ProxyCapabilityTransport::Unknown;
}

[[nodiscard]] QString ProfileName(ProxyTlsProfile value) {
	switch (value) {
	case ProxyTlsProfile::Auto:
		return u"Auto"_q;
	case ProxyTlsProfile::Firefox:
		return u"Firefox"_q;
	case ProxyTlsProfile::AndroidChrome:
		return u"AndroidChrome"_q;
	case ProxyTlsProfile::Yandex:
		return u"Yandex"_q;
	case ProxyTlsProfile::FirefoxAndroid:
		return u"FirefoxAndroid"_q;
	case ProxyTlsProfile::AndroidOkHttp:
		return u"AndroidOkHttp"_q;
	case ProxyTlsProfile::AutoRotate:
		return u"AutoRotate"_q;
	case ProxyTlsProfile::ChromeModern:
		return u"ChromeModern"_q;
	}
	return u"Auto"_q;
}

[[nodiscard]] ProxyTlsProfile ProfileFromName(const QString &value) {
	if (value == u"Firefox"_q) {
		return ProxyTlsProfile::Firefox;
	} else if (value == u"AndroidChrome"_q) {
		return ProxyTlsProfile::AndroidChrome;
	} else if (value == u"Yandex"_q) {
		return ProxyTlsProfile::Yandex;
	} else if (value == u"FirefoxAndroid"_q) {
		return ProxyTlsProfile::FirefoxAndroid;
	} else if (value == u"AndroidOkHttp"_q) {
		return ProxyTlsProfile::AndroidOkHttp;
	} else if (value == u"AutoRotate"_q) {
		return ProxyTlsProfile::AutoRotate;
	} else if (value == u"ChromeModern"_q) {
		return ProxyTlsProfile::ChromeModern;
	}
	return ProxyTlsProfile::Auto;
}

[[nodiscard]] std::vector<QString> ReadStringVector(
		const QJsonObject &object,
		const QString &key) {
	auto result = std::vector<QString>();
	const auto array = object.value(key).toArray();
	result.reserve(array.size());
	for (const auto &value : array) {
		const auto route = value.toString();
		if (!route.isEmpty()) {
			result.push_back(route);
		}
	}
	return result;
}

[[nodiscard]] QJsonArray WriteStringVector(
		const std::vector<QString> &values) {
	auto result = QJsonArray();
	for (const auto &value : values) {
		result.append(value);
	}
	return result;
}

[[nodiscard]] ProxyCapabilityCard ReadCard(const QJsonObject &object) {
	auto result = ProxyCapabilityCard();
	result.proxyKey = object.value("proxyKey").toString();
	result.lastGoodTransport = TransportFromName(
		object.value("lastGoodTransport").toString());
	result.lastGoodProfile = ProfileFromName(
		object.value("lastGoodProfile").toString());
	result.wssAllowed = object.value("wssAllowed").toBool(true);
	result.syntheticPskAllowed = object.value(
		"syntheticPskAllowed").toBool(false);
	result.fragmentationAllowed = object.value(
		"fragmentationAllowed").toBool(false);
	result.lastSuccessAt = crl::time(
		object.value("lastSuccessAt").toDouble());
	result.lastFailureClass = object.value(
		"lastFailureClass").toString();
	result.badRoutes = ReadStringVector(object, "badRoutes");
	result.goodRoutes = ReadStringVector(object, "goodRoutes");
	result.wssBlockedUntil = crl::time(
		object.value("wssBlockedUntil").toDouble());
	return result;
}

[[nodiscard]] QJsonObject WriteCard(const ProxyCapabilityCard &card) {
	auto result = QJsonObject();
	result.insert("proxyKey", card.proxyKey);
	result.insert(
		"lastGoodTransport",
		TransportName(card.lastGoodTransport));
	result.insert("lastGoodProfile", ProfileName(card.lastGoodProfile));
	result.insert("wssAllowed", card.wssAllowed);
	result.insert("syntheticPskAllowed", card.syntheticPskAllowed);
	result.insert("fragmentationAllowed", card.fragmentationAllowed);
	result.insert("lastSuccessAt", double(card.lastSuccessAt));
	result.insert("lastFailureClass", card.lastFailureClass);
	result.insert("badRoutes", WriteStringVector(card.badRoutes));
	result.insert("goodRoutes", WriteStringVector(card.goodRoutes));
	result.insert("wssBlockedUntil", double(card.wssBlockedUntil));
	return result;
}

void AddRoute(std::vector<QString> &routes, const QString &routeKey) {
	if (routeKey.isEmpty()) {
		return;
	}
	const auto i = std::find(begin(routes), end(routes), routeKey);
	if (i != end(routes)) {
		routes.erase(i);
	}
	routes.insert(routes.begin(), routeKey);
	if (routes.size() > kMaxStoredRoutes) {
		routes.resize(kMaxStoredRoutes);
	}
}

void RemoveRoute(std::vector<QString> &routes, const QString &routeKey) {
	const auto i = std::find(begin(routes), end(routes), routeKey);
	if (i != end(routes)) {
		routes.erase(i);
	}
}

} // namespace

ProxyCapabilityCache &ProxyCapabilityCache::Instance() {
	static auto result = ProxyCapabilityCache();
	return result;
}

ProxyCapabilityCard ProxyCapabilityCache::lookup(const ProxyData &proxy) {
	return lookup(ProxyCapabilityKey(proxy));
}

ProxyCapabilityCard ProxyCapabilityCache::lookup(const QString &proxyKey) {
	QMutexLocker lock(&_mutex);
	load();
	const auto i = _cards.find(proxyKey);
	if (i != end(_cards)) {
		return i->second;
	}
	auto result = ProxyCapabilityCard();
	result.proxyKey = proxyKey;
	return result;
}

bool ProxyCapabilityCache::wssAllowed(const ProxyData &proxy) {
	const auto card = lookup(proxy);
	return card.wssAllowed || card.wssBlockedUntil <= crl::now();
}

void ProxyCapabilityCache::noteWssRemoteClosed(
		const ProxyData &proxy,
		crl::time ttl) {
	const auto key = ProxyCapabilityKey(proxy);
	if (key.isEmpty()) {
		return;
	}
	QMutexLocker lock(&_mutex);
	load();
	auto &card = _cards[key];
	card.proxyKey = key;
	card.wssAllowed = false;
	card.wssBlockedUntil = crl::now() + ttl;
	card.lastFailureClass = u"remote_closed"_q;
	save();
}

void ProxyCapabilityCache::noteMtproxySuccess(
		const QString &proxyKey,
		const QString &routeKey,
		ProxyTlsProfile sentProfile,
		const ProxyStealthOptions &stealth) {
	if (proxyKey.isEmpty()) {
		return;
	}
	QMutexLocker lock(&_mutex);
	load();
	auto &card = _cards[proxyKey];
	card.proxyKey = proxyKey;
	card.lastGoodTransport = ProxyCapabilityTransport::MtproxyFakeTlsTcp;
	card.lastGoodProfile = sentProfile;
	card.lastSuccessAt = crl::now();
	card.lastFailureClass.clear();
	if (stealth.syntheticPsk) {
		card.syntheticPskAllowed = true;
	}
	if (stealth.clientHelloFragmentation
			!= ProxyClientHelloFragmentation::Off) {
		card.fragmentationAllowed = true;
	}
	AddRoute(card.goodRoutes, routeKey);
	RemoveRoute(card.badRoutes, routeKey);
	save();
}

void ProxyCapabilityCache::noteMtproxyFailure(
		const QString &proxyKey,
		const QString &routeKey,
		const QString &failureClass) {
	if (proxyKey.isEmpty()) {
		return;
	}
	QMutexLocker lock(&_mutex);
	load();
	auto &card = _cards[proxyKey];
	card.proxyKey = proxyKey;
	card.lastFailureClass = failureClass;
	AddRoute(card.badRoutes, routeKey);
	save();
}

void ProxyCapabilityCache::load() {
	if (_loaded) {
		return;
	}
	_loaded = true;
	const auto data = [&] {
		auto file = QFile(CapabilitiesPath());
		return file.open(QIODevice::ReadOnly) ? file.readAll() : QByteArray();
	}();
	const auto document = QJsonDocument::fromJson(data);
	if (!document.isObject()) {
		return;
	}
	const auto array = document.object().value("cards").toArray();
	for (const auto &value : array) {
		const auto object = value.toObject();
		auto card = ReadCard(object);
		if (!card.proxyKey.isEmpty()) {
			_cards[card.proxyKey] = std::move(card);
		}
	}
}

void ProxyCapabilityCache::save() {
	auto cards = QJsonArray();
	for (const auto &[key, card] : _cards) {
		if (!key.isEmpty()) {
			cards.append(WriteCard(card));
		}
	}
	auto root = QJsonObject();
	root.insert("cards", cards);
	auto file = QSaveFile(CapabilitiesPath());
	if (file.open(QIODevice::WriteOnly)) {
		file.write(QJsonDocument(root).toJson(QJsonDocument::Indented));
		file.commit();
	}
}

QString ProxyCapabilityKey(const ProxyData &proxy) {
	const auto host = ProxyCapabilityHost(proxy);
	if (host.isEmpty() || proxy.port <= 0) {
		return QString();
	}
	const auto port = QString::number(proxy.port);
	return host
		+ ':'
		+ port
		+ ':'
		+ QString::number(int(proxy.type))
		+ ':'
		+ QString::number(int(proxy.type))
		+ ':'
		+ ProxyCapabilitySecretHash(proxy)
		+ ':'
		+ ProxyCapabilityDomain(proxy);
}

} // namespace MTP
