/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "zsg_naive/zsg_warp.h"

#include "core/application.h"
#include "logs.h"
#include "settings.h"
#include "zsg_naive/zsg_naive_api.h"

#include <QtCore/QDateTime>
#include <QtCore/QDir>
#include <QtCore/QFile>
#include <QtCore/QJsonDocument>
#include <QtCore/QJsonObject>
#include <QtCore/QJsonArray>
#include <QtCore/QSaveFile>
#include <QtCore/QTimer>
#include <QtNetwork/QNetworkAccessManager>
#include <QtNetwork/QNetworkReply>
#include <QtNetwork/QNetworkRequest>

#include <atomic>

namespace Zsg::Warp {
namespace {

constexpr auto kRegisterUrl = "https://api.cloudflareclient.com/v0a2158/reg";

struct Account {
	QString privateKey;
	QString publicKey;
	QString peerPublicKey;
	QString endpointHost;
	int endpointPort = 2408;
	QString address;
	QString reserved;

	[[nodiscard]] bool valid() const {
		return !privateKey.isEmpty()
			&& !peerPublicKey.isEmpty()
			&& !endpointHost.isEmpty()
			&& !address.isEmpty();
	}
};

struct State {
	bool enabled = false;
	Account account;
	Naive::WarpHandle *handle = nullptr;
	std::unique_ptr<QNetworkAccessManager> network;
	std::unique_ptr<QTimer> timer;
	bool registering = false;
	int lastState = -1;
	int polls = 0;
	int registrations = 0; // accounts created since the last UP
	qint64 startedAt = 0;
	quint16 port = 0;
};

State &Data() {
	static auto result = State();
	return result;
}

// Read by the MTProto threads, written on the main thread.
std::atomic<int> g_port{0};

[[nodiscard]] QString FilePath() {
	return cWorkingDir() + u"tdata/zsg/warp.json"_q;
}

void Save() {
	const auto &data = Data();
	QDir().mkpath(cWorkingDir() + u"tdata/zsg"_q);
	auto account = QJsonObject();
	account.insert(u"private_key"_q, data.account.privateKey);
	account.insert(u"public_key"_q, data.account.publicKey);
	account.insert(u"peer_public_key"_q, data.account.peerPublicKey);
	account.insert(u"endpoint_host"_q, data.account.endpointHost);
	account.insert(u"endpoint_port"_q, data.account.endpointPort);
	account.insert(u"address"_q, data.account.address);
	account.insert(u"reserved"_q, data.account.reserved);
	auto root = QJsonObject();
	root.insert(u"enabled"_q, data.enabled);
	root.insert(u"account"_q, account);
	auto file = QSaveFile(FilePath());
	if (file.open(QIODevice::WriteOnly)) {
		file.write(QJsonDocument(root).toJson(QJsonDocument::Compact));
		file.commit();
	}
}

void Load() {
	auto &data = Data();
	auto file = QFile(FilePath());
	if (!file.open(QIODevice::ReadOnly)) {
		return;
	}
	const auto root = QJsonDocument::fromJson(file.readAll()).object();
	data.enabled = root.value(u"enabled"_q).toBool();
	const auto account = root.value(u"account"_q).toObject();
	data.account.privateKey = account.value(u"private_key"_q).toString();
	data.account.publicKey = account.value(u"public_key"_q).toString();
	data.account.peerPublicKey = account.value(u"peer_public_key"_q).toString();
	data.account.endpointHost = account.value(u"endpoint_host"_q).toString();
	data.account.endpointPort = account.value(u"endpoint_port"_q).toInt(2408);
	data.account.address = account.value(u"address"_q).toString();
	data.account.reserved = account.value(u"reserved"_q).toString();
}

void StopEngine() {
	auto &data = Data();
	g_port = 0;
	data.port = 0;
	if (data.handle) {
		if (const auto api = Naive::LoadApi(); api && api->warpStop) {
			api->warpStop(data.handle);
		}
		data.handle = nullptr;
	}
	data.lastState = -1;
	if (data.timer) {
		data.timer->stop();
	}
}

void StartEngine();

void Register() {
	auto &data = Data();
	if (data.registering) {
		return;
	}
	const auto api = Naive::LoadApi();
	if (!api || !api->warpKeypair) {
		LOG(("WARP: the zsgnaive library has no WARP support."));
		return;
	}
	char priv[64] = {};
	char pub[64] = {};
	if (!api->warpKeypair(priv, pub, sizeof(priv))) {
		LOG(("WARP: could not generate a key pair."));
		return;
	}
	data.registering = true;
	++data.registrations;
	if (!data.network) {
		data.network = std::make_unique<QNetworkAccessManager>();
		// Registration goes out directly: the entry hop does not exist yet.
		data.network->setProxy(QNetworkProxy::NoProxy);
	}
	auto request = QNetworkRequest(QUrl(QString::fromLatin1(kRegisterUrl)));
	request.setHeader(QNetworkRequest::ContentTypeHeader, u"application/json"_q);
	request.setHeader(QNetworkRequest::UserAgentHeader, u"okhttp/3.12.1"_q);
	request.setRawHeader("CF-Client-Version", "a-6.3-2158");
	request.setTransferTimeout(20000);
	auto body = QJsonObject();
	body.insert(u"key"_q, QString::fromLatin1(pub));
	body.insert(u"install_id"_q, QString());
	body.insert(u"fcm_token"_q, QString());
	body.insert(u"tos"_q, QDateTime::currentDateTimeUtc().toString(Qt::ISODateWithMs));
	body.insert(u"model"_q, u"PC"_q);
	body.insert(u"type"_q, u"Android"_q);
	body.insert(u"locale"_q, u"en_US"_q);
	const auto reply = data.network->post(
		request,
		QJsonDocument(body).toJson(QJsonDocument::Compact));
	const auto privateKey = QString::fromLatin1(priv);
	const auto publicKey = QString::fromLatin1(pub);
	QObject::connect(reply, &QNetworkReply::finished, [=] {
		auto &data = Data();
		data.registering = false;
		const auto ok = (reply->error() == QNetworkReply::NoError);
		const auto bytes = reply->readAll();
		LOG(("WARP: registration %1 (%2 bytes).").arg(ok ? u"answered"_q : reply->errorString()).arg(bytes.size()));
		reply->deleteLater();
		if (!ok) {
			return;
		}
		const auto root = QJsonDocument::fromJson(bytes).object();
		LOG(("WARP: registration warp_enabled=%1.").arg(root.value(u"warp_enabled"_q).toVariant().toString()));
		const auto config = root.value(u"config"_q).toObject();
		const auto peers = config.value(u"peers"_q).toArray();
		if (peers.isEmpty()) {
			LOG(("WARP: registration answer has no peers."));
			return;
		}
		const auto peer = peers[0].toObject();
		const auto endpoint = peer.value(u"endpoint"_q).toObject();
		const auto v4 = endpoint.value(u"v4"_q).toString(); // 162.159.192.4:0
		auto host = v4.section(':', 0, 0);
		if (host.isEmpty()) {
			host = endpoint.value(u"host"_q).toString().section(':', 0, 0);
		}
		auto port = 2408;
		const auto ports = endpoint.value(u"ports"_q).toArray();
		if (!ports.isEmpty()) {
			port = ports[0].toInt(2408);
		}
		auto account = Account();
		account.privateKey = privateKey;
		account.publicKey = publicKey;
		account.peerPublicKey = peer.value(u"public_key"_q).toString();
		account.endpointHost = host;
		account.endpointPort = port;
		account.address = config.value(u"interface"_q).toObject()
			.value(u"addresses"_q).toObject().value(u"v4"_q).toString();
		account.reserved = config.value(u"client_id"_q).toString();
		if (!account.valid()) {
			LOG(("WARP: registration answer is incomplete."));
			return;
		}
		data.account = account;
		Save();
		LOG(("WARP: account registered (endpoint %1:%2).").arg(host).arg(port));
		if (data.enabled) {
			StartEngine();
		}
	});
}

void Poll() {
	auto &data = Data();
	const auto api = Naive::LoadApi();
	if (!data.handle || !api || !api->warpState) {
		return;
	}
	const auto state = api->warpState(data.handle);
	// While the tunnel is not up, put its counters in the log every ~10 s
	// (handshakes sent, what came back), so a failed start can be told apart.
	if (state != Naive::WarpUp && api->warpStats && (++data.polls % 20) == 0) {
		char stats[256] = {};
		api->warpStats(data.handle, stats, sizeof(stats));
		LOG(("WARP: state %1, %2").arg(state).arg(QString::fromLatin1(stats)));
	}
	if (state == Naive::WarpUp) {
		data.registrations = 0;
	} else if (state == Naive::WarpConnecting
		&& data.startedAt
		&& (QDateTime::currentMSecsSinceEpoch() - data.startedAt) > 20000
		&& data.registrations < 4) {
		// A fresh account sometimes never gets an answer from the WARP edge
		// (seen: ~1 in 5); a new one usually does. Accounts are throwaway.
		LOG(("WARP: no answer from the edge in 20 s, registering a new account."));
		StopEngine();
		data.account = Account();
		Register();
		return;
	}
	if (state == data.lastState) {
		return;
	}
	if (api->warpStats) {
		char stats[256] = {};
		api->warpStats(data.handle, stats, sizeof(stats));
		LOG(("WARP: state change to %1, %2").arg(state).arg(QString::fromLatin1(stats)));
	}
	data.lastState = state;
	LOG(("WARP: tunnel state %1.").arg(state));
	// Connections made before the tunnel was up went out directly: restart
	// them so that they use the entry hop (or leave it when it died).
	g_port = (state == Naive::WarpUp) ? int(data.port) : 0;
	Core::App().restartProxyConnections();
}

void StartEngine() {
	auto &data = Data();
	if (data.handle || !data.enabled) {
		return;
	}
	const auto api = Naive::LoadApi();
	if (!api || !api->warpStart) {
		LOG(("WARP: the zsgnaive library has no WARP support."));
		return;
	}
	if (!data.account.valid()) {
		Register();
		return;
	}
	const auto privateKey = data.account.privateKey.toUtf8();
	const auto peerKey = data.account.peerPublicKey.toUtf8();
	const auto reserved = data.account.reserved.toUtf8();
	const auto address = data.account.address.toUtf8();
	const auto host = data.account.endpointHost.toUtf8();
	auto config = Naive::WarpConfigC();
	config.private_key = privateKey.constData();
	config.peer_public_key = peerKey.constData();
	config.reserved = reserved.isEmpty() ? nullptr : reserved.constData();
	config.address = address.constData();
	config.endpoint_host = host.constData();
	config.endpoint_port = uint16_t(data.account.endpointPort);
	config.junk_count = 3;
	auto port = uint16_t(0);
	char error[256] = {};
	data.handle = api->warpStart(&config, &port, error, sizeof(error));
	if (!data.handle) {
		LOG(("WARP: start failed: %1").arg(QString::fromLatin1(error)));
		return;
	}
	LOG(("WARP: tunnel starting, local SOCKS5 port %1.").arg(port));
	if (!data.timer) {
		data.timer = std::make_unique<QTimer>();
		data.timer->setInterval(500);
		QObject::connect(data.timer.get(), &QTimer::timeout, [] { Poll(); });
	}
	data.port = port;
	data.startedAt = QDateTime::currentMSecsSinceEpoch();
	data.timer->start();
}

} // namespace

void Init() {
	Load();
	if (Data().enabled) {
		StartEngine();
	}
}

bool Enabled() {
	return Data().enabled;
}

void SetEnabled(bool enabled) {
	auto &data = Data();
	if (data.enabled == enabled) {
		return;
	}
	data.enabled = enabled;
	Save();
	if (enabled) {
		StartEngine();
	} else {
		StopEngine();
		Core::App().restartProxyConnections();
	}
}

std::optional<QNetworkProxy> EntryProxy() {
	const auto port = g_port.load();
	if (!port) {
		return std::nullopt;
	}
	return QNetworkProxy(
		QNetworkProxy::Socks5Proxy,
		u"127.0.0.1"_q,
		quint16(port));
}

} // namespace Zsg::Warp
