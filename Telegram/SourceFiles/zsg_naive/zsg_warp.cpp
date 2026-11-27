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
#include <QtCore/QRandomGenerator>
#include <QtCore/QSaveFile>
#include <QtCore/QTimer>
#include <QtNetwork/QNetworkAccessManager>
#include <QtNetwork/QNetworkReply>
#include <QtNetwork/QNetworkRequest>

#include <atomic>

namespace Zsg::Warp {
namespace {

constexpr auto kRegisterUrl = "https://api.cloudflareclient.com/v0a2158/reg";
constexpr auto kMasqueApiUrl = "https://api.cloudflareclient.com/v0a4471/reg";

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

// The MASQUE account: a second WARP device enrolled with an ECDSA P-256 key.
struct MasqueAccount {
	QString privateKey;   // base64 SEC1 DER
	QString serverKeyPem; // the endpoint public key (pinned)
	QString address;      // IPv4 tunnel address

	[[nodiscard]] bool valid() const {
		return !privateKey.isEmpty()
			&& !serverKeyPem.isEmpty()
			&& !address.isEmpty();
	}
};

struct State {
	bool enabled = false;
	Account account;
	MasqueAccount masque;
	bool preferMasque = false;  // the last tunnel that worked was MASQUE: try it first
	bool enrolling = false;
	qint64 lastEnrollTry = 0;
	bool enrollViaTunnelTried = false;
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
	auto masque = QJsonObject();
	masque.insert(u"private_key"_q, data.masque.privateKey);
	masque.insert(u"server_key_pem"_q, data.masque.serverKeyPem);
	masque.insert(u"address"_q, data.masque.address);
	auto root = QJsonObject();
	root.insert(u"enabled"_q, data.enabled);
	root.insert(u"prefer_masque"_q, data.preferMasque);
	root.insert(u"account"_q, account);
	root.insert(u"masque"_q, masque);
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
	const auto masque = root.value(u"masque"_q).toObject();
	data.masque.privateKey = masque.value(u"private_key"_q).toString();
	data.masque.serverKeyPem = masque.value(u"server_key_pem"_q).toString();
	data.masque.address = masque.value(u"address"_q).toString();
	data.preferMasque = root.value(u"prefer_masque"_q).toBool();
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
	data.enrollViaTunnelTried = false;
	if (data.timer) {
		data.timer->stop();
	}
}

void StartEngine();

// The MASQUE account: a throwaway device (like the WireGuard one) that is then enrolled with an ECDSA key
// (PATCH with the device token). Done once; the account is kept in tdata/zsg/warp.json.
void EnrollMasque() {
	auto &data = Data();
	if (data.enrolling || data.masque.valid()) {
		return;
	}
	const auto api = Naive::LoadApi();
	if (!api || !api->warpMasqueKeypair || !api->warpKeypair) {
		return;
	}
	char masquePriv[512] = {};
	char masquePub[512] = {};
	char wgPriv[64] = {};
	char wgPub[64] = {};
	if (!api->warpMasqueKeypair(masquePriv, masquePub, sizeof(masquePriv))
		|| !api->warpKeypair(wgPriv, wgPub, sizeof(wgPriv))) {
		LOG(("WARP: could not generate the MASQUE key."));
		return;
	}
	data.enrolling = true;
	data.lastEnrollTry = QDateTime::currentMSecsSinceEpoch();
	if (!data.network) {
		data.network = std::make_unique<QNetworkAccessManager>();
	}
	// Directly while the tunnel is not up; through the tunnel once it is (the provider drops this API by name on some
	// networks, a tunnel that is up reaches it from inside Cloudflare).
	if (const auto entry = Zsg::Warp::EntryProxy()) {
		auto proxy = *entry;
		proxy.setCapabilities(QNetworkProxy::HostNameLookupCapability
			| QNetworkProxy::TunnelingCapability);
		data.network->setProxy(proxy);
	} else {
		data.network->setProxy(QNetworkProxy::NoProxy);
	}
	const auto url = QString::fromLatin1(kMasqueApiUrl);
	const auto prepare = [&](const QUrl &where) {
		auto request = QNetworkRequest(where);
		request.setHeader(QNetworkRequest::ContentTypeHeader, u"application/json"_q);
		request.setHeader(QNetworkRequest::UserAgentHeader, u"WARP for Android"_q);
		request.setRawHeader("CF-Client-Version", "a-6.35-4471");
		request.setTransferTimeout(20000);
		return request;
	};
	auto body = QJsonObject();
	body.insert(u"key"_q, QString::fromLatin1(wgPub));
	body.insert(u"install_id"_q, QString());
	body.insert(u"fcm_token"_q, QString());
	body.insert(u"tos"_q, QDateTime::currentDateTimeUtc().toString(Qt::ISODateWithMs));
	body.insert(u"model"_q, u"PC"_q);
	body.insert(u"serial_number"_q, QString::number(QRandomGenerator::global()->generate64(), 16));
	body.insert(u"os_version"_q, QString());
	body.insert(u"key_type"_q, u"curve25519"_q);
	body.insert(u"tunnel_type"_q, u"wireguard"_q);
	body.insert(u"locale"_q, u"en-US"_q);
	const auto first = data.network->post(
		prepare(QUrl(url)),
		QJsonDocument(body).toJson(QJsonDocument::Compact));
	const auto privateKey = QString::fromLatin1(masquePriv);
	const auto publicKey = QString::fromLatin1(masquePub);
	QObject::connect(first, &QNetworkReply::finished, [=] {
		auto &data = Data();
		const auto ok = (first->error() == QNetworkReply::NoError);
		const auto bytes = first->readAll();
		first->deleteLater();
		const auto device = QJsonDocument::fromJson(bytes).object();
		const auto id = device.value(u"id"_q).toString();
		const auto token = device.value(u"token"_q).toString();
		if (!ok || id.isEmpty() || token.isEmpty()) {
			data.enrolling = false;
			LOG(("WARP: MASQUE device registration failed (%1).").arg(first->errorString()));
			return;
		}
		auto patch = QJsonObject();
		patch.insert(u"key"_q, publicKey);
		patch.insert(u"key_type"_q, u"secp256r1"_q);
		patch.insert(u"tunnel_type"_q, u"masque"_q);
		patch.insert(u"name"_q, u"PC"_q);
		auto request = QNetworkRequest(QUrl(QString::fromLatin1(kMasqueApiUrl) + '/' + id));
		request.setHeader(QNetworkRequest::ContentTypeHeader, u"application/json"_q);
		request.setHeader(QNetworkRequest::UserAgentHeader, u"WARP for Android"_q);
		request.setRawHeader("CF-Client-Version", "a-6.35-4471");
		request.setRawHeader("Authorization", ("Bearer " + token).toUtf8());
		request.setTransferTimeout(20000);
		const auto second = data.network->sendCustomRequest(
			request,
			"PATCH",
			QJsonDocument(patch).toJson(QJsonDocument::Compact));
		QObject::connect(second, &QNetworkReply::finished, [=] {
			auto &data = Data();
			data.enrolling = false;
			const auto ok = (second->error() == QNetworkReply::NoError);
			const auto bytes = second->readAll();
			second->deleteLater();
			if (!ok) {
				LOG(("WARP: MASQUE enrollment failed (%1).").arg(second->errorString()));
				return;
			}
			const auto config = QJsonDocument::fromJson(bytes).object()
				.value(u"config"_q).toObject();
			const auto peers = config.value(u"peers"_q).toArray();
			const auto key = peers.isEmpty()
				? QString()
				: peers[0].toObject().value(u"public_key"_q).toString();
			const auto address = config.value(u"interface"_q).toObject()
				.value(u"addresses"_q).toObject().value(u"v4"_q).toString();
			if (key.isEmpty() || address.isEmpty()) {
				LOG(("WARP: MASQUE enrollment answer is incomplete."));
				return;
			}
			data.masque.privateKey = privateKey;
			data.masque.serverKeyPem = key;
			data.masque.address = address;
			Save();
			LOG(("WARP: MASQUE account enrolled."));
			// A tunnel that is still not up (WireGuard silent) restarts with the new fallback.
			if (data.enabled && data.handle && data.lastState != Naive::WarpUp) {
				StopEngine();
				StartEngine();
			} else if (data.enabled && !data.handle) {
				StartEngine();
			}
		});
	});
}

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
		EnrollMasque();
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
		if (!data.masque.valid() && !data.enrolling && g_port.load() != 0) {
			// The tunnel is up: the API is reachable through it. Once at once, then every 5 minutes.
			const auto now = QDateTime::currentMSecsSinceEpoch();
			if (!data.enrollViaTunnelTried || now - data.lastEnrollTry > 300000) {
				data.enrollViaTunnelTried = true;
				EnrollMasque();
			}
		}
		if (api->warpTransport) {
			// Remember which transport works on this network: MASQUE first next time when WireGuard never did.
			const auto masque = (api->warpTransport(data.handle) == 2);
			if (masque != data.preferMasque) {
				data.preferMasque = masque;
				Save();
			}
		}
	} else if (state != Naive::WarpUp
		&& data.startedAt
		&& (QDateTime::currentMSecsSinceEpoch() - data.startedAt) > 60000
		&& data.registrations < 4) {
		// A fresh account sometimes never gets an answer from the WARP edge
		// (seen: ~1 in 5); a new one usually does. Accounts are throwaway.
		LOG(("WARP: no answer from any edge in 60 s, registering new accounts."));
		StopEngine();
		data.account = Account();
		data.masque = MasqueAccount();
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
	if (!data.masque.valid()) {
		EnrollMasque();
	}
	if (!data.account.valid() && !data.masque.valid()) {
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
	const auto masqueKey = data.masque.privateKey.toUtf8();
	const auto masquePem = data.masque.serverKeyPem.toUtf8();
	const auto masqueAddress = data.masque.address.toUtf8();
	auto masque = Naive::WarpMasqueConfigC();
	masque.private_key = masqueKey.constData();
	masque.server_key_pem = masquePem.constData();
	masque.address = masqueAddress.constData();
	masque.edges = nullptr;
	masque.first = data.preferMasque ? 1 : 0;
	if (api->warpStart2 && data.masque.valid()) {
		data.handle = api->warpStart2(
			data.account.valid() ? &config : nullptr,
			&masque,
			&port,
			error,
			sizeof(error));
	} else if (data.account.valid()) {
		data.handle = api->warpStart(&config, &port, error, sizeof(error));
	}
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

QString StatusText() {
	const auto &data = Data();
	if (!data.enabled) {
		return u"Off."_q;
	}
	const auto api = Naive::LoadApi();
	if (!data.handle || !api || !api->warpState) {
		return (data.registering || data.enrolling)
			? u"Registering a WARP account…"_q
			: u"Starting…"_q;
	}
	switch (api->warpState(data.handle)) {
	case Naive::WarpUp:
		return (api->warpTransport && api->warpTransport(data.handle) == 2)
			? u"Up through MASQUE (TCP 443)."_q
			: u"Up through WireGuard."_q;
	case Naive::WarpFailed:
		return u"No answer from Cloudflare on this network: connections go direct."_q;
	default:
		return data.masque.valid()
			? u"Connecting (WireGuard, then MASQUE over TCP 443)…"_q
			: u"Connecting…"_q;
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
