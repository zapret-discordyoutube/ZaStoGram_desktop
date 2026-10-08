/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "mtproto/proxy/wss/socket.h"

#include "mtproto/protocol/mtproto_binary.h"
#include "mtproto/proxy/diagnostics.h"
#include "logs.h"
#include "base/bytes.h"
#include "base/invoke_queued.h"
#include "base/random.h"

#include <crl/crl_time.h>

#include <atomic>
#include <cstring>
#include <algorithm>
#include <map>

#include <QtCore/QCryptographicHash>
#include <QtCore/QMutex>
#include <QtCore/QDateTime>
#include <QtCore/QFile>
#include <QtNetwork/QNetworkInformation>

namespace MTP::details {
namespace {

constexpr auto kWssMaxFrame = 2 * 1024 * 1024;
constexpr auto kWssHeaderLimit = 32 * 1024;

// How long to remember that only the fallback (domain) relay host works.
constexpr auto kRelayFallbackPreferenceTtl = 30 * 60 * crl::time(1000);

// Which relay host actually works is remembered across sockets: a blocked
// primary relay IP would otherwise be retried first by EVERY new socket,
// and the session-level connect watchdog (1s on the first attempt) kills
// the socket before errorOccurred fires, so the in-socket fallback never
// gets a chance and each reconnect repeats the dead-host dance.
struct RelayPreference {
	bool preferFallback = false;
	crl::time until = 0;
};

QMutex RelayPreferencesMutex;
std::map<QString, RelayPreference> RelayPreferences;

std::atomic<bool> CurrentNetworkMetered = false;

[[nodiscard]] QString NetworkKey(bool metered, const QString &value) {
	return (metered ? u"metered/"_q : u"unmetered/"_q) + value;
}

[[nodiscard]] QString RelayPreferenceKey(const WssRoute &route) {
	return NetworkKey(
		route.metered,
		route.relayHost + u":"_q + QString::number(route.relayPort));
}

[[nodiscard]] bool HasRelayFallback(const WssRoute &route) {
	return !route.relayHostFallback.isEmpty()
		&& (route.relayHostFallback != route.relayHost);
}

[[nodiscard]] bool PreferRelayFallback(const WssRoute &route) {
	if (!HasRelayFallback(route)) {
		return false;
	}
	QMutexLocker lock(&RelayPreferencesMutex);
	const auto i = RelayPreferences.find(RelayPreferenceKey(route));
	return (i != end(RelayPreferences))
		&& i->second.preferFallback
		&& (i->second.until > crl::now());
}

constexpr auto kTunnelOnlyDcId = 203;
// Worker tunnels (zastogram-ws-worker/worker.js), each on its own Cloudflare
// account. A free account serves 100 000 requests a day; past that the worker
// answers 429 (error code: 1027) until 00:00 UTC, and on 08.10.2026 the single
// worker was spent by the evening: DC203 media stood still for everyone. Every
// install starts from a random worker, so the accounts share the load. The
// same list is in the Android client (jni/tgnet/wss/WssSocket.cpp) and in
// ZapretGUI (telegram_proxy/proxy/route_catalog.py, TUNNEL_HOSTS).
constexpr const char *kTunnelHosts[] = {
	"edge.amberwick.workers.dev",
	"fuckyourkn.copperbrook.workers.dev",
};
constexpr auto kTunnelHostCount = int(std::size(kTunnelHosts));

// Отдельный от выбора адреса учёт: у датацентра может не открываться ни один
// адрес релея — у части провайдеров порт 443 к нему закрыт целиком, по обоим
// протоколам. Держать такой датацентр в вечных попытках бессмысленно: медиа
// оттуда не загрузится никогда, хотя прямое соединение может работать. После
// нескольких неудач подряд, ни одна из которых не дошла даже до TCP, маршрут
// WSS для этого датацентра отключается, и фабрика сокетов создаёт обычный TCP.
constexpr auto kRouteFailuresBeforeSuppress = 3;
// Туннель медленнее релея, поэтому держать в нём основной датацентр дольше
// пары минут дороже, чем лишний раз проверить релей.
constexpr auto kRouteSuppressTtl = 2 * 60 * crl::time(1000);
// A throttled network freezes TCP to Cloudflare after about 16 KB downstream,
// TLS handshake included (Android logs (9) and (10), desktop log 25.09: no
// tunnel socket got more than ~13 KB of MTProto). A file connection is
// reopened after one 8 KB part, before it reaches that limit; a tunnel that
// delivered this much is working, even if it would freeze later.
constexpr auto kTunnelRotateBytes = qint64(4 * 1024);
// Chat sessions through the tunnel froze after 11-15 KB and waited out the
// 8 s receive timeout every 15-50 s; they are reopened after this much.
constexpr auto kTunnelMainRotateBytes = qint64(8 * 1024);
// An upgraded tunnel socket killed sooner than this without data was cut by
// a connect budget, not found silent.
constexpr auto kTunnelSilentAfter = 4 * crl::time(1000);
// Соединения открываются пачкой, и их таймауты приходят пачкой. Одна пачка —
// один провал, а не «три подряд».
constexpr auto kRouteFailureCoalesce = 2 * crl::time(1000);
// Провайдер глотает SYN отдельного потока, а соседний сокет к тому же адресу
// проходит. Пока адрес недавно принимал TCP, таймаут соединения — шум потока,
// а не недоступный релей.
constexpr auto kRecentTcpSuccess = 30 * crl::time(1000);

// Cloudflare front domains of tg-ws-proxy (github.com/Flowseal/tg-ws-proxy,
// .github/cfproxy-domains.txt), in the same shifted spelling: each letter of
// the name moved forward by the number of letters, ".co.uk" written ".com".
// kwsN.<domain>/apiws forwards the WebSocket to Telegram Web. Mirrly TG Proxy
// carries MTProto only this way and, unlike the Worker tunnel (frozen after
// ~16 KB on mobile networks), works there for text and media. Same catalog
// and rules as Android (WssSocket.cpp, dev-173/174).
// Dialled by name, as the tunnel is: DNS gives the zone's current Cloudflare
// addresses and Qt handles SNI and verification from the one host name.
// (On dev-31/32 every Cloudflare handshake from the tester's PC was reset
// ~200 ms after TCP; that was a local zapret strategy, curl.exe was reset
// the same way.) Android sets SNI itself and dials the addresses.
constexpr const char *kCdnFronts[] = {
	"virkgj.com",
	"vmmzovy.com",
	"mkuosckvso.com",
	"zaewayzmplad.com",
	"twdmbzcm.com",
	"awzwsldi.com",
	"clngqrflngqin.com",
	"tjacxbqtj.com",
	"bxaxtxmrw.com",
	"dmohrsgmohcrwb.com",
	"vwbmtmoi.com",
	"khgrre.com",
	"ulihssf.com",
	"tmhqsdqmfpmk.com",
	"xwuwoqbm.com",
	"orgcnunpj.com",
	"zhkuldz.com",
	"zypoljnslxa.com",
	"efabnxaowuzs.com",
	"zaftuzsftqdq.com",
};
constexpr auto kCdnFrontCount = int(sizeof(kCdnFronts) / sizeof(kCdnFronts[0]));
// A front connection is either served at once or answers 503 to every
// upgrade (host test 27.09); a retry on the same TLS connection costs ~25 ms.
constexpr auto kCdnUpgradeRetries = 8;
// About 40% of front connections are refused, so three failures in a row are
// ordinary; six mean the fronts are really out of reach.
constexpr auto kCdnFailuresBeforeSuppress = 6;
// Past the ~16 KB freeze seen on the tunnel: a session that delivered this
// much proves the front carries real traffic on this network.
constexpr auto kCdnProofBytes = qint64(32 * 1024);
// Sessions that answered and then went silent below kCdnProofBytes.
constexpr auto kCdnStallsBeforeSuppress = 3;
// Every front attempt rotates to a new address, so "this address connected
// recently" never matched and each lost SYN counted against all fronts.
const auto kAnyCdnHost = u"cdn-any"_q;

struct RouteHealth {
	int consecutiveFailures = 0;
	crl::time suppressedUntil = 0;
	crl::time lastFailureAt = 0;
	// Suppressions in a row without a single answer in between: a relay the
	// network blocks outright was probed every two minutes, and each probe
	// (1+2+4+8 s of connect budgets) was 15 s without DC1 (desktop log
	// 25.09, 18:40 and 18:43). Each repeat doubles the suppression.
	int suppressions = 0;
	// Front sessions that answered and then froze (kCdnProofBytes).
	int stalls = 0;
	// The relay upgraded on this network since the process started.
	bool answered = false;
};
constexpr auto kRouteSuppressMaxTtl = 30 * 60 * crl::time(1000);
// Suppression lived only in memory, and every launch probed the blocked
// relay again before the tunnel. It is kept in tdata; what a restart
// restores is capped, since the network may have changed meanwhile.
constexpr auto kRouteSuppressRestoreMax = 10 * 60 * crl::time(1000);

std::map<QString, RouteHealth> RouteHealthByDomain;
bool RouteHealthLoaded = false;

[[nodiscard]] bool IsCdn(const WssRoute &route) {
	return route.cdnSlot >= 0;
}

[[nodiscard]] const QString &HealthName(const WssRoute &route) {
	return route.healthDomain.isEmpty() ? route.domain : route.healthDomain;
}

// Fronts are checked again on every launch: on Android a restart with the
// relay, the fronts and the tunnel all restored as suppressed left DC2 with
// no route at all for ten minutes (logs (1) (8)).
[[nodiscard]] bool PersistedHealth(const QString &key) {
	return !key.contains(u"/cdn-"_q);
}

[[nodiscard]] QString RouteHealthPath() {
	return cWorkingDir() + u"tdata/wss_route_health"_q;
}

// Both called with RelayPreferencesMutex held.
void LoadRouteHealthLocked() {
	if (RouteHealthLoaded) {
		return;
	}
	RouteHealthLoaded = true;
	auto file = QFile(RouteHealthPath());
	if (!file.open(QIODevice::ReadOnly)) {
		return;
	}
	const auto now = crl::now();
	const auto wall = QDateTime::currentMSecsSinceEpoch();
	for (const auto &line : QString::fromUtf8(file.readAll()).split('\n')) {
		const auto parts = line.split(' ', Qt::SkipEmptyParts);
		// Lines written before the per-network split carry a bare domain.
		if (parts.size() != 3
			|| !parts[0].contains('/')
			|| !PersistedHealth(parts[0])) {
			continue;
		}
		const auto suppressions = parts[1].toInt();
		const auto left = std::min(
			parts[2].toLongLong() - wall,
			qint64(kRouteSuppressRestoreMax));
		if (suppressions <= 0 || left <= 0) {
			continue;
		}
		auto &health = RouteHealthByDomain[parts[0]];
		health.suppressions = suppressions;
		health.suppressedUntil = now + left;
		LOG(("WSS Route: %1 suppressed for %2 s (restored after restart)."
			).arg(parts[0]
			).arg(left / 1000));
	}
}

void SaveRouteHealthLocked() {
	auto file = QFile(RouteHealthPath());
	if (!file.open(QIODevice::WriteOnly | QIODevice::Truncate)) {
		return;
	}
	const auto now = crl::now();
	const auto wall = QDateTime::currentMSecsSinceEpoch();
	auto data = QByteArray();
	for (const auto &[domain, health] : RouteHealthByDomain) {
		if (health.suppressions > 0
			&& health.suppressedUntil > now
			&& PersistedHealth(domain)) {
			data += domain.toUtf8()
				+ ' ' + QByteArray::number(health.suppressions)
				+ ' ' + QByteArray::number(
					wall + (health.suppressedUntil - now))
				+ '\n';
		}
	}
	file.write(data);
}
std::map<QString, crl::time> TcpSuccessByHost;

void NoteTcpConnected(const WssRoute &route, const QString &host) {
	QMutexLocker lock(&RelayPreferencesMutex);
	const auto now = crl::now();
	TcpSuccessByHost[NetworkKey(route.metered, host)] = now;
	if (IsCdn(route)) {
		TcpSuccessByHost[NetworkKey(route.metered, kAnyCdnHost)] = now;
	}
}

[[nodiscard]] bool TcpRecentlyConnected(
		const WssRoute &route,
		const QString &host) {
	QMutexLocker lock(&RelayPreferencesMutex);
	const auto i = TcpSuccessByHost.find(NetworkKey(route.metered, host));
	return (i != end(TcpSuccessByHost))
		&& (crl::now() - i->second < kRecentTcpSuccess);
}

[[nodiscard]] bool RouteSuppressed(const WssRoute &route) {
	const auto domain = NetworkKey(route.metered, HealthName(route));
	QMutexLocker lock(&RelayPreferencesMutex);
	LoadRouteHealthLocked();
	const auto i = RouteHealthByDomain.find(domain);
	if (i == end(RouteHealthByDomain) || !i->second.suppressedUntil) {
		return false;
	} else if (i->second.suppressedUntil <= crl::now()) {
		const auto suppressions = i->second.suppressions;
		i->second = RouteHealth();
		i->second.suppressions = suppressions;
		LOG(("WSS Route: %1 restored (suppression expired).").arg(domain));
		return false;
	}
	return true;
}

// Called with RelayPreferencesMutex held.
void SuppressLocked(
		const WssRoute &route,
		RouteHealth &health,
		crl::time now,
		const QString &reason) {
	const auto ttl = std::min(
		kRouteSuppressTtl << std::min(health.suppressions, 4),
		kRouteSuppressMaxTtl);
	++health.suppressions;
	health.suppressedUntil = now + ttl;
	SaveRouteHealthLocked();
	LOG(("WSS Route: %1 suppressed for %2 s (%3), next: %4."
		).arg(NetworkKey(route.metered, HealthName(route))
		).arg(ttl / 1000
		).arg(reason
		).arg(route.tunnel
			? u"Cloudflare fronts"_q
			: IsCdn(route)
			? u"Cloudflare tunnel"_q
			: u"Cloudflare fronts"_q));
}

// Relay domains share ingress addresses: kws2, kws4, kws2-1 and kws4-1 all
// dial 149.154.167.220. A TCP timeout does not depend on the SNI, so TCP
// failures also count per address, and a suppressed address moves every
// domain on it to the fronts at once instead of each timing out on its own
// (Android logs (23): kws1-1 and kws2-1 lost 8-11 s each after kws1 and kws2
// had already proven their addresses dead). Same rules as Android dev-176.
[[nodiscard]] bool IsOfficialRelay(const WssRoute &route) {
	return !route.tunnel
		&& !IsCdn(route)
		&& route.domain.endsWith(u".web.telegram.org"_q);
}

[[nodiscard]] WssRoute RelayAddressRoute(const WssRoute &route) {
	auto result = route;
	result.healthDomain = u"addr-"_q + route.relayHost;
	return result;
}

void NoteRouteUnreachable(const WssRoute &route) {
	QMutexLocker lock(&RelayPreferencesMutex);
	LoadRouteHealthLocked();
	const auto key = NetworkKey(route.metered, HealthName(route));
	auto &health = RouteHealthByDomain[key];
	// Media relays used to go to the tunnel after their first failure, for
	// half an hour. Connections open in bursts, so a first failure is almost
	// guaranteed, and on a throttled network the tunnel freezes after ~16 KB:
	// in Android logs (10) every DC1/DC5 media session through it died while
	// kws2-1 and kws4-1 delivered megabytes. Media follows the main rules.
	const auto now = crl::now();
	if (health.suppressedUntil > now) {
		return;
	} else if (health.lastFailureAt
		&& (now - health.lastFailureAt < kRouteFailureCoalesce)) {
		return;
	}
	health.lastFailureAt = now;
	++health.consecutiveFailures;
	const auto limit = IsCdn(route)
		? kCdnFailuresBeforeSuppress
		: kRouteFailuresBeforeSuppress;
	LOG(("WSS Route: %1 failure %2/%3."
		).arg(key
		).arg(health.consecutiveFailures
		).arg(limit));
	if (health.consecutiveFailures >= limit) {
		SuppressLocked(route, health, now, u"failures"_q);
	}
}

// The worker answered 429: its account is out of requests for the day, and
// every further attempt gets the same answer. Suppressed at once, without
// counting to three, so the next connection goes straight to the next worker.
void NoteTunnelQuotaExhausted(const WssRoute &route) {
	QMutexLocker lock(&RelayPreferencesMutex);
	LoadRouteHealthLocked();
	auto &health = RouteHealthByDomain[
		NetworkKey(route.metered, HealthName(route))];
	const auto now = crl::now();
	if (health.suppressedUntil > now) {
		return;
	}
	health.lastFailureAt = now;
	health.consecutiveFailures = 0;
	SuppressLocked(route, health, now, u"quota"_q);
}

// The relay's hardcoded address failed and its DNS fallback failed too, so
// the domain went down: siblings on the same address will fail the same way.
// Only a recent failure of the address itself counts: a stray SYN loss long
// ago must not take a sibling off a working relay.
void SuppressRelayAddressWithDomain(const WssRoute &route) {
	if (!IsOfficialRelay(route)) {
		return;
	}
	QMutexLocker lock(&RelayPreferencesMutex);
	const auto now = crl::now();
	const auto domain = RouteHealthByDomain.find(
		NetworkKey(route.metered, route.domain));
	if (domain == end(RouteHealthByDomain)
		|| domain->second.suppressedUntil <= now) {
		return;
	}
	const auto address = RelayAddressRoute(route);
	auto &health = RouteHealthByDomain[
		NetworkKey(route.metered, HealthName(address))];
	if (health.consecutiveFailures > 0
		&& health.suppressedUntil <= now
		&& health.lastFailureAt
		&& (now - health.lastFailureAt < 2 * 60 * crl::time(1000))) {
		SuppressLocked(address, health, now, u"domain"_q);
	}
}

void NoteRouteReachable(const WssRoute &route) {
	QMutexLocker lock(&RelayPreferencesMutex);
	const auto key = NetworkKey(route.metered, HealthName(route));
	auto &health = RouteHealthByDomain[key];
	if (IsCdn(route)) {
		// The first answer only shows that the front accepts connections. On
		// a network that freezes Cloudflare after ~16 KB every session
		// answers, and resetting the backoff here would cycle frozen sessions
		// and the tunnel forever; that is left to NoteCdnProven.
		health.consecutiveFailures = 0;
		health.lastFailureAt = 0;
		return;
	}
	if (health.consecutiveFailures || health.suppressedUntil) {
		LOG(("WSS Route: %1 restored (relay answered).").arg(key));
	}
	const auto persisted = (health.suppressions > 0);
	health = RouteHealth();
	health.answered = true;
	if (persisted) {
		SaveRouteHealthLocked();
	}
}

void NoteCdnProven(const WssRoute &route) {
	QMutexLocker lock(&RelayPreferencesMutex);
	const auto key = NetworkKey(route.metered, HealthName(route));
	auto &health = RouteHealthByDomain[key];
	if (health.stalls || health.suppressions || health.suppressedUntil) {
		LOG(("WSS Route: %1 restored (front carried %2 bytes)."
			).arg(key
			).arg(kCdnProofBytes));
	}
	// A front past the freeze lifts its suppression too: with everything
	// suppressed the fronts carry the DC anyway, and a suppression left in
	// place moved it into the tunnel once the tunnel's own expired.
	health = RouteHealth();
}

void NoteCdnStalled(const WssRoute &route, qint64 received) {
	QMutexLocker lock(&RelayPreferencesMutex);
	const auto key = NetworkKey(route.metered, HealthName(route));
	auto &health = RouteHealthByDomain[key];
	const auto now = crl::now();
	if (health.suppressedUntil > now) {
		return;
	}
	++health.stalls;
	LOG(("WSS Route: %1 stall after %2 bytes, %3/%4."
		).arg(key
		).arg(received
		).arg(health.stalls
		).arg(kCdnStallsBeforeSuppress));
	if (health.stalls >= kCdnStallsBeforeSuppress) {
		health.stalls = 0;
		SuppressLocked(route, health, now, u"stalls"_q);
	}
}

// Every connection starts from this position in kCdnFronts, per network. A
// failure moves it on, so the next connection tries another front and edge;
// a working front is kept. A random start spreads ZaStoGram users over the
// whole catalog instead of all loading its first domain.
std::map<bool, int> CdnCursor;

// Called with RelayPreferencesMutex held.
[[nodiscard]] int CdnCursorLocked(bool metered) {
	auto i = CdnCursor.find(metered);
	if (i == end(CdnCursor)) {
		i = CdnCursor.emplace(metered, base::RandomIndex(kCdnFrontCount)).first;
	}
	return i->second;
}

void AdvanceCdn(const WssRoute &route) {
	if (!IsCdn(route)) {
		return;
	}
	QMutexLocker lock(&RelayPreferencesMutex);
	auto &cursor = CdnCursor[route.metered];
	if (cursor == route.cdnSlot) {
		cursor = (cursor + 1) % kCdnFrontCount;
	}
}

[[nodiscard]] QString DecodeCdnDomain(const char *encoded) {
	// tg-ws-proxy's decoder: shift each letter back by the letter count.
	auto name = QString::fromLatin1(encoded);
	if (!name.endsWith(u".com"_q)) {
		return name;
	}
	name.chop(4);
	auto letters = 0;
	for (const auto ch : name) {
		letters += ch.isLetter() ? 1 : 0;
	}
	for (auto &ch : name) {
		const auto c = ch.toLatin1();
		if (c >= 'a' && c <= 'z') {
			ch = QChar('a' + ((c - 'a') - letters % 26 + 26) % 26);
		} else if (c >= 'A' && c <= 'Z') {
			ch = QChar('A' + ((c - 'A') - letters % 26 + 26) % 26);
		}
	}
	return name + u".co.uk"_q;
}

void NoteRelayAttemptFailed(const WssRoute &route, bool viaFallback) {
	if (!HasRelayFallback(route)) {
		return;
	}
	QMutexLocker lock(&RelayPreferencesMutex);
	if (viaFallback) {
		RelayPreferences.erase(RelayPreferenceKey(route));
	} else {
		RelayPreferences[RelayPreferenceKey(route)] = {
			.preferFallback = true,
			.until = crl::now() + kRelayFallbackPreferenceTtl,
		};
	}
}

void NoteRelayUpgraded(const WssRoute &route, bool viaFallback) {
	if (!HasRelayFallback(route)) {
		return;
	}
	QMutexLocker lock(&RelayPreferencesMutex);
	if (viaFallback) {
		RelayPreferences[RelayPreferenceKey(route)] = {
			.preferFallback = true,
			.until = crl::now() + kRelayFallbackPreferenceTtl,
		};
	} else {
		RelayPreferences.erase(RelayPreferenceKey(route));
	}
}

struct RotatedTunnelSockets {
	int count = 0;
	qint64 sent = 0;
	qint64 received = 0;
	crl::time life = 0;
	crl::time since = 0;
};

QMutex RotatedTunnelSocketsMutex;
RotatedTunnelSockets RotatedTunnelSocketsSum;

void NoteRotatedTunnelSocket(
		not_null<RuntimeEnvironment*> runtime,
		qint64 sent,
		qint64 received,
		crl::time life) {
	constexpr auto kReportEvery = 32;
	constexpr auto kReportAfter = 60 * crl::time(1000);
	auto report = RotatedTunnelSockets();
	{
		QMutexLocker lock(&RotatedTunnelSocketsMutex);
		auto &sum = RotatedTunnelSocketsSum;
		const auto now = crl::now();
		if (!sum.count) {
			sum.since = now;
		}
		++sum.count;
		sum.sent += sent;
		sum.received += received;
		sum.life += life;
		if (sum.count < kReportEvery && now - sum.since < kReportAfter) {
			return;
		}
		report = base::take(sum);
	}
	WriteProxyDiagnosticsLine(runtime, {
		.source = ProxyDiagnosticsSource::Network,
		.phase = ProxyDiagnosticsPhase::AttemptSummary,
		.severity = ProxyDiagnosticsSeverity::Info,
		.transport = u"WSSTunnel"_q,
		.message = u"wss_tunnel_rotated sockets=%1 tx=%2 rx=%3 avg_life_ms=%4"_q
			.arg(report.count)
			.arg(report.sent)
			.arg(report.received)
			.arg(report.life / report.count),
		.route = u"workers.dev"_q,
	});
}

[[nodiscard]] QByteArray RandomBytes(int count) {
	auto result = QByteArray(count, char(0));
	bytes::set_random(bytes::make_detached_span(result));
	return result;
}

[[nodiscard]] QString OfficialRelayIngress(int dcId) {
	// Each ingress serves only its own datacenters; they are not
	// interchangeable. Verified against live relays on 2026-08-08: all three
	// accept the upgrade and carry real MTProto, including the media (-1)
	// hostnames.
	switch (dcId) {
	case 1:
	case 3: return u"149.154.174.100"_q;
	case 2:
	case 4: return u"149.154.167.220"_q;
	case 5: return u"149.154.170.100"_q;
	}
	return QString();
}

[[nodiscard]] std::optional<WssRoute> OfficialRoute(int16 protocolDcId) {
	const auto raw = int(protocolDcId);
	const auto positive = (raw < 0) ? -raw : raw;
	if (positive >= kTestModeDcIdShift) {
		return std::nullopt; // test-mode DCs have no public web relay
	}
	const auto ingress = OfficialRelayIngress(positive);
	if (ingress.isEmpty()) {
		return std::nullopt; // CDN and unknown ids have no public web relay
	}
	auto route = WssRoute();
	route.metered = CurrentNetworkMetered.load();
	route.relayHost = ingress;
	route.relayPort = 443;
	route.path = u"/apiws"_q;
	const auto name = u"kws%1"_q.arg(positive);
	// A file lane can bootstrap a regular key first. Route by the protocol
	// DC sign, not by its large-buffer/file-lane classification, otherwise a
	// positive DC id reaches a media-only relay and is rejected with -444.
	route.domain = (raw < 0)
		? (name + u"-1.web.telegram.org"_q)
		: (name + u".web.telegram.org"_q);
	// Fallback: if the hardcoded relay IP is unreachable, retry once via the
	// domain so DNS yields a currently-valid address.
	route.relayHostFallback = route.domain;
	return route;
}

// The first worker not suppressed now, in a circle from the one this install
// starts with.
[[nodiscard]] std::optional<WssRoute> TunnelRoute() {
	static const auto start = int(uchar(RandomBytes(1)[0])) % kTunnelHostCount;
	for (auto step = 0; step != kTunnelHostCount; ++step) {
		auto route = WssRoute();
		route.metered = CurrentNetworkMetered.load();
		route.relayHost = QString::fromLatin1(
			kTunnelHosts[(start + step) % kTunnelHostCount]);
		route.relayPort = 443;
		route.domain = route.relayHost;
		route.path = u"/apiws"_q;
		route.tunnel = true;
		if (!RouteSuppressed(route)) {
			return route;
		}
	}
	return std::nullopt;
}

[[nodiscard]] std::optional<WssRoute> CdnRoute(
		int dcId,
		bool ignoreSuppression = false) {
	auto route = WssRoute();
	route.metered = CurrentNetworkMetered.load();
	const auto prefix = u"kws%1"_q.arg(dcId);
	route.healthDomain = u"cdn-"_q + prefix;
	if (!ignoreSuppression && RouteSuppressed(route)) {
		return std::nullopt;
	}
	auto slot = 0;
	{
		QMutexLocker lock(&RelayPreferencesMutex);
		slot = CdnCursorLocked(route.metered);
	}
	const auto front = kCdnFronts[slot % kCdnFrontCount];
	route.cdnSlot = slot;
	route.cdnDcId = dcId;
	// The fronts have no -1 media hosts: media rides kwsN too, as in Mirrly,
	// with the plain DC in the obfuscation header (plainDcMarker). A failure
	// moves to the next front instead of a DNS/IP fallback.
	route.domain = prefix + u"."_q + DecodeCdnDomain(front);
	route.relayHost = route.domain;
	route.relayPort = 443;
	route.path = u"/apiws"_q;
	return route;
}

} // namespace

void WssTrackNetwork() {
	static auto tracked = false;
	if (tracked) {
		return;
	}
	tracked = true;
	if (!QNetworkInformation::loadBackendByFeatures(
			QNetworkInformation::Feature::Metered)) {
		LOG(("WSS Route: network type unknown, one state for all networks."));
		return;
	}
	const auto information = QNetworkInformation::instance();
	const auto apply = [](bool metered) {
		if (CurrentNetworkMetered.exchange(metered) != metered) {
			LOG(("WSS Route: network %1."
				).arg(metered ? u"metered"_q : u"unmetered"_q));
		}
	};
	apply(information->isMetered());
	QObject::connect(
		information,
		&QNetworkInformation::isMeteredChanged,
		information,
		apply);
}

std::optional<WssRoute> WssOfficialRoute(int16 protocolDcId) {
	auto route = OfficialRoute(protocolDcId);
	if (!route) {
		// DC203 serves non-Premium media and has no kws relay at all.
		const auto raw = int(protocolDcId);
		if (raw == kTunnelOnlyDcId || raw == -kTunnelOnlyDcId) {
			if (auto tunnel = TunnelRoute()) {
				return tunnel;
			}
		}
		return std::nullopt;
	}
	if (RouteSuppressed(*route)
		|| RouteSuppressed(RelayAddressRoute(*route))) {
		// Релей датацентра недоступен: сначала фронты Cloudflare, потом
		// туннель. Если подавлено всё, остаются фронты: прямой TCP, к
		// которому это раньше сваливалось, такие сети и закрывают.
		const auto raw = int(protocolDcId);
		const auto dcId = (raw < 0) ? -raw : raw;
		if (auto front = CdnRoute(dcId)) {
			return front;
		}
		if (auto tunnel = TunnelRoute()) {
			return tunnel;
		}
		static auto lastFloorLog = std::atomic<crl::time>(0);
		const auto now = crl::now();
		if (now - lastFloorLog.load() > 10 * crl::time(1000)) {
			lastFloorLog = now;
			LOG(("WSS Route: dc %1 has every route suppressed, "
				"using the Cloudflare fronts anyway.").arg(raw));
		}
		return CdnRoute(dcId, true);
	}
	return route;
}

bool WssRelayUnproven(int16 protocolDcId) {
	const auto route = OfficialRoute(protocolDcId);
	if (!route) {
		return false;
	}
	const auto address = RelayAddressRoute(*route);
	if (RouteSuppressed(*route) || RouteSuppressed(address)) {
		return false; // WssOfficialRoute already gives the fronts.
	}
	QMutexLocker lock(&RelayPreferencesMutex);
	const auto failing = [&](const WssRoute &value) {
		const auto i = RouteHealthByDomain.find(
			NetworkKey(value.metered, HealthName(value)));
		return (i != end(RouteHealthByDomain))
			&& (i->second.consecutiveFailures > 0);
	};
	const auto i = RouteHealthByDomain.find(
		NetworkKey(route->metered, HealthName(*route)));
	const auto answered = (i != end(RouteHealthByDomain))
		&& i->second.answered;
	return !answered || failing(*route) || failing(address);
}

std::optional<WssRoute> WssFrontRoute(int16 protocolDcId) {
	if (!OfficialRoute(protocolDcId)) {
		return std::nullopt;
	}
	const auto raw = int(protocolDcId);
	return CdnRoute((raw < 0) ? -raw : raw);
}

bool WssMediaTunneled(int dcId) {
	// Only the tunnel freezes by design; media on a Cloudflare front uses
	// ordinary parts.
	const auto route = WssOfficialRoute(int16(-dcId));
	return route && route->tunnel;
}

std::optional<WssRoute> WssCustomRoute(const ProxyStealthOptions &stealth) {
	if (stealth.wssCustomHost.isEmpty()) {
		return std::nullopt;
	}
	auto route = WssRoute();
	route.relayHost = stealth.wssCustomHost;
	route.relayPort = (stealth.wssCustomPort > 0 && stealth.wssCustomPort <= 65535)
		? stealth.wssCustomPort
		: 443;
	route.path = stealth.wssCustomPath.isEmpty()
		? u"/apiws"_q
		: stealth.wssCustomPath;
	route.domain = stealth.wssCustomDomain.isEmpty()
		? stealth.wssCustomHost
		: stealth.wssCustomDomain;
	if (route.domain != route.relayHost) {
		route.relayHostFallback = route.domain;
	}
	return route;
}

WssRouteDiagnostics WssRouteDiagnosticsForDc(
		const ProxyStealthOptions &stealth,
		int16 protocolDcId) {
	auto result = WssRouteDiagnostics();
	result.route = WssCustomRoute(stealth);
	result.custom = result.route.has_value();
	if (!result.route) {
		result.route = OfficialRoute(protocolDcId);
	}
	if (!result.route) {
		return result;
	}
	const auto &route = *result.route;
	result.prefersFallback = PreferRelayFallback(route);
	result.selectedRelayHost = result.prefersFallback
		? route.relayHostFallback
		: route.relayHost;
	if (result.custom) {
		return result;
	}
	result.suppressed = RouteSuppressed(route);
	{
		QMutexLocker lock(&RelayPreferencesMutex);
		const auto i = RouteHealthByDomain.find(
			NetworkKey(route.metered, route.domain));
		if (i != end(RouteHealthByDomain)) {
			result.consecutiveFailures = i->second.consecutiveFailures;
			result.suppressedFor = std::max(
				i->second.suppressedUntil - crl::now(),
				crl::time(0));
		}
	}
	return result;
}

WssSocket::WssSocket(
	not_null<RuntimeEnvironment*> runtime,
	not_null<QThread*> thread,
	const QNetworkProxy &proxy,
	bool protocolForFiles,
	WssRoute route)
: AbstractSocket(runtime, thread)
, _route(std::move(route)) {
	_socket.moveToThread(thread);
	_socket.setProxy(proxy);
	_socket.setPeerVerifyMode(QSslSocket::VerifyPeer);
	_forFiles = protocolForFiles;
	if (protocolForFiles) {
		_socket.setSocketOption(
			QAbstractSocket::SendBufferSizeSocketOption,
			kFilesSendBufferSize);
		_socket.setSocketOption(
			QAbstractSocket::ReceiveBufferSizeSocketOption,
			kFilesReceiveBufferSize);
	}
	const auto wrap = [&](auto handler) {
		return [=](auto &&...args) {
			InvokeQueued(this, [=] { handler(args...); });
		};
	};
	using Error = QAbstractSocket::SocketError;
	connect(
		&_socket,
		&QAbstractSocket::connected,
		wrap([=] { onTcpConnected(); }));
	connect(
		&_socket,
		&QSslSocket::encrypted,
		wrap([=] { onEncrypted(); }));
	connect(
		&_socket,
		&QSslSocket::disconnected,
		wrap([=] { _disconnected.fire({}); }));
	connect(
		&_socket,
		&QSslSocket::readyRead,
		wrap([=] { onReadyRead(); }));
	connect(
		&_socket,
		&QAbstractSocket::errorOccurred,
		wrap([=](Error e) { handleError(e); }));
}

WssSocket::~WssSocket() {
	if (!_openedAt) {
		return;
	} else if (_rotated) {
		// A tunnel file connection lives for one part; a line for each of
		// them would flood the log, so they are summed up instead.
		NoteRotatedTunnelSocket(
			_runtime,
			_bytesSent,
			_bytesReceived,
			crl::now() - _openedAt);
		return;
	}
	// One line per relay socket: which route it took, how far the handshake
	// got, how much went each way and how long it lived.
	const auto since = [&](crl::time at) {
		return at ? QString::number(at - _openedAt) : u"-1"_q;
	};
	WriteProxyDiagnosticsLine(_runtime, {
		.source = ProxyDiagnosticsSource::Network,
		.phase = ProxyDiagnosticsPhase::AttemptSummary,
		.severity = ProxyDiagnosticsSeverity::Info,
		.transport = _route.tunnel
			? u"WSSTunnel"_q
			: IsCdn(_route)
			? u"WSSFront"_q
			: u"WSS"_q,
		.socketId = _debugId,
		.message = u"wss_session host=%1 tcp=%2 upgraded=%3 tx=%4 rx=%5 ready_ms=%6 first_data_ms=%7 life_ms=%8 upgrade_retries=%9"_q
			.arg(_currentHost)
			.arg(_tcpConnected ? 1 : 0)
			.arg(_upgraded ? 1 : 0)
			.arg(_bytesSent)
			.arg(_bytesReceived)
			.arg(since(_upgradedAt))
			.arg(since(_firstDataAt))
			.arg(crl::now() - _openedAt)
			.arg(_upgradeRetries),
		.route = _route.domain,
	});
}

void WssSocket::connectToHost(const QString &address, int port) {
	Q_UNUSED(port);
	// MTProto-over-WSS always connects to the relay route; the DC
	// endpoint (address, port) is intentionally ignored - the relay routes
	// to the right data center based on the SNI / Host domain.
	if (_route.tunnel) {
		_route.path = u"/apiws?dst="_q + address;
	}
	_usedFallback = PreferRelayFallback(_route);
	_openedAt = crl::now();
	connectToRelayHost();
}

void WssSocket::connectToRelayHost() {
	const auto host = _usedFallback ? _route.relayHostFallback : _route.relayHost;
	_currentHost = host;
	_tcpConnected = false;
	_socket.setPeerVerifyName(_route.domain);
	_socket.connectToHostEncrypted(
		host,
		quint16(_route.relayPort),
		_route.domain);
}

bool WssSocket::plainDcMarker() const {
	return IsCdn(_route);
}

bool WssSocket::outputDrained() const {
	// A photo going out slowly gets no answer until its part is complete, so
	// silence while bytes still wait to be written is an upload in progress,
	// not a frozen front.
	return !_socket.bytesToWrite() && !_socket.encryptedBytesToWrite();
}

void WssSocket::noteFrontFailed() {
	if (!IsCdn(_route) || _frontFailureNoted) {
		return;
	}
	_frontFailureNoted = true;
	AdvanceCdn(_route);
	if (!_tcpConnected
		&& (TcpRecentlyConnected(_route, _currentHost)
			|| TcpRecentlyConnected(_route, kAnyCdnHost))) {
		// Another front reached TCP just now: the provider dropped this
		// flow's SYN, the fronts are fine.
		return;
	}
	// A front refused at any stage, 503 included, is counted: otherwise a
	// Flowseal-wide outage would never reach the tunnel.
	NoteRouteUnreachable(_route);
}

bool WssSocket::takeRotation() {
	const auto limit = _forFiles ? kTunnelRotateBytes : kTunnelMainRotateBytes;
	if (!_route.tunnel || _bytesReceived < limit) {
		return false;
	}
	_rotated = true;
	return true;
}

bool WssSocket::isGoodStartNonce(bytes::const_span nonce) {
	Expects(nonce.size() >= 2 * sizeof(uint32));

	const auto zero = binary::Read<uchar>(nonce);
	const auto first = binary::Read<uint32>(nonce);
	const auto second = binary::ReadAt<uint32>(nonce, sizeof(uint32));
	const auto reserved01 = 0x000000EFU;
	const auto reserved11 = 0x44414548U;
	const auto reserved12 = 0x54534F50U;
	const auto reserved13 = 0x20544547U;
	const auto reserved14 = 0xEEEEEEEEU;
	const auto reserved15 = 0xDDDDDDDDU;
	const auto reserved16 = 0x02010316U;
	const auto reserved21 = 0x00000000U;
	return (zero != reserved01)
		&& (first != reserved11)
		&& (first != reserved12)
		&& (first != reserved13)
		&& (first != reserved14)
		&& (first != reserved15)
		&& (first != reserved16)
		&& (second != reserved21);
}

void WssSocket::timedOut() {
	if (IsCdn(_route)) {
		if (!_upgraded || !_bytesReceived) {
			noteFrontFailed();
		} else if (_bytesReceived < kCdnProofBytes && outputDrained()) {
			// The front answered and then went quiet with nothing left to
			// send: the freeze the tunnel suffers. Counted apart from
			// refusals, and only a session past kCdnProofBytes clears it.
			AdvanceCdn(_route);
			NoteCdnStalled(_route, _bytesReceived);
		}
		return;
	}
	if (_upgraded) {
		if (_route.tunnel
			&& !_bytesReceived
			&& crl::now() - _upgradedAt >= kTunnelSilentAfter) {
			// The tunnel upgraded and then delivered nothing at all. A tunnel
			// that froze after some data is throttled, not dead: suppressing
			// it sent DC1 to direct TCP, which the same network blocks
			// outright, and files did not load at all for two minutes.
			NoteRouteUnreachable(_route);
			logError(0, u"WSS tunnel silent after upgrade"_q);
		}
		return;
	}
	if (!_tcpConnected && TcpRecentlyConnected(_route, _currentHost)) {
		// Соседние сокеты к этому адресу только что подключались: провайдер
		// съел SYN одного потока. Новый сокет пройдёт, а переход на запасной
		// адрес или в туннель здесь только навредит.
		return;
	}
	// The session watchdog is killing this socket before any socket error
	// arrived. Remember which relay host stalled so the next socket starts
	// from the other one instead of repeating the same dead-host attempt.
	if (!_upgraded && !_hostFlipped) {
		NoteRelayAttemptFailed(_route, _usedFallback);
	}
	if (!_upgraded && !_tcpConnected) {
		// Не дошли даже до установленного TCP: адрес релея недоступен, а не
		// протокол сломан.
		if (IsOfficialRelay(_route) && !_usedFallback) {
			NoteRouteUnreachable(RelayAddressRoute(_route));
		}
		NoteRouteUnreachable(_route);
		SuppressRelayAddressWithDomain(_route);
	}
}

bool WssSocket::isConnected() {
	return _upgraded
		&& (_socket.state() == QAbstractSocket::ConnectedState);
}

bool WssSocket::hasBytesAvailable() {
	return !_readBuffer.isEmpty();
}

int64 WssSocket::read(bytes::span buffer) {
	const auto count = std::min(
		int64(buffer.size()),
		int64(_readBuffer.size()));
	if (count <= 0) {
		return 0;
	}
	binary::Copy(
		buffer,
		bytes::make_span(_readBuffer.constData(), count));
	_readBuffer.remove(0, int(count));
	return count;
}

void WssSocket::write(bytes::const_span prefix, bytes::const_span buffer) {
	Expects(!buffer.empty());

	// Frame boundaries are free EXCEPT for the very first binary frame after
	// the upgrade: the relay parses the 64-byte obfuscation header out of that
	// single frame's payload and never revisits the decision. A shorter first
	// frame is fatal and silent - the relay simply never answers, which looks
	// exactly like a network problem. Neither one TCP write nor real WebSocket
	// fragmentation helps; only the frame payload counts. Measured against the
	// live relays on 2026-08-08: 63 bytes never answered, 64 always did.
	// Combining the header with the first packet keeps that guarantee here.
	if (prefix.empty()) {
		sendFrame(0x2, buffer);
		return;
	}
	auto combined = bytes::vector(prefix.size() + buffer.size());
	auto combinedBytes = bytes::make_span(combined);
	binary::Copy(combinedBytes, prefix);
	binary::Copy(combinedBytes.subspan(prefix.size()), buffer);
	sendFrame(0x2, bytes::make_span(combined));
}

int32 WssSocket::debugState() {
	return _socket.state();
}

QString WssSocket::debugPostfix() const {
	return u"WS"_q;
}

HandshakePhase WssSocket::handshakePhase() const {
	return _phase;
}

QString WssSocket::transportName() const {
	return u"WSS"_q;
}

void WssSocket::handleError(int errorCode) {
	// On a connect/handshake failure, retry once via the other relay host
	// (hardcoded IP <-> domain) before giving up, so a blocked or stale
	// relay IP does not kill web-relay connectivity. The failure is recorded
	// so the next socket starts from the host that still may work.
	if (!_upgraded && !_hostFlipped && HasRelayFallback(_route)) {
		NoteRelayAttemptFailed(_route, _usedFallback);
		_hostFlipped = true;
		_usedFallback = !_usedFallback;
		_incoming = QByteArray();
		_phase = HandshakePhase::None;
		_socket.abort();
		connectToRelayHost();
		return;
	}
	if (!_upgraded && !_hostFlipped) {
		NoteRelayAttemptFailed(_route, _usedFallback);
	}
	if (!_upgraded) {
		noteFrontFailed();
	}
	if (!_upgraded
		&& !_tcpConnected
		&& !_route.tunnel
		&& !IsCdn(_route)
		&& !TcpRecentlyConnected(_route, _currentHost)) {
		// Refused outright (a reset, a reject, no such host) instead of
		// staying silent: the session never waits out a budget for such a
		// socket, so timedOut() never counted it, the relay was never
		// suppressed and the fronts were never tried (VM test 02.10: two
		// minutes of retries against a rejecting relay).
		if (IsOfficialRelay(_route) && _hostFlipped) {
			NoteRouteUnreachable(RelayAddressRoute(_route));
		}
		NoteRouteUnreachable(_route);
		SuppressRelayAddressWithDomain(_route);
	}
	logError(errorCode, _socket.errorString());
	_error.fire_copy(errorCode);
}

void WssSocket::onTcpConnected() {
	_tcpConnected = true;
	NoteTcpConnected(_route, _currentHost);
}

void WssSocket::onEncrypted() {
	_phase = HandshakePhase::TcpConnected;
	connectionProgress(_phase);
	sendHttpUpgrade();
	_phase = HandshakePhase::ClientHelloSent;
	connectionProgress(_phase);
}

void WssSocket::sendHttpUpgrade() {
	_secWebSocketKey = QString::fromLatin1(RandomBytes(16).toBase64());
	auto host = _route.domain;
	if (_route.relayPort != 443) {
		host += u":%1"_q.arg(_route.relayPort);
	}
	const auto request = (u"GET %1 HTTP/1.1\r\n"
		u"Host: %2\r\n"
		u"Upgrade: websocket\r\n"
		u"Connection: Upgrade\r\n"
		u"Sec-WebSocket-Key: %3\r\n"
		u"Sec-WebSocket-Version: 13\r\n"
		u"Sec-WebSocket-Protocol: binary\r\n"
		u"Origin: https://web.telegram.org\r\n"
		u"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
		u"AppleWebKit/537.36 (KHTML, like Gecko) "
		u"Chrome/131.0.0.0 Safari/537.36\r\n"
		u"\r\n"_q).arg(_route.path, host, _secWebSocketKey);
	const auto utf8 = request.toUtf8();
	_socket.write(utf8);
}

bool WssSocket::tryFinishUpgrade() {
	const auto end = _incoming.indexOf("\r\n\r\n");
	if (end < 0) {
		if (_incoming.size() > kWssHeaderLimit) {
			logError(0, u"WSS HTTP response too large"_q);
			_error.fire_copy(AbstractConnection::kErrorCodeOther);
		}
		return false;
	}
	const auto header = _incoming.left(end);
	_incoming.remove(0, end + 4);
	if (!header.contains(" 101 ") && !header.contains(" 101\r")) {
		if (retryRefusedUpgrade(header)) {
			return false;
		}
		noteFrontFailed();
		if (_route.tunnel && header.startsWith("HTTP/1.1 429")) {
			NoteTunnelQuotaExhausted(_route);
		}
		logError(0, u"WSS HTTP upgrade rejected"_q);
		_error.fire_copy(AbstractConnection::kErrorCodeOther);
		return false;
	}
	if (!checkUpgradeAccept(header)) {
		logError(0, u"WSS Sec-WebSocket-Accept mismatch"_q);
		_error.fire_copy(AbstractConnection::kErrorCodeOther);
		return false;
	}
	_upgraded = true;
	_upgradedAt = crl::now();
	if (!_route.tunnel && !IsCdn(_route)) {
		// The Cloudflare tunnel upgrades fine and then freezes after ~16 KB
		// on a throttled network; it proves itself in parseFrames instead,
		// and so do the fronts, which also upgrade for silent paths.
		NoteRouteReachable(_route);
		if (IsOfficialRelay(_route) && !_usedFallback) {
			// Only an answer through the hardcoded address clears it; the
			// DNS fallback reaches another one.
			NoteRouteReachable(RelayAddressRoute(_route));
		}
	}
	NoteRelayUpgraded(_route, _usedFallback);
	_phase = HandshakePhase::ServerHelloOk;
	connectionProgress(_phase);
	_connected.fire({});
	return true;
}

bool WssSocket::retryRefusedUpgrade(const QByteArray &header) {
	// A front connection is either served at once or answers 503 to every
	// upgrade; an empty keep-alive 503 leaves the connection clean for the
	// next request, which costs ~25 ms against a new TCP+TLS dial.
	if (!IsCdn(_route)
		|| _upgradeRetries >= kCdnUpgradeRetries
		|| !_incoming.isEmpty()
		|| !(header.startsWith("HTTP/1.1 503")
			|| header.startsWith("HTTP/1.1 429"))) {
		return false;
	}
	const auto lowered = header.toLower() + "\r\n";
	if (!lowered.contains("\r\ncontent-length: 0\r\n")
		|| lowered.contains("connection: close")) {
		return false;
	}
	++_upgradeRetries;
	sendHttpUpgrade();
	return true;
}

bool WssSocket::checkUpgradeAccept(const QByteArray &header) const {
	const auto expected = QCryptographicHash::hash(
		_secWebSocketKey.toLatin1()
			+ QByteArrayLiteral("258EAFA5-E914-47DA-95CA-C5AB0DC85B11"),
		QCryptographicHash::Sha1).toBase64();
	const auto lowered = header.toLower();
	const auto marker = QByteArrayLiteral("sec-websocket-accept:");
	const auto pos = lowered.indexOf(marker);
	if (pos < 0) {
		return false;
	}
	auto valueEnd = header.indexOf('\n', pos);
	if (valueEnd < 0) {
		valueEnd = header.size();
	}
	const auto from = pos + marker.size();
	const auto value = header.mid(from, valueEnd - from).trimmed();
	return (value == expected);
}

void WssSocket::onReadyRead() {
	_incoming += _socket.readAll();
	if (!_upgraded && !tryFinishUpgrade()) {
		return;
	}
	if (_upgraded) {
		parseFrames();
	}
}

void WssSocket::parseFrames() {
	auto produced = false;
	auto offset = 0;
	const auto total = int(_incoming.size());
	const auto data = bytes::make_span(_incoming.constData(), total);
	const auto byteAt = [&](int index) {
		return gsl::to_integer<quint8>(data[index]);
	};
	while (total - offset >= 2) {
		const auto opcode = (byteAt(offset) & 0x0f);
		const auto masked = ((byteAt(offset + 1) & 0x80) != 0);
		auto length = quint64(byteAt(offset + 1) & 0x7f);
		auto headerLen = 2;
		if (length == 126) {
			if (total - offset < 4) {
				break;
			}
			length = (quint64(byteAt(offset + 2)) << 8)
				| quint64(byteAt(offset + 3));
			headerLen = 4;
		} else if (length == 127) {
			if (total - offset < 10) {
				break;
			}
			length = 0;
			for (auto i = 0; i != 8; ++i) {
				length = (length << 8) | quint64(byteAt(offset + 2 + i));
			}
			headerLen = 10;
		}
		if (length > kWssMaxFrame) {
			logError(0, u"WSS frame too large"_q);
			_error.fire_copy(AbstractConnection::kErrorCodeOther);
			return;
		}
		const auto maskLen = masked ? 4 : 0;
		const auto frameLen = quint64(headerLen) + maskLen + length;
		if (quint64(total - offset) < frameLen) {
			break;
		}
		const auto mask = data.subspan(offset + headerLen, maskLen);
		const auto payload = data.subspan(
			offset + headerLen + maskLen,
			int(length));
		if (opcode == 0x8) { // close
			logError(0, u"WSS close frame received"_q);
			_error.fire_copy(AbstractConnection::kErrorCodeOther);
			return;
		} else if (opcode == 0x9) { // ping -> pong
			sendFrame(0xA, payload);
		} else if (opcode == 0x0 || opcode == 0x1 || opcode == 0x2) {
			if (length > 0) {
				_bytesReceived += qint64(length);
				if (_route.tunnel
					&& !_tunnelProven
					&& _bytesReceived >= kTunnelRotateBytes) {
					_tunnelProven = true;
					NoteRouteReachable(_route);
				}
				if (IsCdn(_route) && !_frontAnswered) {
					_frontAnswered = true;
					NoteRouteReachable(_route);
				}
				if (IsCdn(_route)
					&& !_frontProven
					&& _bytesReceived >= kCdnProofBytes) {
					_frontProven = true;
					NoteCdnProven(_route);
				}
				const auto at = int(_readBuffer.size());
				const auto count = int(length);
				_readBuffer.resize(at + count);
				auto out = bytes::make_detached_span(_readBuffer).subspan(at);
				if (masked) {
					for (auto i = 0; i != count; ++i) {
						out[i] = bytes::type(
							byteAt(offset + headerLen + maskLen + i)
							^ gsl::to_integer<quint8>(mask[i % 4]));
					}
				} else {
					binary::Copy(out, payload);
				}
				produced = true;
			}
		}
		offset += int(frameLen);
	}
	if (offset > 0) {
		_incoming.remove(0, offset);
	}
	if (produced) {
		if (_phase == HandshakePhase::ServerHelloOk) {
			_phase = HandshakePhase::FirstDataReceived;
			_firstDataAt = crl::now();
			connectionProgress(_phase);
		}
		_readyRead.fire({});
	}
}

void WssSocket::sendFrame(quint8 opcode, bytes::const_span data) {
	const auto size = int(data.size());
	if (opcode == 0x2) {
		_bytesSent += size;
	}
	auto frame = QByteArray();
	frame.reserve(size + 14);
	frame.append(char(0x80 | opcode));
	if (size < 126) {
		frame.append(char(0x80 | size));
	} else if (size <= 0xffff) {
		frame.append(char(0x80 | 126));
		frame.append(char((size >> 8) & 0xff));
		frame.append(char(size & 0xff));
	} else {
		frame.append(char(0x80 | 127));
		for (auto i = 7; i >= 0; --i) {
			frame.append(char((quint64(size) >> (i * 8)) & 0xff));
		}
	}
	const auto mask = RandomBytes(4);
	frame.append(mask);
	const auto maskBytes = bytes::make_span(mask);
	const auto base = int(frame.size());
	frame.resize(base + size);
	auto out = bytes::make_detached_span(frame).subspan(base);
	for (auto i = 0; i != size; ++i) {
		out[i] = bytes::type(
			gsl::to_integer<quint8>(data[i])
			^ gsl::to_integer<quint8>(maskBytes[i % 4]));
	}
	_socket.write(frame);
}

} // namespace MTP::details
