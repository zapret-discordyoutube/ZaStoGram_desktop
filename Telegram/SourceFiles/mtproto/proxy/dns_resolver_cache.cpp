/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "mtproto/proxy/dns_resolver_cache.h"

#include "mtproto/runtime/runtime_environment.h"
#include "base/invoke_queued.h"
#include "base/timer.h"

#include <QtCore/QMutex>
#include <QtCore/QPointer>

#include <map>
#include <vector>

namespace MTP::details {
namespace {

// An in-flight resolve older than this is considered lost (the resolving
// Instance may have been destroyed before firing proxyDomainResolved) and
// is restarted by the next request, otherwise the host would stay
// "resolving" forever and every connection through it would hang.
constexpr auto kInflightRetryTimeout = 30 * crl::time(1000);

struct DnsResolverSubscriber {
	QPointer<QObject> receiver;
	DnsResolverCache::Callback callback;
};

struct DnsResolverEntry {
	DnsResolverCacheState state = DnsResolverCacheState::Expired;
	QStringList ips;
	qint64 expireAt = 0;
	crl::time inflightSince = 0;
	std::vector<DnsResolverSubscriber> subscribers;
};

void PushResult(
		QPointer<QObject> receiver,
		DnsResolverCache::Callback callback,
		const QString &host,
		const QStringList &ips,
		qint64 expireAt) {
	if (!receiver || !callback) {
		return;
	}
	InvokeQueued(receiver, [=, callback = std::move(callback)]() mutable {
		if (receiver) {
			callback(host, ips, expireAt);
		}
	});
}

} // namespace

struct DnsResolverCache::Storage {
	QMutex mutex;
	std::map<QString, DnsResolverEntry> entries;
};

DnsResolverCache::DnsResolverCache(not_null<RuntimeEnvironment*> runtime)
: _runtime(runtime)
, _storage(std::make_unique<Storage>()) {
}

DnsResolverCache::~DnsResolverCache() = default;

void DnsResolverCache::request(
		QObject *receiver,
		const QString &host,
		Callback callback) {
	if (!receiver || host.isEmpty()) {
		return;
	}

	auto cachedIps = QStringList();
	auto cachedExpireAt = qint64(0);
	auto useCached = false;
	auto startResolve = false;
	{
		QMutexLocker lock(&_storage->mutex);
		auto &entry = _storage->entries[host];
		const auto now = crl::now();
		if ((entry.state == DnsResolverCacheState::Fresh
				|| entry.state == DnsResolverCacheState::Negative)
			&& entry.expireAt > now) {
			cachedIps = entry.ips;
			cachedExpireAt = entry.expireAt;
			useCached = true;
		} else {
			const auto inflight = (entry.state
				== DnsResolverCacheState::Inflight);
			const auto lost = inflight
				&& (now - entry.inflightSince > kInflightRetryTimeout);
			if (!inflight) {
				entry = DnsResolverEntry();
			}
			if (!inflight || lost) {
				entry.state = DnsResolverCacheState::Inflight;
				entry.inflightSince = now;
				startResolve = true;
			}
			entry.subscribers.push_back({
				.receiver = receiver,
				.callback = std::move(callback),
			});
		}
	}
	if (useCached) {
		PushResult(receiver, std::move(callback), host, cachedIps, cachedExpireAt);
	} else if (startResolve) {
		InvokeQueued(_runtime, [=] {
			if (_runtime->proxyResolver().resolveDomain) {
				_runtime->proxyResolver().resolveDomain(host);
			}
		});
	}
}

void DnsResolverCache::resolved(
		const QString &host,
		const QStringList &ips,
		qint64 expireAt) {
	auto subscribers = std::vector<DnsResolverSubscriber>();
	{
		QMutexLocker lock(&_storage->mutex);
		auto &entry = _storage->entries[host];
		entry.state = ips.empty()
			? DnsResolverCacheState::Negative
			: DnsResolverCacheState::Fresh;
		entry.ips = ips;
		entry.expireAt = expireAt;
		subscribers = std::move(entry.subscribers);
		entry.subscribers.clear();
	}
	for (auto &subscriber : subscribers) {
		PushResult(
			subscriber.receiver,
			std::move(subscriber.callback),
			host,
			ips,
			expireAt);
	}
}

} // namespace MTP::details
