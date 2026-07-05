/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "mtproto/proxy/dns_resolver_cache.h"

#include "mtproto/mtp_instance.h"
#include "base/invoke_queued.h"
#include "base/timer.h"

#include <QtCore/QMutex>
#include <QtCore/QPointer>

#include <map>
#include <set>
#include <vector>

namespace MTP::details {
namespace {

struct DnsResolverSubscriber {
	QPointer<QObject> receiver;
	DnsResolverCache::Callback callback;
};

struct DnsResolverEntry {
	DnsResolverCacheState state = DnsResolverCacheState::Expired;
	QStringList ips;
	qint64 expireAt = 0;
	std::vector<DnsResolverSubscriber> subscribers;
};

QMutex EntriesMutex;
std::map<QString, DnsResolverEntry> Entries;
std::set<MTP::Instance*> ConnectedInstances;

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

DnsResolverCache &DnsResolverCache::Instance() {
	static auto result = DnsResolverCache();
	return result;
}

void DnsResolverCache::request(
		MTP::Instance *instance,
		QObject *receiver,
		const QString &host,
		Callback callback) {
	if (!instance || !receiver || host.isEmpty()) {
		return;
	}
	connectInstance(instance);

	auto cachedIps = QStringList();
	auto cachedExpireAt = qint64(0);
	auto useCached = false;
	auto startResolve = false;
	{
		QMutexLocker lock(&EntriesMutex);
		auto &entry = Entries[host];
		const auto now = crl::now();
		if ((entry.state == DnsResolverCacheState::Fresh
				|| entry.state == DnsResolverCacheState::Negative)
			&& entry.expireAt > now) {
			cachedIps = entry.ips;
			cachedExpireAt = entry.expireAt;
			useCached = true;
		} else {
			if (entry.state != DnsResolverCacheState::Inflight) {
				entry = DnsResolverEntry();
				entry.state = DnsResolverCacheState::Inflight;
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
		InvokeQueued(instance, [=] {
			instance->resolveProxyDomain(host);
		});
	}
}

void DnsResolverCache::resolved(
		const QString &host,
		const QStringList &ips,
		qint64 expireAt) {
	auto subscribers = std::vector<DnsResolverSubscriber>();
	{
		QMutexLocker lock(&EntriesMutex);
		auto &entry = Entries[host];
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

void DnsResolverCache::connectInstance(MTP::Instance *instance) {
	auto shouldConnect = false;
	{
		QMutexLocker lock(&EntriesMutex);
		shouldConnect = ConnectedInstances.insert(instance).second;
	}
	if (!shouldConnect) {
		return;
	}
	QObject::connect(
		instance,
		&MTP::Instance::proxyDomainResolved,
		instance,
		[=](QString host, QStringList ips, qint64 expireAt) {
			DnsResolverCache::Instance().resolved(host, ips, expireAt);
		},
		Qt::QueuedConnection);
}

} // namespace MTP::details
