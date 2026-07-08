/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#pragma once

#include "base/basic_types.h"

#include <QtCore/QObject>
#include <QtCore/QStringList>

#include <functional>
#include <memory>

namespace MTP {

class RuntimeEnvironment;

namespace details {

enum class DnsResolverCacheState {
	Fresh,
	Inflight,
	Negative,
	Expired,
};

class DnsResolverCache final {
public:
	using Callback = std::function<void(QString, QStringList, qint64)>;

	explicit DnsResolverCache(not_null<RuntimeEnvironment*> runtime);
	DnsResolverCache(const DnsResolverCache &other) = delete;
	DnsResolverCache &operator=(const DnsResolverCache &other) = delete;
	~DnsResolverCache();

	void request(
		QObject *receiver,
		const QString &host,
		Callback callback);
	void resolved(
		const QString &host,
		const QStringList &ips,
		qint64 expireAt);

private:
	struct Storage;

	const not_null<RuntimeEnvironment*> _runtime;
	const std::unique_ptr<Storage> _storage;
};

} // namespace details
} // namespace MTP
