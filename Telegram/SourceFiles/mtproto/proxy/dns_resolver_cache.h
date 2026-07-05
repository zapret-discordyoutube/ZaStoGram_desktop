/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#pragma once

#include <QtCore/QObject>
#include <QtCore/QStringList>

#include <functional>

namespace MTP {

class Instance;

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

	[[nodiscard]] static DnsResolverCache &Instance();

	void request(
		MTP::Instance *instance,
		QObject *receiver,
		const QString &host,
		Callback callback);
	void resolved(
		const QString &host,
		const QStringList &ips,
		qint64 expireAt);

private:
	void connectInstance(MTP::Instance *instance);
};

} // namespace details
} // namespace MTP
