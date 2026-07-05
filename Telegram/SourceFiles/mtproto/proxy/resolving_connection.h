/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#pragma once

#include "mtproto/mtproto_auth_key.h"
#include "mtproto/connection_abstract.h"
#include "base/timer.h"

#include <vector>

namespace MTP {
namespace details {

class ResolvingConnection : public AbstractConnection {
public:
	ResolvingConnection(
		not_null<Instance*> instance,
		QThread *thread,
		const ProxyData &proxy,
		ConnectionPointer &&child);

	ConnectionPointer clone(const ProxyData &proxy) override;

	crl::time pingTime() const override;
	crl::time fullConnectTimeout() const override;
	void sendData(mtpBuffer &&buffer) override;
	void disconnectFromServer() override;
	void connectToServer(
		const QString &address,
		int port,
		const bytes::vector &protocolSecret,
		int16 protocolDcId,
		bool protocolForFiles) override;
	bool isConnected() const override;

	int32 debugState() const override;

	QString transport() const override;
	QString tag() const override;

private:
	struct RouteAttempt {
		ConnectionPointer child;
		int ipIndex = -1;
	};

	void startRouteAttempts();
	void startNextRouteAttempt();
	void scheduleRouteRace();
	void refreshAttemptTimeout();
	void handleRouteAttemptTimeout();
	[[nodiscard]] int activeRouteAttempts() const;
	[[nodiscard]] std::vector<int> routeOrder() const;
	[[nodiscard]] RouteAttempt *findRouteAttempt(AbstractConnection *child);
	void removeRouteAttempt(AbstractConnection *child);
	void addRouteAttempt(int ipIndex);
	void promoteRouteAttempt(AbstractConnection *child);
	void emitError(int errorCode);

	void domainResolved(
		const QString &host,
		const QStringList &ips,
		qint64 expireAt);
	void handleError(AbstractConnection *child, int errorCode);
	void handleConnected(AbstractConnection *child);
	void handleDisconnected(AbstractConnection *child);
	void handleReceivedData(AbstractConnection *child);

	not_null<Instance*> _instance;
	ConnectionPointer _child;
	std::vector<RouteAttempt> _routeAttempts;
	std::vector<int> _routeOrder;
	bool _connected = false;
	int _ipIndex = -1;
	int _nextRoutePosition = 0;
	QString _address;
	int _port = 0;
	bytes::vector _protocolSecret;
	int16 _protocolDcId = 0;
	bool _protocolForFiles = false;
	base::Timer _timeoutTimer;
	base::Timer _routeRaceTimer;

};

} // namespace details
} // namespace MTP
