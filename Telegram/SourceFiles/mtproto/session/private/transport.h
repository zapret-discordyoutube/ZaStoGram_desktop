/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#pragma once

#include "mtproto/config/mtproto_dc_options.h"
#include "mtproto/runtime/runtime_environment.h"
#include "mtproto/session/private/proxy_port.h"
#include "mtproto/transport/connection_abstract.h"

namespace MTP::details {

class SessionPrivate;

class SessionTransport final {
public:
	SessionTransport(
		not_null<SessionPrivate*> owner,
		not_null<RuntimeEnvironment*> runtime,
		not_null<QThread*> thread);

	void start();
	void connectToServer(bool afterConfig = false);
	void restartNow();
	void migrateProxy(uint64 generation, bool scout);
	void releaseProxyMigration(uint64 generation);
	void restart();
	void doDisconnect();
	void destroyAllConnections();
	void onSentSome(uint64 size);
	void onReceivedSome();
	void startContainerCleanup();
	void retryByTimer();
	void waitConnectedFailed();
	void brokerQueueDeadlineFired();
	void waitReceivedFailed();
	void waitBetterFailed();
	void markConnectionOld();
	void confirmBestConnection();
	void removeTestConnection(not_null<AbstractConnection*> connection);
	void setRetryTimeout(int timeout);
	void scheduleRetryTimeout(int timeout);
	void schedulePing(crl::time timeout);
	void scheduleCheckSentRequests(crl::time timeout);
	void scheduleClearOldContainers(crl::time timeout, bool repeated);
	void resetRetryTimeout();
	void noteMtprotoPayloadReceived();
	void logInfo(const QString &message) const;
	void sendData(
		mtpBuffer &&buffer,
		AbstractConnection::SendDataContext context);
	[[nodiscard]] bool retryTimerActive() const;
	[[nodiscard]] bool checkSentRequestsTimerActive() const;
	[[nodiscard]] bool clearOldContainersTimerActive() const;
	[[nodiscard]] int retryTimeout() const;
	[[nodiscard]] qint64 retryWillFinish() const;
	[[nodiscard]] AbstractConnection *connection() const;
	[[nodiscard]] bool hasReceivedData() const;
	[[nodiscard]] mtpBuffer takeReceivedData();
	[[nodiscard]] QString activeTransport() const;
	[[nodiscard]] QString connectionTag() const;
	[[nodiscard]] crl::time connectionPingTime() const;
	[[nodiscard]] AbstractConnection::TransportServiceRequest serviceRequest()
		const;
	[[nodiscard]] bool serviceRequestNeeded(
		AbstractConnection::TransportServiceRequest request) const;
	[[nodiscard]] mtpBuffer prepareSecurePacket(
		uint64 keyId,
		MTPint128 msgKey,
		uint32 size) const;
	[[nodiscard]] bool empty() const;
	[[nodiscard]] SessionProxyAttempt currentProxyAttempt() const;

private:
	struct TestConnection {
		ConnectionPointer data;
		int priority = 0;
		QString endpoint;
		MtProxy::EndpointId mtproxyEndpoint;
		SessionProxyEndpointUse mtproxyUse = SessionProxyEndpointUse::Main;
		SessionProxyLease mtproxyLease;
		ProxyConnectionAttempt mtproxyAttempt;
		crl::time mtproxyAttemptStartedAt = 0;
	};
	struct ConnectionState {
		ConnectionPointer connection;
		MtProxy::EndpointId mtproxyEndpoint;
		SessionProxyEndpointUse mtproxyUse = SessionProxyEndpointUse::Main;
		ProxyConnectionAttempt mtproxyAttempt;
		crl::time mtproxyAttemptStartedAt = 0;
		uint64 proxyGeneration = 0;
		bool proxyMigrationSuspended = false;
		bool proxyMigrationScout = false;
		bool mtprotoDataReceived = false;
		int mtprotoSilentTimeouts = 0;
		std::vector<TestConnection> testConnections;
		std::vector<SessionProxyTicket> brokerTickets;
		crl::time startedConnectingAt = 0;
	};
	struct TimingState {
		TimingState(
			not_null<RuntimeEnvironment*> runtime,
			not_null<SessionTransport*> owner,
			not_null<QThread*> thread);

		RuntimeTimer retryTimer;
		int retryTimeout = 1;
		qint64 retryWillFinish = 0;
		RuntimeTimer oldConnectionTimer;
		bool oldConnection = true;
		RuntimeTimer waitForConnectedTimer;
		RuntimeTimer waitForReceivedTimer;
		RuntimeTimer waitForBetterTimer;
		RuntimeTimer brokerQueueDeadlineTimer;
		crl::time waitForReceived = 0;
		crl::time waitForConnected = 0;
		crl::time firstSentAt = -1;
		RuntimeTimer pingSender;
		RuntimeTimer checkSentRequestsTimer;
		RuntimeTimer clearOldContainersTimer;
	};

	[[nodiscard]] bool appendTestConnection(
		DcOptions::Variants::Protocol protocol,
		const QString &ip,
		int port,
		const bytes::vector &protocolSecret,
		bool protocolForFiles);
	void connectingTimedOut();
	void requestCDNConfig();
	void handleError(int errorCode);
	void onError(
		not_null<AbstractConnection*> connection,
		qint32 errorCode);
	void onConnected(not_null<AbstractConnection*> connection);
	void onDisconnected(not_null<AbstractConnection*> connection);
	void reportMtproxyConnectionUsable(const TestConnection &connection);
	void removeConnectionBrokerTicket(SessionProxyTicketId id);
	void armWaitForConnectedTimer();
	[[nodiscard]] SessionProxyAttempt proxyAttempt(
		const TestConnection &connection) const;

	const not_null<SessionPrivate*> _owner;
	ConnectionState _state;
	TimingState _timing;
};

} // namespace MTP::details
