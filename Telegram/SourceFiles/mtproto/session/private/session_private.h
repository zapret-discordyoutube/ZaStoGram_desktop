/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#pragma once

#include "mtproto/details/mtproto_received_ids_manager.h"
#include "mtproto/protocol/mtproto_serialized_request.h"
#include "mtproto/auth/mtproto_auth_key.h"
#include "mtproto/config/mtproto_dc_options.h"
#include "mtproto/transport/connection_abstract.h"
#include "mtproto/proxy/connection_broker.h"
#include "mtproto/proxy/diagnostics.h"
#include "mtproto/proxy/status.h"
#include "mtproto/session/session_delegate.h"
#include "mtproto/session/session_state.h"
#include "base/timer.h"

namespace MTP {
namespace details {
class BoundKeyCreator;
} // namespace details

class Instance;
class RuntimeEnvironment;

namespace details {

class AbstractConnection;
class SessionData;
class SessionDelegate;
class RSAPublicKey;
struct SessionOptions;

class SessionPrivate final : public QObject {
public:
	SessionPrivate(
		not_null<Instance*> instance,
		not_null<SessionDelegate*> delegate,
		not_null<QThread*> thread,
		std::shared_ptr<SessionData> data,
		ShiftedDcId shiftedDcId);
	~SessionPrivate();

	[[nodiscard]] int32 getShiftedDcId() const;
	void dcOptionsChanged();
	void cdnConfigChanged();

	[[nodiscard]] int32 getState() const;
	[[nodiscard]] QString transport() const;

	void updateAuthKey();
	void restartNow();
	void migrateProxy(uint64 generation, bool scout);
	void releaseProxyMigration(uint64 generation);
	void sendPingForce();
	void tryToSend();

private:
	static constexpr auto kUpdateStateAlways = 666;

	struct TestConnection {
		ConnectionPointer data;
		int priority = 0;
		QString endpoint;
		MtProxy::EndpointId mtproxyEndpoint;
		MtProxy::EndpointUse mtproxyUse = MtProxy::EndpointUse::Main;
		MtProxy::EndpointAttemptLease mtproxyLease;
		ProxyConnectionAttempt mtproxyAttempt;
		crl::time mtproxyAttemptStartedAt = 0;
	};
	struct SentContainer {
		crl::time sent = 0;
		std::vector<mtpMsgId> messages;
	};
	enum class HandleResult {
		Success,
		Ignored,
		RestartConnection,
		ResetSession,
		DestroyTemporaryKey,
		ParseError,
	};

	void connectToServer(bool afterConfig = false);
	void connectingTimedOut();
	void doDisconnect();
	void restart();
	void requestCDNConfig();
	void handleError(int errorCode);
	void onError(
		not_null<AbstractConnection*> connection,
		qint32 errorCode);
	void onConnected(not_null<AbstractConnection*> connection);
	void onDisconnected(not_null<AbstractConnection*> connection);
	void onSentSome(uint64 size);
	void onReceivedSome();

	void handleReceived();

	void retryByTimer();
	void waitConnectedFailed();
	void brokerQueueDeadlineFired();
	void waitReceivedFailed();
	void waitBetterFailed();
	void markConnectionOld();
	void sendPingByTimer();
	void destroyAllConnections();
	void reportMtproxyConnectionUsable(const TestConnection &connection);
	void removeConnectionBrokerTicket(ConnectionTicketId id);
	void armWaitForConnectedTimer();

	void confirmBestConnection();
	void removeTestConnection(not_null<AbstractConnection*> connection);
	void setConnectionNotice(ConnectionNotice notice);
	void reportPingTime(crl::time time);
	void logMtprotoEvent(
		ProxyDiagnosticsPhase phase,
		ProxyDiagnosticsSeverity severity,
		const QString &message) const;
	[[nodiscard]] QString mtprotoLogDc() const;
	[[nodiscard]] int16 getProtocolDcId() const;

	void checkSentRequests();
	void clearOldContainers();

	mtpMsgId placeToContainer(
		SerializedRequest &toSendRequest,
		mtpMsgId &bigMsgId,
		bool forceNewMsgId,
		SerializedRequest &req);
	mtpMsgId prepareToSend(
		SerializedRequest &request,
		mtpMsgId currentLastId,
		bool forceNewMsgId);
	mtpMsgId replaceMsgId(
		SerializedRequest &request,
		mtpMsgId newId);
	mtpMsgId RegisterSentRequest(
		base::flat_map<mtpMsgId, SerializedRequest> &haveSent,
		SerializedRequest &request,
		mtpMsgId msgId);

	bool sendSecureRequest(
		SerializedRequest &&request,
		bool needAnyResponse);
	mtpRequestId wasSent(mtpMsgId msgId) const;

	struct OuterInfo {
		mtpMsgId outerMsgId = 0;
		uint64 serverSalt = 0;
		int32 serverTime = 0;
		bool badTime = false;
	};
	[[nodiscard]] HandleResult handleOneReceived(
		const mtpPrime *from,
		const mtpPrime *end,
		uint64 msgId,
		OuterInfo info);
	[[nodiscard]] HandleResult handleGzipPacked(
		const mtpPrime *from,
		const mtpPrime *end,
		uint64 msgId,
		OuterInfo info);
	[[nodiscard]] HandleResult handleMsgContainer(
		const mtpPrime *from,
		const mtpPrime *end,
		uint64 msgId,
		OuterInfo info);
	[[nodiscard]] HandleResult handleMsgsAck(
		const mtpPrime *from,
		const mtpPrime *end,
		uint64 msgId,
		OuterInfo info);
	[[nodiscard]] HandleResult handleBadMsgNotification(
		const mtpPrime *from,
		const mtpPrime *end,
		uint64 msgId,
		OuterInfo info);
	[[nodiscard]] HandleResult handleBadServerSalt(
		const mtpPrime *from,
		const mtpPrime *end,
		uint64 msgId,
		OuterInfo info);
	[[nodiscard]] HandleResult handleMsgsStateInfo(
		const mtpPrime *from,
		const mtpPrime *end,
		uint64 msgId,
		OuterInfo info);
	[[nodiscard]] HandleResult handleMsgsAllInfo(
		const mtpPrime *from,
		const mtpPrime *end,
		uint64 msgId,
		OuterInfo info);
	[[nodiscard]] HandleResult handleMsgDetailedInfo(
		const mtpPrime *from,
		const mtpPrime *end,
		uint64 msgId,
		OuterInfo info);
	[[nodiscard]] HandleResult handleMsgNewDetailedInfo(
		const mtpPrime *from,
		const mtpPrime *end,
		uint64 msgId,
		OuterInfo info);
	[[nodiscard]] HandleResult handleRpcResult(
		const mtpPrime *from,
		const mtpPrime *end,
		uint64 msgId,
		OuterInfo info);
	[[nodiscard]] HandleResult handleNewSessionCreated(
		const mtpPrime *from,
		const mtpPrime *end,
		uint64 msgId,
		OuterInfo info);
	[[nodiscard]] HandleResult handlePong(
		const mtpPrime *from,
		const mtpPrime *end,
		uint64 msgId,
		OuterInfo info);
	[[nodiscard]] HandleResult handleUpdates(
		const mtpPrime *from,
		const mtpPrime *end,
		uint64 msgId,
		OuterInfo info);
	[[nodiscard]] HandleResult handleBindResponse(
		mtpMsgId requestMsgId,
		const mtpBuffer &response);
	mtpBuffer ungzip(const mtpPrime *from, const mtpPrime *end) const;
	void handleMsgsStates(const QVector<MTPlong> &ids, const QByteArray &states);

	// _sessionDataMutex must be locked for read.
	bool setState(int state, int ifState = kUpdateStateAlways);

	[[nodiscard]] bool appendTestConnection(
		DcOptions::Variants::Protocol protocol,
		const QString &ip,
		int port,
		const bytes::vector &protocolSecret,
		bool protocolForFiles);

	// if badTime received - search for ids in sessionData->haveSent and sessionData->wereAcked and sync time/salt, return true if found
	bool requestsFixTimeSalt(const QVector<MTPlong> &ids, const OuterInfo &info);

	// if we had a confirmed fast request use its unixtime as a correct one.
	void correctUnixtimeByFastRequest(
		const QVector<MTPlong> &ids,
		TimeId serverTime);
	void correctUnixtimeWithBadLocal(TimeId serverTime);

	// remove msgs with such ids from sessionData->haveSent, add to sessionData->wereAcked
	void requestsAcked(const QVector<MTPlong> &ids, bool byResponse = false);

	void resend(mtpMsgId msgId, crl::time msCanWait = 0);
	void resendAll();
	void clearSpecialMsgId(mtpMsgId msgId);

	[[nodiscard]] DcType tryAcquireKeyCreation();
	void resetSession();
	void checkAuthKey();
	void authKeyChecked();
	void destroyTemporaryKey();
	void clearUnboundKeyCreator();
	void releaseKeyCreationOnFail();
	void applyAuthKey(AuthKeyPtr &&encryptionKey);
	[[nodiscard]] bool noMediaKeyWithExistingRegularKey() const;
	bool destroyOldEnoughPersistentKey();

	void setCurrentKeyId(uint64 newKeyId);
	void changeSessionId();
	[[nodiscard]] bool markSessionAsStarted();
	[[nodiscard]] uint32 nextRequestSeqNumber(bool needAck);

	[[nodiscard]] bool realDcTypeChanged();
	[[nodiscard]] MTPVector<MTPJSONObjectValue> prepareInitParams();

	struct ConnectionState {
		ConnectionPointer connection;
		MtProxy::EndpointId mtproxyEndpoint;
		MtProxy::EndpointUse mtproxyUse = MtProxy::EndpointUse::Main;
		ProxyConnectionAttempt mtproxyAttempt;
		crl::time mtproxyAttemptStartedAt = 0;
		uint64 proxyGeneration = 0;
		bool proxyMigrationSuspended = false;
		bool proxyMigrationScout = false;
		bool mtprotoDataReceived = false;
		int mtprotoSilentTimeouts = 0;
		std::vector<TestConnection> testConnections;
		std::vector<ConnectionTicket> brokerTickets;
		crl::time startedConnectingAt = 0;
	};
	struct TimingState {
		TimingState(
			not_null<QThread*> thread,
			not_null<SessionPrivate*> owner);

		base::Timer retryTimer;
		int retryTimeout = 1;
		qint64 retryWillFinish = 0;
		base::Timer oldConnectionTimer;
		bool oldConnection = true;
		base::Timer waitForConnectedTimer;
		base::Timer waitForReceivedTimer;
		base::Timer waitForBetterTimer;
		base::Timer brokerQueueDeadlineTimer;
		crl::time waitForReceived = 0;
		crl::time waitForConnected = 0;
		crl::time firstSentAt = -1;
		base::Timer pingSender;
		base::Timer checkSentRequestsTimer;
		base::Timer clearOldContainersTimer;
	};
	struct RequestState {
		mtpPingId pingId = 0;
		mtpPingId pingIdToSend = 0;
		crl::time pingSendAt = 0;
		crl::time pingSentTime = 0;
		mtpMsgId pingMsgId = 0;
		QVector<MTPlong> ackData;
		QVector<MTPlong> resendData;
		base::flat_set<mtpMsgId> stateData;
		ReceivedIdsManager receivedIds;
		base::flat_map<mtpMsgId, mtpRequestId> resendingIds;
		base::flat_map<mtpMsgId, mtpRequestId> ackedIds;
		base::flat_map<mtpMsgId, SerializedRequest> stateAndResendRequests;
		base::flat_map<mtpMsgId, SentContainer> sentContainers;
	};
	struct SessionState {
		explicit SessionState(std::shared_ptr<SessionData> data);

		std::shared_ptr<SessionData> data;
		std::unique_ptr<SessionOptions> options;
		AuthKeyPtr encryptionKey;
		uint64 keyId = 0;
		uint64 sessionId = 0;
		uint64 sessionSalt = 0;
		uint32 messagesCounter = 0;
		bool markedAsStarted = false;
		bool needReset = false;
	};
	struct AuthState {
		std::unique_ptr<BoundKeyCreator> keyCreator;
		mtpMsgId bindMsgId = 0;
		crl::time bindMessageSent = 0;
	};

	const not_null<Instance*> _instance;
	const not_null<SessionDelegate*> _delegate;
	const not_null<RuntimeEnvironment*> _runtime;
	const ShiftedDcId _shiftedDcId = 0;
	DcType _realDcType = DcType();
	DcType _currentDcType = DcType();

	mutable QReadWriteLock _stateMutex;
	int _state = DisconnectedState;

	ConnectionState _connectionState;
	TimingState _timing;
	RequestState _requestState;
	SessionState _sessionState;
	AuthState _authState;

};

} // namespace details
} // namespace MTP
