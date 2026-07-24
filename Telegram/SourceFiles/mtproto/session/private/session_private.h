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
#include "mtproto/session/private/auth_factory.h"
#include "mtproto/session/private/connection_factory.h"
#include "mtproto/session/private/message_handler.h"
#include "mtproto/session/private/proxy_port.h"
#include "mtproto/session/private/transport.h"
#include "mtproto/session/session_delegate.h"
#include "mtproto/session/session_role.h"
#include "mtproto/session/session_state.h"

namespace MTP {

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
		ShiftedDcId shiftedDcId,
		SessionRole role,
		uint64 proxyGeneration = 0,
		not_null<SessionProxyPort*> proxyPort = &DefaultSessionProxyPort(),
		not_null<SessionConnectionFactory*> connectionFactory
			= &DefaultSessionConnectionFactory(),
		not_null<SessionAuthKeyFactory*> authKeyFactory
			= &DefaultSessionAuthKeyFactory());
	~SessionPrivate();

	[[nodiscard]] int32 getShiftedDcId() const;
	void dcOptionsChanged();
	void cdnConfigChanged();

	[[nodiscard]] int32 getState() const;
	[[nodiscard]] QString transport() const;

	void updateAuthKey();
	void restartNow();
	void migrateProxy(uint64 generation);
	void sendPingForce();
	void tryToSend();

private:
	friend class SessionTransport;
	friend class SessionMessageHandler;

	static constexpr auto kUpdateStateAlways = 666;

	struct SentContainer {
		crl::time sent = 0;
		std::vector<mtpMsgId> messages;
	};

	void connectToServer(bool afterConfig = false);
	void doDisconnect();
	void restart();
	void onSentSome(uint64 size);
	void onReceivedSome();

	void handleReceived();

	void sendPingByTimer();
	void setConnectionNotice(ConnectionNotice notice);
	void reportPingTime(crl::time time);
	void logMtprotoEvent(
		ProxyDiagnosticsPhase phase,
		ProxyDiagnosticsSeverity severity,
		const QString &message) const;
	[[nodiscard]] QString mtprotoLogDc() const;
	[[nodiscard]] int16 getProtocolDcId() const;

	void checkSentRequests();

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

	bool setState(int state, int ifState = kUpdateStateAlways);

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
		std::unique_ptr<SessionBoundKeyCreator> keyCreator;
		mtpMsgId bindMsgId = 0;
		crl::time bindMessageSent = 0;
	};

	const not_null<Instance*> _instance;
	const not_null<SessionDelegate*> _delegate;
	const not_null<RuntimeEnvironment*> _runtime;
	const not_null<SessionProxyPort*> _proxyPort;
	const not_null<SessionConnectionFactory*> _connectionFactory;
	const not_null<SessionAuthKeyFactory*> _authKeyFactory;
	const ShiftedDcId _shiftedDcId = 0;
	const SessionRole _role = SessionRole::Auxiliary;
	DcType _realDcType = DcType();
	DcType _currentDcType = DcType();

	mutable QReadWriteLock _stateMutex;
	int _state = DisconnectedState;

	SessionTransport _transport;
	SessionMessageHandler _messageHandler;
	RequestState _requestState;
	SessionState _sessionState;
	AuthState _authState;

};

} // namespace details
} // namespace MTP
