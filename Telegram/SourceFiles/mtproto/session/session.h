/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#pragma once

#include "base/timer.h"
#include "mtproto/protocol/mtproto_response.h"
#include "mtproto/proxy/data.h"
#include "mtproto/protocol/mtproto_serialized_request.h"
#include "mtproto/session/session_delegate.h"

#include <QtCore/QTimer>

#include <optional>
#include <utility>
#include <vector>

namespace MTP {

class Instance;
class AuthKey;
using AuthKeyPtr = std::shared_ptr<AuthKey>;
enum class DcType;

namespace details {

class Dcenter;
class SessionPrivate;
class SessionDelegate;

enum class TemporaryKeyType;
enum class CreatingKeyType;

struct SessionOptions {
	SessionOptions() = default;
	SessionOptions(
		const QString &systemLangCode,
		const QString &cloudLangCode,
		const QString &langPackName,
		const ProxyData &proxy,
		bool useIPv4,
		bool useIPv6,
		bool useHttp,
		bool useTcp);

	QString systemLangCode;
	QString cloudLangCode;
	QString langPackName;
	ProxyData proxy;
	bool useIPv4 = true;
	bool useIPv6 = true;
	bool useHttp = true;
	bool useTcp = true;
	ProxyStealthOptions stealth;

};

class Session;
class SessionData final {
public:
	explicit SessionData(not_null<Session*> creator) : _owner(creator) {
	}

	struct SentRequest {
		mtpMsgId msgId = 0;
		SerializedRequest request;
	};

	struct ToSendBatch {
		std::vector<std::pair<mtpRequestId, SerializedRequest>> requests;
		bool someSkipped = false;
	};

	void notifyConnectionInited(const SessionOptions &options);
	void setOptions(SessionOptions options) {
		QWriteLocker locker(&_optionsLock);
		_options = options;
	}
	[[nodiscard]] SessionOptions options() const {
		QReadLocker locker(&_optionsLock);
		return _options;
	}

	not_null<QReadWriteLock*> toSendMutex() {
		return &_toSendLock;
	}
	not_null<QReadWriteLock*> haveSentMutex() {
		return &_haveSentLock;
	}
	not_null<QReadWriteLock*> haveReceivedMutex() {
		return &_haveReceivedLock;
	}

	base::flat_map<mtpRequestId, SerializedRequest> &toSendMap() {
		return _toSend;
	}
	base::flat_map<mtpMsgId, SerializedRequest> &haveSentMap() {
		return _haveSent;
	}
	std::vector<Response> &haveReceivedMessages() {
		return _receivedMessages;
	}

	[[nodiscard]] ToSendBatch takeToSendBatch(int sizeLimit);
	[[nodiscard]] std::optional<SentRequest> takeSentRequest(mtpMsgId msgId);
	[[nodiscard]] std::vector<SentRequest> takeAllSentRequests();
	[[nodiscard]] std::optional<SerializedRequest> takeToSendRequest(
		mtpRequestId requestId);
	void enqueueToSend(const SerializedRequest &request);
	void enqueueResentRequest(const SerializedRequest &request);
	void removeToSend(mtpRequestId requestId);
	void removeSent(mtpMsgId msgId);
	[[nodiscard]] bool hasToSend(mtpRequestId requestId);

	// SessionPrivate -> Session interface.
	void queueTryToReceive();
	void queueNeedToResumeAndSend();
	void queueConnectionStateChange(int newState);
	void queueResetDone();
	void queueSendAnything(crl::time msCanWait = 0);

	[[nodiscard]] bool connectionInited() const;
	[[nodiscard]] AuthKeyPtr getPersistentKey() const;
	[[nodiscard]] AuthKeyPtr getTemporaryKey(TemporaryKeyType type) const;
	[[nodiscard]] CreatingKeyType acquireKeyCreation(DcType type);
	[[nodiscard]] bool releaseKeyCreationOnDone(
		const AuthKeyPtr &temporaryKey,
		const AuthKeyPtr &persistentKeyUsedForBind);
	[[nodiscard]] bool releaseCdnKeyCreationOnDone(
		const AuthKeyPtr &temporaryKey);
	void releaseKeyCreationOnFail();
	void destroyTemporaryKey(uint64 keyId);

	void detach();

private:
	template <typename Callback>
	void withSession(Callback &&callback);

	Session *_owner = nullptr;
	mutable QMutex _ownerMutex;

	SessionOptions _options;
	mutable QReadWriteLock _optionsLock;

	base::flat_map<mtpRequestId, SerializedRequest> _toSend; // map of request_id -> request, that is waiting to be sent
	mutable QReadWriteLock _toSendLock;

	base::flat_map<mtpMsgId, SerializedRequest> _haveSent; // map of msg_id -> request, that was sent
	mutable QReadWriteLock _haveSentLock;

	std::vector<Response> _receivedMessages; // list of responses / updates that should be processed in the main thread
	QReadWriteLock _haveReceivedLock;

};

class Session final : public QObject {
public:
	// Main thread.
	Session(
		not_null<Instance*> instance,
		not_null<SessionDelegate*> delegate,
		not_null<QThread*> thread,
		ShiftedDcId shiftedDcId,
		not_null<Dcenter*> dc,
		uint64 proxyGeneration,
		bool proxyMigrationScout,
		bool proxyMigrationSuspended);
	~Session();

	void start();
	void reInitConnection();
	void setConnectionNotInited();

	void restart();
	void migrateProxy(uint64 generation, bool scout);
	void releaseProxyMigration(uint64 generation);
	void refreshOptions();
	void stop();
	void kill();

	void unpaused();

	// Thread-safe.
	[[nodiscard]] ShiftedDcId getDcWithShift() const;
	[[nodiscard]] AuthKeyPtr getPersistentKey() const;
	[[nodiscard]] AuthKeyPtr getTemporaryKey(TemporaryKeyType type) const;
	[[nodiscard]] bool connectionInited() const;
	void sendPrepared(
		const SerializedRequest &request,
		crl::time msCanWait = 0);

	// SessionPrivate thread.
	[[nodiscard]] CreatingKeyType acquireKeyCreation(DcType type);
	[[nodiscard]] bool releaseKeyCreationOnDone(
		const AuthKeyPtr &temporaryKey,
		const AuthKeyPtr &persistentKeyUsedForBind);
	[[nodiscard]] bool releaseCdnKeyCreationOnDone(const AuthKeyPtr &temporaryKey);
	void releaseKeyCreationOnFail();
	void destroyTemporaryKey(uint64 keyId);

	void notifyDcConnectionInited();

	void ping();
	void cancel(mtpRequestId requestId, mtpMsgId msgId);
	int requestState(mtpRequestId requestId) const;
	int getState() const;
	QString transport() const;

	void tryToReceive();
	void needToResumeAndSend();
	void connectionStateChange(int newState);
	void resetDone();
	void sendAnything(crl::time msCanWait = 0);

private:
	void watchDcKeyChanges();
	void watchDcOptionsChanges();

	void killConnection();

	[[nodiscard]] bool releaseGenericKeyCreationOnDone(
		const AuthKeyPtr &temporaryKey,
		const AuthKeyPtr &persistentKeyUsedForBind);

	const not_null<Instance*> _instance;
	const not_null<SessionDelegate*> _delegate;
	const ShiftedDcId _shiftedDcId = 0;
	const not_null<Dcenter*> _dc;
	const std::shared_ptr<SessionData> _data;
	const not_null<QThread*> _thread;
	uint64 _proxyGeneration = 0;

	SessionPrivate *_private = nullptr;

	bool _proxyMigrationScout = false;
	bool _proxyMigrationSuspended = false;
	bool _killed = false;
	bool _needToReceive = false;

	AuthKeyPtr _dcKeyForCheck;
	CreatingKeyType _myKeyCreation = CreatingKeyType();

	crl::time _msSendCall = 0;
	crl::time _msWait = 0;

	bool _ping = false;

	base::Timer _sender;

	rpl::lifetime _lifetime;

};

} // namespace details
} // namespace MTP
