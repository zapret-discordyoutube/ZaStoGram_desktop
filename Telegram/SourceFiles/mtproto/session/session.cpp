/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "mtproto/session/session.h"

#include "mtproto/dc_id.h"
#include "mtproto/details/mtproto_dcenter.h"
#include "mtproto/instance/mtp_instance.h"
#include "mtproto/session/pause_state.h"
#include "mtproto/session/private/session_private.h"
#include "mtproto/auth/mtproto_auth_key.h"
#include "mtproto/proxy/transport_policy.h"
#include "mtproto/runtime/runtime_environment.h"
#include "mtproto/session/session_state.h"
#include "base/unixtime.h"

namespace MTP {
namespace details {

SessionOptions::SessionOptions(
	const QString &systemLangCode,
	const QString &cloudLangCode,
	const QString &langPackName,
	const ProxyData &proxy,
	bool useIPv4,
	bool useIPv6,
	bool useHttp,
	bool useTcp)
: systemLangCode(systemLangCode)
, cloudLangCode(cloudLangCode)
, langPackName(langPackName)
, proxy(proxy)
, useIPv4(useIPv4)
, useIPv6(useIPv6)
, useHttp(useHttp)
, useTcp(useTcp) {
}

template <typename Callback>
void SessionData::withSession(Callback &&callback) {
	QMutexLocker lock(&_ownerMutex);
	if (const auto session = _owner) {
		InvokeQueued(session, [
			session,
			callback = std::forward<Callback>(callback)
		] {
			callback(session);
		});
	}
}

void SessionData::notifyConnectionInited(const SessionOptions &options) {
	const auto current = this->options();
	if (current.cloudLangCode == options.cloudLangCode
		&& current.systemLangCode == options.systemLangCode
		&& current.langPackName == options.langPackName
		&& current.proxy == options.proxy) {
		QMutexLocker lock(&_ownerMutex);
		if (_owner) {
			_owner->notifyDcConnectionInited();
		}
	}
}

auto SessionData::takeToSendBatch(int sizeLimit) -> ToSendBatch {
	auto result = ToSendBatch();
	QWriteLocker lock(&_toSendLock);
	auto sendingFrom = begin(_toSend);
	auto sendingTill = end(_toSend);
	auto combinedLength = 0;
	for (auto i = sendingFrom; i != sendingTill; ++i) {
		combinedLength += i->second->size();
		if (combinedLength >= sizeLimit) {
			++i;
			if (i != sendingTill) {
				sendingTill = i;
				result.someSkipped = true;
			}
			break;
		}
	}
	result.requests.reserve(sendingTill - sendingFrom);
	for (auto i = sendingFrom; i != sendingTill; ++i) {
		result.requests.emplace_back(i->first, i->second);
	}
	_toSend.erase(sendingFrom, sendingTill);
	return result;
}

std::optional<SessionData::SentRequest> SessionData::takeSentRequest(
		mtpMsgId msgId) {
	QWriteLocker lock(&_haveSentLock);
	const auto i = _haveSent.find(msgId);
	if (i == end(_haveSent)) {
		return std::nullopt;
	}
	auto result = SentRequest{
		.msgId = msgId,
		.request = i->second,
	};
	_haveSent.erase(i);
	return result;
}

std::vector<SessionData::SentRequest> SessionData::takeAllSentRequests() {
	auto result = std::vector<SentRequest>();
	QWriteLocker lock(&_haveSentLock);
	result.reserve(_haveSent.size());
	for (auto &[msgId, request] : _haveSent) {
		result.push_back({
			.msgId = msgId,
			.request = std::move(request),
		});
	}
	_haveSent.clear();
	return result;
}

std::optional<SerializedRequest> SessionData::takeToSendRequest(
		mtpRequestId requestId) {
	QWriteLocker lock(&_toSendLock);
	const auto i = _toSend.find(requestId);
	if (i == end(_toSend)) {
		return std::nullopt;
	}
	auto result = i->second;
	_toSend.erase(i);
	return result;
}

void SessionData::enqueueToSend(const SerializedRequest &request) {
	QWriteLocker lock(&_toSendLock);
	auto queued = request;
	_toSend.emplace(queued->requestId, queued);
	queued.setMsgId(0);
	queued.setSeqNo(0);
}

void SessionData::enqueueResentRequest(const SerializedRequest &request) {
	QWriteLocker lock(&_toSendLock);
	_toSend.emplace(request->requestId, request);
}

void SessionData::removeToSend(mtpRequestId requestId) {
	QWriteLocker lock(&_toSendLock);
	_toSend.remove(requestId);
}

void SessionData::removeSent(mtpMsgId msgId) {
	QWriteLocker lock(&_haveSentLock);
	_haveSent.remove(msgId);
}

bool SessionData::hasToSend(mtpRequestId requestId) {
	QReadLocker lock(&_toSendLock);
	return _toSend.contains(requestId);
}

void SessionData::queueTryToReceive() {
	withSession([](not_null<Session*> session) {
		session->tryToReceive();
	});
}

void SessionData::queueNeedToResumeAndSend() {
	withSession([](not_null<Session*> session) {
		session->needToResumeAndSend();
	});
}

void SessionData::queueConnectionStateChange(int newState) {
	withSession([=](not_null<Session*> session) {
		session->connectionStateChange(newState);
	});
}

void SessionData::queueResetDone() {
	withSession([](not_null<Session*> session) {
		session->resetDone();
	});
}

void SessionData::queueSendAnything(crl::time msCanWait) {
	withSession([=](not_null<Session*> session) {
		session->sendAnything(msCanWait);
	});
}

bool SessionData::connectionInited() const {
	QMutexLocker lock(&_ownerMutex);
	return _owner ? _owner->connectionInited() : false;
}

AuthKeyPtr SessionData::getTemporaryKey(TemporaryKeyType type) const {
	QMutexLocker lock(&_ownerMutex);
	return _owner ? _owner->getTemporaryKey(type) : nullptr;
}

AuthKeyPtr SessionData::getPersistentKey() const {
	QMutexLocker lock(&_ownerMutex);
	return _owner ? _owner->getPersistentKey() : nullptr;
}

CreatingKeyType SessionData::acquireKeyCreation(DcType type) {
	QMutexLocker lock(&_ownerMutex);
	return _owner ? _owner->acquireKeyCreation(type) : CreatingKeyType::None;
}

bool SessionData::releaseKeyCreationOnDone(
		const AuthKeyPtr &temporaryKey,
		const AuthKeyPtr &persistentKeyUsedForBind) {
	QMutexLocker lock(&_ownerMutex);
	return _owner
		? _owner->releaseKeyCreationOnDone(
			temporaryKey,
			persistentKeyUsedForBind)
		: false;
}

bool SessionData::releaseCdnKeyCreationOnDone(
		const AuthKeyPtr &temporaryKey) {
	QMutexLocker lock(&_ownerMutex);
	return _owner
		? _owner->releaseCdnKeyCreationOnDone(temporaryKey)
		: false;
}

void SessionData::releaseKeyCreationOnFail() {
	QMutexLocker lock(&_ownerMutex);
	if (_owner) {
		_owner->releaseKeyCreationOnFail();
	}
}

void SessionData::destroyTemporaryKey(uint64 keyId) {
	QMutexLocker lock(&_ownerMutex);
	if (_owner) {
		_owner->destroyTemporaryKey(keyId);
	}
}

void SessionData::detach() {
	QMutexLocker lock(&_ownerMutex);
	_owner = nullptr;
}

Session::Session(
		not_null<Instance*> instance,
		not_null<SessionDelegate*> delegate,
		not_null<QThread*> thread,
		ShiftedDcId shiftedDcId,
		not_null<Dcenter*> dc,
		uint64 proxyGeneration,
		bool proxyMigrationScout,
		bool proxyMigrationSuspended)
: _instance(instance)
, _delegate(delegate)
, _shiftedDcId(shiftedDcId)
, _dc(dc)
, _data(std::make_shared<SessionData>(this))
, _thread(thread)
, _proxyGeneration(proxyGeneration)
, _proxyMigrationScout(proxyMigrationScout)
, _proxyMigrationSuspended(proxyMigrationSuspended)
, _sender([=] { needToResumeAndSend(); }) {
	refreshOptions();
	watchDcKeyChanges();
	watchDcOptionsChanges();
	start();
}

Session::~Session() {
	Expects(!_private);

	if (_myKeyCreation != CreatingKeyType::None) {
		releaseKeyCreationOnFail();
	}
}

void Session::watchDcKeyChanges() {
	_delegate->dcTemporaryKeyChanged(
	) | rpl::filter([=](DcId dcId) {
		return (dcId == _shiftedDcId) || (dcId == BareDcId(_shiftedDcId));
	}) | rpl::on_next([=] {
		DEBUG_LOG(("AuthKey Info: dcTemporaryKeyChanged in Session %1"
			).arg(_shiftedDcId));
		if (const auto captured = _private) {
			InvokeQueued(captured, [=] {
				DEBUG_LOG(("AuthKey Info: calling Connection::updateAuthKey in Session %1"
					).arg(_shiftedDcId));
				captured->updateAuthKey();
			});
		}
	}, _lifetime);
}

void Session::watchDcOptionsChanges() {
	_delegate->dcOptions().changed(
	) | rpl::filter([=](DcId dcId) {
		return (BareDcId(_shiftedDcId) == dcId) && (_private != nullptr);
	}) | rpl::on_next([=] {
		InvokeQueued(_private, [captured = _private] {
			captured->dcOptionsChanged();
		});
	}, _lifetime);

	_delegate->dcOptions().cdnConfigChanged(
	) | rpl::filter([=] {
		return (_private != nullptr)
			&& (_delegate->dcOptions().dcType(_shiftedDcId) == DcType::Cdn);
	}) | rpl::on_next([=] {
		InvokeQueued(_private, [captured = _private] {
			captured->cdnConfigChanged();
		});
	}, _lifetime);
}

void Session::start() {
	killConnection();
	_private = new SessionPrivate(
		_instance,
		_delegate,
		_thread.get(),
		_data,
		_shiftedDcId,
		_proxyGeneration,
		_proxyMigrationScout,
		_proxyMigrationSuspended);
}

void Session::restart() {
	if (_killed) {
		DEBUG_LOG(("Session Error: can't restart a killed session"));
		return;
	}
	refreshOptions();
	if (const auto captured = _private) {
		InvokeQueued(captured, [=] {
			captured->restartNow();
		});
	}
}

void Session::migrateProxy(uint64 generation, bool scout) {
	if (_killed) {
		DEBUG_LOG(("Session Error: can't migrate proxy in a killed session"));
		return;
	}
	refreshOptions();
	if (scout) {
		setConnectionNotInited();
	}
	_proxyGeneration = generation;
	_proxyMigrationScout = scout;
	_proxyMigrationSuspended = !scout;
	if (const auto captured = _private) {
		InvokeQueued(captured, [=] {
			captured->migrateProxy(generation, scout);
		});
	}
}

void Session::releaseProxyMigration(uint64 generation) {
	if (_killed) {
		return;
	}
	if (_proxyGeneration == generation) {
		_proxyMigrationScout = false;
		_proxyMigrationSuspended = false;
	}
	if (const auto captured = _private) {
		InvokeQueued(captured, [=] {
			captured->releaseProxyMigration(generation);
		});
	}
}

void Session::refreshOptions() {
	auto &runtime = _delegate->runtimeEnvironment();
	const auto proxy = runtime.proxy().selected
		? runtime.proxy().selected()
		: ProxyData();
	const auto isEnabled = runtime.proxy().enabled
		? runtime.proxy().enabled()
		: false;
	const auto proxyType = (isEnabled ? proxy.type : ProxyData::Type::None);
	const auto useTcp = (proxyType != ProxyData::Type::Http);
	const auto useHttp = (proxyType != ProxyData::Type::Mtproto);
	const auto useIPv4 = true;
	const auto useIPv6 = runtime.proxy().tryIPv6
		? runtime.proxy().tryIPv6()
		: false;
	auto options = SessionOptions(
		_delegate->systemLangCode(),
		_delegate->cloudLangCode(),
		_delegate->langPackName(),
		(isEnabled ? proxy : ProxyData()),
		useIPv4,
		useIPv6,
		useHttp,
		useTcp);
	const auto proxySettings = runtime.proxy().settings
		? runtime.proxy().settings()
		: ProxyData::Settings::System;
	const auto stealthOptions = runtime.proxy().stealthOptions
		? runtime.proxy().stealthOptions()
		: ProxyStealthOptions();
	options.stealth = MTP::EffectiveProxyStealthOptions(
		&runtime,
		options.proxy,
		proxySettings,
		stealthOptions);
	_data->setOptions(std::move(options));
}

void Session::reInitConnection() {
	setConnectionNotInited();
	restart();
}

void Session::setConnectionNotInited() {
	_dc->setConnectionInited(false);
}

void Session::stop() {
	if (_killed) {
		DEBUG_LOG(("Session Error: can't stop a killed session"));
		return;
	}
	DEBUG_LOG(("Session Info: stopping session dcWithShift %1").arg(_shiftedDcId));
	killConnection();
}

void Session::kill() {
	stop();
	_killed = true;
	_data->detach();
	DEBUG_LOG(("Session Info: marked session dcWithShift %1 as killed").arg(_shiftedDcId));
}

void Session::unpaused() {
	if (_needToReceive) {
		_needToReceive = false;
		InvokeQueued(this, [=] {
			tryToReceive();
		});
	}
}

void Session::sendAnything(crl::time msCanWait) {
	if (_killed) {
		DEBUG_LOG(("Session Error: can't send anything in a killed session"));
		return;
	}
	const auto ms = crl::now();
	if (_msSendCall) {
		if (ms > _msSendCall + _msWait) {
			_msWait = 0;
		} else {
			_msWait = (_msSendCall + _msWait) - ms;
			if (_msWait > msCanWait) {
				_msWait = msCanWait;
			}
		}
	} else {
		_msWait = msCanWait;
	}
	if (_msWait) {
		DEBUG_LOG(("MTP Info: dcWithShift %1 can wait for %2ms from current %3").arg(_shiftedDcId).arg(_msWait).arg(_msSendCall));
		_msSendCall = ms;
		_sender.callOnce(_msWait);
	} else {
		DEBUG_LOG(("MTP Info: dcWithShift %1 stopped send timer, can wait for %2ms from current %3").arg(_shiftedDcId).arg(_msWait).arg(_msSendCall));
		_sender.cancel();
		_msSendCall = 0;
		needToResumeAndSend();
	}
}

void Session::needToResumeAndSend() {
	if (_killed) {
		DEBUG_LOG(("Session Info: can't resume a killed session"));
		return;
	}
	if (!_private) {
		DEBUG_LOG(("Session Info: resuming session dcWithShift %1").arg(_shiftedDcId));
		start();
	}
	const auto captured = _private;
	const auto ping = base::take(_ping);
	InvokeQueued(captured, [=] {
		if (ping) {
			captured->sendPingForce();
		} else {
			captured->tryToSend();
		}
	});
}

void Session::connectionStateChange(int newState) {
	_delegate->onStateChange(_shiftedDcId, newState);
}

void Session::resetDone() {
	_delegate->onSessionReset(_shiftedDcId);
}

void Session::cancel(mtpRequestId requestId, mtpMsgId msgId) {
	if (requestId) {
		_data->removeToSend(requestId);
	}
	if (msgId) {
		_data->removeSent(msgId);
	}
}

void Session::ping() {
	_ping = true;
	sendAnything();
}

int32 Session::requestState(mtpRequestId requestId) const {
	int32 result = MTP::RequestSent;

	bool connected = false;
	if (_private) {
		const auto s = _private->getState();
		if (s == ConnectedState) {
			connected = true;
		} else if (s == ConnectingState || s == DisconnectedState) {
			if (result < 0 || result == MTP::RequestSent) {
				result = MTP::RequestConnecting;
			}
		} else if (s < 0) {
			if ((result < 0 && s > result) || result == MTP::RequestSent) {
				result = s;
			}
		}
	}
	if (!connected) {
		return result;
	} else if (!requestId) {
		return MTP::RequestSent;
	}

	return _data->hasToSend(requestId)
		? MTP::RequestSending
		: MTP::RequestSent;
}

int32 Session::getState() const {
	int32 result = -86400000;

	if (_private) {
		const auto s = _private->getState();
		if (s == ConnectedState
			|| s == ConnectingState
			|| s == DisconnectedState) {
			return s;
		} else if (s < 0) {
			if (result < 0 && s > result) {
				result = s;
			}
		}
	}
	if (result == -86400000) {
		result = DisconnectedState;
	}
	return result;
}

QString Session::transport() const {
	return _private ? _private->transport() : QString();
}

void Session::sendPrepared(
		const SerializedRequest &request,
		crl::time msCanWait) {
	DEBUG_LOG(("MTP Info: adding request to toSendMap, msCanWait %1"
		).arg(msCanWait));
	_data->enqueueToSend(request);

	DEBUG_LOG(("MTP Info: added, requestId %1").arg(request->requestId));
	if (msCanWait >= 0) {
		InvokeQueued(this, [=] {
			sendAnything(msCanWait);
		});
	}
}

CreatingKeyType Session::acquireKeyCreation(DcType type) {
	Expects(_myKeyCreation == CreatingKeyType::None);

	_myKeyCreation = _dc->acquireKeyCreation(type);
	return _myKeyCreation;
}

bool Session::releaseKeyCreationOnDone(
		const AuthKeyPtr &temporaryKey,
		const AuthKeyPtr &persistentKeyUsedForBind) {
	Expects(_myKeyCreation != CreatingKeyType::None);
	Expects(persistentKeyUsedForBind != nullptr);

	return releaseGenericKeyCreationOnDone(
		temporaryKey,
		persistentKeyUsedForBind);
}

bool Session::releaseCdnKeyCreationOnDone(
		const AuthKeyPtr &temporaryKey) {
	Expects(_myKeyCreation == CreatingKeyType::TemporaryRegular);

	return releaseGenericKeyCreationOnDone(temporaryKey, nullptr);
}

bool Session::releaseGenericKeyCreationOnDone(
		const AuthKeyPtr &temporaryKey,
		const AuthKeyPtr &persistentKeyUsedForBind) {
	const auto wasKeyCreation = std::exchange(
		_myKeyCreation,
		CreatingKeyType::None);
	const auto result = _dc->releaseKeyCreationOnDone(
		wasKeyCreation,
		temporaryKey,
		persistentKeyUsedForBind);

	if (!result) {
		DEBUG_LOG(("AuthKey Info: Persistent key changed "
			"while binding temporary, dcWithShift %1"
			).arg(_shiftedDcId));
		return false;
	}

	DEBUG_LOG(("AuthKey Info: Session key bound, setting, dcWithShift %1"
		).arg(_shiftedDcId));

	const auto dcId = _dc->id();
	const auto instance = _instance;
	const auto delegate = _delegate;
	InvokeQueued(instance, [=] {
		if (wasKeyCreation == CreatingKeyType::Persistent) {
			delegate->dcPersistentKeyChanged(dcId, persistentKeyUsedForBind);
		} else {
			delegate->dcTemporaryKeyChanged(dcId);
		}
	});
	return true;
}

void Session::releaseKeyCreationOnFail() {
	Expects(_myKeyCreation != CreatingKeyType::None);

	const auto wasKeyCreation = std::exchange(
		_myKeyCreation,
		CreatingKeyType::None);
	_dc->releaseKeyCreationOnFail(wasKeyCreation);
}

void Session::notifyDcConnectionInited() {
	DEBUG_LOG(("MTP Info: MTProtoDC::connectionWasInited(), dcWithShift %1"
		).arg(_shiftedDcId));
	_dc->setConnectionInited();
}

void Session::destroyTemporaryKey(uint64 keyId) {
	if (!_dc->destroyTemporaryKey(keyId)) {
		return;
	}
	const auto dcId = _dc->id();
	const auto instance = _instance;
	const auto delegate = _delegate;
	InvokeQueued(instance, [=] {
		delegate->dcTemporaryKeyChanged(dcId);
	});
}

int32 Session::getDcWithShift() const {
	return _shiftedDcId;
}

AuthKeyPtr Session::getTemporaryKey(TemporaryKeyType type) const {
	return _dc->getTemporaryKey(type);
}

AuthKeyPtr Session::getPersistentKey() const {
	return _dc->getPersistentKey();
}

bool Session::connectionInited() const {
	return _dc->connectionInited();
}

void Session::tryToReceive() {
	if (_killed) {
		DEBUG_LOG(("Session Error: can't receive in a killed session"));
		return;
	}
	if (paused()) {
		_needToReceive = true;
		return;
	}
	while (true) {
		auto lock = QWriteLocker(_data->haveReceivedMutex());
		const auto messages = base::take(_data->haveReceivedMessages());
		lock.unlock();
		if (messages.empty()) {
			break;
		}
		const auto guard = QPointer<Session>(this);
		const auto instance = QPointer<Instance>(_instance);
		const auto delegate = _delegate;
		const auto main = (_shiftedDcId == BareDcId(_shiftedDcId));
		for (const auto &message : messages) {
			if (message.requestId) {
				delegate->processCallback(message);
			} else if (main) {
				delegate->processUpdate(message);
			}
			if (!instance) {
				return;
			}
		}
		if (!guard) {
			break;
		}
	}
}

void Session::killConnection() {
	if (!_private) {
		return;
	}

	base::take(_private)->deleteLater();

	Ensures(_private == nullptr);
}

} // namespace details
} // namespace MTP
