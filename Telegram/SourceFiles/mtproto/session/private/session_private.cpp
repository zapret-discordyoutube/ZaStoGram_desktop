/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "mtproto/session/private/session_private.h"

#include "core/version.h"
#include "mtproto/dc_id.h"
#include "mtproto/protocol/mtproto_binary.h"
#include "mtproto/auth/mtproto_bound_key_creator.h"
#include "mtproto/details/mtproto_dcenter.h"
#include "mtproto/protocol/mtproto_dump_to_text.h"
#include "mtproto/details/mtproto_rsa_public_key.h"
#include "mtproto/proxy/transport_policy.h"
#include "mtproto/runtime/connection_status.h"
#include "mtproto/runtime/runtime_environment.h"
#include "mtproto/session/session.h"
#include "mtproto/protocol/mtproto_response.h"
#include "mtproto/config/mtproto_dc_options.h"
#include "mtproto/transport/connection_abstract.h"
#include "base/options.h"
#include "base/random.h"
#include "base/qthelp_url.h"
#include "base/openssl_help.h"
#include "base/unixtime.h"

#include "base/platform/base_platform_info.h"

#include <ksandbox.h>
#include <zlib.h>

namespace MTP {
namespace details {

SessionPrivate::SessionState::SessionState(
		std::shared_ptr<SessionData> data)
: data(std::move(data)) {
}

SessionPrivate::SessionPrivate(
		not_null<Instance*> instance,
		not_null<SessionDelegate*> delegate,
		not_null<QThread*> thread,
		std::shared_ptr<SessionData> data,
		ShiftedDcId shiftedDcId,
		uint64 proxyGeneration,
		bool proxyMigrationScout,
		bool proxyMigrationSuspended,
		not_null<SessionProxyPort*> proxyPort,
		not_null<SessionConnectionFactory*> connectionFactory,
		not_null<SessionAuthKeyFactory*> authKeyFactory)
: QObject(nullptr)
, _instance(instance)
, _delegate(delegate)
, _runtime(&delegate->runtimeEnvironment())
, _proxyPort(proxyPort)
, _connectionFactory(connectionFactory)
, _authKeyFactory(authKeyFactory)
, _shiftedDcId(shiftedDcId)
, _realDcType(_delegate->dcOptions().dcType(_shiftedDcId))
, _currentDcType(_realDcType)
, _state(DisconnectedState)
, _transport(
	this,
	_runtime,
	thread,
	proxyGeneration,
	proxyMigrationScout,
	proxyMigrationSuspended)
, _messageHandler(this)
, _sessionState(std::move(data)) {
	Expects(_shiftedDcId != 0);

	moveToThread(thread);

	InvokeQueued(this, [=] {
		_transport.startContainerCleanup();
		_transport.start();
	});
}

SessionPrivate::~SessionPrivate() {
	releaseKeyCreationOnFail();
	doDisconnect();

	Expects(_transport.empty());
}

void SessionPrivate::connectToServer(bool afterConfig) {
	_transport.connectToServer(afterConfig);
}

void SessionPrivate::doDisconnect() {
	_transport.doDisconnect();
}

void SessionPrivate::restart() {
	_transport.restart();
}

void SessionPrivate::restartNow() {
	_transport.restartNow();
}

void SessionPrivate::migrateProxy(uint64 generation, bool scout) {
	_transport.migrateProxy(generation, scout);
}

void SessionPrivate::releaseProxyMigration(uint64 generation) {
	_transport.releaseProxyMigration(generation);
}

void SessionPrivate::onSentSome(uint64 size) {
	_transport.onSentSome(size);
}

void SessionPrivate::onReceivedSome() {
	_transport.onReceivedSome();
}

void SessionPrivate::handleReceived() {
	_messageHandler.handleReceived();
}

void SessionPrivate::setConnectionNotice(ConnectionNotice notice) {
	const auto shiftedDcId = _shiftedDcId;
	InvokeQueued(_runtime, [=, runtime = _runtime] {
		if (runtime->instance().connectionStatus) {
			runtime->instance().connectionStatus->setNotice(shiftedDcId, notice);
		}
	});
}

void SessionPrivate::reportPingTime(crl::time time) {
	const auto shiftedDcId = _shiftedDcId;
	InvokeQueued(_runtime, [=, runtime = _runtime, delegate = _delegate] {
		if (runtime->instance().connectionStatus) {
			runtime->instance().connectionStatus->setSessionPingTime(
				delegate->mainDcId(),
				shiftedDcId,
				time);
		}
	});
}

QString SessionPrivate::mtprotoLogDc() const {
	const auto suffix = isUploadDcId(_shiftedDcId)
		? u"_upload"_q
		: isMediaClusterDcId(_shiftedDcId)
		? u"_media"_q
		: QString();
	return u"%1%2(%3)"_q
		.arg(BareDcId(_shiftedDcId))
		.arg(suffix)
		.arg(_shiftedDcId);
}

void SessionPrivate::logMtprotoEvent(
		ProxyDiagnosticsPhase phase,
		ProxyDiagnosticsSeverity severity,
		const QString &message) const {
	const auto proxy = _sessionState.options ? _sessionState.options->proxy : ProxyData();
	_proxyPort->logEvent(
		_runtime,
		proxy,
		_transport.currentProxyAttempt().attempt,
		mtprotoLogDc(),
		phase,
		severity,
		message);
}

int16 SessionPrivate::getProtocolDcId() const {
	const auto dcId = BareDcId(_shiftedDcId);
	const auto simpleDcId = isTemporaryDcId(dcId)
		? getRealIdFromTemporaryDcId(dcId)
		: dcId;
	const auto testedDcId = _delegate->isTestMode()
		? (kTestModeDcIdShift + simpleDcId)
		: simpleDcId;
	return (_currentDcType == DcType::MediaCluster)
		? -testedDcId
		: testedDcId;
}

void SessionPrivate::cdnConfigChanged() {
	_transport.connectToServer(true);
}

int32 SessionPrivate::getShiftedDcId() const {
	return _shiftedDcId;
}

void SessionPrivate::dcOptionsChanged() {
	_transport.setRetryTimeout(1);
	_transport.connectToServer(true);
}

int32 SessionPrivate::getState() const {
	QReadLocker lock(&_stateMutex);
	int32 result = _state;
	if (_state < 0) {
		if (_transport.retryTimerActive()) {
			result = int32(crl::now() - _transport.retryWillFinish());
			if (result >= 0) {
				result = -1;
			}
		}
	}
	return result;
}

QString SessionPrivate::transport() const {
	QReadLocker lock(&_stateMutex);
	if (!_transport.connection() || (_state < 0)) {
		return QString();
	}

	Assert(_sessionState.options != nullptr);
	return _transport.activeTransport();
}

bool SessionPrivate::setState(int state, int ifState) {
	if (ifState != kUpdateStateAlways) {
		QReadLocker lock(&_stateMutex);
		if (_state != ifState) {
			return false;
		}
	}

	QWriteLocker lock(&_stateMutex);
	if (_state == state) {
		return false;
	}
	_state = state;
	if (state < 0) {
		_transport.scheduleRetryTimeout(-state);
	}
	lock.unlock();

	_sessionState.data->queueConnectionStateChange(state);
	return true;
}

void SessionPrivate::resetSession() {
	MTP_LOG(_shiftedDcId, ("Resetting session!"));
	_sessionState.needReset = false;

	DEBUG_LOG(("MTP Info: creating new session in resetSession."));
	changeSessionId();

	_sessionState.data->queueResetDone();
}

void SessionPrivate::changeSessionId() {
	auto sessionId = _sessionState.sessionId;
	do {
		sessionId = base::RandomValue<uint64>();
	} while (_sessionState.sessionId == sessionId);

	DEBUG_LOG(("MTP Info: setting server_session: %1").arg(sessionId));

	_sessionState.sessionId = sessionId;
	_sessionState.messagesCounter = 0;
	_sessionState.markedAsStarted = false;
	_requestState.ackData.clear();
	_requestState.resendData.clear();
	_requestState.stateData.clear();
	_requestState.receivedIds.clear();
}

uint32 SessionPrivate::nextRequestSeqNumber(bool needAck) {
	const auto result = _sessionState.messagesCounter;
	_sessionState.messagesCounter += (needAck ? 1 : 0);
	return result * 2 + (needAck ? 1 : 0);
}

bool SessionPrivate::realDcTypeChanged() {
	const auto now = _delegate->dcOptions().dcType(_shiftedDcId);
	if (_realDcType == now) {
		return false;
	}
	_realDcType = now;
	return true;
}

bool SessionPrivate::markSessionAsStarted() {
	if (_sessionState.markedAsStarted) {
		return false;
	}
	_sessionState.markedAsStarted = true;
	return true;
}

MTPVector<MTPJSONObjectValue> SessionPrivate::prepareInitParams() {
	const auto local = QDateTime::currentDateTime();
	const auto utc = QDateTime(local.date(), local.time(), Qt::UTC);
	const auto shift = base::unixtime::now() - (TimeId)::time(nullptr);
	const auto delta = int(utc.toSecsSinceEpoch()) - int(local.toSecsSinceEpoch()) - shift;
	auto sliced = delta;
	while (sliced < -12 * 3600) {
		sliced += 24 * 3600;
	}
	while (sliced > 14 * 3600) {
		sliced -= 24 * 3600;
	}
	const auto sign = (sliced < 0) ? -1 : 1;
	const auto rounded = base::SafeRound(std::abs(sliced) / 900.)
		* 900
		* sign;
	return MTP_vector<MTPJSONObjectValue>(
		1,
		MTP_jsonObjectValue(
			MTP_string("tz_offset"),
			MTP_jsonNumber(MTP_double(rounded))));
}

} // namespace details
} // namespace MTP
