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
#include "mtproto/proxy/connection_broker.h"
#include "mtproto/proxy/control_plane.h"
#include "mtproto/proxy/diagnostics.h"
#include "mtproto/proxy/transport_policy.h"
#include "mtproto/runtime/runtime_environment.h"
#include "mtproto/session/session.h"
#include "mtproto/mtproto_response.h"
#include "mtproto/mtproto_dc_options.h"
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
namespace {

constexpr auto kMinConnectedTimeout = crl::time(1000);
constexpr auto kMinReceiveTimeout = crl::time(4000);
constexpr auto kSentContainerLives = 600 * crl::time(1000);

} // namespace

SessionPrivate::TimingState::TimingState(
		not_null<QThread*> thread,
		not_null<SessionPrivate*> owner)
: retryTimer(thread, [=] { owner->retryByTimer(); })
, oldConnectionTimer(thread, [=] { owner->markConnectionOld(); })
, waitForConnectedTimer(thread, [=] { owner->waitConnectedFailed(); })
, waitForReceivedTimer(thread, [=] { owner->waitReceivedFailed(); })
, waitForBetterTimer(thread, [=] { owner->waitBetterFailed(); })
, brokerQueueDeadlineTimer(thread, [=] { owner->brokerQueueDeadlineFired(); })
, waitForReceived(kMinReceiveTimeout)
, waitForConnected(kMinConnectedTimeout)
, pingSender(thread, [=] { owner->sendPingByTimer(); })
, checkSentRequestsTimer(thread, [=] { owner->checkSentRequests(); })
, clearOldContainersTimer(thread, [=] { owner->clearOldContainers(); }) {
}

SessionPrivate::SessionState::SessionState(
		std::shared_ptr<SessionData> data)
: data(std::move(data)) {
}

SessionPrivate::SessionPrivate(
	not_null<Instance*> instance,
	not_null<QThread*> thread,
	std::shared_ptr<SessionData> data,
	ShiftedDcId shiftedDcId)
: QObject(nullptr)
, _instance(instance)
, _runtime(&instance->runtimeEnvironment())
, _shiftedDcId(shiftedDcId)
, _realDcType(_instance->dcOptions().dcType(_shiftedDcId))
, _currentDcType(_realDcType)
, _state(DisconnectedState)
, _timing(thread, this)
, _sessionState(std::move(data)) {
	Expects(_shiftedDcId != 0);

	moveToThread(thread);

	InvokeQueued(this, [=] {
		_timing.clearOldContainersTimer.callEach(kSentContainerLives);
		connectToServer();
	});
}

SessionPrivate::~SessionPrivate() {
	releaseKeyCreationOnFail();
	doDisconnect();

	Expects(!_connectionState.connection);
	Expects(_connectionState.testConnections.empty());
}

void SessionPrivate::setConnectionNotice(ConnectionNotice notice) {
	const auto shiftedDcId = _shiftedDcId;
	InvokeQueued(_instance, [=, instance = _instance] {
		instance->setConnectionNotice(shiftedDcId, notice);
	});
}

void SessionPrivate::reportPingTime(crl::time time) {
	const auto shiftedDcId = _shiftedDcId;
	InvokeQueued(_instance, [=, instance = _instance] {
		instance->setSessionPingTime(shiftedDcId, time);
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
	if (proxy.type == ProxyData::Type::None) {
		WriteProxyDiagnosticsLine(_runtime, {
			.source = ProxyDiagnosticsSource::MTP,
			.phase = phase,
			.severity = severity,
			.proxy = proxy,
			.dc = mtprotoLogDc(),
			.message = message,
		});
		return;
	}
	ReportProxyEvent(_runtime, {
		.phase = phase,
		.attempt = _connectionState.mtproxyAttempt,
		.severity = severity,
		.proxy = proxy,
		.dc = mtprotoLogDc(),
		.message = message,
	});
}

int16 SessionPrivate::getProtocolDcId() const {
	const auto dcId = BareDcId(_shiftedDcId);
	const auto simpleDcId = isTemporaryDcId(dcId)
		? getRealIdFromTemporaryDcId(dcId)
		: dcId;
	const auto testedDcId = _instance->isTestMode()
		? (kTestModeDcIdShift + simpleDcId)
		: simpleDcId;
	return (_currentDcType == DcType::MediaCluster)
		? -testedDcId
		: testedDcId;
}

void SessionPrivate::cdnConfigChanged() {
	connectToServer(true);
}

int32 SessionPrivate::getShiftedDcId() const {
	return _shiftedDcId;
}

void SessionPrivate::dcOptionsChanged() {
	_timing.retryTimeout = 1;
	connectToServer(true);
}

int32 SessionPrivate::getState() const {
	QReadLocker lock(&_stateMutex);
	int32 result = _state;
	if (_state < 0) {
		if (_timing.retryTimer.isActive()) {
			result = int32(crl::now() - _timing.retryWillFinish);
			if (result >= 0) {
				result = -1;
			}
		}
	}
	return result;
}

QString SessionPrivate::transport() const {
	QReadLocker lock(&_stateMutex);
	if (!_connectionState.connection || (_state < 0)) {
		return QString();
	}

	Assert(_sessionState.options != nullptr);
	return _connectionState.connection->transport();
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
		_timing.retryTimeout = -state;
		_timing.retryTimer.callOnce(_timing.retryTimeout);
		_timing.retryWillFinish = crl::now() + _timing.retryTimeout;
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
	const auto now = _instance->dcOptions().dcType(_shiftedDcId);
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
