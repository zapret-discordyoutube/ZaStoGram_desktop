/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "mtproto/session/private/session_private.h"

namespace MTP::details {
namespace {

constexpr auto kMinConnectedTimeout = crl::time(1000);
constexpr auto kMinReceiveTimeout = crl::time(4000);

} // namespace

SessionTransport::TimingState::TimingState(
		not_null<RuntimeEnvironment*> runtime,
		not_null<SessionTransport*> owner)
: retryTimer(runtime->async().makeTimer(
	not_null<QObject*>{ owner->_owner.get() },
	[=] { owner->retryByTimer(); }))
, oldConnectionTimer(runtime->async().makeTimer(
	not_null<QObject*>{ owner->_owner.get() },
	[=] { owner->markConnectionOld(); }))
, waitForConnectedTimer(runtime->async().makeTimer(
	not_null<QObject*>{ owner->_owner.get() },
	[=] { owner->waitConnectedFailed(); }))
, waitForReceivedTimer(runtime->async().makeTimer(
	not_null<QObject*>{ owner->_owner.get() },
	[=] { owner->waitReceivedFailed(); }))
, waitForBetterTimer(runtime->async().makeTimer(
	not_null<QObject*>{ owner->_owner.get() },
	[=] { owner->waitBetterFailed(); }))
, brokerQueueDeadlineTimer(runtime->async().makeTimer(
	not_null<QObject*>{ owner->_owner.get() },
	[=] { owner->brokerQueueDeadlineFired(); }))
, waitForReceived(kMinReceiveTimeout)
, waitForConnected(kMinConnectedTimeout)
, pingSender(runtime->async().makeTimer(
	not_null<QObject*>{ owner->_owner.get() },
	[=] { owner->_owner->sendPingByTimer(); }))
, checkSentRequestsTimer(runtime->async().makeTimer(
	not_null<QObject*>{ owner->_owner.get() },
	[=] { owner->_owner->checkSentRequests(); }))
, clearOldContainersTimer(runtime->async().makeTimer(
	not_null<QObject*>{ owner->_owner.get() },
	[=] {
		owner->_owner->_messageHandler.clearOldContainers();
	})) {
}

SessionTransport::SessionTransport(
	not_null<SessionPrivate*> owner,
	not_null<RuntimeEnvironment*> runtime)
: _owner(owner)
, _timing(runtime, this) {
}

void SessionTransport::start() {
	connectToServer();
}

void SessionTransport::setRetryTimeout(int timeout) {
	_timing.retryTimeout = timeout;
}

bool SessionTransport::retryTimerActive() const {
	return _timing.retryTimer.isActive();
}

int SessionTransport::retryTimeout() const {
	return _timing.retryTimeout;
}

qint64 SessionTransport::retryWillFinish() const {
	return _timing.retryWillFinish;
}

AbstractConnection *SessionTransport::connection() const {
	return _state.connection.get();
}

QString SessionTransport::activeTransport() const {
	return _state.connection ? _state.connection->transport() : QString();
}

bool SessionTransport::empty() const {
	return !_state.connection && _state.testConnections.empty();
}

SessionProxyAttempt SessionTransport::proxyAttempt(
		const TestConnection &connection) const {
	return {
		.runtime = _owner->_runtime,
		.endpoint = connection.mtproxyEndpoint,
		.use = connection.mtproxyUse,
		.attempt = connection.mtproxyAttempt,
		.attemptStartedAt = connection.mtproxyAttemptStartedAt,
	};
}

SessionProxyAttempt SessionTransport::currentProxyAttempt() const {
	return {
		.runtime = _owner->_runtime,
		.endpoint = _state.mtproxyEndpoint,
		.use = _state.mtproxyUse,
		.attempt = _state.mtproxyAttempt,
		.attemptStartedAt = _state.mtproxyAttemptStartedAt,
	};
}

} // namespace MTP::details
