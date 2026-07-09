/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "mtproto/session/private/session_private.h"
#include "mtproto/session/private/timings.h"

#include "mtproto/instance/mtp_instance.h"
#include "mtproto/proxy/diagnostics.h"

namespace MTP::details {

SessionTransport::TimingState::TimingState(
		not_null<RuntimeEnvironment*> runtime,
		not_null<SessionTransport*> owner,
		not_null<QThread*> thread)
: retryTimer(runtime->async().makeTimer(
	thread,
	[=] { owner->retryByTimer(); }))
, oldConnectionTimer(runtime->async().makeTimer(
	thread,
	[=] { owner->markConnectionOld(); }))
, waitForConnectedTimer(runtime->async().makeTimer(
	thread,
	[=] { owner->waitConnectedFailed(); }))
, waitForReceivedTimer(runtime->async().makeTimer(
	thread,
	[=] { owner->waitReceivedFailed(); }))
, waitForBetterTimer(runtime->async().makeTimer(
	thread,
	[=] { owner->waitBetterFailed(); }))
, brokerQueueDeadlineTimer(runtime->async().makeTimer(
	thread,
	[=] { owner->brokerQueueDeadlineFired(); }))
, waitForReceived(kMinReceiveTimeout)
, waitForConnected(kMinConnectedTimeout)
, pingSender(runtime->async().makeTimer(
	thread,
	[=] { owner->_owner->sendPingByTimer(); }))
, checkSentRequestsTimer(runtime->async().makeTimer(
	thread,
	[=] { owner->_owner->checkSentRequests(); }))
, clearOldContainersTimer(runtime->async().makeTimer(
	thread,
	[=] { owner->_owner->_messageHandler.clearOldContainers(); })) {
}

SessionTransport::SessionTransport(
	not_null<SessionPrivate*> owner,
	not_null<RuntimeEnvironment*> runtime,
	not_null<QThread*> thread)
: _owner(owner)
, _timing(runtime, this, thread) {
}

void SessionTransport::start() {
	connectToServer();
}

void SessionTransport::setRetryTimeout(int timeout) {
	_timing.retryTimeout = timeout;
}

void SessionTransport::scheduleRetryTimeout(int timeout) {
	_timing.retryTimeout = timeout;
	_timing.retryTimer.callOnce(_timing.retryTimeout);
	_timing.retryWillFinish = crl::now() + _timing.retryTimeout;
}

void SessionTransport::schedulePing(crl::time timeout) {
	_timing.pingSender.callOnce(timeout);
}

void SessionTransport::scheduleCheckSentRequests(crl::time timeout) {
	_timing.checkSentRequestsTimer.callOnce(timeout);
}

void SessionTransport::scheduleClearOldContainers(
		crl::time timeout,
		bool repeated) {
	if (repeated) {
		_timing.clearOldContainersTimer.callEach(timeout);
	} else {
		_timing.clearOldContainersTimer.callOnce(timeout);
	}
}

void SessionTransport::resetRetryTimeout() {
	_timing.retryTimeout = 1;
}

bool SessionTransport::retryTimerActive() const {
	return _timing.retryTimer.isActive();
}

bool SessionTransport::checkSentRequestsTimerActive() const {
	return _timing.checkSentRequestsTimer.isActive();
}

bool SessionTransport::clearOldContainersTimerActive() const {
	return _timing.clearOldContainersTimer.isActive();
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

bool SessionTransport::hasReceivedData() const {
	return _state.connection && !_state.connection->received().empty();
}

mtpBuffer SessionTransport::takeReceivedData() {
	Assert(_state.connection != nullptr);
	Assert(!_state.connection->received().empty());

	auto result = std::move(_state.connection->received().front());
	_state.connection->received().pop_front();
	return result;
}

QString SessionTransport::activeTransport() const {
	return _state.connection ? _state.connection->transport() : QString();
}

QString SessionTransport::connectionTag() const {
	return _state.connection ? _state.connection->tag() : u"none"_q;
}

crl::time SessionTransport::connectionPingTime() const {
	return _state.connection ? _state.connection->pingTime() : 0;
}

auto SessionTransport::serviceRequest() const
-> AbstractConnection::TransportServiceRequest {
	Assert(_state.connection != nullptr);
	return _state.connection->serviceRequest();
}

bool SessionTransport::serviceRequestNeeded(
		AbstractConnection::TransportServiceRequest request) const {
	return _state.connection && _state.connection->serviceRequestNeeded(request);
}

mtpBuffer SessionTransport::prepareSecurePacket(
		uint64 keyId,
		MTPint128 msgKey,
		uint32 size) const {
	Assert(_state.connection != nullptr);
	return _state.connection->prepareSecurePacket(keyId, msgKey, size);
}

void SessionTransport::sendData(
		mtpBuffer &&buffer,
		AbstractConnection::SendDataContext context) {
	Assert(_state.connection != nullptr);
	_state.connection->sendData(std::move(buffer), context);
}

void SessionTransport::logInfo(const QString &message) const {
	Assert(_state.connection != nullptr);
	_state.connection->logInfo(message);
}

bool SessionTransport::empty() const {
	return !_state.connection && _state.testConnections.empty();
}

void SessionTransport::startContainerCleanup() {
	_timing.clearOldContainersTimer.callEach(kSentContainerLives);
}

void SessionTransport::noteMtprotoPayloadReceived() {
	_timing.retryTimeout = 1;
	if (!_state.mtprotoDataReceived) {
		_state.mtprotoDataReceived = true;
		_state.mtprotoSilentTimeouts = 0;
		if (_state.proxyMigrationScout) {
			_state.proxyMigrationScout = false;
			const auto generation = _state.proxyGeneration;
			InvokeQueued(_owner->_instance, [
				delegate = _owner->_delegate,
				generation
			] {
				delegate->proxyMigrationSucceeded(generation);
			});
		}
		_owner->logMtprotoEvent(
			ProxyDiagnosticsPhase::MtpFirstDataReceived,
			ProxyDiagnosticsSeverity::Info,
			u"first mtproto payload received"_q);
		if (_state.connection) {
			_state.connection->markProxyMtprotoPayloadReceived();
		}
		_owner->_proxyPort->reportFirstMtprotoPayload(currentProxyAttempt());
	}
	_state.startedConnectingAt = crl::time(0);
}

SessionProxyAttempt SessionTransport::proxyAttempt(
		const TestConnection &connection) const {
	const auto attempt = connection.data
		? connection.data->proxyConnectionAttempt()
		: connection.mtproxyAttempt;
	return {
		.runtime = _owner->_runtime,
		.endpoint = connection.mtproxyEndpoint,
		.use = connection.mtproxyUse,
		.attempt = attempt,
		.plan = connection.mtproxyPlan,
		.transport = connection.data->proxyTransportFailure(),
		.attemptStartedAt = connection.mtproxyAttemptStartedAt,
	};
}

SessionProxyAttempt SessionTransport::currentProxyAttempt() const {
	const auto attempt = _state.connection
		? _state.connection->proxyConnectionAttempt()
		: _state.mtproxyAttempt;
	return {
		.runtime = _owner->_runtime,
		.endpoint = _state.mtproxyEndpoint,
		.use = _state.mtproxyUse,
		.attempt = attempt,
		.plan = _state.mtproxyPlan,
		.transport = _state.connection
			? _state.connection->proxyTransportFailure()
			: ProxyTransportFailure(),
		.attemptStartedAt = _state.mtproxyAttemptStartedAt,
	};
}

} // namespace MTP::details
