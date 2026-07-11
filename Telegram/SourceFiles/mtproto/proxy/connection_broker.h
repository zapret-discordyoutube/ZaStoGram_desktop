/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#pragma once

#include "base/basic_types.h"
#include "mtproto/proxy/mtproxy/endpoint_health.h"
#include "mtproto/proxy/proxy_endpoint_context.h"

#include <QtCore/QMutex>
#include <QtCore/QPointer>

#include <memory>

namespace MTP {

class RuntimeEnvironment;
enum class ProxyDiagnosticsPhase;

namespace details {

using ConnectionTicketId = uint64;

enum class ConnectionBrokerAction {
	StartNow,
	Queued,
	StartAfter,
	Rejected,
};

struct ConnectionBrokerDecision {
	ConnectionBrokerAction action = ConnectionBrokerAction::StartNow;
	crl::time retryAfter = 0;
	MtProxy::FailureReason blockedBy = MtProxy::FailureReason::None;
};

struct ConnectionStart {
	ConnectionTicketId ticketId = 0;
	ProxyConnectionAttempt attempt;
	uint64 proxyGeneration = 0;
	MtProxy::EndpointId endpoint;
	MtProxy::EndpointUse use = MtProxy::EndpointUse::Main;
	ProxyStealthOptions stealth;
	ProxyTlsProfile effectiveTlsProfile = ProxyTlsProfile::Auto;
	MtProxyAttemptPlan plan;
	MtProxy::EndpointAttemptLease lease;
	uint64 attemptId = 0;
	uint64 proxyEpoch = 0;
	uint64 successEpoch = 0;
	crl::time attemptStartedAt = 0;
};

struct ConnectionRequest {
	uint64 proxyGeneration = 0;
	MtProxy::EndpointId endpoint;
	ProxyData proxy;
	MtProxy::EndpointUse use = MtProxy::EndpointUse::Main;
	ProxyStealthOptions stealth;
	ProxyTlsProfile configuredTlsProfile = ProxyTlsProfile::Auto;
	ProxyConnectionPattern connectionPattern = ProxyConnectionPattern::Off;
	crl::time notBefore = 0;
	QPointer<QObject> context;
	Fn<void(ConnectionStart)> start;
	Fn<void(ConnectionBrokerDecision)> status;
};

class ConnectionBroker;

class ConnectionTicket final {
public:
	ConnectionTicket() = default;
	ConnectionTicket(const ConnectionTicket &other) = delete;
	ConnectionTicket &operator=(const ConnectionTicket &other) = delete;
	ConnectionTicket(ConnectionTicket &&other) noexcept;
	ConnectionTicket &operator=(ConnectionTicket &&other) noexcept;
	~ConnectionTicket();

	void cancel();
	[[nodiscard]] ConnectionTicketId id() const;
	[[nodiscard]] explicit operator bool() const;

private:
	friend class ConnectionBroker;

	ConnectionTicket(ConnectionBroker *broker, ConnectionTicketId id);

	ConnectionBroker *_broker = nullptr;
	ConnectionTicketId _id = 0;

};

class ConnectionBroker final {
public:
	explicit ConnectionBroker(not_null<RuntimeEnvironment*> runtime);
	ConnectionBroker(const ConnectionBroker &other) = delete;
	ConnectionBroker &operator=(const ConnectionBroker &other) = delete;
	~ConnectionBroker();

	[[nodiscard]] ConnectionTicket request(ConnectionRequest request);
	void cancel(ConnectionTicketId id);
	void cancelByProxyGeneration(uint64 generation);
	void cancelByOwnerDestruction();

private:
	struct RequestState;
	struct EndpointQueue;
	struct ClaimResult;
	struct DrainVerdict;

	// Keeps a released-slot callback from touching a destroyed broker:
	// the callback locks the guard and checks the pointer, the destructor
	// nulls it under the same lock before removing the listener.
	struct WakeGuard {
		QMutex mutex;
		ConnectionBroker *broker = nullptr;
	};

	[[nodiscard]] EndpointQueue &queueFor(MtProxy::EndpointUse use);
	void wakeEndpoint(const QString &endpointKey);
	void drain();
	void drainQueue(MtProxy::EndpointUse use);
	[[nodiscard]] ClaimResult claimFront(MtProxy::EndpointUse use);
	[[nodiscard]] DrainVerdict computeVerdict(
		const std::shared_ptr<RequestState> &state);
	[[nodiscard]] bool stillFrontLocked(
		MtProxy::EndpointUse use,
		const std::shared_ptr<RequestState> &state);
	void commitEmptyEndpoint(const std::shared_ptr<RequestState> &state);
	void commitAdmitted(
		MtProxy::EndpointUse use,
		const std::shared_ptr<RequestState> &state,
		DrainVerdict &&verdict);
	void commitDenied(
		MtProxy::EndpointUse use,
		const std::shared_ptr<RequestState> &state,
		const DrainVerdict &verdict);
	void scheduleDrain(
		const std::shared_ptr<RequestState> &state,
		crl::time delay);
	void scheduleOpenRetry(
		const std::shared_ptr<RequestState> &state,
		crl::time delay);
	void scheduleStart(
		const std::shared_ptr<RequestState> &state,
		crl::time delay);
	void start(ConnectionTicketId id);
	void releaseAdmission(const std::shared_ptr<RequestState> &state);
	void notify(
		const std::shared_ptr<RequestState> &state,
		ConnectionBrokerDecision decision);
	void reportAdmissionEvent(
		const std::shared_ptr<RequestState> &state,
		ProxyDiagnosticsPhase phase,
		ConnectionBrokerDecision decision,
		const QString &message);

	std::unique_ptr<EndpointQueue> _mainQueue;
	std::unique_ptr<EndpointQueue> _mediaQueue;
	std::unique_ptr<EndpointQueue> _uploadQueue;
	std::unique_ptr<EndpointQueue> _proxyCheckQueue;
	ConnectionTicketId _lastTicketId = 0;
	QMutex _mutex;
	const not_null<RuntimeEnvironment*> _runtime;
	const std::shared_ptr<ProxyEndpointContext> _endpointContext;
	const std::shared_ptr<WakeGuard> _wakeGuard;
	AdmissionReleaseListenerId _releaseListenerId = 0;

};

} // namespace details
} // namespace MTP
