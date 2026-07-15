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

#include <QtCore/QPointer>

#include <atomic>
#include <memory>

namespace MTP {

class RuntimeEnvironment;

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
	MtProxy::MainRecoveryToken acceptedRecoveryToken;
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
	MtProxy::MainRecoveryToken requestedRecoveryToken;
	ProxyStealthOptions stealth;
	ProxyTlsProfile configuredTlsProfile = ProxyTlsProfile::Auto;
	ProxyConnectionPattern connectionPattern = ProxyConnectionPattern::Off;
	crl::time notBefore = 0;
	QPointer<QObject> context;
	Fn<void(MtProxy::EndpointLaneCommand)> laneControl;
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
	[[nodiscard]] MtProxy::MainRecoveryToken acceptedRecoveryToken() const;
	[[nodiscard]] explicit operator bool() const;

private:
	friend class ConnectionBroker;

	ConnectionTicket(
		std::weak_ptr<ProxyEndpointContext> context,
		AdmissionTicketKey key,
		MtProxy::MainRecoveryToken acceptedRecoveryToken);

	std::weak_ptr<ProxyEndpointContext> _context;
	AdmissionTicketKey _key;
	MtProxy::MainRecoveryToken _acceptedRecoveryToken;

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
	std::atomic<ConnectionTicketId> _lastTicketId = 0;
	const not_null<RuntimeEnvironment*> _runtime;
	const std::shared_ptr<ProxyEndpointContext> _endpointContext;

};

} // namespace details
} // namespace MTP
