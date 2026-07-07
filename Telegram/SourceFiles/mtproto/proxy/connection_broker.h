/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#pragma once

#include "mtproto/proxy/mtproxy/endpoint_health.h"
#include "base/basic_types.h"

#include <QtCore/QMutex>
#include <QtCore/QPointer>

#include <memory>

namespace MTP {

class Instance;
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
	uint64 proxyGeneration = 0;
	MtProxy::EndpointId endpoint;
	MtProxy::EndpointUse use = MtProxy::EndpointUse::Main;
	ProxyStealthOptions stealth;
	ProxyTlsProfile effectiveTlsProfile = ProxyTlsProfile::Auto;
	MtProxy::EndpointAttemptLease lease;
	uint64 attemptId = 0;
	uint64 proxyEpoch = 0;
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
	MTP::Instance *instance = nullptr;
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

	explicit ConnectionTicket(ConnectionTicketId id);

	ConnectionTicketId _id = 0;
};

class ConnectionBroker final {
public:
	[[nodiscard]] static ConnectionBroker &Instance();

	[[nodiscard]] ConnectionTicket request(ConnectionRequest request);
	void cancel(ConnectionTicketId id);
	void cancelByProxyGeneration(MTP::Instance *instance, uint64 generation);

private:
	struct RequestState;
	struct EndpointQueue;

	ConnectionBroker();
	~ConnectionBroker();

	[[nodiscard]] EndpointQueue &queueFor(MtProxy::EndpointUse use);
	void drain();
	void drainQueue(MtProxy::EndpointUse use);
	void scheduleDrain(
		const std::shared_ptr<RequestState> &state,
		crl::time delay);
	void scheduleStart(
		const std::shared_ptr<RequestState> &state,
		crl::time delay);
	void start(ConnectionTicketId id);
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
};

} // namespace details
} // namespace MTP
