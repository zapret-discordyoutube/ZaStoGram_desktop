/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#pragma once

#include "base/basic_types.h"
#include "mtproto/proxy/mtproxy/endpoint_health.h"

#include <QtCore/QPointer>

#include <memory>

namespace MTP {

class RuntimeEnvironment;
enum class ProxyDiagnosticsPhase;
enum class ProxyDiagnosticsSeverity;

namespace details {

class SessionProxyPort;

using SessionProxyTicketId = uint64;

enum class SessionProxyAdmissionAction {
	StartNow,
	Queued,
	StartAfter,
	Rejected,
};

struct SessionProxyAdmissionDecision {
	SessionProxyAdmissionAction action = SessionProxyAdmissionAction::StartNow;
	crl::time retryAfter = 0;
	MtProxy::FailureReason blockedBy = MtProxy::FailureReason::None;
};

struct SessionProxyAttempt {
	RuntimeEnvironment *runtime = nullptr;
	MtProxy::EndpointId endpoint;
	MtProxy::EndpointUse use = MtProxy::EndpointUse::Main;
	ProxyConnectionAttempt attempt;
	crl::time attemptStartedAt = 0;
};

struct SessionProxyStart {
	SessionProxyTicketId ticketId = 0;
	uint64 proxyGeneration = 0;
	MtProxy::EndpointId endpoint;
	MtProxy::EndpointUse use = MtProxy::EndpointUse::Main;
	ProxyStealthOptions stealth;
	ProxyTlsProfile effectiveTlsProfile = ProxyTlsProfile::Auto;
	MtProxy::EndpointAttemptLease lease;
	uint64 attemptId = 0;
	uint64 proxyEpoch = 0;
	uint64 successEpoch = 0;
	crl::time attemptStartedAt = 0;
};

struct SessionProxyRequest {
	uint64 proxyGeneration = 0;
	MtProxy::EndpointId endpoint;
	ProxyData proxy;
	MtProxy::EndpointUse use = MtProxy::EndpointUse::Main;
	ProxyStealthOptions stealth;
	ProxyTlsProfile configuredTlsProfile = ProxyTlsProfile::Auto;
	ProxyConnectionPattern connectionPattern = ProxyConnectionPattern::Off;
	crl::time notBefore = 0;
	RuntimeEnvironment *runtime = nullptr;
	QPointer<QObject> context;
	Fn<void(SessionProxyStart)> start;
	Fn<void(SessionProxyAdmissionDecision)> status;
};

class SessionProxyTicket final {
public:
	class Impl {
	public:
		virtual ~Impl();

		virtual void cancel() = 0;
		[[nodiscard]] virtual SessionProxyTicketId id() const = 0;
	};

	SessionProxyTicket() = default;
	explicit SessionProxyTicket(std::unique_ptr<Impl> impl);
	SessionProxyTicket(const SessionProxyTicket &other) = delete;
	SessionProxyTicket &operator=(const SessionProxyTicket &other) = delete;
	SessionProxyTicket(SessionProxyTicket &&other) noexcept;
	SessionProxyTicket &operator=(SessionProxyTicket &&other) noexcept;
	~SessionProxyTicket();

	void cancel();
	[[nodiscard]] SessionProxyTicketId id() const;
	[[nodiscard]] explicit operator bool() const;

private:
	std::unique_ptr<Impl> _impl;
};

class SessionProxyPort {
public:
	virtual ~SessionProxyPort();

	[[nodiscard]] virtual SessionProxyTicket requestConnection(
		SessionProxyRequest request) = 0;
	virtual void cancelByProxyGeneration(
		RuntimeEnvironment *runtime,
		uint64 generation) = 0;
	[[nodiscard]] virtual MtProxy::Snapshot endpointSnapshot(
		not_null<RuntimeEnvironment*> runtime,
		const MtProxy::EndpointId &endpoint) const = 0;
	virtual void reportConnected(
		const SessionProxyAttempt &attempt,
		MtProxy::EndpointAttemptLease *lease,
		MtProxy::SuccessScope scope) = 0;
	virtual void reportFirstMtprotoPayload(
		const SessionProxyAttempt &attempt) = 0;
	virtual void reportConnectionError(
		const SessionProxyAttempt &attempt,
		MtProxy::FailureReason reason,
		MtProxy::EndpointAttemptLease *lease = nullptr) = 0;
	virtual void reportReceiveTimeout(
		not_null<RuntimeEnvironment*> runtime,
		const ProxyData &proxy,
		const QString &dc,
		const SessionProxyAttempt &attempt,
		bool receivedBefore,
		int silentStrikes) = 0;
	virtual void reportConnectTimeout(
		const SessionProxyAttempt &attempt) = 0;
	virtual void reportRelayStall(
		const SessionProxyAttempt &attempt) = 0;
	virtual void logEvent(
		not_null<RuntimeEnvironment*> runtime,
		const ProxyData &proxy,
		const ProxyConnectionAttempt &attempt,
		const QString &dc,
		ProxyDiagnosticsPhase phase,
		ProxyDiagnosticsSeverity severity,
		const QString &message) = 0;
};

[[nodiscard]] SessionProxyPort &DefaultSessionProxyPort();
[[nodiscard]] bool EmptySessionProxyAttempt(
	const SessionProxyAttempt &attempt);

} // namespace details
} // namespace MTP
