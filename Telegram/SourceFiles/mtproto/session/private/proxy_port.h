/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#pragma once

#include "base/basic_types.h"
#include "mtproto/proxy/mtproxy/endpoint_health.h"
#include "mtproto/proxy/endpoint_admission_arbiter.h"
#include "mtproto/runtime/connection_status_types.h"
#include "mtproto/runtime/proxy_endpoint.h"

#include <QtCore/QPointer>

#include <memory>

namespace MTP {

class RuntimeEnvironment;
struct ProxyDiagnosticsEvent;
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
	AdmissionTicketKey key;
	uint64 revision = 0;
	MtProxy::EndpointAdmissionWaitReason waitReason
		= MtProxy::EndpointAdmissionWaitReason::None;
	crl::time retryAfter = 0;
	ProxyConnectionError blockedBy = ProxyConnectionError::None;
};

using SessionProxyEndpointUse = ProxyConnectionUse;

enum class SessionProxySuccessScope {
	Handshake,
	FakeTlsAppData,
	Relay,
};

struct SessionProxyEndpointSnapshot {
	bool healthy = false;
	bool halfOpen = false;
};

class SessionProxyLease final {
public:
	class Impl {
	public:
		virtual ~Impl();

		virtual void release() = 0;
		virtual void transportReady() = 0;
		[[nodiscard]] virtual bool active() const = 0;
		[[nodiscard]] virtual uint64 attemptId() const = 0;
		[[nodiscard]] virtual uint64 proxyGeneration() const = 0;
		[[nodiscard]] virtual uint64 proxyEpoch() const = 0;
		[[nodiscard]] virtual uint64 successEpoch() const = 0;
		[[nodiscard]] virtual crl::time startedAt() const = 0;
		[[nodiscard]] virtual void *opaque() = 0;
	};

	SessionProxyLease() = default;
	explicit SessionProxyLease(std::unique_ptr<Impl> impl);
	SessionProxyLease(const SessionProxyLease &other) = delete;
	SessionProxyLease &operator=(const SessionProxyLease &other) = delete;
	SessionProxyLease(SessionProxyLease &&other) noexcept;
	SessionProxyLease &operator=(SessionProxyLease &&other) noexcept;
	~SessionProxyLease();

	void release();
	void transportReady();
	[[nodiscard]] bool active() const;
	[[nodiscard]] uint64 attemptId() const;
	[[nodiscard]] uint64 proxyGeneration() const;
	[[nodiscard]] uint64 proxyEpoch() const;
	[[nodiscard]] uint64 successEpoch() const;
	[[nodiscard]] crl::time startedAt() const;
	[[nodiscard]] Impl *impl() const;

private:
	std::unique_ptr<Impl> _impl;
};

struct SessionProxyAttempt {
	RuntimeEnvironment *runtime = nullptr;
	MtProxy::EndpointId endpoint;
	SessionProxyEndpointUse use = SessionProxyEndpointUse::Main;
	ProxyConnectionAttempt attempt;
	MtProxyAttemptPlan plan;
	ProxyTransportFailure transport;
	crl::time attemptStartedAt = 0;
};

struct SessionProxyStart {
	SessionProxyTicketId ticketId = 0;
	ProxyConnectionAttempt attempt;
	MtProxy::MainRecoveryToken acceptedRecoveryToken;
	uint64 proxyGeneration = 0;
	MtProxy::EndpointId endpoint;
	SessionProxyEndpointUse use = SessionProxyEndpointUse::Main;
	ProxyStealthOptions stealth;
	ProxyTlsProfile effectiveTlsProfile = ProxyTlsProfile::Auto;
	MtProxyAttemptPlan plan;
	SessionProxyLease lease;
	uint64 attemptId = 0;
	uint64 proxyEpoch = 0;
	uint64 successEpoch = 0;
	crl::time attemptStartedAt = 0;
};

struct SessionProxyRequest {
	uint64 proxyGeneration = 0;
	ProxyData proxy;
	QString address;
	int port = 0;
	SessionProxyEndpointUse use = SessionProxyEndpointUse::Main;
	MtProxy::MainRecoveryToken requestedRecoveryToken;
	MtProxy::EndpointId requestedRecoverySourceEndpoint;
	uint64 requestedRecoverySourceProxyGeneration = 0;
	ProxyStealthOptions stealth;
	ProxyTlsProfile configuredTlsProfile = ProxyTlsProfile::Auto;
	crl::time notBefore = 0;
	RuntimeEnvironment *runtime = nullptr;
	QPointer<QObject> context;
	Fn<void(SessionProxyStart)> start;
	Fn<void(SessionProxyAdmissionDecision)> status;
	crl::time waitStartedAt = 0;
};

class SessionProxyTicket final {
public:
	class Impl {
	public:
		virtual ~Impl();

		virtual void cancel() = 0;
		virtual void reevaluate() = 0;
		[[nodiscard]] virtual SessionProxyTicketId id() const = 0;
		[[nodiscard]] virtual MtProxy::MainRecoveryToken
			acceptedRecoveryToken() const = 0;
	};

	SessionProxyTicket() = default;
	explicit SessionProxyTicket(std::unique_ptr<Impl> impl);
	SessionProxyTicket(const SessionProxyTicket &other) = delete;
	SessionProxyTicket &operator=(const SessionProxyTicket &other) = delete;
	SessionProxyTicket(SessionProxyTicket &&other) noexcept;
	SessionProxyTicket &operator=(SessionProxyTicket &&other) noexcept;
	~SessionProxyTicket();

	void cancel();
	void reevaluate();
	[[nodiscard]] SessionProxyTicketId id() const;
	[[nodiscard]] MtProxy::MainRecoveryToken acceptedRecoveryToken() const {
		return _impl
			? _impl->acceptedRecoveryToken()
			: MtProxy::MainRecoveryToken();
	}
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
	[[nodiscard]] virtual SessionProxyEndpointSnapshot endpointSnapshot(
		not_null<RuntimeEnvironment*> runtime,
		const MtProxy::EndpointId &endpoint) const = 0;
	virtual void reportConnected(
		const SessionProxyAttempt &attempt,
		SessionProxyLease *lease,
		SessionProxySuccessScope scope) = 0;
	virtual void reportFirstMtprotoPayload(
		const SessionProxyAttempt &attempt,
		SessionProxyLease *lease) = 0;
	virtual void reportConnectionError(
		const SessionProxyAttempt &attempt,
		int errorCode,
		ProxyTransportFailure failure = {},
		SessionProxyLease *lease = nullptr,
		bool ignoreHealthyRemoteClosed = false) = 0;
	virtual void reportReceiveTimeout(
		not_null<RuntimeEnvironment*> runtime,
		const ProxyData &proxy,
		const QString &dc,
		const SessionProxyAttempt &attempt,
		bool receivedBefore,
		int silentStrikes,
		MtProxy::MainRecoveryToken &recoveryToken) = 0;
	virtual void reportConnectTimeout(
		const SessionProxyAttempt &attempt) = 0;
	virtual void reportAttemptCancelled(
		const SessionProxyAttempt &attempt,
		ProxyCloseOrigin origin) = 0;
	virtual void reportRelayStall(
		const SessionProxyAttempt &attempt,
		MtProxy::MainRecoveryToken &recoveryToken) = 0;
	virtual void cancelMainRecoveryBackoff(
		not_null<RuntimeEnvironment*> runtime,
		const MtProxy::EndpointId &endpoint,
		uint64 proxyGeneration,
		MtProxy::MainRecoveryToken token) = 0;
	virtual void writeDiagnosticsEvent(
		not_null<RuntimeEnvironment*> runtime,
		ProxyDiagnosticsEvent event) = 0;
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
[[nodiscard]] bool EmptySessionProxyEndpoint(
	const MtProxy::EndpointId &endpoint);

} // namespace details
} // namespace MTP
