/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#pragma once

#include "base/basic_types.h"
#include "mtproto/proxy/mtproxy/endpoint_health.h"
#include "mtproto/proxy/mtproxy/open_scheduler.h"

#include <QtCore/QObject>
#include <QtCore/QPointer>

#include <array>
#include <atomic>
#include <deque>
#include <memory>
#include <optional>
#include <variant>
#include <vector>

namespace MTP {

class ProxyEndpointContext;
struct ProxyDiagnosticsEvent;

} // namespace MTP

namespace MTP::details::MtProxy {

struct EndpointContextStorage;

enum class EndpointOpenGateStage {
	Closed,
	Open,
	HalfOpen,
	Recovering,
};

struct EndpointOpeningFlowKey {
	CanonicalProxyEndpoint endpoint;
	ProxyRuntimeId runtimeId = 0;
	uint64 proxyGeneration = 0;
	EndpointUse use = EndpointUse::Main;

	bool operator==(const EndpointOpeningFlowKey &other) const = default;
};

struct EndpointOpeningTicketOwner {
	AdmissionTicketKey key;
	uint64 revision = 0;

	bool operator==(const EndpointOpeningTicketOwner &other) const = default;
};

struct EndpointOpeningAttemptKey {
	ProxyRuntimeId runtimeId = 0;
	ProxyTraceId traceId = 0;
	uint64 ticketId = 0;
	uint64 proxyGeneration = 0;
	uint64 proxyEpoch = 0;
	uint64 successEpoch = 0;
	uint64 attemptId = 0;
	EndpointUse use = EndpointUse::Main;
	AdmissionTicketKey ticketKey;

	bool operator==(const EndpointOpeningAttemptKey &other) const = default;
};

using EndpointOpeningOwner = std::variant<
	EndpointOpeningTicketOwner,
	EndpointOpeningAttemptKey>;

struct EndpointOpeningIdentity {
	EndpointOpeningFlowKey flow;
	EndpointOpeningOwner owner;

	bool operator==(const EndpointOpeningIdentity &other) const = default;
};

struct EndpointOpeningAttemptIdentity {
	EndpointOpeningFlowKey flow;
	EndpointOpeningAttemptKey key;

	bool operator==(
		const EndpointOpeningAttemptIdentity &other) const = default;
};

struct TransportReady {
	EndpointOpeningAttemptIdentity identity;
	crl::time observedAt = 0;
};

struct RelayReady {
	EndpointOpeningAttemptIdentity identity;
	crl::time observedAt = 0;
};

struct PressureFailure {
	EndpointOpeningAttemptIdentity identity;
	crl::time observedAt = 0;
};

struct Cancelled {
	EndpointOpeningIdentity identity;
	crl::time observedAt = 0;
};

using EndpointOpeningEvent = std::variant<
	TransportReady,
	RelayReady,
	PressureFailure,
	Cancelled>;

struct OpeningAdmissionDecision {
	EndpointOpeningIdentity identity;
	EndpointOpenGateStage stage = EndpointOpenGateStage::Closed;
	ProxySchedulerLifecycle lifecycle = ProxySchedulerLifecycle::None;
	uint64 gateRevision = 0;
	crl::time openAt = 0;
	crl::time retryAt = 0;
	FailureReason blockedBy = FailureReason::None;
	uint64 reservationId = 0;
	uint64 permitId = 0;
	int permitIndex = -1;
	bool allowed = false;

	bool operator==(const OpeningAdmissionDecision &other) const = default;
};

inline constexpr auto kEndpointOpeningPermitCount = 4;

struct EndpointOpeningPermit {
	uint64 id = 0;
	uint64 reservationId = 0;
	EndpointOpeningIdentity owner;
	ProxySchedulerLifecycle lifecycle = ProxySchedulerLifecycle::None;
};

struct EndpointImmediateScoutRequest {
	CanonicalProxyEndpoint endpoint;
	RuntimeGenerationKey requester;
	uint64 requestId = 0;
	crl::time requestedAt = 0;
};

struct EndpointOpeningWakeIdentity {
	CanonicalProxyEndpoint endpoint;
	ProxyRuntimeId driverRuntimeId = 0;
	uint64 gateRevision = 0;
	uint64 token = 0;
	EndpointOpenGateStage stage = EndpointOpenGateStage::Closed;
	crl::time wakeAt = 0;
};

struct EndpointOpenGateState {
	EndpointOpenGateStage stage = EndpointOpenGateStage::Closed;
	uint64 revision = 0;
	uint64 lastPermitId = 0;
	uint64 lastScoutRequestId = 0;
	std::array<
		std::optional<EndpointOpeningPermit>,
		kEndpointOpeningPermitCount> permits;
	std::deque<PressureFailure> pressureWindow;
	int backoffRung = 0;
	crl::time openDeadline = 0;
	std::optional<EndpointOpeningIdentity> stageOwner;
	std::vector<EndpointOpeningAttemptIdentity> proofPendingAttempts;
	std::vector<EndpointOpeningAttemptIdentity> terminalAttempts;
	int recoverySuccessCount = 0;
	crl::time recoveryNextOpenAt = 0;
	std::optional<EndpointImmediateScoutRequest> immediateScoutRequest;
	std::optional<EndpointOpeningWakeIdentity> wake;
	OpenSlotSchedule openings;
};

} // namespace MTP::details::MtProxy

namespace MTP::details {

struct EndpointAdmissionRuntimeDispatch final {
	QPointer<QObject> dispatcher;
	Fn<crl::time()> now;
	Fn<int(int)> randomIndex;
	Fn<void(crl::time, QObject*, Fn<void()>)> singleShot;
	Fn<bool()> fastProxyWarmup;
	Fn<void(ProxyDiagnosticsEvent)> writeProxyDiagnosticsLine;
	std::shared_ptr<std::atomic<bool>> registrationLive;
};

struct EndpointAdmissionUpdate final {
	AdmissionTicketKey key;
	uint64 revision = 0;
	ProxySchedulerLifecycle lifecycle = ProxySchedulerLifecycle::None;
	MtProxy::EndpointUse use = MtProxy::EndpointUse::Main;
	crl::time enqueuedAt = 0;
	crl::time scheduledOpenAt = 0;
	crl::time retryAfter = 0;
	MtProxy::FailureReason blockedBy = MtProxy::FailureReason::None;
};

struct EndpointAdmissionGrant final {
	AdmissionTicketKey key;
	uint64 revision = 0;
	uint64 proxyGeneration = 0;
	MtProxy::EndpointId endpoint;
	MtProxy::EndpointUse use = MtProxy::EndpointUse::Main;
	MtProxy::MainRecoveryToken acceptedRecoveryToken;
	crl::time enqueuedAt = 0;
	crl::time scheduledOpenAt = 0;
	MtProxy::Admission admission;
	ProxyConnectionAttempt attempt;
};

struct EndpointAdmissionRequest final {
	AdmissionTicketKey key;
	uint64 proxyGeneration = 0;
	MtProxy::EndpointId endpoint;
	MtProxy::EndpointUse use = MtProxy::EndpointUse::Main;
	MtProxy::MainRecoveryToken requestedRecoveryToken;
	ProxyStealthOptions stealth;
	ProxyTlsProfile configuredTlsProfile = ProxyTlsProfile::Auto;
	crl::time notBefore = 0;
	ProxyTraceId traceId = 0;
	QPointer<QObject> owner;
	QMetaObject::Connection ownerDestroyed;
	Fn<void(EndpointAdmissionUpdate)> status;
	Fn<void(EndpointAdmissionGrant)> grant;
	crl::time waitStartedAt = 0;
};

struct EndpointAdmissionEnqueueResult final {
	bool accepted = false;
	MtProxy::MainRecoveryToken acceptedRecoveryToken;
};

class EndpointAdmissionArbiter final {
public:
	explicit EndpointAdmissionArbiter(
		MtProxy::EndpointContextStorage &storage);
	EndpointAdmissionArbiter(const EndpointAdmissionArbiter &other) = delete;
	EndpointAdmissionArbiter &operator=(
		const EndpointAdmissionArbiter &other) = delete;
	~EndpointAdmissionArbiter();

	void bindRuntime(
		ProxyRuntimeId runtimeId,
		EndpointAdmissionRuntimeDispatch dispatch);
	void unregisterRuntime(ProxyRuntimeId runtimeId);
	void cancelRuntime(ProxyRuntimeId runtimeId);
	[[nodiscard]] EndpointAdmissionEnqueueResult enqueue(
		std::weak_ptr<ProxyEndpointContext> context,
		EndpointAdmissionRequest request);
	void cancel(AdmissionTicketKey key, uint64 revision = 0);
	void ownerDestroyed(AdmissionTicketKey key);
	void cancelBeforeGeneration(
		ProxyRuntimeId runtimeId,
		uint64 proxyGeneration);
	void drainEndpoint(const QString &endpointKey);
	void openingEvent(MtProxy::EndpointOpeningEvent event);
	void requestImmediateScout(
		const MtProxy::CanonicalProxyEndpoint &endpoint,
		RuntimeGenerationKey requester);
	void composeEndpointViewLocked(
		const MtProxy::EndpointId &endpoint,
		RuntimeGenerationKey runtimeGeneration,
		MtProxy::ProxyEndpointView &view) const;

private:
	class Private;

	void wake(uint64 token);
	void deliverStatus(
		AdmissionTicketKey key,
		uint64 revision,
		uint64 transition,
		ProxySchedulerLifecycle lifecycle,
		const std::shared_ptr<std::atomic<bool>> &registrationLive);
	void deliverGrant(
		AdmissionTicketKey key,
		uint64 revision,
		uint64 transition,
		ProxySchedulerLifecycle lifecycle,
		const std::shared_ptr<std::atomic<bool>> &registrationLive);
	void statusDeliveryMissing(
		AdmissionTicketKey key,
		uint64 revision,
		uint64 transition,
		ProxySchedulerLifecycle lifecycle,
		const std::shared_ptr<std::atomic<bool>> &registrationLive);
	void grantDeliveryMissing(
		AdmissionTicketKey key,
		uint64 revision,
		uint64 transition,
		ProxySchedulerLifecycle lifecycle,
		const std::shared_ptr<std::atomic<bool>> &registrationLive);

	const std::unique_ptr<Private> _private;

};

} // namespace MTP::details
