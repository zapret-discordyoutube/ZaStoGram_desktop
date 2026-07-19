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

#include <atomic>
#include <memory>
#include <optional>
#include <variant>

namespace MTP {

class ProxyEndpointContext;
struct ProxyDiagnosticsEvent;

} // namespace MTP

namespace MTP::details::MtProxy {

struct EndpointContextStorage;

enum class EndpointAdmissionWaitReason {
	None,
	Slot,
	HealthOrNotBefore,
};

struct OpeningPermitTicketOwner {
	AdmissionTicketKey key;
	uint64 revision = 0;

	bool operator==(const OpeningPermitTicketOwner &other) const = default;
};

using EndpointOpeningPermitOwner = std::variant<
	std::monostate,
	OpeningPermitTicketOwner,
	ProxyConnectionAttempt>;

struct EndpointOpeningPermit {
	EndpointOpeningPermitOwner owner;
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
	MtProxy::EndpointAdmissionWaitReason waitReason
		= MtProxy::EndpointAdmissionWaitReason::None;
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
	uint64 revision = 0;
	MtProxy::MainRecoveryToken acceptedRecoveryToken;
	bool accepted = false;
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
	void cancel(AdmissionTicketKey key, uint64 revision);
	void ownerDestroyed(AdmissionTicketKey key, uint64 revision);
	void cancelBeforeGeneration(
		ProxyRuntimeId runtimeId,
		uint64 proxyGeneration);
	void drainEndpoint(const QString &endpointKey);
	void reevaluate(AdmissionTicketKey key, uint64 revision);
	void releaseOpeningPermit(
		const QString &endpointKey,
		const ProxyConnectionAttempt &attempt);
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
