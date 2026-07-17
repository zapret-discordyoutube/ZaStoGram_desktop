/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#pragma once

#include "base/basic_types.h"
#include "mtproto/proxy/mtproxy/endpoint_health.h"

#include <QtCore/QObject>
#include <QtCore/QPointer>

#include <atomic>
#include <memory>

namespace MTP {

class ProxyEndpointContext;
struct ProxyDiagnosticsEvent;

} // namespace MTP

namespace MTP::details::MtProxy {

struct EndpointContextStorage;

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
	Fn<void(MtProxy::EndpointLaneCommand)> laneControl;
	Fn<void(EndpointAdmissionUpdate)> status;
	Fn<void(EndpointAdmissionGrant)> grant;
	crl::time waitStartedAt = 0;
	MtProxy::EndpointTransferDemandKey transferDemand;
	MtProxy::ReclaimEpisodeToken reclaimEpisodeToken;
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
	void endTransferDemand(
		MtProxy::EndpointTransferDemandKey demand,
		QPointer<QObject> owner);
	void cancel(AdmissionTicketKey key, uint64 revision = 0);
	void ownerDestroyed(AdmissionTicketKey key);
	void cancelBeforeGeneration(
		ProxyRuntimeId runtimeId,
		uint64 proxyGeneration);
	[[nodiscard]] bool authorizeLaneSuspension(
		const QString &endpointKey,
		uint64 token,
		ProxyRuntimeId runtimeId,
		uint64 proxyGeneration,
		uint64 attemptId);
	void demandLaneResume(
		const QString &endpointKey,
		uint64 token,
		ProxyRuntimeId runtimeId,
		uint64 proxyGeneration,
		uint64 attemptId);
	void acknowledgeLaneSuspension(
		const QString &endpointKey,
		uint64 token,
		ProxyRuntimeId runtimeId,
		uint64 proxyGeneration,
		uint64 attemptId,
		MtProxy::EndpointLaneCommandResult result,
		bool delivered);
	void acknowledgeLaneResume(
		const QString &endpointKey,
		uint64 token,
		ProxyRuntimeId runtimeId,
		uint64 proxyGeneration,
		uint64 attemptId,
		crl::time deadlineAt,
		MtProxy::EndpointLaneCommandResult result,
		bool delivered);
	void drainEndpoint(const QString &endpointKey);
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
		ProxySchedulerLifecycle lifecycle);
	void deliverGrant(
		AdmissionTicketKey key,
		uint64 revision,
		uint64 transition,
		ProxySchedulerLifecycle lifecycle);

	const std::unique_ptr<Private> _private;

};

} // namespace MTP::details
