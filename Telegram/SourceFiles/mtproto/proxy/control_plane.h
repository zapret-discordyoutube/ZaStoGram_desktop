/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#pragma once

#include "base/basic_types.h"
#include "mtproto/proxy/mtproxy/endpoint_health.h"
#include "mtproto/proxy/status.h"

namespace MTP {

class Instance;
struct ProxyEventReport;

enum class ProxyControlPlaneSuccessScope {
	None,
	Handshake,
	Relay,
};

enum class ProxyAdmissionAction {
	StartNow,
	Queued,
	Rejected,
};

struct ProxyFact {
	ProxyConnectionStatus status;
	ProxyControlPlaneSuccessScope successScope
		= ProxyControlPlaneSuccessScope::None;
};

struct ProxyAdmissionRequest {
	details::MtProxy::EndpointId endpoint;
	details::MtProxy::EndpointUse use = details::MtProxy::EndpointUse::Main;
	ProxyStealthOptions stealth;
	ProxyTlsProfile configuredTlsProfile = ProxyTlsProfile::Auto;
	uint64 proxyGeneration = 0;
	bool relayProofRequired = false;
	bool relayProven = false;
	int active = 0;
	int scoutCap = 2;
	crl::time retryAfter = 1000;
};

struct ProxyAdmissionDecision {
	ProxyAdmissionAction action = ProxyAdmissionAction::StartNow;
	crl::time retryAfter = 0;
	details::MtProxy::FailureReason blockedBy
		= details::MtProxy::FailureReason::None;
	ProxyStealthOptions stealth;
	ProxyTlsProfile effectiveTlsProfile = ProxyTlsProfile::Auto;
	details::MtProxy::EndpointAttemptLease lease;
	uint64 proxyGeneration = 0;
	uint64 attemptId = 0;
	uint64 proxyEpoch = 0;
	uint64 successEpoch = 0;
	crl::time attemptStartedAt = 0;
};

struct ProxyEndpointSnapshot {
	ProxyData proxy;
	ProxyConnectionStatus status;
	bool relayProven = false;
};

class ProxyControlPlane final {
public:
	void submitFact(ProxyFact fact);
	[[nodiscard]] ProxyAdmissionDecision admit(ProxyAdmissionRequest request);
	[[nodiscard]] ProxyConnectionStatus selectedStatus() const;
	[[nodiscard]] ProxyEndpointSnapshot endpointSnapshot() const;

	[[nodiscard]] static ProxyFact FactFromReport(
		const ProxyEventReport &report);
	[[nodiscard]] static ProxyConnectionStatus Reduce(
		const ProxyConnectionStatus &current,
		ProxyFact fact);
	[[nodiscard]] static ProxyAdmissionDecision Admit(
		ProxyAdmissionRequest request);
	static void ReportMtproxyFailure(
		details::MtProxy::FailureReport report);
	static void ReportMtproxySuccess(
		details::MtProxy::SuccessReport report);
	static void NoteMtproxyRelayStall(
		details::MtProxy::RelayStallReport report);
	[[nodiscard]] static details::MtProxy::Snapshot MtproxyEndpointSnapshot(
		const details::MtProxy::EndpointId &endpoint);
	[[nodiscard]] static auto MtproxyEndpointChanges()
	-> rpl::producer<details::MtProxy::EndpointEvent>;
	static void SubmitFact(
		not_null<Instance*> instance,
		const ProxyEventReport &report);

private:
	ProxyConnectionStatus _selectedStatus;
	ProxyEndpointSnapshot _endpointSnapshot;
};

} // namespace MTP
