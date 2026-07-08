/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#pragma once

#include "mtproto/session/private/proxy_port.h"

namespace MTP::details {

class ProductionSessionProxyPort final : public SessionProxyPort {
public:
	[[nodiscard]] SessionProxyTicket requestConnection(
		SessionProxyRequest request) override;
	void cancelByProxyGeneration(
		RuntimeEnvironment *runtime,
		uint64 generation) override;
	[[nodiscard]] MtProxy::Snapshot endpointSnapshot(
		not_null<RuntimeEnvironment*> runtime,
		const MtProxy::EndpointId &endpoint) const override;
	void reportConnected(
		const SessionProxyAttempt &attempt,
		MtProxy::EndpointAttemptLease *lease,
		MtProxy::SuccessScope scope) override;
	void reportFirstMtprotoPayload(
		const SessionProxyAttempt &attempt) override;
	void reportConnectionError(
		const SessionProxyAttempt &attempt,
		MtProxy::FailureReason reason,
		MtProxy::EndpointAttemptLease *lease = nullptr) override;
	void reportReceiveTimeout(
		not_null<RuntimeEnvironment*> runtime,
		const ProxyData &proxy,
		const QString &dc,
		const SessionProxyAttempt &attempt,
		bool receivedBefore,
		int silentStrikes) override;
	void reportConnectTimeout(
		const SessionProxyAttempt &attempt) override;
	void reportRelayStall(
		const SessionProxyAttempt &attempt) override;
	void logEvent(
		not_null<RuntimeEnvironment*> runtime,
		const ProxyData &proxy,
		const ProxyConnectionAttempt &attempt,
		const QString &dc,
		ProxyDiagnosticsPhase phase,
		ProxyDiagnosticsSeverity severity,
		const QString &message) override;
};

} // namespace MTP::details
