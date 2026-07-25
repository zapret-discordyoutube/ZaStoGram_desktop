/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#pragma once

#include "mtproto/proxy/dial_pacer.h"
#include "mtproto/proxy/mtproxy/endpoint_identity.h"
#include "mtproto/transport/connection_abstract.h"

#include <memory>

namespace MTP {

enum class ProxyCheckStatus {
	Idle,
	WaitingForConnectionSlot,
	Resolving,
	TcpConnected,
	ClientHelloSent,
	ServerHelloOk,
	FirstTlsAppData,
	FirstMtprotoPayload,
	ConnectedByActiveSession,
};

class ProxyCheckConnection final {
public:
	struct Data {
		RuntimeEnvironment *runtime = nullptr;
		ProxyData proxy;
		DcId dcId = 0;
		details::ConnectionPointer connection;
		details::ProxyDialLease dial;
		details::MtProxy::EndpointId mtproxyEndpoint;
		ProxyStealthOptions mtproxyStealth;
		ProxyTlsProfile mtproxySentProfile = ProxyTlsProfile::Auto;
		ProxyConnectionAttempt mtproxyAttempt;
		MtProxyAttemptPlan mtproxyPlan;
		crl::time mtproxyAttemptStartedAt = 0;
		Fn<void(ProxyCheckStatus status)> progress;
		QString probeKey;
		ProxyCheckStatus progressStatus = ProxyCheckStatus::Idle;
		bool finished = false;
		bool networkStarted = false;
	};

	ProxyCheckConnection();
	ProxyCheckConnection(const ProxyCheckConnection &other) = delete;
	ProxyCheckConnection &operator=(const ProxyCheckConnection &other) = delete;
	ProxyCheckConnection(ProxyCheckConnection &&other) noexcept;
	ProxyCheckConnection &operator=(ProxyCheckConnection &&other) noexcept;
	~ProxyCheckConnection();

	[[nodiscard]] details::AbstractConnection *get() const;
	[[nodiscard]] explicit operator bool() const;
	[[nodiscard]] details::AbstractConnection *operator->() const;
	[[nodiscard]] std::shared_ptr<Data> state() const;
	void reset();

private:
	std::shared_ptr<Data> _data;

};

void ResetProxyCheckers(
	ProxyCheckConnection &v4,
	ProxyCheckConnection &v6);
void DropProxyChecker(
	ProxyCheckConnection &v4,
	ProxyCheckConnection &v6,
	not_null<details::AbstractConnection*> raw);
[[nodiscard]] bool HasProxyCheckers(
	const ProxyCheckConnection &v4,
	const ProxyCheckConnection &v6);
void StartProxyCheck(
	not_null<RuntimeEnvironment*> runtime,
	const ProxyData &proxy,
	bool tryIPv6,
	const ProxyStealthOptions &stealth,
	ProxyCheckConnection &v4,
	ProxyCheckConnection &v6,
	Fn<void(details::AbstractConnection *raw, int ping)> done,
	Fn<void(details::AbstractConnection *raw)> fail,
	Fn<void(ProxyCheckStatus status)> progress = nullptr);

} // namespace MTP
