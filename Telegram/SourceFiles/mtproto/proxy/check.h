/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#pragma once

#include "mtproto/connection_abstract.h"
#include "mtproto/proxy/connection_broker.h"
#include "mtproto/proxy/handshake_gate.h"

#include <memory>

namespace MTP {

class ProxyCheckConnection final {
public:
	struct Data {
		details::ConnectionPointer connection;
		details::ConnectionTicket connectionTicket;
		details::HandshakeGateLease handshakeGate;
		details::MtProxy::EndpointId mtproxyEndpoint;
		details::MtProxy::EndpointAttemptLease mtproxyLease;
		bool finished = false;
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
	not_null<Instance*> mtproto,
	const ProxyData &proxy,
	bool tryIPv6,
	const ProxyStealthOptions &stealth,
	ProxyCheckConnection &v4,
	ProxyCheckConnection &v6,
	Fn<void(details::AbstractConnection *raw, int ping)> done,
	Fn<void(details::AbstractConnection *raw)> fail);

} // namespace MTP
