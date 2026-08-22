/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "mtproto/proxy/socket_factory.h"

#include "mtproto/proxy/mtproxy/tls_socket.h"
#include "mtproto/proxy/wss/socket.h"
#include "mtproto/details/mtproto_web_proxy_socket.h"
#include "mtproto/transport/details/mtproto_tcp_socket.h"

namespace MTP::details {

std::unique_ptr<AbstractSocket> CreateProxyAwareSocket(
		not_null<RuntimeEnvironment*> runtime,
		not_null<QThread*> thread,
		const bytes::vector &secret,
		const ProxyData &proxy,
		bool protocolForFiles,
		const ProxyStealthOptions &stealth,
		int16 protocolDcId,
		ProxyConnectionAttempt mtproxyAttempt,
		MtProxyAttemptPlan mtproxyPlan,
		crl::time mtproxyAttemptStartedAt) {
	if (proxy.type == ProxyData::Type::Web) {
		return std::make_unique<WebProxySocket>(runtime, thread, proxy);
	}
	const auto networkProxy = ToNetworkProxy(proxy);
	if (stealth.transport == ProxyTransport::Wss) {
		auto route = WssCustomRoute(stealth);
		if (!route) {
			route = WssOfficialRoute(protocolDcId);
		}
		if (route) {
			return std::make_unique<WssSocket>(
				runtime,
				thread,
				networkProxy,
				protocolForFiles,
				std::move(*route));
		}
	}
	if (secret.size() >= 21 && secret[0] == bytes::type(0xEE)) {
		return std::make_unique<TlsSocket>(
			runtime,
			thread,
			secret,
			proxy,
			protocolForFiles,
			stealth,
			mtproxyAttempt,
			std::move(mtproxyPlan),
			mtproxyAttemptStartedAt);
	}
	return std::make_unique<TcpSocket>(
		runtime,
		thread,
		networkProxy,
		protocolForFiles);
}

} // namespace MTP::details
