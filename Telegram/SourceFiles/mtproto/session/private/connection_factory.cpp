/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "mtproto/session/private/connection_factory.h"

namespace MTP::details {
namespace {

class ProductionSessionConnectionFactory final
		: public SessionConnectionFactory {
public:
	ConnectionPointer create(
			not_null<RuntimeEnvironment*> runtime,
			DcOptions::Variants::Protocol protocol,
			QThread *thread,
			const bytes::vector &secret,
			const ProxyData &proxy,
			const ProxyStealthOptions &stealth) override {
		return AbstractConnection::Create(
			runtime,
			protocol,
			thread,
			secret,
			proxy,
			stealth);
	}
};

} // namespace

SessionConnectionFactory &DefaultSessionConnectionFactory() {
	static auto result = ProductionSessionConnectionFactory();
	return result;
}

} // namespace MTP::details
