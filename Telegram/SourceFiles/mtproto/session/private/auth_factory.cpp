/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "mtproto/session/private/auth_factory.h"

#include "mtproto/auth/mtproto_bound_key_creator.h"

namespace MTP::details {
namespace {

[[nodiscard]] BoundKeyCreator::Delegate ToBoundKeyDelegate(
		SessionAuthKeyDelegate delegate) {
	return {
		.unboundReady = std::move(delegate.unboundReady),
		.sentSome = std::move(delegate.sentSome),
		.receivedSome = std::move(delegate.receivedSome),
	};
}

class ProductionSessionBoundKeyCreator final
		: public SessionBoundKeyCreator {
public:
	ProductionSessionBoundKeyCreator(
		DcKeyRequest request,
		SessionAuthKeyDelegate delegate)
	: _inner(std::make_unique<BoundKeyCreator>(
		request,
		ToBoundKeyDelegate(std::move(delegate)))) {
	}

	void start(
			DcId dcId,
			int16 protocolDcId,
			not_null<AbstractConnection*> connection,
			not_null<DcOptions*> dcOptions) override {
		_inner->start(dcId, protocolDcId, connection, dcOptions);
	}

	void stop() override {
		_inner->stop();
	}

	void bind(AuthKeyPtr &&persistentKey) override {
		_inner->bind(std::move(persistentKey));
	}

	void restartBinder() override {
		_inner->restartBinder();
	}

	bool readyToBind() const override {
		return _inner->readyToBind();
	}

	SerializedRequest prepareBindRequest(
			const AuthKeyPtr &temporaryKey,
			uint64 sessionId) override {
		return _inner->prepareBindRequest(temporaryKey, sessionId);
	}

	DcKeyBindState handleBindResponse(const mtpBuffer &response) override {
		return _inner->handleBindResponse(response);
	}

	AuthKeyPtr bindPersistentKey() const override {
		return _inner->bindPersistentKey();
	}

private:
	std::unique_ptr<BoundKeyCreator> _inner;
};

class ProductionSessionAuthKeyFactory final : public SessionAuthKeyFactory {
public:
	std::unique_ptr<SessionBoundKeyCreator> create(
			DcKeyRequest request,
			SessionAuthKeyDelegate delegate) override {
		return std::make_unique<ProductionSessionBoundKeyCreator>(
			request,
			std::move(delegate));
	}
};

} // namespace

SessionAuthKeyFactory &DefaultSessionAuthKeyFactory() {
	static auto result = ProductionSessionAuthKeyFactory();
	return result;
}

} // namespace MTP::details
