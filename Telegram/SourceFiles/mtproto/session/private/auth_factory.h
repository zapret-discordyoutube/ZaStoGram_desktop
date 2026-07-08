/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#pragma once

#include "mtproto/auth/mtproto_dc_key_creator.h"
#include "mtproto/auth/mtproto_dc_key_binder.h"

#include <memory>

namespace MTP::details {

class SerializedRequest;

struct SessionAuthKeyDelegate final {
	Fn<void(base::expected<DcKeyResult, DcKeyError>)> unboundReady;
	Fn<void(uint64)> sentSome;
	Fn<void()> receivedSome;
};

class SessionBoundKeyCreator {
public:
	virtual ~SessionBoundKeyCreator() = default;

	virtual void start(
		DcId dcId,
		int16 protocolDcId,
		not_null<AbstractConnection*> connection,
		not_null<DcOptions*> dcOptions) = 0;
	virtual void stop() = 0;
	virtual void bind(AuthKeyPtr &&persistentKey) = 0;
	virtual void restartBinder() = 0;
	[[nodiscard]] virtual bool readyToBind() const = 0;
	[[nodiscard]] virtual SerializedRequest prepareBindRequest(
		const AuthKeyPtr &temporaryKey,
		uint64 sessionId) = 0;
	[[nodiscard]] virtual DcKeyBindState handleBindResponse(
		const mtpBuffer &response) = 0;
	[[nodiscard]] virtual AuthKeyPtr bindPersistentKey() const = 0;
};

class SessionAuthKeyFactory {
public:
	virtual ~SessionAuthKeyFactory() = default;

	[[nodiscard]] virtual std::unique_ptr<SessionBoundKeyCreator> create(
		DcKeyRequest request,
		SessionAuthKeyDelegate delegate) = 0;
};

[[nodiscard]] SessionAuthKeyFactory &DefaultSessionAuthKeyFactory();

} // namespace MTP::details
