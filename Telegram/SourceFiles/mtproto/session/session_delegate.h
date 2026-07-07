/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#pragma once

#include "mtproto/protocol/mtproto_response.h"
#include "mtproto/dc_id.h"
#include "rpl/producer.h"

#include <memory>

namespace MTP {

class DcOptions;
class AuthKey;
class RuntimeEnvironment;
using AuthKeyPtr = std::shared_ptr<AuthKey>;

namespace details {

class SessionDelegate {
public:
	virtual ~SessionDelegate() = default;

	[[nodiscard]] virtual DcId mainDcId() const = 0;
	[[nodiscard]] virtual QString systemLangCode() const = 0;
	[[nodiscard]] virtual QString cloudLangCode() const = 0;
	[[nodiscard]] virtual QString langPackName() const = 0;
	[[nodiscard]] virtual DcOptions &dcOptions() const = 0;
	[[nodiscard]] virtual RuntimeEnvironment &runtimeEnvironment() const = 0;
	[[nodiscard]] virtual bool isTestMode() const = 0;
	[[nodiscard]] virtual bool isKeysDestroyer() const = 0;
	[[nodiscard]] virtual QString deviceModel() const = 0;
	[[nodiscard]] virtual QString systemVersion() const = 0;
	[[nodiscard]] virtual rpl::producer<DcId> dcTemporaryKeyChanged() const = 0;
	[[nodiscard]] virtual bool hasCallback(mtpRequestId requestId) const = 0;

	virtual void dcPersistentKeyChanged(
		DcId dcId,
		const AuthKeyPtr &persistentKey) = 0;
	virtual void dcTemporaryKeyChanged(DcId dcId) = 0;
	virtual void onStateChange(ShiftedDcId shiftedDcId, int32 state) = 0;
	virtual void onSessionReset(ShiftedDcId shiftedDcId) = 0;
	virtual void processCallback(const Response &response) = 0;
	virtual void processUpdate(const Response &message) = 0;
	virtual void requestConfig() = 0;
	virtual void requestConfigIfOld() = 0;
	virtual void requestCDNConfig() = 0;
	virtual void badConfigurationError() = 0;
	virtual void restartedByTimeout(ShiftedDcId shiftedDcId) = 0;
	virtual void keyWasPossiblyDestroyed(ShiftedDcId shiftedDcId) = 0;
	virtual void keyDestroyedOnServer(ShiftedDcId shiftedDcId, uint64 keyId) = 0;
	virtual void proxyMigrationSucceeded(uint64 generation) = 0;

};

} // namespace details
} // namespace MTP
