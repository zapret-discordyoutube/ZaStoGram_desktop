/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#pragma once

#include "mtproto/core_types.h"
#include "mtproto/protocol/mtproto_serialized_request.h"
#include "mtproto/protocol/mtproto_response.h"

#include <QtCore/QObject>

namespace MTP {

namespace details {

class Dcenter;
class Session;

[[nodiscard]] int GetNextRequestId();

} // namespace details

class DcOptions;
class ConnectionStatus;
class Config;
struct ConfigFields;
class AuthKey;
class RuntimeEnvironment;
using AuthKeyPtr = std::shared_ptr<AuthKey>;
using AuthKeysList = std::vector<AuthKeyPtr>;
enum class Environment : uchar;

class Instance : public QObject {
	Q_OBJECT

public:
	struct Fields {
		Fields();
		Fields(Fields &&other);
		Fields &operator=(Fields &&other);
		~Fields();

		static constexpr auto kNoneMainDc = -1;
		static constexpr auto kNotSetMainDc = 0;
		static constexpr auto kDefaultMainDc = 2;
		static constexpr auto kTemporaryMainDc = kTemporaryMainDcId;

		std::unique_ptr<Config> config;
		std::shared_ptr<RuntimeEnvironment> runtimeEnvironment;
		DcId mainDcId = kNotSetMainDc;
		AuthKeysList keys;
		QString deviceModel;
		QString systemVersion;
	};

	enum class Mode {
		Normal,
		KeysDestroyer,
	};

	Instance(Mode mode, Fields &&fields);
	Instance(const Instance &other) = delete;
	Instance &operator=(const Instance &other) = delete;
	~Instance();

	void suggestMainDcId(DcId mainDcId);
	void setMainDcId(DcId mainDcId);
	[[nodiscard]] DcId mainDcId() const;
	[[nodiscard]] rpl::producer<DcId> mainDcIdValue() const;

	[[nodiscard]] rpl::producer<> writeKeysRequests() const;
	[[nodiscard]] rpl::producer<> allKeysDestroyed() const;

	// Thread-safe.
	[[nodiscard]] Config &config() const;
	[[nodiscard]] const ConfigFields &configValues() const;
	[[nodiscard]] DcOptions &dcOptions() const;
	[[nodiscard]] Environment environment() const;
	[[nodiscard]] bool isTestMode() const;
	[[nodiscard]] RuntimeEnvironment &runtimeEnvironment() const;
	[[nodiscard]] QString deviceModel() const;
	[[nodiscard]] QString systemVersion() const;

	[[nodiscard]] AuthKeysList getKeysForWrite() const;
	void addKeysForDestroy(AuthKeysList &&keys);

	// Main thread.
	void restart();
	void restart(ShiftedDcId shiftedDcId);
	void migrateProxy();
	int32 dcstate(ShiftedDcId shiftedDcId = 0);
	QString dctransport(ShiftedDcId shiftedDcId = 0);
	[[nodiscard]] ConnectionStatus &connectionStatus() const;
	void ping();
	void cancel(mtpRequestId requestId);
	int32 state(mtpRequestId requestId); // < 0 means waiting for such count of ms

	void killSession(ShiftedDcId shiftedDcId);
	void stopSession(ShiftedDcId shiftedDcId);
	void reInitConnection(DcId dcId);
	void logout(Fn<void()> done);

	void setUpdatesHandler(Fn<void(const Response&)> handler);
	void setGlobalFailHandler(
		Fn<void(const Error&, const Response&)> handler);
	void setStateChangedHandler(
		Fn<void(ShiftedDcId shiftedDcId, int32 state)> handler);
	void setSessionResetHandler(Fn<void(ShiftedDcId shiftedDcId)> handler);
	void clearGlobalHandlers();

	// Thread-safe.
	bool isKeysDestroyer() const;

	void requestConfig();
	void requestConfigIfOld();
	void requestCDNConfig();
	void setUserPhone(const QString &phone);

	[[nodiscard]] rpl::producer<ShiftedDcId> restartsByTimeout() const;

	[[nodiscard]] auto nonPremiumDelayedRequests() const
		-> rpl::producer<mtpRequestId>;
	[[nodiscard]] rpl::producer<> frozenErrorReceived() const;

	void syncHttpUnixtime();

	void sendAnything(ShiftedDcId shiftedDcId = 0, crl::time msCanWait = 0);

	template <typename Request>
	mtpRequestId send(
			const Request &request,
			ResponseHandler &&callbacks = {},
			ShiftedDcId shiftedDcId = 0,
			crl::time msCanWait = 0,
			mtpRequestId afterRequestId = 0,
			mtpRequestId overrideRequestId = 0) {
		const auto requestId = overrideRequestId
			? overrideRequestId
			: details::GetNextRequestId();
		sendSerialized(
			requestId,
			details::SerializedRequest::Serialize(request),
			std::move(callbacks),
			shiftedDcId,
			msCanWait,
			afterRequestId);
		return requestId;
	}

	template <typename Request>
	mtpRequestId send(
			const Request &request,
			DoneHandler &&onDone,
			FailHandler &&onFail = nullptr,
			ShiftedDcId shiftedDcId = 0,
			crl::time msCanWait = 0,
			mtpRequestId afterRequestId = 0,
			mtpRequestId overrideRequestId = 0) {
		return send(
			request,
			ResponseHandler{ std::move(onDone), std::move(onFail) },
			shiftedDcId,
			msCanWait,
			afterRequestId,
			overrideRequestId);
	}

	template <typename Request>
	mtpRequestId sendProtocolMessage(
			ShiftedDcId shiftedDcId,
			const Request &request) {
		const auto requestId = details::GetNextRequestId();
		sendRequest(
			requestId,
			details::SerializedRequest::Serialize(request),
			{},
			shiftedDcId,
			0,
			false,
			0);
		return requestId;
	}

	void sendSerialized(
			mtpRequestId requestId,
			details::SerializedRequest &&request,
			ResponseHandler &&callbacks,
			ShiftedDcId shiftedDcId,
			crl::time msCanWait,
			mtpRequestId afterRequestId) {
		const auto needsLayer = true;
		sendRequest(
			requestId,
			std::move(request),
			std::move(callbacks),
			shiftedDcId,
			msCanWait,
			needsLayer,
			afterRequestId);
	}

	[[nodiscard]] rpl::lifetime &lifetime();

Q_SIGNALS:
	void proxyDomainResolved(
		QString host,
		QStringList ips,
		qint64 expireAt);

private:
	void sendRequest(
		mtpRequestId requestId,
		details::SerializedRequest &&request,
		ResponseHandler &&callbacks,
		ShiftedDcId shiftedDcId,
		crl::time msCanWait,
		bool needsLayer,
		mtpRequestId afterRequestId);

	class Private;
	const std::unique_ptr<Private> _private;

};

} // namespace MTP
