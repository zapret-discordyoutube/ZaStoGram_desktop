/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#pragma once

#include "mtproto/dc_id.h"
#include "mtproto/protocol/mtproto_response.h"
#include "mtproto/protocol/mtproto_serialized_request.h"
#include "base/flat_map.h"

#include <QtCore/QMutex>
#include <QtCore/QReadWriteLock>

#include <deque>
#include <map>
#include <optional>
#include <vector>

namespace MTP::details {

class RequestRegistry final {
public:
	enum class DependencyAction {
		SendNow,
		Wait,
	};

	struct DependentRequest {
		mtpRequestId requestId = 0;
		ShiftedDcId dcWithShift = 0;
		SerializedRequest request;
	};

	struct DelayedRequest {
		mtpRequestId requestId = 0;
		std::optional<ShiftedDcId> dcWithShift;
		SerializedRequest request;
	};

	struct UnregisteredRequest {
		SerializedRequest request;
		std::vector<DependentRequest> dependentRequests;
	};

	struct CancelledRequest {
		std::optional<ShiftedDcId> dcWithShift;
		SerializedRequest request;
		mtpMsgId msgId = 0;
		std::vector<DependentRequest> dependentRequests;
	};

	void storeRequest(
		mtpRequestId requestId,
		const SerializedRequest &request,
		ResponseHandler &&callbacks);
	void registerRequest(mtpRequestId requestId, ShiftedDcId shiftedDcId);
	[[nodiscard]] std::optional<ShiftedDcId> queryDc(
		mtpRequestId requestId) const;
	[[nodiscard]] std::optional<ShiftedDcId> changeDc(
		mtpRequestId requestId,
		DcId newdc);
	[[nodiscard]] SerializedRequest request(mtpRequestId requestId) const;
	[[nodiscard]] bool hasCallback(mtpRequestId requestId) const;
	[[nodiscard]] ResponseHandler takeCallback(mtpRequestId requestId);
	void restoreCallback(
		mtpRequestId requestId,
		ResponseHandler &&callbacks);
	[[nodiscard]] UnregisteredRequest unregisterRequest(
		mtpRequestId requestId);
	[[nodiscard]] DependencyAction prepareDependency(
		mtpRequestId requestId,
		const SerializedRequest &request,
		mtpRequestId afterRequestId);
	void addDependency(mtpRequestId requestId, mtpRequestId afterRequestId);
	[[nodiscard]] int nextBackoffSeconds(mtpRequestId requestId);
	[[nodiscard]] bool scheduleDelayed(
		mtpRequestId requestId,
		crl::time sendAt);
	[[nodiscard]] std::vector<DelayedRequest> takeReadyDelayed(crl::time now);
	[[nodiscard]] std::optional<crl::time> nextDelayedAt() const;
	[[nodiscard]] CancelledRequest cancel(mtpRequestId requestId);

private:
	[[nodiscard]] std::vector<DependentRequest> unregisterRequestUnchecked(
		mtpRequestId requestId);

	std::map<mtpRequestId, ShiftedDcId> _requestsByDc;
	mutable QMutex _requestByDcLock;

	std::map<mtpRequestId, ResponseHandler> _parserMap;
	mutable QMutex _parserMapLock;

	std::map<mtpRequestId, SerializedRequest> _requestMap;
	mutable QReadWriteLock _requestMapLock;

	std::deque<std::pair<mtpRequestId, crl::time>> _delayedRequests;
	base::flat_map<mtpRequestId, mtpRequestId> _dependentRequests;
	mutable QMutex _dependentRequestsLock;

	std::map<mtpRequestId, int> _requestsDelays;

};

} // namespace MTP::details
