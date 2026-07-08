/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "mtproto/instance/request_registry.h"

#include "base/flat_set.h"

namespace MTP::details {

void RequestRegistry::storeRequest(
		mtpRequestId requestId,
		const SerializedRequest &request,
		ResponseHandler &&callbacks) {
	if (callbacks.done || callbacks.fail) {
		QMutexLocker locker(&_parserMapLock);
		_parserMap.emplace(requestId, std::move(callbacks));
	}
	{
		QWriteLocker locker(&_requestMapLock);
		_requestMap.emplace(requestId, request);
	}
}

void RequestRegistry::registerRequest(
		mtpRequestId requestId,
		ShiftedDcId shiftedDcId) {
	QMutexLocker locker(&_requestByDcLock);
	_requestsByDc[requestId] = shiftedDcId;
}

std::optional<ShiftedDcId> RequestRegistry::queryDc(
		mtpRequestId requestId) const {
	QMutexLocker locker(&_requestByDcLock);
	const auto it = _requestsByDc.find(requestId);
	if (it != _requestsByDc.cend()) {
		return it->second;
	}
	return std::nullopt;
}

std::optional<ShiftedDcId> RequestRegistry::changeDc(
		mtpRequestId requestId,
		DcId newdc) {
	QMutexLocker locker(&_requestByDcLock);
	const auto it = _requestsByDc.find(requestId);
	if (it != _requestsByDc.cend()) {
		if (it->second < 0) {
			it->second = -newdc;
		} else {
			it->second = ShiftDcId(newdc, GetDcIdShift(it->second));
		}
		return it->second;
	}
	return std::nullopt;
}

SerializedRequest RequestRegistry::request(mtpRequestId requestId) const {
	QReadLocker locker(&_requestMapLock);
	const auto it = _requestMap.find(requestId);
	return (it != _requestMap.cend()) ? it->second : SerializedRequest();
}

bool RequestRegistry::hasCallback(mtpRequestId requestId) const {
	QMutexLocker locker(&_parserMapLock);
	const auto it = _parserMap.find(requestId);
	return (it != _parserMap.cend());
}

ResponseHandler RequestRegistry::takeCallback(mtpRequestId requestId) {
	auto result = ResponseHandler();
	QMutexLocker locker(&_parserMapLock);
	const auto it = _parserMap.find(requestId);
	if (it != _parserMap.cend()) {
		result = std::move(it->second);
		_parserMap.erase(it);
	}
	return result;
}

void RequestRegistry::restoreCallback(
		mtpRequestId requestId,
		ResponseHandler &&callbacks) {
	if (callbacks.done || callbacks.fail) {
		QMutexLocker locker(&_parserMapLock);
		_parserMap.emplace(requestId, std::move(callbacks));
	}
}

std::vector<RequestRegistry::DependentRequest>
RequestRegistry::unregisterRequest(mtpRequestId requestId) {
	_requestsDelays.erase(requestId);

	{
		QWriteLocker locker(&_requestMapLock);
		_requestMap.erase(requestId);
	}
	{
		QMutexLocker locker(&_requestByDcLock);
		_requestsByDc.erase(requestId);
	}
	return unregisterRequestUnchecked(requestId);
}

RequestRegistry::DependencyAction RequestRegistry::prepareDependency(
		mtpRequestId requestId,
		const SerializedRequest &request,
		mtpRequestId afterRequestId) {
	request->after = this->request(afterRequestId);
	if (!request->after) {
		return DependencyAction::SendNow;
	}

	QMutexLocker locker(&_dependentRequestsLock);
	const auto i = _dependentRequests.find(afterRequestId);
	if (i != _dependentRequests.end()) {
		_dependentRequests.emplace(requestId, afterRequestId);
		return DependencyAction::Wait;
	}
	return DependencyAction::SendNow;
}

void RequestRegistry::addDependency(
		mtpRequestId requestId,
		mtpRequestId afterRequestId) {
	QMutexLocker locker(&_dependentRequestsLock);
	_dependentRequests.emplace(requestId, afterRequestId);
}

int RequestRegistry::nextBackoffSeconds(mtpRequestId requestId) {
	const auto it = _requestsDelays.find(requestId);
	if (it != _requestsDelays.cend()) {
		return (it->second > 60) ? it->second : (it->second *= 2);
	}
	_requestsDelays.emplace(requestId, 1);
	return 1;
}

bool RequestRegistry::scheduleDelayed(
		mtpRequestId requestId,
		crl::time sendAt) {
	auto it = _delayedRequests.begin();
	const auto e = _delayedRequests.end();
	for (; it != e; ++it) {
		if (it->first == requestId) {
			return false;
		} else if (it->second > sendAt) {
			break;
		}
	}
	_delayedRequests.insert(it, std::make_pair(requestId, sendAt));
	return true;
}

std::vector<RequestRegistry::DelayedRequest> RequestRegistry::takeReadyDelayed(
		crl::time now) {
	auto result = std::vector<DelayedRequest>();
	while (!_delayedRequests.empty() && now >= _delayedRequests.front().second) {
		const auto requestId = _delayedRequests.front().first;
		_delayedRequests.pop_front();

		result.push_back({
			.requestId = requestId,
			.dcWithShift = queryDc(requestId),
			.request = request(requestId),
		});
	}
	return result;
}

std::optional<crl::time> RequestRegistry::nextDelayedAt() const {
	if (_delayedRequests.empty()) {
		return std::nullopt;
	}
	return _delayedRequests.front().second;
}

RequestRegistry::CancelledRequest RequestRegistry::cancel(
		mtpRequestId requestId) {
	auto result = CancelledRequest();
	result.dcWithShift = queryDc(requestId);
	{
		QWriteLocker locker(&_requestMapLock);
		const auto it = _requestMap.find(requestId);
		if (it != _requestMap.end()) {
			result.msgId = it->second.getMsgId();
			_requestMap.erase(it);
		}
	}
	result.dependentRequests = unregisterRequest(requestId);

	QMutexLocker locker(&_parserMapLock);
	_parserMap.erase(requestId);

	return result;
}

std::vector<RequestRegistry::DependentRequest>
RequestRegistry::unregisterRequestUnchecked(mtpRequestId requestId) {
	auto toRemove = base::flat_set<mtpRequestId>();
	auto toResend = base::flat_set<mtpRequestId>();

	toRemove.emplace(requestId);

	{
		QMutexLocker locker(&_dependentRequestsLock);
		auto handling = 0;
		do {
			handling = toResend.size();
			for (const auto &[resendingId, afterId] : _dependentRequests) {
				if (toRemove.contains(afterId)) {
					toRemove.emplace(resendingId);
					toResend.emplace(resendingId);
				}
			}
		} while (handling != toResend.size());

		for (const auto removingId : toRemove) {
			_dependentRequests.remove(removingId);
		}
	}

	auto result = std::vector<DependentRequest>();
	result.reserve(toResend.size());
	for (const auto resendingId : toResend) {
		if (const auto shiftedDcId = queryDc(resendingId)) {
			result.push_back({
				.requestId = resendingId,
				.dcWithShift = *shiftedDcId,
				.request = request(resendingId),
			});
		}
	}
	return result;
}

} // namespace MTP::details
