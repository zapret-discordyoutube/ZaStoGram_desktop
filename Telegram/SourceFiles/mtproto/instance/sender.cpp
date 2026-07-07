/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "mtproto/instance/sender.h"

#include "mtproto/instance/mtp_instance.h"

namespace MTP {

Sender::Sender(not_null<Instance*> instance) noexcept
: _instance(instance) {
}

Instance &Sender::instance() const {
	return *_instance;
}

mtpRequestId Sender::sendSerializedRequest(
		details::SerializedRequest &&request,
		ResponseHandler &&callbacks,
		ShiftedDcId shiftedDcId,
		crl::time msCanWait,
		mtpRequestId afterRequestId,
		mtpRequestId overrideRequestId) {
	const auto requestId = overrideRequestId
		? overrideRequestId
		: details::GetNextRequestId();
	_instance->sendSerialized(
		requestId,
		std::move(request),
		std::move(callbacks),
		shiftedDcId,
		msCanWait,
		afterRequestId);
	return requestId;
}

void Sender::sendAnything() {
	_instance->sendAnything();
}

void Sender::cancelRequest(mtpRequestId requestId) {
	_instance->cancel(requestId);
}

} // namespace MTP
