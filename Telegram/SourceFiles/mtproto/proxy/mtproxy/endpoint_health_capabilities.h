/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#pragma once

#include "mtproto/proxy/mtproxy/endpoint_health_state.h"

namespace MTP::details::MtProxy {

void NoteCapabilityMtproxyFailure(
	const EndpointId &endpoint,
	const QString &diagnostic);
void NoteCapabilityMtproxyRelayFailure(const CapabilityFailure &failure);
void NoteCapabilityMtproxySuccess(const CapabilitySuccess &success);

} // namespace MTP::details::MtProxy
