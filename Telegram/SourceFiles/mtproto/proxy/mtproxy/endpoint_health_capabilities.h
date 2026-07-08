/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#pragma once

#include "base/basic_types.h"
#include "mtproto/proxy/mtproxy/endpoint_health_state.h"

namespace MTP {

class RuntimeEnvironment;

namespace details::MtProxy {

void NoteCapabilityMtproxyFailure(
	not_null<RuntimeEnvironment*> runtime,
	const EndpointId &endpoint,
	const QString &diagnostic);
void NoteCapabilityMtproxyRelayFailure(
	not_null<RuntimeEnvironment*> runtime,
	const CapabilityFailure &failure);
void NoteCapabilityMtproxySuccess(
	not_null<RuntimeEnvironment*> runtime,
	const CapabilitySuccess &success);

} // namespace details::MtProxy
} // namespace MTP
