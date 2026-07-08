/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#pragma once

#include "mtproto/proxy/mtproxy/endpoint_health.h"
#include "mtproto/runtime/runtime_environment.h"

namespace MTP::details::MtProxy {

class OpenScheduler final {
public:
	explicit OpenScheduler(const RuntimeAsyncGateway &async);
	explicit OpenScheduler(not_null<RuntimeEnvironment*> runtime);

	[[nodiscard]] crl::time ReserveOpenSlot(
		const EndpointId &endpoint,
		ProxyConnectionPattern pattern,
		crl::time notBefore = 0);

private:
	RuntimeAsyncGateway _async;

};

[[nodiscard]] crl::time OpenConnectionSpacing(ProxyConnectionPattern pattern);
[[nodiscard]] crl::time ReserveOpenSlot(
	not_null<RuntimeEnvironment*> runtime,
	const EndpointId &endpoint,
	ProxyConnectionPattern pattern,
	crl::time notBefore = 0);

// Failure-driven pacing feedback, independent of the stealth pattern:
// connect timeouts grow a per-endpoint spacing floor for new opens,
// successes shrink it back to zero. A proxy that throttles bursts of
// new connections gets approached gently instead of hammered by every
// reconnecting session at once.
void NoteConnectTimeout(const EndpointId &endpoint);
void NoteConnectSuccess(const EndpointId &endpoint);

} // namespace MTP::details::MtProxy
