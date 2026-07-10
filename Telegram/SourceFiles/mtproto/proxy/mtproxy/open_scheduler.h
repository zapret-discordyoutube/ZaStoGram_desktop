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

class OpenSlotReservation final {
public:
	OpenSlotReservation() = default;
	OpenSlotReservation(const OpenSlotReservation &other) = delete;
	OpenSlotReservation &operator=(const OpenSlotReservation &other) = delete;
	OpenSlotReservation(OpenSlotReservation &&other) noexcept;
	OpenSlotReservation &operator=(OpenSlotReservation &&other) noexcept;
	~OpenSlotReservation();

	void commit();
	void cancel();
	[[nodiscard]] crl::time delay() const;

private:
	friend class OpenScheduler;

	explicit OpenSlotReservation(crl::time delay);
	OpenSlotReservation(
		std::shared_ptr<ProxyEndpointContext> context,
		QString key,
		uint64 id,
		crl::time openAt,
		crl::time nextOpenAt,
		crl::time delay);

	std::shared_ptr<ProxyEndpointContext> _context;
	QString _key;
	uint64 _id = 0;
	crl::time _openAt = 0;
	crl::time _nextOpenAt = 0;
	crl::time _delay = 0;

};

class OpenScheduler final {
public:
	explicit OpenScheduler(const RuntimeAsyncGateway &async);
	explicit OpenScheduler(not_null<RuntimeEnvironment*> runtime);

	[[nodiscard]] OpenSlotReservation ReserveOpenSlot(
		const EndpointId &endpoint,
		ProxyConnectionPattern pattern,
		crl::time notBefore = 0);

private:
	RuntimeAsyncGateway _async;
	std::shared_ptr<ProxyEndpointContext> _context;

};

[[nodiscard]] crl::time OpenConnectionSpacing(ProxyConnectionPattern pattern);
[[nodiscard]] OpenSlotReservation ReserveOpenSlot(
	not_null<RuntimeEnvironment*> runtime,
	const EndpointId &endpoint,
	ProxyConnectionPattern pattern,
	crl::time notBefore = 0);

// Failure-driven pacing feedback, independent of the stealth pattern:
// connect timeouts grow a per-endpoint spacing floor for new opens,
// successes shrink it back to zero. A proxy that throttles bursts of
// new connections gets approached gently instead of hammered by every
// reconnecting session at once.
void NoteConnectTimeout(
	not_null<RuntimeEnvironment*> runtime,
	const EndpointId &endpoint);
void NoteConnectSuccess(
	not_null<RuntimeEnvironment*> runtime,
	const EndpointId &endpoint);

} // namespace MTP::details::MtProxy
