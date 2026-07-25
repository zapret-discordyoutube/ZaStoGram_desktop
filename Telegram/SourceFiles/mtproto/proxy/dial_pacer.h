/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#pragma once

#include "base/basic_types.h"
#include "mtproto/proxy/data.h"

#include <crl/crl_time.h>

namespace MTP {

class RuntimeEnvironment;

namespace details {

// Paces outgoing connection attempts towards a single proxy server.
//
// Every session dials on its own, so a cold start or a proxy switch makes
// every session of every account open its socket in the same millisecond.
// A public mtproxy answers the first couple of handshakes and silently
// drops the rest, which the client then reads as
// client_hello_sent_no_server_hello or connected_no_mtproto_data across the
// whole batch.
//
// A lease is taken when a connection is created and lives until the attempt
// either proves the relay or dies, so the limit counts unproven handshakes
// and not established connections: a steady state of many live sessions is
// fine, only the burst is spread out. A dial that would exceed the limit
// waits for a slot to come back rather than for a fixed spacing, which turns
// a batch of sessions into a ramp: each one that Telegram answers through
// hands its slot to the next immediately.
//
// A run of attempts that never proved anything also stretches the spacing,
// which is the only thing standing between a blackholed proxy and every
// session redialing it on its own eight second retry timer. This is a rate
// limiter and nothing more: it does not mark endpoints unhealthy, does not
// pick proxies and never touches the handshake shape.
class ProxyDialLease final {
public:
	ProxyDialLease() = default;
	ProxyDialLease(const ProxyDialLease &other) = delete;
	ProxyDialLease &operator=(const ProxyDialLease &other) = delete;
	ProxyDialLease(ProxyDialLease &&other) noexcept;
	ProxyDialLease &operator=(ProxyDialLease &&other) noexcept;
	~ProxyDialLease();

	// How long the caller must wait before starting the attempt.
	[[nodiscard]] crl::time delay() const;

	// The proxy relayed a Telegram reply through this attempt.
	void proven();

	// The attempt is over without having proved anything.
	void release();

	// The attempt is being dropped for a reason of ours - it lost a route
	// race, or the proxy was switched under it. The slot comes back, but the
	// proxy did nothing wrong and is not moved towards the failure spacing.
	void cancel();

private:
	friend ProxyDialLease ReserveProxyDial(
		not_null<RuntimeEnvironment*> runtime,
		const ProxyData &proxy);

	ProxyDialLease(QString key, crl::time delay, crl::time until);

	enum class Verdict {
		Proven,
		Failed,
		Cancelled,
	};
	void finish(Verdict verdict);

	QString _key;
	crl::time _delay = 0;
	crl::time _until = 0;

};

// Direct connections are never paced, so for them this returns an empty
// lease with a zero delay.
[[nodiscard]] ProxyDialLease ReserveProxyDial(
	not_null<RuntimeEnvironment*> runtime,
	const ProxyData &proxy);

} // namespace details
} // namespace MTP
