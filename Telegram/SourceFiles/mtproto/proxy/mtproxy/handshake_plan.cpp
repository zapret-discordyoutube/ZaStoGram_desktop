/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "mtproto/proxy/mtproxy/handshake_plan.h"

#include "mtproto/proxy/mtproxy/client_hello_profile.h"

namespace MTP::details::MtProxy {
namespace {

// A proxy behind a slow or congested link needs more than a couple of
// seconds to relay the ServerHello back; cutting the attempt off early only
// burns another handshake against the same box.
constexpr auto kServerHelloTimeout = crl::time(5000);

} // namespace

MtProxyAttemptPlan MakeAttemptPlan(const ProxyStealthOptions &stealth) {
	// The two auto entries are names for "whatever the client defaults to",
	// so they resolve to a concrete template here - the plan is what the
	// diagnostics report as the profile that was actually sent. A withheld
	// fingerprint resolves away as well, including one a user selected before
	// it was measured as refused.
	const auto effective = EffectiveClientHelloProfile(stealth.tlsProfile);
	auto planned = stealth;
	planned.tlsProfile = effective;
	return {
		.admitted = true,
		.configuredTlsProfile = stealth.tlsProfile,
		.effectiveTlsProfile = effective,
		.stealth = planned,
		.serverHelloTimeout = kServerHelloTimeout,
	};
}

crl::time ConnectionSpacing(ProxyConnectionPattern pattern) {
	switch (pattern) {
	case ProxyConnectionPattern::Soft: return crl::time(150);
	case ProxyConnectionPattern::Quiet: return crl::time(400);
	case ProxyConnectionPattern::Strict: return crl::time(700);
	case ProxyConnectionPattern::Browser: return crl::time(250);
	case ProxyConnectionPattern::Off: break;
	}
	return crl::time(0);
}

} // namespace MTP::details::MtProxy
