/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "mtproto/proxy/mtproxy/policy.h"

#include "mtproto/proxy/mtproxy/adaptive_policy.h"

namespace MTP::details {

crl::time MtproxyConnectionSpacing(ProxyConnectionPattern pattern) {
	switch (pattern) {
	case ProxyConnectionPattern::Soft: return crl::time(150);
	case ProxyConnectionPattern::Quiet: return crl::time(400);
	case ProxyConnectionPattern::Strict: return crl::time(700);
	case ProxyConnectionPattern::Browser: return crl::time(250);
	case ProxyConnectionPattern::Off: break;
	}
	return crl::time(0);
}

int MtproxyEndpointCooldown(const QString &endpointKey) {
	return CooldownMsForEndpoint(endpointKey);
}

void MtproxyNoteEndpointFailure(
		const QString &endpointKey,
		const QString &diagnostic) {
	NoteEndpointFailure(endpointKey, diagnostic);
}

void MtproxyNoteEndpointSuccess(const QString &endpointKey) {
	NoteEndpointSuccess(endpointKey);
}

ProxyTlsProfile MtproxyRotateTlsProfileOnFailure(
		const QString &endpointKey,
		const QString &diagnostic,
		ProxyTlsProfile previous) {
	return RotateTlsProfileOnFailure(endpointKey, diagnostic, previous);
}

}
