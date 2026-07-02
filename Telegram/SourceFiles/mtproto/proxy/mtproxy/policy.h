/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#pragma once

#include "mtproto/proxy/data.h"

namespace MTP::details {

[[nodiscard]] crl::time MtproxyConnectionSpacing(
	ProxyConnectionPattern pattern);

[[nodiscard]] int MtproxyEndpointCooldown(const QString &endpointKey);
void MtproxyNoteEndpointFailure(
	const QString &endpointKey,
	const QString &diagnostic);
void MtproxyNoteEndpointSuccess(const QString &endpointKey);

[[nodiscard]] ProxyTlsProfile MtproxyRotateTlsProfileOnFailure(
	const QString &endpointKey,
	const QString &diagnostic,
	ProxyTlsProfile previous);

}
