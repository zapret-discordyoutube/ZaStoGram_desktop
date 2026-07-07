/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#pragma once

#include "mtproto/proxy/mtproxy/client_hello_builder.h"

namespace MTP::details {

[[nodiscard]] std::optional<SyntheticPskOffer> PrepareSyntheticPskOffer(
	const QString &endpointKey,
	bytes::const_span domain,
	ProxyTlsProfile profile);

void ClearSyntheticPskTickets(
	const QString &endpointKey,
	bytes::const_span domain,
	ProxyTlsProfile profile);

void NoteSyntheticPskDataPathSuccess(
	const QString &endpointKey,
	bytes::const_span domain,
	ProxyTlsProfile profile);

} // namespace MTP::details
