/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#pragma once

#include "mtproto/proxy/mtproxy/client_hello_builder.h"

#include <QtCore/QMutex>

#include <map>
#include <vector>

namespace MTP::details {

class SyntheticPskCache final {
public:
	[[nodiscard]] std::optional<SyntheticPskOffer> prepareOffer(
		const QString &endpointKey,
		bytes::const_span domain,
		ProxyTlsProfile profile);

	void clear(
		const QString &endpointKey,
		bytes::const_span domain,
		ProxyTlsProfile profile);

	void noteDataPathSuccess(
		const QString &endpointKey,
		bytes::const_span domain,
		ProxyTlsProfile profile);

private:
	struct Ticket {
		bytes::vector identity;
		uint32 ticketAgeAdd = 0;
		crl::time issuedAt = 0;
		crl::time expiresAt = 0;
		int binderLength = 0;
	};

	struct Entry {
		std::vector<Ticket> tickets;
		int nextIndex = 0;
	};

	[[nodiscard]] static QString cacheKey(
		const QString &endpointKey,
		bytes::const_span domain,
		ProxyTlsProfile profile);
	[[nodiscard]] static Ticket makeTicket(crl::time now);
	static void dropExpiredTickets(Entry &entry, crl::time now);

	QMutex _mutex;
	std::map<QString, Entry> _entries;

};

} // namespace MTP::details
