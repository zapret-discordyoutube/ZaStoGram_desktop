/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "mtproto/proxy/mtproxy/tls_socket_psk.h"

#include "base/random.h"

#include <QtCore/QMutex>

#include <algorithm>
#include <array>
#include <map>
#include <vector>

namespace MTP::details {
namespace {

constexpr auto kSyntheticPskPoolSize = 3;
constexpr auto kSyntheticPskMinLifetime = crl::time(2 * 60 * 60 * 1000);
constexpr auto kSyntheticPskMaxLifetime = crl::time(8 * 60 * 60 * 1000);

struct SyntheticPskTicket {
	bytes::vector identity;
	uint32 ticketAgeAdd = 0;
	crl::time issuedAt = 0;
	crl::time expiresAt = 0;
	int binderLength = 0;
};

struct SyntheticPskCacheEntry {
	std::vector<SyntheticPskTicket> tickets;
	int nextIndex = 0;
};

QMutex SyntheticPskCacheMutex;
std::map<QString, SyntheticPskCacheEntry> SyntheticPskCache;

[[nodiscard]] uint32 RandomUint32() {
	auto result = uint32();
	bytes::set_random(bytes::object_as_span(&result));
	return result;
}

[[nodiscard]] QString SyntheticPskCacheKey(
		const QString &endpointKey,
		bytes::const_span domain,
		ProxyTlsProfile profile) {
	return endpointKey
		+ u"|"_q
		+ QString::number(int(profile))
		+ u"|"_q
		+ QString::fromLatin1(QByteArray(
			reinterpret_cast<const char*>(domain.data()),
			int(domain.size())).toHex());
}

[[nodiscard]] SyntheticPskTicket MakeSyntheticPskTicket(crl::time now) {
	const auto identityLengths = std::array{ 32, 105, 256 };
	const auto binderLengths = std::array{ 32, 48 };
	const auto identityLength = identityLengths[
		base::RandomIndex(identityLengths.size())];
	const auto binderLength = binderLengths[
		base::RandomIndex(binderLengths.size())];
	const auto lifetimeRange = int(
		kSyntheticPskMaxLifetime - kSyntheticPskMinLifetime + 1);
	auto result = SyntheticPskTicket();
	result.identity.resize(identityLength);
	bytes::set_random(result.identity);
	result.ticketAgeAdd = RandomUint32();
	result.issuedAt = now;
	result.expiresAt = now
		+ kSyntheticPskMinLifetime
		+ base::RandomIndex(lifetimeRange);
	result.binderLength = binderLength;
	return result;
}

void DropExpiredSyntheticPskTickets(
		SyntheticPskCacheEntry &entry,
		crl::time now) {
	for (auto i = entry.tickets.begin(); i != entry.tickets.end();) {
		if (i->expiresAt <= now) {
			i = entry.tickets.erase(i);
		} else {
			++i;
		}
	}
	if (entry.tickets.empty()) {
		entry.nextIndex = 0;
	} else if (entry.nextIndex >= int(entry.tickets.size())) {
		entry.nextIndex = 0;
	}
}

} // namespace

[[nodiscard]] std::optional<SyntheticPskOffer> PrepareSyntheticPskOffer(
		const QString &endpointKey,
		bytes::const_span domain,
		ProxyTlsProfile profile) {
	if (endpointKey.isEmpty() || domain.empty()) {
		return std::nullopt;
	}
	const auto now = crl::now();
	const auto key = SyntheticPskCacheKey(endpointKey, domain, profile);
	QMutexLocker lock(&SyntheticPskCacheMutex);
	const auto i = SyntheticPskCache.find(key);
	if (i == end(SyntheticPskCache)) {
		return std::nullopt;
	}
	auto &entry = i->second;
	DropExpiredSyntheticPskTickets(entry, now);
	if (entry.tickets.empty()) {
		SyntheticPskCache.erase(i);
		return std::nullopt;
	}
	const auto index = entry.nextIndex;
	const auto ticket = entry.tickets[index];
	entry.tickets.erase(entry.tickets.begin() + index);
	if (entry.tickets.empty()) {
		SyntheticPskCache.erase(i);
	} else if (entry.nextIndex >= int(entry.tickets.size())) {
		entry.nextIndex = 0;
	}
	const auto age = std::max(crl::time(0), now - ticket.issuedAt);
	return SyntheticPskOffer{
		.identity = ticket.identity,
		.obfuscatedTicketAge = uint32(
			uint64(ticket.ticketAgeAdd) + uint64(age)),
		.binderLength = ticket.binderLength,
	};
}

void ClearSyntheticPskTickets(
		const QString &endpointKey,
		bytes::const_span domain,
		ProxyTlsProfile profile) {
	if (endpointKey.isEmpty() || domain.empty()) {
		return;
	}
	const auto key = SyntheticPskCacheKey(endpointKey, domain, profile);
	QMutexLocker lock(&SyntheticPskCacheMutex);
	SyntheticPskCache.erase(key);
}

void NoteSyntheticPskDataPathSuccess(
		const QString &endpointKey,
		bytes::const_span domain,
		ProxyTlsProfile profile) {
	if (endpointKey.isEmpty() || domain.empty()) {
		return;
	}
	const auto now = crl::now();
	const auto key = SyntheticPskCacheKey(endpointKey, domain, profile);
	QMutexLocker lock(&SyntheticPskCacheMutex);
	auto &entry = SyntheticPskCache[key];
	DropExpiredSyntheticPskTickets(entry, now);
	while (int(entry.tickets.size()) < kSyntheticPskPoolSize) {
		entry.tickets.push_back(MakeSyntheticPskTicket(now));
	}
	if (entry.nextIndex >= int(entry.tickets.size())) {
		entry.nextIndex = 0;
	}
}

} // namespace MTP::details
