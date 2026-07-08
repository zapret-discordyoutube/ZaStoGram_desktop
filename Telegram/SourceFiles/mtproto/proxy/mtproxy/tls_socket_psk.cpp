/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "mtproto/proxy/mtproxy/tls_socket_psk.h"

#include "base/random.h"

#include <algorithm>
#include <array>

namespace MTP::details {
namespace {

constexpr auto kSyntheticPskPoolSize = 3;
constexpr auto kSyntheticPskMinLifetime = crl::time(2 * 60 * 60 * 1000);
constexpr auto kSyntheticPskMaxLifetime = crl::time(8 * 60 * 60 * 1000);

[[nodiscard]] uint32 RandomUint32() {
	auto result = uint32();
	bytes::set_random(bytes::object_as_span(&result));
	return result;
}

} // namespace

QString SyntheticPskCache::cacheKey(
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

SyntheticPskCache::Ticket SyntheticPskCache::makeTicket(crl::time now) {
	const auto identityLengths = std::array{ 32, 105, 256 };
	const auto binderLengths = std::array{ 32, 48 };
	const auto identityLength = identityLengths[
		base::RandomIndex(identityLengths.size())];
	const auto binderLength = binderLengths[
		base::RandomIndex(binderLengths.size())];
	const auto lifetimeRange = int(
		kSyntheticPskMaxLifetime - kSyntheticPskMinLifetime + 1);
	auto result = Ticket();
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

void SyntheticPskCache::dropExpiredTickets(
		Entry &entry,
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

std::optional<SyntheticPskOffer> SyntheticPskCache::prepareOffer(
		const QString &endpointKey,
		bytes::const_span domain,
		ProxyTlsProfile profile) {
	if (endpointKey.isEmpty() || domain.empty()) {
		return std::nullopt;
	}
	const auto now = crl::now();
	const auto key = cacheKey(endpointKey, domain, profile);
	QMutexLocker lock(&_mutex);
	const auto i = _entries.find(key);
	if (i == end(_entries)) {
		return std::nullopt;
	}
	auto &entry = i->second;
	dropExpiredTickets(entry, now);
	if (entry.tickets.empty()) {
		_entries.erase(i);
		return std::nullopt;
	}
	const auto index = entry.nextIndex;
	const auto ticket = entry.tickets[index];
	entry.tickets.erase(entry.tickets.begin() + index);
	if (entry.tickets.empty()) {
		_entries.erase(i);
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

void SyntheticPskCache::clear(
		const QString &endpointKey,
		bytes::const_span domain,
		ProxyTlsProfile profile) {
	if (endpointKey.isEmpty() || domain.empty()) {
		return;
	}
	const auto key = cacheKey(endpointKey, domain, profile);
	QMutexLocker lock(&_mutex);
	_entries.erase(key);
}

void SyntheticPskCache::noteDataPathSuccess(
		const QString &endpointKey,
		bytes::const_span domain,
		ProxyTlsProfile profile) {
	if (endpointKey.isEmpty() || domain.empty()) {
		return;
	}
	const auto now = crl::now();
	const auto key = cacheKey(endpointKey, domain, profile);
	QMutexLocker lock(&_mutex);
	auto &entry = _entries[key];
	dropExpiredTickets(entry, now);
	while (int(entry.tickets.size()) < kSyntheticPskPoolSize) {
		entry.tickets.push_back(makeTicket(now));
	}
	if (entry.nextIndex >= int(entry.tickets.size())) {
		entry.nextIndex = 0;
	}
}

} // namespace MTP::details
