/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "mtproto/details/mtproto_domain_resolver.h"

#include "base/random.h"
#include "base/invoke_queued.h"
#include "base/call_delayed.h"

#include <QtCore/QJsonDocument>
#include <QtCore/QJsonArray>
#include <QtCore/QJsonObject>
#include <QtNetwork/QHostInfo>
#include <QtNetwork/QHostAddress>
#include <range/v3/algorithm/shuffle.hpp>
#include <range/v3/algorithm/reverse.hpp>
#include <range/v3/algorithm/remove.hpp>
#include <cstring>
#include <random>

namespace MTP::details {
namespace {

constexpr auto kSendNextTimeout = crl::time(800);
constexpr auto kMinTimeToLive = 10 * crl::time(1000);
constexpr auto kMaxTimeToLive = 300 * crl::time(1000);
constexpr auto kSystemDnsTimeToLive = 60 * crl::time(1000);
constexpr auto kNegativeResolveTtl = crl::time(30 * 1000);

void AppendDnsUInt16(QByteArray &bytes, uint16 value) {
	bytes.push_back(char((value >> 8) & 0xFF));
	bytes.push_back(char(value & 0xFF));
}

[[nodiscard]] bool ReadDnsUInt16(
		const QByteArray &bytes,
		int &offset,
		uint16 &value) {
	if (offset + 2 > bytes.size()) {
		return false;
	}
	const auto data = reinterpret_cast<const uchar*>(bytes.constData());
	value = (uint16(data[offset]) << 8) | uint16(data[offset + 1]);
	offset += 2;
	return true;
}

[[nodiscard]] bool ReadDnsUInt32(
		const QByteArray &bytes,
		int &offset,
		uint32 &value) {
	auto high = uint16();
	auto low = uint16();
	if (!ReadDnsUInt16(bytes, offset, high)
		|| !ReadDnsUInt16(bytes, offset, low)) {
		return false;
	}
	value = (uint32(high) << 16) | uint32(low);
	return true;
}

[[nodiscard]] bool SkipDnsName(const QByteArray &bytes, int &offset) {
	auto depth = 0;
	while (offset < bytes.size() && ++depth < 128) {
		const auto data = reinterpret_cast<const uchar*>(bytes.constData());
		const auto length = data[offset++];
		if ((length & 0xC0) == 0xC0) {
			if (offset >= bytes.size()) {
				return false;
			}
			++offset;
			return true;
		} else if (length & 0xC0) {
			return false;
		} else if (!length) {
			return true;
		} else if (offset + length > bytes.size()) {
			return false;
		}
		offset += length;
	}
	return false;
}

[[nodiscard]] QString ParseTxtData(const QByteArray &bytes) {
	auto result = QByteArray();
	auto offset = 0;
	while (offset < bytes.size()) {
		const auto length = uchar(bytes[offset++]);
		if (offset + length > bytes.size()) {
			return QString();
		}
		result.append(bytes.constData() + offset, length);
		offset += length;
	}
	return QString::fromUtf8(result);
}

[[nodiscard]] std::vector<DnsEntry> ParseDnsJsonResponse(
		const QByteArray &bytes,
		std::optional<int> typeRestriction) {
	if (bytes.isEmpty()) {
		return {};
	}

	auto error = QJsonParseError{ 0, QJsonParseError::NoError };
	const auto document = QJsonDocument::fromJson(bytes, &error);
	if (error.error != QJsonParseError::NoError) {
		LOG(("Config Error: Failed to parse dns response JSON, error: %1"
			).arg(error.errorString()));
		return {};
	} else if (!document.isObject()) {
		LOG(("Config Error: Not an object received in dns response JSON."));
		return {};
	}
	const auto response = document.object();
	const auto answerIt = response.find("Answer");
	if (answerIt == response.constEnd()) {
		LOG(("Config Error: Could not find Answer in dns response JSON."));
		return {};
	} else if (!(*answerIt).isArray()) {
		LOG(("Config Error: Not an array received "
			"in Answer in dns response JSON."));
		return {};
	}

	const auto array = (*answerIt).toArray();
	auto result = std::vector<DnsEntry>();
	for (const auto elem : array) {
		if (!elem.isObject()) {
			LOG(("Config Error: Not an object found "
				"in Answer array in dns response JSON."));
			continue;
		}
		const auto object = elem.toObject();
		if (typeRestriction) {
			const auto typeIt = object.find("type");
			if (typeIt == object.constEnd()) {
				LOG(("Config Error: Could not find type field "
					"in Answer array in dns response JSON."));
				continue;
			} else if (!(*typeIt).isDouble()) {
				LOG(("Config Error: Not a number in type field "
					"in Answer array in dns response JSON."));
				continue;
			}
			const auto type = int(base::SafeRound((*typeIt).toDouble()));
			if (type != *typeRestriction) {
				continue;
			}
		}
		const auto dataIt = object.find("data");
		if (dataIt == object.constEnd()) {
			LOG(("Config Error: Could not find data "
				"in Answer array entry in dns response JSON."));
			continue;
		} else if (!(*dataIt).isString()) {
			LOG(("Config Error: Not a string data found "
				"in Answer array entry in dns response JSON."));
			continue;
		}

		const auto ttlIt = object.find("TTL");
		const auto ttl = (ttlIt != object.constEnd())
			? crl::time(base::SafeRound((*ttlIt).toDouble()))
			: crl::time(0);
		result.push_back({ (*dataIt).toString(), ttl });
	}
	return result;
}

} // namespace

const std::vector<DohProvider> &DohProviders() {
	static const auto kResult = std::vector<DohProvider>{
		{ u"cloudflare-dns.com"_q, u"/dns-query"_q },
		{ u"dns.google"_q, u"/dns-query"_q },
		{ u"dns.quad9.net"_q, u"/dns-query"_q },
		{ u"dns.mullvad.net"_q, u"/dns-query"_q },
	};
	return kResult;
}

QByteArray BuildDnsQuery(const QString &domain, int type) {
	auto result = QByteArray();
	result.reserve(512);
	AppendDnsUInt16(result, base::RandomValue<uint16>());
	AppendDnsUInt16(result, 0x0100);
	AppendDnsUInt16(result, 1);
	AppendDnsUInt16(result, 0);
	AppendDnsUInt16(result, 0);
	AppendDnsUInt16(result, 0);
	for (const auto &label : domain.split('.', Qt::SkipEmptyParts)) {
		const auto bytes = label.toUtf8();
		if (bytes.isEmpty() || bytes.size() > 63) {
			return {};
		}
		result.push_back(char(bytes.size()));
		result.append(bytes);
	}
	result.push_back(char(0));
	AppendDnsUInt16(result, uint16(type));
	AppendDnsUInt16(result, 1);
	return result;
}

QByteArray DnsUserAgent() {
	static const auto kResult = QByteArray(
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
		"AppleWebKit/537.36 (KHTML, like Gecko) "
		"Chrome/151.0.0.0 Safari/537.36");
	return kResult;
}

std::vector<DnsEntry> ParseDnsResponse(
		const QByteArray &bytes,
		std::optional<int> typeRestriction) {
	if (bytes.isEmpty()) {
		return {};
	}
	if (bytes.front() == '{') {
		return ParseDnsJsonResponse(bytes, typeRestriction);
	}
	auto offset = 0;
	auto id = uint16();
	auto flags = uint16();
	auto questions = uint16();
	auto answers = uint16();
	auto authority = uint16();
	auto additional = uint16();
	if (!ReadDnsUInt16(bytes, offset, id)
		|| !ReadDnsUInt16(bytes, offset, flags)
		|| !ReadDnsUInt16(bytes, offset, questions)
		|| !ReadDnsUInt16(bytes, offset, answers)
		|| !ReadDnsUInt16(bytes, offset, authority)
		|| !ReadDnsUInt16(bytes, offset, additional)) {
		LOG(("Config Error: Bad dns response header."));
		return {};
	}
	Q_UNUSED(id);
	Q_UNUSED(flags);
	Q_UNUSED(authority);
	Q_UNUSED(additional);
	for (auto i = 0; i != questions; ++i) {
		auto type = uint16();
		auto queryClass = uint16();
		if (!SkipDnsName(bytes, offset)
			|| !ReadDnsUInt16(bytes, offset, type)
			|| !ReadDnsUInt16(bytes, offset, queryClass)) {
			LOG(("Config Error: Bad dns response question."));
			return {};
		}
		Q_UNUSED(type);
		Q_UNUSED(queryClass);
	}
	auto result = std::vector<DnsEntry>();
	for (auto i = 0; i != answers; ++i) {
		auto type = uint16();
		auto answerClass = uint16();
		auto ttl = uint32();
		auto dataSize = uint16();
		if (!SkipDnsName(bytes, offset)
			|| !ReadDnsUInt16(bytes, offset, type)
			|| !ReadDnsUInt16(bytes, offset, answerClass)
			|| !ReadDnsUInt32(bytes, offset, ttl)
			|| !ReadDnsUInt16(bytes, offset, dataSize)
			|| offset + dataSize > bytes.size()) {
			LOG(("Config Error: Bad dns response answer."));
			return {};
		}
		const auto dataOffset = offset;
		offset += dataSize;
		if (answerClass != 1
			|| (typeRestriction && type != *typeRestriction)) {
			continue;
		}
		if (type == 1 && dataSize == 4) {
			const auto data = reinterpret_cast<const uchar*>(
				bytes.constData() + dataOffset);
			result.push_back({
				(u"%1.%2.%3.%4"_q
				).arg(data[0]
				).arg(data[1]
				).arg(data[2]
				).arg(data[3]),
				crl::time(ttl)
			});
		} else if (type == 28 && dataSize == 16) {
			auto raw = Q_IPV6ADDR();
			std::memcpy(raw.c, bytes.constData() + dataOffset, 16);
			result.push_back({
				QHostAddress(raw).toString(),
				crl::time(ttl)
			});
		} else if (type == 16) {
			const auto data = ParseTxtData(bytes.mid(dataOffset, dataSize));
			if (!data.isEmpty()) {
				result.push_back({ data, crl::time(ttl) });
			}
		}
	}
	return result;
}

ServiceWebRequest::ServiceWebRequest(not_null<QNetworkReply*> reply)
: reply(reply.get()) {
}

ServiceWebRequest::ServiceWebRequest(ServiceWebRequest &&other)
: reply(base::take(other.reply)) {
}

ServiceWebRequest &ServiceWebRequest::operator=(ServiceWebRequest &&other) {
	if (reply != other.reply) {
		destroy();
		reply = base::take(other.reply);
	}
	return *this;
}

void ServiceWebRequest::destroy() {
	if (const auto value = base::take(reply)) {
		value->disconnect(
			value,
			&QNetworkReply::finished,
			nullptr,
			nullptr);
		value->abort();
		value->deleteLater();
	}
}

ServiceWebRequest::~ServiceWebRequest() {
	if (reply) {
		reply->deleteLater();
	}
}

DomainResolver::DomainResolver(Fn<void(
	const QString &host,
	const QStringList &ips,
	crl::time expireAt)> callback)
: _callback(std::move(callback)) {
	_manager.setProxy(QNetworkProxy::NoProxy);
}

DomainResolver::~DomainResolver() {
	for (const auto &[domain, lookupId] : _systemLookups) {
		QHostInfo::abortHostLookup(lookupId);
	}
}

void DomainResolver::resolve(const QString &domain) {
	resolve({ domain, false });
	resolve({ domain, true });
}

void DomainResolver::resolve(const AttemptKey &key) {
	if (_attempts.find(key) != end(_attempts)) {
		return;
	} else if (_requests.find(key) != end(_requests)) {
		return;
	} else if (_systemLookups.find(key.domain) != end(_systemLookups)) {
		return;
	}
	const auto i = _cache.find(key);
	_lastTimestamp = crl::now();
	if (i != end(_cache) && i->second.expireAt > _lastTimestamp) {
		checkExpireAndPushResult(key.domain);
		return;
	}
	resolveBySystemDns(key.domain);
}

void DomainResolver::resolveBySystemDns(const QString &domain) {
	const auto lookupId = QHostInfo::lookupHost(
		domain,
		this,
		[=](const QHostInfo &result) { systemDnsDone(domain, result); });
	_systemLookups.emplace(domain, lookupId);
}

void DomainResolver::systemDnsDone(
		const QString &domain,
		const QHostInfo &result) {
	_systemLookups.erase(domain);

	auto ipv4 = QStringList();
	auto ipv6 = QStringList();
	for (const auto &address : result.addresses()) {
		if (address.protocol() == QAbstractSocket::IPv4Protocol) {
			ipv4.push_back(address.toString());
		} else if (address.protocol() == QAbstractSocket::IPv6Protocol) {
			ipv6.push_back(address.toString());
		}
	}
	if (result.error() != QHostInfo::NoError) {
		DEBUG_LOG(("Resolve Error: System DNS failed for %1, error: %2"
			).arg(domain
			).arg(result.errorString()));
	}
	_lastTimestamp = crl::now();
	const auto apply = [&](bool v6, const QStringList &ips) {
		if (ips.isEmpty()) {
			resolveByDnsOverHttps({ domain, v6 });
			return;
		}
		auto entry = CacheEntry();
		entry.ips = ips;
		entry.expireAt = _lastTimestamp + kSystemDnsTimeToLive;
		_cache[AttemptKey{ domain, v6 }] = std::move(entry);
	};
	apply(false, ipv4);
	apply(true, ipv6);
	if (!ipv4.isEmpty()) {
		checkExpireAndPushResult(domain);
	}
	pushResultIfResolveDone(domain);
}

void DomainResolver::resolveByDnsOverHttps(const AttemptKey &key) {
	if (_attempts.find(key) != end(_attempts)
		|| _requests.find(key) != end(_requests)) {
		return;
	}

	auto attempts = std::vector<Attempt>();
	auto providers = DohProviders();
	std::random_device rd;
	ranges::shuffle(providers, std::mt19937(rd()));
	for (const auto &provider : providers) {
		attempts.push_back({ provider });
	}
	ranges::reverse(attempts); // We go from last to first.

	_attempts.emplace(key, Attempts{ std::move(attempts) });
	sendNextRequest(key);
}

void DomainResolver::checkExpireAndPushResult(const QString &domain) {
	const auto ipv4 = _cache.find({ domain, false });
	if (ipv4 == end(_cache) || ipv4->second.expireAt <= _lastTimestamp) {
		return;
	}
	auto result = ipv4->second;
	const auto ipv6 = _cache.find({ domain, true });
	if (ipv6 != end(_cache) && ipv6->second.expireAt > _lastTimestamp) {
		result.ips.append(ipv6->second.ips);
		accumulate_min(result.expireAt, ipv6->second.expireAt);
	}
	InvokeQueued(this, [=] {
		_callback(domain, result.ips, result.expireAt);
	});
}

void DomainResolver::sendNextRequest(const AttemptKey &key) {
	auto i = _attempts.find(key);
	if (i == end(_attempts)) {
		return;
	}
	auto &attempts = i->second;
	auto &list = attempts.list;
	const auto attempt = list.back();
	list.pop_back();

	if (!list.empty()) {
		base::call_delayed(kSendNextTimeout, &attempts.guard, [=] {
			sendNextRequest(key);
		});
	}
	performRequest(key, attempt);
}

void DomainResolver::performRequest(
		const AttemptKey &key,
		const Attempt &attempt) {
	auto url = QUrl();
	url.setScheme("https");
	url.setHost(attempt.provider.host);
	url.setPath(attempt.provider.path);
	auto request = QNetworkRequest();
	const auto payload = BuildDnsQuery(key.domain, key.ipv6 ? 28 : 1);
	if (payload.isEmpty()) {
		checkAttemptsExhausted(key);
		return;
	}
	request.setUrl(url);
	request.setRawHeader("accept", "application/dns-message");
	request.setRawHeader("Content-Type", "application/dns-message");
	request.setRawHeader("User-Agent", DnsUserAgent());
	const auto i = _requests.emplace(
		key,
		std::vector<ServiceWebRequest>()).first;
	const auto reply = i->second.emplace_back(
		_manager.post(request, payload)
	).reply;
	connect(reply, &QNetworkReply::finished, this, [=] {
		requestFinished(key, reply);
	});
}

void DomainResolver::checkAttemptsExhausted(const AttemptKey &key) {
	const auto i = _attempts.find(key);
	if (i != end(_attempts) && !i->second.list.empty()) {
		return;
	} else if (_requests.find(key) != end(_requests)) {
		return;
	}
	_attempts.erase(key);
	pushResultIfResolveDone(key.domain);
}

void DomainResolver::pushResultIfResolveDone(const QString &domain) {
	const auto pending = [&](bool v6) {
		const auto key = AttemptKey{ domain, v6 };
		return (_attempts.find(key) != end(_attempts))
			|| (_requests.find(key) != end(_requests));
	};
	if (pending(false)
		|| pending(true)
		|| _systemLookups.find(domain) != end(_systemLookups)) {
		return;
	}
	_lastTimestamp = crl::now();
	const auto ipv4 = _cache.find({ domain, false });
	if (ipv4 != end(_cache) && ipv4->second.expireAt > _lastTimestamp) {
		return;
	}
	const auto ipv6 = _cache.find({ domain, true });
	if (ipv6 != end(_cache) && ipv6->second.expireAt > _lastTimestamp) {
		const auto result = ipv6->second;
		InvokeQueued(this, [=] {
			_callback(domain, result.ips, result.expireAt);
		});
	} else {
		LOG(("Resolve Error: Could not resolve domain %1 "
			"by system DNS or DNS over HTTPS.").arg(domain));
		const auto expireAt = _lastTimestamp + kNegativeResolveTtl;
		InvokeQueued(this, [=] {
			_callback(domain, QStringList(), expireAt);
		});
	}
}

void DomainResolver::requestFinished(
		const AttemptKey &key,
		not_null<QNetworkReply*> reply) {
	const auto result = finalizeRequest(key, reply);
	const auto response = ParseDnsResponse(result, key.ipv6 ? 28 : 1);
	if (response.empty()) {
		checkAttemptsExhausted(key);
		return;
	}
	_requests.erase(key);
	_attempts.erase(key);

	auto entry = CacheEntry();
	auto ttl = kMaxTimeToLive;
	for (const auto &item : response) {
		entry.ips.push_back(item.data);
		ttl = std::min(
			ttl,
			std::max(item.TTL * crl::time(1000), kMinTimeToLive));
	}
	_lastTimestamp = crl::now();
	entry.expireAt = _lastTimestamp + ttl;
	_cache[key] = std::move(entry);

	checkExpireAndPushResult(key.domain);
	pushResultIfResolveDone(key.domain);
}

QByteArray DomainResolver::finalizeRequest(
		const AttemptKey &key,
		not_null<QNetworkReply*> reply) {
	if (reply->error() != QNetworkReply::NoError) {
		DEBUG_LOG(("Resolve Error: Failed to get response, error: %2 (%3)"
			).arg(reply->errorString()
			).arg(reply->error()));
	}
	const auto result = reply->readAll();
	const auto i = _requests.find(key);
	if (i != end(_requests)) {
		auto &requests = i->second;
		const auto from = ranges::remove(
			requests,
			reply,
			[](const ServiceWebRequest &request) { return request.reply; });
		requests.erase(from, end(requests));
		if (requests.empty()) {
			_requests.erase(i);
		}
	}
	return result;
}

} // namespace MTP::details
