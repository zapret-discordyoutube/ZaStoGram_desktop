/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "mtproto/config/special_config_request.h"

#include "mtproto/protocol/mtproto_binary.h"
#include "mtproto/details/mtproto_rsa_public_key.h"
#include "mtproto/config/mtproto_dc_options.h"
#include "mtproto/auth/mtproto_auth_key.h"
#include "base/unixtime.h"
#include "base/openssl_help.h"
#include "base/call_delayed.h"

#include <QtNetwork/QDnsLookup>

namespace MTP::details {
namespace {

constexpr auto kSendNextTimeout = crl::time(800);
constexpr auto kRequestTransferTimeout = crl::time(6000);
constexpr auto kSimpleConfigBase64Size = 344;
constexpr auto kSimpleConfigBlockSize = 256;

constexpr auto kPublicKey = "\
-----BEGIN RSA PUBLIC KEY-----\n\
MIIBCgKCAQEAyr+18Rex2ohtVy8sroGPBwXD3DOoKCSpjDqYoXgCqB7ioln4eDCF\n\
fOBUlfXUEvM/fnKCpF46VkAftlb4VuPDeQSS/ZxZYEGqHaywlroVnXHIjgqoxiAd\n\
192xRGreuXIaUKmkwlM9JID9WS2jUsTpzQ91L8MEPLJ/4zrBwZua8W5fECwCCh2c\n\
9G5IzzBm+otMS/YKwmR1olzRCyEkyAEjXWqBI9Ftv5eG8m0VkBzOG655WIYdyV0H\n\
fDK/NWcvGqa0w/nriMD6mDjKOryamw0OP9QuYgMN0C9xMW9y8SmP4h92OAWodTYg\n\
Y1hZCxdv6cs5UnW9+PWvS+WIbkh+GaWYxwIDAQAB\n\
-----END RSA PUBLIC KEY-----\
"_cs;

bool CheckPhoneByPrefixesRules(const QString &phone, const QString &rules) {
	static const auto RegExp = QRegularExpression("[^0-9]");
	const auto check = QString(phone).replace(
		RegExp,
		QString());
	auto result = false;
	for (const auto &prefix : rules.split(',')) {
		if (prefix.isEmpty()) {
			result = true;
		} else if (prefix[0] == '+' && check.startsWith(prefix.mid(1))) {
			result = true;
		} else if (prefix[0] == '-' && check.startsWith(prefix.mid(1))) {
			return false;
		}
	}
	return result;
}

QByteArray ConcatenateDnsTxtFields(const std::vector<DnsEntry> &response) {
	auto entries = QMultiMap<int, QString>();
	for (const auto &entry : response) {
		entries.insert(INT_MAX - entry.data.size(), entry.data);
	}
	return QStringList(entries.values()).join(QString()).toLatin1();
}

[[nodiscard]] bytes::vector DecryptSimpleConfigBlock(
		bytes::const_span encrypted) {
	if (encrypted.size() != kSimpleConfigBlockSize) {
		LOG(("Config Error: Bad data size %1 required %2"
			).arg(encrypted.size()
			).arg(kSimpleConfigBlockSize));
		return {};
	}

	auto publicKey = details::RSAPublicKey(bytes::make_span(kPublicKey));
	auto decrypted = publicKey.decrypt(encrypted);
	if (decrypted.size() != kSimpleConfigBlockSize) {
		LOG(("Config Error: Bad decrypted data size %1 required %2"
			).arg(decrypted.size()
			).arg(kSimpleConfigBlockSize));
		return {};
	}
	return decrypted;
}

[[nodiscard]] QDateTime ParseHttpDate(const QString &date) {
	// Wed, 10 Jul 2019 14:33:38 GMT
	static const auto expression = QRegularExpression(
		R"(\w\w\w, (\d\d) (\w\w\w) (\d\d\d\d) (\d\d):(\d\d):(\d\d) GMT)");
	const auto match = expression.match(date);
	if (!match.hasMatch()) {
		return QDateTime();
	}

	const auto number = [&](int index) {
		return match.capturedView(index).toInt();
	};
	const auto day = number(1);
	const auto month = [&] {
		static const auto months = {
			"Jan",
			"Feb",
			"Mar",
			"Apr",
			"May",
			"Jun",
			"Jul",
			"Aug",
			"Sep",
			"Oct",
			"Nov",
			"Dec"
		};
		const auto captured = match.capturedView(2);
		for (auto i = begin(months); i != end(months); ++i) {
			if (captured == QString(*i)) {
				return 1 + int(i - begin(months));
			}
		}
		return 0;
	}();
	const auto year = number(3);
	const auto hour = number(4);
	const auto minute = number(5);
	const auto second = number(6);
	return QDateTime(
		QDate(year, month, day),
		QTime(hour, minute, second),
		Qt::UTC);
}

} // namespace

SpecialConfigRequest::SpecialConfigRequest(
	Fn<void(
		DcId dcId,
		const std::string &ip,
		int port,
		bytes::const_span secret)> callback,
	Fn<void()> timeDoneCallback,
	bool isTestMode,
	const QString &domainString,
	const QString &phone)
: _callback(std::move(callback))
, _timeDoneCallback(std::move(timeDoneCallback))
, _domainString(domainString)
, _phone(phone) {
	Expects((_callback == nullptr) != (_timeDoneCallback == nullptr));
	Q_UNUSED(isTestMode);

	_manager.setProxy(QNetworkProxy::NoProxy);

	if (_timeDoneCallback) {
		startWebRequests();
	} else {
		startSystemTxtLookup();
	}
}

SpecialConfigRequest::SpecialConfigRequest(
	Fn<void(
		DcId dcId,
		const std::string &ip,
		int port,
		bytes::const_span secret)> callback,
	bool isTestMode,
	const QString &domainString,
	const QString &phone)
: SpecialConfigRequest(
	std::move(callback),
	nullptr,
	isTestMode,
	domainString,
	phone) {
}

SpecialConfigRequest::SpecialConfigRequest(
	Fn<void()> timeDoneCallback,
	bool isTestMode,
	const QString &domainString)
: SpecialConfigRequest(
	nullptr,
	std::move(timeDoneCallback),
	isTestMode,
	domainString,
	QString()) {
}

void SpecialConfigRequest::startSystemTxtLookup() {
	_systemLookup = std::make_unique<QDnsLookup>(
		QDnsLookup::TXT,
		_domainString,
		this);
	connect(_systemLookup.get(), &QDnsLookup::finished, this, [=] {
		systemTxtLookupFinished();
	});
	_systemLookup->lookup();
}

void SpecialConfigRequest::systemTxtLookupFinished() {
	const auto lookup = base::take(_systemLookup);
	if (!lookup) {
		return;
	}
	auto entries = std::vector<DnsEntry>();
	if (lookup->error() == QDnsLookup::NoError) {
		for (const auto &record : lookup->textRecords()) {
			for (const auto &value : record.values()) {
				entries.push_back({
					QString::fromUtf8(value),
					crl::time(record.timeToLive())
				});
			}
		}
	} else {
		DEBUG_LOG(("Config Error: System TXT lookup failed for %1, error: %2"
			).arg(_domainString
			).arg(lookup->errorString()));
	}
	if (!entries.empty()
		&& handleResponse(ConcatenateDnsTxtFields(entries))) {
		return;
	}
	startWebRequests();
}

void SpecialConfigRequest::startWebRequests() {
	auto attempts = std::vector<Attempt>();
	auto providers = DohProviders();
	std::random_device rd;
	ranges::shuffle(providers, std::mt19937(rd()));
	for (const auto &provider : providers) {
		attempts.push_back({ Type::Doh, provider });
	}
	ranges::reverse(attempts); // We go from last to first.

	_attempts = std::move(attempts);
	sendNextRequest();
}

void SpecialConfigRequest::sendNextRequest() {
	Expects(!_attempts.empty());

	const auto attempt = _attempts.back();
	_attempts.pop_back();
	if (!_attempts.empty()) {
		base::call_delayed(kSendNextTimeout, this, [=] {
			sendNextRequest();
		});
	}
	performRequest(attempt);
}

void SpecialConfigRequest::performRequest(const Attempt &attempt) {
	const auto type = attempt.type;
	auto url = QUrl();
	url.setScheme(u"https"_q);
	url.setHost(attempt.provider.host);
	url.setPath(attempt.provider.path);
	auto request = QNetworkRequest();
	auto payload = BuildDnsQuery(_domainString, 16);
	switch (type) {
	case Type::Doh: {
		request.setRawHeader("accept", "application/dns-message");
		request.setRawHeader("Content-Type", "application/dns-message");
	} break;
	default: Unexpected("Type in SpecialConfigRequest::performRequest.");
	}
	request.setTransferTimeout(int(kRequestTransferTimeout));
	if (payload.isEmpty()) {
		return;
	}
	request.setUrl(url);
	request.setRawHeader("User-Agent", DnsUserAgent());
	const auto reply = _requests.emplace_back(
		_manager.post(request, payload)
	).reply;
	connect(reply, &QNetworkReply::finished, this, [=] {
		requestFinished(type, reply);
	});
}

void SpecialConfigRequest::handleHeaderUnixtime(
		not_null<QNetworkReply*> reply) {
	if (reply->error() != QNetworkReply::NoError) {
		return;
	}
	const auto date = QString::fromLatin1([&] {
		for (const auto &pair : reply->rawHeaderPairs()) {
			if (pair.first == "Date") {
				return pair.second;
			}
		}
		return QByteArray();
	}());
	if (date.isEmpty()) {
		LOG(("Config Error: No 'Date' header received."));
		return;
	}
	const auto parsed = ParseHttpDate(date);
	if (!parsed.isValid()) {
		LOG(("Config Error: Bad 'Date' header received: %1").arg(date));
		return;
	}
	base::unixtime::http_update(parsed.toSecsSinceEpoch());
	if (_timeDoneCallback) {
		_timeDoneCallback();
	}
}

void SpecialConfigRequest::requestFinished(
		Type type,
		not_null<QNetworkReply*> reply) {
	const auto result = finalizeRequest(reply);
	if (_timeDoneCallback) {
		handleHeaderUnixtime(reply);
		return;
	}
	if (!_callback || result.isEmpty()) {
		return;
	}

	switch (type) {
	case Type::Doh: {
		constexpr auto kTypeRestriction = 16; // TXT
		handleResponse(ConcatenateDnsTxtFields(
			ParseDnsResponse(result, kTypeRestriction)));
	} break;
	default: Unexpected("Type in SpecialConfigRequest::requestFinished.");
	}
}

QByteArray SpecialConfigRequest::finalizeRequest(
		not_null<QNetworkReply*> reply) {
	if (reply->error() != QNetworkReply::NoError) {
		DEBUG_LOG(("Config Error: Failed to get response, error: %2 (%3)"
			).arg(reply->errorString()
			).arg(reply->error()));
	}
	const auto result = reply->readAll();
	const auto from = ranges::remove(
		_requests,
		reply,
		[](const ServiceWebRequest &request) { return request.reply; });
	_requests.erase(from, end(_requests));
	return result;
}

bool SpecialConfigRequest::decryptSimpleConfig(const QByteArray &bytes) {
	auto cleanBytes = bytes;
	auto removeFrom = std::remove_if(cleanBytes.begin(), cleanBytes.end(), [](char ch) {
		auto isGoodBase64 = (ch == '+') || (ch == '=') || (ch == '/')
			|| (ch >= 'a' && ch <= 'z')
			|| (ch >= 'A' && ch <= 'Z')
			|| (ch >= '0' && ch <= '9');
		return !isGoodBase64;
	});
	if (removeFrom != cleanBytes.end()) {
		cleanBytes.remove(removeFrom - cleanBytes.begin(), cleanBytes.end() - removeFrom);
	}

	if (cleanBytes.size() != kSimpleConfigBase64Size) {
		LOG(("Config Error: Bad data size %1 required %2"
			).arg(cleanBytes.size()
			).arg(kSimpleConfigBase64Size));
		return false;
	}
	auto decodedBytes = QByteArray::fromBase64(cleanBytes, QByteArray::Base64Encoding);
	auto decrypted = DecryptSimpleConfigBlock(bytes::make_span(decodedBytes));
	if (decrypted.empty()) {
		return false;
	}
	auto decryptedBytes = gsl::make_span(decrypted);

	auto aesEncryptedBytes = decryptedBytes.subspan(CTRState::KeySize);
	auto aesivec = bytes::make_vector(decryptedBytes.subspan(CTRState::KeySize - CTRState::IvecSize, CTRState::IvecSize));
	AES_KEY aeskey;
	AES_set_decrypt_key(reinterpret_cast<const unsigned char*>(decryptedBytes.data()), CTRState::KeySize * CHAR_BIT, &aeskey);
	AES_cbc_encrypt(reinterpret_cast<const unsigned char*>(aesEncryptedBytes.data()), reinterpret_cast<unsigned char*>(aesEncryptedBytes.data()), aesEncryptedBytes.size(), &aeskey, reinterpret_cast<unsigned char*>(aesivec.data()), AES_DECRYPT);

	constexpr auto kDigestSize = 16;
	auto dataSize = aesEncryptedBytes.size() - kDigestSize;
	auto data = aesEncryptedBytes.subspan(0, dataSize);
	auto hash = openssl::Sha256(data);
	if (bytes::compare(gsl::make_span(hash).subspan(0, kDigestSize), aesEncryptedBytes.subspan(dataSize)) != 0) {
		LOG(("Config Error: Bad digest."));
		return false;
	}

	mtpBuffer buffer;
	buffer.resize(data.size() / sizeof(mtpPrime));
	bytes::copy(bytes::make_span(buffer), data);
	auto from = &*buffer.cbegin();
	auto end = from + buffer.size();
	auto realLength = *from++;
	if (realLength <= 0 || realLength > dataSize || (realLength & 0x03)) {
		LOG(("Config Error: Bad length %1.").arg(realLength));
		return false;
	}

	if (!_simpleConfig.read(from, end)) {
		LOG(("Config Error: Could not read configSimple."));
		return false;
	}
	if ((end - from) * sizeof(mtpPrime) != (dataSize - realLength)) {
		LOG(("Config Error: Bad read length %1, should be %2.").arg((end - from) * sizeof(mtpPrime)).arg(dataSize - realLength));
		return false;
	}
	return true;
}

bool SpecialConfigRequest::handleResponse(const QByteArray &bytes) {
	if (!decryptSimpleConfig(bytes)) {
		return false;
	}
	Assert(_simpleConfig.type() == mtpc_help_configSimple);
	const auto &config = _simpleConfig.c_help_configSimple();
	const auto now = base::unixtime::now();
	if (now > config.vexpires().v) {
		LOG(("Config Error: "
			"Bad date frame for simple config: %1-%2, our time is %3."
			).arg(config.vdate().v
			).arg(config.vexpires().v
			).arg(now));
		return false;
	}
	if (config.vrules().v.empty()) {
		LOG(("Config Error: Empty simple config received."));
		return false;
	}
	for (const auto &rule : config.vrules().v) {
		Assert(rule.type() == mtpc_accessPointRule);
		const auto &data = rule.c_accessPointRule();
		const auto phoneRules = qs(data.vphone_prefix_rules());
		if (!CheckPhoneByPrefixesRules(_phone, phoneRules)) {
			continue;
		}

		const auto dcId = data.vdc_id().v;
		for (const auto &address : data.vips().v) {
			const auto parseIp = [](const MTPint &ipv4) {
				const auto ip = details::binary::Read<uint32>(
					details::binary::AsBytes(&ipv4.v));
				return (u"%1.%2.%3.%4"_q
				).arg((ip >> 24) & 0xFF
				).arg((ip >> 16) & 0xFF
				).arg((ip >> 8) & 0xFF
				).arg(ip & 0xFF).toStdString();
			};
			switch (address.type()) {
			case mtpc_ipPort: {
				const auto &fields = address.c_ipPort();
				const auto ip = parseIp(fields.vipv4());
				if (!ip.empty()) {
					_callback(dcId, ip, fields.vport().v, {});
				}
			} break;
			case mtpc_ipPortSecret: {
				const auto &fields = address.c_ipPortSecret();
				const auto ip = parseIp(fields.vipv4());
				if (!ip.empty()) {
					_callback(
						dcId,
						ip,
						fields.vport().v,
						bytes::make_span(fields.vsecret().v));
				}
			} break;
			default: Unexpected("Type in simpleConfig ips.");
			}
		}
	}
	_callback(0, std::string(), 0, {});
	return true;
}

} // namespace MTP::details
