/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "mtproto/proxy/mtproxy/client_hello_facts.h"

#include "base/bytes.h"
#include "base/openssl_help.h"
#include "mtproto/proxy/mtproxy/client_hello_constants.h"

#include <algorithm>
#include <optional>

namespace MTP::details {
namespace {

[[nodiscard]] std::optional<int> ClientHelloRead16(
		const QByteArray &data,
		int offset) {
	if (offset < 0 || offset + 2 > data.size()) {
		return std::nullopt;
	}
	return (int(uchar(data[offset])) << 8)
		| int(uchar(data[offset + 1]));
}

[[nodiscard]] std::optional<int> ClientHelloRead24(
		const QByteArray &data,
		int offset) {
	if (offset < 0 || offset + 3 > data.size()) {
		return std::nullopt;
	}
	return (int(uchar(data[offset])) << 16)
		| (int(uchar(data[offset + 1])) << 8)
		| int(uchar(data[offset + 2]));
}

[[nodiscard]] bool IsAlphaNum(char value) {
	return (value >= '0' && value <= '9')
		|| (value >= 'A' && value <= 'Z')
		|| (value >= 'a' && value <= 'z');
}

[[nodiscard]] QString TlsVersionCode(int value) {
	switch (value) {
	case 0x0304: return u"13"_q;
	case 0x0303: return u"12"_q;
	case 0x0302: return u"11"_q;
	case 0x0301: return u"10"_q;
	case 0x0300: return u"s3"_q;
	case 0x0002: return u"s2"_q;
	case 0xFEFF: return u"d1"_q;
	case 0xFEFD: return u"d2"_q;
	case 0xFEFC: return u"d3"_q;
	}
	return u"00"_q;
}

[[nodiscard]] QString AlpnCode(const QByteArray &value) {
	if (value.isEmpty()) {
		return u"00"_q;
	}
	const auto first = value.front();
	const auto last = value.back();
	if (IsAlphaNum(first) && IsAlphaNum(last)) {
		return QString::fromLatin1(&first, 1)
			+ QString::fromLatin1(&last, 1);
	}
	const auto hex = value.toHex();
	return QString::fromLatin1(hex.left(1) + hex.right(1));
}

[[nodiscard]] QString Hex16(int value) {
	return QString::number(value, 16).rightJustified(4, QChar('0'));
}

[[nodiscard]] QString JoinHex(QVector<int> values, bool sort) {
	if (sort) {
		std::sort(values.begin(), values.end());
	}
	auto result = QString();
	for (const auto value : values) {
		if (!result.isEmpty()) {
			result += QChar(',');
		}
		result += Hex16(value);
	}
	return result;
}

[[nodiscard]] QString Sha12(const QString &value) {
	if (value.isEmpty()) {
		return u"000000000000"_q;
	}
	const auto input = value.toUtf8();
	const auto hash = openssl::Sha256(bytes::make_span(input));
	const auto hex = QByteArray(
		reinterpret_cast<const char*>(hash.data()),
		int(hash.size())).toHex();
	return QString::fromLatin1(hex.left(12));
}

[[nodiscard]] QVector<int> WithoutGrease(const QVector<int> &values) {
	auto result = QVector<int>();
	result.reserve(values.size());
	for (const auto value : values) {
		if (!IsClientHelloGrease(uint16(value))) {
			result.push_back(value);
		}
	}
	return result;
}

[[nodiscard]] QByteArray SniHost(const QByteArray &value) {
	const auto listLength = ClientHelloRead16(value, 0);
	if (!listLength) {
		return {};
	}
	auto position = 2;
	const auto end = position + *listLength;
	if (end > value.size()) {
		return {};
	}
	while (position + 3 <= end) {
		const auto nameType = uchar(value[position]);
		const auto nameLength = ClientHelloRead16(value, position + 1);
		const auto nameOffset = position + 3;
		if (!nameLength || nameOffset + *nameLength > end) {
			return {};
		}
		if (nameType == 0 && *nameLength > 0) {
			return value.mid(nameOffset, *nameLength);
		}
		position = nameOffset + *nameLength;
	}
	return {};
}

[[nodiscard]] bool HasSniHost(const QByteArray &value) {
	const auto listLength = ClientHelloRead16(value, 0);
	if (!listLength) {
		return false;
	}
	auto position = 2;
	const auto end = position + *listLength;
	if (end > value.size()) {
		return false;
	}
	while (position + 3 <= end) {
		const auto nameType = uchar(value[position]);
		const auto nameLength = ClientHelloRead16(value, position + 1);
		const auto nameOffset = position + 3;
		if (!nameLength || nameOffset + *nameLength > end) {
			return false;
		}
		if (nameType == 0 && *nameLength > 0) {
			return true;
		}
		position = nameOffset + *nameLength;
	}
	return false;
}

[[nodiscard]] QByteArray FirstAlpn(const QByteArray &value) {
	const auto listLength = ClientHelloRead16(value, 0);
	if (!listLength || 2 + *listLength > value.size() || *listLength < 1) {
		return {};
	}
	const auto length = int(uchar(value[2]));
	if (length <= 0 || 3 + length > value.size()) {
		return {};
	}
	return value.mid(3, length);
}

void AppendSupportedVersions(ClientHelloFacts &facts, const QByteArray &value) {
	if (value.isEmpty()) {
		return;
	}
	const auto length = int(uchar(value[0]));
	for (auto offset = 1; offset + 2 <= value.size() && offset < 1 + length;
			offset += 2) {
		if (const auto version = ClientHelloRead16(value, offset)) {
			facts.supportedVersions.push_back(*version);
		}
	}
}

void AppendSignatureAlgorithms(ClientHelloFacts &facts, const QByteArray &value) {
	const auto length = ClientHelloRead16(value, 0);
	if (!length) {
		return;
	}
	for (auto offset = 2; offset + 2 <= value.size() && offset < 2 + *length;
			offset += 2) {
		if (const auto algorithm = ClientHelloRead16(value, offset)) {
			facts.signatureAlgorithms.push_back(*algorithm);
		}
	}
}

} // namespace

bool IsClientHelloGrease(uint16 value) {
	return ((value & 0x0F0F) == 0x0A0A)
		&& (((value >> 8) & 0xFF) == (value & 0xFF));
}

std::optional<ClientHelloFacts> ComputeClientHelloFacts(
		const QByteArray &data) {
	if (data.size() < 9 || uchar(data[0]) != 0x16) {
		return std::nullopt;
	}
	auto position = 5;
	if (uchar(data[position]) != 0x01) {
		return std::nullopt;
	}
	const auto handshakeLength = ClientHelloRead24(data, position + 1);
	position += 4;
	if (!handshakeLength) {
		return std::nullopt;
	}
	const auto handshakeEnd = position + *handshakeLength;
	if (handshakeEnd > data.size()) {
		return std::nullopt;
	}
	auto result = ClientHelloFacts();
	const auto legacyVersion = ClientHelloRead16(data, position);
	if (!legacyVersion) {
		return std::nullopt;
	}
	result.legacyVersion = *legacyVersion;
	position += 2 + 32;
	if (position >= handshakeEnd) {
		return std::nullopt;
	}
	const auto sessionIdLength = int(uchar(data[position++]));
	if (sessionIdLength < 0 || position + sessionIdLength > handshakeEnd) {
		return std::nullopt;
	}
	position += sessionIdLength;
	const auto cipherSuitesLength = ClientHelloRead16(data, position);
	if (!cipherSuitesLength) {
		return std::nullopt;
	}
	position += 2;
	if (*cipherSuitesLength % 2
		|| position + *cipherSuitesLength > handshakeEnd) {
		return std::nullopt;
	}
	for (auto offset = position; offset < position + *cipherSuitesLength;
			offset += 2) {
		if (const auto cipher = ClientHelloRead16(data, offset)) {
			result.cipherSuites.push_back(*cipher);
		} else {
			return std::nullopt;
		}
	}
	position += *cipherSuitesLength;
	if (position >= handshakeEnd) {
		return result;
	}
	const auto compressionLength = int(uchar(data[position++]));
	if (position + compressionLength > handshakeEnd) {
		return std::nullopt;
	}
	position += compressionLength;
	if (position == handshakeEnd) {
		return result;
	}
	const auto extensionsLength = ClientHelloRead16(data, position);
	if (!extensionsLength) {
		return std::nullopt;
	}
	position += 2;
	const auto extensionsEnd = position + *extensionsLength;
	if (extensionsEnd > handshakeEnd) {
		return std::nullopt;
	}
	while (position + 4 <= extensionsEnd) {
		const auto extension = ClientHelloRead16(data, position);
		const auto length = ClientHelloRead16(data, position + 2);
		const auto valueOffset = position + 4;
		if (!extension || !length) {
			return std::nullopt;
		}
		const auto next = valueOffset + *length;
		if (next > extensionsEnd) {
			return std::nullopt;
		}
		const auto value = data.mid(valueOffset, *length);
		result.extensions.push_back(*extension);
		if (*extension == 0x0000) {
			result.hasSni = HasSniHost(value);
			result.sniHost = SniHost(value);
		} else if (*extension == 0x0010) {
			result.firstAlpn = FirstAlpn(value);
		} else if (*extension == 0x002B) {
			AppendSupportedVersions(result, value);
		} else if (*extension == 0x000D) {
			AppendSignatureAlgorithms(result, value);
		}
		position = next;
	}
	const auto cleanVersions = WithoutGrease(result.supportedVersions);
	result.tlsVersion = cleanVersions.isEmpty()
		? result.legacyVersion
		: *std::max_element(cleanVersions.begin(), cleanVersions.end());
	return result;
}

ClientHelloContractIssue CheckClientHelloContract(
		const QByteArray &hello,
		const QByteArray &domainFromSecret) {
	const auto size = int(hello.size());
	if (size < 9
		|| uchar(hello[0]) != 0x16
		|| uchar(hello[1]) != 0x03
		|| uchar(hello[2]) != 0x01
		|| uchar(hello[5]) != 0x01) {
		return ClientHelloContractIssue::BadRecordHeader;
	} else if (size < kCanonicalClientHelloLength) {
		// The relay only enters its fake TLS branch when the high byte of the
		// record length is at least two, so a shorter hello is not rejected -
		// it is never read as a client's in the first place.
		return ClientHelloContractIssue::TooShort;
	} else if (size > kMaxRelayClientHelloLength) {
		return ClientHelloContractIssue::TooLong;
	}
	const auto recordLength = ClientHelloRead16(hello, 3);
	const auto handshakeLength = ClientHelloRead24(hello, 6);
	if (!recordLength
		|| !handshakeLength
		|| *recordLength != size - 5
		|| *handshakeLength != size - 9) {
		return ClientHelloContractIssue::InconsistentLength;
	}
	const auto facts = ComputeClientHelloFacts(hello);
	if (!facts) {
		return ClientHelloContractIssue::InconsistentLength;
	}

	// Nested lengths that do not add up are as fatal as a wrong length in the
	// header, and nothing else in the tree catches them: the fact parser
	// leaves its loop as soon as fewer than four bytes remain, so a template
	// whose extensions stop one to three bytes short of the block passes it
	// without a word. Walk the fixed fields to the extension block, require
	// the block to end where the packet does, and then walk the extensions
	// themselves and require the walk to land on that end exactly.
	auto position = 43 + 1 + int(uchar(hello[43]));
	const auto cipherSuitesLength = ClientHelloRead16(hello, position);
	if (!cipherSuitesLength) {
		return ClientHelloContractIssue::InconsistentLength;
	}
	position += 2 + *cipherSuitesLength;
	if (position >= size) {
		return ClientHelloContractIssue::InconsistentLength;
	}
	position += 1 + int(uchar(hello[position]));
	const auto extensionsLength = ClientHelloRead16(hello, position);
	if (!extensionsLength || position + 2 + *extensionsLength != size) {
		return ClientHelloContractIssue::InconsistentLength;
	}
	position += 2;
	while (position != size) {
		if (position + 4 > size) {
			return ClientHelloContractIssue::InconsistentLength;
		}
		const auto length = ClientHelloRead16(hello, position + 2);
		if (!length) {
			return ClientHelloContractIssue::InconsistentLength;
		}
		position += 4 + *length;
		if (position > size) {
			return ClientHelloContractIssue::InconsistentLength;
		}
	}

	// GREASE is recognised by shape, not by a table of values: both bytes must
	// have 0x0A in the low nibble. A placeholder of any other shape is not
	// skipped - it takes the place of the first real suite and fails the check
	// below, which is exactly what the relay does with it.
	auto first = std::optional<int>();
	for (const auto suite : facts->cipherSuites) {
		if (((suite & 0x0F) == 0x0A) && (((suite >> 8) & 0x0F) == 0x0A)) {
			continue;
		}
		first = suite;
		break;
	}
	if (!first
		|| ((*first >> 8) != 0x13)
		|| ((*first & 0xFF) < 0x01)
		|| ((*first & 0xFF) > 0x03)) {
		return ClientHelloContractIssue::FirstCipherNotTls13;
	}

	if (!facts->hasSni || facts->sniHost.isEmpty()) {
		return ClientHelloContractIssue::SniMissing;
	} else if (facts->sniHost != domainFromSecret) {
		return ClientHelloContractIssue::SniMismatch;
	}
	return ClientHelloContractIssue::None;
}

QString ClientHelloContractIssueSlug(ClientHelloContractIssue issue) {
	switch (issue) {
	case ClientHelloContractIssue::None: return QString();
	case ClientHelloContractIssue::BadRecordHeader:
		return u"bad_record_header"_q;
	case ClientHelloContractIssue::TooShort: return u"under_canonical_length"_q;
	case ClientHelloContractIssue::TooLong: return u"over_relay_read_limit"_q;
	case ClientHelloContractIssue::InconsistentLength:
		return u"declared_lengths_disagree"_q;
	case ClientHelloContractIssue::FirstCipherNotTls13:
		return u"first_cipher_not_tls13"_q;
	case ClientHelloContractIssue::SniMissing: return u"sni_missing"_q;
	case ClientHelloContractIssue::SniMismatch: return u"sni_not_from_secret"_q;
	}
	return u"unknown"_q;
}

QString ComputeClientHelloJa4(const ClientHelloFacts &facts) {
	auto cleanCiphers = WithoutGrease(facts.cipherSuites);
	auto cleanExtensions = WithoutGrease(facts.extensions);
	auto extensionHashValues = QVector<int>();
	extensionHashValues.reserve(cleanExtensions.size());
	for (const auto extension : cleanExtensions) {
		if (extension != 0x0000 && extension != 0x0010) {
			extensionHashValues.push_back(extension);
		}
	}
	const auto cleanSignatures = WithoutGrease(facts.signatureAlgorithms);
	auto extensionHashInput = JoinHex(extensionHashValues, true);
	const auto signatureInput = JoinHex(cleanSignatures, false);
	if (!signatureInput.isEmpty()) {
		extensionHashInput += QChar('_') + signatureInput;
	}
	return u"t"_q
		+ TlsVersionCode(facts.tlsVersion ? facts.tlsVersion : facts.legacyVersion)
		+ (facts.hasSni ? u"d"_q : u"i"_q)
		+ QString::number(std::min(int(cleanCiphers.size()), 99)).rightJustified(
			2,
			QChar('0'))
		+ QString::number(std::min(int(cleanExtensions.size()), 99)).rightJustified(
			2,
			QChar('0'))
		+ AlpnCode(facts.firstAlpn)
		+ QChar('_')
		+ Sha12(JoinHex(cleanCiphers, true))
		+ QChar('_')
		+ Sha12(extensionHashInput);
}

QString ComputeClientHelloJa4(const QByteArray &data) {
	const auto facts = ComputeClientHelloFacts(data);
	return facts ? ComputeClientHelloJa4(*facts) : QString();
}

} // namespace MTP::details
