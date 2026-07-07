/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "mtproto/proxy/mtproxy/client_hello_builder.h"

#include "mtproto/protocol/mtproto_binary.h"
#include "mtproto/proxy/mtproxy/client_hello_constants.h"
#include "base/openssl_help.h"
#include "base/bytes.h"
#include "base/random.h"
#include "base/unixtime.h"

#include <QtCore/QtEndian>

#include <algorithm>
#include <array>
#include <optional>
#include <vector>

namespace MTP::details {
namespace {

[[nodiscard]] bytes::vector PrepareGreases(
		const ClientHelloGenerationOptions &options) {
	auto result = bytes::vector(kClientHelloGreaseCount);
	if (options.deterministic) {
		for (auto i = 0; i != kClientHelloGreaseCount; ++i) {
			result[i] = bytes::type((i << 4) + 0x0A);
		}
		return result;
	}
	bytes::set_random(result);
	for (auto &byte : result) {
		byte = bytes::type((uchar(byte) & 0xF0) + 0x0A);
	}
	static_assert(kClientHelloGreaseCount % 2 == 0);
	for (auto i = 0; i != kClientHelloGreaseCount; i += 2) {
		if (result[i] == result[i + 1]) {
			result[i + 1] = bytes::type(uchar(result[i + 1]) ^ 0x10);
		}
	}
	return result;
}

[[nodiscard]] bytes::vector GeneratePublicKey() {
	const auto context = EVP_PKEY_CTX_new_id(NID_ED25519, nullptr);
	if (!context) {
		return {};
	}
	const auto guardContext = gsl::finally([&] {
		EVP_PKEY_CTX_free(context);
	});

	if (EVP_PKEY_keygen_init(context) <= 0) {
		return {};
	}

	auto key = (EVP_PKEY*)nullptr;
	if (EVP_PKEY_keygen(context, &key) <= 0) {
		return {};
	}
	const auto guardKey = gsl::finally([&] {
		EVP_PKEY_free(key);
	});

	auto length = size_t(0);
	if (!EVP_PKEY_get_raw_public_key(key, nullptr, &length)) {
		return {};
	}
	Assert(length == 32);

	auto result = bytes::vector(length);
	const auto code = EVP_PKEY_get_raw_public_key(
		key,
		reinterpret_cast<unsigned char *>(result.data()),
		&length);
	if (!code) {
		return {};
	}
	return result;
}

[[nodiscard]] bool ShouldPadBeforeSyntheticPsk(ProxyTlsProfile profile) {
	switch (profile) {
	case ProxyTlsProfile::Firefox:
	case ProxyTlsProfile::FirefoxAndroid:
	case ProxyTlsProfile::AndroidOkHttp:
	case ProxyTlsProfile::Yandex:
		return false;
	default:
		return true;
	}
}

class Generator {
public:
	Generator(
		const MTPTlsClientHello &rules,
		bytes::const_span domain,
		bytes::const_span key,
		bool padBeforeSyntheticPsk,
		std::optional<SyntheticPskOffer> pskOffer,
		ClientHelloGenerationOptions options);
	[[nodiscard]] ClientHello take();

private:
	class Part final {
	public:
		explicit Part(
			bytes::const_span domain,
			const bytes::vector &greases,
			bool padBeforeSyntheticPsk,
			const std::optional<SyntheticPskOffer> *pskOffer,
			ClientHelloGenerationOptions options);

		[[nodiscard]] bytes::span grow(int size);
		void writeBlocks(const QVector<MTPTlsBlock> &blocks);
		void writeBlock(const MTPTlsBlock &data);
		void writeBlock(const MTPDtlsBlockString &data);
		void writeBlock(const MTPDtlsBlockZero &data);
		void writeBlock(const MTPDtlsBlockGrease &data);
		void writeBlock(const MTPDtlsBlockRandom &data);
		void writeBlock(const MTPDtlsBlockDomain &data);
		void writeBlock(const MTPDtlsBlockPublicKey &data);
		void writeBlock(const MTPDtlsBlockScope &data);
		void writeBlock(const MTPDtlsBlockPermutation &data);
		void writeBlock(const MTPDtlsBlockM &data);
		void writeBlock(const MTPDtlsBlockE &data);
		void writeBlock(const MTPDtlsBlockPadding &data);
		void finalize(bytes::const_span key);
		[[nodiscard]] QByteArray extractDigest() const;

		[[nodiscard]] bool error() const;
		[[nodiscard]] QByteArray take();

	private:
		void writeSyntheticPskExtension();
		void writeDigest(bytes::const_span key);
		void injectTimestamp();

		bytes::const_span _domain;
		const bytes::vector &_greases;
		bool _padBeforeSyntheticPsk = false;
		const std::optional<SyntheticPskOffer> *_pskOffer = nullptr;
		ClientHelloGenerationOptions _options;
		QByteArray _result;
		const char *_data = nullptr;
		std::optional<int> _digestPosition;
		bool _error = false;

	};

	bytes::vector _greases;
	std::optional<SyntheticPskOffer> _pskOffer;
	bool _padBeforeSyntheticPsk = false;
	ClientHelloGenerationOptions _options;
	Part _result;
	QByteArray _digest;

};

Generator::Part::Part(
	bytes::const_span domain,
	const bytes::vector &greases,
	bool padBeforeSyntheticPsk,
	const std::optional<SyntheticPskOffer> *pskOffer,
	ClientHelloGenerationOptions options)
: _domain(domain)
, _greases(greases)
, _padBeforeSyntheticPsk(padBeforeSyntheticPsk)
, _pskOffer(pskOffer)
, _options(options) {
	_result.reserve(kClientHelloLimit);
	_data = _result.constData();
}

bool Generator::Part::error() const {
	return _error;
}

QByteArray Generator::Part::take() {
	Expects(_error || _result.constData() == _data);

	return _error ? QByteArray() : std::move(_result);
}

bytes::span Generator::Part::grow(int size) {
	if (_error
		|| size <= 0
		|| _result.size() + size > kClientHelloLimit) {
		_error = true;
		return bytes::span();
	}

	const auto offset = _result.size();
	_result.resize(offset + size);
	return bytes::make_detached_span(_result).subspan(offset);
}

void Generator::Part::writeBlocks(const QVector<MTPTlsBlock> &blocks) {
	for (const auto &block : blocks) {
		writeBlock(block);
	}
}

void Generator::Part::writeBlock(const MTPTlsBlock &data) {
	data.match([&](const auto &data) {
		writeBlock(data);
	});
}

void Generator::Part::writeBlock(const MTPDtlsBlockString &data) {
	const auto &bytes = data.vdata().v;
	const auto storage = grow(bytes.size());
	if (storage.empty()) {
		return;
	}
	bytes::copy(storage, bytes::make_span(bytes));
}

void Generator::Part::writeBlock(const MTPDtlsBlockZero &data) {
	const auto length = data.vlength().v;
	const auto already = _result.size();
	const auto storage = grow(length);
	if (storage.empty()) {
		return;
	}
	if (length == kClientHelloDigestLength && !_digestPosition) {
		_digestPosition = already;
	}
	bytes::set_with_const(storage, bytes::type(0));
}

void Generator::Part::writeBlock(const MTPDtlsBlockGrease &data) {
	const auto seed = data.vseed().v;
	if (seed < 0 || seed >= _greases.size()) {
		_error = true;
		return;
	}
	const auto storage = grow(2);
	if (storage.empty()) {
		return;
	}
	bytes::set_with_const(storage, _greases[seed]);
}

void Generator::Part::writeBlock(const MTPDtlsBlockRandom &data) {
	const auto length = data.vlength().v;
	const auto storage = grow(length);
	if (storage.empty()) {
		return;
	}
	if (_options.deterministic) {
		bytes::set_with_const(storage, bytes::type(0));
	} else {
		bytes::set_random(storage);
	}
}

void Generator::Part::writeBlock(const MTPDtlsBlockDomain &data) {
	const auto storage = grow(_domain.size());
	if (storage.empty()) {
		return;
	}
	bytes::copy(storage, _domain);
}

void Generator::Part::writeBlock(const MTPDtlsBlockPublicKey &data) {
	if (_options.deterministic) {
		const auto storage = grow(32);
		if (!storage.empty()) {
			bytes::set_with_const(storage, bytes::type(0));
		}
		return;
	}
	const auto key = GeneratePublicKey();
	const auto storage = grow(key.size());
	if (storage.empty()) {
		return;
	}
	bytes::copy(storage, key);
}

void Generator::Part::writeBlock(const MTPDtlsBlockScope &data) {
	const auto storage = grow(kTlsLengthFieldSize);
	if (storage.empty()) {
		return;
	}
	const auto already = _result.size();
	writeBlocks(data.ventries().v);
	const auto length = qToBigEndian(uint16(_result.size() - already));
	bytes::copy(storage, bytes::object_as_span(&length));
}

void Generator::Part::writeBlock(const MTPDtlsBlockPermutation &data) {
	auto list = std::vector<QByteArray>();
	list.reserve(data.ventries().v.size());
	for (const auto &inner : data.ventries().v) {
		auto part = Part(
			_domain,
			_greases,
			_padBeforeSyntheticPsk,
			nullptr,
			_options);
		part.writeBlocks(inner.v);
		if (part.error()) {
			_error = true;
			return;
		}
		list.push_back(part.take());
	}
	if (!_options.deterministic) {
		ranges::shuffle(list);
	}
	for (const auto &element : list) {
		const auto storage = grow(element.size());
		if (storage.empty()) {
			return;
		}
		bytes::copy(storage, bytes::make_span(element));
	}
}

void Generator::Part::writeBlock(const MTPDtlsBlockM &data) {
	constexpr auto kElements = 384;
	constexpr auto kAdded = 32;

	const auto storage = grow(kElements * 3 + kAdded);
	if (storage.empty()) {
		return;
	}
	if (_options.deterministic) {
		bytes::set_with_const(storage, bytes::type(0));
		return;
	}

	auto random = bytes::vector(kElements * 8 + kAdded);
	bytes::set_random(random);

	auto out = storage;
	for (auto i = 0; i < kElements; ++i) {
		const auto a = int(binary::ReadAt<uint32>(
			bytes::make_span(random),
			i * 2 * int(sizeof(uint32))) % 3329);
		const auto b = int(binary::ReadAt<uint32>(
			bytes::make_span(random),
			(i * 2 + 1) * int(sizeof(uint32))) % 3329);
		out[0] = bytes::type(uchar(a & 255));
		out[1] = bytes::type(uchar((a >> 8) + ((b & 15) << 4)));
		out[2] = bytes::type(uchar(b >> 4));
		out = out.subspan(3);
	}
	bytes::set_random(storage.subspan(kElements * 3));
}

void Generator::Part::writeBlock(const MTPDtlsBlockE &data) {
	const auto lengths = std::array{ 144, 176, 208, 240 };
	const auto length = _options.deterministic
		? lengths.front()
		: lengths[base::RandomIndex(lengths.size())];
	writeBlock(MTP_tlsBlockRandom(MTP_int(length)));
}

void Generator::Part::writeBlock(const MTPDtlsBlockPadding &data) {
	const auto length = int(_result.size());
	if (_padBeforeSyntheticPsk && length < 513) {
		const auto zero = MTP_tlsBlockZero(MTP_int(513 - length));
		writeBlock(MTP_tlsBlockString(MTP_bytes("\x00\x15"_q)));
		writeBlock(MTP_tlsBlockScope(MTP_vector<MTPTlsBlock>(1, zero)));
	}
	writeSyntheticPskExtension();
}

void Generator::Part::writeSyntheticPskExtension() {
	if (!_pskOffer || !*_pskOffer) {
		return;
	}
	const auto &offer = **_pskOffer;
	const auto binderLengths = std::array{ 32, 48 };
	const auto identityLength = int(offer.identity.size());
	const auto binderLength = offer.binderLength;
	if (identityLength <= 0
		|| (binderLength != binderLengths[0]
			&& binderLength != binderLengths[1])) {
		_error = true;
		return;
	}
	const auto identitiesLength = identityLength + 6;
	const auto bindersLength = binderLength + 1;
	const auto extensionLength = identitiesLength + bindersLength + 4;
	const auto write16 = [&](uint16 value) {
		const auto big = qToBigEndian(value);
		const auto storage = grow(sizeof(big));
		if (storage.empty()) {
			return;
		}
		bytes::copy(storage, bytes::object_as_span(&big));
	};
	const auto write32 = [&](uint32 value) {
		const auto big = qToBigEndian(value);
		const auto storage = grow(sizeof(big));
		if (storage.empty()) {
			return;
		}
		bytes::copy(storage, bytes::object_as_span(&big));
	};
	const auto random = [&](int length) {
		const auto storage = grow(length);
		if (storage.empty()) {
			return;
		}
		if (_options.deterministic) {
			bytes::set_with_const(storage, bytes::type(0));
		} else {
			bytes::set_random(storage);
		}
	};
	write16(uint16(0x0029));
	write16(uint16(extensionLength));
	write16(uint16(identitiesLength));
	write16(uint16(identityLength));
	const auto identityStorage = grow(identityLength);
	if (identityStorage.empty()) {
		return;
	}
	bytes::copy(identityStorage, offer.identity);
	write32(offer.obfuscatedTicketAge);
	write16(uint16(bindersLength));
	const auto binderPrefix = grow(1);
	if (binderPrefix.empty()) {
		return;
	}
	binderPrefix[0] = bytes::type(binderLength);
	random(binderLength);
}

void Generator::Part::finalize(bytes::const_span key) {
	if (_error) {
		return;
	} else if (!_digestPosition) {
		_error = true;
		return;
	}
	writeDigest(key);
	if (!_options.deterministic) {
		injectTimestamp();
	}
}

QByteArray Generator::Part::extractDigest() const {
	if (!_digestPosition) {
		return {};
	}
	return _result.mid(*_digestPosition, kClientHelloDigestLength);
}

void Generator::Part::writeDigest(bytes::const_span key) {
	Expects(_digestPosition.has_value());

	bytes::copy(
		bytes::make_detached_span(_result).subspan(*_digestPosition),
		openssl::HmacSha256(key, bytes::make_span(_result)));
}

void Generator::Part::injectTimestamp() {
	Expects(_digestPosition.has_value());

	const auto storage = bytes::make_detached_span(_result).subspan(
		*_digestPosition + kClientHelloDigestLength - sizeof(int32),
		sizeof(int32));
	auto already = int32();
	bytes::copy(bytes::object_as_span(&already), storage);
	already ^= qToLittleEndian(int32(base::unixtime::http_now()));
	bytes::copy(storage, bytes::object_as_span(&already));
}

Generator::Generator(
	const MTPTlsClientHello &rules,
	bytes::const_span domain,
	bytes::const_span key,
	bool padBeforeSyntheticPsk,
	std::optional<SyntheticPskOffer> pskOffer,
	ClientHelloGenerationOptions options)
: _greases(PrepareGreases(options))
, _pskOffer(std::move(pskOffer))
, _padBeforeSyntheticPsk(padBeforeSyntheticPsk)
, _options(options)
, _result(domain, _greases, _padBeforeSyntheticPsk, &_pskOffer, _options) {
	_result.writeBlocks(rules.data().vblocks().v);
	_result.finalize(key);
}

ClientHello Generator::take() {
	auto digest = _result.extractDigest();
	return { _result.take(), std::move(digest) };
}

} // namespace

ClientHello PrepareClientHello(
		const MTPTlsClientHello &rules,
		bytes::const_span domain,
		bytes::const_span key,
		ProxyTlsProfile profile,
		std::optional<SyntheticPskOffer> pskOffer,
		ClientHelloGenerationOptions options) {
	return Generator(
		rules,
		domain,
		key,
		ShouldPadBeforeSyntheticPsk(profile),
		std::move(pskOffer),
		options).take();
}


} // namespace MTP::details
