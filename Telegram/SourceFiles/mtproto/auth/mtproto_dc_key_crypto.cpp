/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "mtproto/auth/mtproto_dc_key_crypto.h"

#include "base/algorithm.h"
#include "base/openssl_help.h"
#include "base/random.h"
#include "logs.h"

#include <algorithm>
#include <cmath>

namespace MTP::details {
namespace {

// Fast PQ factorization taken from TDLib:
// https://github.com/tdlib/td/blob/v1.7.0/tdutils/td/utils/crypto.cpp
[[nodiscard]] uint64 gcd(uint64 a, uint64 b) {
	if (a == 0) {
		return b;
	} else if (b == 0) {
		return a;
	}

	int shift = 0;
	while ((a & 1) == 0 && (b & 1) == 0) {
		a >>= 1;
		b >>= 1;
		shift++;
	}

	while (true) {
		while ((a & 1) == 0) {
			a >>= 1;
		}
		while ((b & 1) == 0) {
			b >>= 1;
		}
		if (a > b) {
			a -= b;
		} else if (b > a) {
			b -= a;
		} else {
			return a << shift;
		}
	}
}

[[nodiscard]] uint64 FactorizeSmallPQ(uint64 pq) {
	if (pq < 2 || (pq > (static_cast<uint64>(1) << 63))) {
		return 1;
	}
	uint64 g = 0;
	for (int i = 0, iter = 0; i < 3 || iter < 1000; i++) {
		uint64 q = (17 + base::RandomIndex(16)) % (pq - 1);
		uint64 x = base::RandomValue<uint64>() % (pq - 1) + 1;
		uint64 y = x;
		int lim = 1 << (std::min(5, i) + 18);
		for (int j = 1; j < lim; j++) {
			iter++;
			uint64 a = x;
			uint64 b = x;
			uint64 c = q;

			// c += a * b
			while (b) {
				if (b & 1) {
					c += a;
					if (c >= pq) {
						c -= pq;
					}
				}
				a += a;
				if (a >= pq) {
					a -= pq;
				}
				b >>= 1;
			}

			x = c;
			uint64 z = x < y ? pq + x - y : x - y;
			g = gcd(z, pq);
			if (g != 1) {
				break;
			}

			if (!(j & (j - 1))) {
				y = x;
			}
		}
		if (g > 1 && g < pq) {
			break;
		}
	}
	if (g != 0) {
		uint64 other = pq / g;
		if (other < g) {
			g = other;
		}
	}
	return g;
}

ParsedPQ FactorizeBigPQ(const QByteArray &pqStr) {
	using namespace openssl;

	Context context;
	BigNum a;
	BigNum b;
	BigNum p;
	BigNum q;
	auto one = BigNum(1);
	auto pq = BigNum(bytes::make_span(pqStr));

	bool found = false;
	for (int i = 0, iter = 0; !found && (i < 3 || iter < 1000); i++) {
		int32 t = 17 + base::RandomIndex(16);
		a.setWord(base::RandomValue<uint32>());
		b = a;

		int32 lim = 1 << (i + 23);
		for (int j = 1; j < lim; j++) {
			iter++;
			a.setModMul(a, a, pq, context);
			a.setAdd(a, BigNum(uint32(t)));
			if (BigNum::Compare(a, pq) >= 0) {
				a = BigNum::Sub(a, pq);
			}
			if (BigNum::Compare(a, b) > 0) {
				q.setSub(a, b);
			} else {
				q.setSub(b, a);
			}
			p.setGcd(q, pq, context);
			if (BigNum::Compare(p, one) != 0) {
				found = true;
				break;
			}
			if ((j & (j - 1)) == 0) {
				b = a;
			}
		}
	}

	if (!found) {
		return ParsedPQ();
	}
	BigNum::Div(&q, nullptr, pq, p, context);
	if (BigNum::Compare(p, q) > 0) {
		std::swap(p, q);
	}

	const auto pb = p.getBytes();
	const auto qb = q.getBytes();

	return {
		QByteArray(reinterpret_cast<const char*>(pb.data()), pb.size()),
		QByteArray(reinterpret_cast<const char*>(qb.data()), qb.size())
	};
}

[[nodiscard]] bool IsGoodEncryptedInner(
		bytes::const_span keyAesEncrypted,
		const RSAPublicKey &key) {
	Expects(keyAesEncrypted.size() == 256);

	const auto modulus = key.getN();
	const auto shift = (256 - int(modulus.size()));
	Assert(shift >= 0);
	for (auto i = 0; i != 256; ++i) {
		const auto a = keyAesEncrypted[i];
		const auto b = (i < shift)
			? bytes::type(0)
			: modulus[i - shift];
		if (a > b) {
			return false;
		} else if (a < b) {
			return true;
		}
	}
	return false;
}

} // namespace

bool ConstantTimeEqual(bytes::const_span a, bytes::const_span b) {
	return (a.size() == b.size())
		&& (CRYPTO_memcmp(a.data(), b.data(), a.size()) == 0);
}

ParsedPQ FactorizePQ(const QByteArray &pqStr) {
	const auto size = pqStr.size();
	if (size > 8 || (size == 8 && (uchar(pqStr[0]) & 128) != 0)) {
		return FactorizeBigPQ(pqStr);
	}

	const auto pqBytes = bytes::make_span(pqStr);
	uint64 pq = 0;
	for (auto i = 0; i != size; ++i) {
		pq = (pq << 8) | gsl::to_integer<uchar>(pqBytes[i]);
	}

	auto p = FactorizeSmallPQ(pq);
	if (p == 0 || (pq % p) != 0) {
		return ParsedPQ();
	}
	auto q = pq / p;

	auto pStr = QByteArray(4, Qt::Uninitialized);
	auto pBytes = bytes::make_detached_span(pStr);
	for (auto i = 0; i != 4; ++i) {
		pBytes[3 - i] = bytes::type(uchar(p & 0xFF));
		p >>= 8;
	}

	auto qStr = QByteArray(4, Qt::Uninitialized);
	auto qBytes = bytes::make_detached_span(qStr);
	for (auto i = 0; i != 4; ++i) {
		qBytes[3 - i] = bytes::type(uchar(q & 0xFF));
		q >>= 8;
	}
	return { pStr, qStr };
}

bytes::vector EncryptPQInnerRSA(
		mtpBuffer dataWithPadding,
		const RSAPublicKey &key) {
	DEBUG_LOG(("AuthKey Info: encrypting pq inner..."));

	constexpr auto kPrime = sizeof(mtpPrime);
	constexpr auto kDataWithPaddingPrimes = 192 / kPrime;
	constexpr auto kDataHashPrimes = (SHA256_DIGEST_LENGTH / kPrime);
	constexpr auto kKeySize = 32;
	constexpr auto kIvSize = 32;

	DEBUG_LOG(("AuthKey Info: starting key generation for pq inner..."));

	while (true) {
		auto dataWithHash = mtpBuffer();
		dataWithHash.reserve(kDataWithPaddingPrimes + kDataHashPrimes);
		dataWithHash.append(dataWithPadding);

		// data_pad_reversed := BYTE_REVERSE(data_with_padding);
		ranges::reverse(bytes::make_span(dataWithHash));

		// data_with_hash := data_pad_reversed
		//	+ SHA256(temp_key + data_with_padding);
		const auto tempKey = base::RandomValue<bytes::array<kKeySize>>();
		dataWithHash.resize(kDataWithPaddingPrimes + kDataHashPrimes);
		const auto dataWithHashBytes = bytes::make_span(dataWithHash);
		bytes::copy(
			dataWithHashBytes.subspan(kDataWithPaddingPrimes * kPrime),
			openssl::Sha256(tempKey, bytes::make_span(dataWithPadding)));

		auto aesEncrypted = mtpBuffer();
		auto keyAesEncrypted = mtpBuffer();
		aesEncrypted.resize(dataWithHash.size());
		const auto aesEncryptedBytes = bytes::make_span(aesEncrypted);

		DEBUG_LOG(("AuthKey Info: encrypting ige for pq inner..."));

		// aes_encrypted := AES256_IGE(data_with_hash, temp_key, 0);
		const auto tempIv = bytes::array<kIvSize>{ { bytes::type(0) } };
		aesIgeEncryptRaw(
			dataWithHashBytes.data(),
			aesEncryptedBytes.data(),
			dataWithHashBytes.size(),
			tempKey.data(),
			tempIv.data());

		DEBUG_LOG(("AuthKey Info: counting hash for pq inner..."));

		// temp_key_xor := temp_key XOR SHA256(aes_encrypted);
		const auto fullSize = (kKeySize / kPrime) + dataWithHash.size();
		keyAesEncrypted.resize(fullSize);
		const auto keyAesEncryptedBytes = bytes::make_span(keyAesEncrypted);
		const auto aesHash = openssl::Sha256(aesEncryptedBytes);
		for (auto i = 0; i != kKeySize; ++i) {
			keyAesEncryptedBytes[i] = tempKey[i] ^ aesHash[i];
		}

		DEBUG_LOG(("AuthKey Info: checking chosen key for pq inner..."));

		// key_aes_encrypted := temp_key_xor + aes_encrypted;
		bytes::copy(
			keyAesEncryptedBytes.subspan(kKeySize),
			aesEncryptedBytes);
		if (IsGoodEncryptedInner(keyAesEncryptedBytes, key)) {
			DEBUG_LOG(("AuthKey Info: chosen key for pq inner is good."));
			return key.encrypt(keyAesEncryptedBytes);
		}

		DEBUG_LOG(("AuthKey Info: chosen key for pq inner is bad..."));
	}
}

std::string EncryptClientDHInner(
		const MTPClient_DH_Inner_Data &data,
		const void *aesKey,
		const void *aesIV) {
	constexpr auto kSkipPrimes = openssl::kSha1Size / sizeof(mtpPrime);

	auto client_dh_inner_size = tl::count_length(data);
	auto encSize = (client_dh_inner_size >> 2) + kSkipPrimes;
	auto encFullSize = encSize;
	if (encSize & 0x03) {
		encFullSize += 4 - (encSize & 0x03);
	}

	auto encBuffer = mtpBuffer();
	encBuffer.reserve(encFullSize);
	encBuffer.resize(kSkipPrimes);
	data.write(encBuffer);
	encBuffer.resize(encFullSize);

	const auto bytes = bytes::make_span(encBuffer);

	const auto hash = openssl::Sha1(bytes.subspan(
		kSkipPrimes * sizeof(mtpPrime),
		client_dh_inner_size));
	bytes::copy(bytes, hash);
	bytes::set_random(bytes.subspan(encSize * sizeof(mtpPrime)));

	auto sdhEncString = std::string(encFullSize * 4, ' ');

	aesIgeEncryptRaw(
		&encBuffer[0],
		&sdhEncString[0],
		encFullSize * sizeof(mtpPrime),
		aesKey,
		aesIV);

	return sdhEncString;
}

MTPint128 NonceDigest(bytes::const_span data) {
	const auto hash = openssl::Sha1(data);
	return binary::ReadAt<MTPint128>(bytes::make_span(hash), 4);
}

} // namespace MTP::details
