/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#pragma once

#include "base/bytes.h"
#include "base/random.h"
#include "mtproto/core_types.h"
#include "mtproto/details/mtproto_rsa_public_key.h"
#include "mtproto/protocol/mtproto_binary.h"
#include "scheme.h"

#include <QtCore/QByteArray>

#include <string>
#include <type_traits>
#include <utility>

namespace MTP::details {

struct ParsedPQ {
	QByteArray p;
	QByteArray q;
};

[[nodiscard]] bool ConstantTimeEqual(
	bytes::const_span a,
	bytes::const_span b);

template <typename Type>
[[nodiscard]] bool ConstantTimeEqual(const Type &a, const Type &b) {
	return ConstantTimeEqual(
		bytes::object_as_span(&a),
		bytes::object_as_span(&b));
}

[[nodiscard]] ParsedPQ FactorizePQ(const QByteArray &pqStr);

[[nodiscard]] bytes::vector EncryptPQInnerRSA(
	mtpBuffer dataWithPadding,
	const RSAPublicKey &key);

template <typename PQInnerData>
[[nodiscard]] bytes::vector EncryptPQInnerRSA(
		const PQInnerData &data,
		const RSAPublicKey &key) {
	constexpr auto kPrime = sizeof(mtpPrime);
	constexpr auto kDataWithPaddingPrimes = 192 / kPrime;
	constexpr auto kMaxSizeInPrimes = 144 / kPrime;

	using BoxedPQInnerData = std::conditional_t<
		tl::is_boxed_v<PQInnerData>,
		PQInnerData,
		tl::boxed<PQInnerData>>;
	const auto boxed = BoxedPQInnerData(data);
	const auto p_q_inner_size = tl::count_length(boxed);
	const auto sizeInPrimes = (p_q_inner_size / kPrime);
	if (sizeInPrimes > kMaxSizeInPrimes) {
		return {};
	}

	auto dataWithPadding = mtpBuffer();
	dataWithPadding.reserve(kDataWithPaddingPrimes);
	boxed.write(dataWithPadding);
	dataWithPadding.resize(kDataWithPaddingPrimes);
	const auto dataWithPaddingBytes = bytes::make_span(dataWithPadding);
	bytes::set_random(dataWithPaddingBytes.subspan(sizeInPrimes * kPrime));

	return EncryptPQInnerRSA(std::move(dataWithPadding), key);
}

[[nodiscard]] std::string EncryptClientDHInner(
	const MTPClient_DH_Inner_Data &data,
	const void *aesKey,
	const void *aesIV);

MTPint128 NonceDigest(bytes::const_span data);

} // namespace MTP::details
