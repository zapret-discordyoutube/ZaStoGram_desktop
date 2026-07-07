/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "mtproto/auth/mtproto_auth_key.h"

#include "base/openssl_help.h"
#include "mtproto/protocol/mtproto_binary.h"

#include <QtCore/QDataStream>

namespace MTP {
namespace {

constexpr auto kMsgKeyPartPosition = 88;
constexpr auto kMsgKeyPartSize = 32;
constexpr auto kMsgKeyReceiveOffset = 8;
constexpr auto kMsgKeyShift = 8;

[[nodiscard]] std::array<uchar, 32> CountMsgKeyLargeHash(
		const AuthKey::Data &key,
		bytes::const_span data,
		bool send) {
	auto result = std::array<uchar, 32>();
	auto context = SHA256_CTX();
	SHA256_Init(&context);
	SHA256_Update(
		&context,
		key.data()
			+ kMsgKeyPartPosition
			+ (send ? 0 : kMsgKeyReceiveOffset),
		kMsgKeyPartSize);
	SHA256_Update(&context, data.data(), data.size());
	SHA256_Final(result.data(), &context);
	return result;
}

} // namespace

AuthKey::AuthKey(Type type, DcId dcId, const Data &data)
: _type(type)
, _dcId(dcId)
, _key(data) {
	countKeyId();
	if (type == Type::Generated || type == Type::Temporary) {
		_creationTime = crl::now();
	}
}

AuthKey::AuthKey(const Data &data) : _type(Type::Local), _key(data) {
	countKeyId();
}

AuthKey::~AuthKey() {
	OPENSSL_cleanse(_key.data(), _key.size());
}

AuthKey::Type AuthKey::type() const {
	return _type;
}

int AuthKey::dcId() const {
	return _dcId;
}

AuthKey::KeyId AuthKey::keyId() const {
	return _keyId;
}

void AuthKey::prepareAES_oldmtp(const MTPint128 &msgKey, MTPint256 &aesKey, MTPint256 &aesIV, bool send) const {
	uint32 x = send ? 0 : 8;

	bytes::array<20> sha1_a, sha1_b, sha1_c, sha1_d;
	bytes::array<16 + 32> data_a;
	details::binary::Copy(
		bytes::make_span(data_a),
		details::binary::AsBytes(&msgKey));
	details::binary::Copy(
		bytes::make_span(data_a).subspan(16),
		bytes::make_span(_key).subspan(x, 32));
	openssl::Sha1To(sha1_a, data_a);

	bytes::array<16 + 16 + 16> data_b;
	details::binary::Copy(
		bytes::make_span(data_b),
		bytes::make_span(_key).subspan(32 + x, 16));
	details::binary::Copy(
		bytes::make_span(data_b).subspan(16),
		details::binary::AsBytes(&msgKey));
	details::binary::Copy(
		bytes::make_span(data_b).subspan(32),
		bytes::make_span(_key).subspan(48 + x, 16));
	openssl::Sha1To(sha1_b, data_b);

	bytes::array<32 + 16> data_c;
	details::binary::Copy(
		bytes::make_span(data_c),
		bytes::make_span(_key).subspan(64 + x, 32));
	details::binary::Copy(
		bytes::make_span(data_c).subspan(32),
		details::binary::AsBytes(&msgKey));
	openssl::Sha1To(sha1_c, data_c);

	bytes::array<16 + 32> data_d;
	details::binary::Copy(
		bytes::make_span(data_d),
		details::binary::AsBytes(&msgKey));
	details::binary::Copy(
		bytes::make_span(data_d).subspan(16),
		bytes::make_span(_key).subspan(96 + x, 32));
	openssl::Sha1To(sha1_d, data_d);

	auto key = details::binary::AsBytes(&aesKey);
	auto iv = details::binary::AsBytes(&aesIV);
	details::binary::Copy(key, bytes::make_span(sha1_a).subspan(0, 8));
	details::binary::Copy(key.subspan(8), bytes::make_span(sha1_b).subspan(8, 12));
	details::binary::Copy(key.subspan(20), bytes::make_span(sha1_c).subspan(4, 12));
	details::binary::Copy(iv, bytes::make_span(sha1_a).subspan(8, 12));
	details::binary::Copy(iv.subspan(12), bytes::make_span(sha1_b).subspan(0, 8));
	details::binary::Copy(iv.subspan(20), bytes::make_span(sha1_c).subspan(16, 4));
	details::binary::Copy(iv.subspan(24), bytes::make_span(sha1_d).subspan(0, 8));
}

void AuthKey::prepareAES(const MTPint128 &msgKey, MTPint256 &aesKey, MTPint256 &aesIV, bool send) const {
	uint32 x = send ? 0 : 8;

	bytes::array<32> sha256_a, sha256_b;
	bytes::array<16 + 36> data_a;
	details::binary::Copy(
		bytes::make_span(data_a),
		details::binary::AsBytes(&msgKey));
	details::binary::Copy(
		bytes::make_span(data_a).subspan(16),
		bytes::make_span(_key).subspan(x, 36));
	openssl::Sha256To(sha256_a, data_a);

	bytes::array<36 + 16> data_b;
	details::binary::Copy(
		bytes::make_span(data_b),
		bytes::make_span(_key).subspan(40 + x, 36));
	details::binary::Copy(
		bytes::make_span(data_b).subspan(36),
		details::binary::AsBytes(&msgKey));
	openssl::Sha256To(sha256_b, data_b);

	auto key = details::binary::AsBytes(&aesKey);
	auto iv = details::binary::AsBytes(&aesIV);
	details::binary::Copy(key, bytes::make_span(sha256_a).subspan(0, 8));
	details::binary::Copy(key.subspan(8), bytes::make_span(sha256_b).subspan(8, 16));
	details::binary::Copy(key.subspan(24), bytes::make_span(sha256_a).subspan(24, 8));
	details::binary::Copy(iv, bytes::make_span(sha256_b).subspan(0, 8));
	details::binary::Copy(iv.subspan(8), bytes::make_span(sha256_a).subspan(8, 16));
	details::binary::Copy(iv.subspan(24), bytes::make_span(sha256_b).subspan(24, 8));
}

MTPint128 AuthKey::countMsgKey(bytes::const_span data, bool send) const {
	const auto hash = CountMsgKeyLargeHash(_key, data, send);
	return details::binary::ReadAt<MTPint128>(
		bytes::make_span(hash),
		kMsgKeyShift);
}

bool AuthKey::validateMsgKey(
		const MTPint128 &msgKey,
		bytes::const_span data,
		bool send) const {
	const auto hash = CountMsgKeyLargeHash(_key, data, send);
	const auto bytes = details::binary::AsBytes(&msgKey);
	return CRYPTO_memcmp(
		bytes.data(),
		hash.data() + kMsgKeyShift,
		bytes.size()) == 0;
}

void AuthKey::write(QDataStream &to) const {
	to.writeRawData(reinterpret_cast<const char*>(_key.data()), _key.size());
}

bool AuthKey::equals(const std::shared_ptr<AuthKey> &other) const {
	return other
		&& (CRYPTO_memcmp(_key.data(), other->_key.data(), _key.size()) == 0);
}

crl::time AuthKey::creationTime() const {
	return _creationTime;
}

TimeId AuthKey::expiresAt() const {
	return _expiresAt;
}

void AuthKey::setExpiresAt(TimeId expiresAt) {
	Expects(_type == Type::Temporary);

	_expiresAt = expiresAt;
}

void AuthKey::FillData(Data &authKey, bytes::const_span computedAuthKey) {
	auto computedAuthKeySize = computedAuthKey.size();
	Assert(computedAuthKeySize <= kSize);
	auto authKeyBytes = gsl::make_span(authKey);
	if (computedAuthKeySize < kSize) {
		bytes::set_with_const(authKeyBytes.subspan(0, kSize - computedAuthKeySize), gsl::byte());
		bytes::copy(authKeyBytes.subspan(kSize - computedAuthKeySize), computedAuthKey);
	} else {
		bytes::copy(authKeyBytes, computedAuthKey);
	}
}

void AuthKey::countKeyId() {
	const auto hash = openssl::Sha1(_key);

	// Lower 64 bits = 8 bytes of 20 byte SHA1 hash.
	_keyId = details::binary::ReadAt<KeyId>(bytes::make_span(hash), 12);
}

void aesIgeEncryptRaw(const void *src, void *dst, uint32 len, const void *key, const void *iv) {
	uchar aes_key[32], aes_iv[32];
	details::binary::Copy(bytes::make_span(aes_key), key, 32);
	details::binary::Copy(bytes::make_span(aes_iv), iv, 32);

	AES_KEY aes;
	AES_set_encrypt_key(aes_key, 256, &aes);
	AES_ige_encrypt(static_cast<const uchar*>(src), static_cast<uchar*>(dst), len, &aes, aes_iv, AES_ENCRYPT);
}

void aesIgeDecryptRaw(const void *src, void *dst, uint32 len, const void *key, const void *iv) {
	uchar aes_key[32], aes_iv[32];
	details::binary::Copy(bytes::make_span(aes_key), key, 32);
	details::binary::Copy(bytes::make_span(aes_iv), iv, 32);

	AES_KEY aes;
	AES_set_decrypt_key(aes_key, 256, &aes);
	AES_ige_encrypt(static_cast<const uchar*>(src), static_cast<uchar*>(dst), len, &aes, aes_iv, AES_DECRYPT);
}

void aesCtrEncrypt(bytes::span data, const void *key, CTRState *state) {
	AES_KEY aes;
	AES_set_encrypt_key(static_cast<const uchar*>(key), 256, &aes);

	static_assert(CTRState::IvecSize == AES_BLOCK_SIZE, "Wrong size of ctr ivec!");
	static_assert(CTRState::EcountSize == AES_BLOCK_SIZE, "Wrong size of ctr ecount!");

	CRYPTO_ctr128_encrypt(
		reinterpret_cast<const uchar*>(data.data()),
		reinterpret_cast<uchar*>(data.data()),
		data.size(),
		&aes,
		state->ivec,
		state->ecount,
		&state->num,
		(block128_f)AES_encrypt);
}

} // namespace MTP
