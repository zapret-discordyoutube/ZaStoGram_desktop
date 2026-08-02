/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "e2e_cloud/vault/cloud_vault.h"

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#include <algorithm>
#include <array>
#include <limits>
#include <set>
#include <utility>

namespace E2ECloud {
namespace {

inline constexpr auto kBlobMagic = std::array<std::uint8_t, 8>{
	'T', 'D', 'E', '2', 'E', 'C', 'V', 'T',
};
inline constexpr auto kPlaintextMagic = std::array<std::uint8_t, 8>{
	'T', 'D', 'E', '2', 'E', 'V', 'P', 'L',
};
inline constexpr auto kNonceSize = 12;
inline constexpr auto kTagSize = 16;
inline constexpr auto kMaximumWrappedKeySize = 4096;
inline constexpr auto kMaximumConversations = 4096;
inline constexpr auto kMaximumPlaintextSize = 2 * 1024 * 1024;

struct Reader {
	const QByteArray &bytes;
	int offset = 0;
};

void AppendUint16(QByteArray &result, std::uint16_t value) {
	result.append(char(value >> 8));
	result.append(char(value));
}

void AppendUint32(QByteArray &result, std::uint32_t value) {
	result.append(char(value >> 24));
	result.append(char(value >> 16));
	result.append(char(value >> 8));
	result.append(char(value));
}

void AppendUint64(QByteArray &result, std::uint64_t value) {
	for (auto shift = 56; shift >= 0; shift -= 8) {
		result.append(char(value >> shift));
	}
}

template <typename Array>
void AppendArray(QByteArray &result, const Array &value) {
	result.append(
		reinterpret_cast<const char*>(value.data()),
		int(value.size()));
}

void AppendBytes(QByteArray &result, const QByteArray &value) {
	AppendUint32(result, std::uint32_t(value.size()));
	result.append(value);
}

[[nodiscard]] bool ReadUint16(Reader &reader, std::uint16_t &value) {
	if (reader.bytes.size() - reader.offset < 2) {
		return false;
	}
	const auto data = reinterpret_cast<const std::uint8_t*>(
		reader.bytes.constData() + reader.offset);
	value = (std::uint16_t(data[0]) << 8) | std::uint16_t(data[1]);
	reader.offset += 2;
	return true;
}

[[nodiscard]] bool ReadUint32(Reader &reader, std::uint32_t &value) {
	if (reader.bytes.size() - reader.offset < 4) {
		return false;
	}
	const auto data = reinterpret_cast<const std::uint8_t*>(
		reader.bytes.constData() + reader.offset);
	value = (std::uint32_t(data[0]) << 24)
		| (std::uint32_t(data[1]) << 16)
		| (std::uint32_t(data[2]) << 8)
		| std::uint32_t(data[3]);
	reader.offset += 4;
	return true;
}

[[nodiscard]] bool ReadUint64(Reader &reader, std::uint64_t &value) {
	if (reader.bytes.size() - reader.offset < 8) {
		return false;
	}
	value = 0;
	for (auto i = 0; i != 8; ++i) {
		value = (value << 8)
			| std::uint8_t(reader.bytes[reader.offset + i]);
	}
	reader.offset += 8;
	return true;
}

template <typename Array>
[[nodiscard]] bool ReadArray(Reader &reader, Array &value) {
	const auto size = int(value.size());
	if (reader.bytes.size() - reader.offset < size) {
		return false;
	}
	std::copy_n(
		reinterpret_cast<const std::uint8_t*>(
			reader.bytes.constData() + reader.offset),
		size,
		value.data());
	reader.offset += size;
	return true;
}

[[nodiscard]] bool ReadBytes(
		Reader &reader,
		int maximumSize,
		QByteArray &value) {
	auto size = std::uint32_t();
	if (!ReadUint32(reader, size)
		|| size > std::uint32_t(maximumSize)
		|| reader.bytes.size() - reader.offset < int(size)) {
		return false;
	}
	value = QByteArray(reader.bytes.constData() + reader.offset, int(size));
	reader.offset += int(size);
	return true;
}

void Cleanse(QByteArray &bytes) {
	if (!bytes.isEmpty()) {
		OPENSSL_cleanse(bytes.data(), bytes.size());
	}
	bytes.clear();
}

template <typename Value>
void Cleanse(Value &value) {
	OPENSSL_cleanse(value.data(), value.size());
}

[[nodiscard]] bool ValidConversations(
		const std::vector<CloudVaultConversation> &conversations) {
	if (conversations.size() > kMaximumConversations) {
		return false;
	}
	auto telegramPeerBindings = std::set<std::uint64_t>();
	for (auto i = std::size_t(0); i != conversations.size(); ++i) {
		const auto &entry = conversations[i];
		if (!entry.conversationId
			|| !entry.telegramPeerIdBinding
			|| !telegramPeerBindings.emplace(
				entry.telegramPeerIdBinding).second
			|| entry.checkpoint.conversationId != entry.conversationId
			|| !entry.checkpoint.generation
			|| !entry.checkpoint.stateHash
			|| !entry.ownerAccountId
			|| (i && !(conversations[i - 1].conversationId
				< entry.conversationId))) {
			return false;
		}
	}
	return true;
}

[[nodiscard]] std::optional<QByteArray> EncodePlaintext(
		std::uint64_t telegramUserIdBinding,
		std::uint64_t generation,
		Digest previousBlobDigest,
		const AccountPrivateIdentity &identity,
		const std::vector<CloudVaultConversation> &conversations) {
	if (!telegramUserIdBinding
		|| !generation
		|| (generation == 1) != !previousBlobDigest
		|| !ValidateAccountPrivateIdentity(identity)
		|| !ValidConversations(conversations)) {
		return std::nullopt;
	}
	const auto credential = AccountCredentialCodecV1().encode(
		identity.credential);
	if (!credential) {
		return std::nullopt;
	}
	auto result = QByteArray();
	AppendArray(result, kPlaintextMagic);
	AppendUint16(result, 1);
	AppendUint64(result, telegramUserIdBinding);
	AppendUint64(result, generation);
	AppendArray(result, previousBlobDigest.bytes);
	AppendArray(result, identity.signingPrivateKey.bytes());
	AppendArray(result, identity.archiveHpkePrivateKey.bytes());
	result.append(*credential);
	AppendUint32(result, std::uint32_t(conversations.size()));
	for (const auto &entry : conversations) {
		AppendArray(result, entry.conversationId.bytes);
		AppendUint64(result, entry.telegramPeerIdBinding);
		AppendUint64(result, entry.checkpoint.generation);
		AppendArray(result, entry.checkpoint.stateHash.bytes);
		AppendArray(result, entry.ownerAccountId.bytes);
	}
	const auto signature = SignAccountData(
		identity.signingPrivateKey,
		AccountSignatureDomain::VaultCheckpoint,
		result);
	if (!signature
		|| result.size() + int(signature->size()) > kMaximumPlaintextSize) {
		Cleanse(result);
		return std::nullopt;
	}
	AppendArray(result, *signature);
	return result;
}

struct DecodedPlaintext {
	std::uint64_t telegramUserIdBinding = 0;
	std::uint64_t generation = 0;
	Digest previousBlobDigest;
	AccountPrivateIdentity identity;
	std::vector<CloudVaultConversation> conversations;
};

[[nodiscard]] std::optional<DecodedPlaintext> DecodePlaintext(
		const QByteArray &plaintext) {
	if (plaintext.size() < 8 + 2 + 8 + 8 + 32 + 32 + 32
		+ kAccountCredentialEncodedSize + 4 + 64
		|| plaintext.size() > kMaximumPlaintextSize) {
		return std::nullopt;
	}
	auto reader = Reader{ plaintext };
	auto magic = std::array<std::uint8_t, 8>();
	auto version = std::uint16_t();
	auto telegramUserIdBinding = std::uint64_t();
	auto generation = std::uint64_t();
	auto previousBlobDigest = Digest();
	auto signingPrivate = std::array<std::uint8_t, 32>();
	auto archivePrivate = std::array<std::uint8_t, 32>();
	auto credentialBytes = QByteArray();
	auto count = std::uint32_t();
	if (!ReadArray(reader, magic)
		|| !ReadUint16(reader, version)
		|| !ReadUint64(reader, telegramUserIdBinding)
		|| !ReadUint64(reader, generation)
		|| !ReadArray(reader, previousBlobDigest.bytes)
		|| !ReadArray(reader, signingPrivate)
		|| !ReadArray(reader, archivePrivate)
		|| reader.bytes.size() - reader.offset
			< kAccountCredentialEncodedSize) {
		Cleanse(signingPrivate);
		Cleanse(archivePrivate);
		return std::nullopt;
	}
	credentialBytes = QByteArray(
		reader.bytes.constData() + reader.offset,
		kAccountCredentialEncodedSize);
	reader.offset += kAccountCredentialEncodedSize;
	if (!ReadUint32(reader, count)
		|| count > kMaximumConversations) {
		Cleanse(signingPrivate);
		Cleanse(archivePrivate);
		return std::nullopt;
	}
	auto conversations = std::vector<CloudVaultConversation>();
	conversations.reserve(count);
	for (auto i = std::uint32_t(0); i != count; ++i) {
		auto entry = CloudVaultConversation();
		if (!ReadArray(reader, entry.conversationId.bytes)
			|| !ReadUint64(reader, entry.telegramPeerIdBinding)
			|| !ReadUint64(reader, entry.checkpoint.generation)
			|| !ReadArray(reader, entry.checkpoint.stateHash.bytes)
			|| !ReadArray(reader, entry.ownerAccountId.bytes)) {
			Cleanse(signingPrivate);
			Cleanse(archivePrivate);
			return std::nullopt;
		}
		entry.checkpoint.conversationId = entry.conversationId;
		conversations.push_back(entry);
	}
	auto signature = AccountSignature();
	if (!ReadArray(reader, signature)
		|| reader.offset != plaintext.size()) {
		Cleanse(signingPrivate);
		Cleanse(archivePrivate);
		return std::nullopt;
	}
	const auto credential = AccountCredentialCodecV1().decode(credentialBytes);
	auto signedBytes = QByteArray(
		plaintext.constData(),
		plaintext.size() - int(signature.size()));
	auto identity = AccountPrivateIdentity{
		.signingPrivateKey = SecureKey32(std::move(signingPrivate)),
		.archiveHpkePrivateKey = SecureKey32(std::move(archivePrivate)),
		.credential = credential.value_or(AccountCredentialPublic()),
	};
	const auto valid = magic == kPlaintextMagic
		&& version == 1
		&& telegramUserIdBinding
		&& generation
		&& (generation == 1) == !previousBlobDigest
		&& credential
		&& ValidConversations(conversations)
		&& ValidateAccountPrivateIdentity(identity)
		&& VerifyAccountSignature(
			*credential,
			AccountSignatureDomain::VaultCheckpoint,
			signedBytes,
			signature);
	Cleanse(signedBytes);
	if (!valid) {
		return std::nullopt;
	}
	return DecodedPlaintext{
		.telegramUserIdBinding = telegramUserIdBinding,
		.generation = generation,
		.previousBlobDigest = previousBlobDigest,
		.identity = std::move(identity),
		.conversations = std::move(conversations),
	};
}

[[nodiscard]] std::optional<QByteArray> Encrypt(
		const SecureKey32 &key,
		const QByteArray &wrappedMasterKey,
		std::uint64_t telegramUserIdBinding,
		std::uint64_t generation,
		const QByteArray &plaintext) {
	if (!key.valid()
		|| wrappedMasterKey.isEmpty()
		|| wrappedMasterKey.size() > kMaximumWrappedKeySize
		|| plaintext.isEmpty()
		|| plaintext.size() > kMaximumPlaintextSize) {
		return std::nullopt;
	}
	auto nonce = std::array<std::uint8_t, kNonceSize>();
	if (RAND_bytes(nonce.data(), nonce.size()) != 1) {
		return std::nullopt;
	}
	auto result = QByteArray();
	AppendArray(result, kBlobMagic);
	AppendUint16(result, 1);
	AppendUint64(result, telegramUserIdBinding);
	AppendUint64(result, generation);
	AppendBytes(result, wrappedMasterKey);
	AppendArray(result, nonce);
	AppendUint32(result, std::uint32_t(plaintext.size()));
	const auto headerSize = result.size();
	result.resize(headerSize + plaintext.size() + kTagSize);
	const auto context = EVP_CIPHER_CTX_new();
	if (!context) {
		return std::nullopt;
	}
	auto outputLength = 0;
	auto totalLength = 0;
	auto ok = EVP_EncryptInit_ex(
		context,
		EVP_aes_256_gcm(),
		nullptr,
		nullptr,
		nullptr) == 1
		&& EVP_CIPHER_CTX_ctrl(
			context,
			EVP_CTRL_GCM_SET_IVLEN,
			nonce.size(),
			nullptr) == 1
		&& EVP_EncryptInit_ex(
			context,
			nullptr,
			nullptr,
			key.bytes().data(),
			nonce.data()) == 1
		&& EVP_EncryptUpdate(
			context,
			nullptr,
			&outputLength,
			reinterpret_cast<const unsigned char*>(result.constData()),
			headerSize) == 1
		&& EVP_EncryptUpdate(
			context,
			reinterpret_cast<unsigned char*>(result.data() + headerSize),
			&outputLength,
			reinterpret_cast<const unsigned char*>(plaintext.constData()),
			plaintext.size()) == 1;
	totalLength = outputLength;
	ok = ok
		&& EVP_EncryptFinal_ex(
			context,
			reinterpret_cast<unsigned char*>(
				result.data() + headerSize + totalLength),
			&outputLength) == 1
		&& totalLength + outputLength == plaintext.size()
		&& EVP_CIPHER_CTX_ctrl(
			context,
			EVP_CTRL_GCM_GET_TAG,
			kTagSize,
			result.data() + headerSize + plaintext.size()) == 1;
	EVP_CIPHER_CTX_free(context);
	if (!ok) {
		Cleanse(result);
		return std::nullopt;
	}
	return result;
}

struct BlobParts {
	std::uint64_t telegramUserIdBinding = 0;
	std::uint64_t generation = 0;
	QByteArray wrappedMasterKey;
	std::array<std::uint8_t, kNonceSize> nonce = {};
	int headerSize = 0;
	int ciphertextSize = 0;
};

[[nodiscard]] std::optional<BlobParts> ParseBlob(
		const QByteArray &encoded) {
	auto reader = Reader{ encoded };
	auto magic = std::array<std::uint8_t, 8>();
	auto version = std::uint16_t();
	auto result = BlobParts();
	auto ciphertextSize = std::uint32_t();
	if (!ReadArray(reader, magic)
		|| !ReadUint16(reader, version)
		|| !ReadUint64(reader, result.telegramUserIdBinding)
		|| !ReadUint64(reader, result.generation)
		|| !ReadBytes(
			reader,
			kMaximumWrappedKeySize,
			result.wrappedMasterKey)
		|| !ReadArray(reader, result.nonce)
		|| !ReadUint32(reader, ciphertextSize)
		|| magic != kBlobMagic
		|| version != 1
		|| !result.telegramUserIdBinding
		|| !result.generation
		|| result.wrappedMasterKey.isEmpty()
		|| !ciphertextSize
		|| ciphertextSize > kMaximumPlaintextSize
		|| encoded.size() - reader.offset
			!= int(ciphertextSize) + kTagSize) {
		return std::nullopt;
	}
	result.headerSize = reader.offset;
	result.ciphertextSize = int(ciphertextSize);
	return result;
}

[[nodiscard]] std::optional<QByteArray> Decrypt(
		const QByteArray &encoded,
		const BlobParts &parts,
		const VaultMasterKey &masterKey) {
	auto plaintext = QByteArray();
	plaintext.resize(parts.ciphertextSize);
	const auto context = EVP_CIPHER_CTX_new();
	if (!context) {
		return std::nullopt;
	}
	auto outputLength = 0;
	auto totalLength = 0;
	auto ok = EVP_DecryptInit_ex(
		context,
		EVP_aes_256_gcm(),
		nullptr,
		nullptr,
		nullptr) == 1
		&& EVP_CIPHER_CTX_ctrl(
			context,
			EVP_CTRL_GCM_SET_IVLEN,
			parts.nonce.size(),
			nullptr) == 1
		&& EVP_DecryptInit_ex(
			context,
			nullptr,
			nullptr,
			masterKey.data(),
			parts.nonce.data()) == 1
		&& EVP_DecryptUpdate(
			context,
			nullptr,
			&outputLength,
			reinterpret_cast<const unsigned char*>(encoded.constData()),
			parts.headerSize) == 1
		&& EVP_DecryptUpdate(
			context,
			reinterpret_cast<unsigned char*>(plaintext.data()),
			&outputLength,
			reinterpret_cast<const unsigned char*>(
				encoded.constData() + parts.headerSize),
			parts.ciphertextSize) == 1;
	totalLength = outputLength;
	ok = ok
		&& EVP_CIPHER_CTX_ctrl(
			context,
			EVP_CTRL_GCM_SET_TAG,
			kTagSize,
			const_cast<char*>(encoded.constData())
				+ parts.headerSize + parts.ciphertextSize) == 1
		&& EVP_DecryptFinal_ex(
			context,
			reinterpret_cast<unsigned char*>(plaintext.data()) + totalLength,
			&outputLength) == 1
		&& totalLength + outputLength == parts.ciphertextSize;
	EVP_CIPHER_CTX_free(context);
	if (!ok) {
		Cleanse(plaintext);
		return std::nullopt;
	}
	return plaintext;
}

[[nodiscard]] std::optional<UnlockedCloudVault> DecodeUnlockedVault(
		const QByteArray &encoded,
		BlobParts parts,
		SecureKey32 &&masterKey,
		std::uint64_t expectedTelegramUserIdBinding,
		const Sha256Provider &sha256) {
	if (!masterKey.valid()
		|| parts.telegramUserIdBinding != expectedTelegramUserIdBinding) {
		return std::nullopt;
	}
	auto plaintext = Decrypt(encoded, parts, masterKey.bytes());
	if (!plaintext) {
		return std::nullopt;
	}
	auto decoded = DecodePlaintext(*plaintext);
	Cleanse(*plaintext);
	const auto blobDigest = sha256.digest(encoded);
	if (!decoded
		|| !blobDigest
		|| decoded->telegramUserIdBinding != parts.telegramUserIdBinding
		|| decoded->generation != parts.generation) {
		return std::nullopt;
	}
	return UnlockedCloudVault{
		.telegramUserIdBinding = decoded->telegramUserIdBinding,
		.generation = decoded->generation,
		.previousBlobDigest = decoded->previousBlobDigest,
		.blobDigest = blobDigest,
		.masterKey = std::move(masterKey),
		.wrappedMasterKey = std::move(parts.wrappedMasterKey),
		.identity = std::move(decoded->identity),
		.conversations = std::move(decoded->conversations),
	};
}

[[nodiscard]] std::vector<CloudVaultConversation> SortedConversations(
		std::vector<CloudVaultConversation> conversations) {
	std::sort(
		std::begin(conversations),
		std::end(conversations),
		[](const auto &a, const auto &b) {
			return a.conversationId < b.conversationId;
		});
	return conversations;
}

} // namespace

CloudVaultCodecV1::CloudVaultCodecV1(
		const PasswordKdf &passwordKdf,
		const Sha256Provider &sha256)
: _passwordVault(passwordKdf)
, _sha256(sha256) {
}

std::optional<CreatedCloudVault> CloudVaultCodecV1::create(
		std::uint64_t telegramUserIdBinding,
		AccountPrivateIdentity &&identity,
		QByteArray password,
		Argon2idConfig config,
		std::vector<CloudVaultConversation> conversations) const {
	auto rawMasterKey = VaultMasterKey();
	if (!telegramUserIdBinding
		|| !ValidateAccountPrivateIdentity(identity)
		|| RAND_bytes(rawMasterKey.data(), rawMasterKey.size()) != 1) {
		Cleanse(password);
		Cleanse(rawMasterKey);
		return std::nullopt;
	}
	auto secureMasterKeyBytes = rawMasterKey;
	auto wrapped = _passwordVault.wrap(
		std::move(rawMasterKey),
		std::move(password),
		config,
		1);
	if (!wrapped) {
		Cleanse(secureMasterKeyBytes);
		return std::nullopt;
	}
	auto masterKey = SecureKey32(std::move(secureMasterKeyBytes));
	conversations = SortedConversations(std::move(conversations));
	const auto encoded = encode(
		telegramUserIdBinding,
		1,
		{},
		masterKey,
		*wrapped,
		identity,
		conversations);
	const auto blobDigest = encoded ? _sha256.digest(*encoded) : Digest();
	if (!encoded || !blobDigest) {
		return std::nullopt;
	}
	return CreatedCloudVault{
		.encoded = *encoded,
		.unlocked = {
			.telegramUserIdBinding = telegramUserIdBinding,
			.generation = 1,
			.previousBlobDigest = {},
			.blobDigest = blobDigest,
			.masterKey = std::move(masterKey),
			.wrappedMasterKey = *wrapped,
			.identity = std::move(identity),
			.conversations = std::move(conversations),
		},
	};
}

std::optional<UnlockedCloudVault> CloudVaultCodecV1::unlock(
		const QByteArray &encoded,
		QByteArray password,
		std::uint64_t expectedTelegramUserIdBinding) const {
	const auto parts = ParseBlob(encoded);
	if (!parts
		|| parts->telegramUserIdBinding != expectedTelegramUserIdBinding) {
		Cleanse(password);
		return std::nullopt;
	}
	auto unwrapped = _passwordVault.unwrap(
		parts->wrappedMasterKey,
		std::move(password));
	if (!unwrapped) {
		return std::nullopt;
	}
	auto secureMasterKey = SecureKey32(std::move(unwrapped->masterKey));
	return DecodeUnlockedVault(
		encoded,
		std::move(*parts),
		std::move(secureMasterKey),
		expectedTelegramUserIdBinding,
		_sha256);
}

std::optional<CloudVaultBlobHeader> CloudVaultCodecV1::inspect(
		const QByteArray &encoded) const {
	const auto parts = ParseBlob(encoded);
	return parts
		? std::optional<CloudVaultBlobHeader>({
			.telegramUserIdBinding = parts->telegramUserIdBinding,
			.generation = parts->generation,
			.wrappedMasterKey = parts->wrappedMasterKey,
		})
		: std::nullopt;
}

std::optional<SecureKey32> CloudVaultCodecV1::unlockMasterKey(
		const QByteArray &wrappedMasterKey,
		QByteArray password) const {
	auto unwrapped = _passwordVault.unwrap(
		wrappedMasterKey,
		std::move(password));
	return unwrapped
		? std::optional<SecureKey32>(
			SecureKey32(std::move(unwrapped->masterKey)))
		: std::nullopt;
}

std::optional<UnlockedCloudVault> CloudVaultCodecV1::unlockWithMasterKey(
		const QByteArray &encoded,
		const SecureKey32 &masterKey,
		std::uint64_t expectedTelegramUserIdBinding) const {
	auto parts = ParseBlob(encoded);
	if (!parts) {
		return std::nullopt;
	}
	auto clonedBytes = masterKey.bytes();
	auto clonedKey = SecureKey32(std::move(clonedBytes));
	return DecodeUnlockedVault(
		encoded,
		std::move(*parts),
		std::move(clonedKey),
		expectedTelegramUserIdBinding,
		_sha256);
}

std::optional<PreparedCloudVaultUpdate> CloudVaultCodecV1::prepareUpdate(
		const UnlockedCloudVault &vault,
		std::vector<CloudVaultConversation> conversations) const {
	if (vault.generation == std::numeric_limits<std::uint64_t>::max()
		|| !vault.blobDigest
		|| !vault.masterKey.valid()) {
		return std::nullopt;
	}
	conversations = SortedConversations(std::move(conversations));
	const auto generation = vault.generation + 1;
	const auto encoded = encode(
		vault.telegramUserIdBinding,
		generation,
		vault.blobDigest,
		vault.masterKey,
		vault.wrappedMasterKey,
		vault.identity,
		conversations);
	const auto blobDigest = encoded ? _sha256.digest(*encoded) : Digest();
	return (encoded && blobDigest)
		? std::optional<PreparedCloudVaultUpdate>({
			.encoded = *encoded,
			.generation = generation,
			.previousBlobDigest = vault.blobDigest,
			.blobDigest = blobDigest,
			.conversations = std::move(conversations),
		})
		: std::nullopt;
}

bool CloudVaultCodecV1::applyPublished(
		UnlockedCloudVault &vault,
		PreparedCloudVaultUpdate &&update) const {
	if (update.generation != vault.generation + 1
		|| update.previousBlobDigest != vault.blobDigest
		|| !update.blobDigest
		|| update.blobDigest != _sha256.digest(update.encoded)
		|| !ValidConversations(update.conversations)) {
		return false;
	}
	vault.generation = update.generation;
	vault.previousBlobDigest = update.previousBlobDigest;
	vault.blobDigest = update.blobDigest;
	vault.conversations = std::move(update.conversations);
	return true;
}

std::optional<QByteArray> CloudVaultCodecV1::encode(
		std::uint64_t telegramUserIdBinding,
		std::uint64_t generation,
		Digest previousBlobDigest,
		const SecureKey32 &masterKey,
		const QByteArray &wrappedMasterKey,
		const AccountPrivateIdentity &identity,
		const std::vector<CloudVaultConversation> &conversations) const {
	auto plaintext = EncodePlaintext(
		telegramUserIdBinding,
		generation,
		previousBlobDigest,
		identity,
		conversations);
	if (!plaintext) {
		return std::nullopt;
	}
	auto result = Encrypt(
		masterKey,
		wrappedMasterKey,
		telegramUserIdBinding,
		generation,
		*plaintext);
	Cleanse(*plaintext);
	return result;
}

} // namespace E2ECloud
