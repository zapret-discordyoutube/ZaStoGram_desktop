/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "e2e_cloud/archive/history_grant_crypto.h"

#include "e2e_cloud/mls/openmls_bridge.h"

#include <openssl/crypto.h>

#include <algorithm>
#include <array>
#include <set>
#include <utility>

namespace E2ECloud {
namespace {

inline constexpr auto kHeaderMagic = std::array<std::uint8_t, 8>{
	'T', 'D', 'E', '2', 'E', 'G', 'R', 'H',
};
inline constexpr auto kPayloadMagic = std::array<std::uint8_t, 8>{
	'T', 'D', 'E', '2', 'E', 'G', 'R', 'P',
};
inline constexpr auto kHpkeInfo = "TDE2E/archive-history-grant/v1";
inline constexpr auto kHeaderSize = 8 + 2 + 32 + 32 + 32 + 16 + 32
	+ 8 + 8 + 1 + 32;
inline constexpr auto kFixedEncodedSize = kHeaderSize + 32 + 4 + 64;

struct Reader {
	const QByteArray &bytes;
	int offset = 0;
};

void AppendUint8(QByteArray &result, std::uint8_t value) {
	result.append(char(value));
}

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

[[nodiscard]] bool ReadUint8(Reader &reader, std::uint8_t &value) {
	if (reader.offset == reader.bytes.size()) {
		return false;
	}
	value = std::uint8_t(reader.bytes[reader.offset++]);
	return true;
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
	const auto data = reinterpret_cast<const std::uint8_t*>(
		reader.bytes.constData() + reader.offset);
	value = 0;
	for (auto i = 0; i != 8; ++i) {
		value = (value << 8) | std::uint64_t(data[i]);
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

[[nodiscard]] bool Nonzero(const auto &value) {
	return std::any_of(begin(value), end(value), [](std::uint8_t byte) {
		return byte != 0;
	});
}

void Cleanse(QByteArray &value) {
	OPENSSL_cleanse(value.data(), value.size());
}

[[nodiscard]] bool ValidGrant(const EncryptedHistoryGrant &grant) {
	return grant.conversationId
		&& grant.grantId
		&& grant.issuerAccountId
		&& grant.issuerClientId
		&& grant.recipientAccountId
		&& grant.telegramPeerIdBinding
		&& grant.groupGeneration
		&& IsValidHistoryAccess(grant.historyAccess)
		&& Nonzero(grant.encapsulatedKey)
		&& !grant.ciphertext.isEmpty()
		&& grant.ciphertext.size() <= kMaximumEncryptedHistoryGrantSize
		&& Nonzero(grant.signature);
}

[[nodiscard]] QByteArray EncodeHeader(const EncryptedHistoryGrant &grant) {
	auto result = QByteArray();
	result.reserve(kHeaderSize);
	AppendArray(result, kHeaderMagic);
	AppendUint16(result, 1);
	AppendArray(result, grant.conversationId.bytes);
	AppendArray(result, grant.grantId.bytes);
	AppendArray(result, grant.issuerAccountId.bytes);
	AppendArray(result, grant.issuerClientId.bytes);
	AppendArray(result, grant.recipientAccountId.bytes);
	AppendUint64(result, grant.telegramPeerIdBinding);
	AppendUint64(result, grant.groupGeneration);
	AppendUint8(result, std::uint8_t(grant.historyAccess.mode));
	AppendArray(result, grant.historyAccess.boundaryEventId.bytes);
	return result;
}

[[nodiscard]] QByteArray SignatureInput(const EncryptedHistoryGrant &grant) {
	auto result = EncodeHeader(grant);
	AppendArray(result, grant.encapsulatedKey);
	AppendUint32(result, std::uint32_t(grant.ciphertext.size()));
	result.append(grant.ciphertext);
	return result;
}

[[nodiscard]] bool ValidEpochs(
		const std::vector<ArchiveEpochSecret> &epochs) {
	if (epochs.empty() || epochs.size() > kMaximumArchiveEpochsPerGrant) {
		return false;
	}
	auto previous = std::uint64_t();
	auto previousGroupGeneration = std::uint64_t();
	auto activationEvents = std::set<ObjectId>();
	for (const auto &epoch : epochs) {
		if (!epoch.generation
			|| !epoch.activationGroupGeneration
			|| !epoch.activationEventId
			|| !epoch.key.valid()
			|| epoch.generation <= previous
			|| epoch.activationGroupGeneration < previousGroupGeneration
			|| !activationEvents.emplace(epoch.activationEventId).second) {
			return false;
		}
		previous = epoch.generation;
		previousGroupGeneration = epoch.activationGroupGeneration;
	}
	return true;
}

[[nodiscard]] std::optional<QByteArray> EncodePayload(
		const CreateHistoryGrantArgs &args) {
	if (!args.epochs
		|| (args.historyAccess.mode == HistoryAccessMode::None
			? !args.epochs->empty()
			: !ValidEpochs(*args.epochs))) {
		return std::nullopt;
	}
	auto result = QByteArray();
	result.reserve(
		8 + 2 + 32 + 32 + 32 + 1 + 32 + 4
		+ int(args.epochs->size()) * (8 + 8 + 32 + kArchiveKeySize));
	AppendArray(result, kPayloadMagic);
	AppendUint16(result, 1);
	AppendArray(result, args.conversationId.bytes);
	AppendArray(result, args.grantId.bytes);
	AppendArray(result, args.recipientAccountId.bytes);
	AppendUint8(result, std::uint8_t(args.historyAccess.mode));
	AppendArray(result, args.historyAccess.boundaryEventId.bytes);
	AppendUint32(result, std::uint32_t(args.epochs->size()));
	for (const auto &epoch : *args.epochs) {
		AppendUint64(result, epoch.generation);
		AppendUint64(result, epoch.activationGroupGeneration);
		AppendArray(result, epoch.activationEventId.bytes);
		AppendArray(result, epoch.key.bytes());
	}
	return result;
}

[[nodiscard]] std::optional<HistoryGrantPayload> DecodePayload(
		const QByteArray &bytes) {
	auto reader = Reader{ bytes };
	auto magic = std::array<std::uint8_t, 8>();
	auto version = std::uint16_t();
	auto mode = std::uint8_t();
	auto count = std::uint32_t();
	auto result = HistoryGrantPayload();
	if (!ReadArray(reader, magic)
		|| !ReadUint16(reader, version)
		|| !ReadArray(reader, result.conversationId.bytes)
		|| !ReadArray(reader, result.grantId.bytes)
		|| !ReadArray(reader, result.recipientAccountId.bytes)
		|| !ReadUint8(reader, mode)
		|| !ReadArray(reader, result.historyAccess.boundaryEventId.bytes)
		|| !ReadUint32(reader, count)
		|| magic != kPayloadMagic
		|| version != 1
		|| count > kMaximumArchiveEpochsPerGrant) {
		return std::nullopt;
	}
	result.historyAccess.mode = HistoryAccessMode(mode);
	result.epochs.reserve(count);
	auto previous = std::uint64_t();
	auto previousGroupGeneration = std::uint64_t();
	auto activationEvents = std::set<ObjectId>();
	for (auto index = std::uint32_t(); index != count; ++index) {
		auto generation = std::uint64_t();
		auto activationGroupGeneration = std::uint64_t();
		auto activationEventId = ObjectId();
		auto key = std::array<std::uint8_t, kArchiveKeySize>();
		if (!ReadUint64(reader, generation)
			|| !ReadUint64(reader, activationGroupGeneration)
			|| !ReadArray(reader, activationEventId.bytes)
			|| !ReadArray(reader, key)
			|| !generation
			|| !activationGroupGeneration
			|| !activationEventId
			|| generation <= previous
			|| activationGroupGeneration < previousGroupGeneration
			|| !activationEvents.emplace(activationEventId).second
			|| !Nonzero(key)) {
			OPENSSL_cleanse(key.data(), key.size());
			return std::nullopt;
		}
		previous = generation;
		previousGroupGeneration = activationGroupGeneration;
		result.epochs.push_back({
			.generation = generation,
			.activationGroupGeneration = activationGroupGeneration,
			.activationEventId = activationEventId,
			.key = ArchiveKey32(std::move(key)),
		});
	}
	return (reader.offset == bytes.size()
		&& result.conversationId
		&& result.grantId
		&& result.recipientAccountId
		&& IsValidHistoryAccess(result.historyAccess)
		&& (result.historyAccess.mode == HistoryAccessMode::None
			? result.epochs.empty()
			: !result.epochs.empty()))
		? std::optional<HistoryGrantPayload>(std::move(result))
		: std::nullopt;
}

} // namespace

std::optional<QByteArray> EncryptedHistoryGrantCodecV1::encode(
		const EncryptedHistoryGrant &grant) const {
	if (!ValidGrant(grant)) {
		return std::nullopt;
	}
	auto result = SignatureInput(grant);
	result.reserve(result.size() + grant.signature.size());
	AppendArray(result, grant.signature);
	return result;
}

std::optional<EncryptedHistoryGrant> EncryptedHistoryGrantCodecV1::decode(
		const QByteArray &bytes) const {
	if (bytes.size() <= kFixedEncodedSize
		|| bytes.size() > kFixedEncodedSize + kMaximumEncryptedHistoryGrantSize) {
		return std::nullopt;
	}
	auto reader = Reader{ bytes };
	auto magic = std::array<std::uint8_t, 8>();
	auto version = std::uint16_t();
	auto mode = std::uint8_t();
	auto ciphertextSize = std::uint32_t();
	auto result = EncryptedHistoryGrant();
	if (!ReadArray(reader, magic)
		|| !ReadUint16(reader, version)
		|| !ReadArray(reader, result.conversationId.bytes)
		|| !ReadArray(reader, result.grantId.bytes)
		|| !ReadArray(reader, result.issuerAccountId.bytes)
		|| !ReadArray(reader, result.issuerClientId.bytes)
		|| !ReadArray(reader, result.recipientAccountId.bytes)
		|| !ReadUint64(reader, result.telegramPeerIdBinding)
		|| !ReadUint64(reader, result.groupGeneration)
		|| !ReadUint8(reader, mode)
		|| !ReadArray(reader, result.historyAccess.boundaryEventId.bytes)
		|| !ReadArray(reader, result.encapsulatedKey)
		|| !ReadUint32(reader, ciphertextSize)
		|| !ciphertextSize
		|| ciphertextSize > kMaximumEncryptedHistoryGrantSize
		|| reader.bytes.size() - reader.offset
			!= int(ciphertextSize) + int(result.signature.size())
		|| magic != kHeaderMagic
		|| version != 1) {
		return std::nullopt;
	}
	result.historyAccess.mode = HistoryAccessMode(mode);
	result.ciphertext = QByteArray(
		reader.bytes.constData() + reader.offset,
		int(ciphertextSize));
	reader.offset += int(ciphertextSize);
	if (!ReadArray(reader, result.signature)
		|| reader.offset != bytes.size()
		|| !ValidGrant(result)) {
		return std::nullopt;
	}
	return result;
}

std::optional<EncryptedHistoryGrant> CreateHistoryGrant(
		const CreateHistoryGrantArgs &args,
		const OpenMlsBridge &bridge) {
	if (!args.conversationId
		|| !args.grantId
		|| !args.issuerAccountId
		|| !args.issuerClientId
		|| !args.recipientAccountId
		|| !args.telegramPeerIdBinding
		|| !args.groupGeneration
		|| !IsValidHistoryAccess(args.historyAccess)
		|| !Nonzero(args.recipientArchivePublicKey)
		|| !args.issuerSigningPrivateKey
		|| !args.issuerSigningPrivateKey->valid()) {
		return std::nullopt;
	}
	auto plaintext = EncodePayload(args);
	if (!plaintext) {
		return std::nullopt;
	}
	auto result = EncryptedHistoryGrant{
		.conversationId = args.conversationId,
		.grantId = args.grantId,
		.issuerAccountId = args.issuerAccountId,
		.issuerClientId = args.issuerClientId,
		.recipientAccountId = args.recipientAccountId,
		.telegramPeerIdBinding = args.telegramPeerIdBinding,
		.groupGeneration = args.groupGeneration,
		.historyAccess = args.historyAccess,
		.encapsulatedKey = {},
		.ciphertext = {},
		.signature = {},
	};
	const auto header = EncodeHeader(result);
	const auto sealed = bridge.hpkeSeal(
		QByteArray(
			reinterpret_cast<const char*>(
				args.recipientArchivePublicKey.data()),
			args.recipientArchivePublicKey.size()),
		QByteArray(kHpkeInfo),
		header,
		*plaintext);
	Cleanse(*plaintext);
	if (sealed.status != OpenMlsBridgeStatus::Ok
		|| sealed.encapsulatedKey.size() != result.encapsulatedKey.size()
		|| sealed.ciphertext.isEmpty()
		|| sealed.ciphertext.size() > kMaximumEncryptedHistoryGrantSize) {
		return std::nullopt;
	}
	std::copy_n(
		reinterpret_cast<const std::uint8_t*>(
			sealed.encapsulatedKey.constData()),
		result.encapsulatedKey.size(),
		result.encapsulatedKey.data());
	result.ciphertext = sealed.ciphertext;
	const auto signatureInput = SignatureInput(result);
	const auto signature = SignAccountData(
		*args.issuerSigningPrivateKey,
		AccountSignatureDomain::HistoryGrant,
		signatureInput);
	if (!signature) {
		return std::nullopt;
	}
	result.signature = *signature;
	return ValidGrant(result)
		? std::optional<EncryptedHistoryGrant>(std::move(result))
		: std::nullopt;
}

std::optional<HistoryGrantPayload> OpenHistoryGrant(
		const EncryptedHistoryGrant &grant,
		AccountId expectedRecipientAccountId,
		const SecureKey32 &recipientArchivePrivateKey,
		const AccountCredentialPublic &issuerCredential,
		const Sha256Provider &sha256,
		const OpenMlsBridge &bridge) {
	if (!ValidGrant(grant)
		|| !expectedRecipientAccountId
		|| grant.recipientAccountId != expectedRecipientAccountId
		|| !recipientArchivePrivateKey.valid()
		|| !VerifyEncryptedHistoryGrantSignature(
			grant,
			issuerCredential,
			sha256)) {
		return std::nullopt;
	}
	const auto header = EncodeHeader(grant);
	auto opened = bridge.hpkeOpen(
		QByteArray(
			reinterpret_cast<const char*>(
				recipientArchivePrivateKey.bytes().data()),
			recipientArchivePrivateKey.bytes().size()),
		QByteArray(
			reinterpret_cast<const char*>(grant.encapsulatedKey.data()),
			grant.encapsulatedKey.size()),
		QByteArray(kHpkeInfo),
		header,
		grant.ciphertext);
	if (opened.status != OpenMlsBridgeStatus::Ok) {
		Cleanse(opened.plaintext);
		return std::nullopt;
	}
	auto result = DecodePayload(opened.plaintext);
	Cleanse(opened.plaintext);
	if (!result
		|| result->conversationId != grant.conversationId
		|| result->grantId != grant.grantId
		|| result->recipientAccountId != grant.recipientAccountId
		|| result->historyAccess != grant.historyAccess) {
		return std::nullopt;
	}
	return result;
}

bool VerifyEncryptedHistoryGrantSignature(
		const EncryptedHistoryGrant &grant,
		const AccountCredentialPublic &issuerCredential,
		const Sha256Provider &sha256) {
	const auto issuerAccountId = DeriveAccountId(issuerCredential, sha256);
	return ValidGrant(grant)
		&& issuerAccountId
		&& *issuerAccountId == grant.issuerAccountId
		&& VerifyAccountSignature(
			issuerCredential,
			AccountSignatureDomain::HistoryGrant,
			SignatureInput(grant),
			grant.signature);
}

} // namespace E2ECloud
