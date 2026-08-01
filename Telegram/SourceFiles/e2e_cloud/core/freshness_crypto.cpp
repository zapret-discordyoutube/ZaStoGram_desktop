/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "e2e_cloud/core/freshness_crypto.h"

#include <algorithm>
#include <array>

namespace E2ECloud {
namespace {

inline constexpr auto kChallengeMagic = std::array<std::uint8_t, 8>{
	'T', 'D', 'E', '2', 'E', 'F', 'C', 'H',
};
inline constexpr auto kResponseMagic = std::array<std::uint8_t, 8>{
	'T', 'D', 'E', '2', 'E', 'F', 'R', 'S',
};
inline constexpr auto kResponseBodySize = kFreshnessResponseEncodedSize - 64;

struct Reader {
	const QByteArray &bytes;
	int offset = 0;
};

void AppendUint16(QByteArray &result, std::uint16_t value) {
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

[[nodiscard]] bool ValidChallenge(const FreshnessChallenge &challenge) {
	return challenge.conversationId
		&& challenge.knownCheckpoint.conversationId
			== challenge.conversationId
		&& challenge.knownCheckpoint.generation
		&& challenge.knownCheckpoint.stateHash
		&& challenge.nonce;
}

[[nodiscard]] bool ValidResponse(const FreshnessResponse &response) {
	return response.conversationId
		&& response.nonce
		&& response.challengedCheckpoint.conversationId
			== response.conversationId
		&& response.challengedCheckpoint.generation
		&& response.challengedCheckpoint.stateHash
		&& response.checkpoint.conversationId == response.conversationId
		&& response.checkpoint.generation
			>= response.challengedCheckpoint.generation
		&& response.checkpoint.stateHash
		&& response.witnessAccountId
		&& response.witnessClientId
		&& response.authenticatedProof.size() == 64;
}

[[nodiscard]] QByteArray EncodeResponseBody(
		const FreshnessResponse &response) {
	auto result = QByteArray();
	result.reserve(kResponseBodySize);
	AppendArray(result, kResponseMagic);
	AppendUint16(result, 1);
	AppendArray(result, response.conversationId.bytes);
	AppendArray(result, response.nonce.bytes);
	AppendUint64(result, response.challengedCheckpoint.generation);
	AppendArray(result, response.challengedCheckpoint.stateHash.bytes);
	AppendUint64(result, response.checkpoint.generation);
	AppendArray(result, response.checkpoint.stateHash.bytes);
	AppendArray(result, response.witnessAccountId.bytes);
	AppendArray(result, response.witnessClientId.bytes);
	return result;
}

} // namespace

std::optional<QByteArray> FreshnessChallengeCodecV1::encode(
		const FreshnessChallenge &challenge) const {
	if (!ValidChallenge(challenge)) {
		return std::nullopt;
	}
	auto result = QByteArray();
	result.reserve(kFreshnessChallengeEncodedSize);
	AppendArray(result, kChallengeMagic);
	AppendUint16(result, 1);
	AppendArray(result, challenge.conversationId.bytes);
	AppendUint64(result, challenge.knownCheckpoint.generation);
	AppendArray(result, challenge.knownCheckpoint.stateHash.bytes);
	AppendArray(result, challenge.nonce.bytes);
	return result;
}

std::optional<FreshnessChallenge> FreshnessChallengeCodecV1::decode(
		const QByteArray &bytes) const {
	if (bytes.size() != kFreshnessChallengeEncodedSize) {
		return std::nullopt;
	}
	auto reader = Reader{ bytes };
	auto magic = std::array<std::uint8_t, 8>();
	auto version = std::uint16_t();
	auto result = FreshnessChallenge();
	if (!ReadArray(reader, magic)
		|| !ReadUint16(reader, version)
		|| !ReadArray(reader, result.conversationId.bytes)
		|| !ReadUint64(reader, result.knownCheckpoint.generation)
		|| !ReadArray(reader, result.knownCheckpoint.stateHash.bytes)
		|| !ReadArray(reader, result.nonce.bytes)
		|| reader.offset != bytes.size()
		|| magic != kChallengeMagic
		|| version != 1) {
		return std::nullopt;
	}
	result.knownCheckpoint.conversationId = result.conversationId;
	return ValidChallenge(result)
		? std::optional<FreshnessChallenge>(std::move(result))
		: std::nullopt;
}

std::optional<QByteArray> FreshnessResponseCodecV1::encode(
		const FreshnessResponse &response) const {
	if (!ValidResponse(response)) {
		return std::nullopt;
	}
	auto result = EncodeResponseBody(response);
	result.append(response.authenticatedProof);
	return result.size() == kFreshnessResponseEncodedSize
		? std::optional<QByteArray>(std::move(result))
		: std::nullopt;
}

std::optional<FreshnessResponse> FreshnessResponseCodecV1::decode(
		const QByteArray &bytes) const {
	if (bytes.size() != kFreshnessResponseEncodedSize) {
		return std::nullopt;
	}
	auto reader = Reader{ bytes };
	auto magic = std::array<std::uint8_t, 8>();
	auto version = std::uint16_t();
	auto proof = std::array<std::uint8_t, 64>();
	auto result = FreshnessResponse();
	if (!ReadArray(reader, magic)
		|| !ReadUint16(reader, version)
		|| !ReadArray(reader, result.conversationId.bytes)
		|| !ReadArray(reader, result.nonce.bytes)
		|| !ReadUint64(reader, result.challengedCheckpoint.generation)
		|| !ReadArray(reader, result.challengedCheckpoint.stateHash.bytes)
		|| !ReadUint64(reader, result.checkpoint.generation)
		|| !ReadArray(reader, result.checkpoint.stateHash.bytes)
		|| !ReadArray(reader, result.witnessAccountId.bytes)
		|| !ReadArray(reader, result.witnessClientId.bytes)
		|| !ReadArray(reader, proof)
		|| reader.offset != bytes.size()
		|| magic != kResponseMagic
		|| version != 1) {
		return std::nullopt;
	}
	result.challengedCheckpoint.conversationId = result.conversationId;
	result.checkpoint.conversationId = result.conversationId;
	result.authenticatedProof = QByteArray(
		reinterpret_cast<const char*>(proof.data()),
		proof.size());
	return ValidResponse(result)
		? std::optional<FreshnessResponse>(std::move(result))
		: std::nullopt;
}

std::optional<FreshnessResponse> CreateFreshnessResponse(
		CreateFreshnessResponseArgs args) {
	if (!ValidChallenge(args.challenge)
		|| args.witnessCheckpoint.conversationId
			!= args.challenge.conversationId
		|| args.witnessCheckpoint.generation
			< args.challenge.knownCheckpoint.generation
		|| !args.witnessCheckpoint.stateHash
		|| !args.witnessAccountId
		|| !args.witnessClientId
		|| !args.witnessSigningPrivateKey
		|| !args.witnessSigningPrivateKey->valid()) {
		return std::nullopt;
	}
	auto result = FreshnessResponse{
		.conversationId = args.challenge.conversationId,
		.nonce = args.challenge.nonce,
		.challengedCheckpoint = args.challenge.knownCheckpoint,
		.checkpoint = args.witnessCheckpoint,
		.witnessAccountId = args.witnessAccountId,
		.witnessClientId = args.witnessClientId,
		.authenticatedProof = {},
	};
	const auto signature = SignAccountData(
		*args.witnessSigningPrivateKey,
		AccountSignatureDomain::FreshnessResponse,
		EncodeResponseBody(result));
	if (!signature) {
		return std::nullopt;
	}
	result.authenticatedProof = QByteArray(
		reinterpret_cast<const char*>(signature->data()),
		signature->size());
	return result;
}

AccountFreshnessResponseVerifier::AccountFreshnessResponseVerifier(
		const PersistentGroupLedger &groupLedger)
: _groupLedger(groupLedger) {
}

bool AccountFreshnessResponseVerifier::verify(
		const FreshnessResponse &response) const {
	const auto challenged = _groupLedger.checkpointAt(
		response.challengedCheckpoint.generation);
	const auto currentGeneration = _groupLedger.state()
		? _groupLedger.state()->generation()
		: 0;
	const auto witnessed = (response.checkpoint.generation
			<= currentGeneration)
		? _groupLedger.checkpointAt(response.checkpoint.generation)
		: std::nullopt;
	if (!ValidResponse(response)
		|| !_groupLedger.loaded()
		|| !_groupLedger.state()
		|| response.conversationId
			!= _groupLedger.state()->conversationId()
		|| !challenged
		|| response.challengedCheckpoint != *challenged
		|| !_groupLedger.wasClientActiveAt(
			response.witnessAccountId,
			response.witnessClientId,
			response.challengedCheckpoint.generation)
		|| (response.checkpoint.generation <= currentGeneration
			&& (!witnessed
				|| *witnessed != response.checkpoint
				|| !_groupLedger.wasClientActiveAt(
					response.witnessAccountId,
					response.witnessClientId,
					response.checkpoint.generation)))) {
		return false;
	}
	const auto credential = _groupLedger.credential(
		response.witnessAccountId);
	auto signature = AccountSignature();
	std::copy_n(
		reinterpret_cast<const std::uint8_t*>(
			response.authenticatedProof.constData()),
		signature.size(),
		signature.data());
	return credential && VerifyAccountSignature(
		*credential,
		AccountSignatureDomain::FreshnessResponse,
		EncodeResponseBody(response),
		signature);
}

} // namespace E2ECloud
